"""ReconBot — runs first, maps the attack surface before any attacks.

Fetches the target, fingerprints the stack from response headers, parses links and
forms to discover endpoints and their parameters, reads robots.txt / sitemap.xml,
probes a small set of common sensitive paths, and flags obvious misconfigurations
(exposed .git, debug endpoints, missing security headers). Everything it learns is
written into ``ctx`` for the other agents and the orchestrator to use.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse, parse_qs

from argus.agents.base import AgentReport, AttackContext, BaseAgent, Endpoint, build_http_poc, gather_limited
from argus.models import Finding, Severity

try:
    from playwright.async_api import async_playwright
except ImportError:  # pragma: no cover - exercised only when the extra isn't installed
    async_playwright = None

_LINK_RE = re.compile(r"""(?:href|src)\s*=\s*['"]([^'"#]+)['"]""", re.IGNORECASE)
# Two groups: (1) the opening <form ...> tag's attributes, (2) the inner content
# (for input discovery). A form's action/method live in the opening tag, not the
# inner content, so they must be searched for in group(1), not group(2).
_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_FORM_ACTION_RE = re.compile(r"""action\s*=\s*['"]([^'"]*)['"]""", re.IGNORECASE)
_FORM_METHOD_RE = re.compile(r"""method\s*=\s*['"]([^'"]*)['"]""", re.IGNORECASE)
_INPUT_NAME_RE = re.compile(r"""<(?:input|textarea|select)\b[^>]*\bname\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)

# (path, label, severity) for common sensitive locations.
_COMMON_PATHS = [
    ("/.git/config", "Exposed .git repository", Severity.HIGH),
    ("/.env", "Exposed .env file", Severity.CRITICAL),
    ("/robots.txt", "robots.txt", Severity.INFO),
    ("/sitemap.xml", "sitemap.xml", Severity.INFO),
    ("/admin", "Admin panel", Severity.MEDIUM),
    ("/actuator/health", "Spring actuator exposed", Severity.MEDIUM),
    ("/debug", "Debug endpoint", Severity.MEDIUM),
    ("/.well-known/security.txt", "security.txt", Severity.INFO),
    ("/graphql", "GraphQL endpoint", Severity.INFO),
    ("/swagger.json", "Swagger/OpenAPI spec", Severity.LOW),
    ("/api/swagger.json", "Swagger/OpenAPI spec", Severity.LOW),
    ("/openapi.json", "Swagger/OpenAPI spec", Severity.LOW),
    ("/api/openapi.json", "Swagger/OpenAPI spec", Severity.LOW),
    ("/.well-known/openapi.json", "Swagger/OpenAPI spec", Severity.LOW),
    ("/v1/openapi.json", "Swagger/OpenAPI spec", Severity.LOW),
]

# Paths worth trying to parse as an actual API spec (not just flagging that
# something answered) — feeds the same endpoint-seeding path `--api-spec`
# uses (roadmap v1.0.1 follow-up C), so an API-only target like VAmPI, whose
# whole surface a link-crawler can never see, still gets tested.
_SPEC_PATHS = {p for p, label, _ in _COMMON_PATHS if "OpenAPI" in label}

_SECURITY_HEADERS = [
    "content-security-policy", "x-frame-options", "strict-transport-security",
    "x-content-type-options",
]


class ReconBot(BaseAgent):
    name = "ReconBot"
    description = "maps endpoints & gathers intelligence"

    async def run(self, ctx: AttackContext) -> AgentReport:
        report = AgentReport(agent=self.name, status="running")
        base = ctx.base_url

        root = await self.get(ctx, base + "/")
        if root is None:
            report.status = "error"
            report.notes.append("target unreachable")
            ctx.emit(self.name, f"target {base} unreachable", "crit")
            return report

        self._fingerprint(ctx, root)
        self._check_security_headers(ctx, root)

        # seed the root endpoint and crawl discovered links one level deep
        ctx.add_endpoint(Endpoint(url=base + "/", method="GET", source="root",
                                  sample_status=root.status_code))
        discovered = self._extract(ctx, base, root.text or "")
        ctx.emit(self.name, f"parsed root — found {len(discovered)} link(s)")

        # fetch discovered same-origin pages to widen the surface
        same_origin = [u for u in discovered if self._same_origin(base, u)][:25]
        responses = await gather_limited([self.get(ctx, u) for u in same_origin], limit=ctx.semaphore._value or 8)
        for url, resp in zip(same_origin, responses):
            if resp is None:
                continue
            ep = ctx.endpoints.get(f"GET {url}")
            if ep:
                ep.sample_status = resp.status_code
            if "text/html" in (resp.headers.get("content-type", "")):
                self._extract(ctx, base, resp.text or "")

        await self._probe_common(ctx, base)
        await self._js_crawl(ctx, base)

        report.requests_sent = ctx.requests_sent
        report.findings = len(ctx.findings)
        report.status = "complete"
        endpoints = ctx.endpoint_list()
        ctx.recon["endpoint_count"] = len(endpoints)
        ctx.emit(self.name, f"mapped {len(endpoints)} endpoint(s) across the target", "ok")
        return report

    # ------------------------------------------------------------------ #
    def _fingerprint(self, ctx: AttackContext, resp) -> None:
        h = resp.headers
        stack = {k: h[k] for k in ("server", "x-powered-by", "x-aspnet-version") if k in h}
        ctx.recon["stack"] = stack
        ctx.recon["cookies"] = list(resp.cookies.keys())
        if stack:
            ctx.emit(self.name, "stack: " + ", ".join(f"{k}={v}" for k, v in stack.items()))

    def _check_security_headers(self, ctx: AttackContext, resp) -> None:
        present = {k.lower() for k in resp.headers.keys()}
        missing = [hh for hh in _SECURITY_HEADERS if hh not in present]
        if missing:
            ctx.report(Finding(
                title="Missing security headers",
                severity=Severity.LOW,
                category="misconfig",
                detector="reconbot",
                endpoint=ctx.base_url + "/",
                evidence="missing: " + ", ".join(missing),
                description="The application does not set "
                            + ", ".join(missing)
                            + ", weakening defence-in-depth against XSS/clickjacking/MITM.",
                fix="Set the missing headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options).",
                cwe="CWE-693",
                poc=build_http_poc("GET", ctx.base_url + "/", resp),
            ))

    def _extract(self, ctx: AttackContext, base: str, html: str) -> list[str]:
        urls: list[str] = []
        for raw in _LINK_RE.findall(html):
            if raw.startswith(("mailto:", "tel:", "javascript:", "data:")):
                continue
            absolute = urljoin(base + "/", raw)
            urls.append(absolute)
            parsed = urlparse(absolute)
            params = list(parse_qs(parsed.query).keys())
            clean = absolute.split("?")[0]
            ctx.add_endpoint(Endpoint(url=clean, method="GET", params=params, source="link"))

        for form_match in _FORM_RE.finditer(html):
            attrs, form_html = form_match.group(1), form_match.group(2)
            action_m = _FORM_ACTION_RE.search(attrs)
            action = action_m.group(1) if action_m else ""
            method = "GET"
            method_m = _FORM_METHOD_RE.search(attrs)
            if method_m:
                method = method_m.group(1).upper() or "GET"
            names = _INPUT_NAME_RE.findall(form_html)
            target = urljoin(base + "/", action) if action else base + "/"
            ctx.add_endpoint(Endpoint(url=target.split("?")[0], method=method,
                                      params=names, source="form"))
        return urls

    @staticmethod
    def _same_origin(base: str, url: str) -> bool:
        b, u = urlparse(base), urlparse(url)
        return (u.scheme in ("http", "https")) and (u.netloc == b.netloc)

    async def _probe_common(self, ctx: AttackContext, base: str) -> None:
        async def probe(path: str, label: str, sev: Severity):
            resp = await self.get(ctx, base + path)
            if resp is None or resp.status_code >= 400:
                return
            body = (resp.text or "")[:400]
            if path == "/robots.txt" and resp.status_code == 200:
                for line in body.splitlines():
                    if line.lower().startswith(("disallow", "allow")):
                        loc = line.split(":", 1)[-1].strip()
                        if loc and loc != "/":
                            ctx.add_endpoint(Endpoint(url=urljoin(base, loc), source="robots"))
                return
            if path == "/graphql":
                ctx.recon["graphql"] = True
            if path in _SPEC_PATHS:
                self._seed_from_spec(ctx, base, path, body_full=resp.text or "")
            if sev is Severity.INFO:
                return
            ctx.report(Finding(
                title=label,
                severity=sev,
                category="infrastructure",
                detector="reconbot",
                endpoint=base + path,
                evidence=f"HTTP {resp.status_code} at {path}",
                description=f"{label} is reachable without authentication.",
                fix="Restrict or remove this resource from the public surface.",
                cwe="CWE-200",
                poc=build_http_poc("GET", base + path, resp),
            ))

        await gather_limited(
            [probe(p, label, sev) for p, label, sev in _COMMON_PATHS],
            limit=ctx.semaphore._value or 8,
        )

    async def _js_crawl(self, ctx: AttackContext, base: str) -> None:
        """JS-aware crawl (roadmap v1.0.1 follow-up A): a regex-over-server-HTML
        crawl is blind to a client-rendered SPA (Angular/React/Vue) — its real
        markup and its XHR/fetch calls to the API only exist after JS runs.
        Reuses DomXSSHunter's optional Playwright dependency: silently skipped,
        zero cost, when it isn't installed (same graceful-degrade pattern as
        Semgrep/domxss); auto-runs otherwise, no extra flag needed, mirroring
        the zero-flag OpenAPI auto-discovery (follow-up C)."""
        if async_playwright is None:
            return

        requests_seen: list[tuple[str, str, list[str]]] = []

        def _on_request(request) -> None:
            if request.resource_type not in ("xhr", "fetch"):
                return
            if not self._same_origin(base, request.url):
                return
            parsed = urlparse(request.url)
            params = list(parse_qs(parsed.query).keys())
            requests_seen.append((request.method, request.url.split("?")[0], params))

        rendered_html = ""
        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch()
                try:
                    browser_ctx = await browser.new_context(extra_http_headers=dict(ctx.client.headers))
                    cookies = [{"name": n, "value": v, "url": base} for n, v in ctx.client.cookies.items()]
                    if cookies:
                        await browser_ctx.add_cookies(cookies)
                    page = await browser_ctx.new_page()
                    page.on("request", _on_request)
                    await page.goto(base + "/", timeout=10000, wait_until="networkidle")
                    rendered_html = await page.content()
                finally:
                    await browser.close()
        except Exception:
            ctx.emit(self.name, "JS-aware crawl skipped (headless browser error)")
            return

        js_links = self._extract(ctx, base, rendered_html) if rendered_html else []
        for method, url, params in requests_seen:
            ctx.add_endpoint(Endpoint(url=url, method=method, params=params, source="js-xhr"))

        if js_links or requests_seen:
            ctx.emit(self.name, f"JS-aware crawl: {len(js_links)} link(s) in the rendered DOM, "
                                 f"{len(requests_seen)} XHR/fetch call(s) invisible to a static crawl")

    def _seed_from_spec(self, ctx: AttackContext, base: str, path: str, body_full: str) -> None:
        """A common-path probe hit what might be an OpenAPI/Swagger spec — try
        parsing it and seed every endpoint it declares. Silent no-op if it
        wasn't actually a spec (e.g. a 200 HTML error page)."""
        from argus.apispec import ApiSpecError, parse_spec_text

        try:
            endpoints, note = parse_spec_text(body_full, base)
        except ApiSpecError:
            return
        for ep in endpoints:
            ctx.add_endpoint(ep)
        if endpoints:
            ctx.emit(self.name, f"auto-discovered API spec at {path} — {note}")
