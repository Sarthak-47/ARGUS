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

from argus.agents.base import AgentReport, AttackContext, BaseAgent, Endpoint, gather_limited
from argus.models import Finding, Severity

_LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*['"]([^'"#]+)['"]""", re.IGNORECASE)
_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
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
]

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

        for form_html in _FORM_RE.findall(html):
            action = (_FORM_ACTION_RE.search(form_html) or [None, ""])[1] if _FORM_ACTION_RE.search(form_html) else ""
            method = "GET"
            m = _FORM_METHOD_RE.search(form_html)
            if m:
                method = m.group(1).upper() or "GET"
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
            ))

        await gather_limited(
            [probe(p, label, sev) for p, label, sev in _COMMON_PATHS],
            limit=ctx.semaphore._value or 8,
        )
