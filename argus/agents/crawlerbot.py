"""CrawlerBot — wordlist-based content & path discovery.

Probes a bundled subset of high-signal paths: backup files, exposed VCS, config
and secret files, admin panels, debug/metrics endpoints, API docs and source maps.
A baseline 404 fingerprint is captured first so we only report paths that respond
differently from "not found" (defeats catch-all 200 handlers).
"""

from __future__ import annotations

from argus.agents.base import AgentReport, AttackContext, BaseAgent, Endpoint, build_http_poc, gather_limited
from argus.models import Finding, Severity

# (path, label, severity) — a compact, high-value slice of a SecLists-style list.
_PATHS: list[tuple[str, str, Severity]] = [
    ("/.env", "Exposed .env file", Severity.CRITICAL),
    ("/.env.local", "Exposed .env.local file", Severity.CRITICAL),
    ("/.env.production", "Exposed production .env", Severity.CRITICAL),
    ("/.git/config", "Exposed .git/config", Severity.HIGH),
    ("/.git/HEAD", "Exposed .git/HEAD", Severity.HIGH),
    ("/config.json", "Exposed config.json", Severity.HIGH),
    ("/secrets.json", "Exposed secrets.json", Severity.CRITICAL),
    ("/database.yml", "Exposed database.yml", Severity.CRITICAL),
    ("/backup.zip", "Exposed backup archive", Severity.HIGH),
    ("/backup.sql", "Exposed SQL dump", Severity.CRITICAL),
    ("/dump.sql", "Exposed SQL dump", Severity.CRITICAL),
    ("/app.js.map", "Exposed source map", Severity.LOW),
    ("/main.js.map", "Exposed source map", Severity.LOW),
    ("/wp-admin/", "WordPress admin panel", Severity.MEDIUM),
    ("/phpmyadmin/", "phpMyAdmin panel", Severity.HIGH),
    ("/admin/", "Admin panel", Severity.MEDIUM),
    ("/dashboard/", "Dashboard panel", Severity.LOW),
    ("/jenkins/", "Jenkins panel", Severity.HIGH),
    ("/actuator", "Spring actuator", Severity.MEDIUM),
    ("/actuator/env", "Spring actuator env (secrets)", Severity.HIGH),
    ("/metrics", "Metrics endpoint", Severity.LOW),
    ("/debug", "Debug endpoint", Severity.MEDIUM),
    ("/server-status", "Apache server-status", Severity.MEDIUM),
    ("/swagger-ui.html", "Swagger UI", Severity.LOW),
    ("/openapi.json", "OpenAPI spec", Severity.LOW),
    ("/api-docs", "API docs", Severity.LOW),
    ("/.DS_Store", "Exposed .DS_Store", Severity.LOW),
    ("/.htaccess", "Exposed .htaccess", Severity.MEDIUM),
    ("/web.config", "Exposed web.config", Severity.MEDIUM),
    ("/.npmrc", "Exposed .npmrc (may contain tokens)", Severity.HIGH),
]

# Backup suffixes appended to already-known endpoints.
_BACKUP_SUFFIXES = [".bak", ".old", "~", ".swp", ".orig", ".save"]


class CrawlerBot(BaseAgent):
    name = "CrawlerBot"
    description = "route discovery"

    async def run(self, ctx: AttackContext) -> AgentReport:
        report = AgentReport(agent=self.name, status="running")
        base = ctx.base_url

        not_found = await self._fingerprint_404(ctx)
        ctx.emit(self.name, f"fuzzing {len(_PATHS)} common paths …")

        async def probe(path: str, label: str, sev: Severity):
            resp = await self.get(ctx, base + path)
            if resp is None or resp.status_code in (404, 401, 403):
                return
            if resp.status_code >= 500:
                return
            body = resp.text or ""
            if not_found and self._similar(body, not_found):
                return
            if resp.status_code < 400:
                ctx.add_endpoint(Endpoint(url=base + path, source="crawl"))
                ctx.report(Finding(
                    title=label,
                    severity=sev,
                    category="infrastructure",
                    detector="crawlerbot",
                    endpoint=base + path,
                    evidence=f"HTTP {resp.status_code} ({len(body)} bytes) at {path}",
                    description=f"{label} is reachable without authentication.",
                    fix="Remove the file from the web root or require authentication / block the path.",
                    cwe="CWE-200",
                    confidence="medium",
                    poc=build_http_poc("GET", base + path, resp),
                ))

        await gather_limited([probe(p, label, sev) for p, label, sev in _PATHS], limit=ctx.semaphore._value or 8)
        await self._backup_sweep(ctx, not_found)

        report.requests_sent = ctx.requests_sent
        report.findings = len([f for f in ctx.findings if f.detector == "crawlerbot"])
        report.status = "complete"
        ctx.emit(self.name, f"crawl complete — surface map updated ({len(ctx.endpoints)} endpoints)", "ok")
        return report

    async def _fingerprint_404(self, ctx: AttackContext) -> str | None:
        resp = await self.get(ctx, ctx.base_url + "/argus-not-here-" + "x9z7")
        return (resp.text or "")[:500] if resp is not None else None

    async def _backup_sweep(self, ctx: AttackContext, not_found: str | None) -> None:
        # Try backup suffixes on a few known file-like endpoints.
        candidates = [ep.url for ep in ctx.endpoint_list() if "." in ep.url.rsplit("/", 1)[-1]][:8]

        async def probe(url: str, suffix: str):
            target = url + suffix
            resp = await self.get(ctx, target)
            if resp is None or resp.status_code >= 400:
                return
            if not_found and self._similar(resp.text or "", not_found):
                return
            ctx.report(Finding(
                title="Exposed backup/temporary file",
                severity=Severity.HIGH,
                category="infrastructure",
                detector="crawlerbot",
                endpoint=target,
                evidence=f"HTTP {resp.status_code} at {target}",
                description="A backup or editor temp copy of a source file is downloadable, "
                            "potentially leaking source code or credentials.",
                fix="Remove backup/temp files from the web root; add them to deploy ignore lists.",
                cwe="CWE-530",
                confidence="medium",
                poc=build_http_poc("GET", target, resp),
            ))

        coros = [probe(u, s) for u in candidates for s in _BACKUP_SUFFIXES]
        await gather_limited(coros, limit=ctx.semaphore._value or 8)

    @staticmethod
    def _similar(a: str, b: str) -> bool:
        """Crude similarity: same length bucket and shared prefix => likely same 404 page."""
        if abs(len(a) - len(b)) <= 24:
            return a[:200] == b[:200]
        return False
