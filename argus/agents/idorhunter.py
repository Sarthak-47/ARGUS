"""IDORHunter — broken object-level authorization (IDOR / BOLA).

Without injected credentials this runs the unauthenticated heuristic: find numeric
object identifiers (in a path segment like /orders/123 or an ``id`` parameter),
request neighbouring IDs, and report when distinct valid objects come back with no
authentication — a strong signal of missing ownership/access checks.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from argus.agents.base import AgentReport, AttackContext, BaseAgent, build_http_poc
from argus.models import Finding, Severity

_INT_SEG = re.compile(r"/(\d{1,12})(?=/|$)")


def _replace_path_int(url: str, original: str, new: str) -> str:
    parsed = urlparse(url)
    new_path = parsed.path.replace(f"/{original}", f"/{new}", 1)
    return urlunparse(parsed._replace(path=new_path))


def _with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [value]
    new_q = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse(parsed._replace(query=new_q))


class IDORHunter(BaseAgent):
    name = "IDORHunter"
    description = "broken object access"

    async def run(self, ctx: AttackContext) -> AgentReport:
        report = AgentReport(agent=self.name, status="running")
        candidates = self._candidates(ctx)
        if not candidates:
            ctx.emit(self.name, "no numeric object identifiers found")
            report.status = "complete"
            return report

        flagged: set[str] = set()
        for kind, url, key in candidates:
            ctx.emit(self.name, f"enumerating {self._short(url)} …")
            if kind == "path":
                await self._probe_path(ctx, url, key, flagged)
            else:
                await self._probe_param(ctx, url, key, flagged)

        report.requests_sent = ctx.requests_sent
        report.findings = len([f for f in ctx.findings if f.detector.startswith("idorhunter")])
        report.status = "complete"
        ctx.emit(self.name, f"sweep complete — {len(flagged)} IDOR candidate(s)", "ok")
        return report

    def _candidates(self, ctx: AttackContext) -> list[tuple[str, str, str]]:
        out: list[tuple[str, str, str]] = []
        seen: set[str] = set()
        for ep in ctx.endpoint_list():
            if ep.method != "GET":
                continue
            m = _INT_SEG.search(urlparse(ep.url).path)
            if m and ep.url not in seen:
                seen.add(ep.url)
                out.append(("path", ep.url, m.group(1)))
            for p in ep.params:
                if p.lower() in ("id", "user", "userid", "user_id", "account", "order", "oid", "pid"):
                    out.append(("param", ep.url, p))
        return out[:15]

    async def _probe_path(self, ctx: AttackContext, url: str, original: str, flagged: set) -> None:
        base = await self.get(ctx, url)
        if base is None or base.status_code >= 400:
            return
        n = int(original)
        bodies = {(base.text or "")[:300]}
        hits = 0
        last_resp = None
        last_url = url
        for cand in (n - 1, n + 1, n + 2):
            if cand < 0:
                continue
            cand_url = _replace_path_int(url, original, str(cand))
            resp = await self.get(ctx, cand_url)
            if resp is not None and resp.status_code == base.status_code and resp.status_code < 400:
                snippet = (resp.text or "")[:300]
                if snippet not in bodies:
                    bodies.add(snippet)
                    hits += 1
                    last_resp, last_url = resp, cand_url
        if hits >= 2:
            flagged.add(url)
            self._report(ctx, f"GET {url}", original, "path segment", last_url, last_resp)

    async def _probe_param(self, ctx: AttackContext, url: str, param: str, flagged: set) -> None:
        base = await self.get(ctx, _with_param(url, param, "1"))
        if base is None or base.status_code >= 400:
            return
        bodies = {(base.text or "")[:300]}
        hits = 0
        last_resp = None
        last_url = url
        for cand in ("2", "3", "1000"):
            cand_url = _with_param(url, param, cand)
            resp = await self.get(ctx, cand_url)
            if resp is not None and resp.status_code < 400:
                snippet = (resp.text or "")[:300]
                if snippet not in bodies:
                    bodies.add(snippet)
                    hits += 1
                    last_resp, last_url = resp, cand_url
        if hits >= 2:
            sig = f"{url}::{param}"
            flagged.add(sig)
            self._report(ctx, f"GET {url}", param, f"'{param}' parameter", last_url, last_resp)

    def _report(self, ctx: AttackContext, endpoint: str, key: str, where: str,
                poc_url: str | None = None, resp=None) -> None:
        ctx.report(Finding(
            title="Insecure Direct Object Reference (IDOR)",
            severity=Severity.HIGH,
            category="access-control",
            detector="idorhunter",
            endpoint=endpoint,
            evidence=f"enumerating the {where} returned distinct objects without authentication",
            description=f"Object identifiers ({where}) can be enumerated to read other objects "
                        f"with no ownership/authorization check.",
            exploit="Increment/replace the identifier to access other users' records.",
            fix="Enforce per-object ownership/authorization on every access; use unguessable IDs.",
            cwe="CWE-639",
            cvss=8.1,
            confidence="medium",
            poc=build_http_poc("GET", poc_url, resp) if resp is not None else {},
        ))

    @staticmethod
    def _short(url: str) -> str:
        p = urlparse(url)
        return (p.path or "/") + ("?" + p.query if p.query else "")
