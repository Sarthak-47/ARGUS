"""XSSHunter — reflected cross-site scripting detection.

For each parameter on each endpoint, injects a uniquely-tagged payload and checks
whether it is reflected into the response *unencoded* (the raw ``<`` / ``>`` and the
marker survive). A unique token per probe prevents false matches against unrelated
page content. Stored and DOM XSS are deeper follow-ups; reflected is the reliable,
verifiable baseline here.
"""

from __future__ import annotations

import uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from argus.agents.base import AgentReport, AttackContext, BaseAgent, Endpoint, build_http_poc
from argus.models import Finding, Severity

_GUESS_PARAMS = ["q", "search", "name", "query", "s", "id", "redirect", "next", "msg", "error"]


def _with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [value]
    new_q = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse(parsed._replace(query=new_q))


class XSSHunter(BaseAgent):
    name = "XSSHunter"
    description = "cross-site scripting"

    async def run(self, ctx: AttackContext) -> AgentReport:
        report = AgentReport(agent=self.name, status="running")
        targets = self._targets(ctx)
        if not targets:
            ctx.emit(self.name, "no reflective parameters to test")
            report.status = "complete"
            return report

        confirmed: set[str] = set()
        for ep, param in targets:
            sig = f"{ep.url}::{param}"
            if sig in confirmed:
                continue
            token = "argus" + uuid.uuid4().hex[:6]
            payload = f"<{token}>\"'"
            url = _with_param(ep.url, param, payload)
            ctx.emit(self.name, f"injecting into {param} on {self._short(ep.url)} …")
            resp = await self.get(ctx, url)
            if resp is None:
                continue
            body = resp.text or ""
            ctype = resp.headers.get("content-type", "")
            if f"<{token}>" in body and "html" in ctype.lower():
                confirmed.add(sig)
                ctx.report(Finding(
                    title="Reflected XSS",
                    severity=Severity.HIGH,
                    category="xss",
                    detector="xsshunter:reflected",
                    endpoint=f"{ep.method} {ep.url}",
                    evidence=f"param '{param}' reflected unencoded: <{token}> appears verbatim in HTML",
                    description=f"Input to '{param}' is reflected into the HTML response without "
                                f"encoding, so injected markup executes in the victim's browser.",
                    exploit="Deliver a crafted link; the script runs in the victim's session "
                            "(cookie theft, session hijack, actions on their behalf).",
                    fix="Context-encode output (HTML-escape), and apply a strict Content-Security-Policy.",
                    cwe="CWE-79",
                    cvss=6.1,
                    confidence="high",
                    poc=build_http_poc(ep.method, url, resp),
                ))

        report.requests_sent = ctx.requests_sent
        report.findings = len([f for f in ctx.findings if f.detector.startswith("xsshunter")])
        report.status = "complete"
        ctx.emit(self.name, f"sweep complete — {len(confirmed)} reflected", "ok")
        return report

    def _targets(self, ctx: AttackContext) -> list[tuple[Endpoint, str]]:
        out: list[tuple[Endpoint, str]] = []
        for ep in ctx.endpoint_list():
            if ep.method != "GET":
                continue
            for p in (ep.params or _GUESS_PARAMS[:4]):
                out.append((ep, p))
        return out[:60]

    @staticmethod
    def _short(url: str) -> str:
        p = urlparse(url)
        return (p.path or "/") + ("?" + p.query if p.query else "")
