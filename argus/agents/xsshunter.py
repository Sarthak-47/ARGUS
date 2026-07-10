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

# Static assets can't reflect input and only crowd out real targets under the
# work cap (an authenticated app surfaces dozens of .css/.png/.js URLs).
_STATIC_SUFFIXES = (
    ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webp", ".pdf",
)


def _is_static_asset(url: str) -> bool:
    return urlparse(url).path.lower().rstrip("/").endswith(_STATIC_SUFFIXES)


def _with_param(url: str, param: str, value: str, base_params: dict | None = None) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if base_params:
        qs.update({k: [v] for k, v in base_params.items()})
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
            # Fill sibling params (a form's submit button, etc.) so the target
            # reaches the code that echoes our input — some pages only render
            # the reflection once the whole form is submitted.
            siblings = {p: "1" for p in (ep.params or []) if p != param}
            url = _with_param(ep.url, param, payload, base_params=siblings)
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
        # Real declared params before guesses, and never spend the cap on
        # static assets — otherwise an authenticated app's asset URLs crowd
        # out the actual reflective endpoints.
        declared: list[tuple[Endpoint, str]] = []
        guessed: list[tuple[Endpoint, str]] = []
        for ep in ctx.endpoint_list():
            if ep.method != "GET" or _is_static_asset(ep.url):
                continue
            if ep.params:
                declared.extend((ep, p) for p in ep.params)
            else:
                guessed.extend((ep, p) for p in _GUESS_PARAMS[:4])
        return (declared + guessed)[:90]

    @staticmethod
    def _short(url: str) -> str:
        p = urlparse(url)
        return (p.path or "/") + ("?" + p.query if p.query else "")
