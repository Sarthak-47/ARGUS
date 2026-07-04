"""SSRFProber — server-side request forgery detection.

For parameters that look like they take a URL (url, uri, fetch, callback, dest,
redirect, image, webhook, …), it injects a unique callback URL and watches the
callback server for an inbound hit — proving the server made the request (blind
SSRF). It also flags reflected responses that look like cloud-metadata output when
a metadata URL is supplied.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from argus.agents.base import AgentReport, AttackContext, BaseAgent, Endpoint, build_http_poc
from argus.models import Finding, Severity

_URL_PARAM_HINT = re.compile(
    r"(?i)\b(url|uri|link|src|source|dest|destination|redirect|next|return|callback|"
    r"webhook|fetch|image|img|avatar|proxy|load|file|path|feed|host|domain|site)\b"
)
_METADATA_SIG = re.compile(r"(?i)ami-id|instance-id|iam/security-credentials|AccessKeyId|computeMetadata")
_METADATA_URL = "http://169.254.169.254/latest/meta-data/"


def _with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [value]
    new_q = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse(parsed._replace(query=new_q))


class SSRFProber(BaseAgent):
    name = "SSRFProber"
    description = "server-side requests"

    async def run(self, ctx: AttackContext) -> AgentReport:
        report = AgentReport(agent=self.name, status="running")
        targets = self._targets(ctx)
        if not targets:
            ctx.emit(self.name, "no URL-like parameters to test")
            report.status = "complete"
            return report

        if ctx.callback is None:
            ctx.emit(self.name, "no callback server — running metadata checks only")

        confirmed: set[str] = set()
        # Phase A: blind SSRF via callback
        pending: list[tuple[Endpoint, str, str, str]] = []  # (ep, param, token, probe_url)
        token_responses: dict[str, object] = {}
        if ctx.callback is not None:
            for ep, param in targets:
                token, cb_url = ctx.callback.new_token()
                probe_url = _with_param(ep.url, param, cb_url)
                ctx.emit(self.name, f"probing {param} on {self._short(ep.url)} for internal reach …")
                initial_resp = await self.get(ctx, probe_url)
                pending.append((ep, param, token, probe_url))
                if initial_resp is not None:
                    token_responses[token] = initial_resp
            await asyncio.sleep(1.5)  # give the target time to call back
            for ep, param, token, probe_url in pending:
                if ctx.callback.was_hit(token):
                    sig = f"{ep.url}::{param}"
                    confirmed.add(sig)
                    initial_resp = token_responses.get(token)
                    ctx.report(Finding(
                        title="Server-Side Request Forgery (blind)",
                        severity=Severity.HIGH,
                        category="ssrf",
                        detector="ssrfprober:callback",
                        endpoint=f"{ep.method} {ep.url}",
                        evidence=f"param '{param}' caused the server to request our callback host",
                        description=f"The server fetched an attacker-supplied URL via '{param}', "
                                    f"confirmed by an out-of-band callback.",
                        exploit="Reach internal services or cloud metadata (169.254.169.254) to steal "
                                "credentials and pivot.",
                        fix="Allow-list outbound hosts; block link-local and private ranges; disable redirects.",
                        cwe="CWE-918",
                        cvss=8.6,
                        confidence="high",
                        poc=build_http_poc(ep.method, probe_url, initial_resp) if initial_resp is not None else {},
                    ))

        # Phase B: cloud-metadata reflection
        for ep, param in targets:
            sig = f"{ep.url}::{param}"
            if sig in confirmed:
                continue
            resp = await self.get(ctx, _with_param(ep.url, param, _METADATA_URL))
            if resp is not None and _METADATA_SIG.search(resp.text or ""):
                confirmed.add(sig)
                ctx.report(Finding(
                    title="SSRF to cloud metadata endpoint",
                    severity=Severity.CRITICAL,
                    category="ssrf",
                    detector="ssrfprober:metadata",
                    endpoint=f"{ep.method} {ep.url}",
                    evidence=f"param '{param}' returned cloud-metadata content",
                    description=f"Supplying the metadata URL to '{param}' returned instance metadata, "
                                f"exposing IAM credentials.",
                    exploit="Read IAM role credentials from 169.254.169.254 and assume the role.",
                    fix="Block requests to link-local/metadata addresses; require IMDSv2; allow-list hosts.",
                    cwe="CWE-918",
                    cvss=9.1,
                    confidence="high",
                    poc=build_http_poc(ep.method, _with_param(ep.url, param, _METADATA_URL), resp),
                ))

        report.requests_sent = ctx.requests_sent
        report.findings = len([f for f in ctx.findings if f.detector.startswith("ssrfprober")])
        report.status = "complete"
        ctx.emit(self.name, f"sweep complete — {len(confirmed)} confirmed", "ok")
        return report

    def _targets(self, ctx: AttackContext) -> list[tuple[Endpoint, str]]:
        out: list[tuple[Endpoint, str]] = []
        for ep in ctx.endpoint_list():
            if ep.method not in ("GET", "POST"):
                continue
            for p in ep.params:
                if _URL_PARAM_HINT.search(p):
                    out.append((ep, p))
        return out[:30]

    @staticmethod
    def _short(url: str) -> str:
        p = urlparse(url)
        return (p.path or "/") + ("?" + p.query if p.query else "")
