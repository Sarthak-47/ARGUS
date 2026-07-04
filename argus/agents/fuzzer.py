"""Fuzzer — malformed-input fuzzing to surface poor input handling.

Sends boundary, type-confusion, oversized, format-string and null-byte payloads at
each parameter and watches for server errors (HTTP 5xx) or stack-trace/exception
disclosure that the baseline request did not produce — both signal missing input
validation and potential information leakage.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from argus.agents.base import AgentReport, AttackContext, BaseAgent, Endpoint, build_http_poc
from argus.models import Finding, Severity

_PAYLOADS = [
    ("oversized", "A" * 8000),
    ("negative", "-1"),
    ("big-int", "99999999999999999999999999"),
    ("format-string", "%s%s%s%n%x"),
    ("null-byte", "x%00y"),
    ("type-array", "[]"),
    ("type-object", "{}"),
    ("unicode", "".join(chr(c) for c in (0x202e, 0x200b, 0xfeff, 0x1f4a5))),
]

_ERROR_SIG = re.compile(
    r"(Traceback \(most recent call last\)|Exception|at [\w.$]+\([\w.]+:\d+\)|"
    r"java\.lang\.|System\.\w+Exception|stack trace|Fatal error|Warning:|Notice:|"
    r"undefined index|TypeError|ValueError|panic:)",
    re.IGNORECASE,
)
_GUESS_PARAMS = ["id", "q", "n", "page", "limit", "search", "name", "amount"]


def _with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [value]
    new_q = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse(parsed._replace(query=new_q))


class Fuzzer(BaseAgent):
    name = "Fuzzer"
    description = "parameter fuzzing"

    async def run(self, ctx: AttackContext) -> AgentReport:
        report = AgentReport(agent=self.name, status="running")
        targets = self._targets(ctx)
        if not targets:
            ctx.emit(self.name, "no parameters to fuzz")
            report.status = "complete"
            return report

        flagged: set[str] = set()
        for ep, param in targets:
            sig = f"{ep.url}::{param}"
            if sig in flagged:
                continue
            base = await self.get(ctx, _with_param(ep.url, param, "1"))
            base_status = base.status_code if base is not None else 0
            ctx.emit(self.name, f"fuzzing {param} on {self._short(ep.url)} …")
            for label, payload in _PAYLOADS:
                resp = await self.get(ctx, _with_param(ep.url, param, payload))
                if resp is None:
                    continue
                body = resp.text or ""
                server_error = resp.status_code >= 500 and base_status < 500
                leaked = bool(_ERROR_SIG.search(body)) and not (base and _ERROR_SIG.search(base.text or ""))
                if server_error or leaked:
                    flagged.add(sig)
                    ctx.report(Finding(
                        title="Improper input handling / error disclosure",
                        severity=Severity.MEDIUM if leaked else Severity.LOW,
                        category="dos",
                        detector="fuzzer",
                        endpoint=f"{ep.method} {ep.url}",
                        evidence=f"param '{param}' + {label} payload -> HTTP {resp.status_code}"
                                 + (" with stack trace/exception" if leaked else ""),
                        description=f"A malformed value ({label}) in '{param}' caused "
                                    + ("an unhandled error exposing internal details."
                                       if leaked else "a server error (5xx)."),
                        exploit="Malformed input can crash handlers or leak stack traces aiding further attacks.",
                        fix="Validate and constrain input types/length; return generic errors; never leak stack traces.",
                        cwe="CWE-20",
                        confidence="medium" if leaked else "low",
                        poc=build_http_poc(ep.method, _with_param(ep.url, param, payload), resp),
                    ))
                    break

        report.requests_sent = ctx.requests_sent
        report.findings = len([f for f in ctx.findings if f.detector == "fuzzer"])
        report.status = "complete"
        ctx.emit(self.name, f"fuzzing complete — {len(flagged)} weak handler(s)", "ok")
        return report

    def _targets(self, ctx: AttackContext) -> list[tuple[Endpoint, str]]:
        out: list[tuple[Endpoint, str]] = []
        for ep in ctx.endpoint_list():
            if ep.method != "GET":
                continue
            for p in (ep.params or _GUESS_PARAMS[:3]):
                out.append((ep, p))
        return out[:40]

    @staticmethod
    def _short(url: str) -> str:
        p = urlparse(url)
        return (p.path or "/") + ("?" + p.query if p.query else "")
