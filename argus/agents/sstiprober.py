"""SSTIProber — server-side template injection (CWE-94, code/template injection).

Injects an arithmetic expression in each template engine's own syntax
(``{{7*7}}`` for Jinja2/Twig, ``${7*7}`` for FreeMarker/Velocity/Thymeleaf,
``#{7*7}`` for Ruby/JSF EL, ``<%= 7*7 %>`` for ERB) and looks for the
*evaluated* result (49, or 7777777 for Jinja2's string-repeat trick) in the
response — not the literal payload merely echoed back, which is reflected
input, not template injection.

Two false-positive guards, in the same spirit as the baseline-comparison
fix applied to ReconBot/CrawlerBot/AuthzTester/HeaderPoker (see base.py):
a control request with an inert value must NOT already contain the marker
(a page that legitimately shows "49" somewhere would otherwise falsely
confirm every candidate), and the payload response must contain the
evaluated marker while NOT containing the raw payload string — proving
execution, not just reflection.
"""

from __future__ import annotations

from argus.agents.base import AgentReport, AttackContext, BaseAgent, Endpoint, build_http_poc
from argus.agents.injector import _GUESS_PARAMS, _is_static_asset, _with_param
from argus.models import Finding, Severity

# (payload, evaluated-marker, engine label). The Jinja2 string-repeat variant
# ({{7*'7'}} -> '7777777') is included because a bare {{7*7}} -> "49" collides
# with the arithmetic marker other engines already produce; keeping a
# Jinja2-distinctive marker lets a confirmed finding also name the engine.
_SSTI_PAYLOADS: list[tuple[str, str, str]] = [
    ("{{7*'7'}}", "7777777", "Jinja2/Twig (string-repeat)"),
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("${7*7}", "49", "FreeMarker/Velocity/Thymeleaf"),
    ("#{7*7}", "49", "Ruby ERB / JSF EL"),
    ("<%= 7*7 %>", "49", "ERB"),
]

_CONTROL_VALUE = "argus-ssti-control-zzz"


class SSTIProber(BaseAgent):
    name = "SSTIProber"
    description = "server-side template injection"

    async def run(self, ctx: AttackContext) -> AgentReport:
        report = AgentReport(agent=self.name, status="running")
        targets = self._targets(ctx)
        if not targets:
            ctx.emit(self.name, "no injectable parameters discovered")
            report.status = "complete"
            return report

        confirmed: set[str] = set()
        for ep, param in targets:
            sig = f"{ep.url}::{param}"
            if sig in confirmed:
                continue
            if await self._probe(ctx, ep, param):
                confirmed.add(sig)

        report.requests_sent = ctx.requests_sent
        report.findings = len([f for f in ctx.findings if f.detector == "sstiprober"])
        report.status = "complete"
        ctx.emit(self.name, f"sweep complete — {len(confirmed)} confirmed", "ok")
        return report

    def _targets(self, ctx: AttackContext) -> list[tuple[Endpoint, str]]:
        declared: list[tuple[Endpoint, str]] = []
        guessed: list[tuple[Endpoint, str]] = []
        for ep in ctx.endpoint_list():
            if ep.method not in ("GET", "POST") or _is_static_asset(ep.url):
                continue
            if ep.params:
                declared.extend((ep, p) for p in ep.params)
            else:
                guessed.extend((ep, p) for p in _GUESS_PARAMS[:3])
        return (declared + guessed)[:80]

    async def _probe(self, ctx: AttackContext, ep: Endpoint, param: str) -> bool:
        siblings = {p: "1" for p in (ep.params or []) if p != param}

        control_url = _with_param(ep.url, param, _CONTROL_VALUE, base_params=siblings)
        control_resp = await self.get(ctx, control_url)
        if control_resp is None:
            return False
        control_body = control_resp.text or ""

        for payload, marker, engine in _SSTI_PAYLOADS:
            # A page that already shows this marker for an unrelated reason
            # (an order total of 49, a page listing "49 results") would
            # otherwise false-positive on every request — skip a marker
            # already present before the payload is even sent.
            if marker in control_body:
                continue

            url = _with_param(ep.url, param, payload, base_params=siblings)
            resp = await self.get(ctx, url)
            if resp is None:
                continue
            body = resp.text or ""
            # The evaluated result must appear, and the raw payload must NOT —
            # otherwise this is input reflection (XSSHunter's territory), not
            # server-side evaluation.
            if marker in body and payload not in body:
                ctx.report(Finding(
                    title="Server-side template injection (SSTI)",
                    severity=Severity.CRITICAL,
                    category="injection",
                    detector="sstiprober",
                    endpoint=f"{ep.method} {ep.url}",
                    evidence=f"param '{param}' payload {payload!r} evaluated to {marker!r} "
                             f"(likely engine: {engine})",
                    description=f"Injecting '{param}' with a template expression was evaluated "
                                f"server-side rather than treated as plain text — the arithmetic "
                                f"result appeared in the response, and the raw payload did not.",
                    exploit="SSTI on most engines escalates to remote code execution via the "
                            "engine's own sandbox-escape gadgets (e.g. Jinja2's "
                            "__class__.__mro__ chain), not just data disclosure.",
                    fix="Never render untrusted input as a template string; treat all user input "
                        "as data passed into a template's context, never as template source.",
                    cwe="CWE-94",
                    cvss=9.8,
                    confidence="high",
                    poc=build_http_poc(ep.method, url, resp),
                ))
                return True
        return False
