"""RaceCondition — concurrency and rate-limit weaknesses.

Fires a burst of simultaneous identical requests at state-changing endpoints. If
every request succeeds and none are throttled (no 429 / lockout), the endpoint
lacks rate limiting and is likely vulnerable to race conditions (double-spend,
coupon reuse) and brute force. Uses asyncio to send the burst concurrently.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from argus.agents.base import AgentReport, AttackContext, BaseAgent, Endpoint, build_http_poc
from argus.models import Finding, Severity

_BURST = 20
# Endpoints whose names suggest a sensitive, stateful action.
_SENSITIVE = ("login", "redeem", "coupon", "voucher", "transfer", "purchase", "buy",
              "checkout", "vote", "like", "withdraw", "register", "signup", "apply")


class RaceCondition(BaseAgent):
    name = "RaceCondition"
    description = "concurrency flaws"

    async def run(self, ctx: AttackContext) -> AgentReport:
        report = AgentReport(agent=self.name, status="running")
        targets = self._targets(ctx)
        if not targets:
            ctx.emit(self.name, "no state-changing endpoints to race")
            report.status = "complete"
            return report

        flagged = 0
        for ep in targets:
            ctx.emit(self.name, f"firing {_BURST} parallel requests at {self._short(ep.url)} …")
            data = {p: "1" for p in ep.params} or {"x": "1"}
            results = await asyncio.gather(
                *[self._request(ctx, ep.method, ep.url, data=data) for _ in range(_BURST)]
            )
            statuses = [r.status_code for r in results if r is not None]
            if not statuses:
                continue
            throttled = any(s in (429, 423) for s in statuses)
            ok = sum(1 for s in statuses if s < 400)
            if not throttled and ok >= _BURST - 1:
                flagged += 1
                ctx.report(Finding(
                    title="No rate limiting (race / brute-force window)",
                    severity=Severity.MEDIUM,
                    category="dos",
                    detector="racecondition",
                    endpoint=f"{ep.method} {ep.url}",
                    evidence=f"{ok}/{_BURST} concurrent requests succeeded, none throttled (no 429)",
                    description="The endpoint processed a concurrent burst with no rate limiting or "
                                "locking, exposing it to race conditions (double-spend, coupon reuse) "
                                "and brute-force attacks.",
                    exploit="Send parallel requests to redeem a single-use action multiple times, or "
                            "brute-force credentials/OTPs without lockout.",
                    fix="Add rate limiting and per-resource locking / atomic compare-and-set "
                        "(e.g. SELECT ... FOR UPDATE) on sensitive actions.",
                    cwe="CWE-362",
                    confidence="medium",
                    poc=build_http_poc(
                        ep.method, ep.url, next(r for r in results if r is not None),
                        body=str(data),
                    ),
                ))

        report.requests_sent = ctx.requests_sent
        report.findings = len([f for f in ctx.findings if f.detector == "racecondition"])
        report.status = "complete"
        ctx.emit(self.name, f"sweep complete — {flagged} unthrottled endpoint(s)", "ok")
        return report

    def _targets(self, ctx: AttackContext) -> list[Endpoint]:
        out: list[Endpoint] = []
        for ep in ctx.endpoint_list():
            name = ep.url.lower()
            if ep.method == "POST" or any(s in name for s in _SENSITIVE):
                out.append(ep)
        return out[:5]

    @staticmethod
    def _short(url: str) -> str:
        p = urlparse(url)
        return (p.path or "/") + ("?" + p.query if p.query else "")
