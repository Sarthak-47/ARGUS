"""BusinessLogicAgent — the flagship differentiator: LLM-driven logic-abuse testing.

Industry-wide, this is the documented, unsolved gap in automated security testing:
roughly 70% of critical web vulnerabilities are business logic flaws, and no
autonomous agent reliably detects them — because there's nothing syntactically
wrong with the code, only the workflow. Every other Argus agent pattern-matches;
this one reasons: it shows the LLM the discovered attack surface, asks for
concrete abuse sequences (coupon stacking, negative quantities, workflow-step
bypass, free-trial abuse), then EXECUTES the proposed requests and confirms
behaviorally rather than trusting the model's claim.

Silently no-ops when no LLM provider is configured (``ctx.provider is None``) —
Argus's raw-scan-only promise holds, and this agent auto-enables the moment a
key/Ollama is set up, with no separate opt-in required.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin

from argus.agents.base import (
    AgentReport,
    AttackContext,
    BaseAgent,
    build_http_poc,
    fetch_fallback_baseline,
    response_matches_fallback,
)
from argus.llm.prompts import BIZLOGIC_SYSTEM, build_bizlogic_user
from argus.models import Finding, Severity

_JSON_ARR = re.compile(r"\[.*\]", re.DOTALL)
_JSON_OBJ = re.compile(r"\{.*\}", re.DOTALL)
_MAX_PLANS = 5
_MAX_STEPS_PER_PLAN = 3


class BusinessLogicAgent(BaseAgent):
    name = "BusinessLogicAgent"
    description = "business logic abuse (LLM-driven)"

    async def run(self, ctx: AttackContext) -> AgentReport:
        report = AgentReport(agent=self.name, status="running")

        if ctx.provider is None:
            ctx.emit(self.name, "no LLM provider configured — skipping (needs one to reason)")
            report.status = "complete"
            return report

        endpoints = self._endpoint_payload(ctx)
        if not endpoints:
            ctx.emit(self.name, "no endpoints discovered to reason over")
            report.status = "complete"
            return report

        ctx.emit(self.name, f"reasoning over {len(endpoints)} endpoint(s) for logic abuse …")
        raw = await self.complete(ctx, BIZLOGIC_SYSTEM, build_bizlogic_user(endpoints, ctx.recon), json_mode=True)
        plans = self._parse_plans(raw)
        if not plans:
            ctx.emit(self.name, "no plausible business-logic test plan produced")
            report.status = "complete"
            return report

        # The LLM proposes step paths itself — it isn't constrained to the
        # discovered endpoint list, and readily invents plausible-looking
        # admin/monitoring paths (jenkins/, phpmyadmin/, actuator, swagger-ui)
        # that were never actually found. On a target with a catch-all
        # handler (an SPA fallback, a generic error page) every one of those
        # invented paths "succeeds" with an identical response, which used to
        # read as a confirmed HIGH finding. Fetched once per run, reused
        # across every plan below.
        fallback_baseline = await fetch_fallback_baseline(self, ctx)

        confirmed = 0
        for plan in plans[:_MAX_PLANS]:
            if await self._execute_plan(ctx, plan, fallback_baseline):
                confirmed += 1

        report.requests_sent = ctx.requests_sent
        report.findings = len([f for f in ctx.findings if f.detector == "businesslogic"])
        report.status = "complete"
        ctx.emit(self.name, f"sweep complete — {confirmed} plan(s) confirmed", "ok")
        return report

    def _endpoint_payload(self, ctx: AttackContext) -> list[dict]:
        return [{"method": ep.method, "url": ep.url, "params": ep.params} for ep in ctx.endpoint_list()][:40]

    def _parse_plans(self, raw: str | None) -> list[dict]:
        if not raw:
            return []

        # Try the instructed shape first: a JSON array of plan objects. Note the
        # regex is greedy/non-anchored, so if the model instead returns a single
        # bare plan object, this can spuriously match that object's *inner*
        # "steps" array (a list of step-dicts, not plan-dicts) — in that case the
        # filter below correctly yields nothing and we fall through to the
        # object check rather than returning an empty result early.
        m = _JSON_ARR.search(raw)
        if m:
            try:
                parsed = json.loads(m.group(0))
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, list):
                plans = [item for item in parsed if isinstance(item, dict) and item.get("steps")]
                if plans:
                    return plans

        # Smaller/local models (observed with qwen2.5:7b) sometimes ignore the
        # "return a JSON array" instruction and return a single bare object when
        # they only found one plausible plan — accept that too rather than
        # silently discarding a real proposal over a formatting technicality.
        m = _JSON_OBJ.search(raw)
        if m:
            try:
                parsed = json.loads(m.group(0))
            except json.JSONDecodeError:
                return []
            if isinstance(parsed, dict) and parsed.get("steps"):
                return [parsed]

        return []

    async def _execute_plan(self, ctx: AttackContext, plan: dict, fallback_baseline: str | None) -> bool:
        title = str(plan.get("title", "Business logic abuse"))[:120]
        rationale = str(plan.get("rationale", "")).strip()
        expect = str(plan.get("expect_vulnerable_if", "")).strip()
        steps = plan.get("steps")
        if not isinstance(steps, list) or not steps:
            return False
        steps = steps[:_MAX_STEPS_PER_PLAN]

        # Trust our own recon over the model's stated method: smaller/local models
        # (observed with qwen2.5:7b) sometimes default every step to GET even when
        # the endpoint list explicitly says POST, which silently 404s a legitimate
        # test against a real vulnerability. We already know the real method from
        # crawling the app — use it instead of re-guessing.
        known_methods = {ep.url: ep.method for ep in ctx.endpoint_list()}

        responses: list[tuple[str, str, object]] = []
        for step in steps:
            if not isinstance(step, dict):
                return False
            method = str(step.get("method", "GET")).upper()
            path = str(step.get("path", "")).strip()
            if not path:
                return False
            url = urljoin(ctx.base_url + "/", path.lstrip("/"))
            if url in known_methods and known_methods[url] != method:
                method = known_methods[url]
            body = step.get("body") if isinstance(step.get("body"), dict) else None
            ctx.emit(self.name, f"testing: {title} — {method} {path}")
            resp = (
                await self._request(ctx, method, url, json=body)
                if body is not None
                else await self._request(ctx, method, url)
            )
            if resp is None:
                return False
            responses.append((method, url, resp))

        # Mechanical confirmation: every replayed step succeeded with no rejection at
        # all is the concrete, checkable signal that something SHOULD have blocked a
        # repeat/abuse but didn't. This can false-positive on legitimately idempotent
        # endpoints, so confidence is deliberately "medium", not "high".
        if not all(r.status_code < 400 for _, _, r in responses):
            return False

        # Every step "succeeding" is meaningless if every step got back the
        # exact same catch-all page a nonexistent path would too — that's a
        # target-wide fallback handler, not a confirmed logic flaw. Require
        # at least one response to be genuinely distinct from the baseline.
        if all(response_matches_fallback(r.text or "", fallback_baseline) for _, _, r in responses):
            return False

        last_method, last_url, last_resp = responses[-1]
        evidence = "; ".join(f"{m} {u} -> HTTP {r.status_code}" for m, u, r in responses)
        ctx.report(Finding(
            title=f"Business logic: {title}",
            severity=Severity.HIGH,
            category="business-logic",
            detector="businesslogic",
            endpoint=f"{last_method} {last_url}",
            evidence=evidence,
            description=rationale or (
                f"An LLM-proposed abuse sequence for '{title}' completed with every step "
                f"succeeding, matching the vulnerable pattern ({expect or 'no request was rejected'})."
            ),
            exploit=f"Replay the same sequence: {evidence}.",
            fix="Add server-side enforcement for this workflow step (idempotency keys, state "
                "checks, ownership/quantity validation) — never rely on client-side or "
                "one-time UI gating alone.",
            cwe="CWE-841",
            confidence="medium",
            poc=build_http_poc(last_method, last_url, last_resp),
        ))
        return True
