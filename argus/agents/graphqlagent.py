"""GraphQLAgent — GraphQL-specific weaknesses.

Locates a GraphQL endpoint (from recon or common paths), then tests whether schema
introspection is enabled in production (full schema disclosure). Introspection being
open is the highest-signal, reliably-detectable GraphQL issue; depth/complexity and
batching abuse are deeper follow-ups.
"""

from __future__ import annotations

from argus.agents.base import AgentReport, AttackContext, BaseAgent
from argus.models import Finding, Severity

_INTROSPECTION = {"query": "{__schema{queryType{name} types{name kind}}}"}
_CANDIDATE_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/graphiql"]


class GraphQLAgent(BaseAgent):
    name = "GraphQLAgent"
    description = "schema introspection"

    async def run(self, ctx: AttackContext) -> AgentReport:
        report = AgentReport(agent=self.name, status="running")

        endpoint = await self._locate(ctx)
        if not endpoint:
            ctx.emit(self.name, "no GraphQL endpoint found")
            report.status = "complete"
            return report

        ctx.emit(self.name, f"testing introspection on {endpoint} …")
        resp = await self.post(ctx, endpoint, json=_INTROSPECTION)
        if resp is not None and resp.status_code < 400:
            body = resp.text or ""
            if "__schema" in body and "queryType" in body:
                ctx.report(Finding(
                    title="GraphQL introspection enabled",
                    severity=Severity.MEDIUM,
                    category="api",
                    detector="graphqlagent:introspection",
                    endpoint=f"POST {endpoint}",
                    evidence="introspection query returned the full __schema",
                    description="Schema introspection is enabled, disclosing every type, query and "
                                "mutation — a roadmap of the entire API for an attacker.",
                    exploit="Enumerate the full schema, then target sensitive mutations/queries.",
                    fix="Disable introspection in production; restrict it to trusted environments.",
                    cwe="CWE-200",
                    confidence="high",
                ))

        report.requests_sent = ctx.requests_sent
        report.findings = len([f for f in ctx.findings if f.detector.startswith("graphqlagent")])
        report.status = "complete"
        ctx.emit(self.name, "sweep complete", "ok")
        return report

    async def _locate(self, ctx: AttackContext) -> str | None:
        # Prefer endpoints already discovered, else probe common paths.
        for ep in ctx.endpoint_list():
            if "graphql" in ep.url.lower():
                return ep.url.split("?")[0]
        for path in _CANDIDATE_PATHS:
            url = ctx.base_url + path
            resp = await self.post(ctx, url, json={"query": "{__typename}"})
            if resp is not None and resp.status_code < 400 and "__typename" in (resp.text or ""):
                return url
        return None
