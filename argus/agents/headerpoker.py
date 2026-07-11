"""HeaderPoker — header, CORS and origin abuse.

Confirms CORS misconfiguration by sending a hostile Origin and checking whether the
server reflects it in Access-Control-Allow-Origin (especially with credentials),
tests the dangerous ``Origin: null`` case, and probes access-control bypass headers
(X-Forwarded-For / X-Original-URL) against paths that previously denied access.
"""

from __future__ import annotations

from argus.agents.base import (
    AgentReport,
    AttackContext,
    BaseAgent,
    build_http_poc,
    response_matches_fallback,
)
from argus.models import Finding, Severity

_EVIL_ORIGIN = "https://evil.argus-test.example"
_BOGUS_PATH = "/argus-fallback-probe-x9z7q"


class HeaderPoker(BaseAgent):
    name = "HeaderPoker"
    description = "header & CORS abuse"

    async def run(self, ctx: AttackContext) -> AgentReport:
        report = AgentReport(agent=self.name, status="running")
        base = ctx.base_url

        await self._permissive_cors(ctx, base + "/")
        await self._cors(ctx, base + "/", _EVIL_ORIGIN, "arbitrary origin")
        await self._cors(ctx, base + "/", "null", "null origin")
        await self._forwarded_bypass(ctx)

        report.requests_sent = ctx.requests_sent
        report.findings = len([f for f in ctx.findings if f.detector.startswith("headerpoker")])
        report.status = "complete"
        ctx.emit(self.name, "sweep complete", "ok")
        return report

    async def _permissive_cors(self, ctx: AttackContext, url: str) -> None:
        """A static wildcard `Access-Control-Allow-Origin: *` lets any site read
        the (non-credentialed) response. Often intentional on a truly public
        API, so this is LOW — but on anything serving non-public data it's a real
        cross-origin exposure, and the reflected-origin/credentials cases below
        (which are HIGH) never fire for a plain wildcard."""
        resp = await self.get(ctx, url, headers={"Origin": _EVIL_ORIGIN})
        if resp is None:
            return
        acao = resp.headers.get("access-control-allow-origin")
        if acao != "*":
            return  # reflection/credentials cases are handled by _cors
        ctx.emit(self.name, "CORS allows any origin (wildcard)", "high")
        ctx.report(Finding(
            title="Permissive CORS (wildcard origin)",
            severity=Severity.LOW,
            category="misconfig",
            detector="headerpoker:cors",
            endpoint=url,
            evidence=f"Access-Control-Allow-Origin: * on {url}",
            description="The server returns a wildcard Access-Control-Allow-Origin, "
                        "so any website can read its responses cross-origin. On any "
                        "endpoint that isn't fully public this discloses data to "
                        "attacker-controlled sites.",
            exploit="Any origin's JavaScript can fetch this endpoint and read the response.",
            fix="Return Access-Control-Allow-Origin only for an explicit allow-list of trusted origins.",
            cwe="CWE-942",
            confidence="high",
            poc=build_http_poc("GET", url, resp),
        ))

    async def _cors(self, ctx: AttackContext, url: str, origin: str, label: str) -> None:
        resp = await self.get(ctx, url, headers={"Origin": origin})
        if resp is None:
            return
        acao = resp.headers.get("access-control-allow-origin")
        acac = resp.headers.get("access-control-allow-credentials", "").lower()
        if not acao:
            return
        reflects = acao == origin
        if reflects and (acao == origin or acac == "true"):
            sev = Severity.HIGH if acac == "true" else Severity.MEDIUM
            ctx.emit(self.name, f"CORS allows {label}", "high")
            ctx.report(Finding(
                title=f"CORS misconfiguration ({label})",
                severity=sev,
                category="misconfig",
                detector="headerpoker:cors",
                endpoint=url,
                evidence=f"Origin: {origin} -> Access-Control-Allow-Origin: {acao}"
                         + (f"; Allow-Credentials: {acac}" if acac else ""),
                description="The server reflects an attacker-controlled Origin"
                            + (" with credentials enabled" if acac == "true" else "")
                            + ", allowing malicious sites to read authenticated responses cross-origin.",
                exploit="Host a page on a hostile origin that fetches the API with credentials "
                        "and exfiltrates the response.",
                fix="Reflect Origin only from a strict allow-list; never combine '*' or reflected "
                    "Origin with Allow-Credentials: true.",
                cwe="CWE-942",
                confidence="high",
                poc=build_http_poc("GET", url, resp),
            ))

    async def _forwarded_bypass(self, ctx: AttackContext) -> None:
        # Find a path that currently returns 401/403, then retry with bypass headers.
        denied = [ep for ep in ctx.endpoint_list() if ep.sample_status in (401, 403)]
        if not denied:
            return
        # A 401/403 -> <400 status flip alone isn't proof the header reached
        # ep.url specifically — the header itself might just make *any* path
        # return the same generic 200 (a WAF/gateway that trusts the header
        # for routing to a catch-all, not for authorization). Cached per
        # header, not per endpoint: whether a bogus, unrelated path also
        # flips to the identical response once it carries the same header.
        baselines: dict[str, str | None] = {}
        for ep in denied[:5]:
            for header in ("X-Forwarded-For", "X-Real-IP", "X-Original-URL", "X-Forwarded-Host"):
                value = "127.0.0.1" if header in ("X-Forwarded-For", "X-Real-IP") else "/"
                resp = await self.get(ctx, ep.url, headers={header: value})
                if resp is None or resp.status_code >= 400:
                    continue
                if header not in baselines:
                    baseline_resp = await self.get(
                        ctx, ctx.base_url + _BOGUS_PATH, headers={header: value},
                    )
                    baselines[header] = baseline_resp.text if baseline_resp is not None else None
                if response_matches_fallback(resp.text or "", baselines[header]):
                    continue
                ctx.report(Finding(
                    title="Access control bypass via request header",
                    severity=Severity.HIGH,
                    category="misconfig",
                    detector="headerpoker:bypass",
                    endpoint=ep.url,
                    evidence=f"{header}: {value} changed {ep.sample_status} -> {resp.status_code}",
                    description=f"Sending {header} bypassed an access restriction, indicating the "
                                f"app trusts a client-supplied header for authorization or routing.",
                    exploit=f"Set {header} to reach restricted functionality.",
                    fix="Do not trust client-supplied forwarding/override headers for access control.",
                    cwe="CWE-290",
                    confidence="high",
                    poc=build_http_poc("GET", ep.url, resp),
                ))
                break
