"""AuthzTester — broken object- and function-level authorization (BOLA/BFLA).

The #1 API risk (OWASP API1/API5) needs two real identities to test properly, so
this agent only runs when a second account is supplied (``--auth-b``). It uses
three actors per candidate endpoint:

  - **anon** — no credentials (baseline: is the endpoint even protected?)
  - **identity A** — the primary session already applied to ``ctx.client``
  - **identity B** — a second, ideally lower-privilege, account

**BOLA** (object-level): an object-scoped endpoint (an id in the path or an
id-like param) that anon can't reach (401/403) but *both* A and B can — a second
authenticated user reading another user's object is missing per-object
authorization. **BFLA** (function-level): a privileged-looking endpoint
(``/admin`` …) that anon can't reach but the ordinary B account can.

Only the "protected-from-anonymous **and** reachable-cross-identity" pattern is
flagged, which keeps public endpoints from producing false positives.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx

from argus.agents.base import (
    AgentReport,
    AttackContext,
    BaseAgent,
    build_http_poc,
    response_matches_fallback,
)
from argus.models import Finding, Severity

_BASELINE_PATH = "/argus-fallback-probe-x9z7q"

_INT_SEG = re.compile(r"/\d{1,12}(?=/|$)")
_ID_PARAMS = {"id", "user", "userid", "user_id", "account", "order", "oid", "pid", "uuid"}
_PRIV_PATH = re.compile(r"/(admin|internal|manage(?:ment)?|config|settings|debug|actuator|users?)(/|$)", re.I)
_PROTECTED = {401, 403}


class AuthzTester(BaseAgent):
    name = "AuthzTester"
    description = "broken object/function authorization (BOLA/BFLA)"

    async def run(self, ctx: AttackContext) -> AgentReport:
        report = AgentReport(agent=self.name, status="running")
        if ctx.identity_b is None:
            ctx.emit(self.name, "skipped — needs a second identity (--auth-b)")
            report.status = "complete"
            return report
        if ctx.identity_a is None:
            ctx.emit(self.name, "skipped — needs a primary identity too (--auth and --auth-b)")
            report.status = "complete"
            return report

        # A second client carrying identity B, plus a credential-free client for
        # the anonymous baseline. Both are torn down when we're done.
        from argus.auth import AuthError

        anon = httpx.AsyncClient(follow_redirects=False, timeout=15.0)
        client_b = httpx.AsyncClient(follow_redirects=False, timeout=15.0)
        try:
            try:
                await ctx.identity_b.apply(client_b)
            except AuthError as exc:
                ctx.emit(self.name, f"second identity login failed: {exc}", "crit")
                report.status = "error"
                return report

            # A gateway/CDN in front of the real app can 403 an unauthenticated
            # request but 200 *any* authenticated one with a generic/catch-all
            # body, regardless of path — that would otherwise look exactly like
            # a BOLA/BFLA bypass. Fetch one definitely-bogus path per identity
            # up front so a "reachable" response can be confirmed as actually
            # distinct content, not just a non-error status code.
            a_baseline_resp = await self.get(ctx, ctx.base_url + _BASELINE_PATH)
            a_baseline = a_baseline_resp.text if a_baseline_resp is not None else None
            b_baseline_resp = await self._raw(ctx, client_b, ctx.base_url + _BASELINE_PATH)
            b_baseline = b_baseline_resp.text if b_baseline_resp is not None else None

            bola, bfla = 0, 0
            for ep in self._candidates(ctx):
                if ep.method != "GET":
                    continue
                url = ep.url
                privileged = bool(_PRIV_PATH.search(urlparse(url).path))
                object_scoped = self._object_scoped(ep)
                if not (privileged or object_scoped):
                    continue

                a_resp = await self.get(ctx, url)
                anon_resp = await self._raw(ctx, anon, url)
                b_resp = await self._raw(ctx, client_b, url)
                if anon_resp is None or a_resp is None or b_resp is None:
                    continue

                anon_protected = anon_resp.status_code in _PROTECTED
                if not anon_protected:
                    continue  # public endpoint — not an authz finding

                if object_scoped and a_resp.status_code < 400 and b_resp.status_code < 400:
                    if response_matches_fallback(a_resp.text or "", a_baseline) or \
                       response_matches_fallback(b_resp.text or "", b_baseline):
                        continue  # indistinguishable from the catch-all baseline — not a real hit
                    bola += 1
                    self._report_bola(ctx, url, b_resp)
                elif privileged and b_resp.status_code < 400:
                    if response_matches_fallback(b_resp.text or "", b_baseline):
                        continue
                    bfla += 1
                    self._report_bfla(ctx, url, b_resp)

            report.requests_sent = ctx.requests_sent
            report.findings = bola + bfla
            report.status = "complete"
            ctx.emit(self.name, f"cross-identity sweep — {bola} BOLA, {bfla} BFLA", "ok")
            return report
        finally:
            await anon.aclose()
            await client_b.aclose()

    async def _raw(self, ctx: AttackContext, client: httpx.AsyncClient, url: str):
        """A GET on a caller-supplied client (identity B / anon), error-safe."""
        async with ctx.semaphore:
            try:
                resp = await client.get(url, timeout=15.0)
                ctx.requests_sent += 1
                return resp
            except httpx.HTTPError:
                ctx.requests_sent += 1
                return None

    def _candidates(self, ctx: AttackContext):
        return [ep for ep in ctx.endpoint_list() if ep.method == "GET"][:20]

    @staticmethod
    def _object_scoped(ep) -> bool:
        if _INT_SEG.search(urlparse(ep.url).path):
            return True
        return any(p.lower() in _ID_PARAMS for p in ep.params)

    def _report_bola(self, ctx: AttackContext, url: str, resp) -> None:
        ctx.report(Finding(
            title="Broken Object Level Authorization (BOLA/IDOR)",
            severity=Severity.HIGH,
            category="access-control",
            detector="authztester:bola",
            endpoint=f"GET {url}",
            evidence="endpoint rejects anonymous access (401/403) but a second authenticated "
                     "user can read the same object — missing per-object ownership check",
            description="A different authenticated user can access this object, so object-level "
                        "authorization isn't enforced (OWASP API1:2023).",
            exploit="Log in as any user and request another user's object by its identifier.",
            fix="Check that the authenticated principal owns (or may access) the specific object "
                "on every request — not just that they're logged in.",
            cwe="CWE-639",
            cvss=8.1,
            confidence="high",
            poc=build_http_poc("GET", url, resp),
        ))

    def _report_bfla(self, ctx: AttackContext, url: str, resp) -> None:
        ctx.report(Finding(
            title="Broken Function Level Authorization (BFLA)",
            severity=Severity.HIGH,
            category="access-control",
            detector="authztester:bfla",
            endpoint=f"GET {url}",
            evidence="privileged-looking endpoint rejects anonymous access but is reachable by an "
                     "ordinary (non-privileged) authenticated user",
            description="An ordinary user can reach a privileged/administrative function, so "
                        "function-level authorization isn't enforced (OWASP API5:2023).",
            exploit="Log in as a normal user and call the administrative endpoint directly.",
            fix="Enforce role/permission checks on privileged endpoints server-side; deny by default.",
            cwe="CWE-285",
            cvss=8.1,
            confidence="medium",
            poc=build_http_poc("GET", url, resp),
        ))
