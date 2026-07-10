"""DataExposureAgent — excessive data exposure / sensitive fields in responses.

Sweeps the discovered GET endpoints and inspects their JSON responses for
fields that should never leave the server — passwords, hashes, tokens, API
keys, private keys, and obvious PII (SSN, credit-card). A list endpoint that
returns every user's password hash (VAmPI's ``/users/v1`` and ``/users/v1/_debug``
are the canonical example) is a classic API-security failure that no header,
injection, or auth agent looks for. Read-only and bounded: it only GETs
endpoints already on the surface.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from argus.agents.base import AgentReport, AttackContext, BaseAgent, build_http_poc
from argus.models import Finding, Severity

# Field names that should never appear in a response body. Split by severity:
# a leaked credential/secret is critical-adjacent; PII is high; a bare token
# field is medium (could be the caller's own).
_SECRET_FIELDS = re.compile(
    r"(?i)\"(password|passwd|pwd|pass_hash|password_hash|hash|secret|"
    r"private_key|privatekey|api_key|apikey|access_key|client_secret)\"\s*:")
_PII_FIELDS = re.compile(
    r"(?i)\"(ssn|social_security|credit_card|creditcard|card_number|cvv|"
    r"passport|tax_id)\"\s*:")


class DataExposureAgent(BaseAgent):
    name = "DataExposure"
    description = "excessive data exposure"

    async def run(self, ctx: AttackContext) -> AgentReport:
        report = AgentReport(agent=self.name, status="running")
        targets = self._targets(ctx)
        if not targets:
            report.status = "complete"
            ctx.emit(self.name, "no JSON endpoints to inspect")
            return report

        flagged: set[str] = set()
        for url in targets:
            if url in flagged:
                continue
            resp = await self.get(ctx, url)
            if resp is None or resp.status_code >= 400:
                continue
            ctype = resp.headers.get("content-type", "").lower()
            if "json" not in ctype:
                continue
            body = resp.text or ""
            secret = _SECRET_FIELDS.search(body)
            pii = _PII_FIELDS.search(body)
            if not secret and not pii:
                continue
            flagged.add(url)
            leaked = secret.group(1) if secret else pii.group(1)
            sev = Severity.HIGH if secret else Severity.MEDIUM
            ctx.emit(self.name, f"response exposes '{leaked}'", "high")
            ctx.report(Finding(
                title="Excessive data exposure",
                severity=sev,
                category="info-exposure",
                detector="dataexposure",
                endpoint=f"GET {url}",
                evidence=f"response body contains a '{leaked}' field",
                description="The endpoint returns sensitive fields "
                            f"(here: '{leaked}') in its response, exposing data "
                            "that should never leave the server — often the whole "
                            "table, for every user, to any caller.",
                exploit="Read the endpoint and harvest credentials/PII for every "
                        "record it returns.",
                fix="Serialize only the fields a client needs; never return "
                    "password hashes, secrets, or PII. Add per-object field "
                    "filtering at the API boundary.",
                cwe="CWE-200",
                cvss=7.5 if secret else 5.3,
                confidence="high",
                poc=build_http_poc("GET", url, resp),
            ))

        report.requests_sent = ctx.requests_sent
        report.findings = len([f for f in ctx.findings if f.detector == "dataexposure"])
        report.status = "complete"
        ctx.emit(self.name, f"sweep complete — {len(flagged)} exposed endpoint(s)", "ok")
        return report

    def _targets(self, ctx: AttackContext) -> list[str]:
        # Concrete GET endpoints only — a path template like /users/v1/{id}
        # can't be fetched as-is, but its collection form usually can.
        out: list[str] = []
        seen: set[str] = set()
        for ep in ctx.endpoint_list():
            if ep.method != "GET":
                continue
            url = ep.url
            if "{" in url:
                url = url.split("/{", 1)[0]  # collection form of a template
            if not urlparse(url).scheme:
                continue
            if url not in seen:
                seen.add(url)
                out.append(url)
        return out[:30]
