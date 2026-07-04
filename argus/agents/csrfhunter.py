"""CSRFHunter — CSRF and clickjacking exposure.

Checks framing protection (X-Frame-Options / CSP frame-ancestors) for clickjacking,
and inspects state-changing forms discovered during recon for a CSRF token. Pure
response analysis — no state change is performed.
"""

from __future__ import annotations

import re

from argus.agents.base import AgentReport, AttackContext, BaseAgent, build_http_poc
from argus.models import Finding, Severity

_TOKEN_HINT = re.compile(r"(?i)csrf|xsrf|authenticity_token|__requestverificationtoken|_token")
_HIDDEN_INPUT = re.compile(r"""<input\b[^>]*type\s*=\s*['"]hidden['"][^>]*>""", re.IGNORECASE)
_NAME_ATTR = re.compile(r"""name\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)


class CSRFHunter(BaseAgent):
    name = "CSRFHunter"
    description = "CSRF & clickjacking"

    async def run(self, ctx: AttackContext) -> AgentReport:
        report = AgentReport(agent=self.name, status="running")
        base = ctx.base_url

        root = await self.get(ctx, base + "/")
        if root is not None:
            self._clickjacking(ctx, root)
            self._form_tokens(ctx, base, root.text or "", root)

        report.requests_sent = ctx.requests_sent
        report.findings = len([f for f in ctx.findings if f.detector.startswith("csrfhunter")])
        report.status = "complete"
        ctx.emit(self.name, "sweep complete", "ok")
        return report

    def _clickjacking(self, ctx: AttackContext, resp) -> None:
        present = {k.lower(): v for k, v in resp.headers.items()}
        xfo = present.get("x-frame-options")
        csp = present.get("content-security-policy", "")
        protected = bool(xfo) or "frame-ancestors" in csp.lower()
        if not protected:
            ctx.report(Finding(
                title="Clickjacking — no framing protection",
                severity=Severity.MEDIUM,
                category="csrf",
                detector="csrfhunter:clickjacking",
                endpoint=ctx.base_url + "/",
                evidence="no X-Frame-Options and no CSP frame-ancestors directive",
                description="The page can be embedded in a hostile iframe, enabling clickjacking "
                            "(UI redress) attacks against authenticated users.",
                exploit="Frame the page on an attacker site and trick users into clicking hidden controls.",
                fix="Send X-Frame-Options: DENY (or SAMEORIGIN) and/or CSP frame-ancestors 'none'.",
                cwe="CWE-1021",
                confidence="high",
                poc=build_http_poc("GET", ctx.base_url + "/", resp),
            ))

    def _form_tokens(self, ctx: AttackContext, base: str, html: str, resp=None) -> None:
        for attrs, body in _FORM_RE.findall(html):
            method_m = re.search(r"""method\s*=\s*['"]([^'"]+)['"]""", attrs, re.IGNORECASE)
            method = (method_m.group(1).upper() if method_m else "GET")
            if method == "GET":
                continue  # only state-changing forms matter
            hidden_names = []
            for hidden in _HIDDEN_INPUT.findall(body):
                nm = _NAME_ATTR.search(hidden)
                if nm:
                    hidden_names.append(nm.group(1))
            if not any(_TOKEN_HINT.search(n) for n in hidden_names):
                action_m = re.search(r"""action\s*=\s*['"]([^'"]*)['"]""", attrs, re.IGNORECASE)
                action = action_m.group(1) if action_m else "(self)"
                ctx.report(Finding(
                    title="Form without CSRF token",
                    severity=Severity.MEDIUM,
                    category="csrf",
                    detector="csrfhunter:form",
                    endpoint=f"{method} {action}",
                    evidence=f"{method} form, hidden fields: {hidden_names or 'none'} — no CSRF token",
                    description="A state-changing form carries no anti-CSRF token, so a forged "
                                "cross-site request can perform the action on a victim's behalf.",
                    exploit="Auto-submit the form from an attacker page while the victim is logged in.",
                    fix="Include and validate a per-session anti-CSRF token; use SameSite cookies.",
                    cwe="CWE-352",
                    confidence="medium",
                    poc=build_http_poc("GET", base, resp) if resp is not None else {},
                ))
