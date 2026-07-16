"""Exploit chaining — surface when confirmed findings compound into an attack path.

Every scanner on the market lists findings atomically: "XSS here", "session
cookie missing HttpOnly there". The compounding is left to the reader. But the
real severity is often in the combination: an XSS plus a session cookie a
script can read isn't two medium issues, it's *account takeover*.

This runs deterministically over the confirmed Phase-2 findings (no LLM, so
it's reliable and testable) and emits a synthesized "attack chain" finding for
each known-dangerous combination present — flagged CRITICAL, since a proven
chain is worse than the sum of its parts. Only chains built entirely from
findings an agent actually *confirmed* are emitted, so a chain is never
speculative.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from argus.models import Finding, Severity


@dataclass
class ChainRule:
    name: str
    detector: str
    cwe: str
    # Each step is a tuple of acceptable detector-id prefixes; a chain fires
    # only when every step is satisfied by some confirmed finding.
    steps: list[tuple[str, ...]]
    title: str
    narrative: str
    fix: str
    severity: Severity = Severity.CRITICAL
    tags: list[str] = field(default_factory=list)


CHAIN_RULES: list[ChainRule] = [
    ChainRule(
        name="xss-session-takeover",
        detector="chain:xss-session-takeover",
        cwe="CWE-79",
        steps=[("xsshunter:", "domxss:"), ("authbreaker:cookie-flags",)],
        title="Attack chain: XSS → session theft → account takeover",
        narrative="A confirmed XSS can execute script in a victim's browser, and the session cookie "
                  "is missing HttpOnly, so that script can read it. Chained, these give an attacker "
                  "the victim's session — full account takeover, not two isolated medium issues.",
        fix="Fix either link to break the chain: eliminate the XSS (sanitise/encode output) AND set "
            "HttpOnly + Secure + SameSite on the session cookie.",
    ),
    ChainRule(
        name="authbypass-idor",
        detector="chain:authbypass-idor",
        cwe="CWE-639",
        steps=[("authbreaker:jwt-none", "authbreaker:jwt-weak-secret", "headerpoker:bypass"),
               ("idorhunter",)],
        title="Attack chain: auth bypass → IDOR → access any user's data",
        narrative="Authentication can be forged/bypassed (weak or 'none' JWT, or a header-based "
                  "access-control bypass) AND object references aren't authorised (IDOR). Together, "
                  "an attacker can impersonate any identity and then read/modify any user's records.",
        fix="Enforce signed, verified tokens (no 'alg:none', strong secret) and check ownership on "
            "every object access — either fix alone materially weakens the chain.",
    ),
    ChainRule(
        name="upload-traversal-rce",
        detector="chain:upload-traversal-rce",
        cwe="CWE-434",
        steps=[("fileattacker:upload",), ("fileattacker:traversal",)],
        title="Attack chain: file upload + path traversal → arbitrary file write",
        narrative="An upload endpoint accepts files AND path traversal is possible. Combined, an "
                  "attacker can write a file to an attacker-chosen path (e.g. a web-root script or a "
                  "cron entry), a common route to remote code execution.",
        fix="Validate upload type/size and store with a generated name in a non-executable location; "
            "canonicalise and confine all file paths to an allow-listed base directory.",
    ),
    ChainRule(
        name="clickjacking-csrf-forced-action",
        detector="chain:clickjacking-csrf-forced-action",
        cwe="CWE-352",
        steps=[("csrfhunter:form",), ("csrfhunter:clickjacking",)],
        title="Attack chain: clickjacking + missing CSRF token → forced state change",
        narrative="A state-changing endpoint has no CSRF protection AND the app can be framed "
                  "(no X-Frame-Options / frame-ancestors). An attacker overlays the app in an "
                  "invisible iframe and tricks a logged-in victim into performing the action — "
                  "change email, transfer funds, escalate a role — with a single click, no token "
                  "needed. Either weakness alone is lower-risk; together they're a working exploit.",
        fix="Add anti-CSRF tokens (or SameSite=Strict cookies) to every state-changing request AND "
            "send X-Frame-Options: DENY / a restrictive frame-ancestors CSP — fixing either link "
            "breaks the chain.",
    ),
    ChainRule(
        name="mcp-exposure-leak",
        detector="chain:mcp-exposure-leak",
        cwe="CWE-306",
        steps=[("mcpsecurity:tool-list", "mcpsecurity:sse"), ("mcpsecurity:leaked-secret",)],
        title="Attack chain: exposed MCP server + leaked credential → AI-infra takeover",
        narrative="An unauthenticated MCP server exposes its tools AND a provider credential leaks in "
                  "a response. An attacker can enumerate and invoke privileged tools and reuse the "
                  "leaked key against the upstream provider — full control of the AI integration.",
        fix="Require authentication on the MCP transport and never echo credentials in tool responses; "
            "rotate the leaked key immediately.",
    ),
]


def _match_step(alternatives: tuple[str, ...], findings: list[Finding]) -> Finding | None:
    for f in findings:
        if f.confirmed and any(f.detector.startswith(alt) for alt in alternatives):
            return f
    return None


# `ctx.report()` sets every finding's `confirmed` to True unconditionally
# (see argus/agents/base.py) — it means "the agent completed its check", not
# "certain to be a true positive". A constituent's own `confidence` field is
# the actual signal for that, and `_match_step` was ignoring it entirely: a
# chain built from a "medium"-confidence IDOR finding (which can itself be a
# false positive — see IDORHunter/RaceCondition's fallback-baseline guards)
# still got reported at flat "high" confidence, laundering an uncertain
# constituent into a maximum-confidence CRITICAL chain finding.
_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def detect_chains(findings: list[Finding]) -> list[Finding]:
    """Return synthesized attack-chain findings for every chain present."""
    chains: list[Finding] = []
    for rule in CHAIN_RULES:
        matched = [_match_step(step, findings) for step in rule.steps]
        if any(m is None for m in matched):
            continue
        constituents = [m for m in matched if m is not None]
        locations = "; ".join(f"{c.title} ({c.location})" for c in constituents)
        # The chain is only as trustworthy as its weakest confirmed link —
        # never blanket-upgrade an uncertain constituent's confidence just
        # because it was chained.
        weakest_confidence = min(
            (c.confidence for c in constituents),
            key=lambda conf: _CONFIDENCE_RANK.get(conf, 1),
        )
        chains.append(Finding(
            title=rule.title,
            severity=rule.severity,
            category="attack-chain",
            detector=rule.detector,
            description=rule.narrative,
            evidence="Chained from confirmed findings: " + locations,
            exploit=rule.narrative,
            fix=rule.fix,
            cwe=rule.cwe,
            confidence=weakest_confidence,
            confirmed=True,
            metadata={"chain_of": [c.id for c in constituents]},
        ))
    return chains
