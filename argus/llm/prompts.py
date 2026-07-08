"""System and user prompts for the LLM reasoning layer.

Kept in one module so prompt wording is auditable and testable. The enrichment
prompt asks the model to return strict JSON so we can parse it deterministically.
"""

from __future__ import annotations

import json

ENRICH_SYSTEM = (
    "You are Argus, a precise application-security analyst. You receive raw static-analysis "
    "findings and the file context around them. For each finding you decide whether it is a "
    "true positive, explain it in plain English for the specific codebase, justify a severity, "
    "describe a concrete exploit scenario, and give a minimal fix. Be terse and technical. "
    "Never invent endpoints or code you were not shown. Respond ONLY with valid JSON."
)

ENRICH_INSTRUCTIONS = """\
For the finding below, return a JSON object with exactly these keys:
{
  "false_positive": boolean,
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "explanation": string,   // 1-3 sentences, specific to this code
  "exploit": string,       // how an attacker abuses it, or "" if false positive
  "fix": string            // concrete remediation, include a code snippet if useful
}
Do not include any prose outside the JSON.
"""


def build_enrich_user(finding: dict, context: str) -> str:
    """Compose the user message for enriching a single finding."""
    payload = {
        "title": finding.get("title"),
        "category": finding.get("category"),
        "severity": finding.get("severity"),
        "file": finding.get("file"),
        "line": finding.get("line"),
        "evidence": finding.get("evidence"),
        "cwe": finding.get("cwe"),
    }
    return (
        ENRICH_INSTRUCTIONS
        + "\n\nFINDING:\n"
        + json.dumps(payload, indent=2)
        + "\n\nCODE CONTEXT (the lines around the finding):\n"
        + "```\n"
        + context[:4000]
        + "\n```\n"
    )


FREEFORM_SYSTEM = (
    "You are Argus performing a free-form security review of a high-risk source file "
    "(auth, payments, admin, or file handling). Look for logic flaws that pattern scanners "
    "miss: broken access control, missing ownership checks, auth bypass via parameter "
    "manipulation, race conditions, and insecure design. Respond ONLY with a JSON array."
)

FREEFORM_INSTRUCTIONS = """\
Return a JSON array of findings. Each element:
{
  "title": string,
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "line": number | null,
  "explanation": string,
  "exploit": string,
  "fix": string
}
Return [] if the file has no real issues. No prose outside the JSON array.
"""


def build_freeform_user(rel_path: str, code: str) -> str:
    return (
        FREEFORM_INSTRUCTIONS
        + f"\n\nFILE: {rel_path}\n```\n"
        + code[:8000]
        + "\n```\n"
    )


FIX_SYSTEM = (
    "You are Argus, a precise application-security engineer writing a minimal patch for one "
    "finding. You will be shown the finding and the exact lines of code around it. Produce the "
    "smallest correct fix — do not refactor unrelated code, do not change formatting elsewhere, "
    "and never invent code you were not shown. If you cannot produce a safe, targeted patch, say "
    "so honestly. Respond ONLY with valid JSON."
)

FIX_INSTRUCTIONS = """\
For the finding below, return a JSON object with exactly these keys:
{
  "can_fix": boolean,          // false if a safe, minimal patch isn't possible from the context shown
  "diff": string,              // a unified diff (---/+++/@@ hunk) touching ONLY the shown file, or ""
  "explanation": string,       // 1-2 sentences on what the patch does and why it's safe
  "regenerate_prompt": string  // see below, or "" if can_fix is false
}
The diff must apply cleanly against the exact code context shown below — match whitespace and
line content exactly. Do not include any prose outside the JSON.

For "regenerate_prompt": many Argus users write code with an AI coding assistant (Copilot,
Cursor, Claude Code) rather than by hand. Write a short, ready-to-paste prompt they could hand
back to that same assistant instead of applying your diff — one that names the specific
vulnerability class, explains concretely why the current code is unsafe, and states the safe
pattern to use instead, so the assistant regenerates the function correctly. Do not just say
"fix the security issue" — be as specific as the diff itself.
"""


TAINT_SYSTEM = (
    "You are Argus performing taint-flow analysis on a source file — a VulnHuntr-style pass that "
    "traces the full path from an untrusted input source (an HTTP request parameter/header/body "
    "field, a file read, an environment variable, a message-queue payload) through every "
    "intermediate function call, to a dangerous sink (SQL/NoSQL query execution, shell/process "
    "execution, deserialization, file path construction, template rendering, eval, an outbound "
    "HTTP request built from tainted data, etc.). Report a finding ONLY when you can point to the "
    "complete chain — the exact source, every hop the tainted value passes through unsanitized, "
    "and the exact sink — within the code you were shown. If you can only see part of the chain "
    "(e.g. a sink with no visible source, or a source that dead-ends before reaching anything "
    "dangerous), do not report it: a partial chain is exactly the kind of speculative guess this "
    "pass exists to avoid. Respond ONLY with valid JSON."
)

TAINT_INSTRUCTIONS = """\
Return a JSON array of confirmed taint flows. Each element:
{
  "title": string,               // e.g. "Tainted request param reaches os.system via build_cmd()"
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "source": string,              // where the untrusted input enters, with line number
  "sink": string,                // the dangerous operation it reaches, with line number
  "call_chain": [string],        // ordered list of each function/hop the tainted value passes through
  "line": number | null,         // the sink's line number
  "explanation": string,         // why the whole path is unsanitized
  "exploit": string,
  "fix": string
}
Return [] if no complete source-to-sink chain exists in this file. No prose outside the JSON array.
"""


def build_taint_user(rel_path: str, code: str) -> str:
    return (
        TAINT_INSTRUCTIONS
        + f"\n\nFILE: {rel_path}\n```\n"
        + code[:8000]
        + "\n```\n"
    )


BIZLOGIC_SYSTEM = (
    "You are Argus, testing a live web application for BUSINESS LOGIC vulnerabilities — the class "
    "of bugs pattern scanners and generic attack agents miss because nothing is syntactically wrong, "
    "only the workflow. You are given the discovered endpoints/parameters and must propose concrete, "
    "safe, replayable HTTP request sequences that would reveal abuse such as: coupon/discount "
    "stacking or reuse, negative price/quantity manipulation, workflow-step bypass (skipping a "
    "required prior step), free-trial/referral abuse, and price-rounding exploitation. Only propose "
    "sequences against endpoints you were actually shown — never invent one. Keep each sequence to "
    "at most 3 HTTP requests. Respond ONLY with valid JSON."
)

BIZLOGIC_INSTRUCTIONS = """\
Given the endpoints below, return a JSON array of up to 5 test plans. Each element:
{
  "title": string,                     // short name for the abuse being tested
  "rationale": string,                 // why this endpoint is a plausible business-logic target
  "steps": [                            // 1-3 HTTP requests to replay in order
    {"method": "GET" | "POST" | "PUT" | "DELETE", "path": string, "body": object | null}
  ],
  "expect_vulnerable_if": string        // what response pattern would indicate the abuse succeeded
}
Return [] if nothing plausible stands out. No prose outside the JSON array.
"""


def build_bizlogic_user(endpoints: list[dict], recon: dict) -> str:
    """Compose the user message proposing business-logic abuse sequences."""
    return (
        BIZLOGIC_INSTRUCTIONS
        + "\n\nDISCOVERED ENDPOINTS:\n"
        + json.dumps(endpoints[:40], indent=2)
        + "\n\nRECON CONTEXT:\n"
        + json.dumps(recon, default=str, indent=2)[:2000]
        + "\n"
    )


def build_fix_user(finding: dict, context: str) -> str:
    """Compose the user message asking for a patch for a single finding."""
    payload = {
        "title": finding.get("title"),
        "category": finding.get("category"),
        "severity": finding.get("severity"),
        "file": finding.get("file"),
        "line": finding.get("line"),
        "evidence": finding.get("evidence"),
        "cwe": finding.get("cwe"),
        "suggested_fix": finding.get("fix"),
    }
    return (
        FIX_INSTRUCTIONS
        + "\n\nFINDING:\n"
        + json.dumps(payload, indent=2)
        + "\n\nCODE CONTEXT (the lines around the finding, with line numbers):\n"
        + "```\n"
        + context[:4000]
        + "\n```\n"
    )
