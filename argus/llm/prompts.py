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
  "can_fix": boolean,       // false if a safe, minimal patch isn't possible from the context shown
  "diff": string,           // a unified diff (---/+++/@@ hunk) touching ONLY the shown file, or ""
  "explanation": string     // 1-2 sentences on what the patch does and why it's safe
}
The diff must apply cleanly against the exact code context shown below — match whitespace and
line content exactly. Do not include any prose outside the JSON.
"""


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
