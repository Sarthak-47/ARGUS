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
