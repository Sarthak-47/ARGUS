"""LLM reasoning layer over deterministic findings.

Three jobs implemented here:
  - enrich_findings: validate/explain/severity-justify each finding in context.
  - freeform_review: read high-risk files in full for logic flaws (--deep).
  - generate_fixes: produce a minimal unified-diff patch per finding (`argus fix`).
All three are best-effort: any LLM/parse error leaves the original state intact.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from argus.llm.prompts import (
    ENRICH_SYSTEM,
    FIX_SYSTEM,
    FREEFORM_SYSTEM,
    build_enrich_user,
    build_fix_user,
    build_freeform_user,
)
from argus.llm.provider import BaseProvider, LLMError
from argus.models import Finding, Severity

_JSON_OBJ = re.compile(r"\{.*\}", re.DOTALL)
_JSON_ARR = re.compile(r"\[.*\]", re.DOTALL)


def _extract_json(text: str, array: bool = False) -> object | None:
    pat = _JSON_ARR if array else _JSON_OBJ
    m = pat.search(text)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None


def _context_for(root: Path, finding: Finding, radius: int = 12) -> str:
    if not finding.file or not finding.line:
        return finding.evidence
    full = root / finding.file
    try:
        lines = full.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return finding.evidence
    lo = max(0, finding.line - radius)
    hi = min(len(lines), finding.line + radius)
    numbered = [f"{i + 1}: {lines[i]}" for i in range(lo, hi)]
    return "\n".join(numbered)


def enrich_findings(
    provider: BaseProvider,
    root: Path,
    findings: list[Finding],
    *,
    max_findings: int = 40,
    on_progress=None,
) -> tuple[list[Finding], int]:
    """Enrich findings in place. Returns (findings, dropped_false_positive_count)."""
    kept: list[Finding] = []
    dropped = 0
    # Enrich the most severe first; pass the rest through untouched.
    ordered = sorted(findings, key=lambda f: -f.severity.rank)
    to_enrich = ordered[:max_findings]
    passthrough = ordered[max_findings:]

    for i, f in enumerate(to_enrich):
        if on_progress:
            on_progress(i + 1, len(to_enrich))
        context = _context_for(root, f)
        try:
            res = provider.complete(ENRICH_SYSTEM, build_enrich_user(f.to_dict(), context), json_mode=True)
        except LLMError:
            kept.append(f)
            continue
        parsed = _extract_json(res.text)
        if not isinstance(parsed, dict):
            kept.append(f)
            continue
        if parsed.get("false_positive") is True:
            dropped += 1
            continue
        if parsed.get("severity"):
            f.severity = Severity.coerce(parsed["severity"])
        if parsed.get("explanation"):
            f.description = str(parsed["explanation"]).strip()
        if parsed.get("exploit"):
            f.exploit = str(parsed["exploit"]).strip()
        if parsed.get("fix"):
            f.fix = str(parsed["fix"]).strip()
        f.confidence = "high"
        f.metadata["llm_enriched"] = True
        kept.append(f)

    kept.extend(passthrough)
    return kept, dropped


def freeform_review(
    provider: BaseProvider,
    root: Path,
    high_risk_files: list[str],
    *,
    max_files: int = 8,
    on_progress=None,
) -> list[Finding]:
    """Read high-risk files in full and ask the LLM for logic flaws."""
    out: list[Finding] = []
    targets = high_risk_files[:max_files]
    for i, rel in enumerate(targets):
        if on_progress:
            on_progress(i + 1, len(targets))
        full = root / rel
        try:
            code = full.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not code.strip():
            continue
        try:
            res = provider.complete(FREEFORM_SYSTEM, build_freeform_user(rel, code), json_mode=True)
        except LLMError:
            continue
        parsed = _extract_json(res.text, array=True)
        if not isinstance(parsed, list):
            continue
        for item in parsed:
            if not isinstance(item, dict) or not item.get("title"):
                continue
            out.append(Finding(
                title=str(item["title"])[:120],
                severity=Severity.coerce(item.get("severity", "MEDIUM")),
                category="logic",
                detector="llm-review",
                file=rel,
                line=item.get("line") if isinstance(item.get("line"), int) else None,
                description=str(item.get("explanation", "")).strip(),
                exploit=str(item.get("exploit", "")).strip(),
                fix=str(item.get("fix", "")).strip(),
                confidence="medium",
                metadata={"llm_review": True},
            ))
    return out


@dataclass
class FixResult:
    """A proposed patch for one finding."""

    finding_id: str
    file: str
    diff: str
    explanation: str


def generate_fixes(
    provider: BaseProvider,
    root: Path,
    findings: list[Finding],
    *,
    max_findings: int = 20,
    on_progress=None,
) -> list[FixResult]:
    """Ask the LLM for a minimal unified diff per fixable finding.

    Only findings with a ``file`` are fixable this way (Phase-2/HTTP findings have
    no source file to patch). Findings the model can't safely fix, or where the
    response fails to parse, are silently skipped — same resilience pattern as
    :func:`enrich_findings`.
    """
    fixable = [f for f in findings if f.file][:max_findings]
    results: list[FixResult] = []

    for i, f in enumerate(fixable):
        if on_progress:
            on_progress(i + 1, len(fixable))
        context = _context_for(root, f)
        try:
            res = provider.complete(FIX_SYSTEM, build_fix_user(f.to_dict(), context), json_mode=True)
        except LLMError:
            continue
        parsed = _extract_json(res.text)
        if not isinstance(parsed, dict) or not parsed.get("can_fix") or not parsed.get("diff"):
            continue
        results.append(FixResult(
            finding_id=f.id,
            file=f.file,
            diff=str(parsed["diff"]),
            explanation=str(parsed.get("explanation", "")).strip(),
        ))
    return results
