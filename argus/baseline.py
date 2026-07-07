"""Baseline support — adopt Argus on an existing codebase without drowning.

A team turning a scanner on a mature repo gets hundreds of pre-existing
findings and, understandably, ignores the tool. A baseline fixes that: record
every finding that exists *today* as accepted, then future scans (and CI
gates) surface only what's genuinely new.

Complementary to two neighbours:
  - ``--diff-base`` filters by *git-changed files* (per-PR); baseline filters
    by *finding identity* (per-adoption) and needs no git.
  - suppression (`argus suppress`) is a manual per-finding decision; a baseline
    is a one-shot bulk "accept everything currently here".

The baseline file is a small JSON list of finding signatures — the same
category + location + normalized-title signature ``argus compare`` uses, so a
finding that merely shifts line numbers stays baselined.
"""

from __future__ import annotations

import json
from pathlib import Path

from argus.compare import finding_signature
from argus.models import Finding


def _sig_key(f: Finding) -> str:
    return "||".join(str(part) for part in finding_signature(f))


def write_baseline(path: Path, findings: list[Finding]) -> int:
    """Record the signatures of ``findings`` as the accepted baseline. Returns
    the number of distinct signatures written."""
    sigs = sorted({_sig_key(f) for f in findings})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"signatures": sigs}, indent=2), encoding="utf-8")
    return len(sigs)


def load_baseline(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return set()
    sigs = data.get("signatures", []) if isinstance(data, dict) else []
    return {s for s in sigs if isinstance(s, str)}


def filter_new(findings: list[Finding], baseline: set[str]) -> tuple[list[Finding], int]:
    """Split findings into (new, baselined_count) — new = not in the baseline."""
    new: list[Finding] = []
    baselined = 0
    for f in findings:
        if _sig_key(f) in baseline:
            baselined += 1
        else:
            new.append(f)
    return new, baselined
