"""Compare two ScanResults by finding signature — the engine side of the
"what's new / what got fixed since last scan" view.

A finding's identity across two independent scans can't be its ``id`` (a
fresh UUID every run) or even its full :meth:`Finding.dedup_key` (that
includes line number, and a shifted line from an unrelated edit shouldn't
make a persisting finding look new/fixed). Signature matching here is
deliberately the same shape used by fix-and-reverify: category + location
(file or endpoint) + normalized title, ignoring line.
"""

from __future__ import annotations

from dataclasses import dataclass

from argus.models import Finding, ScanResult


def finding_signature(f: Finding) -> tuple:
    loc = (f.file or f.endpoint or "").lower()
    return (f.category, loc, " ".join(f.title.lower().split()))


@dataclass
class ComparisonResult:
    """The delta between an ``old`` and a ``new`` ScanResult."""

    old_target: str
    new_target: str
    new_findings: list[Finding]       # present in `new`, absent from `old`
    fixed_findings: list[Finding]     # present in `old`, absent from `new`
    unchanged_count: int              # present in both


def diff_results(old: ScanResult, new: ScanResult) -> ComparisonResult:
    old_sigs = {finding_signature(f): f for f in old.findings}
    new_sigs = {finding_signature(f): f for f in new.findings}

    new_only = [f for sig, f in new_sigs.items() if sig not in old_sigs]
    fixed = [f for sig, f in old_sigs.items() if sig not in new_sigs]
    unchanged = len(set(old_sigs) & set(new_sigs))

    return ComparisonResult(
        old_target=old.target, new_target=new.target,
        new_findings=new_only, fixed_findings=fixed, unchanged_count=unchanged,
    )
