"""Tests for finding deduplication in ScanResult.add/extend.

Detectors regularly overlap (a built-in rule and Semgrep flagging the same SQLi
line); dedup keeps the report from showing the same bug twice while preserving the
strongest severity/confidence and a trail of which detectors agreed.
"""

from __future__ import annotations

from argus.models import Finding, ScanResult, Severity


def test_near_identical_findings_merge():
    r = ScanResult(target="t")
    r.add(Finding(
        title="Possible SQL injection (string-built query)", severity=Severity.HIGH,
        category="injection", detector="rule:py-sql-fstring", file="app.py", line=14,
        confidence="medium",
    ))
    r.add(Finding(
        title="Possible SQL injection (string-built query)", severity=Severity.CRITICAL,
        category="injection", detector="semgrep", file="app.py", line=14,
        confidence="high", references=["https://example.com/sqli"],
    ))
    assert len(r.findings) == 1
    merged = r.findings[0]
    assert merged.severity == Severity.CRITICAL          # kept the stronger severity
    assert merged.confidence == "high"                    # kept the stronger confidence
    assert merged.metadata["merged_count"] == 2
    assert set(merged.metadata["merged_detectors"]) == {"rule:py-sql-fstring", "semgrep"}
    assert merged.references == ["https://example.com/sqli"]


def test_different_titles_do_not_merge():
    r = ScanResult(target="t")
    r.add(Finding(title="SQL injection", severity=Severity.HIGH, category="injection",
                  file="app.py", line=14))
    r.add(Finding(title="Command injection", severity=Severity.HIGH, category="injection",
                  file="app.py", line=14))
    assert len(r.findings) == 2


def test_different_locations_do_not_merge():
    r = ScanResult(target="t")
    r.add(Finding(title="Weak hash", severity=Severity.MEDIUM, category="crypto",
                  file="a.py", line=1))
    r.add(Finding(title="Weak hash", severity=Severity.MEDIUM, category="crypto",
                  file="b.py", line=1))
    assert len(r.findings) == 2


def test_confirmed_flag_propagates_on_merge():
    r = ScanResult(target="t")
    r.add(Finding(title="X", severity=Severity.HIGH, category="c", endpoint="/e", confirmed=False))
    r.add(Finding(title="X", severity=Severity.HIGH, category="c", endpoint="/e", confirmed=True))
    assert r.findings[0].confirmed is True


def test_extend_dedups_same_as_add():
    r = ScanResult(target="t")
    dup = [
        Finding(title="X", severity=Severity.LOW, category="c", file="f.py", line=1),
        Finding(title="X", severity=Severity.LOW, category="c", file="f.py", line=1),
        Finding(title="Y", severity=Severity.LOW, category="c", file="f.py", line=2),
    ]
    r.extend(dup)
    assert len(r.findings) == 2


def test_to_dict_reports_dedup_merged_count():
    r = ScanResult(target="t")
    r.add(Finding(title="X", severity=Severity.HIGH, category="c", file="f.py", line=1))
    r.add(Finding(title="X", severity=Severity.HIGH, category="c", file="f.py", line=1))
    r.add(Finding(title="Solo", severity=Severity.LOW, category="c", file="g.py", line=1))
    d = r.to_dict()
    assert d["dedup_merged"] == 1
    assert len(d["findings"]) == 2
