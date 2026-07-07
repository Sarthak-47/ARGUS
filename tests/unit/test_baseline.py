"""Tests for baseline support (adopt-on-legacy-repo workflow)."""

from __future__ import annotations

from pathlib import Path

from argus.baseline import filter_new, load_baseline, write_baseline
from argus.models import Finding, Severity


def _f(title, *, category="rules", file="app.py", line=10):
    return Finding(title=title, severity=Severity.HIGH, category=category,
                   detector="rule:x", file=file, line=line)


def test_write_then_load_roundtrips(tmp_path: Path):
    findings = [_f("SQL injection"), _f("Hardcoded secret", category="secrets")]
    path = tmp_path / ".argus-baseline.json"
    n = write_baseline(path, findings)
    assert n == 2
    assert path.is_file()
    loaded = load_baseline(path)
    assert len(loaded) == 2


def test_write_deduplicates_signatures(tmp_path: Path):
    # Same signature (category+file+title) recorded once even if two Finding objects.
    findings = [_f("SQL injection"), _f("SQL injection")]
    path = tmp_path / "b.json"
    assert write_baseline(path, findings) == 1


def test_filter_new_hides_baselined_shows_new(tmp_path: Path):
    old = [_f("SQL injection"), _f("XSS", category="rules")]
    path = tmp_path / "b.json"
    write_baseline(path, old)
    baseline = load_baseline(path)

    current = [_f("SQL injection"), _f("XSS", category="rules"), _f("New bug")]
    new, baselined = filter_new(current, baseline)
    assert baselined == 2
    assert [f.title for f in new] == ["New bug"]


def test_baseline_survives_line_number_shift(tmp_path: Path):
    # A finding that moved from line 10 to line 42 (unrelated edit above it) is
    # still the same signature — must stay baselined.
    path = tmp_path / "b.json"
    write_baseline(path, [_f("SQL injection", line=10)])
    baseline = load_baseline(path)
    new, baselined = filter_new([_f("SQL injection", line=42)], baseline)
    assert baselined == 1
    assert new == []


def test_load_missing_or_garbage_returns_empty(tmp_path: Path):
    assert load_baseline(tmp_path / "nope.json") == set()
    bad = tmp_path / "bad.json"
    bad.write_text("not json{", encoding="utf-8")
    assert load_baseline(bad) == set()


def test_empty_baseline_lets_everything_through():
    new, baselined = filter_new([_f("A"), _f("B")], set())
    assert baselined == 0
    assert len(new) == 2
