"""Tests for the finding lifecycle / suppression store."""

from __future__ import annotations

from argus.models import Finding, Severity
from argus.suppressions import apply_suppressions, clear_by_title, list_for, set_status


def _finding(title="Weak hash algorithm (MD5/SHA1)", file="app.py", line=5):
    return Finding(title=title, severity=Severity.MEDIUM, category="crypto", file=file, line=line)


def test_ignored_finding_is_removed_from_visible_results():
    f = _finding()
    set_status("repo", f, "ignored", reason="accepted risk")

    visible, suppressed_count = apply_suppressions("repo", [f])
    assert visible == []
    assert suppressed_count == 1


def test_reviewing_finding_stays_visible_with_metadata_tag():
    f = _finding()
    set_status("repo", f, "reviewing")

    visible, suppressed_count = apply_suppressions("repo", [f])
    assert len(visible) == 1
    assert visible[0].metadata["lifecycle_status"] == "reviewing"
    assert suppressed_count == 0


def test_suppression_survives_line_number_shift():
    original = _finding(line=5)
    set_status("repo", original, "ignored")

    shifted = _finding(line=42)  # same title/file/category, different line
    visible, suppressed_count = apply_suppressions("repo", [shifted])
    assert visible == []
    assert suppressed_count == 1


def test_suppression_is_scoped_per_target():
    f = _finding()
    set_status("repo-a", f, "ignored")

    visible, suppressed_count = apply_suppressions("repo-b", [f])
    assert len(visible) == 1
    assert suppressed_count == 0


def test_list_for_reflects_recorded_suppressions():
    f = _finding()
    set_status("repo", f, "ignored", reason="legacy compat")

    entries = list_for("repo")
    assert len(entries) == 1
    assert entries[0]["title"] == f.title
    assert entries[0]["reason"] == "legacy compat"


def test_set_status_open_removes_the_entry():
    f = _finding()
    set_status("repo", f, "ignored")
    set_status("repo", f, "open")

    assert list_for("repo") == []
    visible, suppressed_count = apply_suppressions("repo", [f])
    assert len(visible) == 1
    assert suppressed_count == 0


def test_clear_by_title_unsuppresses_a_finding_no_longer_in_visible_results():
    # Regression: a suppressed finding is filtered out of every scan's visible
    # results by design, so un-suppressing can't search *visible findings* —
    # it has to search the suppression records themselves.
    f = _finding()
    set_status("repo", f, "ignored", reason="temp")

    removed = clear_by_title("repo", "weak hash")
    assert len(removed) == 1
    assert removed[0]["title"] == f.title
    assert list_for("repo") == []

    visible, suppressed_count = apply_suppressions("repo", [f])
    assert len(visible) == 1
    assert suppressed_count == 0


def test_clear_by_title_no_match_returns_empty():
    assert clear_by_title("repo", "nonexistent") == []


def test_apply_suppressions_noop_when_nothing_recorded():
    findings = [_finding(), _finding(title="Other issue")]
    visible, suppressed_count = apply_suppressions("repo", findings)
    assert visible == findings
    assert suppressed_count == 0
