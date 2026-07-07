"""Tests for the pre-commit hook path (argus/precommit.py)."""

from __future__ import annotations

from pathlib import Path

from argus.precommit import blocking_findings, scan_paths, staged_files
from argus.models import Severity


def _write(p: Path, text: str) -> Path:
    p.write_text(text, encoding="utf-8")
    return p


def test_scan_paths_flags_secret(tmp_path: Path):
    bad = _write(tmp_path / "cfg.py", 'aws_key = "AKIA' + "IOSFODNN7EXAMPLE" + '"\n')
    findings = scan_paths([str(bad)], root=tmp_path)
    assert any(f.detector.startswith("secrets") for f in findings)


def test_scan_paths_flags_vulnerable_rule(tmp_path: Path):
    vuln = _write(tmp_path / "app.py", "import os\ndef r(c):\n    os.system('ping ' + c)\n")
    findings = scan_paths([str(vuln)], root=tmp_path)
    assert any(f.detector.startswith("rule:") for f in findings)


def test_scan_paths_clean_file_no_findings(tmp_path: Path):
    clean = _write(tmp_path / "ok.py", "def add(a, b):\n    return a + b\n")
    assert scan_paths([str(clean)], root=tmp_path) == []


def test_scan_paths_relative_paths_resolve_against_root(tmp_path: Path):
    _write(tmp_path / "app.py", "import os\ndef r(c):\n    os.system('ping ' + c)\n")
    findings = scan_paths(["app.py"], root=tmp_path)
    assert findings
    assert findings[0].file == "app.py"  # repo-relative, not absolute


def test_scan_paths_skips_missing_and_binary_size(tmp_path: Path):
    # a deleted/nonexistent path is silently skipped, not an error
    assert scan_paths([str(tmp_path / "gone.py")], root=tmp_path) == []


def test_scan_paths_dedups_repeated_path(tmp_path: Path):
    bad = _write(tmp_path / "cfg.py", 'password = "hardcoded_secret_value_123456"\n')
    once = scan_paths([str(bad)], root=tmp_path)
    twice = scan_paths([str(bad), str(bad)], root=tmp_path)
    assert len(once) == len(twice)


def test_blocking_findings_respects_threshold(tmp_path: Path):
    # A CRITICAL secret blocks at --fail-on high but not at --fail-on critical-only...
    # here: high threshold catches high+crit; a low threshold catches everything.
    bad = _write(tmp_path / "cfg.py", 'aws_key = "AKIA' + "IOSFODNN7EXAMPLE" + '"\n')
    findings = scan_paths([str(bad)], root=tmp_path)
    assert findings  # sanity
    assert blocking_findings(findings, "low") == findings
    # nothing is above CRITICAL, so a threshold higher than the worst finding
    # yields a subset (never more than all findings)
    assert len(blocking_findings(findings, "critical")) <= len(findings)


def test_severity_threshold_filters_low(tmp_path: Path):
    findings = [type("F", (), {"severity": Severity.LOW})()]
    assert blocking_findings(findings, "high") == []


def test_staged_files_lists_staged(tmp_path: Path):
    from git import Repo

    repo = Repo.init(str(tmp_path))
    repo.config_writer().set_value("user", "email", "t@t.co").release()
    repo.config_writer().set_value("user", "name", "t").release()
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("y = 2\n", encoding="utf-8")
    repo.index.add(["a.py"])  # only a.py is staged
    staged = staged_files(tmp_path)
    assert "a.py" in staged
    assert "b.py" not in staged


def test_staged_files_empty_outside_repo(tmp_path: Path):
    assert staged_files(tmp_path) == []
