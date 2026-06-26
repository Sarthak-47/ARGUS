"""Tests for the built-in deterministic code rules and ingestion."""

from __future__ import annotations

from argus.scanner.ingestion import ingest
from argus.scanner.rules_builtin import scan_rules


def test_rules_detect_core_vulns(vuln_repo):
    findings = scan_rules(vuln_repo)
    cats = {f.category for f in findings}
    titles = " ".join(f.title for f in findings)
    assert "injection" in cats
    assert "SQL injection" in titles
    assert "command injection" in titles
    assert "yaml" in titles.lower()
    assert "MD5" in titles or "weak" in titles.lower()


def test_rules_skip_comments(tmp_path):
    f = tmp_path / "x.py"
    f.write_text("# os.system('rm -rf ' + x)\nprint('safe')\n", encoding="utf-8")
    findings = scan_rules(tmp_path)
    assert findings == []


def test_ingest_builds_map(vuln_repo):
    ing = ingest(str(vuln_repo))
    assert ing.cleanup is False
    cm = ing.map
    assert cm.primary_language == "Python"
    assert "Flask" in cm.frameworks or "React" in cm.frameworks
    assert "requirements.txt" in cm.dependency_manifests
    assert cm.file_count >= 1


def test_ingest_missing_path_raises(tmp_path):
    import pytest

    with pytest.raises(FileNotFoundError):
        ingest(str(tmp_path / "does-not-exist"))
