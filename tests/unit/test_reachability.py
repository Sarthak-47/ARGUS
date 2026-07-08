"""Tests for SCA reachability analysis (argus/reachability.py)."""

from __future__ import annotations

from pathlib import Path

from argus.models import Finding, Severity
from argus.reachability import annotate_reachability, build_import_index, is_reachable


def _dep(package: str, sev=Severity.HIGH) -> Finding:
    return Finding(title=f"Vulnerable dependency: {package}", severity=sev,
                   category="dependency", detector="pip-audit", file="requirements.txt",
                   metadata={"package": package})


def test_build_import_index_python_and_js(tmp_path: Path):
    (tmp_path / "a.py").write_text("import requests\nfrom flask import Flask\nimport os.path\n", encoding="utf-8")
    (tmp_path / "b.ts").write_text("import express from 'express'\nconst x = require('lodash/merge')\n", encoding="utf-8")
    idx = build_import_index(tmp_path)
    assert {"requests", "flask", "os", "express", "lodash"} <= idx


def test_is_reachable_name_normalization():
    idx = {"yaml", "dateutil", "express"}
    assert is_reachable("PyYAML", idx)              # alias dist->import
    assert is_reachable("python-dateutil", idx)     # alias
    assert is_reachable("express", idx)
    assert not is_reachable("requests", idx)


def test_is_reachable_scoped_npm():
    assert is_reachable("@babel/core", {"@babel/core"})
    assert is_reachable("@babel/core", {"core"})     # bare-name fallback


def test_annotate_downgrades_unimported(tmp_path: Path):
    (tmp_path / "app.py").write_text("import requests\n", encoding="utf-8")
    reached = _dep("requests", Severity.CRITICAL)
    unreached = _dep("leftpad", Severity.CRITICAL)
    annotate_reachability([reached, unreached], tmp_path)

    assert reached.metadata["reachable"] is True
    assert reached.severity is Severity.CRITICAL            # kept
    assert unreached.metadata["reachable"] is False
    assert unreached.severity is Severity.HIGH               # downgraded one step
    assert "not imported" in unreached.description


def test_annotate_ignores_non_dependency_findings(tmp_path: Path):
    other = Finding(title="XSS", severity=Severity.HIGH, category="rules", detector="rule:x")
    annotate_reachability([other], tmp_path)
    assert "reachable" not in other.metadata


def test_low_severity_stays_low_when_unimported(tmp_path: Path):
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    f = _dep("unused", Severity.LOW)
    annotate_reachability([f], tmp_path)
    assert f.severity is Severity.LOW
