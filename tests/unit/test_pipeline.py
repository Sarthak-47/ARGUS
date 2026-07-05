"""Tests for the top-level orchestration in argus/pipeline.py — the paths
that were previously only exercised manually via the CLI, not by the suite.
"""

from __future__ import annotations

import typer
import pytest

from argus.pipeline import run_scan, run_attack, export_last, _export
from argus.models import ScanResult


def test_run_scan_nonexistent_path_exits_cleanly(tmp_path, capsys):
    missing = tmp_path / "does-not-exist"
    with pytest.raises(typer.Exit) as exc_info:
        run_scan(str(missing), deep=False, depth=None, no_llm=True)
    assert exc_info.value.exit_code == 1
    assert "does not exist" in capsys.readouterr().out.lower()


def test_run_scan_end_to_end_on_vuln_repo(vuln_repo):
    result = run_scan(str(vuln_repo), deep=False, depth=None, no_llm=True)
    assert result is not None
    assert result.findings
    assert result.risk_score > 0


def test_run_attack_without_url_or_target_exits_cleanly(capsys):
    with pytest.raises(typer.Exit) as exc_info:
        run_attack(target=None, url=None)
    assert exc_info.value.exit_code == 1
    assert "provide --url" in capsys.readouterr().out.lower()


def test_export_last_without_prior_scan_exits_cleanly(capsys):
    with pytest.raises(typer.Exit) as exc_info:
        export_last(fmt="html")
    assert exc_info.value.exit_code == 1
    assert "no previous scan" in capsys.readouterr().out.lower()


def test_export_unknown_format_exits_cleanly(capsys):
    result = ScanResult(target="t", phase="scan")
    with pytest.raises(typer.Exit) as exc_info:
        _export(result, "docx", None)
    assert exc_info.value.exit_code == 1
    assert "unknown format" in capsys.readouterr().out.lower()


def test_export_pdf_without_weasyprint_warns(tmp_path, capsys):
    # Mirrors the real dev environment: weasyprint isn't installed, so the
    # PDF path silently used to fall back to HTML with zero indication.
    result = ScanResult(target="t", phase="scan")
    path = _export(result, "pdf", str(tmp_path))
    out = capsys.readouterr().out
    if path.suffix != ".pdf":
        assert "weasyprint" in out.lower()
