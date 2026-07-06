"""Smoke tests for the Typer CLI surface — argus/cli/main.py.

These invoke the actual command layer (not the pipeline functions directly)
to catch wiring bugs: wrong option names, missing imports inside command
bodies (which stay lazy so --help is instant), bad exit codes.
"""

from __future__ import annotations

from typer.testing import CliRunner

from argus.cli.main import app

runner = CliRunner()


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "argus" in result.stdout.lower()


def test_help_lists_all_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ("scan", "attack", "audit", "fix", "demo", "report", "history", "compare", "status", "config", "setup"):
        assert cmd in result.stdout


def test_scan_nonexistent_path_exits_nonzero(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path / "nope"), "--no-llm"])
    assert result.exit_code != 0


def test_report_without_prior_scan_exits_nonzero():
    result = runner.invoke(app, ["report", "--format", "html"])
    assert result.exit_code != 0


def test_config_show_does_not_crash():
    result = runner.invoke(app, ["config", "--show"])
    assert result.exit_code == 0


def test_status_does_not_crash():
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0


def test_status_json_is_valid_and_has_expected_keys():
    import json

    result = runner.invoke(app, ["status", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    for key in ("resolved_provider", "model", "gpu", "scan_defaults", "report_defaults", "agent_count"):
        assert key in payload


def test_attack_without_target_or_url_exits_nonzero():
    result = runner.invoke(app, ["attack"])
    assert result.exit_code != 0


def test_history_does_not_crash_when_empty():
    result = runner.invoke(app, ["history"])
    assert result.exit_code == 0
    assert "no scan history" in result.stdout.lower()


def test_history_json_format_is_valid_when_empty():
    result = runner.invoke(app, ["history", "--format", "json"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "[]"
