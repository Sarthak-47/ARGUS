"""Tests for the top-level orchestration in argus/pipeline.py — the paths
that were previously only exercised manually via the CLI, not by the suite.
"""

from __future__ import annotations

import typer
import pytest

import argus.pipeline as pipeline
from argus.pipeline import run_scan, run_attack, export_last, _export, _reverify_fixes
from argus.compare import finding_signature
from argus.models import Finding, ScanResult
from argus.fix import AppliedFix


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


def test_run_scan_policy_fails_ci_on_matching_finding(vuln_repo):
    # vuln_repo has an injection finding; a policy that fails on injection
    # should make run_scan exit non-zero (the CI gate).
    (vuln_repo / "gate.toml").write_text(
        'default = "warn"\n\n[[rules]]\ncategory = "injection"\naction = "fail"\n',
        encoding="utf-8",
    )
    with pytest.raises(typer.Exit) as exc_info:
        run_scan(str(vuln_repo), deep=False, depth=None, no_llm=True,
                 policy=str(vuln_repo / "gate.toml"))
    assert exc_info.value.exit_code == 2


def test_run_scan_policy_passes_when_only_warnings(vuln_repo):
    (vuln_repo / "gate.toml").write_text('default = "warn"\n', encoding="utf-8")
    result = run_scan(str(vuln_repo), deep=False, depth=None, no_llm=True,
                      policy=str(vuln_repo / "gate.toml"))
    assert result is not None  # no exit raised


def test_run_scan_missing_policy_file_exits_cleanly(vuln_repo, capsys):
    with pytest.raises(typer.Exit) as exc_info:
        run_scan(str(vuln_repo), deep=False, depth=None, no_llm=True, policy="does-not-exist.toml")
    assert exc_info.value.exit_code == 1
    assert "policy file not found" in capsys.readouterr().out.lower()


def test_run_scan_auto_discovers_policy_in_target_dir(vuln_repo):
    # A .argus-policy.toml sitting in the target dir is applied with no --policy flag.
    (vuln_repo / ".argus-policy.toml").write_text(
        'default = "warn"\n\n[[rules]]\ncategory = "injection"\naction = "fail"\n',
        encoding="utf-8",
    )
    with pytest.raises(typer.Exit) as exc_info:
        run_scan(str(vuln_repo), deep=False, depth=None, no_llm=True)
    assert exc_info.value.exit_code == 2


def test_run_scan_gate_false_skips_policy_gating(vuln_repo):
    # gate=False (what `argus audit`'s Phase 1 uses) must not raise even when a
    # fail-policy would otherwise abort — the audit needs to reach Phase 2.
    (vuln_repo / ".argus-policy.toml").write_text(
        'default = "warn"\n\n[[rules]]\ncategory = "injection"\naction = "fail"\n',
        encoding="utf-8",
    )
    result = run_scan(str(vuln_repo), deep=False, depth=None, no_llm=True, gate=False)
    assert result is not None  # no typer.Exit raised


def test_explicit_fail_on_takes_precedence_over_auto_discovered_policy(tmp_path):
    # An explicit --fail-on is a deliberate choice; an auto-discovered policy
    # file must not silently override it. This repo has only a MEDIUM finding
    # (weak MD5): --fail-on critical won't trip, but the auto-policy WOULD fail
    # on the crypto category — so a clean return proves the policy was skipped.
    repo = tmp_path / "medium-only"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import hashlib\ndef h(p):\n    return hashlib.md5(p.encode()).hexdigest()\n",
        encoding="utf-8",
    )
    (repo / ".argus-policy.toml").write_text(
        'default = "warn"\n\n[[rules]]\ncategory = "crypto"\naction = "fail"\n',
        encoding="utf-8",
    )
    result = run_scan(str(repo), deep=False, depth=None, no_llm=True, fail_on="critical")
    assert result is not None  # --fail-on critical didn't trip; auto-policy was skipped


def test_run_scan_diff_base_keeps_only_changed_file_findings(tmp_path):
    from git import Repo

    repo_dir = tmp_path / "gitrepo"
    repo = Repo.init(str(repo_dir), initial_branch="main")
    repo.config_writer().set_value("user", "email", "t@t.co").release()
    repo.config_writer().set_value("user", "name", "t").release()

    # main: a pre-existing weak-hash finding
    (repo_dir / "old.py").write_text(
        "import hashlib\ndef h(p):\n    return hashlib.md5(p.encode()).hexdigest()\n", encoding="utf-8")
    repo.index.add(["old.py"])
    repo.index.commit("base")

    # feature branch adds a new file with a command-injection finding
    repo.git.checkout("-b", "feature")
    (repo_dir / "new.py").write_text(
        "import os\ndef r(c):\n    os.system('ping ' + c)\n", encoding="utf-8")
    repo.index.add(["new.py"])
    repo.index.commit("feat")

    result = run_scan(str(repo_dir), deep=False, depth=None, no_llm=True, diff_base="main")
    files = {f.file for f in result.findings}
    assert "new.py" in files
    assert "old.py" not in files  # pre-existing, not in the diff


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


def test_signature_ignores_line_number():
    # A correct patch routinely shifts every line below it — the reverify
    # check must not treat that shift alone as "still vulnerable".
    a = finding_signature(Finding(title="Weak hash algorithm (MD5/SHA1)", severity="MEDIUM",
                                   category="crypto", file="app.py", line=5))
    b = finding_signature(Finding(title="  weak hash algorithm (md5/sha1)  ", severity="MEDIUM",
                                   category="crypto", file="APP.PY", line=90))
    assert a == b


def test_reverify_reports_confirmed_closed_when_finding_gone(monkeypatch, capsys):
    original = Finding(title="Weak hash algorithm (MD5/SHA1)", severity="MEDIUM",
                        category="crypto", file="app.py", line=5)
    fixed_scan = ScanResult(target="t", phase="scan")  # no findings — patch worked

    monkeypatch.setattr(pipeline, "_do_scan", lambda *a, **k: fixed_scan)

    applied = AppliedFix(finding_id=original.id, file="app.py", explanation="", diff="", written=True)
    _reverify_fixes("some/repo", [original], [applied])

    out_text = capsys.readouterr().out
    assert "confirmed closed" in out_text.lower()
    assert "still detected" not in out_text.lower()


def test_reverify_reports_still_detected_when_finding_persists(monkeypatch, capsys):
    original = Finding(title="Weak hash algorithm (MD5/SHA1)", severity="MEDIUM",
                        category="crypto", file="app.py", line=5)
    # Same signature still present post-patch (e.g. the LLM's fix was a no-op) —
    # line moved to 9, which must not make this look like a different finding.
    still_there = Finding(title="Weak hash algorithm (MD5/SHA1)", severity="MEDIUM",
                           category="crypto", file="app.py", line=9)
    fresh_scan = ScanResult(target="t", phase="scan")
    fresh_scan.extend([still_there])

    monkeypatch.setattr(pipeline, "_do_scan", lambda *a, **k: fresh_scan)

    applied = AppliedFix(finding_id=original.id, file="app.py", explanation="", diff="", written=True)
    _reverify_fixes("some/repo", [original], [applied])

    assert "still detected" in capsys.readouterr().out.lower()
