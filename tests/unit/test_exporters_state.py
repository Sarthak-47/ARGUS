"""Tests for report exporters and last-scan persistence."""

from __future__ import annotations

import json

from argus.models import Finding, ScanResult, Severity
from argus.report.exporters import to_html, to_json, to_markdown, to_sarif, export
from argus.state import save_result, load_result, load_history, history_path


def _sample() -> ScanResult:
    r = ScanResult(target="github.com/user/app", phase="scan")
    r.add(Finding(
        title="SQL injection in /users", severity=Severity.CRITICAL,
        category="injection", detector="rule:py-sql-fstring", file="app.py", line=7,
        evidence="cur.execute('... ' + name)", description="User input flows into SQL.",
        fix="Use parameterised queries.", cwe="CWE-89",
        poc={"type": "http", "curl": "curl -i -X GET 'http://t/users?name=x'",
             "request": "GET http://t/users?name=x", "response": "HTTP 500\nSQL syntax error"},
    ))
    r.add(Finding(title="Weak hash", severity=Severity.MEDIUM, category="crypto"))
    return r


def test_to_json_is_valid_and_complete():
    data = json.loads(to_json(_sample()))
    assert data["risk_score"] == 48  # 40 + 8
    assert data["counts"]["CRITICAL"] == 1
    assert data["findings"][0]["cwe"] == "CWE-89"


def test_to_markdown_contains_headings():
    md = to_markdown(_sample())
    assert "# Argus Security Report" in md
    assert "SQL injection in /users" in md
    assert "CWE-89" in md


def test_to_html_renders_branding_and_findings():
    html = to_html(_sample())
    assert "ARGUS" in html
    assert "SQL injection in /users" in html
    assert "#8B0000" in html  # critical colour present


def test_to_html_renders_poc_when_present():
    html = to_html(_sample())
    assert "PROOF OF CONCEPT" in html
    assert "curl -i -X GET" in html


def test_to_sarif_is_valid_2_1_0():
    data = json.loads(to_sarif(_sample()))
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "Argus"
    assert len(run["results"]) == 2
    # CRITICAL/HIGH map to error level
    levels = {r["level"] for r in run["results"]}
    assert "error" in levels


def test_to_sarif_includes_poc_properties():
    data = json.loads(to_sarif(_sample()))
    results = data["runs"][0]["results"]
    with_poc = [r for r in results if "poc_curl" in r["properties"]]
    assert len(with_poc) == 1
    assert "curl -i -X GET" in with_poc[0]["properties"]["poc_curl"]


def test_to_sarif_file_based_finding_has_physical_location():
    data = json.loads(to_sarif(_sample()))
    results = data["runs"][0]["results"]
    located = [r for r in results if "locations" in r]
    assert located and "physicalLocation" in located[0]["locations"][0]


def test_export_writes_each_format(tmp_path):
    r = _sample()
    for fmt, name in [("html", "index.html"), ("json", "report.json"),
                      ("markdown", "report.md"), ("sarif", "argus.sarif")]:
        path = export(r, fmt, str(tmp_path / fmt))
        assert path.exists() and path.name == name


def test_export_pdf_falls_back_to_html_without_weasyprint(tmp_path):
    # weasyprint isn't a hard dependency — this dev environment doesn't have
    # it installed, which is exactly the case the fallback exists for.
    path = export(_sample(), "pdf", str(tmp_path))
    assert path.exists()
    # Whichever branch ran, the caller (argus/pipeline.py's _export) detects
    # a fallback purely by suffix mismatch — assert that contract holds.
    if path.suffix != ".pdf":
        assert path.name == "index.html"
        assert "ARGUS" in path.read_text(encoding="utf-8")


def test_state_save_load_roundtrip():
    r = _sample()
    save_result(r)
    loaded = load_result()
    assert loaded is not None
    assert loaded.target == "github.com/user/app"
    assert loaded.risk_score == 48
    assert loaded.sorted_findings()[0].title == "SQL injection in /users"


def test_state_save_load_roundtrip_preserves_poc():
    save_result(_sample())
    loaded = load_result()
    top = loaded.sorted_findings()[0]
    assert top.poc.get("curl") == "curl -i -X GET 'http://t/users?name=x'"


def test_state_save_load_roundtrip_preserves_metadata():
    r = ScanResult(target="t", phase="scan")
    r.add(Finding(title="X", severity=Severity.HIGH, category="c", file="f.py", line=1,
                  metadata={"llm_enriched": True}))
    r.add(Finding(title="X", severity=Severity.HIGH, category="c", file="f.py", line=1,
                  detector="semgrep"))  # collides -> merges, producing merged_count/merged_detectors
    save_result(r)
    loaded = load_result()
    top = loaded.sorted_findings()[0]
    assert top.metadata.get("llm_enriched") is True
    assert top.metadata.get("merged_count") == 2
    assert "semgrep" in top.metadata.get("merged_detectors", [])


def test_load_result_none_when_absent():
    assert load_result() is None


def test_save_result_appends_to_history():
    save_result(_sample())
    entries = load_history()
    assert len(entries) == 1
    assert entries[0]["target"] == "github.com/user/app"
    assert entries[0]["risk_score"] == 48
    assert entries[0]["counts"]["CRITICAL"] == 1


def test_history_filters_by_target():
    save_result(ScanResult(target="repo-a", phase="scan"))
    save_result(ScanResult(target="repo-b", phase="scan"))
    save_result(ScanResult(target="repo-a", phase="attack"))

    only_a = load_history(target="repo-a")
    assert len(only_a) == 2
    assert all(e["target"] == "repo-a" for e in only_a)


def test_history_respects_limit_and_recency_order():
    for i in range(5):
        save_result(ScanResult(target=f"repo-{i}", phase="scan"))

    entries = load_history(limit=2)
    assert len(entries) == 2
    # most recent two, oldest-first within that window
    assert entries[0]["target"] == "repo-3"
    assert entries[1]["target"] == "repo-4"


def test_history_is_capped_at_history_limit(monkeypatch):
    monkeypatch.setattr("argus.state._HISTORY_LIMIT", 3)
    for i in range(10):
        save_result(ScanResult(target=f"repo-{i}", phase="scan"))

    all_entries = load_history(limit=1000)
    assert len(all_entries) == 3
    assert [e["target"] for e in all_entries] == ["repo-7", "repo-8", "repo-9"]


def test_load_history_empty_when_absent():
    assert load_history() == []


def test_history_survives_corrupt_line(tmp_path):
    save_result(ScanResult(target="repo-a", phase="scan"))
    path = history_path()
    with path.open("a", encoding="utf-8") as fh:
        fh.write("not valid json\n")
    save_result(ScanResult(target="repo-b", phase="scan"))

    entries = load_history()
    assert [e["target"] for e in entries] == ["repo-a", "repo-b"]
