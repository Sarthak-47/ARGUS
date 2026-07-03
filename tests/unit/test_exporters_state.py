"""Tests for report exporters and last-scan persistence."""

from __future__ import annotations

import json

from argus.models import Finding, ScanResult, Severity
from argus.report.exporters import to_html, to_json, to_markdown, to_sarif, export
from argus.state import save_result, load_result


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


def test_load_result_none_when_absent():
    assert load_result() is None
