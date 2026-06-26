"""Tests for the core data models: severity ordering, risk scoring, serialisation."""

from __future__ import annotations

from argus.models import Finding, ScanResult, Severity


def test_severity_coerce_and_rank():
    assert Severity.coerce("critical") is Severity.CRITICAL
    assert Severity.coerce("BOGUS") is Severity.INFO
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.LOW.rank
    assert Severity.CRITICAL.color == "#8B0000"


def test_finding_location_prefers_endpoint():
    f = Finding(title="x", severity=Severity.HIGH, file="a.py", line=10)
    assert f.location == "a.py:10"
    f2 = Finding(title="y", severity=Severity.HIGH, endpoint="/api/users")
    assert f2.location == "/api/users"


def test_risk_score_saturates_at_100():
    r = ScanResult(target="t")
    for _ in range(5):
        r.add(Finding(title="c", severity=Severity.CRITICAL))  # 40 each -> 200 raw
    assert r.risk_score == 100
    assert r.risk_band == "CRITICAL"


def test_risk_score_bands():
    r = ScanResult(target="t")
    r.add(Finding(title="m", severity=Severity.MEDIUM))  # weight 8
    assert r.risk_score == 8
    assert r.risk_band == "LOW"


def test_counts_and_sorting():
    r = ScanResult(target="t")
    r.add(Finding(title="low", severity=Severity.LOW))
    r.add(Finding(title="crit", severity=Severity.CRITICAL))
    r.add(Finding(title="med", severity=Severity.MEDIUM))
    counts = r.counts()
    assert counts["CRITICAL"] == 1 and counts["LOW"] == 1
    titles = [f.title for f in r.sorted_findings()]
    assert titles[0] == "crit"  # worst first


def test_to_dict_roundtrip_shape():
    r = ScanResult(target="t")
    r.add(Finding(title="x", severity=Severity.HIGH, cwe="CWE-89"))
    d = r.to_dict()
    assert d["risk_score"] == 20
    assert d["findings"][0]["severity"] == "HIGH"
    assert d["findings"][0]["cwe"] == "CWE-89"
