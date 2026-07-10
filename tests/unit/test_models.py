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


def test_risk_score_anchored_to_worst_finding():
    # A single finding sits at the floor of its own band — the score reflects
    # the worst issue, not a raw sum that saturates.
    r = ScanResult(target="t")
    r.add(Finding(title="m", severity=Severity.MEDIUM))
    assert r.risk_score == 45 and r.risk_band == "MEDIUM"

    r2 = ScanResult(target="t")
    r2.add(Finding(title="h", severity=Severity.HIGH))
    assert r2.risk_score == 70 and r2.risk_band == "HIGH"

    r3 = ScanResult(target="t")
    r3.add(Finding(title="c", severity=Severity.CRITICAL))
    assert r3.risk_score == 85 and r3.risk_band == "CRITICAL"


def test_risk_score_breadth_climbs_with_diminishing_returns_and_caps():
    r = ScanResult(target="t")
    for i in range(3):
        r.add(Finding(title="c", severity=Severity.CRITICAL, file=f"f{i}.py", line=1))
    mid = r.risk_score
    assert 85 < mid < 100  # more findings raise the score above the single-crit floor
    # piling on more findings approaches but never exceeds 100
    for i in range(3, 20):
        r.add(Finding(title="c", severity=Severity.CRITICAL, file=f"f{i}.py", line=1))
    assert r.risk_score > mid
    assert r.risk_score <= 100
    assert r.risk_band == "CRITICAL"


def test_empty_scan_has_zero_risk():
    assert ScanResult(target="t").risk_score == 0


def test_counts_and_sorting():
    r = ScanResult(target="t")
    r.add(Finding(title="low", severity=Severity.LOW))
    r.add(Finding(title="crit", severity=Severity.CRITICAL))
    r.add(Finding(title="med", severity=Severity.MEDIUM))
    counts = r.counts()
    assert counts["CRITICAL"] == 1 and counts["LOW"] == 1
    titles = [f.title for f in r.sorted_findings()]
    assert titles[0] == "crit"  # worst first


def test_priority_score_rewards_confirmed_confidence_and_cvss():
    plain = Finding(title="x", severity=Severity.HIGH, category="c")
    confirmed = Finding(title="y", severity=Severity.HIGH, category="c", confirmed=True)
    high_confidence = Finding(title="z", severity=Severity.HIGH, category="c", confidence="high")
    with_cvss = Finding(title="w", severity=Severity.HIGH, category="c", cvss=9.5)

    assert confirmed.priority_score > plain.priority_score
    assert high_confidence.priority_score > plain.priority_score
    assert with_cvss.priority_score > plain.priority_score


def test_priority_score_never_lets_a_boosted_lower_severity_outrank_a_higher_one():
    # The whole point of scoping this down: a maxed-out HIGH must never be
    # able to look worse than a bare-minimum CRITICAL in sorted_findings().
    maxed_high = Finding(title="a", severity=Severity.HIGH, category="c",
                          confirmed=True, confidence="high", cvss=10.0)
    bare_critical = Finding(title="b", severity=Severity.CRITICAL, category="c")

    r = ScanResult(target="t")
    r.add(maxed_high)
    r.add(bare_critical)
    assert r.sorted_findings()[0] is bare_critical


def test_sorted_findings_breaks_ties_within_a_severity_by_priority_then_title():
    r = ScanResult(target="t")
    unconfirmed = Finding(title="zzz-should-sort-second", severity=Severity.HIGH,
                           category="c", file="a.py")
    confirmed = Finding(title="aaa-should-sort-first", severity=Severity.HIGH,
                         category="c", file="b.py", confirmed=True)
    r.add(unconfirmed)
    r.add(confirmed)

    ordered = r.sorted_findings()
    assert ordered[0] is confirmed  # higher priority_score wins the tie, not alphabetical title
    assert ordered[1] is unconfirmed


def test_to_dict_roundtrip_shape():
    r = ScanResult(target="t")
    r.add(Finding(title="x", severity=Severity.HIGH, cwe="CWE-89"))
    d = r.to_dict()
    assert d["risk_score"] == 70  # single HIGH sits at the HIGH band floor
    assert d["findings"][0]["severity"] == "HIGH"
    assert d["findings"][0]["cwe"] == "CWE-89"
