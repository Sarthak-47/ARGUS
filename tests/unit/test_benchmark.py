"""Tests for the benchmark suite (argus/benchmark.py).

The scoring logic is pure and fully tested here. The `argus_demo` case is also
exercised end-to-end (it needs no Docker — DemoServer is an in-process stdlib
HTTP server), locking in that the harness, the demo target, and the curated
ground truth all actually agree with each other.
"""

from __future__ import annotations

from argus.benchmark import CASES, GroundTruthEntry, render_markdown, run_case, score
from argus.models import Finding, Severity


def _f(**kw) -> Finding:
    base = dict(title="X", severity=Severity.HIGH, category="c", detector="d")
    base.update(kw)
    return Finding(**base)


# ----- GroundTruthEntry.matches -----

def test_matches_on_category():
    e = GroundTruthEntry("x", category="injection")
    assert e.matches(_f(category="injection"))
    assert not e.matches(_f(category="xss"))


def test_matches_on_detector_prefix():
    e = GroundTruthEntry("x", detector_prefix="authbreaker")
    assert e.matches(_f(detector="authbreaker:jwt-none"))
    assert not e.matches(_f(detector="idorhunter"))


def test_matches_on_cwe():
    e = GroundTruthEntry("x", cwe="CWE-89")
    assert e.matches(_f(cwe="CWE-89"))
    assert not e.matches(_f(cwe="CWE-79"))
    assert not e.matches(_f(cwe=None))


def test_matches_on_title_contains_case_insensitive():
    e = GroundTruthEntry("x", title_contains="sql injection")
    assert e.matches(_f(title="Possible SQL Injection (string-built)"))
    assert not e.matches(_f(title="XSS"))


def test_matches_requires_all_given_criteria():
    e = GroundTruthEntry("x", category="injection", cwe="CWE-89")
    assert e.matches(_f(category="injection", cwe="CWE-89"))
    assert not e.matches(_f(category="injection", cwe="CWE-79"))  # category ok, cwe wrong


def test_matches_with_no_criteria_matches_anything():
    e = GroundTruthEntry("x")
    assert e.matches(_f())


# ----- score() -----

def test_score_all_detected():
    gt = [GroundTruthEntry("sqli", cwe="CWE-89"), GroundTruthEntry("xss", cwe="CWE-79")]
    findings = [_f(cwe="CWE-89"), _f(cwe="CWE-79")]
    detected, missed, unmatched = score(findings, gt)
    assert set(detected) == {"sqli", "xss"}
    assert missed == []
    assert unmatched == 0


def test_score_partial_detection():
    gt = [GroundTruthEntry("sqli", cwe="CWE-89"), GroundTruthEntry("ssrf", cwe="CWE-918")]
    findings = [_f(cwe="CWE-89")]
    detected, missed, unmatched = score(findings, gt)
    assert detected == ["sqli"]
    assert missed == ["ssrf"]
    assert unmatched == 0


def test_score_each_ground_truth_entry_consumed_at_most_once():
    # Two identical findings must not double-satisfy one ground-truth entry,
    # nor let one ground-truth entry "eat" the finding meant for another.
    gt = [GroundTruthEntry("a", cwe="CWE-89"), GroundTruthEntry("b", cwe="CWE-89")]
    findings = [_f(cwe="CWE-89")]  # only one real finding
    detected, missed, unmatched = score(findings, gt)
    assert len(detected) == 1
    assert len(missed) == 1
    assert unmatched == 0


def test_score_extra_findings_are_unmatched_not_penalized_as_missed():
    gt = [GroundTruthEntry("sqli", cwe="CWE-89")]
    findings = [_f(cwe="CWE-89"), _f(cwe="CWE-79"), _f(cwe="CWE-22")]
    detected, missed, unmatched = score(findings, gt)
    assert detected == ["sqli"]
    assert missed == []
    assert unmatched == 2


def test_score_empty_ground_truth():
    detected, missed, unmatched = score([_f()], [])
    assert detected == []
    assert missed == []
    assert unmatched == 1


# ----- BenchmarkResult -----

def test_detection_rate_and_unmatched_rate():
    from argus.benchmark import BenchmarkResult

    r = BenchmarkResult(case="x", total_findings=10, ground_truth_count=4,
                        detected=["a", "b", "c"], missed=["d"], unmatched_findings=6)
    assert r.detection_rate == 0.75
    assert r.unmatched_rate == 0.6


def test_detection_rate_zero_ground_truth_is_zero_not_error():
    from argus.benchmark import BenchmarkResult

    r = BenchmarkResult(case="x", total_findings=0, ground_truth_count=0)
    assert r.detection_rate == 0.0
    assert r.unmatched_rate == 0.0


def test_to_dict_roundtrips_key_fields():
    from argus.benchmark import BenchmarkResult

    r = BenchmarkResult(case="x", total_findings=5, ground_truth_count=2,
                        detected=["a", "b"], duration_s=1.234)
    d = r.to_dict()
    assert d["case"] == "x"
    assert d["detection_rate"] == 1.0
    assert d["duration_s"] == 1.2


# ----- render_markdown -----

def test_render_markdown_includes_case_and_rate():
    from argus.benchmark import BenchmarkResult

    r = BenchmarkResult(case="demo", total_findings=3, ground_truth_count=2, detected=["a", "b"])
    md = render_markdown([r])
    assert "demo" in md
    assert "100%" in md


def test_render_markdown_shows_error_row():
    from argus.benchmark import BenchmarkResult

    r = BenchmarkResult(case="broken", total_findings=0, ground_truth_count=1,
                        missed=["x"], error="Docker isn't reachable")
    md = render_markdown([r])
    assert "broken" in md
    assert "error" in md.lower()


# ----- end-to-end: the local case actually runs and detects everything it claims -----

def test_argus_demo_case_registered():
    assert "argus_demo" in CASES
    assert CASES["argus_demo"].kind == "local"
    assert len(CASES["argus_demo"].ground_truth) > 5


def test_argus_demo_case_runs_end_to_end_with_full_detection():
    # This needs no Docker/network -- DemoServer is an in-process stdlib server.
    # Locks in that the harness, the bundled target, and the curated ground
    # truth all actually agree (this test would have caught the SQLi-pattern
    # mismatch bug found and fixed during this feature's development).
    result = run_case(CASES["argus_demo"])
    assert result.error is None
    assert result.detection_rate == 1.0, f"missed: {result.missed}"
    assert result.total_findings > 0


def test_docker_cases_registered_with_images():
    for name in ("juice_shop", "dvwa", "vampi"):
        case = CASES[name]
        assert case.kind == "docker"
        assert case.image
        assert case.container_port
        assert len(case.ground_truth) > 0
