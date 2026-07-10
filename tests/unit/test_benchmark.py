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


def test_dvwa_case_has_setup_and_auth_wired():
    dvwa = CASES["dvwa"]
    assert dvwa.setup_path == "/setup.php"
    assert dvwa.auth_login_path == "/login.php"
    assert dvwa.auth_data.get("username") == "admin"
    assert dvwa.auth_csrf_field == "user_token"


def test_run_setup_swallows_errors(monkeypatch):
    import httpx

    from argus.benchmark import _run_setup

    class FailingClient:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, *a, **kw):
            raise httpx.ConnectError("nope")

        def post(self, *a, **kw):
            raise httpx.ConnectError("nope")

    monkeypatch.setattr(httpx, "Client", lambda **kw: FailingClient())
    _run_setup("http://nope", "/setup.php", {"x": "y"}, attempts=1)  # must not raise, no sleep


def test_run_setup_retries_until_db_creation_verified(monkeypatch):
    import httpx

    from argus.benchmark import _run_setup

    posts = {"n": 0}

    class Resp:
        def __init__(self, text, url):
            self.text = text
            self.url = url

    class FlakyClient:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url, *a, **kw):
            # The verify GET reports success only after the DB has been created.
            if posts["n"] >= 2:
                return Resp("Database has been created.", "http://x/setup.php")
            return Resp("<form>Setup DVWA — create database</form>", "http://x/setup.php")

        def post(self, *a, **kw):
            posts["n"] += 1
            return Resp("", "http://x/setup.php")

    monkeypatch.setattr(httpx, "Client", lambda **kw: FlakyClient())
    monkeypatch.setattr("time.sleep", lambda s: None)  # don't actually wait in tests
    _run_setup("http://x", "/setup.php", {"x": "y"}, attempts=4)
    assert posts["n"] == 2  # kept trying until the verify GET confirmed creation


def test_docker_target_wires_csrf_aware_auth(monkeypatch):
    """The full _run_docker_target flow, with Docker and the network mocked:
    proves setup runs, an AuthConfig is built with the right params, and it's
    passed into run_attack_sync -- without needing a real DVWA container."""
    from argus.benchmark import CASES, _run_docker_target

    setup_calls = []
    attack_calls = []

    class FakeContainer:
        def remove(self, force=True):
            pass

    class FakeContainers:
        def run(self, *a, **kw):
            return FakeContainer()

    class FakeClient:
        containers = FakeContainers()

    monkeypatch.setattr("docker.from_env", lambda: FakeClient())
    monkeypatch.setattr("argus.sandbox.docker_manager._wait_until_reachable", lambda url, timeout: True)
    monkeypatch.setattr(
        "argus.benchmark._run_setup",
        lambda base, path, data, csrf_field=None: setup_calls.append((path, data, csrf_field)),
    )

    def fake_attack_sync(base_url, use_callback=False, auth=None, identity_b=None):
        attack_calls.append((auth, identity_b))
        return [], [], []

    monkeypatch.setattr("argus.llm.orchestrator.run_attack_sync", fake_attack_sync)

    _run_docker_target(CASES["dvwa"])

    assert setup_calls and setup_calls[0][0] == "/setup.php"
    assert setup_calls[0][2] == "user_token"  # setup CSRF token is wired through
    assert len(attack_calls) == 1
    auth, _identity_b = attack_calls[0]
    assert auth is not None
    assert auth.login_url.endswith("/login.php")
    assert auth.csrf_field == "user_token"
    assert auth.login_data["username"] == "admin"


def test_vampi_case_wires_jwt_login_and_second_identity(monkeypatch):
    """VAmPI is a JWT API: primary identity logs in via JSON and extracts a
    bearer token; a second identity (name2) is built for BOLA testing."""
    from argus.benchmark import CASES, _run_docker_target

    attack_calls = []

    class FakeContainer:
        def remove(self, force=True):
            pass

    class FakeClient:
        class containers:
            @staticmethod
            def run(*a, **kw):
                return FakeContainer()

    monkeypatch.setattr("docker.from_env", lambda: FakeClient())
    monkeypatch.setattr("argus.sandbox.docker_manager._wait_until_reachable", lambda url, timeout: True)
    monkeypatch.setattr("argus.benchmark._run_setup", lambda *a, **k: None)

    def fake_attack_sync(base_url, use_callback=False, auth=None, identity_b=None):
        attack_calls.append((auth, identity_b))
        return [], [], []

    monkeypatch.setattr("argus.llm.orchestrator.run_attack_sync", fake_attack_sync)

    _run_docker_target(CASES["vampi"])

    auth, identity_b = attack_calls[0]
    assert auth.login_json is True
    assert auth.token_json_path == "auth_token"
    assert auth.login_data["username"] == "name1"
    assert identity_b is not None
    assert identity_b.login_data["username"] == "name2"
