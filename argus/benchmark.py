"""Benchmark suite against known-vulnerable apps (roadmap v1.0.1).

A scanner's claims are worth nothing without a number behind them. This runs
Argus against apps whose vulnerabilities are already documented (OWASP Juice
Shop, DVWA, VAmPI, and Argus's own bundled demo target), matches the findings
it produces against a hand-curated ground truth, and reports a detection rate
and a false-positive estimate per category — not vibes.

Two kinds of cases:
  - **local** (`argus_demo`): runs entirely in-process against the bundled
    `DemoServer`, no Docker/network needed — the one every dev environment can
    run, used to sanity-check the harness itself.
  - **docker** (Juice Shop, DVWA, VAmPI): pulls a well-known vulnerable image,
    runs the attack swarm against it, tears it down. Needs Docker; the
    `benchmark.yml` GitHub Actions workflow runs these on every release, since
    GitHub-hosted runners have Docker even when a local dev machine doesn't.

Ground truth is intentionally scoped to the subset of each app's documented
vulnerabilities that fall within Argus's actual detector coverage — matching
against a target's *full* CVE/challenge list would silently penalize Argus for
vulnerability classes no agent claims to find, which isn't an honest number.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from argus.models import Finding


@dataclass
class GroundTruthEntry:
    """One documented vulnerability a case's target is known to have.

    A finding matches when every criterion given here is satisfied; leave a
    criterion as ``None`` to not constrain on it. ``title_contains`` is a
    case-insensitive substring match against the finding's title.
    """

    description: str
    category: str | None = None
    detector_prefix: str | None = None
    cwe: str | None = None
    title_contains: str | None = None

    def matches(self, f: Finding) -> bool:
        if self.category is not None and f.category != self.category:
            return False
        if self.detector_prefix is not None and not f.detector.startswith(self.detector_prefix):
            return False
        if self.cwe is not None and f.cwe != self.cwe:
            return False
        if self.title_contains is not None and self.title_contains.lower() not in f.title.lower():
            return False
        return True


@dataclass
class BenchmarkCase:
    name: str
    description: str
    kind: str  # "local" | "docker"
    ground_truth: list[GroundTruthEntry]
    # docker cases only:
    image: str | None = None
    container_port: int | None = None
    ready_path: str = "/"
    # A one-time POST needed before the target is usable at all (DVWA's fresh
    # container has no database until this runs) — best-effort, errors ignored.
    setup_path: str | None = None
    setup_data: dict[str, str] | None = None
    # DVWA's setup form (like its login) carries a CSRF token that must be
    # scraped from the page and posted back, or the DB is never created and
    # every page redirects to setup.php — making the whole target unusable.
    setup_csrf_field: str | None = None
    # Auth *parameters*, not a built AuthConfig — the login URL needs the
    # container's dynamically-assigned host port, only known at run time.
    auth_login_path: str | None = None
    auth_data: dict[str, str] | None = None
    auth_csrf_field: str | None = None
    # JSON-body login that returns a bearer token (a JWT API like VAmPI), plus an
    # optional second identity for cross-user BOLA testing.
    auth_login_json: bool = False
    auth_token_json_path: str | None = None
    identity_b_data: dict[str, str] | None = None
    # An extra request some apps need right after login (DVWA's per-session
    # security level defaults to "impossible" — all vulnerable pages patched —
    # until this runs on the same authenticated session).
    post_login_path: str | None = None
    post_login_data: dict[str, str] | None = None


@dataclass
class BenchmarkResult:
    case: str
    total_findings: int
    ground_truth_count: int
    detected: list[str] = field(default_factory=list)   # descriptions matched
    missed: list[str] = field(default_factory=list)      # descriptions not matched
    unmatched_findings: int = 0                          # findings matching no ground-truth entry
    duration_s: float = 0.0
    error: str | None = None

    @property
    def detection_rate(self) -> float:
        if self.ground_truth_count == 0:
            return 0.0
        return len(self.detected) / self.ground_truth_count

    @property
    def unmatched_rate(self) -> float:
        if self.total_findings == 0:
            return 0.0
        return self.unmatched_findings / self.total_findings

    def to_dict(self) -> dict:
        return {
            "case": self.case,
            "detection_rate": round(self.detection_rate, 3),
            "detected": len(self.detected), "ground_truth_count": self.ground_truth_count,
            "missed": self.missed,
            "total_findings": self.total_findings,
            "unmatched_findings": self.unmatched_findings,
            "unmatched_rate": round(self.unmatched_rate, 3),
            "duration_s": round(self.duration_s, 1),
            "error": self.error,
        }


def score(findings: list[Finding], ground_truth: list[GroundTruthEntry]) -> tuple[list[str], list[str], int]:
    """Greedily match findings to ground-truth entries (each entry consumed at
    most once). Returns (detected_descriptions, missed_descriptions,
    unmatched_finding_count)."""
    remaining = list(ground_truth)
    detected: list[str] = []
    used_findings: set[int] = set()
    for entry in ground_truth:
        for i, f in enumerate(findings):
            if i in used_findings:
                continue
            if entry.matches(f):
                detected.append(entry.description)
                used_findings.add(i)
                remaining.remove(entry)
                break
    missed = [e.description for e in remaining]
    unmatched = len(findings) - len(used_findings)
    return detected, missed, unmatched


# --------------------------------------------------------------------------- #
# the always-runnable local case
# --------------------------------------------------------------------------- #
_ARGUS_DEMO_GROUND_TRUTH = [
    # Note: the demo source deliberately splits its AWS/Stripe-looking literals
    # across a string concatenation (e.g. 'AKIA' + 'IOSFODNN7EXAMPLE') so this
    # repo itself never contains a contiguous, push-protection-triggering
    # secret — so those two specifically can never fire as their own named-format
    # findings here. JWT_SECRET is a genuine single-literal secret and does.
    GroundTruthEntry("Hardcoded JWT signing secret (generic secret pattern)",
                     detector_prefix="secrets", title_contains="generic secret"),
    GroundTruthEntry("SQL injection via string-built query", cwe="CWE-89"),
    GroundTruthEntry("OS command injection via shell=True", cwe="CWE-78"),
    GroundTruthEntry("Weak hash algorithm (MD5)", category="crypto"),
    GroundTruthEntry("Unsafe yaml.load", cwe="CWE-502"),
    GroundTruthEntry("Flask debug mode enabled", title_contains="debug"),
    GroundTruthEntry("Reflected XSS (attack-confirmed)", detector_prefix="xsshunter"),
    GroundTruthEntry("SSRF via server-side fetch (attack-confirmed)", detector_prefix="ssrfprober"),
    GroundTruthEntry("SQL injection (attack-confirmed, error-based)", detector_prefix="injector"),
    GroundTruthEntry("JWT signed with a weak/guessable secret", detector_prefix="authbreaker"),
    GroundTruthEntry("Permissive CORS (reflects Origin + credentials)", detector_prefix="headerpoker"),
    GroundTruthEntry("IDOR on /api/orders/<id>", detector_prefix="idorhunter"),
    GroundTruthEntry("Path traversal via /download?file=", detector_prefix="fileattacker"),
    GroundTruthEntry("GraphQL introspection enabled", detector_prefix="graphqlagent"),
]


def _run_local_demo() -> list[Finding]:
    import shutil
    import tempfile

    from argus.demo.target import SAMPLE_FILES, DemoServer
    from argus.llm.orchestrator import run_attack_sync
    from argus.scanner import rules_builtin, secrets

    findings: list[Finding] = []
    tmp_dir = Path(tempfile.mkdtemp(prefix="argus-bench-"))
    try:
        for name, content in SAMPLE_FILES.items():
            (tmp_dir / name).write_text(content, encoding="utf-8")
        findings.extend(rules_builtin.scan_rules(tmp_dir))
        findings.extend(secrets.scan_secrets(tmp_dir))
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    server = DemoServer().start()
    try:
        # use_callback=True (the real default): SSRFProber's confirmed detection
        # is callback-based, so disabling it would understate real detection.
        attack_findings, _reports, _eps = run_attack_sync(server.url, use_callback=True)
        findings.extend(attack_findings)
    finally:
        server.stop()
    return findings


# --------------------------------------------------------------------------- #
# Docker-based cases — well-known vulnerable apps with documented findings
# --------------------------------------------------------------------------- #
JUICE_SHOP_GROUND_TRUTH = [
    GroundTruthEntry("Missing/weak security headers", category="misconfig"),
    GroundTruthEntry("Permissive CORS configuration", detector_prefix="headerpoker"),
    GroundTruthEntry("GraphQL/API introspection or schema exposure", detector_prefix="graphqlagent"),
    GroundTruthEntry("Reflected or stored XSS", detector_prefix="xsshunter"),
    GroundTruthEntry("SQL injection in a login/search endpoint", detector_prefix="injector"),
    GroundTruthEntry("IDOR on a user/order/basket resource", detector_prefix="idorhunter"),
    GroundTruthEntry("JWT/session weakness", detector_prefix="authbreaker"),
]

DVWA_GROUND_TRUTH = [
    GroundTruthEntry("SQL injection", detector_prefix="injector"),
    GroundTruthEntry("Reflected/stored XSS", detector_prefix="xsshunter"),
    GroundTruthEntry("Command injection", category="injection"),
    GroundTruthEntry("CSRF on a state-changing form", detector_prefix="csrfhunter"),
    GroundTruthEntry("Path/file traversal or inclusion", detector_prefix="fileattacker"),
    GroundTruthEntry("Missing security headers", category="misconfig"),
]

VAMPI_GROUND_TRUTH = [
    GroundTruthEntry("BOLA — cross-user object access", detector_prefix="authztester:bola"),
    GroundTruthEntry("BOLA/IDOR via numeric ID enumeration", detector_prefix="idorhunter"),
    GroundTruthEntry("Excessive data exposure / missing auth", detector_prefix="dataexposure"),
    GroundTruthEntry("SQL injection in an API parameter", detector_prefix="injector"),
    GroundTruthEntry("JWT/auth weakness", detector_prefix="authbreaker"),
]

CASES: dict[str, BenchmarkCase] = {
    "argus_demo": BenchmarkCase(
        name="argus_demo", description="Argus's own bundled vulnerable app (local, no Docker needed)",
        kind="local", ground_truth=_ARGUS_DEMO_GROUND_TRUTH,
    ),
    "juice_shop": BenchmarkCase(
        name="juice_shop", description="OWASP Juice Shop", kind="docker",
        image="bkimminich/juice-shop:latest", container_port=3000, ready_path="/",
        ground_truth=JUICE_SHOP_GROUND_TRUTH,
    ),
    "dvwa": BenchmarkCase(
        name="dvwa", description="Damn Vulnerable Web Application", kind="docker",
        image="vulnerables/web-dvwa:latest", container_port=80, ready_path="/login.php",
        ground_truth=DVWA_GROUND_TRUTH,
        # A fresh container has no database until this runs once.
        setup_path="/setup.php", setup_data={"create_db": "Create / Reset Database"},
        # DVWA's documented default credentials; its login form is
        # CSRF-token-protected (roadmap v1.0.1 follow-up B).
        auth_login_path="/login.php",
        auth_data={"username": "admin", "password": "password", "Login": "Login"},
        auth_csrf_field="user_token",
        setup_csrf_field="user_token",
        # DVWA's vulnerable pages are patched at "impossible" difficulty by
        # default for a fresh session; this lowers it so the real bug classes
        # are actually reachable to attack.
        post_login_path="/security.php",
        post_login_data={"security": "low", "seclev_submit": "Submit"},
    ),
    "vampi": BenchmarkCase(
        name="vampi", description="VAmPI (Vulnerable API)", kind="docker",
        image="erev0s/vampi:latest", container_port=5000, ready_path="/",
        ground_truth=VAMPI_GROUND_TRUTH,
        # VAmPI ships empty; GET /createdb seeds users name1/pass1 … name4.
        setup_path="/createdb",
        # JWT API: POST /users/v1/login returns {"auth_token": "<jwt>"}.
        auth_login_path="/users/v1/login",
        auth_data={"username": "name1", "password": "pass1"},
        auth_login_json=True,
        auth_token_json_path="auth_token",
        # A second real user for cross-user BOLA (authztester).
        identity_b_data={"username": "name2", "password": "pass2"},
    ),
}


def _run_setup(base_url: str, path: str, data: dict[str, str],
               csrf_field: str | None = None, attempts: int = 4) -> None:
    """One-time POST a fresh target needs before it's usable at all (DVWA's DB
    init). Uses ONE session across the GET+POST so a scraped CSRF token and the
    session cookie it's bound to travel together, scrapes the setup form's
    hidden token (DVWA's setup.php carries a ``user_token`` exactly like its
    login — omitting it silently no-ops the DB creation and leaves every page
    redirecting to setup.php), follows redirects so the creation actually
    completes, and verifies by re-fetching the setup page. Retries with backoff
    because a multi-process image (web server + database supervised together)
    can still be initializing the database for a few seconds after the web
    server already answers — so an early attempt can race an unready backend.
    Errors are swallowed: the target may already be initialized, or a version
    mismatch might change the exact form; the ready-path check and the auth
    login remain the real gates on whether the target is usable."""
    import time

    import httpx

    from argus.auth import _extract_hidden_value

    for attempt in range(attempts):
        try:
            with httpx.Client(timeout=20.0, follow_redirects=True) as client:
                page = client.get(base_url + path)
                payload = dict(data)
                if csrf_field:
                    token = _extract_hidden_value(page.text or "", csrf_field)
                    if token:
                        payload[csrf_field] = token
                client.post(base_url + path, data=payload)
                # Verify: once the DB exists, DVWA's setup page reports success
                # and stops redirecting everything back to itself. If it still
                # looks unset, fall through to another attempt.
                check = client.get(base_url + path)
                body = (check.text or "").lower()
                if "database has been created" in body or "already exists" in body \
                        or "populated" in body \
                        or "setup" not in str(check.url).lower():
                    return
        except httpx.HTTPError:
            pass
        if attempt < attempts - 1:
            time.sleep(3.0)


def _run_docker_target(case: BenchmarkCase, timeout: float = 90.0) -> list[Finding]:
    """Pull+run a benchmark target image, attack it, tear it down."""
    import socket

    import docker
    from docker.errors import DockerException

    from argus.llm.orchestrator import run_attack_sync
    from argus.sandbox.docker_manager import SandboxError, _wait_until_reachable

    try:
        client = docker.from_env()
    except DockerException as exc:
        raise SandboxError(f"Docker isn't reachable: {exc}") from exc

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        host_port = s.getsockname()[1]

    container = client.containers.run(
        case.image, detach=True, ports={f"{case.container_port}/tcp": host_port},
        mem_limit="1g",
    )
    try:
        base_url = f"http://127.0.0.1:{host_port}"
        if not _wait_until_reachable(base_url + case.ready_path, timeout=timeout):
            raise SandboxError(f"{case.name} never became reachable at {base_url} within {timeout:.0f}s")

        if case.setup_path:
            _run_setup(base_url, case.setup_path, case.setup_data or {},
                       csrf_field=case.setup_csrf_field)

        auth = None
        identity_b = None
        if case.auth_login_path:
            from argus.auth import AuthConfig

            auth = AuthConfig(
                login_url=base_url + case.auth_login_path,
                login_data=dict(case.auth_data or {}),
                login_json=case.auth_login_json,
                token_json_path=case.auth_token_json_path,
                csrf_field=case.auth_csrf_field,
                post_login_url=(base_url + case.post_login_path) if case.post_login_path else None,
                post_login_data=dict(case.post_login_data or {}),
            )
            if case.identity_b_data:
                identity_b = AuthConfig(
                    login_url=base_url + case.auth_login_path,
                    login_data=dict(case.identity_b_data),
                    login_json=case.auth_login_json,
                    token_json_path=case.auth_token_json_path,
                    csrf_field=case.auth_csrf_field,
                )

        findings, _reports, _eps = run_attack_sync(
            base_url, use_callback=False, auth=auth, identity_b=identity_b)
        return findings
    finally:
        try:
            container.remove(force=True)
        except Exception:  # noqa: BLE001
            pass


def run_case(case: BenchmarkCase) -> BenchmarkResult:
    start = time.time()
    try:
        findings = _run_local_demo() if case.kind == "local" else _run_docker_target(case)
    except Exception as exc:  # noqa: BLE001 — a benchmark run must report, never crash the suite
        return BenchmarkResult(
            case=case.name, total_findings=0, ground_truth_count=len(case.ground_truth),
            missed=[e.description for e in case.ground_truth],
            duration_s=time.time() - start, error=str(exc),
        )
    detected, missed, unmatched = score(findings, case.ground_truth)
    return BenchmarkResult(
        case=case.name, total_findings=len(findings), ground_truth_count=len(case.ground_truth),
        detected=detected, missed=missed, unmatched_findings=unmatched,
        duration_s=time.time() - start,
    )


def run_suite(names: list[str] | None = None) -> list[BenchmarkResult]:
    selected = [CASES[n] for n in names] if names else list(CASES.values())
    return [run_case(c) for c in selected]


def render_markdown(results: list[BenchmarkResult]) -> str:
    lines = ["# Argus benchmark results", "",
             "| Case | Detection rate | Detected | Missed | Findings | Unmatched | Time (s) |",
             "|---|---|---|---|---|---|---|"]
    for r in results:
        if r.error:
            lines.append(f"| {r.case} | — | — | — | — | — | {r.duration_s:.1f} (error: {r.error}) |")
            continue
        lines.append(
            f"| {r.case} | {r.detection_rate:.0%} | {len(r.detected)}/{r.ground_truth_count} | "
            f"{len(r.missed)} | {r.total_findings} | {r.unmatched_findings} ({r.unmatched_rate:.0%}) | "
            f"{r.duration_s:.1f} |"
        )
    lines.append("")
    for r in results:
        if r.missed:
            lines.append(f"**{r.case} — missed:** " + "; ".join(r.missed))
    return "\n".join(lines)
