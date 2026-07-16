"""Top-level orchestration for scan / attack / audit / report.

This is the spine the CLI commands call into. ``run_scan`` executes the full
Phase-1 pipeline: ingest → built-in rules + Semgrep → dependency audit → secret
scan → git-history scan → optional LLM enrichment → persist → render. Phase 2
(``run_attack``) is wired as a clearly-marked stub until the agent swarm lands.
"""

from __future__ import annotations

import re
import shutil
import time
from pathlib import Path

import typer

from argus.cli import output as out
from argus.config import load_settings
from argus.config.defaults import REPORT_FORMATS
from argus.models import Finding, ScanResult

# Machine-readable attack-event stream. Off by default (the CLI shows the Rich
# feed and nothing else). The desktop shell sets ARGUS_EVENT_STREAM=1 and reads
# these sentinel-prefixed JSON lines off stdout to drive a live per-agent feed,
# while ignoring every other (Rich-decorated) line.
_EVENT_SENTINEL = "@@ARGUS_EVENT@@"


def _stream_event(agent: str, text: str, sev: str) -> None:
    import os

    if os.environ.get("ARGUS_EVENT_STREAM") != "1":
        return
    import json
    import sys

    try:
        sys.stdout.write(_EVENT_SENTINEL + json.dumps({"agent": agent, "text": text, "sev": sev}) + "\n")
        sys.stdout.flush()
    except Exception:  # never let telemetry break the attack
        pass


def _do_scan(target: str, deep: bool, depth: str | None, no_llm: bool, taint: bool = False) -> ScanResult:
    from argus.sbom import collect_packages
    from argus.scanner import (
        dependencies, iac, image_cve, ingestion, rules_builtin, secrets, semgrep_runner, supplychain,
    )

    settings = load_settings()
    result = ScanResult(target=target, phase="scan")

    # 1) Ingestion -------------------------------------------------------------
    out.step("Ingesting target…")
    _stream_event("system", "Ingesting target…", "ok")
    ingested = None
    try:
        ingested = ingestion.ingest(target)
    except FileNotFoundError as exc:
        out.error(str(exc))
        _stream_event("system", str(exc), "crit")
        raise typer.Exit(code=1)
    except Exception as exc:  # clone failures etc.
        out.error(f"Ingestion failed: {exc}")
        _stream_event("system", f"Ingestion failed: {exc}", "crit")
        raise typer.Exit(code=1)

    root = ingested.root
    result.codebase_map = ingested.map
    out.codebase_summary(result)

    try:
        # 2) Built-in rules ----------------------------------------------------
        out.step("Running built-in code rules…")
        _stream_event("system", "Running built-in code rules…", "ok")
        result.extend(rules_builtin.scan_rules(root))

        # 3) Semgrep (optional) -----------------------------------------------
        out.step("Running Semgrep (if available)…")
        _stream_event("system", "Running Semgrep (if available)…", "ok")
        sg_findings, sg_note = semgrep_runner.run_semgrep(root)
        result.extend(sg_findings)
        if sg_note:
            out.info(sg_note)

        # 4) Dependency audit --------------------------------------------------
        out.step("Auditing dependencies…")
        _stream_event("system", "Auditing dependencies…", "ok")
        dep_findings, dep_notes = dependencies.audit_dependencies(root)
        result.extend(dep_findings)
        for note in dep_notes:
            out.info(note)

        # 4b) Supply-chain manifest analysis ------------------------------------
        out.step("Checking dependency manifests for supply-chain risk…")
        _stream_event("system", "Checking dependency manifests for supply-chain risk…", "ok")
        manifests = result.codebase_map.dependency_manifests if result.codebase_map else []
        sc_findings, sc_notes = supplychain.audit_supply_chain(root, manifests)
        result.extend(sc_findings)
        for note in sc_notes:
            out.info(note)

        # 4c) Package inventory (for `argus report --format sbom`) -------------
        result.sbom_components = collect_packages(root, manifests)

        # 4d) IaC misconfig (Dockerfiles / compose) ----------------------------
        out.step("Checking container/IaC config…")
        _stream_event("system", "Checking container/IaC config…", "ok")
        iac_findings, _ = iac.scan_iac(root)
        result.extend(iac_findings)

        # 4e) Base-image OS CVEs (Trivy, if installed) -------------------------
        img_findings, img_notes = image_cve.scan_container_images(root)
        result.extend(img_findings)
        for note in img_notes:
            out.info(note)

        # 5) Secret detection --------------------------------------------------
        out.step("Scanning for secrets (regex + entropy)…")
        _stream_event("system", "Scanning for secrets (regex + entropy)…", "ok")
        result.extend(secrets.scan_secrets(root))

        # 6) Git history -------------------------------------------------------
        out.step("Scanning git history for leaked secrets…")
        _stream_event("system", "Scanning git history for leaked secrets…", "ok")
        result.extend(secrets.scan_git_history(root))

        # 7) LLM reasoning -----------------------------------------------------
        if not no_llm:
            _stream_event(
                "system",
                f"LLM reasoning over {len(result.findings)} finding(s) — this step can take a "
                "while on a local model, especially for a large codebase.",
                "ok",
            )
            _run_llm(settings, root, result, deep, taint)
        else:
            out.info("LLM layer skipped (--no-llm).")

    finally:
        if ingested and ingested.cleanup:
            shutil.rmtree(root, ignore_errors=True)

    _stream_event("system", f"Static scan complete — {len(result.findings)} finding(s).", "ok")

    result.finished_at = time.time()
    return result


def _run_llm(settings, root: Path, result: ScanResult, deep: bool, taint: bool = False) -> None:
    from argus.llm.provider import get_provider
    from argus.llm.reasoning import enrich_findings, freeform_review, taint_trace

    provider = get_provider(settings)
    if provider is None:
        out.warn("No LLM provider available — keeping raw deterministic findings.")
        return
    result.llm_provider = f"{provider.name}:{provider.model}"
    out.step(f"LLM reasoning via [yellow3]{provider.name}[/] ({provider.model})…")

    if result.findings:
        with out.progress() as prog:
            task = prog.add_task("enriching findings", total=len(result.findings[:40]) or 1)

            def cb(done: int, total: int) -> None:
                prog.update(task, completed=done, total=total)

            enriched, dropped = enrich_findings(provider, root, result.findings, on_progress=cb)
        result.findings = enriched
        if dropped:
            out.info(f"LLM dismissed {dropped} finding(s) as false positives.")

    if deep and result.codebase_map and result.codebase_map.high_risk_files:
        out.step("Deep review of high-risk files…")
        extra = freeform_review(provider, root, result.codebase_map.high_risk_files)
        if extra:
            result.extend(extra)
            out.success(f"Deep review surfaced {len(extra)} additional finding(s).")

    if taint and result.codebase_map and result.codebase_map.high_risk_files:
        out.step("Tracing taint flows (source → sink) in high-risk files…")
        tainted = taint_trace(provider, root, result.codebase_map.high_risk_files)
        if tainted:
            result.extend(tainted)
            out.success(f"Taint tracing confirmed {len(tainted)} complete source-to-sink flow(s).")


def run_scan(
    target: str,
    *,
    deep: bool = False,
    depth: str | None = None,
    no_llm: bool = False,
    taint: bool = False,
    export_format: str | None = None,
    fail_on: str | None = None,
    policy: str | None = None,
    diff_base: str | None = None,
    baseline: str | None = None,
    write_baseline: str | None = None,
    gate: bool = True,
) -> ScanResult:
    from argus.state import save_result
    from argus.suppressions import apply_suppressions

    out.banner()
    out.rule(f"STATIC SCAN — {target}")
    result = _do_scan(target, deep=deep, depth=depth, no_llm=no_llm, taint=taint)
    result.findings, suppressed_count = apply_suppressions(target, result.findings)
    if suppressed_count:
        out.info(f"{suppressed_count} finding(s) suppressed (ignored) — "
                  f"run [wheat1]argus suppressions {target}[/] to review.")

    # --write-baseline snapshots the *whole* current finding set as accepted and
    # exits — it's an adoption one-shot, not a scan you gate on.
    if write_baseline:
        from argus.baseline import write_baseline as _write_baseline
        count = _write_baseline(Path(write_baseline).expanduser(), result.findings)
        out.success(f"Baseline written → [wheat1]{write_baseline}[/] "
                    f"({count} finding signature(s) recorded as accepted).")
        out.info("Future scans with [wheat1]--baseline[/] this file will report only new findings.")
        return result

    if baseline:
        _filter_to_baseline(baseline, result)

    if diff_base:
        _filter_to_changed_files(target, result, diff_base)

    out.risk_panel(result)
    out.findings_table(result, limit=25)
    if len(result.findings) > 25:
        out.info(f"…and {len(result.findings) - 25} more. Export a report to see all.")

    save_result(result)
    _maybe_notify(result)

    if export_format:
        _export(result, export_format, None)

    out.console.print()
    out.info("Run [wheat1]argus attack --url <running-app>[/] to actively exploit these findings.")

    # CI gating (policy / --fail-on). Skipped when ``gate`` is False — e.g.
    # `argus audit` runs a scan as its Phase 1 but shouldn't abort the whole
    # audit before Phase 2 just because an auto-discovered policy would fail.
    if gate:
        # A policy file supersedes --fail-on (finer-grained gate). If neither is
        # given, an .argus-policy.toml sitting in a local target dir is auto-applied.
        if policy or fail_on is None:
            if _maybe_gate_on_policy(target, result, policy):
                return result
        _maybe_fail(result, fail_on)
    return result


def parse_targets_file(path: str) -> list[str]:
    """One target per line; blank lines and ``#``-prefixed comments ignored."""
    lines = Path(path).expanduser().read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]


def run_scan_batch(
    targets_file: str,
    *,
    deep: bool = False,
    depth: str | None = None,
    no_llm: bool = False,
    taint: bool = False,
    export_format: str | None = None,
    fail_on: str | None = None,
) -> list[ScanResult]:
    """Scan every target listed in ``targets_file``, one Phase-1 run each.

    A single bad target (a typo'd path, an unreachable repo URL) doesn't
    abort the whole batch — it's recorded as an error row in the summary and
    scanning continues. Gating (``--fail-on``) is deferred until every target
    has been scanned, so the aggregate table is the CI signal, not a
    first-target failure that hides everything after it. ``--policy``
    per-target gating isn't supported in batch mode — different targets
    plausibly have different policy files at their own root, which
    ``--fail-on``'s single severity threshold sidesteps entirely.
    """
    targets = parse_targets_file(targets_file)
    if not targets:
        out.error(f"No targets found in {targets_file!r} (blank file, or every line was a comment).")
        raise typer.Exit(code=1)

    out.banner()
    out.rule(f"BATCH SCAN — {len(targets)} target(s)")

    results: list[tuple[str, ScanResult | None, str | None]] = []
    for i, target in enumerate(targets, 1):
        out.console.print()
        out.step(f"[{i}/{len(targets)}] {target}")
        try:
            result = run_scan(
                target, deep=deep, depth=depth, no_llm=no_llm, taint=taint,
                export_format=export_format, gate=False,
            )
            results.append((target, result, None))
        except typer.Exit:
            # run_scan already printed the real reason via out.error() before
            # exiting (bad path, gate failure, etc.) — nothing more to add.
            results.append((target, None, "scan aborted — see log above"))
        except Exception as exc:  # noqa: BLE001 — one bad target must not sink the batch
            out.error(f"{target}: {exc}")
            results.append((target, None, str(exc)))

    out.console.print()
    out.rule("BATCH SUMMARY")
    table_rows = []
    for target, result, error in results:
        if error is not None:
            table_rows.append((target, "ERROR", error, 0))
        else:
            table_rows.append((target, result.risk_band, f"{result.risk_score}/100", len(result.findings)))
    out.batch_summary_table(table_rows)

    if fail_on:
        from argus.models import Severity

        threshold = Severity.coerce(fail_on)
        failing = [
            target for target, result, error in results
            if result is not None and any(f.severity.rank >= threshold.rank for f in result.findings)
        ]
        errored = [target for target, _r, error in results if error is not None]
        if failing or errored:
            if failing:
                out.error(f"{len(failing)} target(s) have a finding at/above {fail_on.upper()}: "
                          f"{', '.join(failing)}")
            if errored:
                out.error(f"{len(errored)} target(s) failed to scan: {', '.join(errored)}")
            raise typer.Exit(code=2)

    return [r for _t, r, _e in results if r is not None]


def _filter_to_changed_files(target: str, result: ScanResult, diff_base: str) -> None:
    """Keep only findings in files changed vs ``diff_base`` (PR-gate model).

    Findings with no file (Phase-2/HTTP findings don't apply to a static scan,
    but dependency/IaC findings do carry a file) are dropped when they're not
    on a changed path. A git failure is fatal here — the user explicitly asked
    to gate on a diff, so silently scanning everything would be misleading."""
    from argus.gitutil import GitError, changed_files

    try:
        changed = changed_files(Path(target).expanduser(), diff_base)
    except GitError as exc:
        out.error(str(exc))
        raise typer.Exit(code=1)

    before = len(result.findings)
    kept = [f for f in result.findings if f.file and f.file.replace("\\", "/") in changed]
    result.findings = kept
    result._seen = {f.dedup_key(): f for f in kept}
    out.info(f"Diff-aware ({diff_base}): {len(kept)} of {before} finding(s) are in the "
             f"{len(changed)} changed file(s); the rest were pre-existing.")


def _filter_to_baseline(baseline_path: str, result: ScanResult) -> None:
    """Keep only findings absent from the baseline (adoption model). Unlike a
    diff gate, a missing/empty baseline file isn't fatal — treat it as "nothing
    accepted yet" so a first run surfaces everything rather than erroring."""
    from argus.baseline import filter_new, load_baseline

    path = Path(baseline_path).expanduser()
    if not path.is_file():
        out.warn(f"Baseline file not found ({path}) — reporting all findings. "
                 f"Create one with [wheat1]--write-baseline {baseline_path}[/].")
        return
    baseline = load_baseline(path)
    before = len(result.findings)
    kept, baselined = filter_new(result.findings, baseline)
    result.findings = kept
    result._seen = {f.dedup_key(): f for f in kept}
    out.info(f"Baseline ({path.name}): {baselined} of {before} finding(s) were already "
             f"accepted; {len(kept)} new.")


def _maybe_gate_on_policy(target: str, result: ScanResult, policy_path: str | None) -> bool:
    """Evaluate a policy file if one applies. Returns True if a policy was
    applied (so the caller skips the coarse --fail-on gate)."""
    from argus.policy import PolicyError, evaluate, find_default_policy, load_policy

    resolved: Path | None
    if policy_path:
        resolved = Path(policy_path).expanduser()
        if not resolved.is_file():
            out.error(f"Policy file not found: {resolved}")
            raise typer.Exit(code=1)
    else:
        resolved = find_default_policy(target)
        if resolved is None:
            return False

    try:
        pol = load_policy(resolved)
    except PolicyError as exc:
        out.error(str(exc))
        raise typer.Exit(code=1)

    outcome = evaluate(pol, result.findings)
    out.console.print()
    out.info(f"Policy [wheat1]{resolved.name}[/]: "
             f"{len(outcome.failing)} fail · {len(outcome.warning)} warn · {len(outcome.ignored)} ignore")
    if outcome.should_fail:
        out.error(f"{len(outcome.failing)} finding(s) violate the fail policy:")
        for f in outcome.failing[:10]:
            out.console.print(f"  [dark_orange3]✗[/] {f.severity.value} · {f.title} ({f.location})")
        raise typer.Exit(code=2)
    return True


def _maybe_notify(result: ScanResult) -> None:
    """Best-effort webhook notification — never let a notification failure
    surface as a scan failure; just note it and move on."""
    from argus.notify import notify_scan_complete

    settings = load_settings()
    if not settings.webhook_url:
        return
    if not notify_scan_complete(settings.webhook_url, result):
        out.warn("Webhook notification failed to send (scan itself is unaffected).")


def _maybe_fail(result: ScanResult, fail_on: str | None) -> None:
    """Exit non-zero when a finding meets/exceeds the --fail-on severity (for CI)."""
    if not fail_on:
        return
    from argus.models import Severity

    threshold = Severity.coerce(fail_on)
    worst = [f for f in result.findings if f.severity.rank >= threshold.rank]
    if worst:
        out.error(
            f"{len(worst)} finding(s) at or above {threshold.value} "
            f"(--fail-on {fail_on.lower()}) — failing."
        )
        raise typer.Exit(code=2)


def _default_output_dir(target: str, fallback: str) -> str:
    """Where a report lands when the caller didn't pass --output.

    ``settings.output_dir`` ("./argus-report") is relative to whatever the
    shell's cwd happens to be — fine when you're scanning the directory
    you're standing in, but scanning some *other* local path from an
    unrelated cwd silently drops the report there instead of anywhere near
    the thing that was actually scanned. If the target is a local directory
    that exists, write next to it; otherwise (a repo URL, or a path that no
    longer exists post-scan) fall back to the configured default.
    """
    target_path = Path(target).expanduser()
    if target_path.is_dir():
        return str(target_path / "argus-report")
    if target_path.is_file():
        return str(target_path.parent / "argus-report")
    return fallback


def _export(result: ScanResult, fmt: str, output: str | None) -> Path:
    from argus.report import export

    settings = load_settings()
    fmt = (fmt or settings.default_format).lower()
    if fmt not in REPORT_FORMATS and fmt != "md":
        out.error(f"Unknown format '{fmt}'. Choose from: {', '.join(REPORT_FORMATS)}")
        raise typer.Exit(code=1)
    output_dir = output or _default_output_dir(result.target, settings.output_dir)
    path = export(result, fmt, output_dir)
    if fmt == "pdf" and path.suffix != ".pdf":
        out.warn(
            "PDF generation needs weasyprint (pip install weasyprint) — "
            "wrote an HTML report instead."
        )
    out.success(f"Report written → [wheat1]{path}[/]")
    return path


def export_last(fmt: str = "html", output: str | None = None) -> None:
    from argus.state import load_result

    result = load_result()
    if result is None:
        out.error("No previous scan found. Run [wheat1]argus scan <target>[/] first.")
        raise typer.Exit(code=1)
    _export(result, fmt, output)


def run_pr_comment() -> None:
    """Post the last scan's findings as inline GitHub PR review comments.

    Meant to run right after `argus scan --diff-base <base>` in a GitHub Actions
    `pull_request` job — reuses that scan's already-persisted result rather than
    re-scanning. A no-op (exit 0) outside a PR context (push event, local run,
    no token) so it's always safe to add to a workflow unconditionally.
    """
    import asyncio

    from argus.prcomments import context_from_env, post_review_comments
    from argus.state import load_result

    ctx = context_from_env()
    if ctx is None:
        out.info("Not running in a GitHub PR context — skipping PR comments.")
        return

    result = load_result()
    if result is None or not result.findings:
        out.info("No findings to comment on.")
        return

    out.step(f"Posting inline PR review comments to {ctx.owner}/{ctx.repo}#{ctx.pr_number}…")
    outcome = asyncio.run(post_review_comments(ctx, result.findings))
    out.success(
        f"Posted {outcome.posted} comment(s) "
        f"({outcome.skipped_duplicate} already posted, "
        f"{outcome.skipped_not_in_diff} not on a diff line, "
        f"{outcome.skipped_no_location} with no file/line)."
    )
    for err in outcome.errors:
        out.warn(f"Could not post comment: {err}")


def run_attack(
    target: str | None = None,
    url: str | None = None,
    agents: str | None = None,
    *,
    auth: str | None = None,
    auth_b: str | None = None,
    api_spec: str | None = None,
    max_requests: int | None = None,
    rate_limit: float | None = None,
    request_log_path: str | None = None,
    assume_authorized: bool = False,
    banner: bool = True,
) -> ScanResult | None:
    from argus.auth import AuthError, load_auth
    from argus.llm.orchestrator import AGENT_REGISTRY, run_attack_sync
    from argus.llm.provider import get_provider
    from argus.sandbox.docker_manager import Sandbox, SandboxError, availability_note, docker_available
    from argus.state import load_result, save_result

    # Resolve the authenticated session(s) up front so a bad config fails fast.
    # ``auth`` (identity A) also auto-discovers .argus-auth.toml; ``auth_b`` (a
    # second identity for BOLA/BFLA testing) is explicit-only.
    try:
        auth_cfg = load_auth(auth)
        auth_b_cfg = load_auth(auth_b, auto=False)
    except AuthError as exc:
        out.banner() if banner else None
        out.error(str(exc))
        raise typer.Exit(code=1)

    if banner:
        out.banner()
    out.rule("ATTACK AGENT")

    base_url = url
    sandbox: Sandbox | None = None
    # `target` is normally a repo to spin up in a Docker sandbox — but if it's
    # already a URL (e.g. the desktop app's single Target field carries
    # whatever the user typed, with no separate "already running" field), treat
    # it as an already-running app instead of trying to Docker-sandbox a URL
    # string as though it were a repo path. Skips the Docker requirement
    # entirely for this case.
    if not base_url and target and re.match(r"^https?://", target, re.IGNORECASE):
        base_url = target
        target = None

    if not base_url:
        if not target:
            out.error("Provide --url of a running app (or a target repo once Docker is set up).")
            raise typer.Exit(code=1)
        if not docker_available():
            out.warn("Attacking a repo requires spinning it up in a sandbox.")
            out.info(availability_note())
            out.info("For now, start the app yourself and run: "
                     "[wheat1]argus attack --url http://localhost:PORT[/]")
            _stream_event(
                "system",
                "Phase 2 needs Docker to sandbox the target automatically, and Docker isn't "
                "available — point Argus at an already-running app's URL instead.",
                "crit",
            )
            raise typer.Exit(code=1)

        out.step("Spinning up the target in a Docker sandbox…")
        _stream_event("system", "Spinning up the target in a Docker sandbox…", "ok")
        sandbox = Sandbox(Path(target).expanduser().resolve())
        try:
            base_url = sandbox.start()
        except SandboxError as exc:
            out.error(str(exc))
            _stream_event("system", f"Sandbox failed to start: {exc}", "crit")
            raise typer.Exit(code=1)
        out.success(f"Sandbox reachable at [wheat1]{base_url}[/]")
        _stream_event("system", f"Sandbox reachable at {base_url}", "ok")

    from argus.authorization import confirm_authorization

    if not confirm_authorization(base_url, assume_yes=assume_authorized):
        out.error(
            f"Not authorized to attack {base_url!r}. Only run Phase 2 against systems you "
            "own or are explicitly authorized to test — confirm interactively, or pass "
            "--yes-i-am-authorized for CI/non-interactive use."
        )
        _stream_event("system", "Attack refused — authorization not confirmed.", "crit")
        raise typer.Exit(code=1)

    try:
        requested = [a.strip().lower() for a in agents.split(",")] if agents else None
        if requested:
            unknown = [a for a in requested if a not in AGENT_REGISTRY]
            if unknown:
                out.warn(f"Not yet implemented (ignored): {', '.join(unknown)}")

        # Bias agent order using the last scan's findings, if any.
        prior = load_result()
        prior_findings = prior.findings if prior else []

        # Resolve an LLM provider once, if configured — enables provider-gated agents
        # (BusinessLogicAgent) without requiring one; raw HTTP agents ignore it entirely.
        settings = load_settings()
        provider = get_provider(settings)
        if provider is not None:
            out.info(f"LLM provider available: [yellow3]{provider.name}[/] ({provider.model}) — "
                     "business-logic reasoning enabled.")

        out.step(f"Target: [wheat1]{base_url}[/]")
        out.step("Deploying agents… (ReconBot first)")

        def feed(agent: str, text: str, sev: str) -> None:
            _stream_event(agent, text, sev)
            if sev == "crit":
                out.console.print(f"  [dark_orange3]\\[{agent}][/] [bold red]✓ {text}[/]")
            else:
                out.console.print(f"  [dark_orange3]\\[{agent}][/] [grey58]{text}[/]")

        # The surface inventory is keyed on the logical target (repo path or
        # URL), not the ephemeral sandbox port — same key `save_result` reports.
        from argus.surface import load_surface, save_surface
        surface_key = target if sandbox else base_url
        seed = load_surface(surface_key) if surface_key else []
        if seed:
            out.info(f"Seeding {len(seed)} endpoint(s) from previous scans of this target.")

        # Seed from an API spec (OpenAPI/Swagger/Postman/GraphQL), if provided.
        if api_spec:
            from argus.apispec import ApiSpecError, load_endpoints

            try:
                spec_eps, note = load_endpoints(api_spec, base_url)
            except ApiSpecError as exc:
                out.error(str(exc))
                raise typer.Exit(code=1)
            seed = list(seed) + spec_eps
            out.info(f"API spec ({note}) — the swarm will test the declared surface directly.")

        if auth_cfg is not None:
            out.info("Authenticated session configured — agents will attack the logged-in surface.")
        if auth_b_cfg is not None:
            out.info("Second identity configured — BOLA/BFLA cross-user authorization testing enabled.")

        try:
            findings, reports, endpoints = run_attack_sync(
                base_url, requested_agents=requested, prior_findings=prior_findings,
                provider=provider, on_event=feed, seed_endpoints=seed or None,
                auth=auth_cfg, identity_b=auth_b_cfg, max_requests=max_requests,
                rate_limit=rate_limit, request_log_path=request_log_path,
            )
        except AuthError as exc:
            out.error(f"Authentication failed — aborting attack: {exc}")
            raise typer.Exit(code=1)
        if request_log_path:
            out.success(f"Request log written → [wheat1]{request_log_path}[/]")
        if surface_key:
            save_surface(surface_key, endpoints)

        # Report the original repo target, not the sandbox's ephemeral localhost
        # port, when Argus spun it up itself — far more meaningful in a report.
        result = ScanResult(target=surface_key, phase="attack")
        result.extend(findings)

        # Exploit chaining: surface compound attack paths from the confirmed set.
        from argus.chains import detect_chains
        chains = detect_chains(result.findings)
        if chains:
            result.extend(chains)
            for c in chains:
                out.console.print(f"  [dark_orange3]\\[CHAIN][/] [bold red]⛓ {c.title}[/]")

        result.finished_at = time.time()

        out.console.print()
        _attack_summary(reports)
        out.risk_panel(result)
        out.findings_table(result)
        save_result(result)
        _maybe_notify(result)
        return result
    finally:
        if sandbox is not None:
            out.step("Tearing down sandbox…")
            sandbox.stop()


def _attack_summary(reports) -> None:
    from rich.table import Table

    table = Table(show_header=True, header_style="bold yellow3", border_style="grey30")
    table.add_column("AGENT", style="dark_orange3")
    table.add_column("STATUS")
    table.add_column("REQUESTS", justify="right")
    table.add_column("FINDINGS", justify="right")
    for r in reports:
        style = "bold red" if r.status == "error" else "yellow3"
        table.add_row(r.agent, f"[{style}]{r.status}[/]", str(r.requests_sent), str(r.findings))
    out.console.print(table)


def run_audit(target: str, fix: bool = False, agents: str | None = None,
              auth: str | None = None, auth_b: str | None = None,
              api_spec: str | None = None, max_requests: int | None = None,
              rate_limit: float | None = None, request_log_path: str | None = None,
              assume_authorized: bool = False) -> None:
    from argus.sandbox.docker_manager import docker_available

    out.banner()
    out.rule("FULL AUDIT")
    # gate=False: a full audit is interactive exploration (Phase 1 + Phase 2),
    # not a CI gate — don't let an auto-discovered policy abort it after Phase 1.
    run_scan(target, gate=False)
    out.console.print()

    # A URL-shaped target is already a running app — Phase 2 can attack it
    # directly and never needs Docker at all. Only a bare repo path needs the
    # sandbox, so only gate *that* case on docker_available(); otherwise this
    # outer check blocked Phase 2 even when nothing here required Docker,
    # which is exactly what made "Strike the app" against a URL silently do
    # nothing in the desktop app (no event ever streamed to explain why).
    target_is_url = bool(target and re.match(r"^https?://", target, re.IGNORECASE))
    if target_is_url or docker_available():
        run_attack(target=target, agents=agents, auth=auth, auth_b=auth_b,
                   api_spec=api_spec, max_requests=max_requests,
                   rate_limit=rate_limit, request_log_path=request_log_path,
                   assume_authorized=assume_authorized, banner=False)
    else:
        out.info("Phase 1 complete. Phase 2 needs Docker to sandbox the target automatically — "
                 "point Argus at a running instance instead:")
        out.info("[wheat1]argus attack --url http://localhost:PORT[/]")
        _stream_event(
            "system",
            "Phase 2 skipped — it needs Docker to sandbox a repo target automatically, and "
            "Docker isn't available. Point Argus at an already-running app's URL instead.",
            "crit",
        )

    if fix:
        out.console.print()
        run_fix(target, apply=False)


def run_fix(target: str, *, apply: bool = False, pr: bool = False) -> None:
    """Generate (and optionally apply) minimal patches for fixable findings.

    Fixable = findings with a ``file`` (Phase-2/HTTP findings have no source file
    to patch). Requires an LLM provider — there's no deterministic way to write a
    correct code patch. Dry-run by default; ``apply=True`` writes patches to disk.

    ``pr=True`` (requires ``apply=True``) commits the applied, reverified fixes
    to a new branch, pushes it, and opens a real GitHub pull request — see
    ``argus/fixpr.py`` for the safety gates (clean working tree, explicit auth).
    """
    from argus.config import load_settings
    from argus.fix import apply_fixes
    from argus.llm.provider import get_provider
    from argus.llm.reasoning import generate_fixes
    from argus.scanner import ingestion

    out.banner()
    out.rule(f"AUTO-FIX — {target}")

    if pr and not apply:
        out.error("--pr requires --apply (a pull request needs the fixes actually applied).")
        raise typer.Exit(code=1)

    repo = None
    if pr:
        from argus.fixpr import PrError, ensure_clean_repo, github_auth_available

        if not github_auth_available():
            out.error(
                "No GitHub authentication found — --pr needs the `gh` CLI logged in "
                "([wheat1]gh auth login[/]) or a GH_TOKEN/GITHUB_TOKEN environment variable."
            )
            raise typer.Exit(code=1)
        try:
            repo = ensure_clean_repo(Path(target).expanduser())
        except PrError as exc:
            out.error(str(exc))
            raise typer.Exit(code=1)

    result = _do_scan(target, deep=False, depth=None, no_llm=True)
    fixable = [f for f in result.findings if f.file]
    if not fixable:
        out.success("No fixable (file-based) findings.")
        return

    settings = load_settings()
    provider = get_provider(settings)
    if provider is None:
        out.error("No LLM provider configured — fix generation needs one "
                  "(run [wheat1]argus setup[/] or [wheat1]argus config --provider ...[/]).")
        raise typer.Exit(code=1)

    # Re-ingest for a root to read/patch: _do_scan already deleted a remote clone.
    try:
        ingested = ingestion.ingest(target)
    except FileNotFoundError as exc:
        out.error(str(exc))
        raise typer.Exit(code=1)

    try:
        if ingested.cleanup and apply:
            out.error(
                "--apply only supports local paths today — a remote clone has nowhere "
                "persistent to write to. Clone the repo locally and run "
                "[wheat1]argus fix <local-path> --apply[/]."
            )
            raise typer.Exit(code=1)

        out.step(f"Generating fixes via [yellow3]{provider.name}[/] ({provider.model})…")
        with out.progress() as prog:
            task = prog.add_task("generating fixes", total=len(fixable[:20]) or 1)

            def cb(done: int, total: int) -> None:
                prog.update(task, completed=done, total=total)

            fixes = generate_fixes(provider, ingested.root, fixable, on_progress=cb)

        if not fixes:
            out.warn("No safe, minimal patch could be produced for any finding.")
            return

        applied = apply_fixes(ingested.root, fixes, apply=apply)
        out.console.print()
        if apply:
            written = [a for a in applied if a.written]
            out.success(f"Applied {len(written)} fix(es).")
            if written:
                _reverify_fixes(target, fixable, written)
            if pr and written:
                _open_fix_pr(repo, ingested.root, written)
            elif pr:
                out.warn("Nothing was written — no pull request to open.")
        else:
            out.info(f"{len(applied)} fix(es) previewed above (dry-run). Re-run with --apply to write them.")
    finally:
        if ingested.cleanup:
            shutil.rmtree(ingested.root, ignore_errors=True)


def _reverify_fixes(target: str, original_findings: list[Finding], written) -> None:
    """Re-scan the patched files and check whether each fix actually closed its
    finding — matching content exactly and not breaking syntax (both already
    checked before writing) proves the patch is *safe*, not that it *worked*.
    """
    from rich.table import Table

    from argus.compare import finding_signature

    by_id = {f.id: f for f in original_findings}
    out.step("Re-scanning to confirm each fix actually closed its finding…")
    fresh = _do_scan(target, deep=False, depth=None, no_llm=True)
    fresh_signatures = {finding_signature(f) for f in fresh.findings}

    table = Table(show_header=True, header_style="bold yellow3", border_style="grey30")
    table.add_column("FILE", style="wheat1")
    table.add_column("FINDING")
    table.add_column("STATUS")
    for fx in written:
        original = by_id.get(fx.finding_id)
        if original is None:
            continue
        closed = finding_signature(original) not in fresh_signatures
        status = "[bold green3]✓ confirmed closed[/]" if closed else "[bold red]⚠ still detected[/]"
        table.add_row(fx.file, original.title, status)
    out.console.print()
    out.console.print(table)


def _open_fix_pr(repo, root: Path, written) -> None:
    """Commit the applied, reverified fixes to a new branch, push it, and open a
    real GitHub pull request. ``repo`` is the pre-validated clean-tree Repo from
    ``ensure_clean_repo`` (called before any patch was applied)."""
    from argus.fixpr import PrError, commit_and_push_fixes, open_pull_request

    out.step("Committing fixes to a new branch and opening a pull request…")
    try:
        base = repo.active_branch.name
        branch = commit_and_push_fixes(repo, written)
    except PrError as exc:
        out.error(str(exc))
        raise typer.Exit(code=1)

    result = open_pull_request(root, branch, base, written)
    if result.url:
        out.success(f"Opened pull request: [wheat1]{result.url}[/]")
    else:
        out.warn(result.note)
