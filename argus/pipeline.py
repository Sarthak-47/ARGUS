"""Top-level orchestration for scan / attack / audit / report.

This is the spine the CLI commands call into. ``run_scan`` executes the full
Phase-1 pipeline: ingest → built-in rules + Semgrep → dependency audit → secret
scan → git-history scan → optional LLM enrichment → persist → render. Phase 2
(``run_attack``) is wired as a clearly-marked stub until the agent swarm lands.
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path

import typer

from argus.cli import output as out
from argus.config import load_settings
from argus.config.defaults import REPORT_FORMATS
from argus.models import ScanResult


def _do_scan(target: str, deep: bool, depth: str | None, no_llm: bool) -> ScanResult:
    from argus.scanner import dependencies, ingestion, rules_builtin, secrets, semgrep_runner, supplychain

    settings = load_settings()
    result = ScanResult(target=target, phase="scan")

    # 1) Ingestion -------------------------------------------------------------
    out.step("Ingesting target…")
    ingested = None
    try:
        ingested = ingestion.ingest(target)
    except FileNotFoundError as exc:
        out.error(str(exc))
        raise typer.Exit(code=1)
    except Exception as exc:  # clone failures etc.
        out.error(f"Ingestion failed: {exc}")
        raise typer.Exit(code=1)

    root = ingested.root
    result.codebase_map = ingested.map
    out.codebase_summary(result)

    try:
        # 2) Built-in rules ----------------------------------------------------
        out.step("Running built-in code rules…")
        result.extend(rules_builtin.scan_rules(root))

        # 3) Semgrep (optional) -----------------------------------------------
        out.step("Running Semgrep (if available)…")
        sg_findings, sg_note = semgrep_runner.run_semgrep(root)
        result.extend(sg_findings)
        if sg_note:
            out.info(sg_note)

        # 4) Dependency audit --------------------------------------------------
        out.step("Auditing dependencies…")
        dep_findings, dep_notes = dependencies.audit_dependencies(root)
        result.extend(dep_findings)
        for note in dep_notes:
            out.info(note)

        # 4b) Supply-chain manifest analysis ------------------------------------
        out.step("Checking dependency manifests for supply-chain risk…")
        manifests = result.codebase_map.dependency_manifests if result.codebase_map else []
        sc_findings, sc_notes = supplychain.audit_supply_chain(root, manifests)
        result.extend(sc_findings)
        for note in sc_notes:
            out.info(note)

        # 5) Secret detection --------------------------------------------------
        out.step("Scanning for secrets (regex + entropy)…")
        result.extend(secrets.scan_secrets(root))

        # 6) Git history -------------------------------------------------------
        out.step("Scanning git history for leaked secrets…")
        result.extend(secrets.scan_git_history(root))

        # 7) LLM reasoning -----------------------------------------------------
        if not no_llm:
            _run_llm(settings, root, result, deep)
        else:
            out.info("LLM layer skipped (--no-llm).")

    finally:
        if ingested and ingested.cleanup:
            shutil.rmtree(root, ignore_errors=True)

    result.finished_at = time.time()
    return result


def _run_llm(settings, root: Path, result: ScanResult, deep: bool) -> None:
    from argus.llm.provider import get_provider
    from argus.llm.reasoning import enrich_findings, freeform_review

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


def run_scan(
    target: str,
    *,
    deep: bool = False,
    depth: str | None = None,
    no_llm: bool = False,
    export_format: str | None = None,
    fail_on: str | None = None,
) -> ScanResult:
    from argus.state import save_result

    out.banner()
    out.rule(f"STATIC SCAN — {target}")
    result = _do_scan(target, deep=deep, depth=depth, no_llm=no_llm)

    out.risk_panel(result)
    out.findings_table(result, limit=25)
    if len(result.findings) > 25:
        out.info(f"…and {len(result.findings) - 25} more. Export a report to see all.")

    save_result(result)

    if export_format:
        _export(result, export_format, None)

    out.console.print()
    out.info("Run [wheat1]argus attack --url <running-app>[/] to actively exploit these findings.")

    _maybe_fail(result, fail_on)
    return result


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


def _export(result: ScanResult, fmt: str, output: str | None) -> Path:
    from argus.report import export

    settings = load_settings()
    fmt = (fmt or settings.default_format).lower()
    if fmt not in REPORT_FORMATS and fmt != "md":
        out.error(f"Unknown format '{fmt}'. Choose from: {', '.join(REPORT_FORMATS)}")
        raise typer.Exit(code=1)
    output_dir = output or settings.output_dir
    path = export(result, fmt, output_dir)
    out.success(f"Report written → [wheat1]{path}[/]")
    return path


def export_last(fmt: str = "html", output: str | None = None) -> None:
    from argus.state import load_result

    result = load_result()
    if result is None:
        out.error("No previous scan found. Run [wheat1]argus scan <target>[/] first.")
        raise typer.Exit(code=1)
    _export(result, fmt, output)


def run_attack(
    target: str | None = None,
    url: str | None = None,
    agents: str | None = None,
    *,
    banner: bool = True,
) -> ScanResult | None:
    from argus.llm.orchestrator import AGENT_REGISTRY, run_attack_sync
    from argus.sandbox.docker_manager import availability_note
    from argus.state import load_result, save_result

    if banner:
        out.banner()
    out.rule("ATTACK AGENT")

    base_url = url
    if not base_url:
        # No running URL given. Auto-sandboxing needs Docker, which we treat as optional.
        if target:
            out.warn("Attacking a repo requires spinning it up in a sandbox.")
            out.info(availability_note())
            out.info("For now, start the app yourself and run: "
                     "[wheat1]argus attack --url http://localhost:PORT[/]")
        else:
            out.error("Provide --url of a running app (or a target repo once Docker is set up).")
        raise typer.Exit(code=1)

    requested = [a.strip().lower() for a in agents.split(",")] if agents else None
    if requested:
        unknown = [a for a in requested if a not in AGENT_REGISTRY]
        if unknown:
            out.warn(f"Not yet implemented (ignored): {', '.join(unknown)}")

    # Bias agent order using the last scan's findings, if any.
    prior = load_result()
    prior_findings = prior.findings if prior else []

    out.step(f"Target: [wheat1]{base_url}[/]")
    out.step("Deploying agents… (ReconBot first)")

    def feed(agent: str, text: str, sev: str) -> None:
        if sev == "crit":
            out.console.print(f"  [dark_orange3]\\[{agent}][/] [bold red]✓ {text}[/]")
        else:
            out.console.print(f"  [dark_orange3]\\[{agent}][/] [grey58]{text}[/]")

    findings, reports = run_attack_sync(
        base_url, requested_agents=requested, prior_findings=prior_findings, on_event=feed
    )

    result = ScanResult(target=base_url, phase="attack")
    result.extend(findings)
    result.finished_at = time.time()

    out.console.print()
    _attack_summary(reports)
    out.risk_panel(result)
    out.findings_table(result)
    save_result(result)
    return result


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


def run_audit(target: str, fix: bool = False, agents: str | None = None) -> None:
    out.banner()
    out.rule("FULL AUDIT")
    run_scan(target)
    out.console.print()
    out.info("Phase 1 complete. For Phase 2, point Argus at the running app:")
    out.info("[wheat1]argus attack --url http://localhost:PORT[/]")
    if fix:
        out.console.print()
        run_fix(target, apply=False)


def run_fix(target: str, *, apply: bool = False) -> None:
    """Generate (and optionally apply) minimal patches for fixable findings.

    Fixable = findings with a ``file`` (Phase-2/HTTP findings have no source file
    to patch). Requires an LLM provider — there's no deterministic way to write a
    correct code patch. Dry-run by default; ``apply=True`` writes patches to disk.
    """
    from argus.config import load_settings
    from argus.fix import apply_fixes
    from argus.llm.provider import get_provider
    from argus.llm.reasoning import generate_fixes
    from argus.scanner import ingestion

    out.banner()
    out.rule(f"AUTO-FIX — {target}")

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
            out.success(f"Applied {len(applied)} fix(es). Re-run argus scan to confirm.")
        else:
            out.info(f"{len(applied)} fix(es) previewed above (dry-run). Re-run with --apply to write them.")
    finally:
        if ingested.cleanup:
            shutil.rmtree(ingested.root, ignore_errors=True)
