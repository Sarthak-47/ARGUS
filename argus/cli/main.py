"""Argus CLI — the Typer application exposing every command.

Command bodies stay thin: they parse options, then delegate to the engine
(``argus.pipeline`` and friends), imported lazily so ``argus --help`` is instant.
"""

from __future__ import annotations

from typing import List, Optional

import typer

from argus import __version__
from argus.cli import output as out

app = typer.Typer(
    name="argus",
    help="Argus — point it at a repo. It reads the code, spins up the app, and attacks it.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)


def _version_callback(value: bool) -> None:
    if value:
        out.console.print(f"argus {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False, "--version", "-V", callback=_version_callback, is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Argus security auditor."""


# --------------------------------------------------------------------------- #
# setup
# --------------------------------------------------------------------------- #
@app.command()
def setup() -> None:
    """First-time setup wizard: detect hardware, pick an LLM, write config."""
    from argus.commands.setup_cmd import run_setup

    run_setup()


@app.command()
def fix(
    target: str = typer.Argument(..., help="Repo path to fix (local paths only for --apply)."),
    apply: bool = typer.Option(False, "--apply", help="Write patches to disk. Default is dry-run (preview only)."),
    pr: bool = typer.Option(False, "--pr", help="With --apply: commit the fixes to a new branch, push it, and open a GitHub pull request. Needs `gh auth login` or a GH_TOKEN/GITHUB_TOKEN env var, and a clean working tree."),
) -> None:
    """Generate LLM-written patches for fixable findings; preview or apply them."""
    from argus.pipeline import run_fix

    run_fix(target, apply=apply, pr=pr)


@app.command()
def demo(
    no_attack: bool = typer.Option(False, "--no-attack", help="Static scan only; skip the live attack."),
) -> None:
    """Run a zero-setup showcase against a bundled vulnerable app."""
    from argus.commands.demo_cmd import run_demo

    run_demo(attack=not no_attack)


# --------------------------------------------------------------------------- #
# scan  (Phase 1)
# --------------------------------------------------------------------------- #
@app.command()
def scan(
    target: str = typer.Argument(..., help="Repo URL or local path to scan."),
    deep: bool = typer.Option(False, "--deep", help="Full LLM free-form review of high-risk files."),
    taint: bool = typer.Option(
        False, "--taint", help="LLM taint-tracing: report only complete source-to-sink flows in high-risk files."
    ),
    depth: Optional[str] = typer.Option(None, "--depth", help="quick | standard | deep"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Deterministic scan only, skip the LLM layer."),
    fmt: Optional[str] = typer.Option(None, "--format", help="Also export a report: html|json|pdf|markdown|sarif|sbom|vex|jira."),
    fail_on: Optional[str] = typer.Option(
        None, "--fail-on", help="Exit non-zero if a finding at/above this severity exists: critical|high|medium|low."
    ),
    policy: Optional[str] = typer.Option(
        None, "--policy", help="Path to a policy file (.argus-policy.toml) for per-rule CI gating. Overrides --fail-on."
    ),
    diff_base: Optional[str] = typer.Option(
        None, "--diff-base", help="Only report findings in files changed vs this git ref (e.g. main) — PR-gate mode."
    ),
    baseline: Optional[str] = typer.Option(
        None, "--baseline", help="Report only findings NOT in this baseline file — adopt Argus on a legacy repo without drowning."
    ),
    write_baseline: Optional[str] = typer.Option(
        None, "--write-baseline", help="Record every current finding to this file as the accepted baseline, then exit."
    ),
) -> None:
    """Phase 1 — static analysis. Read and understand the code without running it."""
    from argus.pipeline import run_scan

    run_scan(target, deep=deep, depth=depth, no_llm=no_llm, taint=taint, export_format=fmt,
             fail_on=fail_on, policy=policy, diff_base=diff_base,
             baseline=baseline, write_baseline=write_baseline)


# --------------------------------------------------------------------------- #
# precommit  (fast staged-file gate for a pre-commit hook)
# --------------------------------------------------------------------------- #
@app.command()
def precommit(
    files: Optional[List[str]] = typer.Argument(
        None, help="Files to scan. A pre-commit hook passes the staged files; omit to scan currently-staged files yourself."
    ),
    fail_on: str = typer.Option(
        "high", "--fail-on", help="Block the commit on a finding at/above this severity: critical|high|medium|low."
    ),
) -> None:
    """Fast staged-file scan for a pre-commit hook — secrets + built-in rules, no LLM, no network."""
    from pathlib import Path

    from argus.cli import output as out
    from argus.precommit import blocking_findings, scan_paths, staged_files

    root = Path.cwd()
    targets = list(files) if files else staged_files(root)
    if not targets:
        raise typer.Exit(0)

    findings = scan_paths(targets, root)
    if not findings:
        raise typer.Exit(0)

    blocking = blocking_findings(findings, fail_on)
    # Show blocking findings prominently; non-blocking ones as an FYI note.
    shown = blocking or findings
    out.console.print()
    for f in shown:
        loc = f"{f.file}:{f.line}" if f.line else (f.file or "")
        out.console.print(
            f"  {out.severity_dot(f.severity)} [bold]{f.title}[/]  "
            f"[grey58]{loc}[/]  [dark_orange3]{f.detector}[/]"
        )
        if f.evidence:
            out.console.print(f"      [grey42]{f.evidence.strip()[:100]}[/]")

    if blocking:
        out.console.print()
        out.error(
            f"{len(blocking)} finding(s) at/above {fail_on.upper()} — commit blocked. "
            f"Fix them, or bypass with [wheat1]git commit --no-verify[/] (not recommended)."
        )
        raise typer.Exit(1)

    out.console.print()
    out.info(f"{len(findings)} low-severity finding(s) noted (below {fail_on.upper()}) — commit allowed.")
    raise typer.Exit(0)


# --------------------------------------------------------------------------- #
# attack  (Phase 2)
# --------------------------------------------------------------------------- #
@app.command()
def attack(
    target: Optional[str] = typer.Argument(None, help="Repo URL/path (sandboxed) — optional."),
    url: Optional[str] = typer.Option(None, "--url", help="Attack an already-running app at this URL."),
    agents: Optional[str] = typer.Option(None, "--agents", help="Comma-separated agent subset, e.g. injector,authbreaker."),
    auth: Optional[str] = typer.Option(None, "--auth", help="Path to a .argus-auth.toml so agents attack the logged-in surface (auto-discovered in the working dir if present)."),
    auth_b: Optional[str] = typer.Option(None, "--auth-b", help="A second identity's auth file — enables BOLA/BFLA cross-user authorization testing (ideally a low-privilege account)."),
    api_spec: Optional[str] = typer.Option(None, "--api-spec", help="OpenAPI/Swagger/Postman/GraphQL spec (file or URL) to seed the attack surface."),
    max_requests: Optional[int] = typer.Option(
        None, "--max-requests", help="Hard cap on total requests sent to the target — a safety backstop "
                                      "against a runaway agent or an overly deep scan hammering the target."
    ),
    rate_limit: Optional[float] = typer.Option(
        None, "--rate-limit", help="Cap requests/second across the whole swarm — --max-requests bounds total "
                                    "volume but not burst rate; this keeps traffic steady on a fragile target."
    ),
    yes_i_am_authorized: bool = typer.Option(
        False, "--yes-i-am-authorized",
        help="Skip the interactive authorization prompt — required for CI/non-interactive use. "
             "Only run Phase 2 against systems you own or are explicitly authorized to test."
    ),
    request_log: Optional[str] = typer.Option(
        None, "--request-log", help="Write a JSON log of every request sent (agent, method, url, "
                                     "status, latency) to this path — for diagnosing a false positive "
                                     "or a slow run without manually re-probing by hand."
    ),
) -> None:
    """Phase 2 — attack agent. Actively exploit a running app."""
    from argus.pipeline import run_attack

    run_attack(target=target, url=url, agents=agents, auth=auth, auth_b=auth_b,
               api_spec=api_spec, max_requests=max_requests, rate_limit=rate_limit,
               request_log_path=request_log, assume_authorized=yes_i_am_authorized)


# --------------------------------------------------------------------------- #
# audit  (Phase 1 + Phase 2)
# --------------------------------------------------------------------------- #
@app.command()
def audit(
    target: str = typer.Argument(..., help="Repo URL or local path."),
    fix: bool = typer.Option(False, "--fix", help="Suggest fixes after the audit."),
    agents: Optional[str] = typer.Option(None, "--agents", help="Comma-separated agent subset."),
    auth: Optional[str] = typer.Option(None, "--auth", help="Path to a .argus-auth.toml so Phase 2 attacks the logged-in surface."),
    auth_b: Optional[str] = typer.Option(None, "--auth-b", help="A second identity's auth file — enables BOLA/BFLA cross-user authorization testing."),
    api_spec: Optional[str] = typer.Option(None, "--api-spec", help="OpenAPI/Swagger/Postman/GraphQL spec (file or URL) to seed the attack surface."),
    max_requests: Optional[int] = typer.Option(
        None, "--max-requests", help="Hard cap on total requests sent to the target during Phase 2 — a safety "
                                      "backstop against a runaway agent or an overly deep scan."
    ),
    rate_limit: Optional[float] = typer.Option(
        None, "--rate-limit", help="Cap requests/second across the whole swarm during Phase 2."
    ),
    yes_i_am_authorized: bool = typer.Option(
        False, "--yes-i-am-authorized",
        help="Skip the interactive authorization prompt before Phase 2 — required for CI/non-interactive "
             "use. Only run Phase 2 against systems you own or are explicitly authorized to test."
    ),
    request_log: Optional[str] = typer.Option(
        None, "--request-log", help="Write a JSON log of every request sent during Phase 2 to this path."
    ),
) -> None:
    """Full pipeline — Phase 1 static analysis then Phase 2 attack."""
    from argus.pipeline import run_audit

    run_audit(target, fix=fix, agents=agents, auth=auth, auth_b=auth_b,
              api_spec=api_spec, max_requests=max_requests, rate_limit=rate_limit,
              request_log_path=request_log,
              assume_authorized=yes_i_am_authorized)


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #
@app.command()
def report(
    fmt: str = typer.Option("html", "--format", help="html | json | pdf | markdown | sarif | sbom | vex | jira"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output directory."),
) -> None:
    """Export the most recent scan result in the chosen format."""
    from argus.pipeline import export_last

    export_last(fmt=fmt, output=output)


# --------------------------------------------------------------------------- #
# pr-comment  (CI: post findings as inline GitHub PR review comments)
# --------------------------------------------------------------------------- #
@app.command(name="pr-comment")
def pr_comment() -> None:
    """Post the last scan's findings as inline GitHub PR review comments.

    Run right after `argus scan --diff-base <base>` in a GitHub Actions
    pull_request job. A no-op outside a PR context, so it's safe to add to any
    workflow unconditionally.
    """
    from argus.pipeline import run_pr_comment

    run_pr_comment()


# --------------------------------------------------------------------------- #
# benchmark  (detection-rate proof against known-vulnerable apps)
# --------------------------------------------------------------------------- #
@app.command()
def benchmark(
    case: Optional[str] = typer.Option(
        None, "--case", help="Run a single case by name (argus_demo|juice_shop|dvwa|vampi). Omit to run all."
    ),
    fmt: str = typer.Option("markdown", "--format", help="markdown | json"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write the report to this file instead of stdout."),
    min_detection_rate: Optional[float] = typer.Option(
        None, "--min-detection-rate",
        help="Fail (exit 1) if any case's detection rate falls below this (0.0-1.0) — "
             "for gating a release on a real accuracy regression, not just a setup error.",
    ),
) -> None:
    """Run Argus against known-vulnerable apps and report a real detection rate.

    `argus_demo` needs no Docker (runs against the bundled in-process target);
    juice_shop/dvwa/vampi pull and attack real, well-known vulnerable images.
    """
    import json as _json

    from argus.benchmark import CASES, render_markdown, run_suite
    from argus.cli import output as out

    names = [case] if case else None
    if case and case not in CASES:
        out.error(f"Unknown case '{case}'. Choose from: {', '.join(CASES)}")
        raise typer.Exit(code=1)

    out.banner()
    out.rule("BENCHMARK")
    results = run_suite(names)

    text = (
        _json.dumps([r.to_dict() for r in results], indent=2)
        if fmt == "json" else render_markdown(results)
    )
    if output:
        from pathlib import Path

        Path(output).write_text(text, encoding="utf-8")
        out.success(f"Report written → [wheat1]{output}[/]")
    else:
        out.console.print(text)

    if any(r.error for r in results):
        raise typer.Exit(code=1)

    # A clean-target case (empty ground truth) has no detection rate to speak
    # of — every finding it produces is a false positive by definition, not a
    # missed-detection. This isn't opt-in like --min-detection-rate: any
    # finding at all on a clean target is always a regression (the exact bug
    # class fixed in v1.2.12 — a scanner reporting fake vulnerabilities on a
    # site with none — should never again ship silently).
    false_positive_cases = [r for r in results if r.is_clean_target and r.total_findings > 0]
    if false_positive_cases:
        names_str = ", ".join(f"{r.case} ({r.total_findings} finding(s))" for r in false_positive_cases)
        out.error(f"False positives on a known-clean target: {names_str}")
        raise typer.Exit(code=1)

    if min_detection_rate is not None:
        regressed = [r for r in results if not r.is_clean_target and r.detection_rate < min_detection_rate]
        if regressed:
            names_str = ", ".join(f"{r.case} ({r.detection_rate:.0%})" for r in regressed)
            out.error(f"Detection rate below {min_detection_rate:.0%} threshold: {names_str}")
            raise typer.Exit(code=1)


# --------------------------------------------------------------------------- #
# mcp-server  (expose scan/attack/fix as MCP tools for an editor agent)
# --------------------------------------------------------------------------- #
@app.command(name="mcp-server")
def mcp_server() -> None:
    """Serve Argus as an MCP server over stdio (argus_scan/argus_attack/argus_fix).

    Lets an MCP-capable editor agent (Claude Code, Cursor, Copilot) run Argus
    directly. Needs the optional 'mcp' extra: pip install 'argus-panoptes\\[mcp]'.
    """
    try:
        from argus.mcp_server import run
    except ImportError:
        from argus.cli import output as out

        out.error(
            "The MCP server needs the optional 'mcp' extra — "
            "pip install 'argus-panoptes\\[mcp]'."
        )
        raise typer.Exit(code=1)

    run()


# --------------------------------------------------------------------------- #
# history
# --------------------------------------------------------------------------- #
@app.command()
def history(
    target: Optional[str] = typer.Option(None, "--target", help="Only show history for this exact target."),
    limit: int = typer.Option(50, "--limit", help="Max entries to show, most recent first."),
    fmt: str = typer.Option("table", "--format", help="table | json"),
) -> None:
    """Show risk score/finding trend across past scans."""
    from argus.commands.history_cmd import run_history

    run_history(target=target, limit=limit, fmt=fmt)


# --------------------------------------------------------------------------- #
# compare
# --------------------------------------------------------------------------- #
@app.command()
def compare(
    fmt: str = typer.Option("table", "--format", help="table | json"),
) -> None:
    """Show what's new/fixed since the previous scan."""
    from argus.commands.compare_cmd import run_compare

    run_compare(fmt=fmt)


# --------------------------------------------------------------------------- #
# status
# --------------------------------------------------------------------------- #
@app.command()
def status(
    fmt: str = typer.Option("table", "--format", help="table | json"),
) -> None:
    """Show the resolved LLM provider, detected GPU, and configured defaults."""
    from argus.commands.status_cmd import run_status

    run_status(fmt=fmt)


# --------------------------------------------------------------------------- #
# surface
# --------------------------------------------------------------------------- #
@app.command()
def surface(
    target: Optional[str] = typer.Option(None, "--target", help="Defaults to the last scan's target."),
    fmt: str = typer.Option("table", "--format", help="table | json"),
) -> None:
    """Show the remembered attack-surface (endpoints) for a target across scans."""
    from argus.commands.surface_cmd import run_surface

    run_surface(target=target, fmt=fmt)


# --------------------------------------------------------------------------- #
# suppress / suppressions
# --------------------------------------------------------------------------- #
@app.command()
def suppress(
    search: str = typer.Argument(..., help="Substring to match against a finding's title (case-insensitive)."),
    status: str = typer.Option("ignored", "--status", help="ignored | reviewing | open"),
    reason: str = typer.Option("", "--reason", help="Why (shown in argus suppressions)."),
    target: Optional[str] = typer.Option(None, "--target", help="Defaults to the last scan's target."),
) -> None:
    """Mark a finding from the last scan as ignored/reviewing/open — ignored findings
    stop counting toward risk score and won't resurface as new on future scans."""
    from argus.commands.suppress_cmd import run_suppress

    run_suppress(search=search, status=status, reason=reason, target=target)


@app.command()
def suppressions(
    target: Optional[str] = typer.Option(None, "--target", help="Defaults to the last scan's target."),
    fmt: str = typer.Option("table", "--format", help="table | json"),
) -> None:
    """List suppressed/reviewing findings for a target."""
    from argus.commands.suppress_cmd import run_suppressions

    run_suppressions(target=target, fmt=fmt)


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #
@app.command()
def config(
    provider: Optional[str] = typer.Option(None, "--provider", help="local|groq|gemini|claude|openrouter"),
    key: Optional[str] = typer.Option(None, "--key", help="API key for the given cloud provider."),
    model: Optional[str] = typer.Option(None, "--model", help="Local model name (for --provider local)."),
    show: bool = typer.Option(False, "--show", help="Print the current configuration."),
    notify_webhook: Optional[str] = typer.Option(
        None, "--notify-webhook", help="Slack/Discord webhook URL for scan-complete notifications. Pass '' to disable."
    ),
) -> None:
    """View or change configuration (provider, keys, model, notifications)."""
    from argus.commands.config_cmd import run_config

    run_config(provider=provider, key=key, model=model, show=show, notify_webhook=notify_webhook)


if __name__ == "__main__":  # pragma: no cover
    app()
