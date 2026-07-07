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
) -> None:
    """Generate LLM-written patches for fixable findings; preview or apply them."""
    from argus.pipeline import run_fix

    run_fix(target, apply=apply)


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
    depth: Optional[str] = typer.Option(None, "--depth", help="quick | standard | deep"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Deterministic scan only, skip the LLM layer."),
    fmt: Optional[str] = typer.Option(None, "--format", help="Also export a report: html|json|pdf|markdown|sarif|sbom."),
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

    run_scan(target, deep=deep, depth=depth, no_llm=no_llm, export_format=fmt,
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
    api_spec: Optional[str] = typer.Option(None, "--api-spec", help="OpenAPI/Swagger/Postman/GraphQL spec (file or URL) to seed the attack surface."),
) -> None:
    """Phase 2 — attack agent. Actively exploit a running app."""
    from argus.pipeline import run_attack

    run_attack(target=target, url=url, agents=agents, auth=auth, api_spec=api_spec)


# --------------------------------------------------------------------------- #
# audit  (Phase 1 + Phase 2)
# --------------------------------------------------------------------------- #
@app.command()
def audit(
    target: str = typer.Argument(..., help="Repo URL or local path."),
    fix: bool = typer.Option(False, "--fix", help="Suggest fixes after the audit."),
    agents: Optional[str] = typer.Option(None, "--agents", help="Comma-separated agent subset."),
    auth: Optional[str] = typer.Option(None, "--auth", help="Path to a .argus-auth.toml so Phase 2 attacks the logged-in surface."),
    api_spec: Optional[str] = typer.Option(None, "--api-spec", help="OpenAPI/Swagger/Postman/GraphQL spec (file or URL) to seed the attack surface."),
) -> None:
    """Full pipeline — Phase 1 static analysis then Phase 2 attack."""
    from argus.pipeline import run_audit

    run_audit(target, fix=fix, agents=agents, auth=auth, api_spec=api_spec)


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #
@app.command()
def report(
    fmt: str = typer.Option("html", "--format", help="html | json | pdf | markdown | sarif | sbom"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output directory."),
) -> None:
    """Export the most recent scan result in the chosen format."""
    from argus.pipeline import export_last

    export_last(fmt=fmt, output=output)


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
