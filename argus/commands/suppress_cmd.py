"""Implementation of ``argus suppress`` / ``argus suppressions``."""

from __future__ import annotations

import json

import typer

from argus.cli import output as out
from argus.state import load_result
from argus.suppressions import clear_by_title, list_for, set_status


def run_suppress(search: str, status: str, reason: str, target: str | None) -> None:
    result = load_result()
    effective_target = target or (result.target if result else None)
    if effective_target is None:
        out.error("No previous scan found. Run [wheat1]argus scan <target>[/] first, or pass --target.")
        raise typer.Exit(code=1)

    if status == "open":
        # A suppressed finding is filtered out of the visible scan results by
        # design — search the suppression records themselves, not the scan.
        removed = clear_by_title(effective_target, search)
        if not removed:
            out.error(f"No suppression matching '{search}' recorded for {effective_target}.")
            raise typer.Exit(code=1)
        for e in removed:
            out.success(f"'{e['title']}' is no longer suppressed.")
        return

    if result is None:
        out.error("No previous scan found. Run [wheat1]argus scan <target>[/] first.")
        raise typer.Exit(code=1)

    matches = [f for f in result.findings if search.lower() in f.title.lower()]
    if not matches:
        out.error(f"No finding matching '{search}' in the last scan of {effective_target}.")
        raise typer.Exit(code=1)
    if len(matches) > 1:
        out.warn(f"{len(matches)} finding(s) match '{search}' — be more specific:")
        for f in matches:
            out.info(f"  - {f.title} ({f.file or f.endpoint or '—'})")
        raise typer.Exit(code=1)

    set_status(effective_target, matches[0], status, reason)
    out.success(f"Marked '{matches[0].title}' as [yellow3]{status}[/]"
                 + (f" — {reason}" if reason else "") + ".")


def run_suppressions(target: str | None, fmt: str) -> None:
    effective_target = target
    if effective_target is None:
        result = load_result()
        effective_target = result.target if result else None

    if effective_target is None:
        out.error("No target given and no previous scan found.")
        raise typer.Exit(code=1)

    entries = list_for(effective_target)

    if fmt == "json":
        out.console.print_json(json.dumps(entries))
        return

    out.banner()
    out.rule("SUPPRESSIONS")
    if not entries:
        out.info(f"No suppressions recorded for {effective_target}.")
        return

    from rich.table import Table

    table = Table(show_header=True, header_style="bold yellow3", border_style="grey30")
    table.add_column("STATUS")
    table.add_column("FINDING")
    table.add_column("LOCATION")
    table.add_column("REASON")
    for e in entries:
        table.add_row(e.get("status", "?"), e.get("title", "?"), e.get("location", "—"), e.get("reason", ""))
    out.console.print(table)
