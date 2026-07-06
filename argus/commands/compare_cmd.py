"""Implementation of ``argus compare`` — what's new/fixed since the last scan."""

from __future__ import annotations

import json

import typer

from argus.cli import output as out
from argus.compare import diff_results
from argus.state import load_previous_result, load_result


def _finding_dict(f) -> dict:
    return {
        "title": f.title, "severity": f.severity.value, "category": f.category,
        "file": f.file, "line": f.line, "endpoint": f.endpoint,
    }


def run_compare(fmt: str) -> None:
    new = load_result()
    if new is None:
        out.error("No scan found. Run argus scan/attack/audit first.")
        raise typer.Exit(code=1)

    old = load_previous_result()
    if old is None:
        if fmt == "json":
            out.console.print_json(json.dumps({
                "old_target": None, "new_target": new.target,
                "new_findings": [], "fixed_findings": [], "unchanged_count": 0,
            }))
        else:
            out.banner()
            out.rule("COMPARE")
            out.info("Only one scan recorded so far — nothing to compare against yet. "
                      "Run another scan to see what's changed.")
        return

    result = diff_results(old, new)

    if fmt == "json":
        out.console.print_json(json.dumps({
            "old_target": result.old_target, "new_target": result.new_target,
            "new_findings": [_finding_dict(f) for f in result.new_findings],
            "fixed_findings": [_finding_dict(f) for f in result.fixed_findings],
            "unchanged_count": result.unchanged_count,
        }))
        return

    out.banner()
    out.rule("COMPARE")
    if result.old_target != result.new_target:
        out.warn(f"Comparing different targets: [wheat1]{result.old_target}[/] -> "
                 f"[wheat1]{result.new_target}[/] — results may not be meaningful.")

    from rich.table import Table

    if result.new_findings:
        table = Table(title="NEW", show_header=True, header_style="bold red",
                      border_style="grey30")
        table.add_column("SEVERITY")
        table.add_column("FINDING")
        table.add_column("LOCATION")
        for f in result.new_findings:
            table.add_row(f.severity.value, f.title, f.file or f.endpoint or "—")
        out.console.print(table)
    else:
        out.success("No new findings since the last scan.")

    out.console.print()
    if result.fixed_findings:
        table = Table(title="FIXED", show_header=True, header_style="bold green3",
                      border_style="grey30")
        table.add_column("SEVERITY")
        table.add_column("FINDING")
        table.add_column("LOCATION")
        for f in result.fixed_findings:
            table.add_row(f.severity.value, f.title, f.file or f.endpoint or "—")
        out.console.print(table)
    else:
        out.info("Nothing resolved since the last scan.")

    out.console.print()
    out.info(f"{result.unchanged_count} finding(s) unchanged since the last scan.")
