"""Implementation of ``argus surface`` — the persisted attack-surface inventory."""

from __future__ import annotations

import json

import typer

from argus.cli import output as out
from argus.state import load_result
from argus.surface import load_surface


def run_surface(target: str | None, fmt: str) -> None:
    effective = target
    if effective is None:
        result = load_result()
        effective = result.target if result else None
    if effective is None:
        out.error("No target given and no previous scan found. Pass --target.")
        raise typer.Exit(code=1)

    endpoints = load_surface(effective)

    if fmt == "json":
        out.console.print_json(json.dumps([
            {"method": ep.method, "url": ep.url, "params": ep.params,
             "source": ep.source, "sample_status": ep.sample_status}
            for ep in endpoints
        ]))
        return

    out.banner()
    out.rule("ATTACK SURFACE")
    if not endpoints:
        out.info(f"No surface recorded for {effective} yet — run argus attack against it first.")
        return

    from rich.table import Table

    table = Table(show_header=True, header_style="bold yellow3", border_style="grey30")
    table.add_column("METHOD")
    table.add_column("URL", style="wheat1")
    table.add_column("PARAMS")
    table.add_column("STATUS", justify="right")
    for ep in endpoints:
        table.add_row(ep.method, ep.url, ", ".join(ep.params) or "—",
                      str(ep.sample_status) if ep.sample_status is not None else "—")
    out.console.print(table)
    out.console.print()
    out.info(f"{len(endpoints)} endpoint(s) known for {effective}.")
