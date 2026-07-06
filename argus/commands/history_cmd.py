"""Implementation of ``argus history`` — trend data across past scans."""

from __future__ import annotations

import json

from argus.cli import output as out
from argus.state import load_history


def run_history(target: str | None, limit: int, fmt: str) -> None:
    entries = load_history(target=target, limit=limit)

    if fmt == "json":
        out.console.print_json(json.dumps(entries))
        return

    out.banner()
    out.rule("SCAN HISTORY")
    if not entries:
        out.info("No scan history yet — run argus scan/attack/audit at least once.")
        return

    from rich.table import Table

    table = Table(show_header=True, header_style="bold yellow3", border_style="grey30")
    table.add_column("WHEN")
    table.add_column("TARGET", style="wheat1")
    table.add_column("PHASE")
    table.add_column("RISK", justify="right")
    table.add_column("BAND")
    for e in entries:
        when = _format_ts(e.get("finished_at"))
        table.add_row(when, str(e.get("target", "?")), str(e.get("phase", "?")),
                      str(e.get("risk_score", "?")), str(e.get("risk_band", "?")))
    out.console.print(table)


def _format_ts(ts: float | None) -> str:
    if not ts:
        return "—"
    import datetime

    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
