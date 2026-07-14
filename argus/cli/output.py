"""Rich-based terminal output: banner, severity tables, risk panels, progress.

Keeps all presentation in one place so commands stay focused on logic. The palette
sticks to the 'carved in stone' system — goldenrod/bronze/parchment, crimson/sienna
for severity — and deliberately avoids green/blue/purple.
"""

from __future__ import annotations

import sys
from contextlib import contextmanager

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from argus.models import ScanResult, Severity


# Windows consoles default to cp1252 and choke on the design glyphs (◈, ■, —).
# Reconfigure the standard streams to UTF-8 so Argus renders everywhere. Done at
# import time (before any Console write) but after imports to keep linters happy.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass

console = Console()

# Reusable styles aligned to the design palette.
GOLD = "yellow3"
GOLD_PALE = "light_goldenrod2"
BRONZE = "dark_orange3"
PARCHMENT = "wheat1"
STONE = "grey46"
CRIMSON = "bold red"


def banner() -> None:
    """Print the Argus wordmark."""
    eye = Text("◈", style=f"bold {GOLD}")
    name = Text(" ARGUS", style=f"bold {GOLD_PALE}")
    tag = Text("  ·  the hundred-eyed security auditor", style=f"italic {STONE}")
    console.print(Text.assemble(eye, name, tag))


def rule(label: str = "") -> None:
    console.rule(Text(label, style=GOLD) if label else "", style="grey30")


def info(msg: str) -> None:
    console.print(f"[{STONE}]›[/] {msg}")


def success(msg: str) -> None:
    console.print(f"[{GOLD}]✓[/] {msg}")


def warn(msg: str) -> None:
    console.print(f"[{BRONZE}]![/] {msg}")


def error(msg: str) -> None:
    console.print(f"[{CRIMSON}]✗[/] {msg}")


def step(msg: str) -> None:
    console.print(f"  [{BRONZE}]▸[/] [{PARCHMENT}]{msg}[/]")


@contextmanager
def progress(description: str = "working"):
    """A bronze-tinted progress context for long-running work."""
    prog = Progress(
        SpinnerColumn(style=BRONZE),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(complete_style=BRONZE, finished_style=GOLD),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )
    with prog:
        yield prog


def severity_dot(sev: Severity) -> Text:
    """Square-ish severity marker (terminal can't do real squares; use ■)."""
    return Text("■", style=sev.rich_style)


def risk_panel(result: ScanResult) -> None:
    """Big risk score + per-severity breakdown, in the Phase-1 output style."""
    counts = result.counts()
    score = result.risk_score
    band = result.risk_band
    band_style = (
        "bold red" if score >= 70 else "dark_orange3" if score >= 45 else "yellow3"
    )

    header = Text.assemble(
        ("Risk Score  ", f"bold {STONE}"),
        (f"{score}", f"bold {band_style}"),
        ("/100  ", STONE),
        (f"[{band}]", band_style),
    )

    table = Table(show_header=False, box=None, pad_edge=False, padding=(0, 1))
    table.add_column(justify="left", width=3)
    table.add_column(justify="left", width=10)
    table.add_column(justify="right", width=5)
    for sev in Severity:
        n = counts[sev.value]
        style = sev.rich_style if n else STONE
        table.add_row(
            severity_dot(sev),
            Text(sev.value, style=style),
            Text(str(n), style=style),
        )

    console.print()
    console.print(Panel(table, title=header, border_style="grey30", expand=False))


def findings_table(result: ScanResult, limit: int | None = None) -> None:
    """Tabular listing of findings, worst-first."""
    findings = result.sorted_findings()
    if limit:
        findings = findings[:limit]
    if not findings:
        info("No findings.")
        return

    table = Table(
        show_header=True,
        header_style=f"bold {GOLD}",
        border_style="grey30",
        expand=True,
        row_styles=["", "on grey7"],
    )
    table.add_column("", width=1)
    table.add_column("SEVERITY", width=9)
    table.add_column("FINDING", ratio=3)
    table.add_column("LOCATION", ratio=2, style=STONE)
    table.add_column("DETECTOR", width=14, style=BRONZE)

    for f in findings:
        table.add_row(
            severity_dot(f.severity),
            Text(f.severity.value, style=f.severity.rich_style),
            Text(f.title, style=PARCHMENT),
            f.location,
            f.detector,
        )
    console.print(table)


def batch_summary_table(rows: list[tuple[str, str, str, int]]) -> None:
    """One row per target from `argus scan --targets-file`: (target, band-or-
    "ERROR", score-or-error-message, finding count)."""
    table = Table(
        show_header=True,
        header_style=f"bold {GOLD}",
        border_style="grey30",
        expand=True,
        row_styles=["", "on grey7"],
    )
    table.add_column("TARGET", ratio=3, style=PARCHMENT)
    table.add_column("BAND", width=10)
    table.add_column("SCORE / ERROR", ratio=2, style=STONE)
    table.add_column("FINDINGS", width=9, justify="right")

    band_style = {
        "CRITICAL": "bold red", "HIGH": "dark_orange3", "MEDIUM": "yellow3",
        "LOW": "grey58", "ERROR": CRIMSON,
    }
    for target, band, score_or_error, count in rows:
        table.add_row(
            target,
            Text(band, style=band_style.get(band, "grey58")),
            score_or_error,
            str(count) if band != "ERROR" else "—",
        )
    console.print(table)


def codebase_summary(result: ScanResult) -> None:
    """One-line-per-fact summary of what ingestion understood."""
    cm = result.codebase_map
    if not cm:
        return
    langs = ", ".join(f"{k} ({v})" for k, v in sorted(cm.languages.items(), key=lambda x: -x[1])[:5])
    step(f"Language: [{PARCHMENT}]{cm.primary_language or 'unknown'}[/]   "
         f"Files: {cm.file_count}   LOC: {cm.total_loc}")
    if cm.frameworks:
        step(f"Frameworks: {', '.join(cm.frameworks)}")
    if langs:
        step(f"Breakdown: {langs}")
    if cm.high_risk_files:
        step(f"High-risk files: {len(cm.high_risk_files)}")
