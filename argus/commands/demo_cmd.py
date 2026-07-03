"""Implementation of ``argus demo`` — the zero-setup showcase.

Writes the bundled vulnerable sample to a temp dir and runs a full static scan on
it, then (unless --no-attack) spins the bundled vulnerable app on a local port and
unleashes the attack swarm against it. Everything is self-contained and legal to
attack — it is Argus's own demo target.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from argus.cli import output as out
from argus.demo.target import SAMPLE_FILES, DemoServer


def run_demo(attack: bool = True) -> None:
    out.banner()
    out.console.print()
    out.console.print(
        "[wheat1]Argus demo[/] — scanning and attacking a [italic]bundled, "
        "intentionally-vulnerable[/] app. Nothing external is touched."
    )

    tmp = Path(tempfile.mkdtemp(prefix="argus-demo-"))
    try:
        for name, content in SAMPLE_FILES.items():
            (tmp / name).write_text(content, encoding="utf-8")

        # --- Phase 1: static scan of the sample source ---
        from argus.pipeline import run_scan

        out.console.print()
        run_scan(str(tmp), no_llm=True)

        # --- Phase 2: attack the running bundled app ---
        if attack:
            from argus.pipeline import run_attack

            out.console.print()
            server = DemoServer().start()
            try:
                out.info(f"Bundled target running at [wheat1]{server.url}[/]")
                run_attack(url=server.url, banner=False)
            finally:
                server.stop()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    out.console.print()
    out.rule("DEMO COMPLETE")
    out.success("That was Argus against its own bundled vulnerable app.")
    out.info("Point it at real code next: [wheat1]argus scan <repo-url-or-path>[/]")
    out.info("Or attack a running app: [wheat1]argus attack --url http://localhost:3000[/]")
