"""Fix engine: validates and applies LLM-generated unified diffs.

LLM-produced diffs are frequently imprecise about exact line numbers, so rather
than trusting the ``@@ -l,s +l,s @@`` header positions, each hunk's old-content
block is located by an *exact content search* within the target file and replaced
with the new-content block. A hunk that doesn't match exactly once (zero matches,
or more than one — ambiguous) is rejected rather than guessed at: a security tool
must never silently mis-patch code.

Default is dry-run: fixes are printed for review but nothing is written. Pass
``apply=True`` to write them to disk.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from argus.cli import output as out
from argus.llm.reasoning import FixResult

_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@")
_FILE_HEADER = re.compile(r"^(---|\+\+\+) ")


@dataclass
class AppliedFix:
    """The outcome of validating (and optionally writing) one proposed fix."""

    file: str
    explanation: str
    diff: str
    written: bool


def _parse_hunks(diff_text: str) -> list[tuple[list[str], list[str]]]:
    """Split a unified diff into (old_lines, new_lines) pairs, one per hunk."""
    hunks: list[tuple[list[str], list[str]]] = []
    old: list[str] = []
    new: list[str] = []
    in_hunk = False

    def flush() -> None:
        if old or new:
            hunks.append((old[:], new[:]))
        old.clear()
        new.clear()

    for line in diff_text.splitlines():
        if _FILE_HEADER.match(line):
            continue
        if _HUNK_HEADER.match(line):
            flush()
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if line.startswith("-"):
            old.append(line[1:])
        elif line.startswith("+"):
            new.append(line[1:])
        elif line.startswith(" "):
            old.append(line[1:])
            new.append(line[1:])
        elif line == "":
            old.append("")
            new.append("")
    flush()
    return hunks


def apply_diff_to_text(original: str, diff_text: str) -> str | None:
    """Apply a unified diff to ``original`` via exact content matching.

    Returns the patched text, or ``None`` if any hunk's old-content block doesn't
    match exactly one location in the original text (rejected, never guessed).
    """
    hunks = _parse_hunks(diff_text)
    if not hunks:
        return None
    text = original
    for old_lines, new_lines in hunks:
        old_block = "\n".join(old_lines)
        new_block = "\n".join(new_lines)
        if old_block == new_block:
            continue  # no-op hunk
        if not old_block.strip():
            return None  # nothing concrete to anchor an insertion to — refuse to guess
        if text.count(old_block) != 1:
            return None  # zero or ambiguous matches
        text = text.replace(old_block, new_block, 1)
    return text


def apply_fixes(root: Path, fixes: list[FixResult], *, apply: bool = False) -> list[AppliedFix]:
    """Preview (default) or write each fix's patch. Returns the fixes that validated."""
    results: list[AppliedFix] = []
    for fx in fixes:
        target = root / fx.file
        try:
            original = target.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            out.warn(f"Skipped {fx.file}: could not read the file")
            continue

        patched = apply_diff_to_text(original, fx.diff)
        if patched is None:
            out.warn(f"Skipped {fx.file}: diff did not match the current file content exactly")
            continue

        out.console.print()
        out.step(f"Fix for [wheat1]{fx.file}[/]: {fx.explanation}")
        out.console.print(fx.diff)

        written = False
        if apply:
            target.write_text(patched, encoding="utf-8")
            out.success(f"Applied → {fx.file}")
            written = True

        results.append(AppliedFix(file=fx.file, explanation=fx.explanation, diff=fx.diff, written=written))
    return results
