"""Fast, file-scoped scan for the `pre-commit` hook (roadmap D1).

`pre-commit` runs a hook against the list of staged files and blocks the commit
if the hook exits non-zero. This is the cheapest, highest-frequency way to use
Argus — catch a hardcoded secret or an obvious vulnerable pattern *before* it
lands in history, where it's far cheaper to fix.

Deliberately narrow: only the deterministic, offline passes that are fast enough
to run on every commit — the secret scanner (regex + entropy) and the built-in
static rules. No LLM, no dependency audit, no attack. Reuses the exact per-file
helpers the full `argus scan` uses, so a finding here is the same finding there.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from argus.models import Finding, Severity


def staged_files(root: Path) -> list[str]:
    """Files staged for commit (added/copied/modified), repo-relative. Empty on
    any git error — the caller then simply has nothing to scan."""
    try:
        proc = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            cwd=str(root), capture_output=True, text=True, timeout=15,
        )
    except (subprocess.SubprocessError, OSError):
        return []
    if proc.returncode != 0:
        return []
    return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]


def scan_paths(paths: list[str], root: Path | None = None) -> list[Finding]:
    """Run the secret + built-in-rule passes over the given files only.

    Paths may be absolute or repo-relative; missing (e.g. deleted) or oversized
    files are skipped. Findings carry the same signatures as a full scan.
    """
    from argus.scanner import rules_builtin as R
    from argus.scanner import secrets as S

    root = (root or Path.cwd()).resolve()
    findings: list[Finding] = []
    seen: set[tuple] = set()

    for p in paths:
        full = Path(p)
        if not full.is_absolute():
            full = root / p
        if not full.is_file():
            continue
        try:
            if full.stat().st_size > R.MAX_FILE_BYTES:
                continue
            text = full.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        try:
            rel = str(full.resolve().relative_to(root)).replace("\\", "/")
        except ValueError:
            rel = str(full).replace("\\", "/")

        name_lc = full.name.lower()
        ext = full.suffix.lower()

        file_findings: list[Finding] = []
        if ext in S._TEXT_EXT or name_lc in S._ALWAYS_SCAN:
            file_findings.extend(S._scan_text(rel, text))
        if ext in R._TEXT_EXT:
            lang = R._lang_for(full)
            if lang:
                file_findings.extend(R._scan_file(rel, lang, text))

        # De-dup identical hits (same detector/file/line) if a path is passed twice.
        for f in file_findings:
            key = (f.detector, f.file, f.line, f.title)
            if key not in seen:
                seen.add(key)
                findings.append(f)
    return findings


def blocking_findings(findings: list[Finding], fail_on: str) -> list[Finding]:
    """Findings at or above the ``fail_on`` severity — these block the commit."""
    threshold = Severity.coerce(fail_on)
    return [f for f in findings if f.severity.rank >= threshold.rank]
