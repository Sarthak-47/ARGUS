"""Optional Semgrep integration.

Semgrep is the industry-standard static engine, but it does not run natively on
Windows and is an optional Argus dependency. This module runs it when available
(``argus[semgrep]`` installed and the binary on PATH) and returns normalised
Findings; otherwise it returns a note and Argus relies on its built-in rules.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from argus.models import Finding, Severity

_SEV_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def run_semgrep(root: Path, config: str = "auto", timeout: int = 300) -> tuple[list[Finding], str | None]:
    """Run Semgrep, returning (findings, note_if_skipped)."""
    if not semgrep_available():
        return [], "semgrep not installed — using built-in rules (pip install 'argus-panoptes[semgrep]')"

    cmd = [
        "semgrep", "scan", "--config", config, "--json", "--quiet",
        "--timeout", "20", "--max-target-bytes", "1500000", str(root),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.SubprocessError, OSError) as exc:
        return [], f"semgrep failed to run: {exc}"

    if not proc.stdout:
        return [], "semgrep produced no output"
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return [], "could not parse semgrep output"

    findings: list[Finding] = []
    for res in data.get("results", []):
        extra = res.get("extra", {})
        meta = extra.get("metadata", {})
        sev = _SEV_MAP.get(str(extra.get("severity", "INFO")).upper(), Severity.LOW)
        path = res.get("path", "")
        try:
            rel = str(Path(path).resolve().relative_to(root.resolve())).replace("\\", "/")
        except ValueError:
            rel = path
        findings.append(Finding(
            title=extra.get("message", res.get("check_id", "semgrep finding")).split("\n")[0][:120],
            severity=sev,
            category=(meta.get("category") or "semgrep"),
            detector="semgrep",
            file=rel,
            line=res.get("start", {}).get("line"),
            evidence=(extra.get("lines") or "").strip()[:200],
            description=extra.get("message", ""),
            fix=extra.get("fix") or "See the Semgrep rule guidance for remediation.",
            cwe=(meta.get("cwe", [None])[0] if isinstance(meta.get("cwe"), list) else meta.get("cwe")),
            confidence=str(meta.get("confidence", "medium")).lower(),
            references=meta.get("references", []) or [],
            metadata={"check_id": res.get("check_id")},
        ))
    return findings, None
