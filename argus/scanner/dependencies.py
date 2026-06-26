"""Dependency vulnerability audit via per-language tools.

Wraps the native auditors when present (``npm audit --json``, ``pip-audit -f json``)
and degrades gracefully when they are not installed. Results are normalised into
Argus Findings. Designed to never crash a scan: a missing tool is a skipped step,
not an error.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from argus.models import Finding, Severity

_SEV_MAP = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH, "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
}


def _run(cmd: list[str], cwd: Path, timeout: int = 120) -> subprocess.CompletedProcess | None:
    if shutil.which(cmd[0]) is None:
        return None
    try:
        return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
    except (subprocess.SubprocessError, OSError):
        return None


def audit_npm(root: Path) -> tuple[list[Finding], str | None]:
    """Run ``npm audit --json`` if a package.json + npm exist."""
    if not (root / "package.json").exists():
        return [], None
    if shutil.which("npm") is None:
        return [], "npm not installed — skipped Node dependency audit"
    # npm audit needs a lockfile; if absent, note it.
    if not any((root / lf).exists() for lf in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock")):
        return [], "no Node lockfile — skipped npm audit"

    proc = _run(["npm", "audit", "--json"], root)
    if proc is None or not proc.stdout:
        return [], "npm audit produced no output"
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return [], "could not parse npm audit output"

    findings: list[Finding] = []
    for name, info in (data.get("vulnerabilities") or {}).items():
        sev = _SEV_MAP.get(str(info.get("severity", "low")).lower(), Severity.LOW)
        via = info.get("via", [])
        titles = [v.get("title") for v in via if isinstance(v, dict) and v.get("title")]
        detail = titles[0] if titles else f"Vulnerable version range of {name}"
        findings.append(Finding(
            title=f"Vulnerable dependency: {name}",
            severity=sev,
            category="dependency",
            detector="npm-audit",
            file="package.json",
            description=f"{detail}. Affected range: {info.get('range', 'unknown')}.",
            fix=f"Update {name} to a fixed version (npm audit fix) or replace it.",
            cwe="CWE-1395",
            confidence="high",
            metadata={"package": name, "range": info.get("range")},
        ))
    return findings, None


def audit_pip(root: Path) -> tuple[list[Finding], str | None]:
    """Run ``pip-audit`` against requirements if available."""
    has_manifest = any((root / m).exists() for m in ("requirements.txt", "pyproject.toml", "Pipfile.lock"))
    if not has_manifest:
        return [], None
    if shutil.which("pip-audit") is None:
        return [], "pip-audit not installed — skipped Python dependency audit (pip install pip-audit)"

    cmd = ["pip-audit", "-f", "json"]
    if (root / "requirements.txt").exists():
        cmd += ["-r", "requirements.txt"]
    proc = _run(cmd, root)
    if proc is None or not proc.stdout:
        return [], "pip-audit produced no output"
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return [], "could not parse pip-audit output"

    deps = data.get("dependencies", data) if isinstance(data, dict) else data
    findings: list[Finding] = []
    for dep in deps if isinstance(deps, list) else []:
        name = dep.get("name", "?")
        version = dep.get("version", "?")
        for vuln in dep.get("vulns", []) or []:
            vid = vuln.get("id", "CVE")
            fix_versions = ", ".join(vuln.get("fix_versions", []) or []) or "a patched release"
            findings.append(Finding(
                title=f"Vulnerable dependency: {name} {version}",
                severity=Severity.HIGH,
                category="dependency",
                detector="pip-audit",
                file="requirements.txt",
                description=f"{vid}: {vuln.get('description', '')[:300]}",
                fix=f"Upgrade {name} to {fix_versions}.",
                cwe="CWE-1395",
                confidence="high",
                references=[f"https://osv.dev/vulnerability/{vid}"],
                metadata={"package": name, "version": version, "id": vid},
            ))
    return findings, None


def audit_dependencies(root: Path) -> tuple[list[Finding], list[str]]:
    """Run all available dependency auditors. Returns (findings, notes)."""
    findings: list[Finding] = []
    notes: list[str] = []
    for fn in (audit_npm, audit_pip):
        f, note = fn(root)
        findings.extend(f)
        if note:
            notes.append(note)
    return findings, notes
