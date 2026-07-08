"""Container base-image CVE scanning via Trivy (roadmap v0.4.3).

The dependency audit covers *language* packages (npm/pip); it says nothing about
the OS packages baked into the container base image, which is where a lot of real
CVEs live (an old `python:3.9` or `node:18` base drags in vulnerable openssl,
zlib, etc.). This complements the Dockerfile *lint* (argus/scanner/iac.py) with an
actual CVE scan of the base image(s) a repo's Dockerfiles declare.

Follows the same graceful-degradation contract as the npm/pip auditors: it only
runs when Trivy is installed and a Dockerfile declares a scannable base image;
otherwise it's a skipped step with a note, never an error. Digest-pinned and
stage-alias FROMs are handled; `scratch` is ignored.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from argus.models import Finding, Severity

_FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.I | re.M)
_SEV_MAP = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW, "UNKNOWN": Severity.LOW,
}


def _is_dockerfile(name: str) -> bool:
    n = name.lower()
    return n == "dockerfile" or n.startswith("dockerfile.")


def base_images(root: Path) -> list[str]:
    """Distinct base images declared across the repo's Dockerfiles, excluding
    ``scratch`` and references to earlier build stages."""
    images: list[str] = []
    seen: set[str] = set()
    for path in root.rglob("*"):
        if not path.is_file() or not _is_dockerfile(path.name):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        stages: set[str] = set()
        for m in _FROM_RE.finditer(text):
            image, alias = m.group(1), m.group(2)
            if alias:
                stages.add(alias.lower())
            if image.lower() in stages or image.lower() == "scratch":
                continue
            if image not in seen:
                seen.add(image)
                images.append(image)
    return images


def _scan_image(image: str, timeout: int = 300) -> tuple[list[Finding], str | None]:
    proc = subprocess.run(
        ["trivy", "image", "--quiet", "--format", "json", "--scanners", "vuln", image],
        capture_output=True, text=True, timeout=timeout,
    )
    if not proc.stdout:
        return [], f"trivy could not scan {image} (image not pulled or unreachable)"
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return [], f"could not parse trivy output for {image}"

    findings: list[Finding] = []
    seen: set[str] = set()
    for result in data.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID", "CVE")
            pkg = v.get("PkgName", "?")
            key = f"{vid}:{pkg}"
            if key in seen:
                continue
            seen.add(key)
            fixed = v.get("FixedVersion")
            findings.append(Finding(
                title=f"Vulnerable OS package in base image: {pkg} ({vid})",
                severity=_SEV_MAP.get(str(v.get("Severity", "LOW")).upper(), Severity.LOW),
                category="dependency",
                detector="trivy-image",
                file="Dockerfile",
                description=f"{vid} in {pkg} {v.get('InstalledVersion', '?')} from base image "
                            f"'{image}': {(v.get('Title') or v.get('Description') or '')[:200]}",
                fix=(f"Upgrade {pkg} to {fixed}." if fixed
                     else "Rebuild on a patched/newer base image tag.") + " Prefer a slim/current base.",
                cwe="CWE-1395",
                confidence="high",
                references=[u for u in (v.get("References") or [])[:2]],
                metadata={"package": pkg, "id": vid, "image": image, "reachable": True},
            ))
    return findings, None


def scan_container_images(root: Path) -> tuple[list[Finding], list[str]]:
    """Scan the repo's Dockerfile base image(s) for OS CVEs. Graceful: returns a
    note (not an error) when Trivy is missing or no Dockerfile declares a base."""
    images = base_images(root)
    if not images:
        return [], []
    if shutil.which("trivy") is None:
        return [], ["trivy not installed — skipped base-image CVE scan "
                    "(install Trivy for OS-package CVEs; the Dockerfile lint still ran)"]
    findings: list[Finding] = []
    notes: list[str] = []
    for image in images[:5]:
        try:
            f, note = _scan_image(image)
        except (subprocess.SubprocessError, OSError) as exc:
            notes.append(f"trivy failed on {image}: {exc}")
            continue
        findings.extend(f)
        if note:
            notes.append(note)
    return findings, notes
