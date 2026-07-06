"""Package inventory extraction for SBOM export.

Separate from ``argus/scanner/supplychain.py``, which parses the same
manifests but only to hunt for *vulnerabilities* (typosquats, unpinned
versions, install-script abuse) — an SBOM needs the full package list
regardless of whether anything's wrong with it, so it's collected here as
its own concern rather than bolted onto the finding-generation code.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


def _parse_npm_packages(root: Path, manifest_rel: str) -> list[dict]:
    full = root / manifest_rel
    try:
        data = json.loads(full.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []

    packages: list[dict] = []
    for key in ("dependencies", "devDependencies"):
        section = data.get(key)
        if not isinstance(section, dict):
            continue
        for name, version in section.items():
            if not isinstance(version, str):
                continue
            packages.append({
                "name": name,
                "version": re.sub(r"^[\^~>=<]+", "", version.strip()) or "unknown",
                "ecosystem": "npm",
            })
    return packages


def _parse_pip_packages(root: Path, manifest_rel: str) -> list[dict]:
    full = root / manifest_rel
    try:
        lines = full.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []

    packages: list[dict] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        parts = re.split(r"==", stripped, maxsplit=1)
        name = re.split(r"[<>!~\[; ]", parts[0], maxsplit=1)[0].strip()
        if not name:
            continue
        version = parts[1].strip() if len(parts) > 1 else "unknown"
        packages.append({"name": name, "version": version, "ecosystem": "pypi"})
    return packages


def collect_packages(root: Path, manifests: list[str]) -> list[dict]:
    """Extract a flat, deduplicated package inventory from known manifest types.

    Silently skips manifest types Argus doesn't have a parser for — an SBOM
    with fewer entries than expected is a better failure mode for a security
    tool than one that crashes or fabricates package data.
    """
    packages: list[dict] = []
    seen: set[tuple] = set()
    for rel in manifests:
        name = Path(rel).name.lower()
        if name == "package.json":
            found = _parse_npm_packages(root, rel)
        elif name == "requirements.txt":
            found = _parse_pip_packages(root, rel)
        else:
            continue
        for pkg in found:
            key = (pkg["ecosystem"], pkg["name"].lower())
            if key in seen:
                continue
            seen.add(key)
            packages.append(pkg)
    return packages
