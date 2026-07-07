"""Infrastructure-as-code misconfiguration scanning — Dockerfiles & compose.

The regular rule scanner (``rules_builtin.py``) is keyed on file extension via
``LANGUAGE_BY_EXT``, so it never looks at a ``Dockerfile`` (no extension) or a
``docker-compose.yml`` beyond secret scanning. Yet the vibe-coder audience
ships almost everything in a container, and the classic container footguns —
running as root, an unpinned ``:latest`` base, ``ADD``ing a remote URL, piping
a download straight into a shell, ``privileged: true`` — are exactly the kind
of thing that never gets reviewed. This adds a small, file-aware linter for
them, wired into the scan alongside the dependency/supply-chain checks.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from argus.config.defaults import IGNORE_DIRS
from argus.models import Finding, Severity

_DOCKERFILE_NAMES = ("dockerfile",)
_COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")

_FROM = re.compile(r"^\s*FROM\s+(?P<image>\S+)", re.IGNORECASE)
_USER = re.compile(r"^\s*USER\s+(?P<user>\S+)", re.IGNORECASE)
_ADD_URL = re.compile(r"^\s*ADD\s+https?://", re.IGNORECASE)
_PIPE_SHELL = re.compile(r"(?i)(?:curl|wget)\b[^|&;]*\|\s*(?:sh|bash|zsh)\b")


def _dockerfile_findings(rel: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()

    has_from = False
    switches_to_nonroot = False
    last_from_line = 0

    for idx, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        m = _FROM.match(line)
        if m:
            has_from = True
            last_from_line = idx
            image = m.group("image")
            # scratch and build-stage refs (AS name / referencing a prior stage) are fine
            if image.lower() != "scratch" and "$" not in image:
                tag = image.split(":", 1)[1] if ":" in image.split("@")[0] else None
                if "@sha256:" in image:
                    pass  # digest-pinned — the strongest form
                elif tag is None or tag.lower() == "latest":
                    findings.append(Finding(
                        title="Unpinned container base image",
                        severity=Severity.LOW, category="misconfig", detector="iac:dockerfile-unpinned-base",
                        file=rel, line=idx, evidence=line[:200],
                        description=f"Base image '{image}' uses no tag or ':latest', so a rebuild can silently "
                                    f"pull a different, possibly compromised image.",
                        fix="Pin the base image to a specific version (and ideally a @sha256 digest).",
                        cwe="CWE-1104", confidence="medium",
                    ))

        u = _USER.match(line)
        if u and u.group("user").lower() not in ("root", "0"):
            switches_to_nonroot = True

        if _ADD_URL.match(line):
            findings.append(Finding(
                title="Dockerfile ADD from a remote URL",
                severity=Severity.MEDIUM, category="misconfig", detector="iac:dockerfile-add-url",
                file=rel, line=idx, evidence=line[:200],
                description="ADD with a URL fetches a remote file at build time with no integrity check "
                            "and silently unpacks archives.",
                fix="Use COPY for local files, or RUN curl with a pinned checksum for remote ones.",
                cwe="CWE-829", confidence="high",
            ))

        if _PIPE_SHELL.search(line):
            findings.append(Finding(
                title="Dockerfile pipes a remote download into a shell",
                severity=Severity.HIGH, category="misconfig", detector="iac:dockerfile-curl-pipe-sh",
                file=rel, line=idx, evidence=line[:200],
                description="A remote script is piped straight into a shell at build time — whatever the URL "
                            "serves at build runs with no review (a classic supply-chain vector).",
                fix="Download to a file, verify a pinned checksum, then execute.",
                cwe="CWE-829", confidence="high",
            ))

    if has_from and not switches_to_nonroot:
        findings.append(Finding(
            title="Container runs as root (no USER directive)",
            severity=Severity.MEDIUM, category="misconfig", detector="iac:dockerfile-runs-as-root",
            file=rel, line=last_from_line, evidence="No 'USER' directive switching away from root",
            description="The image never drops to a non-root user, so a container compromise runs as root "
                        "inside the container (and closer to the host).",
            fix="Add a non-root 'USER' directive after installing dependencies.",
            cwe="CWE-250", confidence="medium",
        ))
    return findings


_COMPOSE_PRIVILEGED = re.compile(r"(?i)^\s*privileged\s*:\s*true")
_COMPOSE_HOST_NET = re.compile(r"(?i)^\s*network_mode\s*:\s*['\"]?host")


def _compose_findings(rel: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for idx, raw in enumerate(text.splitlines(), start=1):
        if _COMPOSE_PRIVILEGED.match(raw):
            findings.append(Finding(
                title="Privileged container in compose",
                severity=Severity.HIGH, category="misconfig", detector="iac:compose-privileged",
                file=rel, line=idx, evidence=raw.strip()[:200],
                description="'privileged: true' gives the container near-total access to the host — a "
                            "container escape becomes a host compromise.",
                fix="Remove 'privileged: true'; grant only the specific capabilities actually needed.",
                cwe="CWE-250", confidence="high",
            ))
        if _COMPOSE_HOST_NET.match(raw):
            findings.append(Finding(
                title="Host network mode in compose",
                severity=Severity.MEDIUM, category="misconfig", detector="iac:compose-host-network",
                file=rel, line=idx, evidence=raw.strip()[:200],
                description="'network_mode: host' removes network isolation between the container and the host.",
                fix="Use the default bridge network and publish only the ports you need.",
                cwe="CWE-668", confidence="high",
            ))
    return findings


def scan_iac(root: Path) -> tuple[list[Finding], list[str]]:
    """Scan Dockerfiles and compose files for common misconfigurations."""
    findings: list[Finding] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for fn in filenames:
            lower = fn.lower()
            full = Path(dirpath) / fn
            try:
                text = full.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(full.relative_to(root)).replace("\\", "/")
            if lower in _DOCKERFILE_NAMES or lower.startswith("dockerfile."):
                findings.extend(_dockerfile_findings(rel, text))
            elif lower in _COMPOSE_NAMES:
                findings.extend(_compose_findings(rel, text))
    return findings, []
