"""Optional Docker sandbox management.

When Docker is available and the target is a repo (not a live URL), Argus can spin
the app up in an isolated container to attack it. Docker is *not* required: this
module detects availability and the pipeline falls back to ``--url`` mode when it
is missing. Full auto-Dockerfile generation is a later milestone; for now this
provides detection plus a thin run/stop wrapper over the Docker SDK if installed.
"""

from __future__ import annotations

import shutil


def docker_available() -> bool:
    """True only if the docker CLI exists and the daemon answers."""
    if shutil.which("docker") is None:
        return False
    try:
        import subprocess

        proc = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=8,
        )
        return proc.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def availability_note() -> str:
    if docker_available():
        return "docker available"
    if shutil.which("docker") is None:
        return "docker not installed — use 'argus attack --url <running-app>' instead"
    return "docker installed but daemon not reachable — start Docker Desktop"
