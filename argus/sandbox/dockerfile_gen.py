"""Auto-generates a minimal Dockerfile for the handful of stacks Argus can
confidently guess a start command for.

Deliberately conservative: a wrong guess produces a container that silently
never starts, which for a security tool means an honest target gets reported
as "zero findings" instead of "couldn't sandbox this" — a dangerous false
negative. Better to recognize fewer stacks correctly than more stacks wrong.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


def find_existing_dockerfile(root: Path) -> tuple[str, int] | None:
    """If the repo already ships a Dockerfile, use it as-is.

    Returns (dockerfile_name, guessed_container_port). The port is parsed from
    an ``EXPOSE`` line if present — EXPOSE is documentation only (it doesn't
    actually configure networking), so this is a best-effort guess, not a
    guarantee; falls back to 8080.
    """
    path = root / "Dockerfile"
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8", errors="ignore")
    match = re.search(r"^\s*EXPOSE\s+(\d+)", text, re.MULTILINE | re.IGNORECASE)
    port = int(match.group(1)) if match else 8080
    return "Dockerfile", port


def generate_dockerfile(root: Path) -> tuple[str, int] | None:
    """Returns (dockerfile_content, container_port), or None if the stack
    can't be confidently determined — caller should fall back to ``--url``.
    """
    for probe in (_try_django, _try_node):
        result = probe(root)
        if result is not None:
            return result
    return None


def _try_django(root: Path) -> tuple[str, int] | None:
    # manage.py is a strong, near-universal Django convention — reliable
    # enough to guess "python manage.py runserver" with confidence.
    if not (root / "manage.py").exists():
        return None
    if not (root / "requirements.txt").exists():
        return None
    dockerfile = (
        "FROM python:3.12-slim\n"
        "WORKDIR /app\n"
        "COPY . .\n"
        "RUN pip install --no-cache-dir -r requirements.txt\n"
        "ENV PYTHONUNBUFFERED=1\n"
        "EXPOSE 8000\n"
        'CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]\n'
    )
    return dockerfile, 8000


def _try_node(root: Path) -> tuple[str, int] | None:
    pkg = root / "package.json"
    if not pkg.exists():
        return None
    try:
        data = json.loads(pkg.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    scripts = data.get("scripts")
    # Only trust repos that define their own "start" script — guessing an
    # entrypoint file (index.js? server.js? src/main.js?) is too unreliable.
    if not isinstance(scripts, dict) or "start" not in scripts:
        return None
    dockerfile = (
        "FROM node:20-slim\n"
        "WORKDIR /app\n"
        "COPY . .\n"
        "RUN npm install\n"
        "ENV PORT=3000\n"
        "EXPOSE 3000\n"
        'CMD ["npm", "start"]\n'
    )
    return dockerfile, 3000
