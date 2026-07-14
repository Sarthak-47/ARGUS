"""Explicit, logged authorization before Phase 2 (active attack) runs.

SECURITY.md says "only run Argus against systems you own or are explicitly
authorized to test" — until now that was purely an honor-system statement,
nothing in the code actually required it. This makes it a real gate: an
interactive y/N confirmation by default, or an explicit
``--yes-i-am-authorized`` flag for CI/non-interactive use, with every
confirmation appended to a local, persistent audit log (who, what target,
when) — not a config value that gets set once and silently forgotten.

Deliberately does not gate Phase 1 (static analysis never touches the
target) or ``argus demo`` (attacks a bundled local target, not something a
user could plausibly lack authorization for).
"""

from __future__ import annotations

import getpass
import json
import socket
import sys
import time
from pathlib import Path

from argus.config.settings import config_dir


def authorization_log_path() -> Path:
    return config_dir() / "authorizations.jsonl"


def record_authorization(target: str) -> None:
    entry = {
        "target": target,
        "operator": getpass.getuser(),
        "hostname": socket.gethostname(),
        "timestamp": time.time(),
    }
    path = authorization_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def confirm_authorization(target: str, *, assume_yes: bool) -> bool:
    """Whether the operator has confirmed authorization to attack `target`.

    ``assume_yes`` (``--yes-i-am-authorized``) skips the prompt but still
    writes the audit record — it's an explicit assertion, not a bypass of
    the logging. With no flag and no interactive terminal (CI, a piped
    invocation), this refuses rather than silently attacking: the whole
    point is that Phase 2 can no longer run unattended without someone
    having deliberately set the flag.
    """
    if assume_yes:
        record_authorization(target)
        return True
    if not sys.stdin.isatty():
        return False
    prompt = (
        f"\nArgus is about to actively attack {target!r}.\n"
        "Only proceed if you own this system or are explicitly authorized to test it.\n"
        "Type 'yes' to confirm and continue: "
    )
    try:
        answer = input(prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if answer == "yes":
        record_authorization(target)
        return True
    return False
