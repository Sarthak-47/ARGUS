"""Finding lifecycle: Open (default) / Reviewing / Ignored, persisted per target.

An ignored finding is a known false positive or an accepted risk — it
shouldn't keep resurfacing as "new" on every subsequent scan and shouldn't
count toward the risk score. Keyed by the same signature used for
scan-to-scan comparison (:func:`argus.compare.finding_signature`) so
suppression survives line-number shifts from unrelated edits, same as
fix-and-reverify and `argus compare`.

Stored as a flat JSON file (``~/.argus/suppressions.json``), one entry per
(target, signature) pair — deliberately not scoped to a single scan run, so
marking something ignored sticks across every future scan of that target.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from argus.compare import finding_signature
from argus.config.settings import config_dir
from argus.models import Finding

_VALID_STATUSES = ("open", "reviewing", "ignored")


def suppressions_path() -> Path:
    return config_dir() / "suppressions.json"


def _load() -> dict:
    path = suppressions_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save(data: dict) -> None:
    path = suppressions_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write to a sibling temp file and atomically replace — a plain
    # write_text() truncates the file before writing the new content, so a
    # second `argus` process reading concurrently (e.g. a suppress command
    # racing a scan finishing) could see a half-written or empty file.
    # os.replace() is atomic on both POSIX and Windows.
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _key(sig: tuple) -> str:
    return "||".join(str(part) for part in sig)


def set_status(target: str, finding: Finding, status: str, reason: str = "") -> None:
    if status not in _VALID_STATUSES:
        raise ValueError(f"status must be one of {_VALID_STATUSES}, got {status!r}")
    data = _load()
    bucket = data.setdefault(target, {})
    key = _key(finding_signature(finding))
    if status == "open":
        bucket.pop(key, None)  # "open" is the default — no entry needed
    else:
        bucket[key] = {
            "status": status, "reason": reason, "title": finding.title,
            "location": finding.file or finding.endpoint or "", "updated_at": time.time(),
        }
    if not bucket:
        data.pop(target, None)
    _save(data)


def list_for(target: str) -> list[dict]:
    return list(_load().get(target, {}).values())


def clear_by_title(target: str, search: str) -> list[dict]:
    """Remove suppression entries whose title contains ``search`` (case-
    insensitive). Returns the removed entries.

    A suppressed finding is filtered out of every scan's visible results by
    design — searching *visible findings* for something to un-suppress would
    never find it. This searches the suppression records themselves instead.
    """
    data = _load()
    bucket = data.get(target, {})
    matching_keys = [k for k, e in bucket.items() if search.lower() in e.get("title", "").lower()]
    removed = [bucket[k] for k in matching_keys]
    for k in matching_keys:
        del bucket[k]
    if not bucket:
        data.pop(target, None)
    _save(data)
    return removed


def apply_suppressions(target: str, findings: list[Finding]) -> tuple[list[Finding], int]:
    """Split findings into (visible, suppressed_count) for a target.

    "Ignored" findings are removed from the visible list entirely (they
    don't count toward risk score or clutter the findings table). "Reviewing"
    findings stay visible but get a metadata tag so a report/GUI can show
    their status.
    """
    bucket = _load().get(target, {})
    if not bucket:
        return findings, 0

    visible: list[Finding] = []
    suppressed = 0
    for f in findings:
        entry = bucket.get(_key(finding_signature(f)))
        if entry is None:
            visible.append(f)
            continue
        if entry["status"] == "ignored":
            suppressed += 1
            continue
        f.metadata["lifecycle_status"] = entry["status"]
        visible.append(f)
    return visible, suppressed
