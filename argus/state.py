"""Persist the most recent ScanResult so ``argus report`` can export it later,
plus a lightweight append-only history of every scan for trend/comparison views.

The full result is stored as JSON under the config dir (``~/.argus/last_scan.json``).
Before each new save, the previous full result is preserved as
``~/.argus/previous_scan.json`` — one prior snapshot, enough for `argus compare`
to show what's new/fixed since the last run without an unbounded archive.
History is a separate, much smaller JSON-Lines file (``~/.argus/scan_history.jsonl``)
— one line per scan with just enough to plot a trend (timestamp, target, phase,
risk score/band, severity counts), capped at a bounded number of entries so it
never grows without limit on a machine that scans the same repo daily for years.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from argus.config.settings import config_dir
from argus.models import CodebaseMap, Finding, ScanResult, Severity

_HISTORY_LIMIT = 200


def last_scan_path() -> Path:
    return config_dir() / "last_scan.json"


def previous_scan_path() -> Path:
    return config_dir() / "previous_scan.json"


def history_path() -> Path:
    return config_dir() / "scan_history.jsonl"


def _history_entry(result: ScanResult) -> dict:
    return {
        "target": result.target,
        "phase": result.phase,
        "finished_at": result.finished_at,
        "risk_score": result.risk_score,
        "risk_band": result.risk_band,
        "counts": result.counts(),
    }


def append_history(result: ScanResult) -> None:
    """Append one line for this scan, trimming to the most recent entries.

    Best-effort: a history write failing must never break the scan it's
    recording — this is a nice-to-have trend view, not the source of truth
    (``last_scan.json`` is).
    """
    try:
        path = history_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        if path.exists():
            lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        lines.append(json.dumps(_history_entry(result)))
        lines = lines[-_HISTORY_LIMIT:]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError:
        pass


def load_history(target: str | None = None, limit: int = 50) -> list[dict]:
    """Return up to ``limit`` most recent history entries, oldest first.

    Filters to ``target`` (exact match) when given, otherwise returns every
    target's history interleaved by recency.
    """
    path = history_path()
    if not path.exists():
        return []
    entries: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if target is not None and entry.get("target") != target:
            continue
        entries.append(entry)
    return entries[-limit:]


def save_result(result: ScanResult) -> Path:
    path = last_scan_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        try:
            shutil.copyfile(path, previous_scan_path())
        except OSError:
            pass  # best-effort — `argus compare` degrades to "no prior scan", not a crash
    path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    append_history(result)
    return path


def _deserialize(data: dict) -> ScanResult:
    result = ScanResult(target=data.get("target", "unknown"), phase=data.get("phase", "scan"))
    result.started_at = data.get("started_at", result.started_at)
    result.finished_at = data.get("finished_at")
    result.llm_provider = data.get("llm_provider")
    result.errors = data.get("errors", [])

    cm = data.get("codebase_map")
    if cm:
        result.codebase_map = CodebaseMap(
            root=cm.get("root", ""),
            languages=cm.get("languages", {}),
            frameworks=cm.get("frameworks", []),
            entry_points=cm.get("entry_points", []),
            auth_files=cm.get("auth_files", []),
            db_files=cm.get("db_files", []),
            config_files=cm.get("config_files", []),
            dependency_manifests=cm.get("dependency_manifests", []),
            external_calls=cm.get("external_calls", []),
            high_risk_files=cm.get("high_risk_files", []),
            file_count=cm.get("file_count", 0),
            total_loc=cm.get("total_loc", 0),
        )

    for fd in data.get("findings", []):
        f = Finding(
            title=fd.get("title", "Finding"),
            severity=Severity.coerce(fd.get("severity", "INFO")),
            category=fd.get("category", "misc"),
            detector=fd.get("detector", "argus"),
            description=fd.get("description", ""),
            file=fd.get("file"),
            line=fd.get("line"),
            endpoint=fd.get("endpoint"),
            evidence=fd.get("evidence", ""),
            exploit=fd.get("exploit", ""),
            fix=fd.get("fix", ""),
            poc=fd.get("poc", {}),
            cvss=fd.get("cvss"),
            cwe=fd.get("cwe"),
            confidence=fd.get("confidence", "medium"),
            references=fd.get("references", []),
            confirmed=fd.get("confirmed", False),
            metadata=fd.get("metadata", {}),
        )
        result.add(f)
    return result


def _load(path: Path) -> ScanResult | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return _deserialize(data)


def load_result() -> ScanResult | None:
    return _load(last_scan_path())


def load_previous_result() -> ScanResult | None:
    """The scan before the most recent one, for `argus compare`. ``None`` if
    fewer than two scans have run yet."""
    return _load(previous_scan_path())
