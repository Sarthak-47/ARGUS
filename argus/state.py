"""Persist the most recent ScanResult so ``argus report`` can export it later.

Stored as JSON under the config dir (``~/.argus/last_scan.json``). We persist the
serialised dict and rebuild lightweight objects on load — enough for the exporters.
"""

from __future__ import annotations

import json
from pathlib import Path

from argus.config.settings import config_dir
from argus.models import CodebaseMap, Finding, ScanResult, Severity


def last_scan_path() -> Path:
    return config_dir() / "last_scan.json"


def save_result(result: ScanResult) -> Path:
    path = last_scan_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    return path


def load_result() -> ScanResult | None:
    path = last_scan_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

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
            cvss=fd.get("cvss"),
            cwe=fd.get("cwe"),
            confidence=fd.get("confidence", "medium"),
            references=fd.get("references", []),
            confirmed=fd.get("confirmed", False),
        )
        result.add(f)
    return result
