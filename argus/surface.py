"""Persistent attack-surface inventory — remember discovered endpoints per target.

Each ``argus attack`` run today starts from zero surface knowledge: ReconBot
crawls, and whatever it happens to find this run is all the later agents get.
A flaky target, a slow crawl, or an endpoint only reachable after a prior
action means real surface gets missed intermittently. Persisting the union of
everything ever discovered for a target — and seeding the next run with it —
makes the surface monotonically grow instead of resetting each time.

Stored one JSON file per target under ``~/.argus/surface/`` (filename is a hash
of the target key, so URLs/paths with slashes are safe as filenames). Scoped
down from CloudSEK's continuous org-wide/dark-web monitoring to exactly what a
single-target CLI can own: this one target's endpoint list.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from argus.agents.base import Endpoint
from argus.config.settings import config_dir

_SURFACE_LIMIT = 2000  # endpoints per target — a sane cap against unbounded growth


def surface_dir() -> Path:
    return config_dir() / "surface"


def surface_path(target: str) -> Path:
    digest = hashlib.sha256(target.encode("utf-8")).hexdigest()[:16]
    return surface_dir() / f"{digest}.json"


def _endpoint_to_dict(ep: Endpoint) -> dict:
    return {
        "url": ep.url, "method": ep.method, "params": ep.params,
        "content_type": ep.content_type, "source": ep.source,
        "sample_status": ep.sample_status,
    }


def _endpoint_from_dict(d: dict) -> Endpoint:
    return Endpoint(
        url=d.get("url", ""), method=d.get("method", "GET"),
        params=list(d.get("params", [])), content_type=d.get("content_type"),
        source=d.get("source", "crawl"), sample_status=d.get("sample_status"),
    )


def load_surface(target: str) -> list[Endpoint]:
    path = surface_path(target)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    endpoints = data.get("endpoints", []) if isinstance(data, dict) else []
    return [_endpoint_from_dict(d) for d in endpoints if isinstance(d, dict)]


def save_surface(target: str, endpoints: list[Endpoint]) -> None:
    """Persist the union of the previously-known surface and this run's, keyed
    on ``(method, url)``. Best-effort — surface memory is an optimisation, never
    a reason to fail an attack."""
    try:
        merged: dict[str, Endpoint] = {ep.key(): ep for ep in load_surface(target)}
        for ep in endpoints:
            existing = merged.get(ep.key())
            if existing is None:
                merged[ep.key()] = ep
            else:
                for p in ep.params:
                    if p not in existing.params:
                        existing.params.append(p)
                if ep.sample_status is not None:
                    existing.sample_status = ep.sample_status

        ordered = list(merged.values())[:_SURFACE_LIMIT]
        path = surface_path(target)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Write-then-rename instead of a direct write_text(): the same target
        # can be scanned concurrently (e.g. CI running two jobs against the
        # same app), and a plain write truncates the file before the new
        # content lands, so a concurrent load_surface() could read a
        # half-written/empty file. os.replace() is atomic on POSIX and Windows.
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(
            json.dumps({"target": target, "endpoints": [_endpoint_to_dict(e) for e in ordered]}, indent=2),
            encoding="utf-8",
        )
        os.replace(tmp, path)
    except OSError:
        pass
