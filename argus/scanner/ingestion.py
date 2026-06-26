"""Repo ingestion: obtain the code and build a structural CodebaseMap.

Accepts a local path or a git URL. Git URLs are shallow-cloned into a temp dir.
Then we walk the tree once, classifying files by language, spotting dependency
manifests, config files, and security-relevant (auth/db/admin/payment/upload)
sources so later stages know where to look.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from argus.config.defaults import (
    ADMIN_HINTS,
    AUTH_HINTS,
    CONFIG_FILES,
    DB_HINTS,
    DEPENDENCY_MANIFESTS,
    IGNORE_DIRS,
    LANGUAGE_BY_EXT,
    PAYMENT_HINTS,
    UPLOAD_HINTS,
)
from argus.models import CodebaseMap

# Skip files larger than this when counting LOC / reading (bytes).
MAX_READ_BYTES = 2_000_000


@dataclass
class Ingested:
    """The materialised repo plus its map and whether we must clean it up."""

    root: Path
    map: CodebaseMap
    cleanup: bool = False
    is_remote: bool = False


def _looks_like_url(target: str) -> bool:
    return target.startswith(("http://", "https://", "git@", "ssh://")) or target.endswith(".git")


def _clone(url: str) -> Path:
    """Shallow-clone a git URL into a temp directory."""
    from git import Repo  # imported here so a missing git binary fails lazily

    tmp = Path(tempfile.mkdtemp(prefix="argus-"))
    Repo.clone_from(url, tmp, multi_options=["--depth", "1"])
    return tmp


def _classify_path(rel: str, name_lc: str, cmap: CodebaseMap) -> None:
    """Tag a file into high-level buckets based on its path."""
    if any(h in rel for h in AUTH_HINTS):
        cmap.auth_files.append(rel)
        cmap.high_risk_files.append(rel)
    if any(h in rel for h in DB_HINTS):
        cmap.db_files.append(rel)
    if any(h in rel for h in ADMIN_HINTS) or any(h in rel for h in PAYMENT_HINTS):
        cmap.high_risk_files.append(rel)
    if any(h in rel for h in UPLOAD_HINTS):
        cmap.high_risk_files.append(rel)
    if name_lc in CONFIG_FILES or name_lc.startswith(".env"):
        cmap.config_files.append(rel)


def _detect_frameworks(root: Path, cmap: CodebaseMap) -> None:
    """Light framework fingerprinting from manifest contents."""
    fw: set[str] = set()
    pkg = root / "package.json"
    if pkg.exists():
        try:
            text = pkg.read_text(encoding="utf-8", errors="ignore").lower()
            for marker, label in (
                ("\"react\"", "React"), ("\"next\"", "Next.js"), ("\"vue\"", "Vue"),
                ("\"express\"", "Express"), ("\"@nestjs", "NestJS"), ("\"svelte\"", "Svelte"),
                ("\"fastify\"", "Fastify"), ("\"koa\"", "Koa"), ("\"@angular", "Angular"),
            ):
                if marker in text:
                    fw.add(label)
        except OSError:
            pass
    req = root / "requirements.txt"
    pyproj = root / "pyproject.toml"
    py_text = ""
    for p in (req, pyproj):
        if p.exists():
            py_text += p.read_text(encoding="utf-8", errors="ignore").lower()
    for marker, label in (
        ("django", "Django"), ("flask", "Flask"), ("fastapi", "FastAPI"),
        ("tornado", "Tornado"), ("aiohttp", "aiohttp"),
    ):
        if marker in py_text:
            fw.add(label)
    if (root / "go.mod").exists():
        gt = (root / "go.mod").read_text(encoding="utf-8", errors="ignore").lower()
        if "gin-gonic" in gt:
            fw.add("Gin")
        if "fiber" in gt:
            fw.add("Fiber")
    cmap.frameworks = sorted(fw)


def build_map(root: Path) -> CodebaseMap:
    """Walk the tree once and produce a CodebaseMap."""
    cmap = CodebaseMap(root=str(root))
    for dirpath, dirnames, filenames in os.walk(root):
        # prune ignored dirs in-place for speed
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS and not d.startswith(".git")]
        for fn in filenames:
            full = Path(dirpath) / fn
            rel = str(full.relative_to(root)).replace("\\", "/")
            rel_lc = rel.lower()
            name_lc = fn.lower()
            ext = full.suffix.lower()

            if name_lc in DEPENDENCY_MANIFESTS:
                cmap.dependency_manifests.append(rel)

            lang = LANGUAGE_BY_EXT.get(ext)
            if lang:
                cmap.languages[lang] = cmap.languages.get(lang, 0) + 1
                cmap.file_count += 1
                try:
                    if full.stat().st_size <= MAX_READ_BYTES:
                        with full.open("r", encoding="utf-8", errors="ignore") as fh:
                            cmap.total_loc += sum(1 for _ in fh)
                except OSError:
                    pass

            _classify_path(rel_lc, name_lc, cmap)

    # de-dupe while preserving order
    for attr in ("auth_files", "db_files", "config_files", "high_risk_files"):
        seen: set[str] = set()
        deduped = []
        for item in getattr(cmap, attr):
            if item not in seen:
                seen.add(item)
                deduped.append(item)
        setattr(cmap, attr, deduped)

    _detect_frameworks(root, cmap)
    return cmap


def ingest(target: str) -> Ingested:
    """Resolve ``target`` to a local tree and build its map."""
    if _looks_like_url(target):
        root = _clone(target)
        cmap = build_map(root)
        return Ingested(root=root, map=cmap, cleanup=True, is_remote=True)

    path = Path(target).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Target path does not exist: {path}")
    if path.is_file():
        path = path.parent
    cmap = build_map(path)
    return Ingested(root=path, map=cmap, cleanup=False, is_remote=False)
