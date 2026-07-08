"""SCA reachability analysis (roadmap v0.4.2).

A dependency CVE only matters if the vulnerable package is actually used. A
lockfile pulls in dozens of transitive packages the app never imports; flagging
all of them at full severity is the fastest way to train developers to ignore
the scanner. This does a lightweight, import-level reachability pass: if a
vulnerable package is never imported anywhere in the first-party code, its
finding is downgraded one severity and annotated "likely transitive/unused".

Import-level (not full call-graph) on purpose — it's fast, language-agnostic
enough for Python + JS/TS, and cuts the majority of the noise. Findings for
packages that *are* imported keep their severity and are marked reachable.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from argus.config.defaults import IGNORE_DIRS
from argus.models import Finding, Severity

_PY_IMPORT = re.compile(r"^\s*(?:import|from)\s+([a-zA-Z0-9_\.]+)", re.M)
_JS_IMPORT = re.compile(r"""(?:import\b[^'"]*from\s*|import\s*|require\s*\(\s*)['"]([^'"]+)['"]""")
_SRC_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"}
_MAX_BYTES = 1_500_000

# Distribution name -> import name, for the common cases where they differ.
_ALIASES = {
    "pyyaml": "yaml", "beautifulsoup4": "bs4", "pillow": "pil", "scikit-learn": "sklearn",
    "python-dateutil": "dateutil", "opencv-python": "cv2", "msgpack-python": "msgpack",
    "attrs": "attr", "protobuf": "google", "setuptools": "setuptools", "python-jose": "jose",
    "pyjwt": "jwt", "websocket-client": "websocket", "python-magic": "magic",
}

_DOWNGRADE = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.LOW,
    Severity.INFO: Severity.INFO,
}


def _norm_js_module(spec: str) -> str | None:
    """Top-level package name from a JS import specifier, or None if relative."""
    if spec.startswith((".", "/")):
        return None
    if spec.startswith("@"):
        parts = spec.split("/")
        return "/".join(parts[:2]).lower()
    return spec.split("/")[0].lower()


def build_import_index(root: Path) -> set[str]:
    """The set of top-level module/package names imported anywhere in ``root``."""
    index: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for fn in filenames:
            if Path(fn).suffix.lower() not in _SRC_EXT:
                continue
            full = Path(dirpath) / fn
            try:
                if full.stat().st_size > _MAX_BYTES:
                    continue
                text = full.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for m in _PY_IMPORT.finditer(text):
                index.add(m.group(1).split(".")[0].lower())
            for m in _JS_IMPORT.finditer(text):
                mod = _norm_js_module(m.group(1))
                if mod:
                    index.add(mod)
    return index


def is_reachable(package: str, index: set[str]) -> bool:
    """Whether ``package`` (a distribution name) appears imported in ``index``."""
    p = package.lower()
    candidates = {p, p.replace("-", "_"), p.replace("_", "-")}
    if p in _ALIASES:
        candidates.add(_ALIASES[p])
    if p.startswith("@"):  # scoped npm package — also try the bare name
        candidates.add(p.split("/")[-1])
    return bool(candidates & index)


def annotate_reachability(findings: list[Finding], root: Path) -> list[Finding]:
    """Mutate dependency findings in place with reachability: downgrade + note
    the ones whose package is never imported in first-party code."""
    dep_findings = [f for f in findings if f.category == "dependency" and f.metadata.get("package")]
    if not dep_findings:
        return findings
    index = build_import_index(root)
    for f in dep_findings:
        reachable = is_reachable(str(f.metadata["package"]), index)
        f.metadata["reachable"] = reachable
        if reachable:
            f.description = (f.description or "") + " Reachability: this package is imported in the scanned code."
        else:
            f.severity = _DOWNGRADE.get(f.severity, f.severity)
            f.confidence = "low"
            f.description = ((f.description or "")
                             + " Reachability: this package is not imported in the scanned code — "
                               "likely transitive or unused, so it's downgraded and lower priority.")
    return findings
