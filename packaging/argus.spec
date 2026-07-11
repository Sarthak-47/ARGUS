# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for the bundled Argus CLI — the fix for the desktop app
depending on a system-installed `argus` reachable on PATH. Produces a single
self-contained executable (dist/argus-cli[.exe]) with no dependency on a
system Python or `pip install argus-panoptes` having been run at all; the
Tauri app ships this binary as a resource and calls it directly.

Only the CLI's *core* dependencies are bundled (typer/rich/httpx/jinja2/
GitPython/PyYAML/etc. — see pyproject.toml's [project.dependencies]) — the
optional extras (sandbox/browser/llm-provider SDKs) stay out to keep this
lean, matching how those are already opt-in for a pip install. A user who
needs them can still point Settings' CLI-path override at a full `pip install
'argus-panoptes[...]'` environment; this bundle covers the common path (scan,
audit against a local target, report, history, status, config) with zero
setup.

Build: `pyinstaller packaging/argus.spec` from the repo root (after `pip
install -e . pyinstaller` in the environment being frozen).
"""

from PyInstaller.utils.hooks import collect_submodules, copy_metadata

import os

REPO_ROOT = os.path.dirname(SPECPATH)  # noqa: F821 — SPECPATH is injected by PyInstaller

hidden = collect_submodules("argus")

datas = [
    (os.path.join(REPO_ROOT, "argus", "report", "templates", "report.html.j2"), "argus/report/templates"),
] + copy_metadata("argus-panoptes")  # so importlib.metadata.version() resolves

a = Analysis(
    [os.path.join(SPECPATH, "argus_entry.py")],  # noqa: F821
    pathex=[REPO_ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter", "test", "unittest",
        # Optional extras (sandbox/browser/most LLM SDKs) are deliberately
        # excluded from the bundled build — see module docstring above.
        "playwright", "docker",
    ],
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="argus-cli",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,   # this IS the CLI — its stdout/output is the whole point
    onefile=True,
)
