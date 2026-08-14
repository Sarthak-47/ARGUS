# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for the bundled Argus CLI — the fix for the desktop app
depending on a system-installed `argus` reachable on PATH. Produces a single
self-contained executable (dist/argus-cli[.exe]) with no dependency on a
system Python or `pip install argus-panoptes` having been run at all; the
Tauri app ships this binary as a resource and calls it directly.

The CLI's core dependencies are bundled (typer/rich/httpx/jinja2/GitPython/
PyYAML/etc. — see pyproject.toml's [project.dependencies]), plus the `sandbox`
extra (`docker>=7.0` — a pure-Python client for a locally-running Docker
daemon, not the Docker Engine itself) so "Strike the app" against a bare repo
path works out of the box in the desktop app, same as attacking a URL
directly. The remaining extras (browser/most LLM SDKs) stay out to keep this
lean — they pull in much heavier native dependencies (Playwright's browser
binaries, torch-class SDKs) for features most sessions don't touch. A user
who needs those can still point Settings' CLI-path override at a full `pip
install 'argus-panoptes[...]'` environment.

Build: `pyinstaller packaging/argus.spec` from the repo root (after `pip
install -e ".[sandbox]" pyinstaller` in the environment being frozen).
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
        # Heavier optional extras stay excluded from the bundled build — see
        # module docstring above. `docker` (sandbox) is deliberately NOT
        # excluded here; it ships.
        "playwright",
    ],
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,   # onedir mode — see COLLECT below
    name="argus-cli",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,   # this IS the CLI — its stdout/output is the whole point
)

# onedir, not onefile: a onefile build self-extracts its entire payload to a
# temp directory on *every single launch* — measured at ~1.1s of pure
# unpacking overhead per invocation on this machine, vs ~250ms for a normal
# install. Since the desktop app invokes this CLI many times per session
# (status/history checks on nearly every screen navigation, plus scan/report
# per action), that overhead compounded into exactly the "app lags whenever I
# click something" symptom. onedir unpacks once at build time — startup is
# just process-spawn overhead, no unpacking, regardless of invocation count.
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="argus-cli",
)
