# Bundled Argus CLI

The desktop app ships a self-contained, PyInstaller-frozen build of the
`argus` CLI as a resource inside the installer (see
`gui/src-tauri/tauri.{windows,macos,linux}.conf.json`'s `bundle.resources`),
so the packaged app works with zero setup — no system Python, no
`pip install argus-panoptes`, no PATH configuration. This is the fix for the
app depending on `argus` being separately installed and reachable on PATH,
which a GUI launched from the Dock/Start menu often can't see anyway.

## Building it

```bash
pip install -e . pyinstaller   # from the repo root, in the environment to freeze
pyinstaller packaging/argus.spec --distpath dist
# -> dist/argus-cli(.exe)
```

Then copy the result into the Tauri resource path CI expects:

```bash
mkdir -p gui/src-tauri/binaries/argus-cli
cp dist/argus-cli(.exe) gui/src-tauri/binaries/argus-cli/
```

`.github/workflows/desktop-release.yml` does exactly this, on each platform,
right before the Tauri build step.

## What's bundled vs. not

Only the CLI's *core* dependencies (typer, rich, httpx, jinja2, GitPython,
PyYAML, etc. — see `pyproject.toml`'s `[project.dependencies]`) are frozen in.
The optional extras — `[sandbox]` (Docker), `[browser]` (Playwright/DomXSS) —
are excluded to keep the bundle lean, matching how they're already opt-in for
a `pip install`. This bundle covers the GUI's core flows: scan, audit against
a local target, report, history, status, config, suppress.

A user who needs an excluded extra can still install `argus-panoptes` with
that extra into their own Python environment and point Settings' "Argus CLI"
path field at it — the manual override always takes priority over the bundle.

## Known limitation

The macOS build currently freezes for whatever architecture the CI runner
is (arm64, since `macos-latest` GitHub runners are Apple Silicon) — unlike
the Tauri *app* itself, which is built as a universal binary
(`--target universal-apple-darwin`). An Intel Mac would need Rosetta to run
the bundled `argus-cli`. Building a true `universal2` PyInstaller binary is a
known-solvable but separate problem (freeze on both arches, `lipo` them
together) not yet done here.
