"""Shared pytest fixtures.

Crucially, every test runs against an isolated config directory so the suite never
touches the developer's real ``~/.argus``. We point both ARGUS_CONFIG_DIR and
ARGUS_CONFIG at a per-test temp path; settings/state read these at call time.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    cfg_dir = tmp_path / "argus-home"
    cfg_dir.mkdir()
    monkeypatch.setenv("ARGUS_CONFIG_DIR", str(cfg_dir))
    monkeypatch.setenv("ARGUS_CONFIG", str(cfg_dir / "config.toml"))
    yield cfg_dir


@pytest.fixture
def vuln_repo(tmp_path) -> Path:
    """A tiny repo with a representative spread of vulnerabilities."""
    repo = tmp_path / "vuln"
    repo.mkdir()
    # Build the fake credentials by concatenation so the literal patterns never
    # appear in committed source (GitHub push protection would otherwise flag
    # them); the full keys only exist in the temp file the detector scans.
    aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
    stripe_key = "sk_" + "live_4eC39HqLyjWDarjtT1zdp7dcABCDEFGH"
    (repo / "app.py").write_text(
        "import os, hashlib, sqlite3, yaml\n"
        f"AWS_KEY = '{aws_key}'\n"
        f"stripe = '{stripe_key}'\n"
        "DEBUG = True\n"
        "def q(name):\n"
        "    c = sqlite3.connect('d'); cur = c.cursor()\n"
        "    cur.execute('SELECT * FROM u WHERE n = ' + name)\n"
        "def run(host):\n"
        "    os.system('ping ' + host)\n"
        "def weak(p):\n"
        "    return hashlib.md5(p.encode()).hexdigest()\n"
        "def load(d):\n"
        "    return yaml.load(d)\n",
        encoding="utf-8",
    )
    (repo / "requirements.txt").write_text("flask==2.0.1\npyyaml==5.3\n", encoding="utf-8")
    (repo / "package.json").write_text('{"name":"x","dependencies":{"react":"18.0.0"}}\n', encoding="utf-8")
    return repo
