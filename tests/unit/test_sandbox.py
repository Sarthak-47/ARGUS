"""Tests for the Docker sandbox lifecycle.

The real build/run/teardown path needs an actual Docker daemon — skipped
cleanly (like test_domxss.py does for playwright) when one isn't available,
so the suite stays green in CI environments without Docker. Verified live
against a real Node app during development; this test locks that behavior in.
"""

from __future__ import annotations

import json

import httpx
import pytest

from argus.sandbox.docker_manager import Sandbox, SandboxError, docker_available

pytestmark = pytest.mark.skipif(not docker_available(), reason="Docker not available")


@pytest.fixture
def node_app(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "sandbox-test", "scripts": {"start": "node server.js"}}),
        encoding="utf-8",
    )
    (tmp_path / "server.js").write_text(
        "const http = require('http');\n"
        "const port = process.env.PORT || 3000;\n"
        "http.createServer((req, res) => {\n"
        "  res.writeHead(200, {'Content-Type': 'text/plain'});\n"
        "  res.end('sandbox test app alive');\n"
        "}).listen(port, '0.0.0.0');\n",
        encoding="utf-8",
    )
    return tmp_path


def test_sandbox_builds_runs_and_tears_down_cleanly(node_app):
    sandbox = Sandbox(node_app)
    try:
        base_url = sandbox.start(timeout=90)
        resp = httpx.get(base_url, timeout=5)
        assert resp.status_code == 200
        assert "alive" in resp.text
    finally:
        sandbox.stop()

    # Nothing should be left running after stop().
    assert sandbox._container is not None  # sanity: start() actually ran
    import docker

    client = docker.from_env()
    assert all(c.id != sandbox._container.id for c in client.containers.list(all=True))


def test_sandbox_raises_friendly_error_for_unrecognized_stack(tmp_path):
    (tmp_path / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
    sandbox = Sandbox(tmp_path)
    with pytest.raises(SandboxError, match="Couldn't determine how to run"):
        sandbox.start()
