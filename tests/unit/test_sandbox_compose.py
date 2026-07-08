"""Tests for the docker-compose sandbox path (roadmap v0.5.3) — subprocess
calls are mocked, so these run without a real Docker daemon (unlike
test_sandbox.py's build/run/teardown tests, which need one).
"""

from __future__ import annotations

import subprocess

import pytest

from argus.sandbox.docker_manager import Sandbox, SandboxError


def _compose_repo(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    build: .\n    ports:\n      - \"8000:8000\"\n", encoding="utf-8")
    return tmp_path


def test_start_falls_back_to_compose_when_no_dockerfile(tmp_path, monkeypatch):
    _compose_repo(tmp_path)
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("argus.sandbox.docker_manager._wait_until_reachable", lambda url, timeout: True)

    sandbox = Sandbox(tmp_path)
    base_url = sandbox.start(timeout=5)

    assert base_url == "http://127.0.0.1:8000"
    # First call checks `docker compose version`, second is `up -d --build`.
    assert any(c[:3] == ["docker", "compose", "version"] for c in calls)
    up_calls = [c for c in calls if "up" in c]
    assert up_calls and up_calls[0][:2] == ["docker", "compose"]
    assert "-f" in up_calls[0] and str(tmp_path / "docker-compose.yml") in up_calls[0]
    assert "--build" in up_calls[0]


def test_start_compose_fails_when_plugin_unavailable(tmp_path, monkeypatch):
    _compose_repo(tmp_path)
    monkeypatch.setattr(subprocess, "run",
                        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, stdout="", stderr="not found"))

    sandbox = Sandbox(tmp_path)
    with pytest.raises(SandboxError, match="compose' plugin isn't available"):
        sandbox.start(timeout=5)


def test_start_compose_raises_on_up_failure(tmp_path, monkeypatch):
    _compose_repo(tmp_path)

    def fake_run(cmd, **kwargs):
        if "version" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="Docker Compose v2", stderr="")
        raise subprocess.CalledProcessError(1, cmd, output="", stderr="build failed: bad Dockerfile")

    monkeypatch.setattr(subprocess, "run", fake_run)

    sandbox = Sandbox(tmp_path)
    with pytest.raises(SandboxError, match="docker compose up failed"):
        sandbox.start(timeout=5)


def test_start_compose_raises_when_never_reachable(tmp_path, monkeypatch):
    _compose_repo(tmp_path)
    monkeypatch.setattr(subprocess, "run",
                        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, stdout="", stderr=""))
    monkeypatch.setattr("argus.sandbox.docker_manager._wait_until_reachable", lambda url, timeout: False)

    sandbox = Sandbox(tmp_path)
    with pytest.raises(SandboxError, match="never became reachable"):
        sandbox.start(timeout=5)


def test_stop_tears_down_compose_stack(tmp_path, monkeypatch):
    _compose_repo(tmp_path)
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("argus.sandbox.docker_manager._wait_until_reachable", lambda url, timeout: True)

    sandbox = Sandbox(tmp_path)
    sandbox.start(timeout=5)
    calls.clear()
    sandbox.stop()

    down_calls = [c for c in calls if "down" in c]
    assert down_calls, "stop() must run `docker compose down` when a compose stack was started"
    assert "-v" in down_calls[0]


def test_no_dockerfile_no_compose_raises_friendly_error(tmp_path):
    (tmp_path / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
    sandbox = Sandbox(tmp_path)
    with pytest.raises(SandboxError, match="Couldn't determine how to run"):
        sandbox.start()


def test_single_dockerfile_path_preferred_over_compose(tmp_path, monkeypatch):
    # When both a plain Dockerfile and a compose file exist, the simpler
    # single-container path wins (no subprocess/compose calls at all) --
    # verified by making any subprocess.run call fail the test.
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\nEXPOSE 8080\n", encoding="utf-8")
    _compose_repo(tmp_path)

    def fail_run(cmd, **kwargs):
        raise AssertionError(f"compose path must not run for a repo with its own Dockerfile: {cmd}")

    monkeypatch.setattr(subprocess, "run", fail_run)

    try:
        import docker  # noqa: F401
    except ImportError:
        pytest.skip("docker python package not installed")

    # docker.from_env() will fail fast if no daemon is reachable -- that's fine,
    # the assertion above is what proves compose was never attempted.
    sandbox = Sandbox(tmp_path)
    with pytest.raises(SandboxError):
        sandbox.start(timeout=2)
