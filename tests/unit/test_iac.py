"""Tests for Dockerfile / compose IaC misconfiguration scanning."""

from __future__ import annotations

from argus.scanner.iac import scan_iac


def _detectors(tmp_path, filename, content):
    (tmp_path / filename).write_text(content, encoding="utf-8")
    fs, _ = scan_iac(tmp_path)
    return {f.detector for f in fs}


def test_vulnerable_dockerfile_flags_all(tmp_path):
    dets = _detectors(tmp_path, "Dockerfile",
        "FROM python:latest\n"
        "ADD https://example.com/x.sh /tmp/\n"
        "RUN curl https://get.example.com | bash\n"
        "COPY . /app\n")
    assert "iac:dockerfile-unpinned-base" in dets
    assert "iac:dockerfile-runs-as-root" in dets
    assert "iac:dockerfile-add-url" in dets
    assert "iac:dockerfile-curl-pipe-sh" in dets


def test_hardened_dockerfile_is_clean(tmp_path):
    dets = _detectors(tmp_path, "Dockerfile",
        "FROM python:3.12-slim\n"
        "COPY . /app\n"
        "RUN pip install -r requirements.txt\n"
        "USER appuser\n")
    assert dets == set()


def test_digest_pinned_base_is_not_flagged_unpinned(tmp_path):
    dets = _detectors(tmp_path, "Dockerfile",
        "FROM python:3.12-slim@sha256:" + "a" * 64 + "\n"
        "USER app\n")
    assert "iac:dockerfile-unpinned-base" not in dets


def test_dockerfile_with_nonroot_user_not_flagged_as_root(tmp_path):
    dets = _detectors(tmp_path, "Dockerfile", "FROM alpine:3.19\nUSER 1001\n")
    assert "iac:dockerfile-runs-as-root" not in dets


def test_dockerfile_variant_filename_is_scanned(tmp_path):
    dets = _detectors(tmp_path, "Dockerfile.prod", "FROM node:latest\nUSER node\n")
    assert "iac:dockerfile-unpinned-base" in dets


def test_compose_privileged_and_host_network_flagged(tmp_path):
    dets = _detectors(tmp_path, "docker-compose.yml",
        "services:\n  web:\n    image: myapp:1.2.3\n    privileged: true\n    network_mode: \"host\"\n")
    assert "iac:compose-privileged" in dets
    assert "iac:compose-host-network" in dets


def test_safe_compose_is_clean(tmp_path):
    dets = _detectors(tmp_path, "docker-compose.yml",
        "services:\n  web:\n    image: myapp:1.2.3\n    ports:\n      - '8080:8080'\n")
    assert dets == set()
