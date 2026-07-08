"""Tests for container base-image CVE scanning (argus/scanner/image_cve.py)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from argus.models import Severity
from argus.scanner import image_cve


def test_base_images_multistage_and_scratch(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text(
        "FROM node:18 AS build\n"
        "RUN npm ci\n"
        "FROM nginx:alpine\n"
        "COPY --from=build /app /usr/share/nginx/html\n", encoding="utf-8")
    (tmp_path / "Dockerfile.api").write_text("FROM scratch\nCOPY x /\n", encoding="utf-8")
    imgs = image_cve.base_images(tmp_path)
    assert "node:18" in imgs
    assert "nginx:alpine" in imgs
    assert "build" not in imgs        # stage alias, not a base image
    assert "scratch" not in imgs


def test_base_images_digest_pinned(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12@sha256:abcdef\n", encoding="utf-8")
    assert image_cve.base_images(tmp_path) == ["python:3.12@sha256:abcdef"]


def test_no_dockerfile_returns_nothing(tmp_path: Path):
    findings, notes = image_cve.scan_container_images(tmp_path)
    assert findings == []
    assert notes == []


def test_graceful_skip_when_trivy_absent(tmp_path: Path, monkeypatch):
    (tmp_path / "Dockerfile").write_text("FROM node:18\n", encoding="utf-8")
    monkeypatch.setattr(image_cve.shutil, "which", lambda _: None)
    findings, notes = image_cve.scan_container_images(tmp_path)
    assert findings == []
    assert any("trivy not installed" in n for n in notes)


def test_parser_maps_trivy_json(tmp_path: Path, monkeypatch):
    (tmp_path / "Dockerfile").write_text("FROM node:18\n", encoding="utf-8")
    trivy_json = {
        "Results": [{
            "Target": "node:18 (debian 12)",
            "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl",
                 "InstalledVersion": "3.0.11", "FixedVersion": "3.0.13",
                 "Severity": "CRITICAL", "Title": "openssl flaw"},
                {"VulnerabilityID": "CVE-2024-0002", "PkgName": "zlib",
                 "InstalledVersion": "1.2.13", "Severity": "LOW", "Title": "zlib issue"},
            ],
        }],
    }

    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(trivy_json), stderr="")

    monkeypatch.setattr(image_cve.shutil, "which", lambda _: "/usr/bin/trivy")
    monkeypatch.setattr(image_cve.subprocess, "run", fake_run)

    findings, notes = image_cve.scan_container_images(tmp_path)
    by_pkg = {f.metadata["package"]: f for f in findings}
    assert set(by_pkg) == {"openssl", "zlib"}
    assert by_pkg["openssl"].severity is Severity.CRITICAL
    assert by_pkg["zlib"].severity is Severity.LOW
    assert by_pkg["openssl"].detector == "trivy-image"
    assert by_pkg["openssl"].metadata["image"] == "node:18"
    assert by_pkg["openssl"].metadata["reachable"] is True   # base-image CVEs are reachable
    assert "3.0.13" in by_pkg["openssl"].fix
