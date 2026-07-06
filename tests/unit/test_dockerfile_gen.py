"""Tests for auto-Dockerfile generation — pure logic, no Docker required.

Deliberately narrow: generate_dockerfile only recognizes stacks it can
confidently guess a start command for (Django via manage.py, Node via an
explicit "start" script). Anything else must return None so the caller falls
back to --url instead of silently producing a container that never starts.
"""

from __future__ import annotations

import json

from argus.sandbox.dockerfile_gen import find_existing_dockerfile, generate_dockerfile


def test_django_detected_with_manage_py_and_requirements(tmp_path):
    (tmp_path / "manage.py").write_text("# django\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("django==5.0\n", encoding="utf-8")

    result = generate_dockerfile(tmp_path)

    assert result is not None
    content, port = result
    assert port == 8000
    assert "manage.py" in content
    assert "runserver" in content


def test_django_not_detected_without_requirements_txt(tmp_path):
    (tmp_path / "manage.py").write_text("# django\n", encoding="utf-8")
    assert generate_dockerfile(tmp_path) is None


def test_node_detected_with_start_script(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x", "scripts": {"start": "node server.js"}}), encoding="utf-8",
    )
    result = generate_dockerfile(tmp_path)
    assert result is not None
    content, port = result
    assert port == 3000
    assert "npm" in content and "start" in content


def test_node_not_detected_without_start_script(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x", "scripts": {"build": "webpack"}}), encoding="utf-8",
    )
    assert generate_dockerfile(tmp_path) is None


def test_node_not_detected_with_malformed_package_json(tmp_path):
    (tmp_path / "package.json").write_text("{not valid json", encoding="utf-8")
    assert generate_dockerfile(tmp_path) is None


def test_unrecognized_stack_returns_none(tmp_path):
    (tmp_path / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
    assert generate_dockerfile(tmp_path) is None


def test_existing_dockerfile_is_used_and_port_parsed(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\nEXPOSE 8080\nCMD [\"python\", \"app.py\"]\n", encoding="utf-8",
    )
    result = find_existing_dockerfile(tmp_path)
    assert result == ("Dockerfile", 8080)


def test_existing_dockerfile_without_expose_defaults_to_8080(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\nCMD [\"python\", \"app.py\"]\n", encoding="utf-8")
    result = find_existing_dockerfile(tmp_path)
    assert result == ("Dockerfile", 8080)


def test_no_dockerfile_returns_none(tmp_path):
    assert find_existing_dockerfile(tmp_path) is None
