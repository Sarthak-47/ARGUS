"""Tests for auto-Dockerfile generation — pure logic, no Docker required.

Deliberately narrow: generate_dockerfile only recognizes stacks it can
confidently guess a start command for (Django via manage.py, Flask/FastAPI via
their own app-instantiation pattern, Rails via Gemfile+config.ru, Node via an
explicit "start"/dev-server script). Anything else must return None so the
caller falls back to --url instead of silently producing a container that
never starts.
"""

from __future__ import annotations

import json

from argus.sandbox.dockerfile_gen import (
    compose_target,
    find_compose_file,
    find_existing_dockerfile,
    generate_dockerfile,
)


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


# ----- Flask -----

def test_flask_detected_with_app_instantiation(tmp_path):
    (tmp_path / "requirements.txt").write_text("Flask==3.0\n", encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n", encoding="utf-8")
    result = generate_dockerfile(tmp_path)
    assert result is not None
    content, port = result
    assert port == 5000
    assert "FLASK_APP=app" in content
    assert "flask" in content and "run" in content


def test_flask_not_detected_without_flask_in_requirements(tmp_path):
    (tmp_path / "requirements.txt").write_text("django==5.0\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n", encoding="utf-8")
    assert generate_dockerfile(tmp_path) is None


def test_flask_not_detected_without_app_instantiation(tmp_path):
    (tmp_path / "requirements.txt").write_text("Flask==3.0\n", encoding="utf-8")
    (tmp_path / "utils.py").write_text("def helper():\n    pass\n", encoding="utf-8")
    assert generate_dockerfile(tmp_path) is None


def test_flask_skips_test_directories(tmp_path):
    (tmp_path / "requirements.txt").write_text("Flask==3.0\n", encoding="utf-8")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "fixture.py").write_text("from flask import Flask\napp = Flask(__name__)\n", encoding="utf-8")
    assert generate_dockerfile(tmp_path) is None


# ----- FastAPI -----

def test_fastapi_detected_with_app_var(tmp_path):
    (tmp_path / "requirements.txt").write_text("fastapi==0.110\nuvicorn==0.29\n", encoding="utf-8")
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\napi = FastAPI()\n", encoding="utf-8")
    result = generate_dockerfile(tmp_path)
    assert result is not None
    content, port = result
    assert port == 8000
    assert "main:api" in content
    assert "uvicorn" in content


def test_fastapi_defaults_app_var_when_no_assignment_found(tmp_path):
    # FastAPI() is instantiated but never assigned to a name Argus can find
    # (e.g. passed straight into another call) -- falls back to "app".
    (tmp_path / "requirements.txt").write_text("fastapi\nuvicorn\n", encoding="utf-8")
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\nregister(FastAPI())\n", encoding="utf-8")
    result = generate_dockerfile(tmp_path)
    assert result is not None
    assert "main:app" in result[0]


def test_fastapi_not_detected_without_uvicorn(tmp_path):
    (tmp_path / "requirements.txt").write_text("fastapi==0.110\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    assert generate_dockerfile(tmp_path) is None


# ----- Rails -----

def test_rails_detected_with_gemfile_and_config_ru(tmp_path):
    (tmp_path / "Gemfile").write_text("source 'https://rubygems.org'\ngem 'rails', '7.1'\n", encoding="utf-8")
    (tmp_path / "config.ru").write_text("run Rails.application\n", encoding="utf-8")
    result = generate_dockerfile(tmp_path)
    assert result is not None
    content, port = result
    assert port == 3000
    assert "rails" in content and "server" in content


def test_rails_not_detected_without_config_ru(tmp_path):
    (tmp_path / "Gemfile").write_text("gem 'rails'\n", encoding="utf-8")
    assert generate_dockerfile(tmp_path) is None


def test_rails_not_detected_when_gemfile_lacks_rails_gem(tmp_path):
    (tmp_path / "Gemfile").write_text("gem 'sinatra'\n", encoding="utf-8")
    (tmp_path / "config.ru").write_text("run App\n", encoding="utf-8")
    assert generate_dockerfile(tmp_path) is None


# ----- Node: build+start and dev-server fallback -----

def test_node_start_with_build_script_builds_first(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"build": "next build", "start": "next start"}}), encoding="utf-8")
    content, port = generate_dockerfile(tmp_path)
    assert port == 3000
    assert "RUN npm run build" in content
    assert "npm start" in content


def test_node_dev_server_fallback_for_vite(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"dev": "vite"}, "devDependencies": {"vite": "^5.0.0"}}),
        encoding="utf-8")
    content, port = generate_dockerfile(tmp_path)
    assert port == 3000
    assert "vite --host" in content


def test_node_no_dev_server_and_no_start_returns_none(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"test": "jest"}, "dependencies": {"lodash": "^4.0.0"}}), encoding="utf-8")
    assert generate_dockerfile(tmp_path) is None


# ----- docker-compose detection -----

def test_compose_file_found_by_standard_names(tmp_path):
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    assert find_compose_file(tmp_path) == tmp_path / "docker-compose.yml"


def test_compose_target_extracts_published_port_string_form(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    build: .\n    ports:\n      - \"8000:8000\"\n", encoding="utf-8")
    result = compose_target(tmp_path)
    assert result is not None
    _, port = result
    assert port == 8000


def test_compose_target_extracts_published_port_dict_form(tmp_path):
    (tmp_path / "compose.yaml").write_text(
        "services:\n  api:\n    build: .\n    ports:\n      - published: 9090\n        target: 8080\n",
        encoding="utf-8")
    result = compose_target(tmp_path)
    assert result is not None
    _, port = result
    assert port == 9090


def test_compose_target_none_when_no_published_port(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  worker:\n    build: .\n", encoding="utf-8")
    assert compose_target(tmp_path) is None


def test_compose_target_none_when_port_is_container_only(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  internal:\n    build: .\n    ports:\n      - \"8080\"\n", encoding="utf-8")
    assert compose_target(tmp_path) is None


def test_compose_target_none_without_compose_file(tmp_path):
    assert compose_target(tmp_path) is None


def test_compose_target_bind_ip_form(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    build: .\n    ports:\n      - \"127.0.0.1:8000:8000\"\n", encoding="utf-8")
    result = compose_target(tmp_path)
    assert result is not None
    assert result[1] == 8000


def test_static_site_detected_with_index_html_at_root(tmp_path):
    # A plain static site — the common shape of a repo with no Dockerfile and
    # no backend at all, which used to fall straight through to None (no
    # Phase 2 possible even with Docker running).
    (tmp_path / "index.html").write_text("<h1>hi</h1>", encoding="utf-8")
    result = generate_dockerfile(tmp_path)
    assert result is not None
    content, port = result
    assert port == 80
    assert "nginx" in content


def test_static_site_detected_in_public_subdir(tmp_path):
    (tmp_path / "public").mkdir()
    (tmp_path / "public" / "index.html").write_text("<h1>hi</h1>", encoding="utf-8")
    result = generate_dockerfile(tmp_path)
    assert result is not None
    content, port = result
    assert port == 80
    assert "COPY public " in content


def test_static_site_not_detected_without_index_html(tmp_path):
    (tmp_path / "README.md").write_text("hi", encoding="utf-8")
    assert generate_dockerfile(tmp_path) is None


def test_backend_framework_takes_priority_over_static_fallback(tmp_path):
    # A repo can ship both a real backend AND a static index.html (e.g. an
    # SPA's built assets) — the narrower, earlier probe must win so a real
    # dynamic app is never mistaken for "just a static site".
    (tmp_path / "manage.py").write_text("# django\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("django==5.0\n", encoding="utf-8")
    (tmp_path / "index.html").write_text("<h1>hi</h1>", encoding="utf-8")
    content, port = generate_dockerfile(tmp_path)
    assert port == 8000
    assert "manage.py" in content


def test_php_detected_with_index_php(tmp_path):
    (tmp_path / "index.php").write_text("<?php echo 1; ?>", encoding="utf-8")
    result = generate_dockerfile(tmp_path)
    assert result is not None
    content, port = result
    assert port == 8000
    assert "php" in content.lower()


def test_php_not_detected_without_index_php(tmp_path):
    (tmp_path / "README.md").write_text("hi", encoding="utf-8")
    assert generate_dockerfile(tmp_path) is None
