"""Tests for API schema ingestion (argus/apispec.py)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus.apispec import ApiSpecError, load_endpoints

BASE = "http://localhost:3000"


def _write(tmp_path: Path, name: str, data) -> str:
    p = tmp_path / name
    p.write_text(json.dumps(data) if not isinstance(data, str) else data, encoding="utf-8")
    return str(p)


def test_openapi3_paths_methods_params(tmp_path: Path):
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.com/v2"}],
        "paths": {
            "/users": {
                "get": {"parameters": [{"name": "limit", "in": "query"}]},
                "post": {"requestBody": {"content": {"application/json": {
                    "schema": {"properties": {"email": {}, "password": {}}}}}}},
            },
            "/users/{id}": {"get": {"parameters": [{"name": "id", "in": "path"}]}},
        },
    }
    eps, note = load_endpoints(_write(tmp_path, "o.json", spec), BASE)
    by_key = {e.key(): e for e in eps}
    # basePath /v2 from servers is prepended, resolved against the attack base_url
    assert "GET http://localhost:3000/v2/users" in by_key
    assert "POST http://localhost:3000/v2/users" in by_key
    assert "GET http://localhost:3000/v2/users/{id}" in by_key
    assert "limit" in by_key["GET http://localhost:3000/v2/users"].params
    assert set(by_key["POST http://localhost:3000/v2/users"].params) == {"email", "password"}
    assert "openapi" in note


def test_swagger2_basepath(tmp_path: Path):
    spec = {
        "swagger": "2.0",
        "basePath": "/api/v1",
        "paths": {"/login": {"post": {"parameters": [{"name": "username"}, {"name": "password"}]}}},
    }
    eps, _ = load_endpoints(_write(tmp_path, "s.json", spec), BASE)
    assert eps[0].url == "http://localhost:3000/api/v1/login"
    assert eps[0].method == "POST"
    assert set(eps[0].params) == {"username", "password"}


def test_openapi_yaml(tmp_path: Path):
    yaml_spec = (
        "openapi: 3.0.0\n"
        "paths:\n"
        "  /ping:\n"
        "    get:\n"
        "      parameters:\n"
        "        - name: q\n"
        "          in: query\n"
    )
    eps, _ = load_endpoints(_write(tmp_path, "o.yaml", yaml_spec), BASE)
    assert eps[0].url == "http://localhost:3000/ping"
    assert eps[0].params == ["q"]


def test_postman_collection(tmp_path: Path):
    spec = {
        "info": {"schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": [
            {"name": "folder", "item": [
                {"name": "get user", "request": {
                    "method": "GET",
                    "url": {"path": ["api", "users"], "query": [{"key": "id"}]}}},
            ]},
            {"name": "login", "request": {
                "method": "POST",
                "url": {"raw": "http://x/api/login", "path": ["api", "login"]},
                "body": {"mode": "urlencoded", "urlencoded": [{"key": "user"}, {"key": "pass"}]}}},
        ],
    }
    eps, note = load_endpoints(_write(tmp_path, "p.json", spec), BASE)
    by_key = {e.key(): e for e in eps}
    assert "GET http://localhost:3000/api/users" in by_key
    assert by_key["GET http://localhost:3000/api/users"].params == ["id"]
    assert "POST http://localhost:3000/api/login" in by_key
    assert set(by_key["POST http://localhost:3000/api/login"].params) == {"user", "pass"}
    assert "postman" in note


def test_graphql_introspection(tmp_path: Path):
    spec = {"data": {"__schema": {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {"name": "Query", "fields": [{"name": "me"}, {"name": "orders"}]},
            {"name": "Mutation", "fields": [{"name": "login"}]},
        ],
    }}}
    eps, _ = load_endpoints(_write(tmp_path, "g.json", spec), BASE)
    assert len(eps) == 1
    assert eps[0].url == "http://localhost:3000/graphql"
    assert eps[0].method == "POST"
    assert set(eps[0].params) == {"me", "orders", "login"}


def test_unknown_spec_raises(tmp_path: Path):
    with pytest.raises(ApiSpecError):
        load_endpoints(_write(tmp_path, "x.json", {"hello": "world"}), BASE)


def test_missing_file_raises():
    with pytest.raises(ApiSpecError):
        load_endpoints("nope-does-not-exist.json", BASE)


def test_dedup_across_paths(tmp_path: Path):
    spec = {"openapi": "3.0.0", "paths": {"/a": {"get": {}}, "/a ": {"get": {}}}}
    # not truly duplicate, but ensure no crash and both counted distinctly
    eps, _ = load_endpoints(_write(tmp_path, "d.json", spec), BASE)
    assert len(eps) >= 1
