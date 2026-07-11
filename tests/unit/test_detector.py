"""Tests for argus.llm.detector — GPU detection and local-model listing."""

from __future__ import annotations

import httpx

from argus.llm.detector import list_ollama_models


class _Resp:
    def __init__(self, status_code: int, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


def test_list_ollama_models_returns_sorted_names(monkeypatch):
    monkeypatch.setattr(
        httpx, "get",
        lambda url, timeout=None: _Resp(200, {"models": [{"name": "qwen3:8b"}, {"name": "llama3.1:8b"}]}),
    )
    assert list_ollama_models() == ["llama3.1:8b", "qwen3:8b"]


def test_list_ollama_models_empty_when_ollama_unreachable(monkeypatch):
    def raise_connect_error(url, timeout=None):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "get", raise_connect_error)
    assert list_ollama_models() == []


def test_list_ollama_models_empty_on_non_200(monkeypatch):
    monkeypatch.setattr(httpx, "get", lambda url, timeout=None: _Resp(500))
    assert list_ollama_models() == []


def test_list_ollama_models_empty_on_malformed_json(monkeypatch):
    class BadResp:
        status_code = 200

        def json(self):
            raise ValueError("not json")

    monkeypatch.setattr(httpx, "get", lambda url, timeout=None: BadResp())
    assert list_ollama_models() == []


def test_list_ollama_models_skips_entries_without_a_name(monkeypatch):
    monkeypatch.setattr(
        httpx, "get",
        lambda url, timeout=None: _Resp(200, {"models": [{"name": "a"}, {}, {"size": 123}]}),
    )
    assert list_ollama_models() == ["a"]
