"""Cloud provider model selection + availability.

Groq decommissioned ``llama-3.1-70b-versatile`` while the API key stayed valid,
which silently broke every Groq scan and showed a misleading "reachable" in
``argus status``. These guard the fix: a config-overridable cloud model, and an
``available()`` that verifies the model is actually served."""

from __future__ import annotations

import httpx

from argus.config.defaults import DEFAULT_CLOUD_MODELS
from argus.config.settings import Settings
from argus.llm.provider import OpenAICompatProvider, build_provider


def test_default_cloud_models_are_current():
    # The exact string that was decommissioned must never be the default again.
    assert DEFAULT_CLOUD_MODELS["groq"] != "llama-3.1-70b-versatile"
    assert DEFAULT_CLOUD_MODELS["gemini"] != "gemini-1.5-flash"


def test_cloud_model_falls_back_to_default():
    s = Settings({"cloud": {"groq_key": "k"}})
    assert s.cloud_model("groq") == DEFAULT_CLOUD_MODELS["groq"]


def test_cloud_model_config_override_wins():
    # The escape hatch for a future rotation: set the model in config, no release.
    s = Settings({"cloud": {"groq_key": "k", "groq_model": "openai/gpt-oss-120b"}})
    assert s.cloud_model("groq") == "openai/gpt-oss-120b"


def test_build_provider_uses_configured_cloud_model():
    s = Settings({"cloud": {"groq_key": "k", "groq_model": "qwen/qwen3.8-27b"}})
    p = build_provider("groq", s)
    assert p.model == "qwen/qwen3.8-27b"


class _Resp:
    def __init__(self, status, data):
        self.status_code = status
        self._data = data

    def json(self):
        return self._data


def test_available_true_when_model_is_served(monkeypatch):
    p = OpenAICompatProvider("groq", "k", "openai/gpt-oss-20b",
                             "https://api.groq.com/openai/v1/chat/completions")
    monkeypatch.setattr(httpx, "get",
                        lambda *a, **k: _Resp(200, {"data": [{"id": "openai/gpt-oss-20b"}]}))
    assert p.available() is True


def test_available_false_when_model_decommissioned(monkeypatch):
    """The exact bug: key valid, model gone."""
    p = OpenAICompatProvider("groq", "k", "llama-3.1-70b-versatile",
                             "https://api.groq.com/openai/v1/chat/completions")
    monkeypatch.setattr(httpx, "get",
                        lambda *a, **k: _Resp(200, {"data": [{"id": "openai/gpt-oss-20b"}]}))
    assert p.available() is False


def test_available_no_key_is_false():
    p = OpenAICompatProvider("groq", "", "openai/gpt-oss-20b",
                             "https://api.groq.com/openai/v1/chat/completions")
    assert p.available() is False


def test_available_tolerates_network_error(monkeypatch):
    """Offline/transient must not report a configured provider as unavailable."""
    def _boom(*a, **k):
        raise httpx.ConnectError("offline")

    p = OpenAICompatProvider("groq", "k", "openai/gpt-oss-20b",
                             "https://api.groq.com/openai/v1/chat/completions")
    monkeypatch.setattr(httpx, "get", _boom)
    assert p.available() is True
