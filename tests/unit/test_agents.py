"""Tests for Phase 2 agent helpers that don't require a live target.

Covers JWT weak-secret cracking, injection URL construction, the callback server's
hit recording, and the orchestrator's agent-ordering logic.
"""

from __future__ import annotations

import hashlib
import hmac
import json

import httpx
import pytest

from argus.agents.authbreaker import AuthBreaker, _b64url_decode, _b64url_encode
from argus.agents.base import AttackContext, BaseAgent
from argus.agents.injector import _with_param
from argus.llm.orchestrator import _select_order
from argus.llm.provider import LLMResult
from argus.models import Finding, Severity
from argus.sandbox.callback_server import CallbackServer


def _make_jwt(secret: str, payload: dict | None = None) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = payload or {"sub": "1", "role": "user"}
    si = f"{_b64url_encode(json.dumps(header).encode())}.{_b64url_encode(json.dumps(payload).encode())}"
    sig = hmac.new(secret.encode(), si.encode(), hashlib.sha256).digest()
    return f"{si}.{_b64url_encode(sig)}"


def test_b64url_roundtrip():
    assert _b64url_decode(_b64url_encode(b"hello world!!")) == b"hello world!!"


def test_crack_weak_secret():
    ab = AuthBreaker()
    token = _make_jwt("secret")
    assert ab._crack_hs(token) == "secret"


def test_strong_secret_not_cracked():
    ab = AuthBreaker()
    token = _make_jwt("a-very-long-random-secret-not-in-the-list-xyz-123456")
    assert ab._crack_hs(token) is None


def test_with_param_sets_query():
    url = _with_param("http://t/users", "name", "1' OR '1'='1")
    assert "name=" in url
    assert url.startswith("http://t/users?")


def test_with_param_preserves_other_params():
    url = _with_param("http://t/s?page=2", "q", "x")
    assert "page=2" in url and "q=x" in url


def test_select_order_default():
    order = _select_order(None, [])
    assert order[0] == "crawlerbot"  # widen the surface first
    assert "injector" in order and "xsshunter" in order and "ssrfprober" in order
    assert "reconbot" not in order  # recon runs separately, first


def test_select_order_biases_authbreaker_on_prior_jwt():
    prior = [Finding(title="Hardcoded JWT secret", severity=Severity.HIGH, category="auth")]
    order = _select_order(None, prior)
    assert order[0] == "authbreaker"


def test_select_order_respects_requested_subset():
    assert _select_order(["injector"], []) == ["injector"]


def test_ssrf_param_hint_matches_url_like_names():
    from argus.agents.ssrfprober import _URL_PARAM_HINT
    assert _URL_PARAM_HINT.search("url")
    assert _URL_PARAM_HINT.search("redirect")
    assert _URL_PARAM_HINT.search("webhook")
    assert not _URL_PARAM_HINT.search("username")  # word-boundary: not a URL param


def test_xss_with_param_builds_query():
    from argus.agents.xsshunter import _with_param
    url = _with_param("http://t/search", "q", "<x>")
    assert "q=" in url and url.startswith("http://t/search?")


def test_crawlerbot_404_similarity():
    from argus.agents.crawlerbot import CrawlerBot
    cb = CrawlerBot()
    assert cb._similar("not found page", "not found page") is True
    assert cb._similar("a" * 50, "b" * 400) is False


def test_registry_contains_full_swarm():
    from argus.llm.orchestrator import AGENT_REGISTRY
    expected = {
        "reconbot", "crawlerbot", "injector", "authbreaker", "idorhunter", "xsshunter",
        "ssrfprober", "headerpoker", "csrfhunter", "fileattacker", "fuzzer",
        "racecondition", "graphqlagent", "websocketagent",
    }
    assert expected <= set(AGENT_REGISTRY)  # all 13 agents + recon registered


def test_idor_finds_numeric_path_segment():
    from argus.agents.idorhunter import _INT_SEG, _replace_path_int
    assert _INT_SEG.search("/api/orders/10472").group(1) == "10472"
    assert _replace_path_int("http://t/api/orders/10472", "10472", "10473") == "http://t/api/orders/10473"


def test_fileattacker_param_and_signatures():
    from argus.agents.fileattacker import _FILE_PARAM, _SIGS
    assert _FILE_PARAM.search("file") and _FILE_PARAM.search("download")
    assert _SIGS.search("root:x:0:0:root:/root:/bin/bash")
    assert _SIGS.search("[fonts]\n[extensions]")
    assert not _SIGS.search("nothing interesting here")


def test_fuzzer_error_signatures():
    from argus.agents.fuzzer import _ERROR_SIG, _PAYLOADS
    assert _ERROR_SIG.search("Traceback (most recent call last):")
    assert _ERROR_SIG.search("ValueError: invalid literal")
    assert len(_PAYLOADS) >= 8  # includes the unicode edge payload (no null bytes)
    # ensure no payload contains a NUL byte
    assert all("\x00" not in p for _, p in _PAYLOADS)


@pytest.mark.asyncio
async def test_callback_server_records_hit():
    with CallbackServer() as cb:
        token, url = cb.new_token()
        assert cb.was_hit(token) is False
        async with httpx.AsyncClient() as client:
            await client.get(url)
        assert cb.was_hit(token) is True
        assert cb.hits(token)[0]["path"].strip("/").startswith(token[:6])


class _FakeProvider:
    name = "fake"
    model = "fake-model"

    def __init__(self, text: str = '{"ok": true}'):
        self._text = text

    def complete(self, system, user, *, json_mode=False):
        return LLMResult(self._text, self.name, self.model)


class _RaisingProvider:
    def complete(self, system, user, *, json_mode=False):
        from argus.llm.provider import LLMError
        raise LLMError("boom")


@pytest.mark.asyncio
async def test_base_agent_complete_returns_none_without_provider():
    async with httpx.AsyncClient() as client:
        ctx = AttackContext("http://t", client=client, provider=None)
        result = await BaseAgent().complete(ctx, "sys", "user")
    assert result is None


@pytest.mark.asyncio
async def test_base_agent_complete_returns_provider_text():
    async with httpx.AsyncClient() as client:
        ctx = AttackContext("http://t", client=client, provider=_FakeProvider('{"x": 1}'))
        result = await BaseAgent().complete(ctx, "sys", "user", json_mode=True)
    assert result == '{"x": 1}'


@pytest.mark.asyncio
async def test_base_agent_complete_returns_none_on_llm_error():
    async with httpx.AsyncClient() as client:
        ctx = AttackContext("http://t", client=client, provider=_RaisingProvider())
        result = await BaseAgent().complete(ctx, "sys", "user")
    assert result is None


def test_attack_context_provider_defaults_to_none():
    import httpx as _httpx
    ctx = AttackContext("http://t", client=_httpx.AsyncClient())
    assert ctx.provider is None
