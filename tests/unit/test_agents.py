"""Tests for Phase 2 agent helpers that don't require a live target.

Covers JWT weak-secret cracking, injection URL construction, the callback server's
hit recording, and the orchestrator's agent-ordering logic.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

import httpx
import pytest

from argus.agents.authbreaker import AuthBreaker, _b64url_decode, _b64url_encode
from argus.agents.injector import _with_param
from argus.llm.orchestrator import _select_order
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
    assert _select_order(None, []) == ["injector", "authbreaker"]


def test_select_order_biases_authbreaker_on_prior_jwt():
    prior = [Finding(title="Hardcoded JWT secret", severity=Severity.HIGH, category="auth")]
    order = _select_order(None, prior)
    assert order[0] == "authbreaker"


def test_select_order_respects_requested_subset():
    assert _select_order(["injector"], []) == ["injector"]


@pytest.mark.asyncio
async def test_callback_server_records_hit():
    with CallbackServer() as cb:
        token, url = cb.new_token()
        assert cb.was_hit(token) is False
        async with httpx.AsyncClient() as client:
            await client.get(url)
        assert cb.was_hit(token) is True
        assert cb.hits(token)[0]["path"].strip("/").startswith(token[:6])
