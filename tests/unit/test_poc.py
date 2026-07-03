"""Tests for build_http_poc: reproducible proof-of-concept capture with redaction."""

from __future__ import annotations

import httpx

from argus.agents.base import build_http_poc


def _response(headers: dict | None = None, status_code: int = 500, text: str = "body") -> httpx.Response:
    request = httpx.Request("GET", "http://target.test/api/users?name=x", headers=headers or {})
    return httpx.Response(status_code, request=request, text=text)


def test_build_http_poc_shape():
    resp = _response()
    poc = build_http_poc("GET", "http://target.test/api/users?name=x", resp)
    assert poc["type"] == "http"
    assert "curl" in poc and "-X GET" in poc["curl"]
    assert "GET http://target.test" in poc["request"]
    assert "HTTP 500" in poc["response"]
    assert "body" in poc["response"]


def test_build_http_poc_redacts_authorization_and_cookie():
    resp = _response(headers={"Authorization": "Bearer supersecrettoken", "Cookie": "session=abc123"})
    poc = build_http_poc("GET", "http://target.test/api/users", resp)
    assert "supersecrettoken" not in poc["curl"]
    assert "supersecrettoken" not in poc["request"]
    assert "abc123" not in poc["curl"]
    assert "***REDACTED***" in poc["curl"]


def test_build_http_poc_keeps_non_sensitive_headers():
    resp = _response(headers={"X-Custom-Header": "keep-me"})
    poc = build_http_poc("GET", "http://target.test/x", resp)
    assert "keep-me" in poc["curl"]


def test_build_http_poc_truncates_long_response_body():
    resp = _response(text="A" * 5000)
    poc = build_http_poc("GET", "http://target.test/x", resp)
    # 2000-char body cap + "HTTP 500\n" prefix
    assert len(poc["response"]) <= 2000 + len("HTTP 500\n")
