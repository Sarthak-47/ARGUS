"""Tests for authenticated attack sessions (argus/auth.py)."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from argus.auth import AuthConfig, AuthError, load_auth


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# ----- parsing -----

def test_bearer_sugar_becomes_auth_header():
    cfg = AuthConfig.from_dict({"bearer": "abc123"})
    assert cfg.headers["Authorization"] == "Bearer abc123"


def test_basic_requires_both_fields():
    with pytest.raises(AuthError):
        AuthConfig.from_dict({"basic": {"username": "admin"}})


def test_login_requires_data():
    with pytest.raises(AuthError):
        AuthConfig.from_dict({"login": {"url": "http://x/login"}})


def test_from_toml_roundtrip(tmp_path: Path):
    p = tmp_path / ".argus-auth.toml"
    p.write_text(
        '[headers]\nX-API-Key = "k"\n\n[cookies]\nsession = "s"\n', encoding="utf-8")
    cfg = AuthConfig.from_toml(p)
    assert cfg.headers["X-API-Key"] == "k"
    assert cfg.cookies["session"] == "s"


# ----- apply(): static credentials -----

async def test_apply_sets_headers_and_cookies():
    cfg = AuthConfig.from_dict({"bearer": "tok", "cookies": {"sid": "xyz"}})
    async with _client(lambda r: httpx.Response(200)) as client:
        summary = await cfg.apply(client)
    assert client.headers["Authorization"] == "Bearer tok"
    assert client.cookies.get("sid") == "xyz"
    assert "header" in summary and "cookie" in summary


async def test_apply_sets_basic_auth():
    cfg = AuthConfig.from_dict({"basic": {"username": "u", "password": "p"}})
    async with _client(lambda r: httpx.Response(200)) as client:
        await cfg.apply(client)
    assert isinstance(client.auth, httpx.BasicAuth)


# ----- apply(): form login -----

async def test_form_login_extracts_token():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/login"
        return httpx.Response(200, json={"data": {"token": "JWT123"}})

    cfg = AuthConfig.from_dict({
        "login": {"url": "http://app/login", "json": True,
                  "token_json_path": "data.token", "data": {"u": "a", "p": "b"}}
    })
    async with _client(handler) as client:
        await cfg.apply(client)
    assert client.headers["Authorization"] == "Bearer JWT123"


async def test_form_login_session_cookie():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"set-cookie": "session=abc; Path=/"})

    cfg = AuthConfig.from_dict({"login": {"url": "http://app/login", "data": {"u": "a"}}})
    async with _client(handler) as client:
        summary = await cfg.apply(client)
        assert client.cookies.get("session") == "abc"
    assert "session cookie" in summary


async def test_form_login_bad_credentials_raises():
    cfg = AuthConfig.from_dict({"login": {"url": "http://app/login", "data": {"u": "a"}}})
    async with _client(lambda r: httpx.Response(401)) as client:
        with pytest.raises(AuthError):
            await cfg.apply(client)


async def test_form_login_missing_token_raises():
    cfg = AuthConfig.from_dict({
        "login": {"url": "http://app/login", "token_json_path": "token", "data": {"u": "a"}}
    })
    async with _client(lambda r: httpx.Response(200, json={"nope": 1})) as client:
        with pytest.raises(AuthError):
            await cfg.apply(client)


# ----- apply(): oauth2 client-credentials -----

async def test_oauth2_client_credentials():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/oauth/token"
        return httpx.Response(200, json={"access_token": "OA2TOKEN", "token_type": "bearer"})

    cfg = AuthConfig.from_dict({
        "oauth2": {"token_url": "http://app/oauth/token", "client_id": "id", "client_secret": "sec"}
    })
    async with _client(handler) as client:
        await cfg.apply(client)
    assert client.headers["Authorization"] == "Bearer OA2TOKEN"


# ----- load_auth resolution -----

def test_load_auth_missing_file_raises():
    with pytest.raises(AuthError):
        load_auth("does-not-exist.toml")


def test_load_auth_empty_config_returns_none(tmp_path: Path):
    p = tmp_path / "a.toml"
    p.write_text("# nothing here\n", encoding="utf-8")
    assert load_auth(str(p)) is None


def test_load_auth_none_when_no_file_and_no_autodiscover():
    assert load_auth(None, auto=False) is None


# ----- end-to-end: the swarm carries the session to a real socket -----

def test_swarm_sends_auth_on_every_request():
    """Proof that applying auth to the shared client means every agent request
    to a real server carries the credential."""
    import http.server
    import socketserver
    import threading

    from argus.llm.orchestrator import run_attack_sync

    seen: list[str | None] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def _serve(self):
            seen.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>ok</body></html>")

        do_GET = do_POST = do_HEAD = _serve

        def log_message(self, *a):  # silence
            pass

    class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    srv = Server(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cfg = AuthConfig.from_dict({"bearer": "SECRET_SESSION_TOKEN"})
        run_attack_sync(
            f"http://127.0.0.1:{port}", requested_agents=["headerpoker"],
            use_callback=False, auth=cfg,
        )
    finally:
        srv.shutdown()

    assert seen, "the swarm made no requests"
    assert all(a == "Bearer SECRET_SESSION_TOKEN" for a in seen), \
        f"some requests were unauthenticated: {[a for a in seen if a != 'Bearer SECRET_SESSION_TOKEN']}"
