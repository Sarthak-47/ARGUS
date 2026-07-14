"""Tests for Phase 2 agent helpers that don't require a live target.

Covers JWT weak-secret cracking, injection URL construction, the callback server's
hit recording, and the orchestrator's agent-ordering logic.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time

import httpx
import pytest

from argus.agents.authbreaker import AuthBreaker, _b64url_decode, _b64url_encode
from argus.agents.base import AttackContext, BaseAgent, Endpoint, _destroys_session
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


@pytest.mark.asyncio
async def test_authbreaker_analyses_the_session_bearer_token():
    """A weak JWT supplied as the session's own Authorization header (via --auth)
    must get cracked — it's the token most worth checking, and previously only
    tokens the homepage handed out were analysed."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        token = _make_jwt("secret")  # weak, in the wordlist
        async with httpx.AsyncClient(headers={"Authorization": f"Bearer {token}"}) as client:
            ctx = AttackContext(base, client=client, concurrency=4)
            await AuthBreaker().run(ctx)
        weak = [f for f in ctx.findings if "secret" in f.title.lower() or f.detector == "authbreaker:jwt-weak-secret"]
        assert weak, "expected the session's weak JWT secret to be flagged"
    finally:
        srv.shutdown()


@pytest.mark.parametrize("url,destroys", [
    ("http://t/logout.php", True),
    ("http://t/logout", True),
    ("http://t/users/sign_out", True),
    ("http://t/account/log-off", True),
    ("http://t/api/v1/signout", True),
    ("http://t/vulnerabilities/sqli/", False),
    ("http://t/logout_history", False),   # not a logout action
    ("http://t/blog/about-logout-hooks", False),
])
def test_destroys_session_matches_only_real_logout_paths(url, destroys):
    assert _destroys_session(url) is destroys


def test_add_endpoint_skips_session_destroying_urls():
    ctx = AttackContext("http://t", client=httpx.AsyncClient())
    ctx.add_endpoint(Endpoint(url="http://t/logout.php"))
    ctx.add_endpoint(Endpoint(url="http://t/vulnerabilities/sqli/", params=["id"]))
    urls = {e.url for e in ctx.endpoint_list()}
    assert "http://t/logout.php" not in urls
    assert "http://t/vulnerabilities/sqli/" in urls


def test_attack_context_rejects_off_origin_endpoints():
    ctx = AttackContext("https://example.test:8443", client=httpx.AsyncClient())
    ctx.add_endpoint(Endpoint(url="https://example.test:8443/in-scope"))
    ctx.add_endpoint(Endpoint(url="https://outside.test/owned-by-someone-else"))
    ctx.add_endpoint(Endpoint(url="http://example.test:8443/downgraded-scheme"))
    assert [ep.url for ep in ctx.endpoint_list()] == ["https://example.test:8443/in-scope"]


@pytest.mark.asyncio
async def test_request_refuses_to_hit_logout():
    ctx = AttackContext("http://t", client=httpx.AsyncClient())
    resp = await BaseAgent().get(ctx, "http://t/logout.php")
    assert resp is None
    assert ctx.requests_sent == 0  # never even sent


@pytest.mark.asyncio
async def test_request_refuses_to_hit_off_origin_url():
    ctx = AttackContext("http://t", client=httpx.AsyncClient())
    resp = await BaseAgent().get(ctx, "http://outside.test/")
    assert resp is None
    assert ctx.requests_sent == 0  # never even sent


@pytest.mark.asyncio
async def test_request_stops_once_max_requests_budget_is_exhausted():
    def handler(request):
        return httpx.Response(200, text="ok")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ctx = AttackContext("http://t", client=client, max_requests=2)
    agent = BaseAgent()

    r1 = await agent.get(ctx, "http://t/a")
    r2 = await agent.get(ctx, "http://t/b")
    r3 = await agent.get(ctx, "http://t/c")

    assert r1 is not None and r2 is not None
    assert r3 is None
    assert ctx.requests_sent == 2


@pytest.mark.asyncio
async def test_rate_limit_spaces_requests_apart():
    def handler(request):
        return httpx.Response(200, text="ok")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    # 10 req/s -> at least ~0.1s between the 1st and 3rd request (2 intervals).
    ctx = AttackContext("http://t", client=client, rate_limit=10.0, concurrency=10)
    agent = BaseAgent()

    start = time.monotonic()
    await asyncio.gather(*(agent.get(ctx, f"http://t/{i}") for i in range(3)))
    elapsed = time.monotonic() - start

    assert ctx.requests_sent == 3
    assert elapsed >= 0.2 - 0.02  # small tolerance for scheduling jitter


@pytest.mark.asyncio
async def test_no_rate_limit_by_default_is_fast():
    def handler(request):
        return httpx.Response(200, text="ok")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ctx = AttackContext("http://t", client=client)  # rate_limit=None
    agent = BaseAgent()

    start = time.monotonic()
    await asyncio.gather(*(agent.get(ctx, f"http://t/{i}") for i in range(5)))
    elapsed = time.monotonic() - start

    assert ctx.requests_sent == 5
    assert elapsed < 0.2  # no artificial spacing


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


def test_fallback_baseline_similarity():
    from argus.agents.base import response_matches_fallback

    assert response_matches_fallback("not found page", "not found page") is True
    assert response_matches_fallback("a" * 50, "b" * 400) is False
    assert response_matches_fallback("anything", None) is False


def test_fallback_baseline_similarity_not_defeated_by_truncated_baseline():
    # Regression: the baseline used to be pre-truncated to 500 chars while the
    # candidate body was compared at full length, so the length-bucket check
    # always failed for any real page longer than ~524 chars — silently
    # disabling the whole guard on any SPA whose fallback page (a real
    # index.html, easily 1-3KB) was longer than that.
    from argus.agents.base import response_matches_fallback

    baseline = "<!doctype html>" + "x" * 2000  # a realistic SPA fallback page
    same_page = baseline  # what an unrelated probed path gets back
    assert response_matches_fallback(same_page, baseline) is True


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


def test_idor_detects_rest_path_templates():
    from argus.agents.base import AttackContext, Endpoint
    from argus.agents.idorhunter import IDORHunter

    ctx = AttackContext("http://t", client=httpx.AsyncClient())
    ctx.add_endpoint(Endpoint(url="http://t/users/v1/{username}", method="GET"))
    ctx.add_endpoint(Endpoint(url="http://t/api/items/{id}", method="GET"))
    cands = IDORHunter()._candidates(ctx)
    kinds = {(k, key) for k, _u, key in cands}
    assert ("template", "username") in kinds
    assert ("template", "id") in kinds


def test_idor_harvests_identifier_values_from_json():
    from argus.agents.idorhunter import IDORHunter

    found: set[str] = set()
    IDORHunter()._walk_scalars(
        [{"username": "name1", "id": 1}, {"username": "name2", "id": 2}], found
    )
    assert {"name1", "name2"} <= found


@pytest.mark.asyncio
async def test_idor_enumerates_username_template_via_collection_harvest():
    """The concrete usernames aren't in /users/v1/{username}; IDORHunter must
    harvest them from the collection (GET /users/v1) and enumerate — the BOLA
    shape a numeric-only heuristic misses entirely."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from argus.agents.base import AttackContext, Endpoint
    from argus.agents.idorhunter import IDORHunter

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if self.path.rstrip("/") == "/users/v1":
                body = b'{"users":[{"username":"name1"},{"username":"name2"}]}'
            elif self.path == "/users/v1/name1":
                body = b'{"username":"name1","email":"a@x.com","password":"aaa"}'
            elif self.path == "/users/v1/name2":
                body = b'{"username":"name2","email":"b@x.com","password":"bbb"}'
            else:
                body = b'{}'
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        async with httpx.AsyncClient() as client:
            ctx = AttackContext(base, client=client, concurrency=4)
            ctx.add_endpoint(Endpoint(url=base + "/users/v1/{username}", method="GET"))
            await IDORHunter().run(ctx)
        idor = [f for f in ctx.findings if f.detector.startswith("idorhunter")]
        assert idor, "expected an IDOR finding from enumerating harvested usernames"
    finally:
        srv.shutdown()


@pytest.mark.asyncio
async def test_headerpoker_flags_wildcard_cors():
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from argus.agents.base import AttackContext
    from argus.agents.headerpoker import HeaderPoker

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"ok")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        async with httpx.AsyncClient() as client:
            ctx = AttackContext(base, client=client, concurrency=4)
            await HeaderPoker().run(ctx)
        cors = [f for f in ctx.findings if f.detector == "headerpoker:cors"]
        assert len(cors) == 1  # wildcard flagged exactly once, not per-probe
        assert "wildcard" in cors[0].title.lower()
    finally:
        srv.shutdown()


@pytest.mark.asyncio
async def test_headerpoker_forwarded_bypass_ignores_a_catchall_gateway():
    """Regression: a gateway that 401s a plain request but 200s *any* request
    once it carries an X-Forwarded-For/X-Real-IP/etc. header — same generic
    body regardless of the header's value or the target path — used to read
    as a confirmed HIGH "access control bypass," purely from the status flip.
    Every real request in this test gets the identical catch-all body."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from argus.agents.base import AttackContext, Endpoint
    from argus.agents.headerpoker import HeaderPoker

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            bypass_headers = ("x-forwarded-for", "x-real-ip", "x-original-url", "x-forwarded-host")
            if not any(h in (k.lower() for k in self.headers.keys()) for h in bypass_headers):
                self.send_response(401)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"generic":"same catch-all body for any bypass header"}')

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        async with httpx.AsyncClient() as client:
            ctx = AttackContext(base, client=client, concurrency=4)
            ctx.add_endpoint(Endpoint(url=base + "/admin", method="GET", sample_status=401))
            await HeaderPoker().run(ctx)
        bypass = [f for f in ctx.findings if f.detector == "headerpoker:bypass"]
        assert bypass == [], bypass
    finally:
        srv.shutdown()


def test_crawlerbot_treats_spa_html_fallback_as_not_exposed():
    from argus.agents.crawlerbot import CrawlerBot

    class R:
        def __init__(self, ctype):
            self.headers = {"content-type": ctype}

    # HTML served for a path that should be a config/binary file = SPA catch-all
    assert CrawlerBot._is_spa_fallback("/.env", R("text/html; charset=utf-8")) is True
    assert CrawlerBot._is_spa_fallback("/backup.sql", R("text/html")) is True
    # A real JSON/text file is not a fallback
    assert CrawlerBot._is_spa_fallback("/config.json", R("application/json")) is False
    # HTML panels legitimately return HTML
    assert CrawlerBot._is_spa_fallback("/admin/", R("text/html")) is False


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


@pytest.mark.asyncio
async def test_reconbot_suppresses_findings_on_an_spa_fallback_site():
    """Regression: an SPA (Netlify/Vercel/any client-routed app) serves the
    same index.html with HTTP 200 for every unmatched path. Reproduced live
    against a real Netlify-hosted site: ReconBot reported "Exposed .env file"
    (CRITICAL) and "Exposed .git repository" (HIGH) purely because the
    fallback page happened to return 200 — it had no baseline-comparison
    guard at all."""
    from argus.agents.reconbot import ReconBot

    fallback_body = "<!doctype html>" + "x" * 2000  # a realistic SPA index.html

    def handler(request):
        return httpx.Response(200, text=fallback_body, headers={"content-type": "text/html"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ctx = AttackContext("http://t", client=client)
    await ReconBot()._probe_common(ctx, "http://t")

    assert ctx.findings == []


@pytest.mark.asyncio
async def test_crawlerbot_suppresses_findings_on_an_spa_fallback_site():
    from argus.agents.crawlerbot import CrawlerBot

    fallback_body = "<!doctype html>" + "x" * 2000

    def handler(request):
        return httpx.Response(200, text=fallback_body, headers={"content-type": "text/html"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ctx = AttackContext("http://t", client=client)
    report = await CrawlerBot().run(ctx)

    assert report.findings == 0
    assert ctx.findings == []
