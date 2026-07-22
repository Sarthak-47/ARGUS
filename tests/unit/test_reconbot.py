"""Tests for ReconBot's link/form parsing — especially form method/action extraction.

Regression coverage for a real bug found via live testing: the original single-
capture-group form regex handed the form's *inner content* to the action/method
searches, but action= and method= live in the opening <form ...> tag, not the
inner content — so every form was silently recorded as GET regardless of what
method="..." actually said. This broke every downstream consumer of the endpoint
list (attack agents would probe a POST-only endpoint with GET and get a 404).
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from argus.agents.base import AttackContext
from argus.agents.reconbot import ReconBot

_HTML = """
<html><body>
<a href="/about">about</a>
<form action="/api/redeem" method="post">
  <input name="code">
</form>
<form action="/transfer" method="POST">
  <input type="hidden" name="amount" value="100">
  <input name="to">
</form>
<form action="/search">
  <input name="q">
</form>
</body></html>
"""


def _ctx() -> AttackContext:
    return AttackContext("http://t", client=httpx.AsyncClient())


def test_extract_form_method_is_post_not_get():
    ctx = _ctx()
    ReconBot()._extract(ctx, "http://t", _HTML)
    endpoints = {ep.url: ep.method for ep in ctx.endpoint_list()}
    assert endpoints["http://t/api/redeem"] == "POST"
    assert endpoints["http://t/transfer"] == "POST"


def test_extract_form_without_method_defaults_to_get():
    ctx = _ctx()
    ReconBot()._extract(ctx, "http://t", _HTML)
    endpoints = {ep.url: ep.method for ep in ctx.endpoint_list()}
    assert endpoints["http://t/search"] == "GET"


def test_extract_form_captures_input_names():
    ctx = _ctx()
    ReconBot()._extract(ctx, "http://t", _HTML)
    redeem = next(ep for ep in ctx.endpoint_list() if ep.url == "http://t/api/redeem")
    assert "code" in redeem.params


def test_extract_does_not_duplicate_form_action_as_a_get_link():
    """A <form action="..."> must not also be recorded as a plain GET link —
    only the form-parsing pass (with its real method) should add it."""
    ctx = _ctx()
    ReconBot()._extract(ctx, "http://t", _HTML)
    keys = list(ctx.endpoints.keys())
    assert "GET http://t/api/redeem" not in keys
    assert "GET http://t/transfer" not in keys


def test_extract_action_hash_form_binds_to_page_not_root():
    """DVWA's vulnerable pages carry the injectable param in a
    <form action="#" method="GET"> that posts back to the *current* page.
    The form endpoint must bind to that page's URL, not the site root —
    otherwise the injection agents attack the wrong (non-vulnerable) endpoint."""
    ctx = _ctx()
    page = "http://t/vulnerabilities/sqli/"
    html = '<form action="#" method="GET"><input name="id"><input name="Submit"></form>'
    ReconBot()._extract(ctx, "http://t", html, page_url=page)
    ep = next(ep for ep in ctx.endpoint_list() if ep.url == page)
    assert ep.method == "GET"
    assert "id" in ep.params
    # and it must NOT have leaked onto the root
    assert "GET http://t/" not in ctx.endpoints


def test_extract_relative_query_link_resolves_against_page():
    """A relative "?page=x" link (DVWA's file-inclusion page) must resolve
    against the sub-page it appears on, not the site root."""
    ctx = _ctx()
    page = "http://t/vulnerabilities/fi/"
    ReconBot()._extract(ctx, "http://t", '<a href="?page=file2.php">next</a>', page_url=page)
    urls = {ep.url for ep in ctx.endpoint_list()}
    assert page in urls


def test_extract_plain_links_still_recorded_as_get():
    ctx = _ctx()
    ReconBot()._extract(ctx, "http://t", _HTML)
    endpoints = {ep.url: ep.method for ep in ctx.endpoint_list()}
    assert endpoints["http://t/about"] == "GET"


# ----- API spec auto-discovery (roadmap v1.0.1 follow-up C) -----

def _openapi_spec() -> str:
    return json.dumps({
        "openapi": "3.0.0",
        "paths": {"/api/hidden-only-in-spec": {"get": {"parameters": [{"name": "id", "in": "query"}]}}},
    })


@pytest.mark.asyncio
async def test_full_run_seeds_endpoints_from_discovered_openapi_spec():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json=json.loads(_openapi_spec()))
        if request.url.path == "/":
            return httpx.Response(200, text="<html><body>hi</body></html>")
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        ctx = AttackContext("http://t", client=client)
        await ReconBot().run(ctx)

    urls = {ep.url for ep in ctx.endpoint_list()}
    assert "http://t/api/hidden-only-in-spec" in urls
    seeded = ctx.endpoints["GET http://t/api/hidden-only-in-spec"]
    assert seeded.params == ["id"]


def test_seed_from_spec_ignores_non_spec_body():
    ctx = _ctx()
    before = len(ctx.endpoint_list())
    ReconBot()._seed_from_spec(ctx, "http://t", "/openapi.json", body_full="<html>not a spec</html>")
    assert len(ctx.endpoint_list()) == before  # silent no-op, no crash


def test_seed_from_spec_adds_endpoints_and_emits_event():
    ctx = _ctx()
    events = []
    ctx._on_event = lambda agent, text, sev="ok": events.append(text)
    ReconBot()._seed_from_spec(ctx, "http://t", "/api/openapi.json", body_full=_openapi_spec())
    assert "GET http://t/api/hidden-only-in-spec" in ctx.endpoints
    assert any("auto-discovered API spec" in e for e in events)


# ----- JS-aware crawling (roadmap v1.0.1 follow-up A) -----
# Skipped entirely if the optional `browser` extra (playwright) isn't
# installed — same graceful-degrade pattern test_domxss.py uses.

pytest.importorskip("playwright")

_SPA_PAGE = b"""<!doctype html><html><body>
<div id="app"></div>
<script>
  document.getElementById('app').innerHTML = '<a href="/js-only-link">hidden</a>';
  fetch('/api/js-only-endpoint?id=1');
</script>
</body></html>"""


class _SPAHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return

    def do_GET(self):  # noqa: N802
        if self.path == "/" or self.path == "":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(_SPA_PAGE)
            return
        if self.path.startswith("/api/js-only-endpoint"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")
            return
        self.send_response(404)
        self.end_headers()


@pytest.fixture
def spa_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _SPAHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()
    srv.server_close()


@pytest.mark.asyncio
async def test_js_crawl_finds_link_only_in_rendered_dom(spa_server):
    """The core follow-up A case: a link that only exists after JS runs
    (Angular/React/Vue-style client rendering) — invisible to the static
    regex-over-server-HTML crawl, caught by rendering in a real browser."""
    async with httpx.AsyncClient() as client:
        ctx = AttackContext(spa_server, client=client)
        await ReconBot().run(ctx)

    urls = {ep.url for ep in ctx.endpoint_list()}
    assert f"{spa_server}/js-only-link" in urls


@pytest.mark.asyncio
async def test_js_crawl_finds_xhr_call_invisible_to_static_crawl(spa_server):
    """The Juice Shop / VAmPI-style gap: an API call the SPA fires via
    fetch/XHR after load, with no href/src anywhere in the server-rendered
    HTML for a static crawl to ever find."""
    async with httpx.AsyncClient() as client:
        ctx = AttackContext(spa_server, client=client)
        await ReconBot().run(ctx)

    xhr_endpoints = [ep for ep in ctx.endpoint_list() if ep.source == "js-xhr"]
    assert any(ep.url.endswith("/api/js-only-endpoint") and "id" in ep.params for ep in xhr_endpoints)


@pytest.mark.asyncio
async def test_js_crawl_skips_cleanly_when_playwright_unavailable(monkeypatch):
    monkeypatch.setattr("argus.agents.reconbot.async_playwright", None)
    async with httpx.AsyncClient() as client:
        ctx = AttackContext("http://t", client=client)
        events = []
        ctx._on_event = lambda agent, text, sev="ok": events.append(text)
        await ReconBot()._js_crawl(ctx, "http://t")
    # no browser-error note, no crash — a silent, zero-cost no-op
    assert not any("JS-aware crawl" in e for e in events)


def test_detect_challenge_flags_vercel_and_cloudflare_but_not_ordinary_403():
    """Reported from a real report: a Vercel-protected site (403 +
    X-Vercel-Mitigated: challenge) scanned to a near-empty, low-risk result
    that read like a clean bill of health — when really Argus never got past
    the challenge. Detection must catch the known challenge providers while
    NOT mislabelling an ordinary 403 or a normal 200 as a challenge."""
    from argus.agents.reconbot import _detect_challenge_provider

    vercel = httpx.Response(403, headers={"x-vercel-mitigated": "challenge",
                                          "x-vercel-challenge-token": "tok", "server": "Vercel"},
                            text="<html>challenge</html>")
    assert _detect_challenge_provider(vercel) == "Vercel bot protection"

    cf = httpx.Response(503, headers={"server": "cloudflare"},
                        text="<html>Just a moment... challenge-platform</html>")
    assert _detect_challenge_provider(cf) == "Cloudflare challenge"

    cf_hdr = httpx.Response(403, headers={"cf-mitigated": "challenge"}, text="x")
    assert _detect_challenge_provider(cf_hdr) == "Cloudflare"

    captcha = httpx.Response(429, headers={"server": "nginx"}, text="please complete the captcha")
    assert _detect_challenge_provider(captcha) == "bot-challenge / CAPTCHA wall"

    # must NOT flag: a plain app-level 403, or a normal 200 (even on Vercel)
    assert _detect_challenge_provider(httpx.Response(403, headers={"server": "nginx"}, text="Forbidden")) is None
    assert _detect_challenge_provider(httpx.Response(200, headers={"server": "Vercel"}, text="<html>hi</html>")) is None
