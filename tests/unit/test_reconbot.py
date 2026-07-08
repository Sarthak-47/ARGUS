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
