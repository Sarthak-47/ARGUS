"""Every agent must survive a real run against a live target.

The orchestrator wraps each agent in try/except and turns a crash into an
"error" report (so one bad agent can't sink the whole run). That safety net
also means an agent that raises on ordinary input degrades silently — a real
user just quietly loses that agent's coverage. This smoke test runs each
registered agent against a small local server that answers every request, and
asserts it completes with an AgentReport instead of raising. It's the guard
that keeps a refactor from breaking an agent unnoticed.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from argus.agents.base import AttackContext, Endpoint
from argus.llm.orchestrator import AGENT_REGISTRY

_PAGE = b"""<!doctype html><html><head><title>mock</title></head><body>
<a href="/item?id=1">item</a><a href="/search?q=x">search</a>
<form action="/login" method="post"><input name="username"><input name="password"><input name="submit"></form>
<form action="/comment" method="get"><input name="text"><input name="Submit"></form>
<script>fetch('/api/users?uid=1')</script></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _send(self, code=200, body=_PAGE, ctype="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Set-Cookie", "session=abc")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        if self.path.startswith("/graphql"):
            self._send(body=b'{"data":{"__schema":{"types":[]}}}', ctype="application/json")
        else:
            self._send()

    def do_POST(self):
        self._send()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()


@pytest.fixture(scope="module")
def mock_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize("name", list(AGENT_REGISTRY))
async def test_agent_completes_without_raising(name, mock_server):
    cls = AGENT_REGISTRY[name]
    async with httpx.AsyncClient(follow_redirects=True, timeout=8.0) as client:
        ctx = AttackContext(mock_server, client=client, concurrency=5)
        for ep in (
            Endpoint(url=mock_server + "/item", method="GET", params=["id"]),
            Endpoint(url=mock_server + "/search", method="GET", params=["q"]),
            Endpoint(url=mock_server + "/api/users", method="GET", params=["uid"]),
            Endpoint(url=mock_server + "/comment", method="GET", params=["text", "Submit"]),
        ):
            ctx.add_endpoint(ep)
        report = await cls().run(ctx)
        # A clean run yields a real report; the agent never raised.
        assert report is not None
        assert report.status in ("complete", "running", "error")
        assert report.agent
