"""Tests for PromptInjectionAgent against tiny local servers simulating a
vulnerable (echoes raw input) and a safe (fixed reply) chatbot backend.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from argus.agents.base import AttackContext, Endpoint
from argus.agents.promptinjection import PromptInjectionAgent, _looks_like_ai_endpoint


def test_looks_like_ai_endpoint_matches_common_names():
    assert _looks_like_ai_endpoint("http://t/api/chat")
    assert _looks_like_ai_endpoint("http://t/assistant/ask")
    assert _looks_like_ai_endpoint("http://t/v1/completions")


def test_looks_like_ai_endpoint_false_for_unrelated_paths():
    assert not _looks_like_ai_endpoint("http://t/api/users")
    assert not _looks_like_ai_endpoint("http://t/checkout")


class _VulnerableChatHandler(BaseHTTPRequestHandler):
    """Echoes the 'message' field verbatim — the vulnerable pattern."""

    def log_message(self, *a):
        return

    def do_POST(self):  # noqa: N802
        if self.path == "/api/chat":
            length = int(self.headers.get("Content-Length", 0) or 0)
            data = json.loads(self.rfile.read(length) or b"{}")
            reply = {"reply": f"Bot says: {data.get('message', '')}"}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(reply).encode())
            return
        self.send_response(404)
        self.end_headers()

    def do_GET(self):  # noqa: N802
        self.send_response(404)
        self.end_headers()


class _SafeChatHandler(BaseHTTPRequestHandler):
    """Never echoes user input — a fixed canned reply."""

    def log_message(self, *a):
        return

    def do_POST(self):  # noqa: N802
        if self.path == "/api/chat":
            length = int(self.headers.get("Content-Length", 0) or 0)
            self.rfile.read(length)
            reply = {"reply": "I can help you with your order status."}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(reply).encode())
            return
        self.send_response(404)
        self.end_headers()

    def do_GET(self):  # noqa: N802
        self.send_response(404)
        self.end_headers()


def _start(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{port}"


@pytest.fixture
def vulnerable_chat_server():
    srv, base_url = _start(_VulnerableChatHandler)
    yield base_url
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def safe_chat_server():
    srv, base_url = _start(_SafeChatHandler)
    yield base_url
    srv.shutdown()
    srv.server_close()


@pytest.mark.asyncio
async def test_confirms_injection_when_endpoint_echoes_input(vulnerable_chat_server):
    async with httpx.AsyncClient() as client:
        ctx = AttackContext(vulnerable_chat_server, client=client)
        # Simulate ReconBot having discovered this via a plain <a href> link —
        # recorded as GET, even though the real endpoint is POST-only. The
        # agent must not trust that recorded method.
        ctx.add_endpoint(Endpoint(url=f"{vulnerable_chat_server}/api/chat", method="GET"))
        report = await PromptInjectionAgent().run(ctx)

    assert report.status == "complete"
    findings = [f for f in ctx.findings if f.detector == "promptinjection:echo"]
    assert len(findings) == 1
    f = findings[0]
    assert f.confirmed is True
    assert f.endpoint.startswith("POST ")
    assert f.poc and f.poc["curl"].startswith("curl")


@pytest.mark.asyncio
async def test_no_finding_when_endpoint_does_not_echo_input(safe_chat_server):
    async with httpx.AsyncClient() as client:
        ctx = AttackContext(safe_chat_server, client=client)
        ctx.add_endpoint(Endpoint(url=f"{safe_chat_server}/api/chat", method="POST"))
        report = await PromptInjectionAgent().run(ctx)

    assert report.status == "complete"
    assert report.findings == 0


@pytest.mark.asyncio
async def test_no_ai_endpoint_short_circuits_without_requests():
    async with httpx.AsyncClient() as client:
        ctx = AttackContext("http://nope.test", client=client)
        ctx.add_endpoint(Endpoint(url="http://nope.test/api/users", method="GET"))
        report = await PromptInjectionAgent().run(ctx)

    assert report.status == "complete"
    assert report.findings == 0
    assert ctx.requests_sent == 0
