"""Tests for MCPSecurityAgent against a tiny local server mimicking exposed MCP surface."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from argus.agents.base import AttackContext
from argus.agents.mcpsecurity import MCPSecurityAgent, _looks_like_tool_list


def test_looks_like_tool_list_json_rpc_envelope():
    body = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "read_file"}]}}
    tools = _looks_like_tool_list(body)
    assert tools == [{"name": "read_file"}]


def test_looks_like_tool_list_bare_tools_key():
    assert _looks_like_tool_list({"tools": [{"name": "x"}]}) == [{"name": "x"}]


def test_looks_like_tool_list_none_when_absent():
    assert _looks_like_tool_list({"result": {"ok": True}}) is None


class _UnauthMCPHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return

    def do_POST(self):  # noqa: N802
        if self.path == "/mcp":
            length = int(self.headers.get("Content-Length", 0) or 0)
            self.rfile.read(length)
            body = {
                "jsonrpc": "2.0", "id": 1,
                "result": {"tools": [{"name": "read_file"}, {"name": "shell_exec"}]},
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())
            return
        self.send_response(404)
        self.end_headers()

    def do_GET(self):  # noqa: N802
        self.send_response(404)
        self.end_headers()


@pytest.fixture
def mcp_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _UnauthMCPHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()
    srv.server_close()


@pytest.mark.asyncio
async def test_mcpsecurity_confirms_unauthenticated_tool_list(mcp_server):
    async with httpx.AsyncClient() as client:
        ctx = AttackContext(mcp_server, client=client)
        report = await MCPSecurityAgent().run(ctx)

    assert report.status == "complete"
    findings = [f for f in ctx.findings if f.detector == "mcpsecurity:tool-list"]
    assert len(findings) == 1
    f = findings[0]
    assert f.confirmed is True
    assert "read_file" in f.evidence
    assert f.poc and "curl" in f.poc
    assert f.poc["curl"].startswith("curl")


@pytest.mark.asyncio
async def test_mcpsecurity_no_findings_when_nothing_exposed():
    async def handler_404(request):
        return httpx.Response(404)

    transport = httpx.MockTransport(handler_404)
    async with httpx.AsyncClient(transport=transport) as client:
        ctx = AttackContext("http://nope.test", client=client)
        report = await MCPSecurityAgent().run(ctx)

    assert report.status == "complete"
    assert report.findings == 0
