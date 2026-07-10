"""DataExposureAgent — flags sensitive fields (password hashes, secrets, PII)
returned in JSON responses, the excessive-data-exposure class no other agent
covers."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from argus.agents.base import AttackContext, Endpoint
from argus.agents.dataexposure import DataExposureAgent, _SECRET_FIELDS, _PII_FIELDS


def test_secret_and_pii_field_patterns():
    assert _SECRET_FIELDS.search('{"password": "x"}')
    assert _SECRET_FIELDS.search('{"api_key":"abc"}')
    assert _PII_FIELDS.search('{"ssn": "111-22-3333"}')
    assert not _SECRET_FIELDS.search('{"passenger":"ok","username":"a"}')


def _server(routes):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body, ctype = routes.get(self.path.rstrip("/") or "/", (b"{}", "application/json"))
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.mark.asyncio
async def test_flags_password_hash_in_collection_response():
    srv = _server({
        "/users/v1": (b'{"users":[{"username":"a","password":"h1"},{"username":"b","password":"h2"}]}',
                      "application/json"),
    })
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        async with httpx.AsyncClient() as client:
            ctx = AttackContext(base, client=client, concurrency=4)
            ctx.add_endpoint(Endpoint(url=base + "/users/v1", method="GET"))
            await DataExposureAgent().run(ctx)
        hits = [f for f in ctx.findings if f.detector == "dataexposure"]
        assert len(hits) == 1
        assert hits[0].cwe == "CWE-200"
    finally:
        srv.shutdown()


@pytest.mark.asyncio
async def test_ignores_clean_json_and_non_json():
    srv = _server({
        "/ok": (b'{"items":[{"id":1,"name":"widget"}]}', "application/json"),
        "/html": (b'<html>password: hunter2</html>', "text/html"),
    })
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        async with httpx.AsyncClient() as client:
            ctx = AttackContext(base, client=client, concurrency=4)
            ctx.add_endpoint(Endpoint(url=base + "/ok", method="GET"))
            ctx.add_endpoint(Endpoint(url=base + "/html", method="GET"))
            await DataExposureAgent().run(ctx)
        assert [f for f in ctx.findings if f.detector == "dataexposure"] == []
    finally:
        srv.shutdown()
