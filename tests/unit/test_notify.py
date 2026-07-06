"""Tests for the scan-complete webhook notification."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from argus.models import Finding, ScanResult, Severity
from argus.notify import notify_scan_complete


def _sample_result() -> ScanResult:
    r = ScanResult(target="repo", phase="scan")
    r.add(Finding(title="SQLi", severity=Severity.CRITICAL, category="injection"))
    r.add(Finding(title="Missing header", severity=Severity.LOW, category="misc"))
    return r


def test_notify_returns_false_when_no_url():
    assert notify_scan_complete("", _sample_result()) is False


class _CaptureHandler(BaseHTTPRequestHandler):
    received: list = []

    def log_message(self, *a):
        return

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length)
        _CaptureHandler.received.append(body.decode())
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')


@pytest.fixture
def capture_server():
    _CaptureHandler.received = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _CaptureHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}/webhook"
    srv.shutdown()
    srv.server_close()


def test_notify_posts_summary_with_slack_and_discord_keys(capture_server):
    ok = notify_scan_complete(capture_server, _sample_result())
    assert ok is True
    assert len(_CaptureHandler.received) == 1

    import json
    payload = json.loads(_CaptureHandler.received[0])
    assert "text" in payload and "content" in payload
    assert payload["text"] == payload["content"]
    assert "repo" in payload["text"]
    assert "1 critical" in payload["text"]


def test_notify_returns_false_on_unreachable_host():
    ok = notify_scan_complete("http://127.0.0.1:1/webhook", _sample_result())
    assert ok is False
