"""Tests for DomXSSHunter. Skipped entirely if the optional `browser` extra
(playwright) isn't installed — this agent is opt-in and CI's default matrix
won't have it, so these tests must degrade to a clean skip, not a failure.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import httpx
import pytest

pytest.importorskip("playwright")

from argus.agents.base import AttackContext, Endpoint  # noqa: E402
from argus.agents.domxss import DomXSSHunter, async_playwright  # noqa: E402

_PAGE = b"""<!doctype html><html><body><div id="out"></div>
<script>
  var params = new URLSearchParams(location.search);
  document.getElementById('out').innerHTML = params.get('q') || '';
</script>
</body></html>"""


class _DomXSSHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return

    def do_GET(self):  # noqa: N802
        u = urlparse(self.path)
        if u.path == "/vuln":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(_PAGE)
            return
        self.send_response(404)
        self.end_headers()


@pytest.fixture
def dom_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _DomXSSHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()
    srv.server_close()


def test_async_playwright_importable():
    assert async_playwright is not None


@pytest.mark.asyncio
async def test_domxss_confirms_real_dom_sink(dom_server):
    """The genuine end-to-end case: a real DOM XSS sink (innerHTML from a query
    param), caught by actually running a headless browser against it — not a
    pattern guess, an executed proof."""
    async with httpx.AsyncClient() as client:
        ctx = AttackContext(dom_server, client=client)
        ctx.add_endpoint(Endpoint(url=f"{dom_server}/vuln", method="GET", params=["q"]))
        report = await DomXSSHunter().run(ctx)

    assert report.status == "complete"
    findings = [f for f in ctx.findings if f.detector == "domxss:confirmed"]
    assert len(findings) == 1
    assert findings[0].confirmed is True
    assert findings[0].poc["type"] == "browser"
    assert "/vuln" in findings[0].poc["url"]


@pytest.mark.asyncio
async def test_domxss_no_targets_short_circuits():
    async with httpx.AsyncClient() as client:
        ctx = AttackContext("http://t", client=client)
        report = await DomXSSHunter().run(ctx)

    assert report.status == "complete"
    assert report.findings == 0
    assert report.requests_sent == 0
