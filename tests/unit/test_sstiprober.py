"""Tests for SSTIProber — server-side template injection detection."""

from __future__ import annotations

import httpx
import pytest

from argus.agents.base import AttackContext, Endpoint
from argus.agents.sstiprober import SSTIProber


@pytest.mark.asyncio
async def test_confirms_ssti_when_payload_is_evaluated():
    def handler(request):
        query = str(request.url.query)
        if "7%2A%277%27" in query or "7*'7'" in query:
            # {{7*'7'}} evaluated by Jinja2 -> the string "7" repeated 7 times.
            return httpx.Response(200, text="result: 7777777")
        return httpx.Response(200, text="result: nothing here")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ctx = AttackContext("http://t", client=client)
    ctx.add_endpoint(Endpoint(url="http://t/render", method="GET", params=["name"]))

    report = await SSTIProber().run(ctx)

    assert report.findings == 1
    finding = ctx.findings[0]
    assert finding.detector == "sstiprober"
    assert finding.severity.value == "CRITICAL"


@pytest.mark.asyncio
async def test_no_finding_when_payload_is_only_reflected_not_evaluated():
    def handler(request):
        query = str(request.url.query)
        # Echo whatever was sent verbatim -- classic reflection, not SSTI.
        import urllib.parse
        params = urllib.parse.parse_qs(query)
        name = params.get("name", [""])[0]
        return httpx.Response(200, text=f"you searched for: {name}")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ctx = AttackContext("http://t", client=client)
    ctx.add_endpoint(Endpoint(url="http://t/search", method="GET", params=["name"]))

    await SSTIProber().run(ctx)

    assert ctx.findings == []


@pytest.mark.asyncio
async def test_no_finding_when_marker_already_present_in_control_response():
    # A page that always shows "49" (e.g. "49 results found") regardless of
    # input must not false-positive just because the marker happens to match.
    def handler(request):
        return httpx.Response(200, text="49 results found for your query")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ctx = AttackContext("http://t", client=client)
    ctx.add_endpoint(Endpoint(url="http://t/search", method="GET", params=["q"]))

    await SSTIProber().run(ctx)

    assert ctx.findings == []


@pytest.mark.asyncio
async def test_no_targets_completes_cleanly():
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    ctx = AttackContext("http://t", client=client)  # no endpoints seeded

    report = await SSTIProber().run(ctx)

    assert report.status == "complete"
    assert report.findings == 0
