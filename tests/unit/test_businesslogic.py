"""Tests for BusinessLogicAgent: no-provider no-op, and a confirmed abuse sequence."""

from __future__ import annotations

import json

import httpx
import pytest

from argus.agents.base import AttackContext, Endpoint
from argus.agents.businesslogic import BusinessLogicAgent
from argus.llm.provider import LLMResult


class _FakePlanProvider:
    name = "fake"
    model = "fake-model"

    def __init__(self, plan: list[dict]):
        self._plan = plan

    def complete(self, system, user, *, json_mode=False):
        return LLMResult(json.dumps(self._plan), self.name, self.model)


_STACKABLE_COUPON_PLAN = [{
    "title": "Coupon reuse",
    "rationale": "A single-use coupon is applied twice in a row.",
    "steps": [
        {"method": "POST", "path": "/api/redeem", "body": {"code": "SAVE10"}},
        {"method": "POST", "path": "/api/redeem", "body": {"code": "SAVE10"}},
    ],
    "expect_vulnerable_if": "both calls return 200",
}]


def _mock_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_noop_without_provider():
    async def handler(request):
        return httpx.Response(200)

    async with _mock_client(handler) as client:
        ctx = AttackContext("http://t", client=client, provider=None)
        ctx.add_endpoint(Endpoint(url="http://t/api/redeem", method="POST"))
        report = await BusinessLogicAgent().run(ctx)

    assert report.status == "complete"
    assert report.findings == 0
    assert report.requests_sent == 0  # never touched the target at all
    assert ctx.findings == []


@pytest.mark.asyncio
async def test_confirms_abuse_when_every_replayed_step_succeeds():
    async def handler(request):
        if request.url.path == "/api/redeem":
            return httpx.Response(200, json={"status": "redeemed"})
        return httpx.Response(404)

    provider = _FakePlanProvider(_STACKABLE_COUPON_PLAN)
    async with _mock_client(handler) as client:
        ctx = AttackContext("http://t", client=client, provider=provider)
        ctx.add_endpoint(Endpoint(url="http://t/api/redeem", method="POST"))
        report = await BusinessLogicAgent().run(ctx)

    assert report.status == "complete"
    findings = [f for f in ctx.findings if f.detector == "businesslogic"]
    assert len(findings) == 1
    f = findings[0]
    assert f.confirmed is True
    assert "redeem" in f.evidence.lower()
    assert f.poc and f.poc.get("curl", "").startswith("curl")


@pytest.mark.asyncio
async def test_no_finding_when_llm_invents_a_path_on_an_spa_fallback_site():
    # Regression: the LLM proposes step paths itself, unconstrained by the
    # discovered endpoint list, and readily invents plausible admin-panel
    # paths (jenkins/, phpmyadmin/, actuator, swagger-ui) that were never
    # actually found. Reproduced live against a real site: a catch-all
    # handler (an SPA fallback) made every one of those invented paths
    # "succeed" with an identical response, reported as a confirmed HIGH
    # "Business logic" finding. The only correct result here is none.
    fallback_body = "<!doctype html>" + "x" * 2000  # a realistic SPA index.html

    async def handler(request):
        return httpx.Response(200, text=fallback_body, headers={"content-type": "text/html"})

    invented_plan = [{
        "title": "Jenkins Access",
        "rationale": "An exposed CI panel might allow unauthenticated access.",
        "steps": [
            {"method": "GET", "path": "/jenkins/"},
            {"method": "GET", "path": "/jenkins/"},
        ],
        "expect_vulnerable_if": "the panel is reachable without authentication",
    }]
    provider = _FakePlanProvider(invented_plan)
    async with _mock_client(handler) as client:
        ctx = AttackContext("http://t", client=client, provider=provider)
        ctx.add_endpoint(Endpoint(url="http://t/", method="GET"))  # the only real endpoint
        report = await BusinessLogicAgent().run(ctx)

    assert report.status == "complete"
    assert [f for f in ctx.findings if f.detector == "businesslogic"] == []


@pytest.mark.asyncio
async def test_corrects_method_to_match_known_endpoint():
    """Regression test for a real observation with a live local model (qwen2.5:7b):
    it proposed GET for a step even though the endpoint list explicitly says the
    real endpoint is POST-only. The agent must use recon's known method, not the
    model's guess — otherwise a real vulnerability silently 404s."""
    seen_methods = []

    async def handler(request):
        if request.url.path == "/api/redeem":
            seen_methods.append(request.method)
            if request.method == "POST":
                return httpx.Response(200, json={"status": "redeemed"})
            return httpx.Response(404)  # GET is not handled — the real bug being guarded against
        # Anything else (including the agent's own fallback-baseline probe)
        # is deliberately distinct from the real endpoint's response, so it
        # can't be mistaken for a target-wide catch-all.
        return httpx.Response(404, text="not found")

    plan = [{
        "title": "Coupon reuse",
        "rationale": "replay",
        "steps": [
            {"method": "GET", "path": "/api/redeem", "body": {"code": "SAVE10"}},
            {"method": "GET", "path": "/api/redeem", "body": {"code": "SAVE10"}},
        ],
        "expect_vulnerable_if": "both calls return 200",
    }]
    provider = _FakePlanProvider(plan)
    async with _mock_client(handler) as client:
        ctx = AttackContext("http://t", client=client, provider=provider)
        ctx.add_endpoint(Endpoint(url="http://t/api/redeem", method="POST"))
        await BusinessLogicAgent().run(ctx)

    assert seen_methods == ["POST", "POST"]  # corrected from the model's GET
    assert any(f.detector == "businesslogic" for f in ctx.findings)


@pytest.mark.asyncio
async def test_confirms_abuse_when_model_returns_bare_object_not_array():
    """Regression test for a real observation with a live local model (qwen2.5:7b):
    it ignored the 'return a JSON array' instruction and returned a single bare
    object (one plan, no surrounding []) when it only found one plausible abuse.
    The parser must accept that instead of silently discarding a real finding."""
    async def handler(request):
        if request.url.path == "/api/redeem":
            return httpx.Response(200, json={"status": "redeemed"})
        return httpx.Response(404)

    bare_object_plan = _STACKABLE_COUPON_PLAN[0]  # a dict, not wrapped in a list
    provider = _FakePlanProvider(bare_object_plan)
    async with _mock_client(handler) as client:
        ctx = AttackContext("http://t", client=client, provider=provider)
        ctx.add_endpoint(Endpoint(url="http://t/api/redeem", method="POST"))
        report = await BusinessLogicAgent().run(ctx)

    assert report.status == "complete"
    findings = [f for f in ctx.findings if f.detector == "businesslogic"]
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_does_not_confirm_when_a_step_is_rejected():
    async def handler(request):
        # First redeem succeeds, second is correctly rejected -> NOT vulnerable.
        if request.url.path == "/api/redeem":
            body = request.content.decode()
            return httpx.Response(200 if "1" in body else 409)
        return httpx.Response(404)

    plan = [{
        "title": "Coupon reuse",
        "rationale": "replay",
        "steps": [
            {"method": "POST", "path": "/api/redeem", "body": {"attempt": "1"}},
            {"method": "POST", "path": "/api/redeem", "body": {"attempt": "2"}},
        ],
        "expect_vulnerable_if": "both calls return 200",
    }]
    provider = _FakePlanProvider(plan)
    async with _mock_client(handler) as client:
        ctx = AttackContext("http://t", client=client, provider=provider)
        ctx.add_endpoint(Endpoint(url="http://t/api/redeem", method="POST"))
        await BusinessLogicAgent().run(ctx)

    assert ctx.findings == []


@pytest.mark.asyncio
async def test_no_endpoints_short_circuits():
    async def handler(request):
        return httpx.Response(200)

    provider = _FakePlanProvider(_STACKABLE_COUPON_PLAN)
    async with _mock_client(handler) as client:
        ctx = AttackContext("http://t", client=client, provider=provider)
        report = await BusinessLogicAgent().run(ctx)

    assert report.status == "complete"
    assert report.findings == 0
    assert ctx.findings == []
