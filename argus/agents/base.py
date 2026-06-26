"""Shared attack-agent infrastructure: context, endpoint model, base class.

Every Phase-2 agent receives an :class:`AttackContext` (the async HTTP client, the
discovered attack surface, configuration, a callback server for blind detection,
and a sink for findings) and implements ``async run(ctx)``. The base class offers
safe request helpers that never raise on network errors — an agent should degrade,
not crash, when the target misbehaves.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

import httpx

from argus.models import Finding, Severity


@dataclass
class Endpoint:
    """A discovered request target plus the inputs an agent can manipulate."""

    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)   # query/body parameter names
    content_type: str | None = None
    source: str = "crawl"                              # how it was discovered
    sample_status: int | None = None

    def key(self) -> str:
        return f"{self.method} {self.url}"


@dataclass
class AgentReport:
    """A single agent's run summary, surfaced to the live feed / orchestrator."""

    agent: str
    requests_sent: int = 0
    findings: int = 0
    status: str = "complete"          # queued | running | complete | error
    notes: list[str] = field(default_factory=list)


class AttackContext:
    """Mutable state shared across a single attack run."""

    def __init__(
        self,
        base_url: str,
        *,
        client: httpx.AsyncClient,
        concurrency: int = 10,
        prior_findings: list[Finding] | None = None,
        callback_host: str | None = None,
        on_event: Callable[[str, str, str], None] | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.client = client
        self.endpoints: dict[str, Endpoint] = {}
        self.findings: list[Finding] = []
        self.prior_findings = prior_findings or []
        self.recon: dict[str, Any] = {}
        self.callback_host = callback_host
        self.semaphore = asyncio.Semaphore(concurrency)
        self._on_event = on_event
        self.requests_sent = 0

    # ----- attack surface -----
    def add_endpoint(self, ep: Endpoint) -> None:
        existing = self.endpoints.get(ep.key())
        if existing:
            for p in ep.params:
                if p not in existing.params:
                    existing.params.append(p)
        else:
            self.endpoints[ep.key()] = ep

    def endpoint_list(self) -> list[Endpoint]:
        return list(self.endpoints.values())

    # ----- findings + feed -----
    def report(self, finding: Finding) -> None:
        finding.confirmed = True
        self.findings.append(finding)
        self.emit(finding.detector, f"{finding.title}", "crit"
                  if finding.severity in (Severity.CRITICAL, Severity.HIGH) else "ok")

    def emit(self, agent: str, text: str, sev: str = "ok") -> None:
        """Push a line to the live feed (agent, text, severity tag)."""
        if self._on_event:
            self._on_event(agent.upper(), text, sev)


class BaseAgent:
    """Base class for all attack agents."""

    name: str = "agent"
    description: str = ""

    async def run(self, ctx: AttackContext) -> AgentReport:  # pragma: no cover
        raise NotImplementedError

    # ----- safe HTTP helpers -----
    async def _request(
        self,
        ctx: AttackContext,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response | None:
        """Perform a request under the concurrency limit; return None on error."""
        kwargs.setdefault("timeout", 15.0)
        async with ctx.semaphore:
            try:
                resp = await ctx.client.request(method, url, **kwargs)
                ctx.requests_sent += 1
                return resp
            except httpx.HTTPError:
                ctx.requests_sent += 1
                return None

    async def get(self, ctx: AttackContext, url: str, **kwargs: Any) -> httpx.Response | None:
        return await self._request(ctx, "GET", url, **kwargs)

    async def post(self, ctx: AttackContext, url: str, **kwargs: Any) -> httpx.Response | None:
        return await self._request(ctx, "POST", url, **kwargs)

    async def timed_request(
        self, ctx: AttackContext, method: str, url: str, **kwargs: Any
    ) -> tuple[httpx.Response | None, float]:
        """Like _request but also returns elapsed seconds (for time-based tests)."""
        start = time.perf_counter()
        resp = await self._request(ctx, method, url, **kwargs)
        return resp, time.perf_counter() - start


async def gather_limited(coros: list[Awaitable], limit: int = 20) -> list:
    """Run awaitables with a concurrency cap, swallowing individual failures."""
    sem = asyncio.Semaphore(limit)

    async def _wrap(c):
        async with sem:
            try:
                return await c
            except Exception:
                return None

    return await asyncio.gather(*(_wrap(c) for c in coros))
