"""Shared attack-agent infrastructure: context, endpoint model, base class.

Every Phase-2 agent receives an :class:`AttackContext` (the async HTTP client, the
discovered attack surface, configuration, a callback server for blind detection,
and a sink for findings) and implements ``async run(ctx)``. The base class offers
safe request helpers that never raise on network errors — an agent should degrade,
not crash, when the target misbehaves.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

import httpx

from argus.models import Finding, Severity

# Endpoints that destroy the current session when requested. Attacking them has
# no security value, but a single GET mid-run logs every subsequent agent out —
# silently gutting all authenticated testing after it (on DVWA this made the
# post-login attack agents miss everything behind auth). We never crawl or
# attack these; auth stays live for the whole run.
_SESSION_DESTROYING = re.compile(r"(?:^|/)(?:log[-_]?out|log[-_]?off|sign[-_]?out|signoff)(?:[./]|$)", re.IGNORECASE)


def _destroys_session(url: str) -> bool:
    return bool(_SESSION_DESTROYING.search(urlparse(url).path))


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
        max_requests: int | None = None,
        prior_findings: list[Finding] | None = None,
        callback=None,
        provider=None,
        on_event: Callable[[str, str, str], None] | None = None,
        identity_a=None,
        identity_b=None,
    ):
        self.base_url = base_url.rstrip("/")
        # The attack surface is deliberately constrained to exactly the origin
        # the operator supplied.  A target page may contain third-party links,
        # forms, redirects, or poisoned API-spec entries; those must never turn
        # into requests against a system outside the engagement's scope.
        self._origin = self._origin_of(self.base_url)
        self.client = client
        # Two authenticated identities enable cross-user authorization testing
        # (BOLA/BFLA). ``identity_a`` is the session already applied to ``client``;
        # ``identity_b`` is a second, ideally lower-privilege, account.
        self.identity_a = identity_a
        self.identity_b = identity_b
        self.endpoints: dict[str, Endpoint] = {}
        self.findings: list[Finding] = []
        self.prior_findings = prior_findings or []
        self.recon: dict[str, Any] = {}
        self.callback = callback                      # CallbackServer | None (blind detection)
        self.callback_host = getattr(callback, "base_url", None)
        self.provider = provider                       # BaseProvider | None — LLM access for agents
        self.semaphore = asyncio.Semaphore(concurrency)
        self._on_event = on_event
        self.requests_sent = 0
        # A hard ceiling on total requests against the target, independent of
        # concurrency (which only bounds how many run *at once*, not how many
        # run in total) — a safety backstop against a runaway agent or a
        # misconfigured deep scan hammering someone else's production system.
        self.max_requests = max_requests
        self._budget_exhausted_notified = False

    # ----- attack surface -----
    @staticmethod
    def _origin_of(url: str) -> tuple[str, str] | None:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return None
        return parsed.scheme.lower(), parsed.netloc.lower()

    def in_scope(self, url: str) -> bool:
        """Whether ``url`` is on the exact user-authorized origin."""
        return self._origin is not None and self._origin_of(url) == self._origin

    def add_endpoint(self, ep: Endpoint) -> None:
        # Never add a session-destroying endpoint to the surface — no agent
        # should crawl or attack it and log the whole run out.
        if not self.in_scope(ep.url) or _destroys_session(ep.url):
            return
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
        # Refuse to request a session-destroying endpoint even if one slips
        # through as a direct URL (e.g. a crawl following a logout link) —
        # this is the last line keeping the authenticated session alive.
        if not ctx.in_scope(url) or _destroys_session(url):
            return None
        if ctx.max_requests is not None and ctx.requests_sent >= ctx.max_requests:
            if not ctx._budget_exhausted_notified:
                ctx._budget_exhausted_notified = True
                ctx.emit("engine", f"request budget of {ctx.max_requests} reached — "
                                    "remaining probes are being skipped", "crit")
            return None
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

    # ----- LLM access (opt-in; most agents never touch this) -----
    async def complete(self, ctx: AttackContext, system: str, user: str, *, json_mode: bool = False) -> str | None:
        """Call the configured LLM provider, or return None if none is set / it fails.

        ``BaseProvider.complete`` is synchronous (blocking httpx calls), so it runs
        in a thread to avoid stalling the event loop other agents share.
        """
        if ctx.provider is None:
            return None
        from argus.llm.provider import LLMError

        try:
            result = await asyncio.to_thread(ctx.provider.complete, system, user, json_mode=json_mode)
        except LLMError:
            return None
        return result.text


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


# Headers that must never appear verbatim in a captured PoC — a security tool must
# not leak the very credentials it used while proving a vulnerability.
_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key"}
_POC_BODY_LIMIT = 2000


def build_http_poc(method: str, url: str, resp: httpx.Response, *, body: str | None = None) -> dict[str, str]:
    """Build a reproducible proof-of-concept from a confirmed HTTP exchange.

    Captures a runnable curl command plus the raw request/response so a confirmed
    finding is provable, not just asserted — sensitive headers are redacted and the
    response body is truncated so reports stay a sane size and never echo secrets.
    """
    headers: dict[str, str] = {}
    req = getattr(resp, "request", None)
    if req is not None:
        for k, v in req.headers.items():
            headers[k] = "***REDACTED***" if k.lower() in _SENSITIVE_HEADERS else v

    curl_parts = ["curl", "-i", "-X", method, f"'{url}'"]
    for k, v in headers.items():
        curl_parts.append(f"-H '{k}: {v}'")
    if body:
        curl_parts.append(f"--data '{body[:500]}'")

    header_lines = "\n".join(f"{k}: {v}" for k, v in headers.items())
    request_text = f"{method} {url}" + (f"\n{header_lines}" if header_lines else "")

    status = getattr(resp, "status_code", "?")
    resp_body = (getattr(resp, "text", "") or "")[:_POC_BODY_LIMIT]
    response_text = f"HTTP {status}\n{resp_body}"

    return {
        "type": "http",
        "curl": " ".join(curl_parts),
        "request": request_text,
        "response": response_text,
    }
