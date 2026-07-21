"""Attack orchestration loop.

ReconBot always runs first to map the surface. The orchestrator then chooses an
agent order — biased by any Phase-1 findings passed in (e.g. prior JWT issues push
AuthBreaker earlier) — runs the selected agents, and collects findings and
per-agent reports. The interface is deliberately simple now; the adaptive,
LLM-in-the-loop version layers on top of this without changing callers.
"""

from __future__ import annotations

import asyncio

import httpx

from argus.agents.authbreaker import AuthBreaker
from argus.agents.authztester import AuthzTester
from argus.agents.base import AgentReport, AttackContext
from argus.agents.businesslogic import BusinessLogicAgent
from argus.agents.crawlerbot import CrawlerBot
from argus.agents.csrfhunter import CSRFHunter
from argus.agents.dataexposure import DataExposureAgent
from argus.agents.domxss import DomXSSHunter
from argus.agents.fileattacker import FileAttacker
from argus.agents.fuzzer import Fuzzer
from argus.agents.graphqlagent import GraphQLAgent
from argus.agents.headerpoker import HeaderPoker
from argus.agents.idorhunter import IDORHunter
from argus.agents.injector import Injector
from argus.agents.mcpsecurity import MCPSecurityAgent
from argus.agents.promptinjection import PromptInjectionAgent
from argus.agents.racecondition import RaceCondition
from argus.agents.reconbot import ReconBot
from argus.agents.ssrfprober import SSRFProber
from argus.agents.sstiprober import SSTIProber
from argus.agents.websocketagent import WebSocketAgent
from argus.agents.xsshunter import XSSHunter
from argus.models import Finding

# The full agent swarm (ReconBot runs separately, first).
AGENT_REGISTRY = {
    "reconbot": ReconBot,
    "crawlerbot": CrawlerBot,
    "injector": Injector,
    "sstiprober": SSTIProber,
    "authbreaker": AuthBreaker,
    "idorhunter": IDORHunter,
    "authztester": AuthzTester,
    "xsshunter": XSSHunter,
    "ssrfprober": SSRFProber,
    "headerpoker": HeaderPoker,
    "csrfhunter": CSRFHunter,
    "fileattacker": FileAttacker,
    "fuzzer": Fuzzer,
    "racecondition": RaceCondition,
    "graphqlagent": GraphQLAgent,
    "websocketagent": WebSocketAgent,
    "mcpsecurity": MCPSecurityAgent,
    "promptinjection": PromptInjectionAgent,
    "businesslogic": BusinessLogicAgent,
    "dataexposure": DataExposureAgent,
    "domxss": DomXSSHunter,
}

# Default priority order for the agents we run after recon. CrawlerBot runs early
# to widen the surface; high-signal exploit agents next; fuzz/race last (noisier).
# BusinessLogicAgent sits late so the surface it reasons over is as complete as
# possible — it silently no-ops without a configured LLM provider (see its docstring).
# DomXSSHunter is deliberately NOT in this list — it needs the optional `browser`
# extra (Playwright + a Chromium download) and only runs via --agents domxss.
_DEFAULT_ORDER = [
    "crawlerbot", "injector", "sstiprober", "authbreaker", "idorhunter", "authztester", "xsshunter",
    "ssrfprober", "headerpoker", "csrfhunter", "fileattacker", "graphqlagent",
    "websocketagent", "mcpsecurity", "promptinjection", "businesslogic",
    "dataexposure", "fuzzer", "racecondition",
]


def _select_order(requested: list[str] | None, prior: list[Finding]) -> list[str]:
    """Resolve which post-recon agents to run and in what order."""
    if requested:
        order = [a for a in requested if a in AGENT_REGISTRY and a != "reconbot"]
    else:
        order = list(_DEFAULT_ORDER)

    # Bias: if Phase 1 already flagged auth/JWT issues, run AuthBreaker first.
    has_auth = any(f.category in ("auth",) or "jwt" in f.title.lower() for f in prior)
    if has_auth and "authbreaker" in order:
        order.remove("authbreaker")
        order.insert(0, "authbreaker")
    return order


async def run_attack_async(
    base_url: str,
    *,
    requested_agents: list[str] | None = None,
    prior_findings: list[Finding] | None = None,
    use_callback: bool = True,
    provider=None,
    concurrency: int = 10,
    max_requests: int | None = None,
    rate_limit: float | None = None,
    request_log_path: str | None = None,
    on_event=None,
    seed_endpoints=None,
    auth=None,
    identity_b=None,
    callback_advertise_host: str | None = None,
) -> tuple[list[Finding], list[AgentReport], list]:
    """Run recon + selected agents against ``base_url``.

    ``callback_advertise_host`` — set this to "host.docker.internal" when
    ``base_url`` is a target Argus itself sandboxed in Docker; otherwise a
    blind SSRF/SQLi/XSS payload's callback URL points at the container's own
    loopback, never reaches this process, and the vulnerability silently
    reports as a false negative. Leave unset for a plain external/local URL,
    where the target really can reach 127.0.0.1 back to us.

    ``seed_endpoints`` (from a persisted surface inventory) pre-populate the
    attack surface before recon runs, so later agents benefit from endpoints a
    prior run found even if this run's recon misses them.

    ``request_log_path``, if given, writes a JSON array of every request sent
    (agent, method, url, status, latency_ms, timestamp) once the run
    completes — for diagnosing a false positive or a slow run without
    manually re-probing candidate paths by hand.

    Returns (findings, reports, discovered_endpoints).
    """
    from argus.sandbox.callback_server import CallbackServer

    prior = prior_findings or []
    reports: list[AgentReport] = []

    callback = None
    if use_callback:
        try:
            callback = CallbackServer(advertise_host=callback_advertise_host).start()
        except OSError:
            callback = None

    headers = {"User-Agent": "Argus/0.1 (+https://github.com/Sarthak-47/ARGUS)"}
    try:
        # Do not follow a target-controlled redirect to a different origin.
        # Scope checks in BaseAgent provide a second line of defence for all
        # explicit requests, while TLS verification remains enabled by default.
        async with httpx.AsyncClient(
            follow_redirects=False, headers=headers, timeout=15.0
        ) as client:
            ctx = AttackContext(
                base_url,
                client=client,
                concurrency=concurrency,
                max_requests=max_requests,
                rate_limit=rate_limit,
                log_requests=bool(request_log_path),
                prior_findings=prior,
                callback=callback,
                provider=provider,
                on_event=on_event,
                identity_a=auth,
                identity_b=identity_b,
            )

            # 0a) Authenticate the shared client, if configured — every agent
            # (and ReconBot's crawl) then acts as the logged-in user.
            if auth is not None:
                from argus.auth import AuthError

                try:
                    summary = await auth.apply(client)
                    ctx.emit("auth", f"authenticated session: {summary}")
                except AuthError as exc:
                    ctx.emit("auth", f"authentication failed: {exc}", "crit")
                    raise

            # 0) Seed from the persisted surface inventory, if any.
            if seed_endpoints:
                for ep in seed_endpoints:
                    ctx.add_endpoint(ep)
                ctx.emit("surface", f"seeded {len(seed_endpoints)} endpoint(s) from prior scans")

            # 1) Recon always first
            recon = ReconBot()
            recon_report = await recon.run(ctx)
            reports.append(recon_report)

            if recon_report.status == "error":
                # Recon couldn't even reach the target — every other agent would
                # just re-discover the same dead connection. Stop here instead of
                # burning a timeout per agent against a host we know is down.
                _write_request_log(ctx, request_log_path)
                return ctx.findings, reports, ctx.endpoint_list()

            # 2) Ordered post-recon agents
            order = _select_order(requested_agents, prior)
            for name in order:
                agent_cls = AGENT_REGISTRY[name]
                agent = agent_cls()
                try:
                    reports.append(await agent.run(ctx))
                except Exception as exc:  # an agent must never sink the whole run
                    reports.append(AgentReport(agent=agent.name, status="error", notes=[str(exc)]))
                    ctx.emit(agent.name, f"agent error: {exc}", "crit")

            _write_request_log(ctx, request_log_path)
            return ctx.findings, reports, ctx.endpoint_list()
    finally:
        if callback is not None:
            callback.stop()


def _write_request_log(ctx: AttackContext, path: str | None) -> None:
    if not path:
        return
    import json as _json

    with open(path, "w", encoding="utf-8") as f:
        _json.dump(ctx.request_log, f, indent=2)


def run_attack_sync(base_url: str, **kwargs):
    """Blocking wrapper around :func:`run_attack_async` for the CLI."""
    return asyncio.run(run_attack_async(base_url, **kwargs))
