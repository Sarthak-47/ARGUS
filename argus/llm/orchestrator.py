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
from argus.agents.base import AgentReport, AttackContext
from argus.agents.crawlerbot import CrawlerBot
from argus.agents.csrfhunter import CSRFHunter
from argus.agents.fileattacker import FileAttacker
from argus.agents.fuzzer import Fuzzer
from argus.agents.graphqlagent import GraphQLAgent
from argus.agents.headerpoker import HeaderPoker
from argus.agents.idorhunter import IDORHunter
from argus.agents.injector import Injector
from argus.agents.mcpsecurity import MCPSecurityAgent
from argus.agents.racecondition import RaceCondition
from argus.agents.reconbot import ReconBot
from argus.agents.ssrfprober import SSRFProber
from argus.agents.websocketagent import WebSocketAgent
from argus.agents.xsshunter import XSSHunter
from argus.models import Finding

# The full 13-agent swarm (ReconBot runs separately, first).
AGENT_REGISTRY = {
    "reconbot": ReconBot,
    "crawlerbot": CrawlerBot,
    "injector": Injector,
    "authbreaker": AuthBreaker,
    "idorhunter": IDORHunter,
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
}

# Default priority order for the agents we run after recon. CrawlerBot runs early
# to widen the surface; high-signal exploit agents next; fuzz/race last (noisier).
_DEFAULT_ORDER = [
    "crawlerbot", "injector", "authbreaker", "idorhunter", "xsshunter",
    "ssrfprober", "headerpoker", "csrfhunter", "fileattacker", "graphqlagent",
    "websocketagent", "mcpsecurity", "fuzzer", "racecondition",
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
    on_event=None,
) -> tuple[list[Finding], list[AgentReport]]:
    """Run recon + selected agents against ``base_url``. Returns (findings, reports)."""
    from argus.sandbox.callback_server import CallbackServer

    prior = prior_findings or []
    reports: list[AgentReport] = []

    callback = None
    if use_callback:
        try:
            callback = CallbackServer().start()
        except OSError:
            callback = None

    headers = {"User-Agent": "Argus/0.1 (+https://github.com/Sarthak-47/ARGUS)"}
    try:
        async with httpx.AsyncClient(
            follow_redirects=True, headers=headers, verify=False, timeout=15.0
        ) as client:
            ctx = AttackContext(
                base_url,
                client=client,
                concurrency=concurrency,
                prior_findings=prior,
                callback=callback,
                provider=provider,
                on_event=on_event,
            )

            # 1) Recon always first
            recon = ReconBot()
            reports.append(await recon.run(ctx))

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

            return ctx.findings, reports
    finally:
        if callback is not None:
            callback.stop()


def run_attack_sync(base_url: str, **kwargs):
    """Blocking wrapper around :func:`run_attack_async` for the CLI."""
    return asyncio.run(run_attack_async(base_url, **kwargs))
