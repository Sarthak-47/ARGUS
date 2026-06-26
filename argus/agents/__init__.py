"""Phase 2 — the attack agent swarm.

Each agent subclasses BaseAgent and actively probes a running target. The
orchestrator decides which agents run, in what order, against which endpoints.
"""

from argus.agents.base import AttackContext, BaseAgent, Endpoint

__all__ = ["AttackContext", "BaseAgent", "Endpoint"]
