"""Regression guard for the SPA-fallback false-positive bug class (v1.2.12).

Five agents (ReconBot, CrawlerBot, AuthzTester, HeaderPoker, plus Injector's
timing baseline) reported fake findings because they trusted a raw HTTP
status code as proof a path/response was genuine, without confirming it was
actually distinct from what a catch-all handler would also produce. The fix
was two shared helpers in argus/agents/base.py — this test doesn't re-verify
the fix's correctness (test_agents.py / test_benchmark.py's clean_spa case
already do that end-to-end), it guards against someone *removing* the usage
later: e.g. a refactor that drops the import while leaving the status-code
check behind, silently reintroducing the exact bug.

Any new agent added to AGENTS_THAT_PROBE_PATH_EXISTENCE without wiring in
fetch_fallback_baseline/response_matches_fallback should be treated as a real
finding from this test, not a false alarm to silence.
"""

from __future__ import annotations

import inspect

from argus.agents import authztester, crawlerbot, headerpoker, reconbot

# Agents whose core technique is "probe a candidate path/header value and
# trust the response is genuine based on its HTTP status" — the exact
# pattern a catch-all/SPA-fallback handler defeats unless a baseline
# comparison confirms the response is actually distinct.
AGENTS_THAT_PROBE_PATH_EXISTENCE = {
    "reconbot": reconbot,
    "crawlerbot": crawlerbot,
    "authztester": authztester,
    "headerpoker": headerpoker,
}


def test_every_path_probing_agent_imports_the_baseline_helpers():
    for name, module in AGENTS_THAT_PROBE_PATH_EXISTENCE.items():
        source = inspect.getsource(module)
        uses_baseline = "fetch_fallback_baseline" in source or "response_matches_fallback" in source
        assert uses_baseline, (
            f"{name} probes path/header existence but no longer references "
            f"fetch_fallback_baseline/response_matches_fallback — this is the exact "
            f"shape of the bug fixed in v1.2.12 (fake findings against a "
            f"catch-all/SPA-fallback target). See argus/agents/base.py."
        )


def test_base_still_exports_the_baseline_helpers():
    from argus.agents.base import fetch_fallback_baseline, response_matches_fallback

    assert callable(fetch_fallback_baseline)
    assert callable(response_matches_fallback)
