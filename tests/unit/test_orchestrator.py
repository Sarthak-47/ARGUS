"""When ReconBot can't reach the target at all, the run should stop right there
instead of running every other agent against a host we already know is dead —
each of which would otherwise burn its own timeout for nothing.
"""

from __future__ import annotations

import pytest

from argus.llm.orchestrator import run_attack_async


@pytest.mark.asyncio
async def test_unreachable_target_short_circuits_after_recon():
    # A closed local port refuses the connection immediately (no timeout wait).
    findings, reports = await run_attack_async(
        "http://127.0.0.1:1", use_callback=False, concurrency=2,
    )

    assert findings == []
    assert len(reports) == 1
    assert reports[0].agent == "ReconBot"
    assert reports[0].status == "error"
    assert "unreachable" in reports[0].notes[0]
