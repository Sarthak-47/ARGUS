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
    findings, reports, endpoints = await run_attack_async(
        "http://127.0.0.1:1", use_callback=False, concurrency=2,
    )

    assert findings == []
    assert len(reports) == 1
    assert reports[0].agent == "ReconBot"
    assert reports[0].status == "error"
    assert "unreachable" in reports[0].notes[0]
    assert endpoints == []


@pytest.mark.asyncio
async def test_request_log_path_writes_even_on_the_early_recon_error_return(tmp_path):
    # request_log_path must be honoured on *every* return path, including
    # the short-circuit above — not just the normal end-of-run return.
    log_path = tmp_path / "requests.json"
    await run_attack_async(
        "http://127.0.0.1:1", use_callback=False, concurrency=2,
        request_log_path=str(log_path),
    )
    assert log_path.exists()

    import json

    entries = json.loads(log_path.read_text(encoding="utf-8"))
    assert isinstance(entries, list)
    assert len(entries) >= 1
    assert entries[0]["agent"] == "ReconBot"


@pytest.mark.asyncio
async def test_no_request_log_file_written_when_path_not_given(tmp_path):
    log_path = tmp_path / "would-be-written-here.json"
    await run_attack_async(
        "http://127.0.0.1:1", use_callback=False, concurrency=2,
    )
    assert not log_path.exists()
