"""Tests for the MCP server (argus/mcp_server.py).

Skipped cleanly when the optional 'mcp' extra isn't installed, matching the
pattern test_domxss.py/test_sandbox.py use for their own optional deps.
"""

from __future__ import annotations

import io
import sys

import pytest

pytest.importorskip("mcp")

from argus.mcp_server import build_server  # noqa: E402


def _call(server, name: str, args: dict):
    """Invoke a tool through the real MCP call_tool path (not the bare Python
    function), so this exercises what an actual MCP client would trigger."""
    import asyncio

    return asyncio.run(server.call_tool(name, args))


def test_server_registers_all_three_tools():
    import asyncio

    server = build_server()
    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    assert names == {"argus_scan", "argus_attack", "argus_fix"}


def test_scan_tool_no_stdout_leakage(tmp_path):
    # MCP's stdio transport IS stdout -- any stray print corrupts the protocol.
    (tmp_path / "app.py").write_text(
        "import os\ndef r(c):\n    os.system('ping ' + c)\n", encoding="utf-8")

    real_stdout = sys.stdout
    capture = io.StringIO()
    sys.stdout = capture
    try:
        server = build_server()
        _call(server, "argus_scan", {"target": str(tmp_path)})
    finally:
        sys.stdout = real_stdout

    assert capture.getvalue() == ""


def test_scan_tool_returns_real_findings(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\ndef r(c):\n    os.system('ping ' + c)\n", encoding="utf-8")

    server = build_server()
    content, structured = _call(server, "argus_scan", {"target": str(tmp_path)})

    assert structured["risk_score"] > 0
    assert any(f["detector"].startswith("rule:") for f in structured["findings"])
    # the text content block must be valid JSON matching the structured result
    import json

    parsed = json.loads(content[0].text)
    assert parsed["target"] == str(tmp_path)


def test_scan_tool_missing_target_reports_error(tmp_path):
    missing = str(tmp_path / "does-not-exist")
    server = build_server()
    content, structured = _call(server, "argus_scan", {"target": missing})
    assert "error" in structured
    assert missing in structured["error"] or "does-not-exist" in structured["error"]


def test_attack_tool_no_stdout_leakage_and_returns_findings():
    from argus.demo.target import DemoServer

    server = DemoServer().start()
    try:
        real_stdout = sys.stdout
        capture = io.StringIO()
        sys.stdout = capture
        try:
            mcp_server = build_server()
            content, structured = _call(mcp_server, "argus_attack",
                                        {"url": server.url, "agents": "xsshunter"})
        finally:
            sys.stdout = real_stdout
        assert capture.getvalue() == ""
        assert structured["target"] == server.url
        assert isinstance(structured["findings"], list)
        assert any(r["agent"] == "XSSHunter" for r in structured["agents_run"])
    finally:
        server.stop()


def test_fix_tool_reports_missing_provider_cleanly(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr("argus.llm.provider.get_provider", lambda settings: None)

    server = build_server()
    content, structured = _call(server, "argus_fix", {"target": str(tmp_path)})
    assert "error" in structured
    assert "No LLM provider" in structured["error"]
