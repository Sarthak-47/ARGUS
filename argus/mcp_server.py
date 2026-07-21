"""Argus as an MCP server (roadmap D3).

Exposes scan / attack / fix as MCP tools so an editor agent (Claude Code,
Cursor, Copilot) can run Argus directly instead of shelling out to the CLI and
scraping text. Optional: ``pip install 'argus-panoptes[mcp]'``, then
``argus mcp-server``.

MCP's stdio transport is a raw JSON-RPC stream *over stdout* — any stray print
corrupts it, and the engine's own Rich console output (``argus/cli/output.py``)
writes straight to stdout by design for the CLI. Every tool here runs the
engine with stdout redirected away while it works, and returns structured
JSON instead of printed text.
"""

from __future__ import annotations

import contextlib
import io
import shutil
from typing import Any, Callable


class MCPUnavailableError(RuntimeError):
    """The optional ``mcp`` package isn't installed — raised with an actionable
    install hint instead of letting a raw ModuleNotFoundError surface."""


def _quiet(fn: Callable, *args: Any, **kwargs: Any) -> Any:
    """Run ``fn`` with stdout redirected away — required so the engine's Rich
    console output never corrupts the MCP stdio JSON-RPC stream."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        return fn(*args, **kwargs)


def _error_dict(exc: Exception) -> dict[str, str]:
    """A tool-call failure (bad target, unreachable app, ...) as a clean
    structured response an agent can read, rather than a raw exception
    propagating through the MCP protocol as an opaque JSON-RPC error."""
    return {"error": str(exc)}


def build_server():
    """Construct the FastMCP server with argus_scan/argus_attack/argus_fix
    registered. Split out from :func:`run` so tests can call tools directly
    without needing a real stdio client."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ModuleNotFoundError as exc:
        # `mcp` is an optional extra (pyproject: mcp = ["mcp>=1.28.1"]) — the
        # base install doesn't ship it. Degrade to a clear, actionable message
        # like every other optional integration (semgrep/pip-audit/trivy/docker)
        # rather than dumping a raw ModuleNotFoundError traceback at the user.
        raise MCPUnavailableError(
            "The MCP server needs the optional 'mcp' package, which isn't installed. "
            "Install it with:  pip install 'argus-panoptes[mcp]'"
        ) from exc

    server = FastMCP("argus")

    @server.tool()
    def argus_scan(target: str, deep: bool = False) -> dict[str, Any]:
        """Run Argus's Phase 1 static security scan against a local path or repo
        URL. Deterministic (no LLM) for speed and reproducibility; returns risk
        score, band, finding counts, and every finding with its file/line/CWE/fix.
        """
        from argus.pipeline import _do_scan
        from argus.scanner import ingestion

        try:
            ingested = ingestion.ingest(target)
        except Exception as exc:  # bad path, unreachable repo URL, ...
            return _error_dict(exc)
        try:
            result = _quiet(_do_scan, target, deep=deep, depth=None, no_llm=True)
        except Exception as exc:
            return _error_dict(exc)
        finally:
            if ingested.cleanup:
                shutil.rmtree(ingested.root, ignore_errors=True)
        return result.to_dict()

    @server.tool()
    async def argus_attack(url: str, agents: str | None = None) -> dict[str, Any]:
        """Run Argus's Phase 2 attack swarm against an already-running app at
        `url`. Actively exploits the target (SQLi, XSS, SSRF, auth bypass, IDOR,
        ...) and returns every confirmed finding with a reproducible PoC.
        `agents` is an optional comma-separated subset (e.g. "injector,xsshunter");
        omit to run the full swarm.
        """
        from argus.llm.orchestrator import run_attack_async

        # The MCP tool call already runs inside an event loop, so this awaits
        # the async orchestrator directly rather than the sync asyncio.run()
        # wrapper (which would fail with "cannot be called from a running
        # event loop"). Still redirect stdout for defensive consistency with
        # the other tools, even though the orchestrator itself prints nothing.
        requested = [a.strip().lower() for a in agents.split(",")] if agents else None
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                findings, reports, _eps = await run_attack_async(url, requested_agents=requested)
        except Exception as exc:  # unreachable url, bad agent name, ...
            return _error_dict(exc)
        return {
            "target": url,
            "findings": [f.to_dict() for f in findings],
            "agents_run": [
                {"agent": r.agent, "status": r.status, "requests_sent": r.requests_sent, "findings": r.findings}
                for r in reports
            ],
        }

    @server.tool()
    def argus_fix(target: str, apply: bool = False) -> dict[str, Any]:
        """Generate LLM-written patches for fixable findings in `target`. Needs an
        LLM provider already configured (`argus setup`). Dry-run by default
        (apply=False) — returns each proposed diff for review without writing
        anything; apply=True validates and writes each patch to disk.
        """
        from argus.config import load_settings
        from argus.fix import apply_fixes
        from argus.llm.provider import get_provider
        from argus.llm.reasoning import generate_fixes
        from argus.pipeline import _do_scan
        from argus.scanner import ingestion

        settings = load_settings()
        provider = get_provider(settings)
        if provider is None:
            return {"error": "No LLM provider configured — run `argus setup` first."}

        try:
            result = _quiet(_do_scan, target, deep=False, depth=None, no_llm=True)
        except Exception as exc:
            return _error_dict(exc)
        fixable = [f for f in result.findings if f.file]
        if not fixable:
            return {"fixes": [], "note": "No fixable (file-based) findings."}

        try:
            ingested = ingestion.ingest(target)
        except Exception as exc:
            return _error_dict(exc)
        try:
            fixes = _quiet(generate_fixes, provider, ingested.root, fixable)
            applied = _quiet(apply_fixes, ingested.root, fixes, apply=apply)
        except Exception as exc:
            return _error_dict(exc)
        finally:
            if ingested.cleanup:
                shutil.rmtree(ingested.root, ignore_errors=True)
        return {
            "applied": apply,
            "fixes": [
                {"finding_id": a.finding_id, "file": a.file, "explanation": a.explanation,
                 "diff": a.diff, "written": a.written}
                for a in applied
            ],
        }

    return server


def run() -> None:
    """Entry point for ``argus mcp-server`` — blocks, serving over stdio."""
    import typer

    from argus.cli import output as out

    try:
        server = build_server()
    except MCPUnavailableError as exc:
        # escape() so the "[mcp]" in the pip extra survives Rich markup parsing
        # instead of being swallowed as a style tag.
        from rich.markup import escape
        out.error(escape(str(exc)))
        raise typer.Exit(code=1)
    server.run()
