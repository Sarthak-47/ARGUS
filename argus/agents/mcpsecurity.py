"""MCPSecurityAgent — exposed/unauthenticated MCP servers and AI-infra leaks.

Cursor/Copilot-era developers increasingly ship their own MCP servers and agent
tool definitions with little security review — an unclaimed attack surface most
pentest tooling ignores. This agent probes well-known MCP transport endpoints
(JSON-RPC over HTTP, the SSE transport, and the `.well-known` discovery
convention) for servers that respond with tool definitions without any
authentication, and scans successful responses for leaked provider credentials
using the same patterns as the static secret scanner.
"""

from __future__ import annotations

import json

from argus.agents.base import AgentReport, AttackContext, BaseAgent, build_http_poc
from argus.models import Finding, Severity
from argus.scanner.secrets import _SECRET_PATTERNS

# Candidate MCP surface. `/mcp`-style paths speak JSON-RPC over HTTP (the
# "Streamable HTTP" transport); `/sse` is the older HTTP+SSE transport.
_JSON_RPC_PATHS = ["/mcp", "/api/mcp", "/.well-known/mcp"]
_SSE_PATHS = ["/sse", "/mcp/sse"]

_TOOLS_LIST_REQUEST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}


def _looks_like_tool_list(body: dict) -> list[dict] | None:
    """Return the tool list if ``body`` looks like a JSON-RPC tools/list result."""
    result = body.get("result")
    if isinstance(result, dict) and isinstance(result.get("tools"), list):
        return result["tools"]
    if isinstance(body.get("tools"), list):  # some servers skip the JSON-RPC envelope
        return body["tools"]
    return None


class MCPSecurityAgent(BaseAgent):
    name = "MCPSecurityAgent"
    description = "exposed MCP servers & AI-infra leaks"

    async def run(self, ctx: AttackContext) -> AgentReport:
        report = AgentReport(agent=self.name, status="running")
        base = ctx.base_url

        found_any = False
        for path in _JSON_RPC_PATHS:
            url = base + path
            ctx.emit(self.name, f"probing {path} for an unauthenticated MCP server …")
            resp = await self.post(ctx, url, json=_TOOLS_LIST_REQUEST,
                                    headers={"Content-Type": "application/json"})
            if resp is None or resp.status_code >= 400:
                continue
            self._check_leaked_secrets(ctx, "POST", url, resp)
            try:
                body = resp.json()
            except ValueError:
                continue
            tools = _looks_like_tool_list(body) if isinstance(body, dict) else None
            if tools is not None:
                found_any = True
                names = ", ".join(str(t.get("name", "?")) for t in tools[:8])
                ctx.report(Finding(
                    title="Unauthenticated MCP server exposes tool definitions",
                    severity=Severity.HIGH,
                    category="ai-infra",
                    detector="mcpsecurity:tool-list",
                    endpoint=f"POST {url}",
                    evidence=f"tools/list returned {len(tools)} tool(s) with no authentication: {names}",
                    description="An MCP server responds to a tools/list request without requiring "
                                "authentication, disclosing every tool (and its schema/capabilities) "
                                "to anyone who can reach the endpoint.",
                    exploit="Enumerate available tools, then invoke sensitive ones directly (e.g. "
                            "file access, shell execution, database queries) bypassing the intended "
                            "client/agent and any of its guardrails.",
                    fix="Require authentication on the MCP transport (mTLS, bearer token, or network "
                        "isolation) and disable introspection endpoints in production.",
                    cwe="CWE-306",
                    cvss=8.1,
                    confidence="high",
                    poc=build_http_poc("POST", url, resp, body=json.dumps(_TOOLS_LIST_REQUEST)),
                ))

        for path in _SSE_PATHS:
            url = base + path
            resp = await self.get(ctx, url, headers={"Accept": "text/event-stream"})
            if resp is None or resp.status_code >= 400:
                continue
            ctype = resp.headers.get("content-type", "")
            if "text/event-stream" in ctype.lower():
                found_any = True
                ctx.report(Finding(
                    title="Unauthenticated MCP SSE endpoint",
                    severity=Severity.MEDIUM,
                    category="ai-infra",
                    detector="mcpsecurity:sse",
                    endpoint=f"GET {url}",
                    evidence=f"{path} opened an SSE stream (Content-Type: {ctype}) with no authentication",
                    description="The MCP SSE transport endpoint accepts connections without "
                                "authentication, allowing any client to attach as an MCP peer.",
                    exploit="Establish an SSE session and issue tool calls as if a trusted agent.",
                    fix="Require authentication before upgrading to the SSE/event stream.",
                    cwe="CWE-306",
                    confidence="medium",
                    poc=build_http_poc("GET", url, resp),
                ))
            self._check_leaked_secrets(ctx, "GET", url, resp)

        if not found_any:
            ctx.emit(self.name, "no exposed MCP server found")

        report.requests_sent = ctx.requests_sent
        report.findings = len([f for f in ctx.findings if f.detector.startswith("mcpsecurity")])
        report.status = "complete"
        ctx.emit(self.name, "sweep complete", "ok")
        return report

    def _check_leaked_secrets(self, ctx: AttackContext, method: str, url: str, resp) -> None:
        """Scan a successful response body for leaked provider credentials."""
        body = resp.text or ""
        for label, sev, pattern in _SECRET_PATTERNS:
            m = pattern.search(body)
            if not m:
                continue
            ctx.report(Finding(
                title=f"Leaked credential in MCP response: {label}",
                severity=sev,
                category="ai-infra",
                detector="mcpsecurity:leaked-secret",
                endpoint=f"{method} {url}",
                evidence=f"response body contains a {label} pattern",
                description=f"An MCP endpoint response includes what appears to be a {label}, "
                            f"exposing a live credential to any client that can reach it.",
                exploit="Use the leaked credential directly against the provider it belongs to.",
                fix="Never echo secrets/credentials in tool responses; load them server-side only "
                    "and redact before returning to a client.",
                cwe="CWE-522",
                confidence="medium",
                poc=build_http_poc(method, url, resp),
            ))
            return  # one leaked-secret finding per response is enough signal
