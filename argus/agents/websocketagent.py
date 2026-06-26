"""WebSocketAgent — WebSocket upgrade and origin checks.

Discovers WebSocket URLs referenced in page/JS content (ws:// or wss://), then
attempts an HTTP Upgrade handshake. A ``101 Switching Protocols`` response — with no
auth and no Origin enforcement — indicates an unauthenticated/cross-origin socket.
Implemented with a raw httpx upgrade request to avoid a websockets dependency; deep
message fuzzing is a follow-up.
"""

from __future__ import annotations

import base64
import os
import re
from urllib.parse import urlparse

from argus.agents.base import AgentReport, AttackContext, BaseAgent
from argus.models import Finding, Severity

_WS_URL = re.compile(r"""['"(](wss?://[^'")\s]+)['")\s]""", re.IGNORECASE)
_COMMON_WS_PATHS = ["/ws", "/socket", "/websocket", "/socket.io/?EIO=4&transport=websocket"]


class WebSocketAgent(BaseAgent):
    name = "WebSocketAgent"
    description = "socket hijacking"

    async def run(self, ctx: AttackContext) -> AgentReport:
        report = AgentReport(agent=self.name, status="running")

        urls = await self._discover(ctx)
        if not urls:
            ctx.emit(self.name, "no WebSocket endpoints found")
            report.status = "complete"
            return report

        for url in urls:
            ctx.emit(self.name, f"testing WS upgrade {url} …")
            await self._test_upgrade(ctx, url)

        report.requests_sent = ctx.requests_sent
        report.findings = len([f for f in ctx.findings if f.detector.startswith("websocketagent")])
        report.status = "complete"
        ctx.emit(self.name, "sweep complete", "ok")
        return report

    async def _discover(self, ctx: AttackContext) -> list[str]:
        found: set[str] = set()
        root = await self.get(ctx, ctx.base_url + "/")
        if root is not None:
            for m in _WS_URL.finditer(root.text or ""):
                found.add(m.group(1))
        # also try common ws paths derived from the base host
        http_base = urlparse(ctx.base_url)
        for path in _COMMON_WS_PATHS:
            found.add(f"{http_base.scheme}://{http_base.netloc}{path}")
        return list(found)[:6]

    async def _test_upgrade(self, ctx: AttackContext, ws_url: str) -> None:
        # Convert ws(s):// to http(s):// for the handshake request.
        parsed = urlparse(ws_url)
        scheme = "https" if parsed.scheme in ("wss", "https") else "http"
        http_url = f"{scheme}://{parsed.netloc}{parsed.path or '/'}"
        if parsed.query:
            http_url += f"?{parsed.query}"

        key = base64.b64encode(os.urandom(16)).decode()
        headers = {
            "Connection": "Upgrade",
            "Upgrade": "websocket",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": key,
            "Origin": "https://evil.argus-test.example",  # hostile origin on purpose
        }
        resp = await self.get(ctx, http_url, headers=headers)
        if resp is not None and resp.status_code == 101:
            ctx.report(Finding(
                title="WebSocket accepts unauthenticated cross-origin upgrade",
                severity=Severity.MEDIUM,
                category="api",
                detector="websocketagent:upgrade",
                endpoint=ws_url,
                evidence="101 Switching Protocols with a hostile Origin and no authentication",
                description="The WebSocket endpoint upgrades without checking authentication or the "
                            "Origin header, enabling cross-site WebSocket hijacking (CSWSH).",
                exploit="A malicious page opens a socket on the victim's behalf and reads/sends messages.",
                fix="Authenticate the upgrade request and validate the Origin header against an allow-list.",
                cwe="CWE-1385",
                confidence="medium",
            ))
