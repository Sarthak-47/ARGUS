"""Tests for BOLA/BFLA cross-identity authorization testing (AuthzTester)."""

from __future__ import annotations

import http.server
import socketserver
import threading

from argus.agents.base import Endpoint
from argus.auth import AuthConfig
from argus.llm.orchestrator import run_attack_sync


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def _make_handler(*, enforce: bool):
    """A tiny app. /orders/<id> is user-owned; /admin/users is privileged;
    /public is open. With enforce=False it forgets to check ownership/role."""

    valid = {"Bearer TOKEN_A": "a", "Bearer TOKEN_B": "b"}
    owner = {"1": "a", "2": "b"}

    class H(http.server.BaseHTTPRequestHandler):
        def _reply(self, code: int, body: bytes = b"{}"):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?")[0]
            who = valid.get(self.headers.get("Authorization"))
            if path == "/public":
                return self._reply(200, b'{"public":true}')
            if who is None:
                return self._reply(401)  # protected from anonymous
            if path.startswith("/orders/"):
                oid = path.rsplit("/", 1)[-1]
                if enforce and owner.get(oid) != who:
                    return self._reply(403)  # correct: not your object
                return self._reply(200, b'{"order":"' + oid.encode() + b'","secret":"data"}')
            if path.startswith("/admin/"):
                if enforce and who != "a":  # only user 'a' is admin
                    return self._reply(403)
                return self._reply(200, b'{"admin":true}')
            return self._reply(404)

        do_HEAD = do_GET

        def log_message(self, *a):
            pass

    return H


def _run(enforce: bool):
    srv = _Server(("127.0.0.1", 0), _make_handler(enforce=enforce))
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    seeds = [
        Endpoint(url=f"{base}/orders/1", method="GET"),
        Endpoint(url=f"{base}/admin/users", method="GET"),
        Endpoint(url=f"{base}/public", method="GET"),
    ]
    try:
        findings, _, _ = run_attack_sync(
            base, requested_agents=["authztester"], use_callback=False,
            seed_endpoints=seeds,
            auth=AuthConfig.from_dict({"bearer": "TOKEN_A"}),
            identity_b=AuthConfig.from_dict({"bearer": "TOKEN_B"}),
        )
    finally:
        srv.shutdown()
    return findings


def test_flags_bola_and_bfla_on_vulnerable_app():
    findings = _run(enforce=False)
    detectors = {f.detector for f in findings}
    assert "authztester:bola" in detectors, findings
    assert "authztester:bfla" in detectors, findings
    # /public must never be flagged
    assert all("/public" not in (f.endpoint or "") for f in findings)


def test_no_findings_when_authorization_enforced():
    findings = _run(enforce=True)
    detectors = {f.detector for f in findings}
    assert "authztester:bola" not in detectors
    assert "authztester:bfla" not in detectors


def _make_catchall_handler():
    """A gateway that 401s unauthenticated requests but returns the exact
    same generic 200 body for *any* authenticated request, regardless of
    path — the access-control layer works, but a naive "anon denied, both
    identities got <400" check can't tell that apart from a real BOLA/BFLA
    bypass unless it also confirms the content is genuinely distinct."""

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.headers.get("Authorization") not in ("Bearer TOKEN_A", "Bearer TOKEN_B"):
                self.send_response(401)
                self.end_headers()
                return
            body = b'{"generic":"catch-all response for any authenticated request"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        do_HEAD = do_GET

        def log_message(self, *a):
            pass

    return H


def test_no_findings_on_a_catchall_gateway_that_returns_identical_content():
    srv = _Server(("127.0.0.1", 0), _make_catchall_handler())
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    seeds = [
        Endpoint(url=f"{base}/orders/1", method="GET"),
        Endpoint(url=f"{base}/admin/users", method="GET"),
    ]
    try:
        findings, _, _ = run_attack_sync(
            base, requested_agents=["authztester"], use_callback=False,
            seed_endpoints=seeds,
            auth=AuthConfig.from_dict({"bearer": "TOKEN_A"}),
            identity_b=AuthConfig.from_dict({"bearer": "TOKEN_B"}),
        )
    finally:
        srv.shutdown()
    detectors = {f.detector for f in findings}
    assert "authztester:bola" not in detectors, findings
    assert "authztester:bfla" not in detectors, findings


def test_skips_without_second_identity():
    # No identity_b -> the agent no-ops (no crash, no findings).
    srv = _Server(("127.0.0.1", 0), _make_handler(enforce=False))
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        findings, reports, _ = run_attack_sync(
            base, requested_agents=["authztester"], use_callback=False,
            seed_endpoints=[Endpoint(url=f"{base}/orders/1", method="GET")],
            auth=AuthConfig.from_dict({"bearer": "TOKEN_A"}),
        )
    finally:
        srv.shutdown()
    assert not [f for f in findings if f.detector.startswith("authztester")]
