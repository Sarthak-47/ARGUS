"""Lightweight HTTP callback server for blind vulnerability detection.

Blind SQLi/SSRF/XSS only reveal themselves when the *target* reaches back out to a
server we control. This runs a tiny threaded HTTP server, hands out unique tokens,
and records any inbound hit carrying a token. Agents embed callback URLs in their
payloads, then ask :meth:`was_hit` whether the token fired.

Bound to localhost by default — it is reachable by a target running on the same
host (the common ``attack --url http://localhost:PORT`` case). Remote targets need
a publicly reachable host, which is out of scope for the local MVP.
"""

from __future__ import annotations

import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _Handler(BaseHTTPRequestHandler):
    def _record(self) -> None:
        token = self.path.strip("/").split("/")[0].split("?")[0]
        server: "CallbackServer" = self.server.argus_cb  # type: ignore[attr-defined]
        server.record(token, self.client_address[0], self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self) -> None:  # noqa: N802
        self._record()

    def do_POST(self) -> None:  # noqa: N802
        self._record()

    def log_message(self, *args) -> None:  # silence default stderr logging
        return


class CallbackServer:
    """Threaded callback collector with per-probe tokens."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self._httpd = ThreadingHTTPServer((host, port), _Handler)
        self._httpd.argus_cb = self  # type: ignore[attr-defined]
        self.port = self._httpd.server_address[1]
        self._hits: dict[str, list[dict]] = {}
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def new_token(self) -> tuple[str, str]:
        """Return (token, full_callback_url) for embedding in a payload."""
        token = uuid.uuid4().hex[:16]
        with self._lock:
            self._hits.setdefault(token, [])
        return token, f"{self.base_url}/{token}"

    def record(self, token: str, src_ip: str, path: str) -> None:
        with self._lock:
            self._hits.setdefault(token, []).append({"ip": src_ip, "path": path})

    def was_hit(self, token: str) -> bool:
        with self._lock:
            return bool(self._hits.get(token))

    def hits(self, token: str) -> list[dict]:
        with self._lock:
            return list(self._hits.get(token, []))

    def start(self) -> "CallbackServer":
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        try:
            self._httpd.shutdown()
            self._httpd.server_close()
        except Exception:
            pass

    def __enter__(self) -> "CallbackServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
