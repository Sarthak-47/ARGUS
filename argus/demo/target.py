"""The bundled vulnerable target: sample source (for static scan) + a live server
(for the attack swarm). Intentionally insecure — never ship any of this for real.

``SAMPLE_FILES`` is written to a temp dir and scanned by ``argus demo``. ``DemoServer``
runs a stdlib HTTP server on an ephemeral localhost port with planted vulns that the
attack agents confirm: reflected XSS, SSRF (real server-side fetch), error-based SQLi,
a weakly-signed JWT, permissive CORS, missing headers, GraphQL introspection, IDOR,
path traversal, and a CSRF-less form.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# ---- sample source scanned by `argus demo` (keys split so no secret literal ships) ----
SAMPLE_FILES: dict[str, str] = {
    "app.py": (
        "import os, hashlib, sqlite3, yaml, subprocess\n"
        "from flask import Flask, request\n\n"
        "app = Flask(__name__)\n"
        "DEBUG = True\n"
        "AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE'\n"
        "STRIPE = 'sk_' + 'live_4eC39HqLyjWDarjtT1zdp7dcABCDEFGH'\n"
        "JWT_SECRET = 'supersecretjwtkey1234567890'\n\n"
        "@app.route('/api/users')\n"
        "def users():\n"
        "    q = request.args.get('search')\n"
        "    con = sqlite3.connect('db'); cur = con.cursor()\n"
        "    cur.execute(\"SELECT * FROM users WHERE name = '\" + q + \"'\")\n"
        "    return str(cur.fetchall())\n\n"
        "@app.route('/api/ping')\n"
        "def ping():\n"
        "    host = request.args.get('host')\n"
        "    subprocess.call('ping ' + host, shell=True)\n"
        "    return 'ok'\n\n"
        "def hash_pw(p):\n"
        "    return hashlib.md5(p.encode()).hexdigest()\n\n"
        "def load_cfg(data):\n"
        "    return yaml.load(data)\n\n"
        "if __name__ == '__main__':\n"
        "    app.run(host='0.0.0.0', debug=True)\n"
    ),
    "requirements.txt": "flask==2.0.1\npyyaml==5.3\n",
}


def _b64(d: bytes) -> str:
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()


def _make_jwt() -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "1", "role": "user"}  # no exp on purpose
    si = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(payload).encode())}"
    sig = hmac.new(b"secret", si.encode(), hashlib.sha256).digest()  # weak secret
    return f"{si}.{_b64(sig)}"


_JWT = _make_jwt()


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        return

    def _cors(self):
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")

    def _send(self, code: int, ctype: str, body: bytes, cookie: str | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if u.path == "/":
            body = (
                "<html><body><h1>DemoShop</h1>"
                "<a href='/api/users?search=alice'>users</a> "
                "<a href='/search?q=hello'>search</a> "
                "<a href='/fetch?url=http://example.com'>fetch</a> "
                "<a href='/api/orders/10472'>order</a> "
                "<a href='/download?file=readme.txt'>download</a> "
                "<a href='/graphql'>api</a>"
                "<form action='/transfer' method='post'>"
                "<input type='hidden' name='amount' value='100'><input name='to'></form>"
                "<form action='/api/redeem' method='post'>"
                "<input name='code' value='SAVE10'></form>"
                "</body></html>"
            ).encode()
            self._send(200, "text/html", body, cookie=f"session={_JWT}")
        elif u.path == "/api/users":
            q = qs.get("search", [""])[0]
            if "'" in q or '"' in q:
                self._send(500, "text/plain",
                           b'SQL syntax error near "\'": SELECT * FROM users WHERE name = \''
                           + q.encode("utf-8", "ignore") + b"'")
            else:
                self._send(200, "text/plain", f"user: {q}".encode())
        elif u.path == "/search":
            q = qs.get("q", [""])[0]
            self._send(200, "text/html", f"<html><body>Results: {q}</body></html>".encode("utf-8", "ignore"))
        elif u.path == "/fetch":
            url = qs.get("url", [""])[0]
            out = "fetched"
            try:
                with urllib.request.urlopen(url, timeout=2) as r:  # intentional SSRF
                    out = r.read(200).decode("utf-8", "ignore")
            except Exception as e:  # noqa: BLE001
                out = f"error: {e}"
            self._send(200, "text/plain", out.encode("utf-8", "ignore"))
        elif u.path.startswith("/api/orders/"):
            oid = u.path.rsplit("/", 1)[-1]
            self._send(200, "application/json",
                       json.dumps({"id": oid, "owner": f"user{oid}@x.com"}).encode())
        elif u.path == "/download":
            f = qs.get("file", [""])[0]
            if "passwd" in f:
                self._send(200, "text/plain", b"root:x:0:0:root:/root:/bin/bash")
            elif "win.ini" in f:
                self._send(200, "text/plain", b"[fonts]\n[extensions]\n")
            else:
                self._send(200, "text/plain", f"contents of {f}".encode("utf-8", "ignore"))
        else:
            self._send(404, "text/plain", b"not found")

    def do_POST(self):  # noqa: N802
        u = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        if u.path == "/graphql":
            self._send(200, "application/json", json.dumps({
                "data": {"__typename": "Query", "__schema": {"queryType": {"name": "Query"},
                         "types": [{"name": "User", "kind": "OBJECT"}]}}
            }).encode())
        elif u.path == "/api/redeem":
            # Deliberately vulnerable: no state tracking at all, so the "same" coupon
            # code can be redeemed any number of times — the stackable-discount
            # business-logic pattern BusinessLogicAgent is built to catch.
            self._send(200, "application/json",
                       json.dumps({"status": "redeemed", "discount": "10%"}).encode())
        else:
            self._send(200, "text/plain", b"ok:" + raw[:40])


class DemoServer:
    """Threaded vulnerable server on an ephemeral localhost port."""

    def __init__(self, host: str = "127.0.0.1"):
        self._httpd = ThreadingHTTPServer((host, 0), _Handler)
        self.host = host
        self.port = self._httpd.server_address[1]
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> "DemoServer":
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        time.sleep(0.2)
        return self

    def stop(self) -> None:
        try:
            self._httpd.shutdown()
            self._httpd.server_close()
        except Exception:  # noqa: BLE001
            pass

    def __enter__(self) -> "DemoServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
