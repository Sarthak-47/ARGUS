"""AuthBreaker — authentication weaknesses, starting with JWT.

Finds JWTs in cookies/headers/body, then analyses them without any third-party JWT
library (HS256 verification is done with stdlib hmac/hashlib):
  * weak-secret bruteforce  — recompute the HMAC over a small wordlist; a match
    means tokens can be forged (critical).
  * alg:none / weak alg     — flag tokens accepting unsigned or downgradeable algs.
  * missing expiry          — tokens without ``exp`` never expire.
Also inspects session-cookie flags (Secure / HttpOnly / SameSite).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re

from argus.agents.base import AgentReport, AttackContext, BaseAgent, build_http_poc
from argus.models import Finding, Severity

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.([A-Za-z0-9_\-]{0,})\b")

# Small but high-signal weak-secret list (rockyou-style top entries + dev defaults).
_WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "jwt_secret", "your-256-bit-secret",
    "supersecret", "secretkey", "admin", "test", "key", "mysecret", "token",
    "qwerty", "letmein", "default", "s3cr3t", "private", "shhhh", "topsecret",
]

_SESSION_COOKIE_HINTS = ("session", "sid", "auth", "token", "jwt", "connect.sid")


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class AuthBreaker(BaseAgent):
    name = "AuthBreaker"
    description = "auth & JWT flaws"

    async def run(self, ctx: AttackContext) -> AgentReport:
        report = AgentReport(agent=self.name, status="running")

        resp = await self.get(ctx, ctx.base_url + "/")
        tokens: set[str] = set()
        if resp is not None:
            tokens |= self._find_tokens(resp)
            self._check_cookie_flags(ctx, resp)

        # The authenticated session itself carries a token — a Bearer JWT applied
        # via --auth (or one login already deposited in the cookie jar). Analyse
        # that too: otherwise a user who scans with a JWT never gets it checked,
        # which is exactly the token most worth checking.
        tokens |= self._session_tokens(ctx)

        # also scan any JWT-looking strings the recon stage saw
        for token in tokens:
            ctx.emit(self.name, f"analysing JWT ({token[:18]}…)")
            self._analyse_jwt(ctx, token, resp)

        if not tokens:
            ctx.emit(self.name, "no JWT found on the public surface")

        report.requests_sent = ctx.requests_sent
        report.findings = len([f for f in ctx.findings if f.detector.startswith("authbreaker")])
        report.status = "complete"
        ctx.emit(self.name, "sweep complete", "ok")
        return report

    # ------------------------------------------------------------------ #
    def _session_tokens(self, ctx: AttackContext) -> set[str]:
        """JWTs carried by the authenticated client itself — the Authorization
        header and the cookie jar — not just what the homepage hands out."""
        tokens: set[str] = set()
        auth_header = ctx.client.headers.get("Authorization", "")
        tokens |= {m.group(0) for m in _JWT_RE.finditer(auth_header)}
        try:
            for v in ctx.client.cookies.values():
                tokens |= {m.group(0) for m in _JWT_RE.finditer(v)}
        except Exception:  # noqa: BLE001 — cookie jar access is best-effort
            pass
        return tokens

    def _find_tokens(self, resp) -> set[str]:
        tokens: set[str] = set()
        for v in resp.cookies.values():
            tokens |= {m.group(0) for m in _JWT_RE.finditer(v)}
        for hv in resp.headers.values():
            tokens |= {m.group(0) for m in _JWT_RE.finditer(hv)}
        tokens |= {m.group(0) for m in _JWT_RE.finditer(resp.text or "")}
        return tokens

    def _analyse_jwt(self, ctx: AttackContext, token: str, resp=None) -> None:
        parts = token.split(".")
        if len(parts) != 3:
            return
        h_seg, p_seg, sig_seg = parts
        try:
            header = json.loads(_b64url_decode(h_seg))
            payload = json.loads(_b64url_decode(p_seg))
        except (ValueError, json.JSONDecodeError):
            return

        alg = str(header.get("alg", "")).lower()

        if alg == "none":
            ctx.report(Finding(
                title="JWT accepts 'alg: none'",
                severity=Severity.CRITICAL,
                category="auth",
                detector="authbreaker:jwt-none",
                endpoint=ctx.base_url,
                evidence=f"header alg=none, payload={json.dumps(payload)[:120]}",
                description="The JWT header uses 'none', meaning tokens are unsigned and any "
                            "payload is trusted.",
                exploit="Forge an admin token by setting alg:none and arbitrary claims.",
                fix="Reject 'none'; pin the algorithm to a strong signed scheme (e.g. RS256/HS256).",
                cwe="CWE-347", cvss=9.8, confidence="high",
                poc=build_http_poc("GET", ctx.base_url + "/", resp) if resp is not None else {},
            ))
            return

        if alg.startswith("hs"):
            cracked = self._crack_hs(token)
            if cracked is not None:
                ctx.report(Finding(
                    title="JWT signed with a weak secret",
                    severity=Severity.CRITICAL,
                    category="auth",
                    detector="authbreaker:jwt-weak-secret",
                    endpoint=ctx.base_url,
                    evidence=f"secret = {cracked!r} (alg {header.get('alg')})",
                    description=f"The HMAC secret was recovered ({cracked!r}) from a small wordlist, "
                                f"so tokens can be forged.",
                    exploit="Sign a token with elevated claims (e.g. role=admin) using the cracked secret.",
                    fix="Rotate to a long, random secret (>=256 bits) stored securely.",
                    cwe="CWE-326", cvss=9.8, confidence="high",
                    poc=build_http_poc("GET", ctx.base_url + "/", resp) if resp is not None else {},
                ))

        if "exp" not in payload:
            ctx.report(Finding(
                title="JWT has no expiry (exp) claim",
                severity=Severity.MEDIUM,
                category="auth",
                detector="authbreaker:jwt-no-exp",
                endpoint=ctx.base_url,
                evidence=f"payload keys: {', '.join(payload.keys())}",
                description="The JWT lacks an 'exp' claim, so a leaked token is valid forever.",
                exploit="A stolen token can be replayed indefinitely.",
                fix="Add a short 'exp' and validate it server-side.",
                cwe="CWE-613", confidence="high",
                poc=build_http_poc("GET", ctx.base_url + "/", resp) if resp is not None else {},
            ))

    def _crack_hs(self, token: str) -> str | None:
        h_seg, p_seg, sig_seg = token.split(".")
        signing_input = f"{h_seg}.{p_seg}".encode()
        try:
            given_sig = _b64url_decode(sig_seg)
        except ValueError:
            return None
        digestmod = hashlib.sha256
        if token and '"HS384"' in _safe(h_seg):
            digestmod = hashlib.sha384
        elif token and '"HS512"' in _safe(h_seg):
            digestmod = hashlib.sha512
        for secret in _WEAK_SECRETS:
            candidate = hmac.new(secret.encode(), signing_input, digestmod).digest()
            if hmac.compare_digest(candidate, given_sig):
                return secret
        return None

    def _check_cookie_flags(self, ctx: AttackContext, resp) -> None:
        set_cookie = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else \
            [resp.headers["set-cookie"]] if "set-cookie" in resp.headers else []
        for raw in set_cookie:
            lower = raw.lower()
            name = raw.split("=", 1)[0].strip().lower()
            if not any(h in name for h in _SESSION_COOKIE_HINTS):
                continue
            missing = []
            if "httponly" not in lower:
                missing.append("HttpOnly")
            if "secure" not in lower:
                missing.append("Secure")
            if "samesite" not in lower:
                missing.append("SameSite")
            if missing:
                ctx.report(Finding(
                    title="Session cookie missing security flags",
                    severity=Severity.MEDIUM,
                    category="auth",
                    detector="authbreaker:cookie-flags",
                    endpoint=ctx.base_url,
                    evidence=f"{name}: missing {', '.join(missing)}",
                    description=f"The session cookie '{name}' is missing {', '.join(missing)}, "
                                f"exposing it to theft or CSRF.",
                    exploit="Cookie theft via XSS (no HttpOnly) or interception (no Secure).",
                    fix="Set HttpOnly, Secure, and SameSite=Lax/Strict on session cookies.",
                    cwe="CWE-1004", confidence="high",
                    poc=build_http_poc("GET", ctx.base_url + "/", resp),
                ))


def _safe(seg: str) -> str:
    try:
        return _b64url_decode(seg).decode("utf-8", "ignore")
    except ValueError:
        return ""
