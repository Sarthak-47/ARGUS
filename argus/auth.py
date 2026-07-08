"""Authenticated attack sessions (roadmap v0.3.1).

Almost every real app hides its interesting surface behind a login, so an
unauthenticated scan only ever sees the doormat. This lets the whole attack
swarm carry a real authenticated session: because every agent issues requests
through the one shared ``httpx.AsyncClient``, applying auth to that client once
means all 17 agents — and ReconBot's crawl — act as the logged-in user.

Supported, cheapest-first:
  - static credentials: a bearer token / arbitrary headers, session cookies,
    or HTTP basic auth;
  - a **form login** — POST credentials to a login URL and reuse the session
    cookie it sets (or extract a token from the JSON response → Bearer).
    Optionally CSRF-aware: many real login forms (DVWA's included) embed a
    rotating hidden token that must be echoed back or the POST is rejected —
    set ``csrf_field`` and Argus GETs the login page first to scrape it;
  - **OAuth2 client-credentials** — fetch an access token and use it as Bearer.

Config comes from a ``.argus-auth.toml`` (see ``argus attack --auth <file>``),
auto-discovered in the working directory if present. Credentials never appear
in a captured proof-of-concept — ``build_http_poc`` already redacts the
Authorization/Cookie headers this module sets.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

AUTH_FILENAME = ".argus-auth.toml"


class AuthError(RuntimeError):
    """Raised when an auth config is invalid or a login flow fails."""


@dataclass
class AuthConfig:
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    basic: tuple[str, str] | None = None
    # form login
    login_url: str | None = None
    login_method: str = "POST"
    login_json: bool = False
    login_data: dict[str, str] = field(default_factory=dict)
    token_json_path: str | None = None
    csrf_field: str | None = None
    # oauth2 client-credentials
    oauth_token_url: str | None = None
    oauth_client_id: str | None = None
    oauth_client_secret: str | None = None
    oauth_scope: str | None = None

    # ----- construction -----
    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AuthConfig":
        headers = {str(k): str(v) for k, v in (d.get("headers") or {}).items()}
        cookies = {str(k): str(v) for k, v in (d.get("cookies") or {}).items()}
        # A bare `bearer = "..."` is sugar for an Authorization header.
        if d.get("bearer"):
            headers.setdefault("Authorization", f"Bearer {d['bearer']}")

        basic = None
        b = d.get("basic")
        if b:
            if not (b.get("username") and b.get("password")):
                raise AuthError("[basic] needs both username and password.")
            basic = (str(b["username"]), str(b["password"]))

        login = d.get("login") or {}
        oauth = d.get("oauth2") or {}
        cfg = cls(
            headers=headers,
            cookies=cookies,
            basic=basic,
            login_url=login.get("url"),
            login_method=str(login.get("method", "POST")).upper(),
            login_json=bool(login.get("json", False)),
            login_data={str(k): str(v) for k, v in (login.get("data") or {}).items()},
            token_json_path=login.get("token_json_path"),
            csrf_field=login.get("csrf_field"),
            oauth_token_url=oauth.get("token_url"),
            oauth_client_id=oauth.get("client_id"),
            oauth_client_secret=oauth.get("client_secret"),
            oauth_scope=oauth.get("scope"),
        )
        if cfg.login_url and not cfg.login_data:
            raise AuthError("[login] needs a [login.data] table with the credentials to POST.")
        if cfg.oauth_token_url and not (cfg.oauth_client_id and cfg.oauth_client_secret):
            raise AuthError("[oauth2] needs client_id and client_secret.")
        return cfg

    @classmethod
    def from_toml(cls, path: Path) -> "AuthConfig":
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise AuthError(f"Could not read auth file {path}: {exc}") from exc
        return cls.from_dict(data)

    def is_empty(self) -> bool:
        return not (self.headers or self.cookies or self.basic
                    or self.login_url or self.oauth_token_url)

    # ----- application -----
    async def apply(self, client: httpx.AsyncClient) -> str:
        """Attach auth to a shared client; run any login flow. Returns a short,
        secret-free summary of what was applied."""
        notes: list[str] = []
        if self.headers:
            client.headers.update(self.headers)
            notes.append(f"{len(self.headers)} header(s)")
        for k, v in self.cookies.items():
            client.cookies.set(k, v)
        if self.cookies:
            notes.append(f"{len(self.cookies)} cookie(s)")
        if self.basic:
            client.auth = httpx.BasicAuth(*self.basic)
            notes.append("HTTP basic")

        token: str | None = None
        if self.oauth_token_url:
            token = await self._oauth2(client)
            notes.append("OAuth2 client-credentials")
        elif self.login_url:
            token = await self._form_login(client)
            notes.append("form login " + ("(bearer token)" if token else "(session cookie)"))

        if token:
            client.headers["Authorization"] = f"Bearer {token}"
        return ", ".join(notes) if notes else "none"

    async def _form_login(self, client: httpx.AsyncClient) -> str | None:
        data = dict(self.login_data)
        if self.csrf_field:
            try:
                page = await client.get(self.login_url)
            except httpx.HTTPError as exc:
                raise AuthError(
                    f"Could not GET the login page at {self.login_url} to scrape a CSRF token: {exc}"
                ) from exc
            token = _extract_hidden_value(page.text or "", self.csrf_field)
            if token is None:
                raise AuthError(
                    f"Login page at {self.login_url} has no hidden input named "
                    f"'{self.csrf_field}' — check the field name."
                )
            data[self.csrf_field] = token

        kwargs: dict[str, Any] = {"json": data} if self.login_json else {"data": data}
        try:
            resp = await client.request(self.login_method, self.login_url, **kwargs)
        except httpx.HTTPError as exc:
            raise AuthError(f"Login request to {self.login_url} failed: {exc}") from exc
        if resp.status_code >= 400:
            raise AuthError(f"Login to {self.login_url} returned HTTP {resp.status_code} — check credentials.")
        # Session cookies are now stored in the client's jar automatically.
        if self.token_json_path:
            token = _dig(_safe_json(resp), self.token_json_path)
            if not token:
                raise AuthError(
                    f"Login succeeded but no token at JSON path '{self.token_json_path}' in the response."
                )
            return str(token)
        return None

    async def _oauth2(self, client: httpx.AsyncClient) -> str:
        data = {
            "grant_type": "client_credentials",
            "client_id": self.oauth_client_id,
            "client_secret": self.oauth_client_secret,
        }
        if self.oauth_scope:
            data["scope"] = self.oauth_scope
        try:
            resp = await client.post(self.oauth_token_url, data=data)
        except httpx.HTTPError as exc:
            raise AuthError(f"OAuth2 token request to {self.oauth_token_url} failed: {exc}") from exc
        if resp.status_code >= 400:
            raise AuthError(f"OAuth2 token endpoint returned HTTP {resp.status_code}.")
        token = _dig(_safe_json(resp), "access_token")
        if not token:
            raise AuthError("OAuth2 response had no access_token.")
        return str(token)


_INPUT_TAG = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_ATTR_NAME = re.compile(r"""\bname\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
_ATTR_VALUE = re.compile(r"""\bvalue\s*=\s*['"]([^'"]*)['"]""", re.IGNORECASE)


def _extract_hidden_value(html: str, field_name: str) -> str | None:
    """Find ``<input ... name="field_name" ... value="X" ...>`` and return X,
    regardless of attribute order — real-world login forms vary (DVWA puts
    type/name/value in one order, other apps in another)."""
    for tag_match in _INPUT_TAG.finditer(html):
        tag = tag_match.group(0)
        name_m = _ATTR_NAME.search(tag)
        if not name_m or name_m.group(1) != field_name:
            continue
        value_m = _ATTR_VALUE.search(tag)
        if value_m:
            return value_m.group(1)
    return None


def _safe_json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except ValueError:
        return {}


def _dig(data: Any, dotted: str) -> Any:
    """Fetch a value from nested dicts by a dotted path (e.g. 'data.token')."""
    cur = data
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def find_auth_file(cwd: Path | None = None) -> Path | None:
    p = (cwd or Path.cwd()) / AUTH_FILENAME
    return p if p.is_file() else None


def load_auth(path: str | None, *, auto: bool = True) -> AuthConfig | None:
    """Resolve an AuthConfig from an explicit path, or auto-discover one in the
    working directory. Returns None when there's no auth to apply."""
    if path:
        resolved = Path(path).expanduser()
        if not resolved.is_file():
            raise AuthError(f"Auth file not found: {resolved}")
        cfg = AuthConfig.from_toml(resolved)
        return None if cfg.is_empty() else cfg
    if auto:
        found = find_auth_file()
        if found:
            cfg = AuthConfig.from_toml(found)
            return None if cfg.is_empty() else cfg
    return None
