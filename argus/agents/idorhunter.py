"""IDORHunter — broken object-level authorization (IDOR / BOLA).

Without injected credentials this runs the unauthenticated heuristic: find object
identifiers — a numeric path segment like /orders/123, an ``id`` parameter, or a
REST path template like /users/v1/{username} or /api/items/{id} — request
neighbouring/other objects, and report when distinct valid objects come back with
no authentication — a strong signal of missing ownership/access checks.

For a path template the concrete identifier isn't in the URL, so we harvest real
candidate values from the collection endpoint (the same path with the templated
segment dropped, e.g. GET /users/v1 to learn the usernames) and enumerate those
plus a few numeric guesses — the general shape of every modern REST API's IDOR
surface, which a pure /orders/123 pattern never sees.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from argus.agents.base import AgentReport, AttackContext, BaseAgent, build_http_poc
from argus.models import Finding, Severity

_INT_SEG = re.compile(r"/(\d{1,12})(?=/|$)")
# A REST path-template placeholder: /users/v1/{username}, /api/items/{id}.
_TEMPLATE_SEG = re.compile(r"\{([^}/]+)\}")


def _replace_path_int(url: str, original: str, new: str) -> str:
    parsed = urlparse(url)
    new_path = parsed.path.replace(f"/{original}", f"/{new}", 1)
    return urlunparse(parsed._replace(path=new_path))


def _with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [value]
    new_q = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse(parsed._replace(query=new_q))


class IDORHunter(BaseAgent):
    name = "IDORHunter"
    description = "broken object access"

    async def run(self, ctx: AttackContext) -> AgentReport:
        report = AgentReport(agent=self.name, status="running")
        candidates = self._candidates(ctx)
        if not candidates:
            ctx.emit(self.name, "no object identifiers found")
            report.status = "complete"
            return report

        flagged: set[str] = set()
        for kind, url, key in candidates:
            ctx.emit(self.name, f"enumerating {self._short(url)} …")
            if kind == "path":
                await self._probe_path(ctx, url, key, flagged)
            elif kind == "template":
                await self._probe_template(ctx, url, key, flagged)
            else:
                await self._probe_param(ctx, url, key, flagged)

        report.requests_sent = ctx.requests_sent
        report.findings = len([f for f in ctx.findings if f.detector.startswith("idorhunter")])
        report.status = "complete"
        ctx.emit(self.name, f"sweep complete — {len(flagged)} IDOR candidate(s)", "ok")
        return report

    def _candidates(self, ctx: AttackContext) -> list[tuple[str, str, str]]:
        out: list[tuple[str, str, str]] = []
        seen: set[str] = set()
        for ep in ctx.endpoint_list():
            if ep.method != "GET":
                continue
            path = urlparse(ep.url).path
            tmpl = _TEMPLATE_SEG.search(path)
            if tmpl and ep.url not in seen:
                seen.add(ep.url)
                out.append(("template", ep.url, tmpl.group(1)))
                continue
            m = _INT_SEG.search(path)
            if m and ep.url not in seen:
                seen.add(ep.url)
                out.append(("path", ep.url, m.group(1)))
            for p in ep.params:
                if p.lower() in ("id", "user", "userid", "user_id", "account", "order", "oid", "pid"):
                    out.append(("param", ep.url, p))
        return out[:15]

    async def _probe_template(self, ctx: AttackContext, url: str, placeholder: str, flagged: set) -> None:
        """Enumerate a REST path template like /users/v1/{username}. The concrete
        id isn't in the URL, so harvest candidate values from the collection
        endpoint (the path with the `/{placeholder}` segment dropped) and try
        those plus a few numeric guesses. Distinct valid objects across ≥2
        different ids with no auth ⇒ broken object-level access."""
        candidates = self._harvest_ids(ctx, url, placeholder)
        candidates = await self._harvest_from_collection(ctx, url) | candidates
        candidates |= {"1", "2", "3"}
        bodies: set[str] = set()
        hits = 0
        last_resp = last_url = None
        for cand in list(candidates)[:8]:
            probe_url = _TEMPLATE_SEG.sub(cand, url, count=1) if _TEMPLATE_SEG.search(url) else url
            resp = await self.get(ctx, probe_url)
            if resp is not None and resp.status_code < 400:
                snippet = (resp.text or "")[:300]
                if snippet and snippet not in bodies:
                    bodies.add(snippet)
                    hits += 1
                    last_resp, last_url = resp, probe_url
        if hits >= 2:
            flagged.add(url)
            self._report(ctx, f"GET {url}", placeholder, f"'{{{placeholder}}}' path template",
                         last_url, last_resp)

    @staticmethod
    def _harvest_ids(ctx: AttackContext, url: str, placeholder: str) -> set[str]:
        # Numeric-looking placeholder → numeric guesses; otherwise leave to the
        # collection harvest (a {username} can't be guessed numerically).
        if re.search(r"id$|_id$|num|^n$", placeholder, re.IGNORECASE):
            return {"1", "2", "3", "4"}
        return set()

    async def _harvest_from_collection(self, ctx: AttackContext, url: str) -> set[str]:
        """GET the collection endpoint (URL with the /{template} segment removed)
        and pull identifier-shaped scalar values out of its JSON — the real
        usernames/ids to enumerate the per-object endpoint with."""
        collection = _TEMPLATE_SEG.sub("", url, count=1).rstrip("/")
        resp = await self.get(ctx, collection)
        if resp is None or resp.status_code >= 400:
            return set()
        try:
            data = resp.json()
        except Exception:  # noqa: BLE001 — not JSON, nothing to harvest
            return set()
        found: set[str] = set()
        self._walk_scalars(data, found)
        return found

    def _walk_scalars(self, node, found: set[str], depth: int = 0) -> None:
        if depth > 4 or len(found) >= 8:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, (str, int)) and k.lower() in (
                    "id", "username", "user", "name", "user_id", "userid", "email", "uuid"
                ):
                    s = str(v).strip()
                    if s and len(s) <= 64:
                        found.add(s)
                else:
                    self._walk_scalars(v, found, depth + 1)
        elif isinstance(node, list):
            for item in node[:10]:
                self._walk_scalars(item, found, depth + 1)

    async def _probe_path(self, ctx: AttackContext, url: str, original: str, flagged: set) -> None:
        base = await self.get(ctx, url)
        if base is None or base.status_code >= 400:
            return
        n = int(original)
        bodies = {(base.text or "")[:300]}
        hits = 0
        last_resp = None
        last_url = url
        for cand in (n - 1, n + 1, n + 2):
            if cand < 0:
                continue
            cand_url = _replace_path_int(url, original, str(cand))
            resp = await self.get(ctx, cand_url)
            if resp is not None and resp.status_code == base.status_code and resp.status_code < 400:
                snippet = (resp.text or "")[:300]
                if snippet not in bodies:
                    bodies.add(snippet)
                    hits += 1
                    last_resp, last_url = resp, cand_url
        if hits >= 2:
            flagged.add(url)
            self._report(ctx, f"GET {url}", original, "path segment", last_url, last_resp)

    async def _probe_param(self, ctx: AttackContext, url: str, param: str, flagged: set) -> None:
        base = await self.get(ctx, _with_param(url, param, "1"))
        if base is None or base.status_code >= 400:
            return
        bodies = {(base.text or "")[:300]}
        hits = 0
        last_resp = None
        last_url = url
        for cand in ("2", "3", "1000"):
            cand_url = _with_param(url, param, cand)
            resp = await self.get(ctx, cand_url)
            if resp is not None and resp.status_code < 400:
                snippet = (resp.text or "")[:300]
                if snippet not in bodies:
                    bodies.add(snippet)
                    hits += 1
                    last_resp, last_url = resp, cand_url
        if hits >= 2:
            sig = f"{url}::{param}"
            flagged.add(sig)
            self._report(ctx, f"GET {url}", param, f"'{param}' parameter", last_url, last_resp)

    def _report(self, ctx: AttackContext, endpoint: str, key: str, where: str,
                poc_url: str | None = None, resp=None) -> None:
        ctx.report(Finding(
            title="Insecure Direct Object Reference (IDOR)",
            severity=Severity.HIGH,
            category="access-control",
            detector="idorhunter",
            endpoint=endpoint,
            evidence=f"enumerating the {where} returned distinct objects without authentication",
            description=f"Object identifiers ({where}) can be enumerated to read other objects "
                        f"with no ownership/authorization check.",
            exploit="Increment/replace the identifier to access other users' records.",
            fix="Enforce per-object ownership/authorization on every access; use unguessable IDs.",
            cwe="CWE-639",
            cvss=8.1,
            confidence="medium",
            poc=build_http_poc("GET", poc_url, resp) if resp is not None else {},
        ))

    @staticmethod
    def _short(url: str) -> str:
        p = urlparse(url)
        return (p.path or "/") + ("?" + p.query if p.query else "")
