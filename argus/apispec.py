"""API schema ingestion (roadmap v0.3.2).

Modern apps are API-first and stateful; a crawler that follows links misses most
of the surface. If you have the spec, hand it to Argus and it seeds the attack
surface directly:

    argus attack --url http://localhost:3000 --api-spec openapi.yaml

Supports OpenAPI 3.x, Swagger 2.0, Postman v2 collections, and a GraphQL
introspection dump — as a file path or a URL. Every endpoint the spec declares
becomes an :class:`Endpoint` seeded before recon, so the whole swarm tests it
even if the crawler never reaches it. Paths are resolved against the attack
``base_url`` (plus any basePath the spec declares), so a spec written for
production still points at your local/staging target.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from argus.agents.base import Endpoint

_METHODS = ("get", "post", "put", "delete", "patch", "head", "options")


class ApiSpecError(RuntimeError):
    """Raised when a spec can't be read or understood."""


# --------------------------------------------------------------------------- #
# public entry point
# --------------------------------------------------------------------------- #
def load_endpoints(source: str, base_url: str) -> tuple[list[Endpoint], str]:
    """Parse an API spec into seed endpoints resolved against ``base_url``.

    Returns (endpoints, human-note). Raises :class:`ApiSpecError` on failure.
    """
    raw = _read_source(source)
    return parse_spec_text(raw, base_url)


def parse_spec_text(raw: str, base_url: str) -> tuple[list[Endpoint], str]:
    """Like :func:`load_endpoints` but takes the spec's raw text directly —
    for a caller (ReconBot's spec auto-discovery) that already fetched the
    response body and shouldn't re-fetch it."""
    data = _parse(raw)
    if not isinstance(data, dict):
        raise ApiSpecError("Spec did not parse to an object.")

    base = base_url.rstrip("/")
    kind = _detect(data)
    if kind == "openapi3":
        eps = _from_openapi(data, base, oas3=True)
    elif kind == "swagger2":
        eps = _from_openapi(data, base, oas3=False)
    elif kind == "postman":
        eps = _from_postman(data, base)
    elif kind == "graphql":
        eps = _from_graphql(data, base)
    else:
        raise ApiSpecError(
            "Unrecognized spec — expected OpenAPI 3, Swagger 2, a Postman v2 "
            "collection, or a GraphQL introspection dump."
        )
    # De-dup on method+url.
    seen: dict[str, Endpoint] = {}
    for ep in eps:
        seen.setdefault(ep.key(), ep)
    endpoints = list(seen.values())
    return endpoints, f"{kind}: seeded {len(endpoints)} endpoint(s)"


# --------------------------------------------------------------------------- #
# reading / parsing
# --------------------------------------------------------------------------- #
def _read_source(source: str) -> str:
    if source.startswith(("http://", "https://")):
        import httpx

        try:
            resp = httpx.get(source, timeout=15.0, follow_redirects=True)
            resp.raise_for_status()
            return resp.text
        except httpx.HTTPError as exc:
            raise ApiSpecError(f"Could not fetch spec from {source}: {exc}") from exc
    from pathlib import Path

    p = Path(source).expanduser()
    if not p.is_file():
        raise ApiSpecError(f"Spec file not found: {p}")
    try:
        return p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ApiSpecError(f"Could not read spec {p}: {exc}") from exc


def _parse(raw: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    try:
        import yaml

        return yaml.safe_load(raw)
    except ImportError:  # pragma: no cover - PyYAML is a declared dependency
        raise ApiSpecError("Spec isn't JSON and PyYAML isn't available for YAML parsing.")
    except yaml.YAMLError as exc:
        raise ApiSpecError(f"Spec is neither valid JSON nor YAML: {exc}") from exc


def _detect(data: dict) -> str | None:
    if str(data.get("openapi", "")).startswith("3"):
        return "openapi3"
    if str(data.get("swagger", "")) == "2.0":
        return "swagger2"
    schema = str(data.get("info", {}).get("schema", "")) if isinstance(data.get("info"), dict) else ""
    if "getpostman" in schema or ("item" in data and "info" in data):
        return "postman"
    if "__schema" in data or "__schema" in (data.get("data") or {}):
        return "graphql"
    return None


# --------------------------------------------------------------------------- #
# OpenAPI 3.x / Swagger 2.0
# --------------------------------------------------------------------------- #
def _openapi_base_path(data: dict, oas3: bool) -> str:
    if oas3:
        servers = data.get("servers") or []
        if servers and isinstance(servers[0], dict):
            return urlparse(str(servers[0].get("url", ""))).path.rstrip("/")
        return ""
    return str(data.get("basePath", "")).rstrip("/")


def _from_openapi(data: dict, base: str, *, oas3: bool) -> list[Endpoint]:
    base_path = _openapi_base_path(data, oas3)
    paths = data.get("paths") or {}
    out: list[Endpoint] = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared_params = _param_names(item.get("parameters"))
        for method in _METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            params = list(shared_params)
            params += _param_names(op.get("parameters"))
            content_type = None
            if oas3:
                body = (op.get("requestBody") or {}).get("content") or {}
                if body:
                    content_type = next(iter(body), None)
                    for spec in body.values():
                        params += _schema_props((spec or {}).get("schema"))
                        break
            else:
                consumes = data.get("consumes") or op.get("consumes")
                if consumes:
                    content_type = consumes[0]
            url = base + base_path + path
            out.append(Endpoint(
                url=url, method=method.upper(), params=_dedup(params),
                content_type=content_type, source="openapi",
            ))
    return out


def _param_names(params: Any) -> list[str]:
    if not isinstance(params, list):
        return []
    return [str(p["name"]) for p in params if isinstance(p, dict) and p.get("name")]


def _schema_props(schema: Any) -> list[str]:
    if not isinstance(schema, dict):
        return []
    props = schema.get("properties")
    if isinstance(props, dict):
        return [str(k) for k in props.keys()]
    return []


# --------------------------------------------------------------------------- #
# Postman v2 collection
# --------------------------------------------------------------------------- #
def _from_postman(data: dict, base: str) -> list[Endpoint]:
    out: list[Endpoint] = []
    _walk_postman(data.get("item") or [], base, out)
    return out


def _walk_postman(items: list, base: str, out: list[Endpoint]) -> None:
    for it in items:
        if not isinstance(it, dict):
            continue
        if isinstance(it.get("item"), list):  # a folder
            _walk_postman(it["item"], base, out)
            continue
        req = it.get("request")
        if not isinstance(req, dict):
            continue
        method = str(req.get("method", "GET")).upper()
        path, query = _postman_url(req.get("url"))
        if path is None:
            continue
        params = list(query)
        params += _postman_body_params(req.get("body"))
        out.append(Endpoint(
            url=base + path, method=method, params=_dedup(params), source="postman",
        ))


def _postman_url(url: Any) -> tuple[str | None, list[str]]:
    """Return (path, query-param-names) from a Postman url (string or object)."""
    if isinstance(url, str):
        parsed = urlparse(url)
        return (parsed.path or "/"), []
    if isinstance(url, dict):
        segs = url.get("path")
        if isinstance(segs, list):
            path = "/" + "/".join(str(s) for s in segs)
        else:
            raw = str(url.get("raw", ""))
            path = urlparse(raw).path or "/"
        query = [str(q["key"]) for q in (url.get("query") or []) if isinstance(q, dict) and q.get("key")]
        return path, query
    return None, []


def _postman_body_params(body: Any) -> list[str]:
    if not isinstance(body, dict):
        return []
    mode = body.get("mode")
    if mode in ("urlencoded", "formdata"):
        return [str(f["key"]) for f in (body.get(mode) or []) if isinstance(f, dict) and f.get("key")]
    if mode == "raw":
        try:
            parsed = json.loads(body.get("raw") or "")
            if isinstance(parsed, dict):
                return [str(k) for k in parsed.keys()]
        except (json.JSONDecodeError, TypeError):
            return []
    return []


# --------------------------------------------------------------------------- #
# GraphQL introspection
# --------------------------------------------------------------------------- #
def _from_graphql(data: dict, base: str) -> list[Endpoint]:
    schema = data.get("__schema") or (data.get("data") or {}).get("__schema") or {}
    ops: list[str] = []
    for root_key in ("queryType", "mutationType"):
        root = schema.get(root_key)
        if not isinstance(root, dict):
            continue
        type_name = root.get("name")
        for t in schema.get("types") or []:
            if isinstance(t, dict) and t.get("name") == type_name:
                ops += [str(f["name"]) for f in (t.get("fields") or []) if isinstance(f, dict) and f.get("name")]
    # GraphQL is a single endpoint; seed the conventional path with the
    # operations as manipulable "params" so the GraphQL agent has a head start.
    return [Endpoint(url=base + "/graphql", method="POST", params=_dedup(ops),
                     content_type="application/json", source="graphql")]


def _dedup(items: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for i in items:
        seen.setdefault(i, None)
    return list(seen.keys())
