"""Inline PR review comments for CI (roadmap v0.5.2).

`argus scan --diff-base <base>` already narrows findings to what a PR actually
introduces. This posts each of those findings as an inline GitHub PR review
comment — right on the changed line, in the diff view — instead of only being
visible in a SARIF upload buried in the Security tab. Complements SARIF; doesn't
replace it. GitHub Advanced Security parity for repos that don't have GHAS.

Designed to run inside GitHub Actions with zero extra setup: a workflow job
gets a `GITHUB_TOKEN` automatically, and the standard `pull_request` event
payload (at `GITHUB_EVENT_PATH`) carries the PR number. No `gh` CLI dependency
(unlike the auto-fix-PR feature) — this talks to the REST API directly via
httpx, which Argus already depends on.

Idempotent: each comment embeds an invisible fingerprint
(``<!-- argus:<sig> -->``) derived from the same signature `argus compare` uses,
so re-running CI on the same PR doesn't double-post; existing comments are
listed once and matched before posting anything new.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from argus.compare import finding_signature
from argus.models import Finding, Severity

_API = "https://api.github.com"
_SEV_EMOJI = {
    Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵", Severity.INFO: "⚪",
}


class PrCommentError(RuntimeError):
    """Raised when the GitHub API interaction can't proceed at all."""


@dataclass
class PrContext:
    owner: str
    repo: str
    pr_number: int
    commit_sha: str
    token: str


@dataclass
class PrCommentResult:
    posted: int = 0
    skipped_duplicate: int = 0
    skipped_not_in_diff: int = 0
    skipped_no_location: int = 0
    errors: list[str] = field(default_factory=list)


def context_from_env(env: dict[str, str] | None = None) -> PrContext | None:
    """Build a :class:`PrContext` from the standard GitHub Actions environment.

    Returns ``None`` (not an error) when the environment doesn't describe a pull
    request — e.g. a push-event run, or running locally — so callers can no-op
    rather than fail.
    """
    e = env if env is not None else os.environ
    token = e.get("GITHUB_TOKEN") or e.get("GH_TOKEN")
    repo_full = e.get("GITHUB_REPOSITORY")
    sha = e.get("GITHUB_SHA")
    event_path = e.get("GITHUB_EVENT_PATH")
    if not (token and repo_full and sha and event_path):
        return None
    if "/" not in repo_full:
        return None
    owner, repo = repo_full.split("/", 1)

    try:
        payload = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    pr = payload.get("pull_request")
    if not isinstance(pr, dict) or not pr.get("number"):
        return None
    return PrContext(owner=owner, repo=repo, pr_number=int(pr["number"]), commit_sha=sha, token=token)


def finding_fingerprint(f: Finding) -> str:
    """A short, stable id for a finding — the same signature `argus compare`
    uses, hashed so it's safe to embed invisibly in a comment body."""
    sig = "||".join(str(p) for p in finding_signature(f))
    return hashlib.sha256(sig.encode()).hexdigest()[:16]


def build_comment_body(f: Finding) -> str:
    emoji = _SEV_EMOJI.get(f.severity, "⚪")
    lines = [f"{emoji} **{f.severity.value} — {f.title}**", ""]
    if f.description:
        lines.append(f.description)
        lines.append("")
    if f.fix:
        lines.append(f"**Fix:** {f.fix}")
        lines.append("")
    lines.append(f"*Flagged by [Argus](https://github.com/Sarthak-47/ARGUS) "
                 f"({f.detector}{f' · {f.cwe}' if f.cwe else ''})*")
    lines.append(f"<!-- argus:{finding_fingerprint(f)} -->")
    return "\n".join(lines)


def _headers(ctx: PrContext) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {ctx.token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


async def _existing_fingerprints(ctx: PrContext, client: httpx.AsyncClient) -> set[str]:
    """Fingerprints already posted on this PR (across all pages), so a re-run
    doesn't duplicate comments."""
    fps: set[str] = set()
    url = f"{_API}/repos/{ctx.owner}/{ctx.repo}/pulls/{ctx.pr_number}/comments?per_page=100"
    for _ in range(10):  # hard cap — this is a safety net, not a real pager
        resp = await client.get(url, headers=_headers(ctx))
        if resp.status_code != 200:
            break
        for c in resp.json() or []:
            body = c.get("body") or ""
            if "<!-- argus:" in body:
                fps.add(body.rsplit("<!-- argus:", 1)[-1].split(" ")[0].rstrip("-> \n"))
        next_url = resp.links.get("next", {}).get("url")
        if not next_url:
            break
        url = next_url
    return fps


async def post_review_comments(
    ctx: PrContext, findings: list[Finding], *, client: httpx.AsyncClient | None = None
) -> PrCommentResult:
    """Post each file/line finding as an inline PR review comment. Idempotent
    (skips ones already posted) and degrades gracefully: a comment on a line
    outside the PR's diff is skipped rather than failing the whole batch."""
    result = PrCommentResult()
    locatable = [f for f in findings if f.file and f.line]
    result.skipped_no_location = len(findings) - len(locatable)
    if not locatable:
        return result

    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=15.0)
    try:
        existing = await _existing_fingerprints(ctx, client)
        to_post = []
        for f in locatable:
            if finding_fingerprint(f) in existing:
                result.skipped_duplicate += 1
            else:
                to_post.append(f)
        if not to_post:
            return result

        # One atomic review with all comments — GitHub validates every comment's
        # line is within the PR's diff and 422s the whole call if any aren't, so
        # fall back to posting them individually and skip just the offenders.
        review_url = f"{_API}/repos/{ctx.owner}/{ctx.repo}/pulls/{ctx.pr_number}/reviews"
        payload = {
            "commit_id": ctx.commit_sha,
            "event": "COMMENT",
            "body": f"Argus found {len(to_post)} new finding(s) in this PR.",
            "comments": [
                {"path": f.file, "line": f.line, "side": "RIGHT", "body": build_comment_body(f)}
                for f in to_post
            ],
        }
        resp = await client.post(review_url, headers=_headers(ctx), json=payload)
        if resp.status_code in (200, 201):
            result.posted = len(to_post)
            return result

        # Fallback: post one at a time so a single bad line doesn't sink the batch.
        comment_url = f"{_API}/repos/{ctx.owner}/{ctx.repo}/pulls/{ctx.pr_number}/comments"
        for f in to_post:
            body = {"commit_id": ctx.commit_sha, "path": f.file, "line": f.line,
                    "side": "RIGHT", "body": build_comment_body(f)}
            r = await client.post(comment_url, headers=_headers(ctx), json=body)
            if r.status_code in (200, 201):
                result.posted += 1
            elif r.status_code == 422:
                result.skipped_not_in_diff += 1
            else:
                result.errors.append(f"{f.file}:{f.line} -> HTTP {r.status_code}")
        return result
    finally:
        if owns_client:
            await client.aclose()
