"""Tests for inline GitHub PR review comments (argus/prcomments.py)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from argus.models import Finding, Severity
from argus.prcomments import (
    PrContext,
    build_comment_body,
    context_from_env,
    finding_fingerprint,
    post_review_comments,
)

_PR_EVENT = {"action": "opened", "pull_request": {"number": 42}}
_PUSH_ENV = {
    "GITHUB_TOKEN": "tok", "GITHUB_REPOSITORY": "acme/widgets", "GITHUB_SHA": "abc123",
}


def _finding(**kw) -> Finding:
    base = dict(title="SQL Injection", severity=Severity.HIGH, category="injection",
                detector="rule:x", file="app.py", line=42)
    base.update(kw)
    return Finding(**base)


# ----- context_from_env -----

def test_context_from_env_parses_pr_number(tmp_path: Path):
    event_file = tmp_path / "event.json"
    event_file.write_text(json.dumps(_PR_EVENT), encoding="utf-8")
    env = {**_PUSH_ENV, "GITHUB_EVENT_PATH": str(event_file)}
    ctx = context_from_env(env)
    assert ctx == PrContext(owner="acme", repo="widgets", pr_number=42, commit_sha="abc123", token="tok")


def test_context_from_env_none_when_not_a_pr(tmp_path: Path):
    event_file = tmp_path / "event.json"
    event_file.write_text(json.dumps({"action": "push"}), encoding="utf-8")
    env = {**_PUSH_ENV, "GITHUB_EVENT_PATH": str(event_file)}
    assert context_from_env(env) is None


def test_context_from_env_none_when_missing_token():
    assert context_from_env({"GITHUB_REPOSITORY": "a/b", "GITHUB_SHA": "x", "GITHUB_EVENT_PATH": "x"}) is None


def test_context_from_env_none_when_event_file_missing(tmp_path: Path):
    env = {**_PUSH_ENV, "GITHUB_EVENT_PATH": str(tmp_path / "nope.json")}
    assert context_from_env(env) is None


def test_context_from_env_accepts_gh_token_fallback(tmp_path: Path):
    event_file = tmp_path / "event.json"
    event_file.write_text(json.dumps(_PR_EVENT), encoding="utf-8")
    env = {"GH_TOKEN": "tok2", "GITHUB_REPOSITORY": "acme/widgets", "GITHUB_SHA": "sha",
           "GITHUB_EVENT_PATH": str(event_file)}
    ctx = context_from_env(env)
    assert ctx.token == "tok2"


# ----- fingerprint / body -----

def test_fingerprint_is_stable_and_short():
    f = _finding()
    fp1 = finding_fingerprint(f)
    fp2 = finding_fingerprint(_finding())  # different id, same signature
    assert fp1 == fp2
    assert len(fp1) == 16


def test_fingerprint_differs_for_different_findings():
    assert finding_fingerprint(_finding()) != finding_fingerprint(_finding(title="XSS"))


def test_comment_body_embeds_fingerprint_and_content():
    f = _finding(description="tainted input reaches a query", fix="use parameterised queries")
    body = build_comment_body(f)
    assert "SQL Injection" in body
    assert "tainted input" in body
    assert "parameterised queries" in body
    assert f"<!-- argus:{finding_fingerprint(f)} -->" in body


# ----- post_review_comments -----

def _ctx() -> PrContext:
    return PrContext(owner="acme", repo="widgets", pr_number=42, commit_sha="deadbeef", token="tok")


@pytest.mark.asyncio
async def test_posts_all_findings_when_none_exist_and_review_succeeds():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "GET" and "/pulls/42/comments" in str(request.url):
            return httpx.Response(200, json=[])
        if request.method == "POST" and str(request.url).endswith("/pulls/42/reviews"):
            body = json.loads(request.content)
            assert body["commit_id"] == "deadbeef"
            assert len(body["comments"]) == 2
            return httpx.Response(200, json={"id": 1})
        return httpx.Response(404)

    findings = [_finding(title="SQLi"), _finding(title="XSS", line=10)]
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await post_review_comments(_ctx(), findings, client=client)

    assert result.posted == 2
    assert result.skipped_duplicate == 0


@pytest.mark.asyncio
async def test_skips_findings_already_commented():
    f = _finding(title="SQLi")
    fp = finding_fingerprint(f)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and "/pulls/42/comments" in str(request.url):
            return httpx.Response(200, json=[{"body": f"already flagged\n<!-- argus:{fp} -->"}])
        return httpx.Response(404)  # a POST here would be a bug — nothing left to post

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await post_review_comments(_ctx(), [f], client=client)

    assert result.posted == 0
    assert result.skipped_duplicate == 1


@pytest.mark.asyncio
async def test_falls_back_to_individual_comments_when_review_422s():
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if request.method == "GET" and "/pulls/42/comments" in url and request.method == "GET":
            return httpx.Response(200, json=[])
        if request.method == "POST" and url.endswith("/pulls/42/reviews"):
            return httpx.Response(422, json={"message": "line not in diff"})
        if request.method == "POST" and url.endswith("/pulls/42/comments"):
            body = json.loads(request.content)
            if body["line"] == 42:
                return httpx.Response(201, json={"id": 5})
            return httpx.Response(422, json={"message": "pull_request_review_thread.line not in diff"})
        return httpx.Response(404)

    findings = [_finding(title="in-diff", line=42), _finding(title="not-in-diff", line=999)]
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await post_review_comments(_ctx(), findings, client=client)

    assert result.posted == 1
    assert result.skipped_not_in_diff == 1


@pytest.mark.asyncio
async def test_findings_without_location_are_skipped():
    no_loc = Finding(title="X", severity=Severity.LOW, category="c", detector="d")  # no file/line

    async def _unused_handler(request):  # pragma: no cover - must never be called
        raise AssertionError("no HTTP call should happen with zero locatable findings")

    async with httpx.AsyncClient(transport=httpx.MockTransport(_unused_handler)) as client:
        result = await post_review_comments(_ctx(), [no_loc], client=client)

    assert result.posted == 0
    assert result.skipped_no_location == 1


@pytest.mark.asyncio
async def test_empty_findings_list_is_a_clean_noop():
    result = await post_review_comments(_ctx(), [])
    assert result.posted == 0
    assert result.errors == []
