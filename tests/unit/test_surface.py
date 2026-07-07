"""Tests for the persistent attack-surface inventory."""

from __future__ import annotations

from argus.agents.base import Endpoint
from argus.surface import load_surface, save_surface, surface_path


def _ep(url, method="GET", params=None, status=200):
    return Endpoint(url=url, method=method, params=params or [], sample_status=status)


def test_load_surface_empty_when_absent():
    assert load_surface("http://nope.test") == []


def test_save_and_load_roundtrip():
    save_surface("t1", [_ep("http://t/a"), _ep("http://t/b", method="POST", params=["x"])])
    loaded = load_surface("t1")
    by_key = {e.key(): e for e in loaded}
    assert "GET http://t/a" in by_key
    assert by_key["POST http://t/b"].params == ["x"]


def test_save_merges_union_across_runs():
    save_surface("t2", [_ep("http://t/a")])
    save_surface("t2", [_ep("http://t/b")])  # different endpoint, second run
    urls = {e.url for e in load_surface("t2")}
    assert urls == {"http://t/a", "http://t/b"}  # union, not replacement


def test_save_merges_params_for_same_endpoint():
    save_surface("t3", [_ep("http://t/a", params=["x"])])
    save_surface("t3", [_ep("http://t/a", params=["y"])])
    ep = load_surface("t3")[0]
    assert set(ep.params) == {"x", "y"}


def test_different_targets_are_isolated():
    save_surface("target-a", [_ep("http://a/x")])
    save_surface("target-b", [_ep("http://b/y")])
    assert {e.url for e in load_surface("target-a")} == {"http://a/x"}
    assert {e.url for e in load_surface("target-b")} == {"http://b/y"}


def test_surface_path_is_filename_safe_for_url_targets():
    # A URL with slashes/colons must hash to a safe filename, not blow up.
    p = surface_path("http://example.com/a/b?c=d")
    assert p.name.endswith(".json")
    assert "/" not in p.name and ":" not in p.name


def test_save_surface_survives_corrupt_existing_file():
    path = surface_path("t-corrupt")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{ not valid json", encoding="utf-8")
    # Should treat the corrupt prior file as empty, not crash.
    save_surface("t-corrupt", [_ep("http://t/a")])
    assert {e.url for e in load_surface("t-corrupt")} == {"http://t/a"}
