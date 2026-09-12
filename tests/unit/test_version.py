"""The desktop app bundles this package as a PyInstaller onedir upgraded in
place, which can orphan the previous version's ``*.dist-info`` next to the new
one — making a naive ``importlib.metadata.version()`` return the stale version
in ``argus --version`` and in every SBOM/VEX tool-version field. These guard the
resolver that fixes that."""

from __future__ import annotations

import argus


def test_version_sort_key_orders_numerically():
    from argus import _version_sort_key

    # String comparison would put "1.2.9" after "1.2.10"; numeric must not.
    assert _version_sort_key("1.2.9") < _version_sort_key("1.2.10")
    assert _version_sort_key("1.2.32") > _version_sort_key("1.2.30")
    assert _version_sort_key("2.0.0") > _version_sort_key("1.9.9")


def test_resolve_version_picks_highest_when_dist_info_duplicated(monkeypatch):
    """The exact in-place-upgrade scenario: two argus-panoptes dist-infos on
    disk at once. The resolver must report the newest, not whichever enumerates
    first."""
    class _Dist:
        def __init__(self, name, version):
            self.metadata = {"Name": name}
            self.version = version

    dists = [
        _Dist("some-other-pkg", "9.9.9"),
        _Dist("argus-panoptes", "1.2.30"),   # orphaned old metadata
        _Dist("argus-panoptes", "1.2.32"),   # the actual installed version
    ]
    monkeypatch.setattr(argus, "distributions", lambda: iter(dists))
    assert argus._resolve_version() == "1.2.32"


def test_resolve_version_single_dist_info(monkeypatch):
    class _Dist:
        def __init__(self, name, version):
            self.metadata = {"Name": name}
            self.version = version

    monkeypatch.setattr(argus, "distributions", lambda: iter([_Dist("argus-panoptes", "1.2.32")]))
    assert argus._resolve_version() == "1.2.32"


def test_resolve_version_falls_back_when_not_installed(monkeypatch):
    from importlib.metadata import PackageNotFoundError

    def _boom():
        raise PackageNotFoundError("argus-panoptes")

    # No matching distribution, and version() raises → dev fallback.
    monkeypatch.setattr(argus, "distributions", lambda: iter([]))
    monkeypatch.setattr(argus, "version", lambda name: (_ for _ in ()).throw(PackageNotFoundError()))
    assert argus._resolve_version() == "0.0.0-dev"
