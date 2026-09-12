"""Argus — AI-powered security audit agent.

Point it at a repo. It reads the code, spins up the app, and attacks it.
"""

from importlib.metadata import PackageNotFoundError, distributions, version


def _version_sort_key(v: str) -> tuple[int, ...]:
    """Order plain ``X.Y.Z`` release strings numerically (1.2.9 < 1.2.10)."""
    out = []
    for part in v.split(".")[:3]:
        digits = "".join(ch for ch in part if ch.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out)


def _resolve_version() -> str:
    # Single source of truth: pyproject.toml's [project].version, read back from
    # the installed package's metadata (a hardcoded string here drifted out of
    # sync with every real release for the project's whole history).
    #
    # But the desktop app bundles this package as a PyInstaller *onedir* whose
    # ``*.dist-info`` directory is named with the version, and its NSIS installer
    # upgrades in place by overlaying files — so an in-place upgrade leaves the
    # previous version's ``argus_panoptes-<old>.dist-info`` orphaned next to the
    # new one. ``importlib.metadata.version()`` then returns whichever it finds
    # first, which was observed to be the *stale* one (a 1.2.30 bundle upgraded
    # to 1.2.32 reported 1.2.30 in ``argus --version`` and in every SBOM/VEX
    # tool-version field). When more than one is present, take the highest — the
    # bundle's actual code is always the newest installed.
    try:
        found = [
            d.version
            for d in distributions()
            if (d.metadata["Name"] or "").lower() == "argus-panoptes" and d.version
        ]
        if len(found) > 1:
            return max(found, key=_version_sort_key)
        if found:
            return found[0]
        return version("argus-panoptes")
    except PackageNotFoundError:  # running from source, not installed
        return "0.0.0-dev"


__version__ = _resolve_version()

__all__ = ["__version__"]
