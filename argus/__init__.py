"""Argus — AI-powered security audit agent.

Point it at a repo. It reads the code, spins up the app, and attacks it.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    # Single source of truth: pyproject.toml's [project].version, via the
    # installed package's metadata. A hardcoded string here drifted out of
    # sync with every real release for the project's entire history (this
    # silently reported "0.1.0" in `argus --version` and in every SBOM/VEX
    # export's tool-version field, regardless of the actual shipped version).
    __version__ = version("argus-panoptes")
except PackageNotFoundError:  # running from source, not pip-installed
    __version__ = "0.0.0-dev"

__all__ = ["__version__"]
