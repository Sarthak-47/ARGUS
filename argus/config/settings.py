"""Read/write Argus configuration as TOML at a cross-platform location.

Config lives at ``~/.argus/config.toml`` (overridable via ``ARGUS_CONFIG`` env var).
Reading uses stdlib ``tomllib`` (3.11+) with a ``tomli`` fallback; writing uses
``tomli_w``. The :class:`Settings` wrapper exposes typed accessors and the
provider-resolution logic.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import tomli_w

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - 3.10 fallback
    import tomli as tomllib  # type: ignore

from argus.config.defaults import DEFAULT_CONFIG, PROVIDER_CHAIN


def config_dir() -> Path:
    """Directory holding Argus config and caches."""
    override = os.environ.get("ARGUS_CONFIG_DIR")
    if override:
        return Path(override)
    # The context doc specifies ~/.argus; honour that for familiarity.
    return Path.home() / ".argus"


def config_path() -> Path:
    override = os.environ.get("ARGUS_CONFIG")
    if override:
        return Path(override)
    return config_dir() / "config.toml"


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge ``override`` into a copy of ``base``."""
    out = {k: (dict(v) if isinstance(v, dict) else v) for k, v in base.items()}
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


class Settings:
    """Typed view over the merged config dictionary."""

    def __init__(self, data: dict[str, Any]):
        self.data = data

    # ----- section accessors -----
    @property
    def preferred_provider(self) -> str:
        return self.data.get("provider", {}).get("preferred", "local")

    @property
    def local_model(self) -> str:
        return self.data.get("local", {}).get("model", "")

    @property
    def local_backend(self) -> str:
        return self.data.get("local", {}).get("backend", "ollama")

    @property
    def default_depth(self) -> str:
        return self.data.get("scan", {}).get("default_depth", "standard")

    @property
    def output_dir(self) -> str:
        return self.data.get("report", {}).get("output_dir", "./argus-report")

    @property
    def default_format(self) -> str:
        return self.data.get("report", {}).get("default_format", "html")

    @property
    def webhook_url(self) -> str:
        return self.data.get("notify", {}).get("webhook_url", "") or ""

    def cloud_key(self, provider: str) -> str:
        return self.data.get("cloud", {}).get(f"{provider}_key", "") or ""

    def has_key(self, provider: str) -> bool:
        return bool(self.cloud_key(provider))

    # ----- provider resolution -----
    def resolve_provider(self) -> str | None:
        """Return the first usable provider following the priority chain.

        ``local`` is considered usable if a model is configured (actual Ollama
        reachability is checked later by the provider itself). Cloud providers are
        usable when a key is present. Returns ``None`` for raw-scan-only mode.
        """
        order = [self.preferred_provider] + [p for p in PROVIDER_CHAIN if p != self.preferred_provider]
        seen: set[str] = set()
        for p in order:
            if p in seen:
                continue
            seen.add(p)
            if p == "local" and self.local_model:
                return "local"
            if p in ("groq", "gemini", "claude", "openrouter") and self.has_key(p):
                return p
        return None

    # ----- mutation -----
    def set(self, section: str, key: str, value: Any) -> None:
        self.data.setdefault(section, {})[key] = value

    def redacted(self) -> dict[str, Any]:
        """Config copy with secrets masked, for display."""
        out = _deep_merge(self.data, {})
        cloud = out.get("cloud", {})
        for k, v in list(cloud.items()):
            if k.endswith("_key") and v:
                cloud[k] = v[:4] + "•" * 8
        notify = out.get("notify", {})
        webhook = notify.get("webhook_url")
        if webhook:
            # Slack/Discord webhook URLs embed a bearer-equivalent token in
            # the path itself — leaking the full URL is exactly as bad as
            # leaking an API key, so it gets the same treatment.
            notify["webhook_url"] = webhook[:24] + "•" * 8
        return out


def load_settings() -> Settings:
    """Load config, merging file contents over defaults. Missing file is fine."""
    path = config_path()
    data = DEFAULT_CONFIG
    if path.exists():
        with path.open("rb") as fh:
            file_data = tomllib.load(fh)
        data = _deep_merge(DEFAULT_CONFIG, file_data)
    else:
        data = _deep_merge(DEFAULT_CONFIG, {})
    return Settings(data)


def save_settings(settings: Settings) -> Path:
    """Persist config to disk, creating the directory if needed."""
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        tomli_w.dump(settings.data, fh)
    return path
