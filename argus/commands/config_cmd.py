"""Implementation of ``argus config``."""

from __future__ import annotations

import json

import typer

from argus.cli import output as out
from argus.config import load_settings, save_settings, config_path
from argus.config.defaults import ALL_PROVIDERS, CLOUD_PROVIDERS


def run_config(
    provider: str | None, key: str | None, model: str | None, show: bool,
    notify_webhook: str | None = None,
) -> None:
    settings = load_settings()

    if show or (provider is None and key is None and model is None and notify_webhook is None):
        out.banner()
        out.rule("CONFIGURATION")
        out.info(f"Config file: [wheat1]{config_path()}[/]")
        out.console.print_json(json.dumps(settings.redacted(), indent=2))
        resolved = settings.resolve_provider()
        if resolved:
            out.success(f"Active provider resolves to: [yellow3]{resolved}[/]")
        else:
            out.warn("No LLM provider configured — Argus will run in raw-scan-only mode.")
        return

    changed = False

    if provider is not None:
        if provider not in ALL_PROVIDERS:
            out.error(f"Unknown provider '{provider}'. Choose from: {', '.join(ALL_PROVIDERS)}")
            raise typer.Exit(code=1)
        settings.set("provider", "preferred", provider)
        out.success(f"Preferred provider set to [yellow3]{provider}[/]")
        changed = True

    if model is not None:
        settings.set("local", "model", model)
        out.success(f"Local model set to [yellow3]{model}[/]")
        changed = True

    if key is not None:
        target = provider if provider in CLOUD_PROVIDERS else None
        if target is None:
            out.error("--key requires --provider to be one of: " + ", ".join(CLOUD_PROVIDERS))
            raise typer.Exit(code=1)
        settings.set("cloud", f"{target}_key", key)
        out.success(f"API key stored for [yellow3]{target}[/]")
        changed = True

    if notify_webhook is not None:
        settings.set("notify", "webhook_url", notify_webhook)
        if notify_webhook:
            out.success("Webhook URL saved — scan-complete notifications will be sent there.")
        else:
            out.success("Webhook notifications disabled.")
        changed = True

    if changed:
        path = save_settings(settings)
        out.info(f"Saved → [wheat1]{path}[/]")
