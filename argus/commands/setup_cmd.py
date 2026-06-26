"""Implementation of ``argus setup`` — the first-time wizard."""

from __future__ import annotations

import typer

from argus.cli import output as out
from argus.config import load_settings, save_settings
from argus.config.defaults import CLOUD_PROVIDERS, DEFAULT_CLOUD_MODELS
from argus.llm.detector import detect_gpu, recommend_model


def run_setup() -> None:
    out.banner()
    out.rule("SETUP")
    settings = load_settings()

    # --- hardware detection ---
    out.step("Detecting hardware…")
    gpu = detect_gpu()
    if gpu.detected:
        out.success(f"GPU: [wheat1]{gpu.name}[/] · {gpu.vram_gb:g}GB VRAM")
        model = recommend_model(gpu.vram_gb)
        if model:
            out.success(f"Recommended local model: [yellow3]{model}[/]")
        else:
            out.warn("VRAM too low for a local model; a cloud provider is recommended.")
            model = None
    else:
        out.info("No GPU detected — local models would be slow; use a cloud provider (BYOK).")
        model = None

    # --- choose provider ---
    out.console.print()
    out.console.print("[yellow3]Choose your LLM provider:[/]")
    out.console.print("  [grey46]1[/] local (Ollama)   "
                      "[grey46]2[/] groq   [grey46]3[/] gemini   "
                      "[grey46]4[/] claude   [grey46]5[/] openrouter   "
                      "[grey46]6[/] none (raw scan only)")
    choice = typer.prompt("Provider", default="2" if not gpu.detected else "1").strip().lower()
    mapping = {
        "1": "local", "local": "local",
        "2": "groq", "groq": "groq",
        "3": "gemini", "gemini": "gemini",
        "4": "claude", "claude": "claude",
        "5": "openrouter", "openrouter": "openrouter",
        "6": "none", "none": "none",
    }
    provider = mapping.get(choice, "none")

    if provider == "local":
        settings.set("provider", "preferred", "local")
        chosen = typer.prompt("Local model", default=model or settings.local_model or "qwen2.5-coder:7b")
        settings.set("local", "model", chosen)
        out.success("Configured local Ollama provider. Make sure Ollama is running: [wheat1]ollama serve[/]")
    elif provider in CLOUD_PROVIDERS:
        settings.set("provider", "preferred", provider)
        key = typer.prompt(f"{provider} API key", default="", hide_input=True).strip()
        if key:
            settings.set("cloud", f"{provider}_key", key)
            out.success(f"Stored {provider} key. Default model: "
                        f"[yellow3]{DEFAULT_CLOUD_MODELS.get(provider)}[/]")
        else:
            out.warn("No key entered — set it later with: "
                     f"[wheat1]argus config --provider {provider} --key <KEY>[/]")
    else:
        out.warn("Running in raw-scan-only mode (no LLM). Deterministic findings still work.")

    path = save_settings(settings)
    out.console.print()
    out.success(f"Setup complete. Config saved → [wheat1]{path}[/]")
    out.info("Next: [wheat1]argus scan <repo-url-or-path>[/]")
