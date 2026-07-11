"""Implementation of ``argus status`` — resolved provider, GPU, and defaults.

Exists so the desktop GUI's Settings/Sidebar screens can show real state
(which provider will actually run, what model, what hardware was detected,
what the configured scan/report defaults are) instead of guessing or —
worse — showing fixed placeholder values that never reflect reality.
"""

from __future__ import annotations

import json

from argus.cli import output as out
from argus.config import load_settings


def _status_payload() -> dict:
    from argus.llm.detector import detect_gpu, list_ollama_models, recommend_model
    from argus.llm.orchestrator import AGENT_REGISTRY
    from argus.llm.provider import build_provider

    settings = load_settings()
    resolved = settings.resolve_provider()
    model = None
    available = False
    if resolved:
        provider = build_provider(resolved, settings)
        if provider is not None:
            model = provider.model
            available = provider.available()

    gpu = detect_gpu()
    recommended = recommend_model(gpu.vram_gb) if gpu.detected else None
    # Every model actually pulled in the local Ollama install, so Settings can
    # offer a real choice among what's already on this machine — not just the
    # one size-recommended default. Empty when Ollama isn't running; cheap
    # either way (a 2s-timeout local HTTP call).
    local_models = list_ollama_models()

    return {
        "resolved_provider": resolved,
        "preferred_provider": settings.preferred_provider,
        "model": model,
        "available": available,
        "gpu": {
            "vendor": gpu.vendor, "name": gpu.name,
            "vram_gb": gpu.vram_gb, "detected": gpu.detected,
        },
        "recommended_model": recommended,
        "local_models": local_models,
        "scan_defaults": {"depth": settings.default_depth},
        "report_defaults": {"output_dir": settings.output_dir, "format": settings.default_format},
        "agent_count": len(AGENT_REGISTRY),
    }


def run_status(fmt: str) -> None:
    payload = _status_payload()

    if fmt == "json":
        out.console.print_json(json.dumps(payload))
        return

    out.banner()
    out.rule("STATUS")
    if payload["resolved_provider"]:
        reach = "reachable" if payload["available"] else "configured but unreachable"
        out.success(f"Provider: [yellow3]{payload['resolved_provider']}[/] "
                     f"({payload['model']}) — {reach}")
    else:
        out.warn("No LLM provider configured — Argus runs in raw-scan-only mode.")

    gpu = payload["gpu"]
    if gpu["detected"]:
        out.info(f"GPU: [wheat1]{gpu['name']}[/] ({gpu['vram_gb']} GB) — "
                  f"recommended local model: {payload['recommended_model']}")
    else:
        out.info("No GPU detected.")

    out.info(f"Scan default depth: {payload['scan_defaults']['depth']}")
    out.info(f"Report output dir: {payload['report_defaults']['output_dir']} "
              f"(default format: {payload['report_defaults']['format']})")
    out.info(f"Attack agents available: {payload['agent_count']}")
