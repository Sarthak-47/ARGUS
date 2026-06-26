"""Unified LLM interface across Ollama (local) and cloud providers (BYOK).

One ``complete(system, user)`` method, four cloud backends plus local Ollama, all
spoken over httpx so we avoid heavy per-vendor SDKs. The factory ``get_provider``
reads Settings, resolves the active provider via the priority chain, and returns
``None`` when nothing is configured (raw-scan-only mode).
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from argus.config.defaults import (
    DEFAULT_CLOUD_MODELS,
    PROVIDER_ENDPOINTS,
)
from argus.config.settings import Settings


class LLMError(RuntimeError):
    """Raised when an LLM call fails in a way the caller should know about."""


@dataclass
class LLMResult:
    text: str
    provider: str
    model: str


class BaseProvider:
    name = "base"

    def __init__(self, model: str, timeout: float = 90.0):
        self.model = model
        self.timeout = timeout

    def complete(self, system: str, user: str, *, json_mode: bool = False) -> LLMResult:  # pragma: no cover
        raise NotImplementedError

    def available(self) -> bool:
        return True


class OllamaProvider(BaseProvider):
    name = "local"

    def __init__(self, model: str, host: str | None = None, timeout: float = 180.0):
        super().__init__(model, timeout)
        self.url = host or PROVIDER_ENDPOINTS["ollama"]

    def available(self) -> bool:
        base = self.url.replace("/api/chat", "")
        try:
            r = httpx.get(f"{base}/api/tags", timeout=3.0)
            return r.status_code == 200
        except httpx.HTTPError:
            return False

    def complete(self, system: str, user: str, *, json_mode: bool = False) -> LLMResult:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {"temperature": 0.1},
        }
        if json_mode:
            payload["format"] = "json"
        try:
            r = httpx.post(self.url, json=payload, timeout=self.timeout)
            r.raise_for_status()
            data = r.json()
        except httpx.HTTPError as exc:
            raise LLMError(f"Ollama request failed: {exc}") from exc
        return LLMResult(data.get("message", {}).get("content", ""), self.name, self.model)


class OpenAICompatProvider(BaseProvider):
    """Groq and OpenRouter both speak the OpenAI chat-completions schema."""

    def __init__(self, name: str, api_key: str, model: str, endpoint: str, timeout: float = 90.0):
        super().__init__(model, timeout)
        self.name = name
        self.api_key = api_key
        self.endpoint = endpoint

    def available(self) -> bool:
        return bool(self.api_key)

    def complete(self, system: str, user: str, *, json_mode: bool = False) -> LLMResult:
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        if self.name == "openrouter":
            headers["HTTP-Referer"] = "https://github.com/Sarthak-47/ARGUS"
            headers["X-Title"] = "Argus"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.1,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        try:
            r = httpx.post(self.endpoint, json=payload, headers=headers, timeout=self.timeout)
            r.raise_for_status()
            data = r.json()
        except httpx.HTTPError as exc:
            raise LLMError(f"{self.name} request failed: {exc}") from exc
        return LLMResult(data["choices"][0]["message"]["content"], self.name, self.model)


class ClaudeProvider(BaseProvider):
    name = "claude"

    def __init__(self, api_key: str, model: str, timeout: float = 90.0):
        super().__init__(model, timeout)
        self.api_key = api_key
        self.endpoint = PROVIDER_ENDPOINTS["claude"]

    def available(self) -> bool:
        return bool(self.api_key)

    def complete(self, system: str, user: str, *, json_mode: bool = False) -> LLMResult:
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": self.model,
            "max_tokens": 4096,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "temperature": 0.1,
        }
        try:
            r = httpx.post(self.endpoint, json=payload, headers=headers, timeout=self.timeout)
            r.raise_for_status()
            data = r.json()
        except httpx.HTTPError as exc:
            raise LLMError(f"Claude request failed: {exc}") from exc
        parts = data.get("content", [])
        text = "".join(p.get("text", "") for p in parts if p.get("type") == "text")
        return LLMResult(text, self.name, self.model)


class GeminiProvider(BaseProvider):
    name = "gemini"

    def __init__(self, api_key: str, model: str, timeout: float = 90.0):
        super().__init__(model, timeout)
        self.api_key = api_key

    def available(self) -> bool:
        return bool(self.api_key)

    def complete(self, system: str, user: str, *, json_mode: bool = False) -> LLMResult:
        base = PROVIDER_ENDPOINTS["gemini"]
        url = f"{base}/{self.model}:generateContent?key={self.api_key}"
        payload = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {"temperature": 0.1},
        }
        if json_mode:
            payload["generationConfig"]["responseMimeType"] = "application/json"
        try:
            r = httpx.post(url, json=payload, timeout=self.timeout)
            r.raise_for_status()
            data = r.json()
        except httpx.HTTPError as exc:
            raise LLMError(f"Gemini request failed: {exc}") from exc
        cands = data.get("candidates", [])
        if not cands:
            return LLMResult("", self.name, self.model)
        parts = cands[0].get("content", {}).get("parts", [])
        text = "".join(p.get("text", "") for p in parts)
        return LLMResult(text, self.name, self.model)


def build_provider(name: str, settings: Settings) -> BaseProvider | None:
    """Instantiate a provider by name from settings (no availability check)."""
    if name == "local":
        model = settings.local_model or "qwen2.5-coder:7b"
        return OllamaProvider(model)
    if name in ("groq", "openrouter"):
        key = settings.cloud_key(name)
        if not key:
            return None
        return OpenAICompatProvider(name, key, DEFAULT_CLOUD_MODELS[name], PROVIDER_ENDPOINTS[name])
    if name == "claude":
        key = settings.cloud_key("claude")
        return ClaudeProvider(key, DEFAULT_CLOUD_MODELS["claude"]) if key else None
    if name == "gemini":
        key = settings.cloud_key("gemini")
        return GeminiProvider(key, DEFAULT_CLOUD_MODELS["gemini"]) if key else None
    return None


def get_provider(settings: Settings) -> BaseProvider | None:
    """Resolve and return the active provider, or None for raw-scan-only mode."""
    name = settings.resolve_provider()
    if not name:
        return None
    provider = build_provider(name, settings)
    if provider is None:
        return None
    # For local, verify Ollama is actually reachable; otherwise fall back to None.
    if provider.name == "local" and not provider.available():
        return None
    return provider
