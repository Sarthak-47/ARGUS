"""Tests for config load/save and provider resolution."""

from __future__ import annotations

from argus.config import load_settings, save_settings
from argus.config.settings import Settings


def test_defaults_load_when_no_file():
    s = load_settings()
    assert s.preferred_provider == "local"
    assert s.default_depth == "standard"
    assert s.webhook_url == ""


def test_webhook_url_save_and_reload_roundtrip():
    s = load_settings()
    s.set("notify", "webhook_url", "https://hooks.slack.com/services/x")
    save_settings(s)

    s2 = load_settings()
    assert s2.webhook_url == "https://hooks.slack.com/services/x"


def test_save_and_reload_roundtrip():
    s = load_settings()
    s.set("provider", "preferred", "groq")
    s.set("cloud", "groq_key", "gsk_secret_value_123")
    path = save_settings(s)
    assert path.exists()

    s2 = load_settings()
    assert s2.preferred_provider == "groq"
    assert s2.cloud_key("groq") == "gsk_secret_value_123"


def test_resolve_provider_prefers_configured_cloud_key():
    s = Settings({
        "provider": {"preferred": "groq"},
        "local": {"model": ""},
        "cloud": {"groq_key": "k", "gemini_key": "", "claude_key": "", "openrouter_key": ""},
    })
    assert s.resolve_provider() == "groq"


def test_resolve_provider_falls_through_chain():
    # preferred is local but no model -> next usable is gemini (has key)
    s = Settings({
        "provider": {"preferred": "local"},
        "local": {"model": ""},
        "cloud": {"groq_key": "", "gemini_key": "g", "claude_key": "", "openrouter_key": ""},
    })
    assert s.resolve_provider() == "gemini"


def test_resolve_provider_none_when_nothing_configured():
    s = Settings({
        "provider": {"preferred": "groq"},
        "local": {"model": ""},
        "cloud": {"groq_key": "", "gemini_key": "", "claude_key": "", "openrouter_key": ""},
    })
    assert s.resolve_provider() is None


def test_redacted_masks_keys():
    s = Settings({
        "provider": {"preferred": "groq"},
        "local": {"model": ""},
        "cloud": {"groq_key": "gsk_supersecret", "gemini_key": "", "claude_key": "", "openrouter_key": ""},
    })
    red = s.redacted()
    assert "supersecret" not in red["cloud"]["groq_key"]
    assert red["cloud"]["groq_key"].startswith("gsk_")


def test_redacted_masks_webhook_url():
    # Slack/Discord webhook URLs embed a bearer-equivalent token in the path —
    # leaking the full URL in `argus config --show` is as bad as leaking a key.
    s = Settings({
        "provider": {"preferred": "local"}, "local": {"model": ""},
        "cloud": {"groq_key": "", "gemini_key": "", "claude_key": "", "openrouter_key": ""},
        "notify": {"webhook_url": "https://hooks.slack.com/services/T00/B00/xxxxSECRETxxxx"},
    })
    red = s.redacted()
    assert "xxxxSECRETxxxx" not in red["notify"]["webhook_url"]
    assert red["notify"]["webhook_url"].startswith("https://hooks.slack.com")


def test_redacted_leaves_empty_webhook_url_alone():
    s = Settings({
        "provider": {"preferred": "local"}, "local": {"model": ""},
        "cloud": {"groq_key": "", "gemini_key": "", "claude_key": "", "openrouter_key": ""},
        "notify": {"webhook_url": ""},
    })
    assert s.redacted()["notify"]["webhook_url"] == ""
