"""Tests for argus.authorization — the Phase 2 confirm-before-attacking gate."""

from __future__ import annotations

import json

from argus.authorization import confirm_authorization, record_authorization


def test_assume_yes_confirms_and_logs(tmp_path, monkeypatch):
    monkeypatch.setattr("argus.authorization.config_dir", lambda: tmp_path)
    assert confirm_authorization("https://example.test", assume_yes=True) is True
    lines = (tmp_path / "authorizations.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["target"] == "https://example.test"
    assert "operator" in entry and "hostname" in entry and "timestamp" in entry


def test_non_interactive_without_assume_yes_refuses(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert confirm_authorization("https://example.test", assume_yes=False) is False


def test_interactive_yes_confirms_and_logs(tmp_path, monkeypatch):
    monkeypatch.setattr("argus.authorization.config_dir", lambda: tmp_path)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "yes")
    assert confirm_authorization("https://example.test", assume_yes=False) is True
    assert (tmp_path / "authorizations.jsonl").exists()


def test_interactive_non_yes_answer_refuses_and_does_not_log(tmp_path, monkeypatch):
    monkeypatch.setattr("argus.authorization.config_dir", lambda: tmp_path)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "no")
    assert confirm_authorization("https://example.test", assume_yes=False) is False
    assert not (tmp_path / "authorizations.jsonl").exists()


def test_interactive_eof_refuses(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    def raise_eof(prompt):
        raise EOFError

    monkeypatch.setattr("builtins.input", raise_eof)
    assert confirm_authorization("https://example.test", assume_yes=False) is False


def test_record_authorization_appends_multiple_entries(tmp_path, monkeypatch):
    monkeypatch.setattr("argus.authorization.config_dir", lambda: tmp_path)
    record_authorization("https://a.test")
    record_authorization("https://b.test")
    lines = (tmp_path / "authorizations.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["target"] == "https://a.test"
    assert json.loads(lines[1])["target"] == "https://b.test"
