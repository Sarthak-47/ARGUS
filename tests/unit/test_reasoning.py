"""Tests for the LLM taint-tracing mode (roadmap v0.4.6)."""

from __future__ import annotations

import json

from argus.llm.provider import LLMResult
from argus.llm.reasoning import taint_trace
from argus.models import Severity

_SOURCE_FILE = (
    "import subprocess\n"
    "from flask import request\n\n"
    "def build_cmd(host):\n"
    "    return 'ping ' + host\n\n"
    "@app.route('/ping')\n"
    "def ping():\n"
    "    host = request.args.get('host')\n"
    "    cmd = build_cmd(host)\n"
    "    subprocess.call(cmd, shell=True)\n"
)


class _FakeProvider:
    name = "fake"
    model = "fake-model"

    def __init__(self, response_text: str):
        self._text = response_text

    def complete(self, system, user, *, json_mode=False):
        return LLMResult(self._text, self.name, self.model)


def test_taint_trace_reports_complete_chain(tmp_path):
    (tmp_path / "app.py").write_text(_SOURCE_FILE, encoding="utf-8")
    provider = _FakeProvider(json.dumps([{
        "title": "Tainted request param reaches subprocess.call via build_cmd()",
        "severity": "CRITICAL",
        "source": "request.args.get('host') at line 7",
        "sink": "subprocess.call(cmd, shell=True) at line 9",
        "call_chain": ["ping()", "build_cmd()", "subprocess.call()"],
        "line": 9,
        "explanation": "host flows unsanitized from the request into a shell command.",
        "exploit": "?host=x; rm -rf /",
        "fix": "Use subprocess.call(['ping', host], shell=False).",
    }]))

    findings = taint_trace(provider, tmp_path, ["app.py"])

    assert len(findings) == 1
    f = findings[0]
    assert f.category == "taint-trace"
    assert f.detector == "llm-taint"
    assert f.severity == Severity.CRITICAL
    assert f.line == 9
    assert "build_cmd()" in f.metadata["call_chain"]
    assert "source:" in f.evidence and "sink:" in f.evidence and "chain:" in f.evidence


def test_taint_trace_returns_empty_when_no_complete_chain(tmp_path):
    (tmp_path / "app.py").write_text(_SOURCE_FILE, encoding="utf-8")
    provider = _FakeProvider(json.dumps([]))

    findings = taint_trace(provider, tmp_path, ["app.py"])
    assert findings == []


def test_taint_trace_skips_items_missing_sink(tmp_path):
    (tmp_path / "app.py").write_text(_SOURCE_FILE, encoding="utf-8")
    provider = _FakeProvider(json.dumps([{"title": "incomplete", "source": "x"}]))

    findings = taint_trace(provider, tmp_path, ["app.py"])
    assert findings == []


def test_taint_trace_skips_unreadable_file(tmp_path):
    provider = _FakeProvider(json.dumps([]))
    findings = taint_trace(provider, tmp_path, ["does-not-exist.py"])
    assert findings == []


def test_taint_trace_skips_malformed_json_response(tmp_path):
    (tmp_path / "app.py").write_text(_SOURCE_FILE, encoding="utf-8")
    provider = _FakeProvider("not json at all")

    findings = taint_trace(provider, tmp_path, ["app.py"])
    assert findings == []


def test_taint_trace_respects_max_files(tmp_path):
    for i in range(5):
        (tmp_path / f"f{i}.py").write_text(_SOURCE_FILE, encoding="utf-8")
    calls = []

    class _CountingProvider(_FakeProvider):
        def complete(self, system, user, *, json_mode=False):
            calls.append(user)
            return LLMResult(json.dumps([]), self.name, self.model)

    provider = _CountingProvider("[]")
    taint_trace(provider, tmp_path, [f"f{i}.py" for i in range(5)], max_files=2)
    assert len(calls) == 2
