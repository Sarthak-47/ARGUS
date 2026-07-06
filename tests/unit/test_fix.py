"""Tests for the fix engine: diff parsing/application and generate_fixes/run_fix."""

from __future__ import annotations

from argus.fix import apply_diff_to_text, apply_fixes, _parse_hunks, _would_break_syntax
from argus.llm.provider import LLMResult
from argus.llm.reasoning import FixResult, generate_fixes
from argus.models import Finding, Severity

_ORIGINAL = (
    "import sqlite3\n"
    "def q(name):\n"
    "    cur.execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\")\n"
    "    return cur.fetchall()\n"
)

_DIFF = (
    "--- a/app.py\n"
    "+++ b/app.py\n"
    "@@ -1,4 +1,4 @@\n"
    " import sqlite3\n"
    " def q(name):\n"
    "-    cur.execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\")\n"
    "+    cur.execute(\"SELECT * FROM users WHERE name = ?\", (name,))\n"
    "     return cur.fetchall()\n"
)


def test_parse_hunks_extracts_old_and_new():
    hunks = _parse_hunks(_DIFF)
    assert len(hunks) == 1
    old, new = hunks[0]
    assert any("name + " in line for line in old)  # sanity: old has the concatenation
    assert any("?" in line for line in new)


def test_apply_diff_to_text_replaces_matched_block():
    patched = apply_diff_to_text(_ORIGINAL, _DIFF)
    assert patched is not None
    assert 'cur.execute("SELECT * FROM users WHERE name = ?", (name,))' in patched
    assert "name + \"'\"" not in patched


def test_apply_diff_to_text_rejects_no_match():
    diff = _DIFF.replace("import sqlite3", "import totally_different_module")
    assert apply_diff_to_text(_ORIGINAL, diff) is None


def test_apply_diff_to_text_noop_hunk_is_fine():
    diff = (
        "@@ -1,1 +1,1 @@\n"
        " import sqlite3\n"
    )
    assert apply_diff_to_text(_ORIGINAL, diff) == _ORIGINAL


def test_apply_fixes_dry_run_does_not_write(tmp_path):
    f = tmp_path / "app.py"
    f.write_text(_ORIGINAL, encoding="utf-8")
    fixes = [FixResult(finding_id="x", file="app.py", diff=_DIFF, explanation="parameterise")]

    applied = apply_fixes(tmp_path, fixes, apply=False)
    assert len(applied) == 1
    assert applied[0].written is False
    assert f.read_text(encoding="utf-8") == _ORIGINAL  # untouched


def test_apply_fixes_apply_writes_file(tmp_path):
    f = tmp_path / "app.py"
    f.write_text(_ORIGINAL, encoding="utf-8")
    fixes = [FixResult(finding_id="x", file="app.py", diff=_DIFF, explanation="parameterise")]

    applied = apply_fixes(tmp_path, fixes, apply=True)
    assert applied[0].written is True
    new_content = f.read_text(encoding="utf-8")
    assert "name = ?" in new_content
    assert "name + \"'\"" not in new_content


def test_apply_fixes_skips_unreadable_or_mismatched(tmp_path):
    fixes = [FixResult(finding_id="x", file="missing.py", diff=_DIFF, explanation="n/a")]
    assert apply_fixes(tmp_path, fixes, apply=True) == []


def test_would_break_syntax_catches_bad_python():
    assert _would_break_syntax("app.py", "def f(:\n    pass\n") is True
    assert _would_break_syntax("app.py", "def f():\n    pass\n") is False


def test_would_break_syntax_ignores_non_python_files():
    # No validator for other languages yet — must not false-positive-reject them.
    assert _would_break_syntax("app.js", "function f( {{{ broken") is False


def test_apply_fixes_rejects_diff_that_would_corrupt_syntax(tmp_path):
    """Regression test for a real failure mode seen with a live LLM (qwen2.5:7b):
    a single-context-line hunk that content-matches as a bare substring (so the
    content-match rule "succeeds") but is written as context + an unindented
    addition rather than a proper substitution — degenerate to a single-line
    old_block, the substring search finds it mid-line and preserves the file's
    original indentation before it, but the appended line has none of its own,
    leaving the file syntactically broken. The syntax check must catch this."""
    original = (
        "def ping(host):\n"
        "    subprocess.call(\"ping \" + host, shell=True)\n"
        "    return \"ok\"\n"
    )
    bad_diff = (
        "@@ -2,1 +2,2 @@\n"
        " subprocess.call(\"ping \" + host, shell=True)\n"
        "+subprocess.call(['ping', host], shell=False)\n"
    )
    f = tmp_path / "app.py"
    f.write_text(original, encoding="utf-8")
    fixes = [FixResult(finding_id="x", file="app.py", diff=bad_diff, explanation="fix cmd injection")]

    applied = apply_fixes(tmp_path, fixes, apply=True)
    assert applied == []
    assert f.read_text(encoding="utf-8") == original  # untouched — never corrupted


class _FakeProvider:
    name = "fake"
    model = "fake-model"

    def __init__(self, response_text: str):
        self._text = response_text

    def complete(self, system, user, *, json_mode=False):
        return LLMResult(self._text, self.name, self.model)


def test_generate_fixes_parses_valid_response(tmp_path):
    import json

    (tmp_path / "app.py").write_text(_ORIGINAL, encoding="utf-8")
    finding = Finding(title="SQLi", severity=Severity.CRITICAL, category="injection",
                       file="app.py", line=3, evidence="concat")
    provider = _FakeProvider(json.dumps({"can_fix": True, "diff": _DIFF, "explanation": "use params"}))

    fixes = generate_fixes(provider, tmp_path, [finding])
    assert len(fixes) == 1
    assert fixes[0].file == "app.py"
    assert "name = ?" in fixes[0].diff


def test_generate_fixes_parses_regenerate_prompt(tmp_path):
    import json

    (tmp_path / "app.py").write_text(_ORIGINAL, encoding="utf-8")
    finding = Finding(title="SQLi", severity=Severity.CRITICAL, category="injection",
                       file="app.py", line=3, evidence="concat")
    provider = _FakeProvider(json.dumps({
        "can_fix": True, "diff": _DIFF, "explanation": "use params",
        "regenerate_prompt": "Rewrite q() to use parameterised queries instead of string concat.",
    }))

    fixes = generate_fixes(provider, tmp_path, [finding])
    assert fixes[0].regenerate_prompt == "Rewrite q() to use parameterised queries instead of string concat."


def test_generate_fixes_defaults_regenerate_prompt_to_empty_when_absent(tmp_path):
    import json

    (tmp_path / "app.py").write_text(_ORIGINAL, encoding="utf-8")
    finding = Finding(title="SQLi", severity=Severity.CRITICAL, category="injection", file="app.py", line=3)
    provider = _FakeProvider(json.dumps({"can_fix": True, "diff": _DIFF, "explanation": "use params"}))

    fixes = generate_fixes(provider, tmp_path, [finding])
    assert fixes[0].regenerate_prompt == ""


def test_apply_fixes_carries_regenerate_prompt_through(tmp_path):
    (tmp_path / "app.py").write_text(_ORIGINAL, encoding="utf-8")
    fixes = [FixResult(finding_id="x", file="app.py", diff=_DIFF, explanation="parameterise",
                        regenerate_prompt="Use parameterised queries.")]

    applied = apply_fixes(tmp_path, fixes, apply=False)
    assert applied[0].regenerate_prompt == "Use parameterised queries."


def test_generate_fixes_skips_when_cannot_fix(tmp_path):
    import json

    (tmp_path / "app.py").write_text(_ORIGINAL, encoding="utf-8")
    finding = Finding(title="SQLi", severity=Severity.CRITICAL, category="injection", file="app.py", line=3)
    provider = _FakeProvider(json.dumps({"can_fix": False, "diff": "", "explanation": "too risky"}))

    assert generate_fixes(provider, tmp_path, [finding]) == []


def test_generate_fixes_skips_findings_without_file(tmp_path):
    finding = Finding(title="SSRF", severity=Severity.HIGH, category="ssrf", endpoint="/fetch")
    provider = _FakeProvider("{}")
    assert generate_fixes(provider, tmp_path, [finding]) == []
