"""Tests for the fix engine: diff parsing/application and generate_fixes/run_fix."""

from __future__ import annotations

from argus.fix import apply_diff_to_text, apply_fixes, _parse_hunks
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
