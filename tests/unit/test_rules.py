"""Tests for the built-in deterministic code rules and ingestion."""

from __future__ import annotations

from argus.scanner.ingestion import ingest
from argus.scanner.rules_builtin import scan_rules


def test_rules_detect_core_vulns(vuln_repo):
    findings = scan_rules(vuln_repo)
    cats = {f.category for f in findings}
    titles = " ".join(f.title for f in findings)
    assert "injection" in cats
    assert "SQL injection" in titles
    assert "command injection" in titles
    assert "yaml" in titles.lower()
    assert "MD5" in titles or "weak" in titles.lower()


def test_rules_skip_comments(tmp_path):
    f = tmp_path / "x.py"
    f.write_text("# os.system('rm -rf ' + x)\nprint('safe')\n", encoding="utf-8")
    findings = scan_rules(tmp_path)
    assert findings == []


def _detectors(tmp_path, filename, content):
    (tmp_path / filename).write_text(content, encoding="utf-8")
    return {f.detector for f in scan_rules(tmp_path)}


def test_js_new_rules_fire_and_skip_safe_variants(tmp_path):
    dets = _detectors(tmp_path, "app.js",
        "document.write(userInput);\n"
        "document.write('<p>static</p>');\n"
        "res.redirect(req.query.next);\n"
        "res.redirect('/home');\n"
        "crypto.createCipher('aes', k);\n"
        "crypto.createCipheriv('aes', k, iv);\n"
        "localStorage.setItem('authToken', t);\n"
        "localStorage.setItem('theme', 'dark');\n")
    assert "rule:js-document-write" in dets
    assert "rule:js-open-redirect" in dets
    assert "rule:js-deprecated-cipher" in dets  # createCipher, not createCipheriv
    assert "rule:js-localstorage-secret" in dets


def test_python_new_rules_fire(tmp_path):
    dets = _detectors(tmp_path, "app.py",
        "render_template_string('Hi ' + name)\n"
        "mark_safe(user_bio)\n"
        "hashlib.new('md5')\n"
        "etree.fromstring(untrusted)\n")
    assert "rule:py-ssti-render-string" in dets
    assert "rule:py-django-mark-safe" in dets
    assert "rule:hashlib-new-weak" in dets
    assert "rule:py-xxe-parse" in dets


def test_go_new_rules_fire_and_skip_safe_command(tmp_path):
    dets = _detectors(tmp_path, "app.go",
        "tls.Config{InsecureSkipVerify: true}\n"
        "exec.Command(\"sh\", \"-c\", userCmd)\n"
        "exec.Command(\"ls\", \"-la\")\n")
    assert "rule:go-insecure-skip-verify" in dets
    assert "rule:go-shell-command" in dets


def test_createcipheriv_is_not_flagged_as_deprecated_cipher(tmp_path):
    dets = _detectors(tmp_path, "safe.js", "const c = crypto.createCipheriv('aes-256-gcm', key, iv);\n")
    assert "rule:js-deprecated-cipher" not in dets


def test_ingest_builds_map(vuln_repo):
    ing = ingest(str(vuln_repo))
    assert ing.cleanup is False
    cm = ing.map
    assert cm.primary_language == "Python"
    assert "Flask" in cm.frameworks or "React" in cm.frameworks
    assert "requirements.txt" in cm.dependency_manifests
    assert cm.file_count >= 1


def test_ingest_missing_path_raises(tmp_path):
    import pytest

    with pytest.raises(FileNotFoundError):
        ingest(str(tmp_path / "does-not-exist"))
