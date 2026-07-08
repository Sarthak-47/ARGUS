"""Tests for secret detection: entropy, known formats, masking, placeholders."""

from __future__ import annotations

from argus.scanner.secrets import scan_secrets, shannon_entropy, _mask


def test_shannon_entropy_ranges():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaa") < 1.0
    assert shannon_entropy("aB3$xZ9kLp2qWm7n") > 3.0


def test_detects_aws_and_stripe(vuln_repo):
    findings = scan_secrets(vuln_repo)
    titles = " ".join(f.title for f in findings)
    assert "AWS Access Key ID" in titles
    assert "Stripe Live Secret Key" in titles


def test_masking_hides_token_body():
    token = "AKIA" + "IOSFODNN7EXAMPLE"
    masked = _mask(f"key = {token}")
    assert token not in masked
    assert "•" in masked


def test_placeholder_not_flagged(tmp_path):
    f = tmp_path / "conf.py"
    f.write_text("password = 'your_password_here'\napi_key = 'changeme'\n", encoding="utf-8")
    findings = scan_secrets(tmp_path)
    generic = [x for x in findings if "Generic Secret" in x.title]
    assert generic == []


def test_real_generic_secret_flagged(tmp_path):
    f = tmp_path / "conf.py"
    f.write_text("password = 'Tr0ub4dor&3xKqun'\n", encoding="utf-8")
    findings = scan_secrets(tmp_path)
    assert any("Generic Secret" in x.title for x in findings)


def test_detects_modern_token_formats(tmp_path):
    # Fake-but-format-valid tokens built by concatenation so no complete
    # secret literal is committed (GitHub push protection would flag it).
    tokens = {
        "npm Access Token": "npm_" + "A" * 36,
        "PyPI Upload Token": "pypi-AgE" + "B" * 55,
        "HashiCorp Vault Token": "hvs." + "C" * 30,
        "DigitalOcean PAT": "dop_v1_" + "a" * 64,
        "Shopify Access Token": "shpat_" + "a" * 32,
    }
    lines = [f"key{i} = '{tok}'" for i, tok in enumerate(tokens.values())]
    (tmp_path / "creds.env").write_text("\n".join(lines) + "\n", encoding="utf-8")
    titles = " ".join(f.title for f in scan_secrets(tmp_path))
    for label in tokens:
        assert label in titles, f"{label} not detected"


def test_modern_token_patterns_ignore_benign_text(tmp_path):
    (tmp_path / "readme.md").write_text(
        "Run npm install then dapper up. Visit https://example.com for docs.\n",
        encoding="utf-8",
    )
    findings = scan_secrets(tmp_path)
    labels = {f.title for f in findings}
    for label in ("npm Access Token", "Databricks Token", "HashiCorp Vault Token"):
        assert label not in labels


def test_entropy_skipped_in_lockfile_but_pattern_still_fires(tmp_path):
    # package-lock.json is full of integrity hashes (entropy noise) — the entropy
    # pass is skipped there, but a real key pattern is still caught.
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        '{"a": {"integrity": "sha512-' + "AbCdEf0123456789+/ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLlKk012345678==" + '"},\n'
        ' "b": {"key": "AKIA' + "IOSFODNN7EXAMPLE" + '"}}\n', encoding="utf-8")
    findings = scan_secrets(tmp_path)
    dets = {(f.detector, f.title) for f in findings}
    assert not any(d == "secrets-entropy" for d, _ in dets)          # noise gone
    assert any("AWS Access Key ID" in t for _, t in dets)             # real key kept


def test_entropy_skipped_in_minified_and_vendored(tmp_path):
    (tmp_path / "app.min.js").write_text(
        "var x='" + "Zx9Kd82hFmQp04SsRrTtUuVvWwXxYyZz+/AbCd" + "';\n", encoding="utf-8")
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "bundle.js").write_text(
        "const k='" + "9f8e7d6c5b4a32100011223344556677AbCdEf" + "';\n", encoding="utf-8")
    findings = [f for f in scan_secrets(tmp_path) if f.detector == "secrets-entropy"]
    assert findings == []


def test_hash_length_hex_token_not_flagged_as_entropy(tmp_path):
    # a bare md5 (32) / sha1 (40) / sha256 (64) hex digest is a checksum, not a secret
    (tmp_path / "seed.sql").write_text(
        "INSERT INTO u VALUES ('" + "5f4dcc3b5aa765d61d8327deb882cf99" + "');\n", encoding="utf-8")
    findings = [f for f in scan_secrets(tmp_path) if f.detector == "secrets-entropy"]
    assert findings == []


def test_entropy_still_fires_in_normal_source(tmp_path):
    # regression guard: a genuine unknown-format high-entropy secret in real code
    # must still be caught.
    (tmp_path / "cfg.py").write_text(
        "SESSION_KEY = '" + "kJ8xQ2mZ9pR4vT7wY0aB3cD6eF1gH5iN" + "'\n", encoding="utf-8")
    findings = [f for f in scan_secrets(tmp_path)
                if f.detector in ("secrets", "secrets-entropy")]
    assert findings, "a real high-entropy secret in normal source should still be flagged"
