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
