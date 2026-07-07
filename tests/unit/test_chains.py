"""Tests for exploit chaining (attack-path detection)."""

from __future__ import annotations

from argus.chains import detect_chains
from argus.models import Finding, Severity


def _f(detector, confirmed=True):
    return Finding(title="x", severity=Severity.HIGH, category="c", detector=detector, confirmed=confirmed)


def test_xss_plus_cookie_flags_forms_takeover_chain():
    chains = detect_chains([_f("xsshunter:reflected"), _f("authbreaker:cookie-flags")])
    assert [c.detector for c in chains] == ["chain:xss-session-takeover"]
    assert chains[0].severity is Severity.CRITICAL
    assert chains[0].category == "attack-chain"
    assert chains[0].confirmed is True


def test_domxss_also_satisfies_xss_step():
    chains = detect_chains([_f("domxss:confirmed"), _f("authbreaker:cookie-flags")])
    assert [c.detector for c in chains] == ["chain:xss-session-takeover"]


def test_authbypass_plus_idor_chain():
    for auth in ("authbreaker:jwt-none", "authbreaker:jwt-weak-secret", "headerpoker:bypass"):
        chains = detect_chains([_f(auth), _f("idorhunter")])
        assert [c.detector for c in chains] == ["chain:authbypass-idor"], auth


def test_upload_plus_traversal_chain():
    chains = detect_chains([_f("fileattacker:upload"), _f("fileattacker:traversal")])
    assert [c.detector for c in chains] == ["chain:upload-traversal-rce"]


def test_mcp_exposure_plus_leak_chain():
    chains = detect_chains([_f("mcpsecurity:tool-list"), _f("mcpsecurity:leaked-secret")])
    assert [c.detector for c in chains] == ["chain:mcp-exposure-leak"]


def test_clickjacking_plus_csrf_forms_forced_action_chain():
    chains = detect_chains([_f("csrfhunter:form"), _f("csrfhunter:clickjacking")])
    assert [c.detector for c in chains] == ["chain:clickjacking-csrf-forced-action"]
    assert chains[0].cwe == "CWE-352"


def test_clickjacking_alone_does_not_chain():
    assert detect_chains([_f("csrfhunter:clickjacking")]) == []
    assert detect_chains([_f("csrfhunter:form")]) == []


def test_single_half_does_not_form_a_chain():
    assert detect_chains([_f("xsshunter:reflected")]) == []
    assert detect_chains([_f("idorhunter")]) == []


def test_unconfirmed_findings_never_chain():
    chains = detect_chains([_f("xsshunter:reflected", confirmed=False),
                            _f("authbreaker:cookie-flags", confirmed=False)])
    assert chains == []


def test_chain_records_its_constituents():
    xss = _f("xsshunter:reflected")
    cookie = _f("authbreaker:cookie-flags")
    chains = detect_chains([xss, cookie])
    assert set(chains[0].metadata["chain_of"]) == {xss.id, cookie.id}


def test_multiple_distinct_chains_all_fire():
    findings = [
        _f("xsshunter:reflected"), _f("authbreaker:cookie-flags"),
        _f("authbreaker:jwt-none"), _f("idorhunter"),
    ]
    dets = {c.detector for c in detect_chains(findings)}
    assert dets == {"chain:xss-session-takeover", "chain:authbypass-idor"}
