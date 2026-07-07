"""Tests for policy-as-code CI gating."""

from __future__ import annotations

import pytest

from argus.models import Finding, Severity
from argus.policy import (
    Policy,
    PolicyError,
    PolicyRule,
    evaluate,
    find_default_policy,
    load_policy,
    parse_policy,
)


def _f(title="X", severity=Severity.HIGH, category="misc", detector="argus", confirmed=False):
    return Finding(title=title, severity=severity, category=category, detector=detector, confirmed=confirmed)


def test_rule_matches_on_severity():
    rule = PolicyRule(action="fail", severity="critical")
    assert rule.matches(_f(severity=Severity.CRITICAL))
    assert not rule.matches(_f(severity=Severity.HIGH))


def test_rule_matches_on_category_case_insensitive():
    rule = PolicyRule(action="fail", category="Injection")
    assert rule.matches(_f(category="injection"))
    assert not rule.matches(_f(category="crypto"))


def test_rule_detector_matches_by_prefix():
    rule = PolicyRule(action="ignore", detector="secrets")
    assert rule.matches(_f(detector="secrets-entropy"))
    assert rule.matches(_f(detector="secrets"))
    assert not rule.matches(_f(detector="rule:py-sql"))


def test_rule_matches_on_confirmed():
    rule = PolicyRule(action="fail", confirmed=True)
    assert rule.matches(_f(confirmed=True))
    assert not rule.matches(_f(confirmed=False))


def test_rule_fields_are_anded():
    rule = PolicyRule(action="fail", severity="high", category="injection")
    assert rule.matches(_f(severity=Severity.HIGH, category="injection"))
    assert not rule.matches(_f(severity=Severity.HIGH, category="crypto"))


def test_first_matching_rule_wins():
    policy = Policy(default="warn", rules=[
        PolicyRule(action="ignore", detector="secrets-entropy"),
        PolicyRule(action="fail", severity="high"),
    ])
    # both rules could apply to this finding; the first (ignore) wins
    f = _f(severity=Severity.HIGH, detector="secrets-entropy")
    assert policy.action_for(f) == "ignore"


def test_default_action_when_no_rule_matches():
    policy = Policy(default="fail", rules=[PolicyRule(action="ignore", category="crypto")])
    assert policy.action_for(_f(category="injection")) == "fail"


def test_evaluate_partitions_findings():
    policy = Policy(default="warn", rules=[
        PolicyRule(action="fail", category="injection"),
        PolicyRule(action="ignore", detector="secrets-entropy"),
    ])
    findings = [
        _f(title="sqli", category="injection"),
        _f(title="header", category="misc"),
        _f(title="entropy", detector="secrets-entropy"),
    ]
    outcome = evaluate(policy, findings)
    assert [f.title for f in outcome.failing] == ["sqli"]
    assert [f.title for f in outcome.warning] == ["header"]
    assert [f.title for f in outcome.ignored] == ["entropy"]
    assert outcome.should_fail is True


def test_evaluate_should_not_fail_when_nothing_matches_fail():
    policy = Policy(default="warn", rules=[])
    outcome = evaluate(policy, [_f(), _f()])
    assert outcome.should_fail is False


def test_parse_policy_rejects_bad_action():
    with pytest.raises(PolicyError):
        parse_policy({"default": "explode"})


def test_parse_policy_rejects_rule_without_action():
    with pytest.raises(PolicyError):
        parse_policy({"rules": [{"severity": "high"}]})


def test_parse_policy_rejects_non_list_rules():
    with pytest.raises(PolicyError):
        parse_policy({"rules": "nope"})


def test_load_policy_roundtrip(tmp_path):
    (tmp_path / "p.toml").write_text(
        'default = "warn"\n\n[[rules]]\ncategory = "injection"\naction = "fail"\n',
        encoding="utf-8",
    )
    policy = load_policy(tmp_path / "p.toml")
    assert policy.default == "warn"
    assert len(policy.rules) == 1
    assert policy.rules[0].category == "injection"
    assert policy.rules[0].action == "fail"


def test_load_policy_invalid_toml_raises(tmp_path):
    (tmp_path / "bad.toml").write_text("this is = = not toml", encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "bad.toml")


def test_find_default_policy_discovers_file_in_target_dir(tmp_path):
    (tmp_path / ".argus-policy.toml").write_text('default = "warn"\n', encoding="utf-8")
    assert find_default_policy(str(tmp_path)) == tmp_path / ".argus-policy.toml"


def test_find_default_policy_none_when_absent(tmp_path):
    assert find_default_policy(str(tmp_path)) is None
