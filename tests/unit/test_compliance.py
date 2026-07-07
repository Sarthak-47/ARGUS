"""Tests for CWE -> ASVS/PCI-DSS compliance tagging."""

from __future__ import annotations

import re
from pathlib import Path

from argus.compliance import _CWE_MAP, compliance_for
from argus.models import Finding, Severity


def test_maps_known_cwe():
    c = compliance_for("CWE-89")
    assert c == {"asvs": "ASVS V5.3.4", "pci_dss": "PCI-DSS 6.2.4", "label": "SQL injection"}


def test_accepts_bare_number_and_lowercase():
    assert compliance_for("89") == compliance_for("CWE-89") == compliance_for("cwe-89")


def test_unknown_cwe_returns_none():
    assert compliance_for("CWE-99999") is None


def test_none_and_garbage_return_none():
    assert compliance_for(None) is None
    assert compliance_for("not-a-cwe") is None
    assert compliance_for("") is None


def test_finding_exposes_compliance_property():
    f = Finding(title="SQLi", severity=Severity.CRITICAL, category="injection", cwe="CWE-89")
    assert f.compliance is not None
    assert f.compliance["asvs"] == "ASVS V5.3.4"


def test_finding_without_cwe_has_no_compliance():
    f = Finding(title="X", severity=Severity.LOW, category="misc")
    assert f.compliance is None


def test_to_dict_includes_compliance():
    f = Finding(title="SQLi", severity=Severity.HIGH, category="injection", cwe="CWE-89")
    assert f.to_dict()["compliance"]["pci_dss"] == "PCI-DSS 6.2.4"


def test_every_cwe_the_codebase_emits_is_mapped():
    # Guards against a new agent/rule introducing a CWE without a compliance
    # entry — the whole value of the tag is that it's always present.
    emitted: set[str] = set()
    for path in (Path(__file__).parents[2] / "argus").rglob("*.py"):
        for num in re.findall(r"CWE-(\d+)", path.read_text(encoding="utf-8")):
            emitted.add(num)
    missing = sorted(n for n in emitted if n not in _CWE_MAP)
    assert missing == [], f"CWEs emitted but not mapped to compliance: {missing}"
