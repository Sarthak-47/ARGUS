"""Tests for argus/sbom.py (package inventory) and the CycloneDX exporter."""

from __future__ import annotations

import json

from argus.models import ScanResult
from argus.report.exporters import to_sbom
from argus.sbom import collect_packages


def test_collect_packages_from_npm_manifest(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"react": "^18.2.0"}, "devDependencies": {"typescript": "~5.3.0"}}),
        encoding="utf-8",
    )
    packages = collect_packages(tmp_path, ["package.json"])
    names = {p["name"]: p for p in packages}
    assert names["react"]["version"] == "18.2.0"
    assert names["react"]["ecosystem"] == "npm"
    assert names["typescript"]["version"] == "5.3.0"


def test_collect_packages_from_requirements_txt(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==2.3.0\nrequests>=2.28\n# a comment\n", encoding="utf-8")
    packages = collect_packages(tmp_path, ["requirements.txt"])
    names = {p["name"]: p for p in packages}
    assert names["flask"]["version"] == "2.3.0"
    assert names["flask"]["ecosystem"] == "pypi"
    assert names["requests"]["version"] == "unknown"  # unpinned — no exact version to report


def test_collect_packages_deduplicates_across_manifests(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"react": "18.0.0"}}), encoding="utf-8")
    packages = collect_packages(tmp_path, ["package.json", "package.json"])
    assert len(packages) == 1


def test_collect_packages_skips_unknown_manifest_types(tmp_path):
    (tmp_path / "go.mod").write_text("module x\n", encoding="utf-8")
    assert collect_packages(tmp_path, ["go.mod"]) == []


def test_collect_packages_malformed_manifest_does_not_crash(tmp_path):
    (tmp_path / "package.json").write_text("{not valid json", encoding="utf-8")
    assert collect_packages(tmp_path, ["package.json"]) == []


def test_to_sbom_produces_valid_cyclonedx_structure():
    result = ScanResult(target="my-app", phase="scan")
    result.sbom_components = [
        {"name": "react", "version": "18.2.0", "ecosystem": "npm"},
        {"name": "requests", "version": "unknown", "ecosystem": "pypi"},
    ]
    sbom = json.loads(to_sbom(result))

    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["metadata"]["component"]["name"] == "my-app"
    assert len(sbom["components"]) == 2

    react = next(c for c in sbom["components"] if c["name"] == "react")
    assert react["purl"] == "pkg:npm/react@18.2.0"

    requests_pkg = next(c for c in sbom["components"] if c["name"] == "requests")
    assert requests_pkg["purl"] == "pkg:pypi/requests"  # no version suffix when unknown


def test_to_sbom_empty_when_no_components():
    result = ScanResult(target="my-app", phase="scan")
    sbom = json.loads(to_sbom(result))
    assert sbom["components"] == []
