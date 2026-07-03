"""Supply-chain manifest analysis: typosquats, unpinned versions, install-script abuse.

Argus's first real manifest *parser* (the dependency auditors only shell out to
``npm audit``/``pip-audit`` and normalize their output — they never look at manifest
content directly). Runs offline against ``package.json``/``requirements.txt``:

  - typosquat detection — package names within edit-distance 1 of a well-known
    name are flagged for review (bundled static allowlist, no network calls);
  - unpinned versions — ``*``/``latest`` always, ``^``/``~`` ranges only when no
    lockfile exists to pin the actually-installed version;
  - suspicious install scripts — ``postinstall``/``preinstall`` piping a download
    straight into a shell, the classic supply-chain-compromise pattern.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from argus.models import Finding, Severity
from argus.scanner.popular_packages import POPULAR_NPM, POPULAR_PYPI

_NPM_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")
_SHELL_PIPE = re.compile(r"(?i)(curl|wget)\b[^|;&]*\|\s*(sh|bash|zsh)\b")
_FLOATING_RANGE = re.compile(r"^[\^~]")


def _levenshtein_le1(a: str, b: str) -> bool:
    """True if a and b are one edit apart — substitution, insertion/deletion, or an
    adjacent-character transposition (Damerau-Levenshtein distance 1) — and unequal.

    Transposition matters here: "reqeust" vs "request" is a classic typosquat that a
    plain Hamming/Levenshtein check would miss (it looks like distance 2 — two
    substituted positions — unless the swap is recognised as one transposition).
    """
    if a == b:
        return False
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diffs = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diffs) == 1:
            return True
        if len(diffs) == 2 and diffs[1] == diffs[0] + 1:
            i, j = diffs
            return a[i] == b[j] and a[j] == b[i]
        return False
    longer, shorter = (a, b) if len(a) > len(b) else (b, a)
    for i in range(len(longer)):
        if longer[:i] + longer[i + 1:] == shorter:
            return True
    return False


def _typosquat_match(name: str, allowlist: set[str]) -> str | None:
    lname = name.lower()
    if lname in allowlist:
        return None
    for known in allowlist:
        if _levenshtein_le1(lname, known):
            return known
    return None


def _check_npm_manifest(root: Path, manifest_rel: str) -> list[Finding]:
    findings: list[Finding] = []
    full = root / manifest_rel
    try:
        data = json.loads(full.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return findings
    if not isinstance(data, dict):
        return findings

    has_lockfile = any((full.parent / lf).exists() for lf in _NPM_LOCKFILES)

    deps: dict[str, str] = {}
    for key in ("dependencies", "devDependencies"):
        section = data.get(key)
        if isinstance(section, dict):
            deps.update({k: str(v) for k, v in section.items() if isinstance(v, str)})

    for name, version in deps.items():
        match = _typosquat_match(name, POPULAR_NPM)
        if match:
            findings.append(Finding(
                title=f"Possible typosquat dependency: '{name}'",
                severity=Severity.HIGH, category="dependency", detector="supplychain:typosquat",
                file=manifest_rel,
                evidence=f"'{name}' differs by one character from the popular package '{match}'",
                description=f"'{name}' is one edit away from the well-known package '{match}', "
                            f"a common typosquatting pattern used to trick developers into "
                            f"installing a malicious look-alike.",
                exploit="If this is a typosquat, its install/postinstall scripts run attacker "
                        "code with the same privileges as the build.",
                fix=f"Verify this is the intended package. If not, replace it with '{match}'.",
                cwe="CWE-1357", confidence="medium",
            ))

        stripped = version.strip()
        if stripped in ("*", "latest", ""):
            findings.append(Finding(
                title=f"Unpinned dependency version: '{name}'",
                severity=Severity.MEDIUM, category="dependency", detector="supplychain:unpinned",
                file=manifest_rel,
                evidence=f"{name}: \"{version}\"",
                description=f"'{name}' has no version constraint at all ({version!r}), so any "
                            f"future publish — including a compromised one — installs immediately.",
                fix=f"Pin '{name}' to a specific version or a narrow range, and commit a lockfile.",
                cwe="CWE-1104", confidence="high",
            ))
        elif _FLOATING_RANGE.match(stripped) and not has_lockfile:
            findings.append(Finding(
                title=f"Unpinned dependency version: '{name}'",
                severity=Severity.LOW, category="dependency", detector="supplychain:unpinned",
                file=manifest_rel,
                evidence=f"{name}: \"{version}\" (no lockfile present)",
                description=f"'{name}' uses a floating range ({version!r}) with no lockfile in the "
                            f"repo, so the exact installed version isn't reproducible or pinned.",
                fix="Commit a lockfile (package-lock.json/yarn.lock/pnpm-lock.yaml) so installs "
                    "are reproducible, or pin exact versions.",
                cwe="CWE-1104", confidence="medium",
            ))

    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for hook in ("postinstall", "preinstall"):
            cmd = scripts.get(hook)
            if isinstance(cmd, str) and _SHELL_PIPE.search(cmd):
                findings.append(Finding(
                    title=f"Suspicious install script: '{hook}'",
                    severity=Severity.CRITICAL, category="dependency", detector="supplychain:install-script",
                    file=manifest_rel,
                    evidence=f"{hook}: {cmd[:200]}",
                    description=f"The '{hook}' script downloads a remote script and pipes it "
                                f"directly into a shell — the exact pattern used in real "
                                f"supply-chain compromises (arbitrary code execution on every install).",
                    exploit="Anyone who runs `npm install` on this package executes whatever the "
                            "remote URL currently serves, with no review possible at install time.",
                    fix="Never pipe a remote download into a shell from an install hook. Vendor the "
                        "script, or require an explicit, reviewed install step.",
                    cwe="CWE-829", cvss=8.6, confidence="high",
                ))
    return findings


def _check_requirements_txt(root: Path, manifest_rel: str) -> list[Finding]:
    findings: list[Finding] = []
    full = root / manifest_rel
    try:
        lines = full.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return findings

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        name = re.split(r"[=<>!~\[; ]", stripped, maxsplit=1)[0].strip()
        if not name:
            continue

        match = _typosquat_match(name, POPULAR_PYPI)
        if match:
            findings.append(Finding(
                title=f"Possible typosquat dependency: '{name}'",
                severity=Severity.HIGH, category="dependency", detector="supplychain:typosquat",
                file=manifest_rel,
                evidence=f"'{name}' differs by one character from the popular package '{match}'",
                description=f"'{name}' is one edit away from the well-known package '{match}', "
                            f"a common typosquatting pattern.",
                exploit="A typosquat's setup.py/build hooks run attacker code on install.",
                fix=f"Verify this is intended. If not, replace it with '{match}'.",
                cwe="CWE-1357", confidence="medium",
            ))

        if "==" not in stripped:
            findings.append(Finding(
                title=f"Unpinned dependency version: '{name}'",
                severity=Severity.LOW, category="dependency", detector="supplychain:unpinned",
                file=manifest_rel,
                evidence=stripped[:200],
                description=f"'{name}' has no exact version pin ({stripped!r}), so installs aren't "
                            f"reproducible and a future (possibly compromised) release installs freely.",
                fix=f"Pin '{name}' with '=='  to a specific, reviewed version.",
                cwe="CWE-1104", confidence="medium",
            ))
    return findings


def audit_supply_chain(root: Path, manifests: list[str]) -> tuple[list[Finding], list[str]]:
    """Analyse dependency manifests for typosquats, unpinned versions, and install-script abuse."""
    findings: list[Finding] = []
    notes: list[str] = []
    for rel in manifests:
        name = Path(rel).name.lower()
        if name == "package.json":
            findings.extend(_check_npm_manifest(root, rel))
        elif name == "requirements.txt":
            findings.extend(_check_requirements_txt(root, rel))
    return findings, notes
