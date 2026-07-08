"""Lightweight compliance tagging: CWE → OWASP ASVS control + PCI-DSS requirement.

Deliberately *not* a compliance-scoring product (Wiz/enterprise territory) —
just a static, offline lookup that tells a developer "this finding maps to
ASVS V5.3.4 / PCI-DSS 6.2.4", giving audit-relevant context without claiming
to certify anything. Every CWE Argus actually emits has an entry; unknown
CWEs simply carry no tag rather than a wrong one.

References:
  - OWASP ASVS 4.0.3 (control numbering, e.g. "V5.3.4").
  - PCI-DSS v4.0 (requirement numbering, e.g. "6.2.4").
Mappings are to the single most representative control/requirement, not an
exhaustive cross-reference — enough to orient a reviewer, not to replace one.
"""

from __future__ import annotations

# CWE id (bare number as string) -> (ASVS control, PCI-DSS requirement, short label)
_CWE_MAP: dict[str, tuple[str, str, str]] = {
    "20": ("V5.1.3", "6.2.4", "Input validation"),
    "22": ("V12.3.1", "6.2.4", "Path traversal"),
    "77": ("V5.3.8", "6.2.4", "Command injection"),
    "250": ("V14.1.1", "2.2.1", "Execution with unnecessary privilege"),
    "78": ("V5.3.8", "6.2.4", "OS command injection"),
    "79": ("V5.3.3", "6.2.4", "Cross-site scripting"),
    "89": ("V5.3.4", "6.2.4", "SQL injection"),
    "94": ("V5.2.5", "6.2.4", "Code / template injection"),
    "95": ("V5.2.4", "6.2.4", "Code injection / eval"),
    "200": ("V7.4.1", "3.3.1", "Information exposure"),
    "285": ("V4.1.3", "7.2.1", "Improper authorization (BFLA)"),
    "290": ("V2.2.1", "8.3.1", "Authentication bypass"),
    "295": ("V9.2.1", "4.2.1", "Certificate validation"),
    "306": ("V4.1.1", "8.3.1", "Missing authentication"),
    "326": ("V6.2.1", "3.6.1", "Weak encryption strength"),
    "327": ("V6.2.2", "3.6.1", "Broken crypto algorithm"),
    "338": ("V6.3.1", "3.6.1", "Weak PRNG"),
    "347": ("V6.2.7", "3.6.1", "Signature verification"),
    "352": ("V4.2.2", "6.2.4", "Cross-site request forgery"),
    "362": ("V11.1.6", "6.2.4", "Race condition"),
    "434": ("V12.2.1", "6.2.4", "Unrestricted file upload"),
    "489": ("V14.1.3", "6.2.4", "Debug code enabled"),
    "502": ("V5.5.1", "6.2.4", "Unsafe deserialization"),
    "522": ("V2.7.2", "8.3.1", "Insufficiently protected credentials"),
    "530": ("V14.3.2", "6.2.4", "Backup/temp file exposure"),
    "601": ("V5.1.5", "6.2.4", "Open redirect"),
    "611": ("V5.5.2", "6.2.4", "XML external entity (XXE)"),
    "613": ("V3.3.1", "8.6.1", "Insufficient session expiration"),
    "639": ("V4.2.1", "6.2.4", "Insecure direct object reference"),
    "668": ("V1.14.4", "1.3.1", "Resource exposed to wrong sphere"),
    "693": ("V14.4.1", "6.2.4", "Protection mechanism failure"),
    "506": ("V10.3.1", "6.3.2", "Embedded malicious/obfuscated code"),
    "732": ("V12.3.1", "7.1.2", "Incorrect permission assignment on a critical resource"),
    "798": ("V2.10.4", "8.3.1", "Hardcoded credentials"),
    "829": ("V10.3.2", "6.3.2", "Untrusted functionality inclusion"),
    "841": ("V11.1.1", "6.2.4", "Improper workflow / business logic"),
    "918": ("V12.6.1", "6.2.4", "Server-side request forgery"),
    "942": ("V14.4.6", "6.2.4", "Permissive CORS"),
    "1004": ("V3.4.2", "6.2.4", "Cookie missing HttpOnly"),
    "1021": ("V14.4.7", "6.2.4", "Clickjacking / UI redress"),
    "1104": ("V14.2.1", "6.3.2", "Unmaintained dependency"),
    "1357": ("V14.2.4", "6.3.2", "Untrustworthy component"),
    "1385": ("V13.2.6", "6.2.4", "WebSocket origin validation"),
    "1395": ("V14.2.1", "6.3.2", "Vulnerable dependency"),
}


def _cwe_number(cwe: str | None) -> str | None:
    if not cwe:
        return None
    text = cwe.upper().replace("CWE-", "").strip()
    return text if text.isdigit() else None


def compliance_for(cwe: str | None) -> dict | None:
    """Return {"asvs", "pci_dss", "label"} for a CWE, or None if unmapped."""
    num = _cwe_number(cwe)
    if num is None or num not in _CWE_MAP:
        return None
    asvs, pci, label = _CWE_MAP[num]
    return {"asvs": f"ASVS {asvs}", "pci_dss": f"PCI-DSS {pci}", "label": label}
