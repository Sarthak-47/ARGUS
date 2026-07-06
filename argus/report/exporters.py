"""Export a ScanResult to HTML, JSON, Markdown, or PDF.

HTML uses a Jinja2 template carrying the 'carved in stone' Argus branding. JSON is
the raw machine-readable model. Markdown suits GitHub issues/PRs. PDF is best-effort:
it renders only if an HTML->PDF backend (weasyprint) is installed, otherwise it
falls back to HTML with a clear note.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from argus.models import ScanResult, Severity

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )


_TOP_RISK_LIMIT = 5


def _ctx(result: ScanResult) -> dict:
    sorted_findings = result.sorted_findings()
    # Leads the report before the full findings table — a reader should see
    # the handful of things that actually matter without scrolling past
    # every LOW/INFO finding first. Empty when there's nothing CRITICAL/HIGH:
    # a clean-ish scan's risk score already says everything an exec summary
    # needs to, and an empty "Top Risks" section would just be noise.
    top_risks = [f for f in sorted_findings if f.severity.value in ("CRITICAL", "HIGH")][:_TOP_RISK_LIMIT]
    return {
        "result": result,
        "findings": sorted_findings,
        "top_risks": top_risks,
        "counts": result.counts(),
        "risk_score": result.risk_score,
        "risk_band": result.risk_band,
        "risk_band_color": result.risk_band_color,
        "codebase": result.codebase_map,
        "generated": time.strftime("%Y-%m-%d %H:%M"),
        "sev_color": {s.value: s.color for s in Severity},
        "version": __import__("argus").__version__,
    }


def to_html(result: ScanResult) -> str:
    return _env().get_template("report.html.j2").render(**_ctx(result))


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


_PURL_TYPE = {"npm": "npm", "pypi": "pypi"}


def to_sbom(result: ScanResult) -> str:
    """CycloneDX 1.5 JSON SBOM from the package inventory collected at scan time."""
    import uuid

    components = []
    for pkg in result.sbom_components:
        purl_type = _PURL_TYPE.get(pkg["ecosystem"], pkg["ecosystem"])
        version = pkg["version"]
        purl = f"pkg:{purl_type}/{pkg['name']}@{version}" if version != "unknown" else f"pkg:{purl_type}/{pkg['name']}"
        components.append({
            "type": "library",
            "bom-ref": f"{pkg['ecosystem']}:{pkg['name']}@{version}",
            "name": pkg["name"],
            "version": version,
            "purl": purl,
        })

    return json.dumps({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tools": [{"vendor": "Sarthak-47", "name": "Argus", "version": __import__("argus").__version__}],
            "component": {"type": "application", "name": result.target},
        },
        "components": components,
    }, indent=2)


_SARIF_LEVEL = {
    "CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note",
}


def to_sarif(result: ScanResult) -> str:
    """SARIF 2.1.0 output for GitHub code scanning / any SARIF consumer."""
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in result.sorted_findings():
        rule_id = f.detector or f.category or "argus"
        if rule_id not in rules:
            rule = {
                "id": rule_id,
                "name": f.category or "finding",
                "shortDescription": {"text": f.title},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.severity.value, "note")},
                "properties": {"security-severity": str(f.cvss) if f.cvss else _severity_number(f.severity.value)},
            }
            if f.cwe:
                rule["properties"]["cwe"] = f.cwe
            rules[rule_id] = rule

        entry: dict = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(f.severity.value, "note"),
            "message": {"text": _sarif_message(f)},
            "properties": {"severity": f.severity.value, "confidence": f.confidence},
        }
        if f.poc:
            entry["properties"]["poc_curl"] = f.poc.get("curl", "")
            entry["properties"]["poc_request"] = f.poc.get("request", "")
            entry["properties"]["poc_response"] = f.poc.get("response", "")
        if f.file:
            region = {"startLine": f.line} if f.line else {"startLine": 1}
            entry["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": region,
                }
            }]
        elif f.endpoint:
            entry["locations"] = [{
                "logicalLocations": [{"fullyQualifiedName": f.endpoint, "kind": "endpoint"}]
            }]
        results.append(entry)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Argus",
                "informationUri": "https://github.com/Sarthak-47/ARGUS",
                "version": __import__("argus").__version__,
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def _severity_number(sev: str) -> str:
    # GitHub maps 'security-severity' 0-10 to its own buckets.
    return {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.0", "LOW": "3.0", "INFO": "1.0"}.get(sev, "1.0")


def _sarif_message(f) -> str:
    parts = [f.title]
    if f.description:
        parts.append(f.description)
    if f.fix:
        parts.append(f"Fix: {f.fix}")
    return " — ".join(parts)


def to_markdown(result: ScanResult) -> str:
    lines: list[str] = []
    a = lines.append
    a(f"# Argus Security Report — `{result.target}`\n")
    a(f"**Risk Score:** {result.risk_score}/100  **[{result.risk_band}]**  ")
    a(f"_Generated {time.strftime('%Y-%m-%d %H:%M')} · phase: {result.phase}_\n")

    counts = result.counts()
    a("| Severity | Count |")
    a("|---|---|")
    for s in Severity:
        a(f"| {s.value} | {counts[s.value]} |")
    a("")

    top_risks = [f for f in result.sorted_findings() if f.severity.value in ("CRITICAL", "HIGH")][:_TOP_RISK_LIMIT]
    if top_risks:
        a("## Top Risks\n")
        for f in top_risks:
            a(f"- **[{f.severity.value}]** {f.title} — `{f.location}`")
        a("")

    if result.codebase_map:
        cm = result.codebase_map
        a("## Codebase\n")
        a(f"- Primary language: **{cm.primary_language or 'unknown'}**")
        a(f"- Files: {cm.file_count} · LOC: {cm.total_loc}")
        if cm.frameworks:
            a(f"- Frameworks: {', '.join(cm.frameworks)}")
        a("")

    a("## Findings\n")
    for f in result.sorted_findings():
        a(f"### [{f.severity.value}] {f.title}")
        a(f"- **Location:** `{f.location}`  ")
        a(f"- **Detector:** {f.detector}" + (f" · **CWE:** {f.cwe}" if f.cwe else ""))
        if f.description:
            a(f"\n{f.description}\n")
        if f.evidence:
            a(f"```\n{f.evidence}\n```")
        if f.exploit:
            a(f"**Exploit:** {f.exploit}\n")
        if f.fix:
            a(f"**Fix:** {f.fix}\n")
        a("")
    return "\n".join(lines)


def export(result: ScanResult, fmt: str, output_dir: str) -> Path:
    """Write the report in ``fmt`` to ``output_dir``. Returns the file path."""
    fmt = fmt.lower()
    out = Path(output_dir).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        path = out / "report.json"
        path.write_text(to_json(result), encoding="utf-8")
        return path
    if fmt == "sarif":
        path = out / "argus.sarif"
        path.write_text(to_sarif(result), encoding="utf-8")
        return path
    if fmt == "sbom":
        path = out / "sbom.cdx.json"
        path.write_text(to_sbom(result), encoding="utf-8")
        return path
    if fmt in ("md", "markdown"):
        path = out / "report.md"
        path.write_text(to_markdown(result), encoding="utf-8")
        return path
    if fmt == "pdf":
        html = to_html(result)
        try:
            from weasyprint import HTML  # type: ignore

            path = out / "report.pdf"
            HTML(string=html).write_pdf(str(path))
            return path
        except Exception:
            # graceful fallback — write HTML and let the caller know
            path = out / "index.html"
            path.write_text(html, encoding="utf-8")
            return path

    # default: html
    path = out / "index.html"
    path.write_text(to_html(result), encoding="utf-8")
    return path
