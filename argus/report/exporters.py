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


def _ctx(result: ScanResult) -> dict:
    return {
        "result": result,
        "findings": result.sorted_findings(),
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
