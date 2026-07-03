"""Secret detection: known key formats, Shannon entropy, and git-history scan.

Three complementary passes:
  1. Regex match against well-known credential formats (AWS, Stripe, GitHub, …).
  2. High-entropy string detection (catches unknown key formats > 20 chars).
  3. Git-history scan — secrets removed in later commits still live in history.
All deterministic; runs with zero LLM cost.
"""

from __future__ import annotations

import math
import re
from pathlib import Path

from argus.config.defaults import IGNORE_DIRS
from argus.models import Finding, Severity

# --- known credential formats: (label, severity, compiled regex) ---
_SECRET_PATTERNS: list[tuple[str, Severity, re.Pattern]] = [
    ("AWS Access Key ID", Severity.CRITICAL, re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS Secret Access Key", Severity.CRITICAL, re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})")),
    ("Stripe Live Secret Key", Severity.CRITICAL, re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("Stripe Restricted Key", Severity.HIGH, re.compile(r"\brk_live_[0-9a-zA-Z]{24,}\b")),
    ("GitHub Token", Severity.CRITICAL, re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("GitLab PAT", Severity.HIGH, re.compile(r"\bglpat-[0-9A-Za-z_\-]{20,}\b")),
    ("Slack Token", Severity.HIGH, re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("Google API Key", Severity.HIGH, re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Twilio Account SID", Severity.HIGH, re.compile(r"\bAC[0-9a-fA-F]{32}\b")),
    ("SendGrid API Key", Severity.HIGH, re.compile(r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b")),
    ("OpenAI API Key", Severity.CRITICAL, re.compile(r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b")),
    ("Anthropic API Key", Severity.CRITICAL, re.compile(r"\bsk-ant-[0-9A-Za-z_\-]{20,}\b")),
    ("Private Key Block", Severity.CRITICAL, re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("JWT", Severity.MEDIUM, re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("DB Connection String w/ creds", Severity.HIGH, re.compile(r"(?i)(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s:@/]+@")),
    ("Generic Secret Assignment", Severity.MEDIUM, re.compile(r"(?i)(?:password|passwd|secret|api[_-]?key|token|access[_-]?key)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]")),
]

# Extensions worth scanning for secrets (skip binaries / images).
_TEXT_EXT = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".php", ".java", ".kt",
    ".rs", ".c", ".cpp", ".cs", ".sh", ".sql", ".vue", ".svelte", ".env",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".txt", ".md",
    ".xml", ".properties", ".tf", ".tfvars",
}
_ALWAYS_SCAN = {".env", "dockerfile", "docker-compose.yml", "docker-compose.yaml"}
MAX_FILE_BYTES = 1_500_000

# Tokens that indicate a placeholder rather than a real secret.
_PLACEHOLDER = re.compile(r"(?i)(your[_-]?|example|placeholder|changeme|xxx+|<.*>|\bdummy\b|\bsample\b|\.\.\.)")


def shannon_entropy(s: str) -> float:
    """Shannon entropy (bits per char) of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


_HIGH_ENTROPY_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")


def _scan_text(rel: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    seen: set[tuple[str, int]] = set()

    for idx, line in enumerate(lines, start=1):
        if len(line) > 4000:
            continue
        for label, sev, pat in _SECRET_PATTERNS:
            m = pat.search(line)
            if not m:
                continue
            snippet = line.strip()[:160]
            if label == "Generic Secret Assignment" and _PLACEHOLDER.search(snippet):
                continue
            key = (label, idx)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                title=f"Hardcoded secret: {label}",
                severity=sev,
                category="secret",
                detector="secrets",
                file=rel,
                line=idx,
                evidence=_mask(snippet),
                description=f"A {label} appears hardcoded in source. Hardcoded credentials "
                            f"can be extracted from the repository, its history, or shipped bundles.",
                fix="Move the secret to an environment variable or a secrets manager, "
                    "rotate the exposed credential, and purge it from git history.",
                cwe="CWE-798",
                confidence="high",
            ))

    # entropy pass — only on lines not already flagged
    flagged_lines = {ln for _, ln in seen}
    for idx, line in enumerate(lines, start=1):
        if idx in flagged_lines or len(line) > 2000:
            continue
        for token in _HIGH_ENTROPY_TOKEN.findall(line):
            if _PLACEHOLDER.search(token) or len(set(token)) < 12:
                continue
            if shannon_entropy(token) >= 4.3:
                findings.append(Finding(
                    title="High-entropy string (possible secret)",
                    severity=Severity.LOW,
                    category="secret",
                    detector="secrets-entropy",
                    file=rel,
                    line=idx,
                    evidence=_mask(line.strip()[:160]),
                    description="A high-entropy string was found that resembles a credential or key "
                                "but matches no known format. Verify it is not a live secret.",
                    fix="If this is a credential, move it to a secret store and rotate it.",
                    cwe="CWE-798",
                    confidence="low",
                ))
                break  # one entropy hit per line is enough
    return findings


def _mask(s: str) -> str:
    """Mask long credential-looking tokens in evidence so we don't echo secrets."""
    def repl(m: re.Match) -> str:
        tok = m.group(0)
        return tok[:4] + "•" * 6 + tok[-2:] if len(tok) > 12 else tok
    return _HIGH_ENTROPY_TOKEN.sub(repl, s)


def scan_secrets(root: Path) -> list[Finding]:
    """Run the regex + entropy passes across the tree."""
    import os

    findings: list[Finding] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for fn in filenames:
            name_lc = fn.lower()
            ext = Path(fn).suffix.lower()
            if ext not in _TEXT_EXT and name_lc not in _ALWAYS_SCAN:
                continue
            full = Path(dirpath) / fn
            try:
                if full.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = full.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(full.relative_to(root)).replace("\\", "/")
            findings.extend(_scan_text(rel, text))
    return findings


def scan_git_history(root: Path, max_commits: int = 200) -> list[Finding]:
    """Scan recent git history for secrets that were later removed."""
    try:
        from git import Repo
        from git.exc import GitCommandError
    except ImportError:
        return []

    try:
        repo = Repo(root)
    except Exception:
        return []
    if not repo.head.is_valid():
        return []

    findings: list[Finding] = []
    seen: set[str] = set()
    try:
        commits = list(repo.iter_commits(max_count=max_commits))
    except (GitCommandError, ValueError):
        return []

    pattern_subset = [p for p in _SECRET_PATTERNS if p[0] != "Generic Secret Assignment"]
    for commit in commits:
        try:
            diff_text = repo.git.show(commit.hexsha, "--unified=0", "--no-color")
        except Exception:
            continue
        for line in diff_text.splitlines():
            if not line.startswith("+") or line.startswith("+++"):
                continue
            for label, sev, pat in pattern_subset:
                m = pat.search(line)
                if not m:
                    continue
                dedupe = f"{label}:{m.group(0)[:12]}"
                if dedupe in seen:
                    continue
                seen.add(dedupe)
                findings.append(Finding(
                    title=f"Secret in git history: {label}",
                    severity=sev if sev != Severity.CRITICAL else Severity.HIGH,
                    category="secret",
                    detector="secrets-git",
                    evidence=_mask(line.strip()[:160]),
                    description=f"A {label} was committed in {commit.hexsha[:8]} "
                                f"({commit.committed_datetime:%Y-%m-%d}). Even if removed from the "
                                f"working tree, it remains recoverable from history.",
                    fix="Rotate the credential immediately, then rewrite history "
                        "(git filter-repo / BFG) to purge it.",
                    cwe="CWE-798",
                    confidence="high",
                    metadata={"commit": commit.hexsha},
                ))
    return findings
