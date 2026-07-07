"""Built-in deterministic code rules — Argus's offline scanner.

Semgrep is the heavyweight engine, but it does not run natively on Windows and is
optional. These regex/line rules give Argus a useful, zero-dependency static scan
on every platform: injection sinks, dangerous calls, weak crypto, and insecure
defaults. Each rule is scoped to relevant languages to cut false positives.

A rule is a dict: id, title, severity, category, langs, pattern, cwe, fix, [require].
``require`` is an optional second pattern that must also be present on the line
(used to demand a tainted/variable argument rather than a constant).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from argus.config.defaults import IGNORE_DIRS, LANGUAGE_BY_EXT
from argus.models import Finding, Severity

# Variable-ish argument: f-strings, concatenation, template literals, % / .format.
_TAINT = r"""(?:f['"]|['"]\s*\+|\+\s*[A-Za-z_]|`[^`]*\$\{|%\s*[A-Za-z(]|\.format\(|\$\{|\#\{)"""

RULES: list[dict] = [
    # ---------------- Injection ----------------
    {
        "id": "py-sql-fstring", "title": "Possible SQL injection (string-built query)",
        "severity": Severity.HIGH, "category": "injection", "langs": {"Python"},
        "pattern": re.compile(r"(?i)(?:execute|executemany|executescript|raw|cursor\.execute)\s*\(\s*(?:f['\"]|['\"].*['\"]\s*[+%]|.*\.format\()"),
        "cwe": "CWE-89",
        "fix": "Use parameterised queries (e.g. cursor.execute(sql, (params,))) instead of string interpolation.",
    },
    {
        "id": "js-sql-concat", "title": "Possible SQL injection (string-built query)",
        "severity": Severity.HIGH, "category": "injection", "langs": {"JavaScript", "TypeScript"},
        "pattern": re.compile(r"(?i)\.(?:query|execute|raw)\s*\(\s*(?:`[^`]*\$\{|['\"].*['\"]\s*\+)"),
        "cwe": "CWE-89",
        "fix": "Use parameterised queries / prepared statements or an ORM with bound parameters.",
    },
    {
        "id": "py-command-injection", "title": "Possible command injection",
        "severity": Severity.HIGH, "category": "injection", "langs": {"Python"},
        "pattern": re.compile(r"(?i)(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output))\s*\(.*"),
        "require": re.compile(_TAINT),
        "extra_require_for": "shell=True",
        "cwe": "CWE-78",
        "fix": "Avoid shell=True; pass an argument list and never interpolate user input into a shell string.",
    },
    {
        "id": "py-eval-exec", "title": "Dangerous dynamic execution (eval/exec)",
        "severity": Severity.HIGH, "category": "injection", "langs": {"Python"},
        "pattern": re.compile(r"(?<![\w.])(?:eval|exec)\s*\("),
        "cwe": "CWE-95",
        "fix": "Remove eval/exec; use ast.literal_eval for data or a safe dispatch table.",
    },
    {
        "id": "js-eval", "title": "Dangerous dynamic execution (eval / Function)",
        "severity": Severity.HIGH, "category": "injection", "langs": {"JavaScript", "TypeScript"},
        "pattern": re.compile(r"(?<![\w.])(?:eval\s*\(|new\s+Function\s*\()"),
        "cwe": "CWE-95",
        "fix": "Avoid eval/new Function on dynamic input; use JSON.parse or explicit logic.",
    },
    {
        "id": "js-child-process", "title": "Possible command injection (child_process)",
        "severity": Severity.HIGH, "category": "injection", "langs": {"JavaScript", "TypeScript"},
        "pattern": re.compile(r"(?i)(?:child_process\.)?exec(?:Sync)?\s*\(\s*(?:`[^`]*\$\{|['\"].*['\"]\s*\+|[A-Za-z_]\w*)"),
        "cwe": "CWE-78",
        "fix": "Use execFile/spawn with an argument array instead of exec with an interpolated string.",
    },
    # ---------------- XSS / template ----------------
    {
        "id": "react-dangerous-html", "title": "XSS sink: dangerouslySetInnerHTML",
        "severity": Severity.MEDIUM, "category": "xss", "langs": {"JavaScript", "TypeScript"},
        "pattern": re.compile(r"dangerouslySetInnerHTML"),
        "cwe": "CWE-79",
        "fix": "Sanitise HTML (e.g. DOMPurify) before rendering, or avoid raw HTML injection.",
    },
    {
        "id": "dom-innerhtml", "title": "XSS sink: assignment to innerHTML",
        "severity": Severity.MEDIUM, "category": "xss", "langs": {"JavaScript", "TypeScript"},
        "pattern": re.compile(r"\.innerHTML\s*=\s*(?:`[^`]*\$\{|[A-Za-z_]\w*|['\"].*\+)"),
        "cwe": "CWE-79",
        "fix": "Use textContent or sanitise input before assigning to innerHTML.",
    },
    {
        "id": "vue-vhtml", "title": "XSS sink: v-html",
        "severity": Severity.MEDIUM, "category": "xss", "langs": {"Vue"},
        "pattern": re.compile(r"v-html\s*="),
        "cwe": "CWE-79",
        "fix": "Avoid v-html with untrusted content; sanitise first.",
    },
    {
        "id": "js-document-write", "title": "XSS sink: document.write with dynamic input",
        "severity": Severity.MEDIUM, "category": "xss", "langs": {"JavaScript", "TypeScript"},
        "pattern": re.compile(r"document\.write(?:ln)?\s*\(\s*(?:`[^`]*\$\{|[A-Za-z_]\w*|['\"].*['\"]\s*\+)"),
        "cwe": "CWE-79",
        "fix": "Avoid document.write; build DOM nodes with textContent, or sanitise before injecting HTML.",
    },
    {
        "id": "py-django-mark-safe", "title": "XSS sink: mark_safe on dynamic input",
        "severity": Severity.MEDIUM, "category": "xss", "langs": {"Python"},
        "pattern": re.compile(r"mark_safe\s*\(\s*(?:f['\"]|[A-Za-z_]\w*|['\"].*['\"]\s*[+%]|.*\.format\()"),
        "cwe": "CWE-79",
        "fix": "Don't mark_safe() attacker-influenced strings; escape them, or sanitise HTML first.",
    },
    # ---------------- Open redirect / SSTI ----------------
    {
        "id": "js-open-redirect", "title": "Possible open redirect (user-controlled location)",
        "severity": Severity.MEDIUM, "category": "injection", "langs": {"JavaScript", "TypeScript"},
        "pattern": re.compile(r"(?i)\.redirect\s*\([^)]*\breq\.(?:query|params|body|headers)\b"),
        "cwe": "CWE-601",
        "fix": "Validate redirect targets against an allow-list; never redirect straight to a request-supplied URL.",
    },
    {
        "id": "py-ssti-render-string", "title": "Server-side template injection (render_template_string)",
        "severity": Severity.HIGH, "category": "injection", "langs": {"Python"},
        "pattern": re.compile(r"render_template_string\s*\(\s*(?:f['\"]|[A-Za-z_]\w*|['\"].*['\"]\s*[+%]|.*\.format\()"),
        "cwe": "CWE-94",
        "fix": "Never build a template from user input; render a fixed template and pass data as context variables.",
    },
    # ---------------- Crypto ----------------
    {
        "id": "weak-hash-md5-sha1", "title": "Weak hash algorithm (MD5/SHA1)",
        "severity": Severity.MEDIUM, "category": "crypto", "langs": {"Python", "JavaScript", "TypeScript", "Go", "Java", "PHP", "Ruby"},
        "pattern": re.compile(r"(?i)(?:hashlib\.(?:md5|sha1)|createHash\(\s*['\"](?:md5|sha1)|MessageDigest\.getInstance\(\s*['\"](?:MD5|SHA-1))"),
        "cwe": "CWE-327",
        "fix": "Use SHA-256+ for integrity, and bcrypt/scrypt/argon2 for passwords.",
    },
    {
        "id": "insecure-random", "title": "Insecure randomness for security context",
        "severity": Severity.LOW, "category": "crypto", "langs": {"Python", "JavaScript", "TypeScript"},
        "pattern": re.compile(r"(?i)(?:random\.(?:random|randint|choice)\s*\(|Math\.random\s*\()"),
        "require": re.compile(r"(?i)(?:token|secret|password|otp|nonce|session|key|salt)"),
        "cwe": "CWE-338",
        "fix": "Use secrets (Python) or crypto.randomBytes (Node) for security-sensitive values.",
    },
    {
        "id": "hashlib-new-weak", "title": "Weak hash algorithm (MD5/SHA1 via hashlib.new)",
        "severity": Severity.MEDIUM, "category": "crypto", "langs": {"Python"},
        "pattern": re.compile(r"(?i)hashlib\.new\s*\(\s*['\"](?:md5|sha1)['\"]"),
        "cwe": "CWE-327",
        "fix": "Use SHA-256+ for integrity, and bcrypt/scrypt/argon2 for passwords.",
    },
    {
        "id": "js-deprecated-cipher", "title": "Deprecated/insecure cipher (createCipher)",
        "severity": Severity.MEDIUM, "category": "crypto", "langs": {"JavaScript", "TypeScript"},
        "pattern": re.compile(r"crypto\.createCipher(?!iv)\s*\("),
        "cwe": "CWE-327",
        "fix": "createCipher derives a weak key with no IV — use createCipheriv with a random IV instead.",
    },
    {
        "id": "js-localstorage-secret", "title": "Sensitive value stored in web storage",
        "severity": Severity.LOW, "category": "crypto", "langs": {"JavaScript", "TypeScript"},
        "pattern": re.compile(r"(?i)(?:localStorage|sessionStorage)\.setItem\s*\("),
        "require": re.compile(r"(?i)(?:token|secret|password|jwt|api[_-]?key|session)"),
        "cwe": "CWE-522",
        "fix": "Don't keep tokens/secrets in localStorage (readable by any XSS); use httpOnly cookies.",
    },
    # ---------------- Misconfig / insecure defaults ----------------
    {
        "id": "debug-true", "title": "Debug mode enabled",
        "severity": Severity.MEDIUM, "category": "misconfig", "langs": {"Python"},
        "pattern": re.compile(r"(?i)DEBUG\s*=\s*True"),
        "cwe": "CWE-489",
        "fix": "Set DEBUG=False in production; drive it from an environment variable.",
    },
    {
        "id": "cors-wildcard", "title": "Permissive CORS (wildcard origin)",
        "severity": Severity.MEDIUM, "category": "misconfig", "langs": {"Python", "JavaScript", "TypeScript", "Go"},
        "pattern": re.compile(r"(?i)(?:Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*|origin\s*[:=]\s*['\"]\*['\"]|cors\(\s*\{\s*origin\s*:\s*['\"]?\*)"),
        "cwe": "CWE-942",
        "fix": "Restrict CORS to an explicit allow-list of trusted origins.",
    },
    {
        "id": "verify-disabled", "title": "TLS certificate verification disabled",
        "severity": Severity.HIGH, "category": "misconfig", "langs": {"Python", "JavaScript", "TypeScript"},
        "pattern": re.compile(r"(?i)(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0)"),
        "cwe": "CWE-295",
        "fix": "Never disable certificate verification; fix the underlying trust-store issue instead.",
    },
    {
        "id": "go-insecure-skip-verify", "title": "TLS certificate verification disabled",
        "severity": Severity.HIGH, "category": "misconfig", "langs": {"Go"},
        "pattern": re.compile(r"InsecureSkipVerify\s*:\s*true"),
        "cwe": "CWE-295",
        "fix": "Remove InsecureSkipVerify: true; configure a proper trust store instead.",
    },
    {
        "id": "go-shell-command", "title": "Possible command injection (shell via exec.Command)",
        "severity": Severity.HIGH, "category": "injection", "langs": {"Go"},
        "pattern": re.compile(r"exec\.Command\s*\(\s*['\"](?:/bin/)?(?:sh|bash|zsh|cmd|powershell)['\"]\s*,\s*['\"]-c"),
        "cwe": "CWE-78",
        "fix": "Pass the program and its args directly to exec.Command; don't route user input through a shell -c.",
    },
    {
        "id": "flask-host-all", "title": "Service bound to all interfaces with debug",
        "severity": Severity.LOW, "category": "misconfig", "langs": {"Python"},
        "pattern": re.compile(r"(?i)\.run\(.*host\s*=\s*['\"]0\.0\.0\.0['\"].*debug\s*=\s*True"),
        "cwe": "CWE-489",
        "fix": "Do not expose a debug server on 0.0.0.0; disable debug in production.",
    },
    # ---------------- Deserialisation / SSRF-ish ----------------
    {
        "id": "py-yaml-load", "title": "Unsafe YAML deserialisation (yaml.load)",
        "severity": Severity.HIGH, "category": "deserialization", "langs": {"Python"},
        "pattern": re.compile(r"yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)"),
        "cwe": "CWE-502",
        "fix": "Use yaml.safe_load() instead of yaml.load().",
    },
    {
        "id": "py-pickle-loads", "title": "Unsafe deserialisation (pickle)",
        "severity": Severity.MEDIUM, "category": "deserialization", "langs": {"Python"},
        "pattern": re.compile(r"pickle\.loads?\s*\("),
        "cwe": "CWE-502",
        "fix": "Never unpickle untrusted data; use JSON or a signed, safe format.",
    },
    {
        "id": "py-xxe-parse", "title": "Possible XXE (untrusted XML parsing)",
        "severity": Severity.LOW, "category": "deserialization", "langs": {"Python"},
        "pattern": re.compile(r"(?i)(?:etree\.(?:parse|fromstring)|xml\.dom\.minidom\.parse|parseString)\s*\("),
        "cwe": "CWE-611",
        "fix": "Parse untrusted XML with defusedxml, which disables external entity/DTD resolution (XXE).",
    },
]

_TEXT_EXT = set(LANGUAGE_BY_EXT)
MAX_FILE_BYTES = 1_500_000
# Strip line/block comments cheaply to reduce false positives on commented code.
_COMMENT_PREFIX = ("#", "//", "*", "/*", "<!--")


def _lang_for(path: Path) -> str | None:
    return LANGUAGE_BY_EXT.get(path.suffix.lower())


def scan_rules(root: Path) -> list[Finding]:
    """Apply all built-in rules across the tree."""
    findings: list[Finding] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for fn in filenames:
            ext = Path(fn).suffix.lower()
            if ext not in _TEXT_EXT:
                continue
            full = Path(dirpath) / fn
            lang = _lang_for(full)
            if not lang:
                continue
            try:
                if full.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = full.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(full.relative_to(root)).replace("\\", "/")
            findings.extend(_scan_file(rel, lang, text))
    return findings


def _scan_file(rel: str, lang: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    applicable = [r for r in RULES if lang in r["langs"]]
    if not applicable:
        return out
    for idx, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith(_COMMENT_PREFIX):
            continue
        if len(line) > 4000:
            continue
        for rule in applicable:
            if not rule["pattern"].search(line):
                continue
            if "require" in rule and not rule["require"].search(line):
                continue
            extra = rule.get("extra_require_for")
            if extra and extra not in line and not rule.get("require", re.compile("")).search(line):
                continue
            out.append(Finding(
                title=rule["title"],
                severity=rule["severity"],
                category=rule["category"],
                detector=f"rule:{rule['id']}",
                file=rel,
                line=idx,
                evidence=line[:200],
                description=rule["title"] + ".",
                fix=rule["fix"],
                cwe=rule.get("cwe"),
                confidence="medium",
            ))
    return out
