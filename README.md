<div align="center">

# ◈ ARGUS

**The security tool built for the vibe-coding era.**

*Point it at a repo. It reads the code, spins up the app, and attacks it.*

[![CI](https://github.com/Sarthak-47/ARGUS/actions/workflows/ci.yml/badge.svg)](https://github.com/Sarthak-47/ARGUS/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-B8860B.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-B8860B.svg)](https://www.python.org)

</div>

---

**Argus** is an AI-powered security audit agent for developers. Named after **Argus Panoptes** —
the hundred-eyed giant of Greek myth who never slept and saw everything.

Static scanners tell you what *looks* wrong. Argus **proves** it: it reads your code, then spins
your app up and actually attacks it — dumping data via SQLi, forging admin JWTs, reaching cloud
metadata via SSRF — and explains every finding in plain English, tailored to your codebase.

## ⚡ See it in 30 seconds

```bash
pip install argus-sec        # or: pipx install argus-sec
argus demo
```

`argus demo` scans and attacks a **bundled, intentionally-vulnerable app** (nothing external is
touched) so you can watch the full flow immediately:

```
◈ ARGUS — STATIC SCAN
Risk Score 98/100  [CRITICAL]
  ■ HIGH   SQL injection · command injection · unsafe yaml.load

◈ ARGUS — ATTACK AGENT
  [INJECTOR:SQLI-ERROR]         ✓ SQL injection (error-based)
  [AUTHBREAKER:JWT-WEAK-SECRET] ✓ JWT signed with a weak secret
  [XSSHUNTER:REFLECTED]         ✓ Reflected XSS
  [SSRFPROBER:CALLBACK]         ✓ Server-Side Request Forgery (blind)
  [IDORHUNTER]                  ✓ Insecure Direct Object Reference
  [FILEATTACKER:TRAVERSAL]      ✓ Path traversal (arbitrary file read)
```

## How it works — two phases

| Phase | What it does |
|---|---|
| **1 · Static Analysis** | Reads the codebase without running it: built-in rules, dependency CVEs (`npm/pip audit`), secret detection (regex + Shannon entropy + git history), then an LLM layer that validates, explains and re-rates each finding for *your* code. |
| **2 · Attack Agent** | Points a swarm of **16 specialised agents** at the running app — orchestrated in a loop, with an out-of-band callback server to confirm *blind* vulnerabilities, and every confirmed finding carries a runnable proof-of-concept (curl command + real request/response), not just a description. |

### The attack swarm

`ReconBot` · `CrawlerBot` · `Injector` (SQLi/NoSQL/command) · `AuthBreaker` (JWT/session/MFA) ·
`IDORHunter` · `XSSHunter` · `SSRFProber` · `HeaderPoker` (CORS) · `CSRFHunter` · `FileAttacker`
(upload/traversal) · `Fuzzer` · `RaceCondition` · `GraphQLAgent` · `WebSocketAgent` ·
`MCPSecurityAgent` (exposed MCP servers & AI-infra leaks) · **`BusinessLogicAgent`** — reasons
over the discovered endpoints with an LLM to propose coupon-stacking/negative-quantity/workflow-
bypass abuse, then *executes* it and confirms behaviorally. This targets the gap the rest of the
industry hasn't solved: ~70% of critical web vulnerabilities are business logic flaws, and no
autonomous agent reliably detects them. Auto-enables the moment an LLM provider is configured —
no flag needed — and stays silent otherwise.

Opt-in: **`DomXSSHunter`** — a real headless-browser agent (`--agents domxss`) that catches DOM
XSS in React/Vue/Next apps the HTTP-only agents can't see. Needs `pip install
'argus-sec[browser]' && playwright install chromium`.

## Install & use

```bash
pip install argus-sec

argus demo                                # zero-setup showcase — see it work in 30s
argus setup                               # first-time wizard (detects GPU, picks an LLM)
argus scan <repo-url|path>                # Phase 1 — static analysis
argus scan <path> --deep                  # + full LLM free-form review of high-risk files
argus attack --url http://localhost:3000  # Phase 2 — attack a running app
argus audit <repo-url>                    # Phase 1 + Phase 2
argus fix <path>                          # generate patches for fixable findings (dry-run)
argus fix <path> --apply                  # write the patches to disk
argus report --format html                # export the last scan (html|json|markdown|sarif|pdf)
argus config --show
```

### Run in Docker (bundles Semgrep + auditors)

```bash
docker build -t argus .
docker run --rm -v "$PWD:/src" argus scan /src --no-llm
```

## Works on any machine — local or BYOK

Argus needs no hosted service. Pick a **local model** (Ollama — private, offline) or **bring your
own key** for Groq / Gemini / Claude / OpenRouter. On `argus setup` it detects your GPU and
recommends a model that fits your VRAM. **With no LLM configured it still runs the full
deterministic scan** (rules + dependency audit + secret detection).

## Put it in CI

Add Argus to any repo and publish findings to GitHub's **Security tab**:

```yaml
- uses: Sarthak-47/ARGUS@main
  id: argus
  with:
    target: "."
    fail-on: "critical"      # fail the build on critical findings
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.argus.outputs.sarif-file }}
```

`argus scan --format sarif` and `argus scan --fail-on high` also work standalone in any pipeline.

## Desktop GUI

A React + Vite + Tauri desktop app ("a war room inside the Parthenon") with five screens —
Dashboard, New Scan, Live Attack, Reports, Settings — that renders **real engine output** (drop
an `argus scan --format json` result at `gui/public/report.json`).

```bash
cd gui
npm install
npm run dev              # browser dev server, http://localhost:5173
npm run tauri dev        # native window (needs Rust: https://rustup.rs)
npm run tauri build      # produces a real .exe/.dmg/.AppImage in src-tauri/target/release
```

The native shell is ~9MB and starts in well under a second — a fraction of an Electron
equivalent. Wiring the desktop window to invoke the Python engine directly (rather than reading
a dropped-in `report.json`) is tracked as the next step.

## Why Argus

| Tool | Static | Active attack | LLM reasoning | Free | Local model | Open source |
|---|---|---|---|---|---|---|
| Snyk | ✓ | ✗ | ✗ | Partial | ✗ | ✗ |
| SonarQube | ✓ | ✗ | ✗ | Partial | ✗ | Partial |
| Semgrep | ✓ | ✗ | ✗ | ✓ | ✗ | ✓ |
| Burp Suite | ✗ | ✓ | ✗ | Partial | ✗ | ✗ |
| OWASP ZAP | ✗ | ✓ | ✗ | ✓ | ✗ | ✓ |
| **Argus** | **✓** | **✓** | **✓** | **✓** | **✓** | **✓** |

Nobody else combines all six. That's the gap Argus owns.

## Status

- ✅ **Phase 1 — Static analysis** (`argus scan`): rules, dependency audit, supply-chain manifest
  analysis (typosquats, unpinned versions, install-script abuse), secret detection, LLM reasoning,
  reports (HTML/JSON/Markdown/SARIF).
- ✅ **Phase 2 — Attack swarm** (`argus attack`): **16 agents** (13 original + MCPSecurityAgent,
  BusinessLogicAgent, and the opt-in DomXSSHunter), orchestration loop, callback server for blind
  detection, deduplicated findings, and a reproducible proof-of-concept per confirmed exploit.
- ✅ **`argus fix`**: LLM-generated patches for fixable findings — dry-run preview or `--apply`.
- ✅ **`argus demo`**: zero-setup showcase against a bundled vulnerable app.
- ✅ **GUI**: five screens rendering real engine data, including captured PoCs.
- ✅ **CI-ready**: SARIF output, `--fail-on`, GitHub Action, green test suite (92 tests).
- 🚧 Native packaging (Tauri `.exe`/`.dmg`/`.AppImage`) and PyPI publish.

*Semgrep is optional and layered in when available — it has no native Windows build, so Argus's
own rules carry the scan there (use the Docker image for full Semgrep).*

## Responsible use

Argus is an **offensive** tool. **Only run it against systems you own or are authorized to
test.** See [SECURITY.md](SECURITY.md). `argus demo` gives you a safe, bundled target to explore.

## Contributing

New attack agents, rules and payloads are very welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT © Sarthak-47 · see [LICENSE](LICENSE)
