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
| **2 · Attack Agent** | Points a swarm of **17 specialised agents** at the running app — orchestrated in a loop, with an out-of-band callback server to confirm *blind* vulnerabilities, and every confirmed finding carries a runnable proof-of-concept (curl command + real request/response), not just a description. |

### The attack swarm

`ReconBot` · `CrawlerBot` · `Injector` (SQLi/NoSQL/command) · `AuthBreaker` (JWT/session/MFA) ·
`IDORHunter` · `XSSHunter` · `SSRFProber` · `HeaderPoker` (CORS) · `CSRFHunter` · `FileAttacker`
(upload/traversal) · `Fuzzer` · `RaceCondition` · `GraphQLAgent` · `WebSocketAgent` ·
`MCPSecurityAgent` (exposed MCP servers & AI-infra leaks) · `PromptInjectionAgent` (probes the
app's own chatbot/AI features for prompt injection — sends a unique canary token wrapped in an
instruction-override payload and only reports a finding if that exact token comes back verbatim,
proving untrusted input reached the model without isolation from system instructions) ·
**`BusinessLogicAgent`** — reasons
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
argus report --format html                # export the last scan (html|json|markdown|sarif|sbom|pdf)
argus history                             # risk-score trend across past scans
argus compare                             # what's new/fixed since the last scan
argus suppress "<finding title>"          # mark a finding ignored — stops it recurring
argus surface                             # endpoints remembered across attack runs
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
For finer control than a single severity threshold, drop a `.argus-policy.toml` at your repo root
(or pass `--policy <file>`) to fail/warn/ignore per category, detector, or confirmed status — e.g.
fail on any confirmed SQLi but only warn on missing headers. See
[`.argus-policy.example.toml`](.argus-policy.example.toml). And `argus scan --diff-base main` (or
the Action's `diff-base` input) reports only findings in files the PR changed, so a pre-existing
backlog doesn't fail the build.

Adopting Argus on a repo that already has a backlog? Snapshot it once with `argus scan --write-baseline
.argus-baseline.json`, commit that file, then scan with `--baseline .argus-baseline.json` — every
finding that existed at adoption is treated as accepted and only genuinely new ones are reported and
gated on (survives line-number shifts, needs no git — unlike `--diff-base`).

## Attack behind a login (authenticated scanning)

Most real apps hide their interesting surface behind a login, so an
unauthenticated scan only sees the doormat. Give Argus a session and the whole
17-agent swarm — including ReconBot's crawl — acts as the logged-in user:

```bash
argus attack --url http://localhost:3000 --auth .argus-auth.toml
```

A `.argus-auth.toml` (auto-discovered in the working directory, or passed with
`--auth`) supports a **bearer token**, arbitrary **headers**, session
**cookies**, **HTTP basic**, a **form login** (reuses the session cookie it sets,
or extracts a token from the JSON response), and **OAuth2 client-credentials**.
See [`.argus-auth.example.toml`](.argus-auth.example.toml). Credentials are never
echoed into a captured proof-of-concept. (Keep `.argus-auth.toml` out of git.)

## Catch it before it commits (pre-commit hook)

The cheapest way to use Argus is on every commit — block a hardcoded secret or
an obvious vulnerable pattern *before* it ever lands in git history. Add to your
`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Sarthak-47/ARGUS
    rev: v0.2.0
    hooks:
      - id: argus            # blocks on HIGH+ findings (use `argus-strict` for MEDIUM+)
```

Then `pre-commit install`. It runs the deterministic passes only (secrets +
built-in rules) — no LLM, no network — so it's fast enough for every commit.
Standalone: `argus precommit` scans your currently-staged files.

## Desktop GUI

A React + Vite + Tauri desktop app ("a war room inside the Parthenon") with six screens —
Dashboard (with a live risk-trend graph), New Scan, Live Attack, Reports, CodeView, Settings.
Inside the native app it **invokes the Python engine directly** to run real scans; in the browser
dev build it renders a dropped-in `argus scan --format json` result at `gui/public/report.json`.

```bash
cd gui
npm install
npm run dev              # browser dev server, http://localhost:5173
npm run tauri dev        # native window (needs Rust: https://rustup.rs)
npm run tauri build      # produces a real .exe/.dmg/.AppImage in src-tauri/target/release
```

The native shell is ~9MB and starts in well under a second — a fraction of an Electron equivalent.

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
  reports (HTML/JSON/Markdown/SARIF/PDF), CycloneDX SBOM export, and OWASP ASVS / PCI-DSS tags
  per finding.
- ✅ **Phase 2 — Attack swarm** (`argus attack`): **17 agents** (13 original + MCPSecurityAgent,
  PromptInjectionAgent, BusinessLogicAgent, and the opt-in DomXSSHunter), orchestration loop,
  Docker auto-sandboxing when no `--url` is given, callback server for blind detection,
  **exploit chaining** (compounds confirmed findings into attack paths — e.g. XSS + a
  script-readable session cookie → account takeover, or clickjacking + a missing CSRF token →
  forced state change), deduplicated findings, a persistent
  attack-surface inventory that grows across runs, and a
  reproducible proof-of-concept per confirmed exploit.
- ✅ **`argus fix`**: LLM-generated patches for fixable findings — dry-run preview or `--apply`,
  with fix-and-reverify (re-scans afterward to confirm each patch actually closed the finding)
  and an AI-assistant regenerate-prompt alongside every diff.
- ✅ **Workflow**: scan history + trend (`argus history`), scan-to-scan diff (`argus compare`),
  finding lifecycle/suppression (`argus suppress`), Slack/Discord webhook notifications.
- ✅ **`argus demo`**: zero-setup showcase against a bundled vulnerable app.
- ✅ **GUI**: six screens (Dashboard with a live risk-trend graph, New Scan, Live Attack, Reports,
  CodeView, Settings) rendering real engine data, including captured PoCs.
- ✅ **Desktop shell**: Tauri 2.0 wraps the GUI as a real native app that invokes the Python engine
  directly (real scans, not just dropped-in JSON). `desktop-release.yml` builds Windows/macOS
  (universal)/Linux installers on tag; v0.1.0, v0.1.1 and v0.2.0 published. Ships with no demo
  data — every screen shows real engine output or an honest empty/first-run state.
- ✅ **CI-ready**: SARIF output, `--fail-on`, per-rule policy gating (`.argus-policy.toml`),
  GitHub Action, Docker image, green test suite (200+ tests).
- ✅ **Package verified**: `python -m build` + `twine check` pass; the built wheel installs into
  a clean venv and runs. `release.yml` publishes to PyPI on tag via trusted publishing.

*Semgrep is optional and layered in when available — it has no native Windows build, so Argus's
own rules carry the scan there (use the Docker image for full Semgrep).*

## Roadmap

Where Argus is headed next — the path from v0.2.0 to a benchmark-proven 1.0
(authenticated scanning, API-schema awareness, reachability-filtered SCA,
auto-fix PRs) is laid out in [ROADMAP.md](ROADMAP.md).

## Responsible use

Argus is an **offensive** tool. **Only run it against systems you own or are authorized to
test.** See [SECURITY.md](SECURITY.md). `argus demo` gives you a safe, bundled target to explore.

## Contributing

New attack agents, rules and payloads are very welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT © Sarthak-47 · see [LICENSE](LICENSE)
