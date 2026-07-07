# Changelog

All notable changes to Argus are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- **Dockerfile / compose IaC scanning** (`argus/scanner/iac.py`): the rule scanner is
  extension-keyed and so never looked at Dockerfiles. New file-aware linter flags running as root
  (no `USER`), unpinned/`:latest` base images, `ADD` from a URL, piping a remote download into a
  shell, and compose `privileged: true` / `network_mode: host`. Runs as part of every `argus scan`.
- **10 new secret-detection patterns** for modern token formats with distinctive prefixes
  (very low false-positive): GitHub fine-grained PAT, Google OAuth client secret, npm, PyPI,
  HashiCorp Vault, DigitalOcean, Databricks, Shopify, Telegram bot, and Square tokens.
- **10 new built-in static rules** broadening language coverage beyond the Python-heavy
  baseline: JS/TS `document.write`/open-redirect/deprecated-`createCipher`/secrets-in-`localStorage`,
  Python SSTI (`render_template_string`), Django `mark_safe`, `hashlib.new('md5')`, XXE-prone XML
  parsing, and Go `InsecureSkipVerify`/shell-via-`exec.Command`. Each verified to skip its safe
  variant (e.g. `createCipheriv`, static `document.write`, `exec.Command("ls", ...)`).
- **Docker auto-sandbox**: `argus attack <repo>` and `argus audit <repo>` now actually spin the
  target up in Docker and attack it, instead of only printing instructions to start it yourself.
  Auto-generates a Dockerfile for Django (via `manage.py`) and Node (via a `package.json` `start`
  script) when the repo doesn't ship one; uses the repo's own Dockerfile otherwise. Falls back
  to the existing `--url` flow when Docker isn't available or the stack can't be confidently
  determined. New optional `sandbox` extra (`pip install argus-sec[sandbox]`).
- `argus audit` now genuinely runs Phase 2 automatically when Docker is available, instead of
  only running Phase 1 and telling the user to run `attack --url` by hand.
- **Fix-and-reverify**: `argus fix --apply` now re-scans the patched files afterward and reports,
  per finding, whether it's actually confirmed closed or still detected — instead of a patch that
  matched content and compiled cleanly being trusted as "fixed" when the LLM's diff didn't
  actually address the vulnerable pattern.
- **AI-native remediation**: `argus fix` now also produces a ready-to-paste prompt for an AI
  coding assistant (Copilot/Cursor/Claude Code) as an alternative to applying the diff directly —
  since much of the code Argus scans was written with one of these in the first place, closing
  the loop through the same tool is often the more natural fix path than a raw patch.
- **PromptInjectionAgent** (17th agent): probes AI/chat features the scanned app itself exposes
  for prompt injection — sends a unique canary token wrapped in an instruction-override payload
  and only reports a finding if that exact token comes back verbatim, proving untrusted input
  reached the model without isolation from system instructions. Tries both POST (JSON body) and
  GET (query params) regardless of the method ReconBot/CrawlerBot recorded, since chat widgets
  are almost always driven by a JS `fetch()` POST that static HTML/form parsing can't see.
- **Scan history + risk trend graph** (UPGRADE.md #1): every scan now appends a small record to
  `~/.argus/scan_history.jsonl` (capped at 200 entries). New `argus history` CLI command renders
  it as a table or JSON. The desktop GUI's Dashboard now shows a real risk-over-time trend graph
  and a real "Recent Audits" list once at least one real scan has run, instead of always showing
  the bundled demo data.
- **Scan comparison** (UPGRADE.md #2): Argus now retains one prior full scan result
  (`~/.argus/previous_scan.json`) and can diff it against the latest by finding signature. New
  `argus compare` CLI command shows what's new/fixed/unchanged since the last scan; the desktop
  GUI's Reports screen shows the same as a "SINCE LAST SCAN" panel when available.
- New `argus status` CLI command: resolved LLM provider + model, detected GPU/VRAM and
  recommended local model, and configured scan/report defaults, as clean JSON or a table.
- **Executive-summary-first reports** (UPGRADE.md #3): HTML, PDF, and Markdown reports now lead
  with a "Top Risks" section (the top 5 CRITICAL/HIGH findings) right after the risk-score
  summary and before the full findings table, instead of the full table being the first thing a
  reader sees. Omitted entirely on a clean scan with nothing CRITICAL/HIGH.
- **Finding lifecycle + suppression** (UPGRADE.md #4): findings can now be marked
  ignored/reviewing/open, persisted per target and keyed by the same signature `argus compare`
  uses (survives line-number shifts from unrelated edits). Ignored findings no longer resurface
  on future scans or count toward risk score. New `argus suppress <search>` and `argus
  suppressions` CLI commands; the desktop GUI's Reports screen gets an IGNORE button.
- **Slack/Discord webhook notifications** (UPGRADE.md #7): `argus config --notify-webhook <url>`
  posts a scan summary (target, risk score/band, critical/high counts) to Slack or Discord when
  a scan completes — one URL, no OAuth, no ticketing system to stand up.
- **SBOM export** (UPGRADE.md #6): `argus scan/report --format sbom` produces a real CycloneDX
  1.5 JSON SBOM with correct `purl`s, built from a new full package-inventory parser
  (`argus/sbom.py`) over `package.json`/`requirements.txt`.
- **Risk-based prioritization** (UPGRADE.md #8): findings now carry a `priority_score` (confidence
  + confirmed + CVSS) used as the sort tie-break within a severity band, so a confirmed,
  high-confidence, high-CVSS finding surfaces before a merely-plausible one at the same
  severity — without ever letting a lower severity outrank a higher one.
- **CI policy-as-code gating** (UPGRADE.md #9): a `.argus-policy.toml` file (new `--policy` flag,
  or auto-detected in the target dir) lets you fail/warn/ignore per severity, category, detector,
  or confirmed status — e.g. fail on any confirmed SQLi but only warn on missing headers, finer
  than the single-threshold `--fail-on`. `argus scan` exits 2 on a policy failure. The GitHub
  Action gained a `policy` input. See `.argus-policy.example.toml`.
- **OWASP ASVS / PCI-DSS tagging** (UPGRADE.md #10): every finding with a CWE now carries the
  matching OWASP ASVS 4.0.3 control and PCI-DSS 4.0 requirement, shown in JSON/HTML/Markdown
  reports and the desktop GUI's finding detail panel. Static offline mapping, full coverage of
  the CWEs Argus emits — audit-relevant context, not a compliance-scoring product.
- **Persistent attack-surface inventory** (UPGRADE.md #11): `argus attack` now remembers the
  endpoints it discovers per target (`~/.argus/surface/`) and seeds the next run against the same
  target from that inventory, so a flaky/partial recon on one run doesn't lose surface the later
  agents need. New `argus surface` command lists it.

### Fixed
- `argus report --format pdf` now warns explicitly when `weasyprint` isn't installed and it
  falls back to HTML, instead of silently writing a different file.
- `argus scan <bad-git-url>` now prints git's actual failure reason instead of dumping the raw
  command invocation, and no longer leaks an empty temp directory on a failed clone.
- **Desktop GUI: removed hardcoded provider/GPU/scan-default data.** The Sidebar always showed a
  fixed "GROQ / llama-3.1-70b" regardless of what was actually configured; Settings showed a fixed
  "RTX 4070 · 12GB VRAM" and fake scan defaults that didn't correspond to any real setting, and its
  API key field and "TEST CONNECTION" button did nothing. All of it now reflects real state via the
  new `argus status` command (real resolved provider/model, real detected GPU via
  `argus/llm/detector.py`, real scan/report defaults) — provider selection persists through `argus
  config --provider`, and the key field actually saves via `argus config --key`. In the browser
  dev build (no desktop backend to query), these now show an explicit "demo preview" / "—"
  placeholder state instead of fabricated numbers.
- **`argus config --show` was leaking the full webhook URL unredacted.** Slack/Discord webhook
  URLs embed a bearer-equivalent token in the path — `Settings.redacted()` only masked
  `cloud.*_key` fields, so a configured notification webhook printed in full. Now masked the same
  way as an API key.
- `argus attack --url <dead-host>` now stops after ReconBot reports the target unreachable
  instead of running all 15 other agents against a host we already know is down.

## [0.1.1] — 2026-07-05

### Fixed
- macOS desktop build now produces a single universal `.dmg` covering both Intel and Apple
  Silicon, instead of an Apple-Silicon-only build.
- `desktop-release.yml` grants `contents: write` so the release workflow can actually create
  GitHub Releases (previously failed on every platform with a permissions error).
- Release notes are now real install/usage instructions instead of a placeholder string.

## [0.1.0] — 2026-07-05

Initial tagged release.

### Added
- **Phase 1 — static analysis** (`argus scan`): built-in rules, dependency/CVE audit, supply-chain
  manifest analysis (typosquat detection, unpinned versions, malicious install scripts), secret
  detection (regex + entropy + git history), optional LLM enrichment, exports to
  HTML/JSON/Markdown/SARIF/PDF.
- **Phase 2 — attack swarm** (`argus attack`): 16 agents (ReconBot, CrawlerBot, Injector,
  AuthBreaker, IDORHunter, XSSHunter, SSRFProber, HeaderPoker, CSRFHunter, FileAttacker, Fuzzer,
  RaceCondition, GraphQLAgent, WebSocketAgent, MCPSecurityAgent, BusinessLogicAgent) plus the
  opt-in browser-based DomXSSHunter, with a callback server for blind-vulnerability confirmation,
  deduplicated findings, and a reproducible proof-of-concept per confirmed exploit.
- **`argus fix`**: LLM-generated unified-diff patches for fixable findings, dry-run by default,
  `--apply` to write them, with a syntax-check safety net before writing.
- **`argus demo`**: zero-setup showcase against a bundled vulnerable app.
- **Desktop GUI**: Tauri 2.0 shell wrapping a React/Vite frontend — Dashboard, New Scan, Live
  Attack, Reports, and Settings screens — capable of invoking the real Python engine directly
  (not just rendering a dropped-in report) and showing real progress during a live audit.
- **CI/CD**: engine tests + lint, GUI build, desktop `cargo check`, Docker image build/smoke-test,
  and a cross-platform desktop-installer release workflow (Windows `.exe`/`.msi`, macOS
  universal `.dmg`, Linux `.deb`/`.rpm`/`.AppImage`).
- Local-first LLM support (Ollama) plus BYOK providers (Groq, Gemini, Claude, OpenRouter).

[Unreleased]: https://github.com/Sarthak-47/ARGUS/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/Sarthak-47/ARGUS/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Sarthak-47/ARGUS/releases/tag/v0.1.0
