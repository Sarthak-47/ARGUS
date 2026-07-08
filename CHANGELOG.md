# Changelog

All notable changes to Argus are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- **"Scanned by Argus" badge** (ROADMAP D2): a static shields.io badge
  (`security: scanned by Argus`) other repos can drop into their own README —
  documented with copy-pasteable markdown right in ours. Honestly scoped: a
  static claim, not a live status (Argus has no hosted backend to poll), paired
  with a pointer to the Action/pre-commit hook for anyone who wants the claim
  actually enforced.

## [0.5.0] — 2026-07-08

### Added
- **Broader auto-sandbox stack detection** (ROADMAP v0.5.3): `argus attack`/`audit`
  against a bare repo (no `--url`) now recognizes Flask (via its `Flask(__name__)`
  instantiation), FastAPI (`FastAPI()` + uvicorn), and Rails (`Gemfile` + `config.ru`)
  in addition to the existing Django/Node detection — each still via an
  unambiguous, near-universal convention, never a filename guess. Node detection
  broadened too: a `build` step now runs before `start` when the repo declares one
  (fixes Next.js/Vite apps that need `next build`/`vite build` first), and a
  dev-server fallback (`next dev` / `vite --host` / `react-scripts start`) covers
  repos with only a dev script. New: **docker-compose support** — when no single
  Dockerfile matches, a `docker-compose.yml`/`compose.yaml` with an explicitly
  published port (never an unpublished/guessed one) is brought up via
  `docker compose up -d --build` and torn down with `down -v`, so multi-service
  repos (a separate frontend/backend, a DB sidecar) can run Phase 2 automatically
  too.
- **Inline PR review comments** (ROADMAP v0.5.2): the GitHub Action gained a
  `pr-comments` input (and a new `argus pr-comment` command) that posts each new
  finding as an inline review comment right on the changed line — not just
  buried in the SARIF-driven Security tab. Zero extra setup inside GitHub
  Actions (uses the job's automatic `github.token` + the standard
  `pull_request` event payload); a no-op outside a PR context, so it's safe to
  leave on unconditionally. Idempotent — each comment embeds an invisible
  fingerprint (the same signature `argus compare` uses) so re-running CI on the
  same commit never double-posts. Posts one atomic review when every finding is
  on a diff line; falls back to individual comments (skipping only the ones
  outside the diff) if not.
- **Auto-fix pull requests** (ROADMAP v0.5.1): `argus fix <path> --apply --pr`
  takes the already-validated, reverified patches one step further — commits
  them to a new `argus/auto-fix-<ts>` branch, pushes it, and opens a real
  GitHub pull request (via the `gh` CLI) with each finding's explanation in the
  description. Opt-in and gated: requires `gh auth login` or a `GH_TOKEN`/
  `GITHUB_TOKEN` env var (Argus never tries to acquire credentials itself), and
  refuses on a dirty working tree, a detached HEAD, or a repo with no `origin`
  remote, so nothing but the fix itself ends up in the branch. Verified
  end-to-end (real static scan → mocked LLM patch → apply → reverify → commit →
  push) against a throwaway local "remote" — never GitHub — plus the individual
  safety-gate refusals.
- **Container base-image CVE scanning** (ROADMAP v0.4.3): `argus scan` now extracts
  the base image(s) from a repo's Dockerfile(s) and, when Trivy is installed, scans
  them for OS-package CVEs (openssl/zlib/etc. baked into an old `python:`/`node:`
  base) — complementing the existing Dockerfile *lint* and the language dependency
  audit. Handles multi-stage builds, digest-pinned and stage-alias FROMs, and
  ignores `scratch`. Graceful like the npm/pip auditors: a skipped step with a note
  when Trivy isn't present, never an error.
- **SCA reachability analysis** (ROADMAP v0.4.2): a vulnerable dependency that
  isn't actually imported anywhere in the first-party code is now downgraded one
  severity and annotated "likely transitive/unused", so real, reachable CVEs
  surface first. Import-level pass over Python (`import`/`from`) and JS/TS
  (`import`/`require`, incl. scoped packages), with dist→import aliases for the
  common mismatches (PyYAML→yaml, beautifulsoup4→bs4, …). Reachable findings keep
  their severity and are marked as imported.

## [0.4.0] — 2026-07-08

### Changed
- **Secret-scan noise reduction** (ROADMAP v0.4.1): the high-entropy heuristic no
  longer fires in low-signal files — lockfiles (`package-lock.json`, `yarn.lock`,
  `go.sum`, …), minified bundles (`*.min.js`, `*.map`), and vendored/build output
  (`dist/`, `build/`, `vendor/`, `node_modules/`) — and skips pure-hex tokens of
  checksum length (md5/sha1/sha256/sha512). The high-confidence *pattern* pass
  still runs everywhere, so a real key in a lockfile is still caught. This removes
  the bulk of the false-positive entropy hits a real-world audit surfaced (mostly
  `package-lock.json` integrity hashes) without dropping genuine secrets.

### Added
- **Deeper MCP-security scanning** (ROADMAP v0.3.4): MCPSecurityAgent now goes
  past "is a server exposed" to inspect the exposed catalog — it flags **tool
  poisoning** (instruction-override text hidden in a tool description that can
  hijack any agent reading the catalog, CWE-94), classifies **dangerous
  capabilities** on unauthenticated tools (shell/exec, arbitrary file access,
  outbound-network/SSRF, database, code-eval — CWE-306), and enumerates
  **resources/ and prompts/** catalogs (disclosure of filesystem roots / prompt
  templates). Verified against a mock MCP server: a poisoned, shell-capable tool
  and exposed resources/prompts are flagged, while a benign server only trips the
  disclosure finding.
- **BOLA/BFLA authorization testing** (ROADMAP v0.3.3): a new **AuthzTester** agent
  (18th) tests broken object- and function-level authorization — the #1 API risk —
  using a second identity supplied with `--auth-b <file>`. It compares three actors
  per endpoint (anonymous, identity A, identity B) and flags only the
  "protected-from-anonymous yet reachable-cross-user" pattern: an object a second
  authenticated user can read (BOLA, CWE-639), or a privileged route an ordinary
  user can reach (BFLA, CWE-285). Verified against both a vulnerable and a
  correctly-authorized app — zero findings on the latter (low false-positive).
- **API schema ingestion** (ROADMAP v0.3.2): `argus attack`/`audit --api-spec
  <file|url>` seeds the attack surface straight from an **OpenAPI 3.x**, **Swagger
  2.0**, **Postman v2** collection, or **GraphQL introspection** dump — so the
  swarm tests spec-declared endpoints a link-following crawler would never reach.
  Paths (and any basePath the spec declares) are resolved against the target's
  URL, so a production spec still points at localhost/staging. Verified
  end-to-end: the swarm attacks a spec-only endpoint with no inbound links.

## [0.3.0] — 2026-07-08

### Added
- **Authenticated attack sessions** (ROADMAP v0.3.1): `argus attack`/`audit --auth
  .argus-auth.toml` (auto-discovered in the working dir) give the whole 17-agent
  swarm — and ReconBot's crawl — a real logged-in session, so Argus can finally
  attack the surface behind a login instead of only the unauthenticated doormat.
  Supports a bearer token, arbitrary headers, session cookies, HTTP basic, a form
  login (reuses the session cookie it sets or extracts a token from the JSON
  response), and OAuth2 client-credentials. Because every agent shares one httpx
  client, auth is applied once and inherited everywhere; credentials are never
  echoed into a captured PoC. See `.argus-auth.example.toml`.
- **`pre-commit` hook** (ROADMAP D1): a new `argus precommit` command plus a
  `.pre-commit-hooks.yaml` (`id: argus`, and `argus-strict` for MEDIUM+) so any
  repo can gate commits on secrets and vulnerable code patterns in three lines.
  Scans only the staged files with the fast deterministic passes (secrets +
  built-in rules — no LLM, no network), reusing the exact per-file scanners the
  full `argus scan` uses, and blocks the commit (exit 1) on any finding at/above
  `--fail-on` (default HIGH). Shift-left: catch a leaked key before it lands in
  history, where it's far cheaper to fix.

## [0.2.0] — 2026-07-08

### Added
- **Baseline adoption** (`argus scan --write-baseline <file>` / `--baseline <file>`): the standard
  way to turn a scanner on a mature repo without drowning. `--write-baseline` snapshots every
  finding that exists today as accepted; a later `--baseline` scan reports (and gates on) only what's
  genuinely new. Keyed by the same category+location+normalized-title signature `argus compare`
  uses, so a finding that merely shifts line numbers stays baselined. Complements `--diff-base`
  (git-changed files, per-PR) — baseline is finding-identity-based, per-adoption, and needs no git.
  Composes with `--fail-on`/`--policy`: pre-existing criticals don't fail the build, a brand-new one
  does.
- **Exploit chaining** (`argus/chains.py`): after the attack swarm runs, Argus deterministically
  detects when confirmed findings *compound* into an attack path and emits a synthesized CRITICAL
  "attack chain" finding — e.g. a confirmed XSS + a session cookie missing HttpOnly is flagged as
  account takeover, not two isolated medium issues. Ships five chains (XSS→session-theft,
  auth-bypass→IDOR, upload+traversal→arbitrary-write, clickjacking+missing-CSRF→forced-action,
  exposed-MCP+leaked-secret); each only fires from findings an agent actually confirmed, so a chain
  is never speculative. The desktop GUI's Reports screen now badges these findings distinctly — a
  ⛓ marker in the list and an "ATTACK CHAIN — COMPOUNDS N CONFIRMED FINDINGS" banner in the detail
  panel — so a compound attack path reads as more than just another CRITICAL row.
- **Diff-aware scanning** (`argus scan --diff-base <ref>`): the PR-gate model — only report
  findings in files changed vs a base ref (committed, staged, and untracked), so a pre-existing
  backlog doesn't drown out or fail CI on what the current change actually introduced. Composes
  with `--fail-on`/`--policy`; the GitHub Action gained a `diff-base` input.
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

### Changed
- **Desktop GUI ships with zero fabricated data.** Removed the bundled demo findings, the fake
  "Recent Audits"/stats on the Dashboard, and the scripted Live-Attack timeline. Every screen now
  shows real engine data or an honest empty/first-run state (Reports: "no report yet"; Dashboard:
  real stats derived from scan history; Live Attack: real running clock during an audit, idle
  prompt otherwise). No `report.json` is bundled, so a fresh install starts clean. The `argus demo`
  CLI showcase (bundled vulnerable app) is unchanged.

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

[Unreleased]: https://github.com/Sarthak-47/ARGUS/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/Sarthak-47/ARGUS/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Sarthak-47/ARGUS/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Sarthak-47/ARGUS/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Sarthak-47/ARGUS/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Sarthak-47/ARGUS/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Sarthak-47/ARGUS/releases/tag/v0.1.0
