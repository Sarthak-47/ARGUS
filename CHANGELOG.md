# Changelog

All notable changes to Argus are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
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

### Fixed
- `argus report --format pdf` now warns explicitly when `weasyprint` isn't installed and it
  falls back to HTML, instead of silently writing a different file.
- `argus scan <bad-git-url>` now prints git's actual failure reason instead of dumping the raw
  command invocation, and no longer leaks an empty temp directory on a failed clone.
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
