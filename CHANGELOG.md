# Changelog

All notable changes to Argus are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Fixed
- `argus report --format pdf` now warns explicitly when `weasyprint` isn't installed and it
  falls back to HTML, instead of silently writing a different file.

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
