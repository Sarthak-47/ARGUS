<div align="center">

# ◈ ARGUS

**The security tool built for the vibe coding era.**

*Point it at a repo. It reads the code, spins up the app, and attacks it.*

</div>

---

Argus is an AI-powered security audit agent for developers. Named after **Argus Panoptes** —
the hundred-eyed giant of Greek mythology who never slept and saw everything.

It runs in two phases:

| Phase | What it does |
|---|---|
| **Phase 1 — Static Analysis** | Reads and understands the codebase without running it: custom rules, dependency CVEs, secret detection (regex + entropy + git history), then an LLM reasoning layer that validates and explains every finding in plain English. |
| **Phase 2 — Attack Agent** | Spins the app up in an isolated sandbox and actively attacks it with a swarm of 13 specialised agents (SQLi, auth bypass, IDOR, SSRF, XSS, and more). |

Argus works on **any machine**: use a **local model** (Ollama, privacy-first) or **bring your own
key** for Groq / Gemini / Claude / OpenRouter. With no LLM configured it still runs the full
deterministic scan.

## Install (development)

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -e .
```

## Usage

```bash
argus setup                               # first-time setup wizard
argus scan <repo-url|path>                # Phase 1 — static analysis
argus scan <repo-url> --deep              # + full LLM free-form review
argus attack --url http://localhost:3000  # Phase 2 — attack a running app
argus audit <repo-url>                    # Phase 1 + Phase 2 full pipeline
argus report --format html                # export the last scan
argus config --show                       # show current configuration
```

## Status

Active development, built in phase order (see [`ARGUS_CONTEXT.md`](ARGUS_CONTEXT.md)).

- ✅ **Phase 0 — Foundation:** Typer CLI, Rich output, TOML config, repo ingestion, GPU/VRAM
  detection, unified LLM provider (Ollama/Groq/Gemini/Claude/OpenRouter, BYOK).
- ✅ **Phase 1 — Static analysis:** built-in code rules, dependency audit (npm/pip), secret
  detection (regex + Shannon entropy + git history), LLM reasoning layer, HTML/JSON/Markdown
  reports. `argus scan` works end-to-end. *(Semgrep optional — it has no native Windows build.)*
- 🚧 **Phase 2 — Attack agents (9 of 13):** ReconBot, CrawlerBot, Injector (SQLi:
  error/time/boolean), AuthBreaker (JWT cracking, alg:none, cookie flags), XSSHunter
  (reflected), SSRFProber (blind via callback server + cloud metadata), HeaderPoker (CORS /
  header bypass), CSRFHunter (clickjacking + form tokens), and GraphQLAgent (introspection) —
  driven by an orchestration loop with an out-of-band callback server. `argus attack --url
  <running-app>` works end-to-end. Remaining agents (IDOR, Fuzzer, FileAttacker, RaceCondition,
  WebSocket) and the Docker auto-sandbox are in progress.
- 🚧 **GUI:** React + Vite + TypeScript desktop UI — all five screens (Dashboard, New Scan,
  Live Attack, Reports, Settings) ported from the design with the live-attack animation. The
  Reports screen renders **real engine output**: drop an `argus scan --format json` result at
  `gui/public/report.json` and it shows actual findings/risk (falls back to demo data). The
  Tauri shell for native packaging is the remaining step.

Test suite: 40 unit tests (`pytest`).

## GUI (development)

```bash
cd gui
npm install
npm run dev        # http://localhost:5173
npm run build      # type-check + production build
```

## License

MIT © Sarthak-47
