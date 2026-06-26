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

Early development. See [`ARGUS_CONTEXT.md`](ARGUS_CONTEXT.md) for the full architecture and
roadmap. Built in phase order: Phase 0 (foundation) → Phase 1 (static analysis) →
Phase 2 (attack agents) → GUI.

## License

MIT © Sarthak-47
