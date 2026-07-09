# Getting Started

## Install

```bash
pip install argus-panoptes          # or: pipx install argus-panoptes
```

Everything is self-contained — no account, no hosted service, no signup.

## See it work in 30 seconds

```bash
argus demo
```

Scans and attacks a bundled, intentionally-vulnerable app. Nothing external is
touched. This is the fastest way to see the full Phase 1 → Phase 2 flow and
confirm your install works.

## First-time setup (optional but recommended)

```bash
argus setup
```

Detects your GPU/VRAM and helps you pick an LLM: a local model via
[Ollama](https://ollama.com) (private, offline, free) or a hosted key (Groq,
Gemini, Claude, OpenRouter). **Argus works without this** — every deterministic
pass (rules, dependency audit, secret detection) runs with `--no-llm` and needs
no provider at all. The LLM layer adds explanation, false-positive filtering,
and `argus fix`.

## Your first real scan

```bash
argus scan /path/to/your/repo
# or a remote repo:
argus scan https://github.com/you/your-repo
```

This is Phase 1 — static analysis. It reads the code without running it:
built-in rules, `npm audit`/`pip-audit`, secret detection (regex + entropy +
git history), supply-chain manifest checks, and (unless `--no-llm`) an LLM pass
that validates and explains each finding for your specific code. Output is a
risk score, a severity breakdown, and a findings table in your terminal.

Useful flags:
```bash
argus scan <path> --deep            # + full LLM free-form review of high-risk files
argus scan <path> --no-llm          # deterministic only, no LLM cost/latency
argus scan <path> --format sarif    # also export a report (html|json|markdown|sarif|sbom|jira|pdf)
argus scan <path> --fail-on high    # exit non-zero for CI — see docs/ci-integration.md
```

## Your first attack

Phase 2 actively exploits a **running** app — it needs something to attack.

```bash
argus attack --url http://localhost:3000
```

This points the 18-agent swarm (SQLi, XSS, SSRF, auth bypass, IDOR, CSRF, and
more) at the URL and reports only **confirmed** exploits — each with a runnable
proof-of-concept (a `curl` command plus the real request/response), not just a
pattern match.

No app running yet? If you have Docker, point Argus at the repo directly and
it'll try to spin the app up itself:

```bash
argus attack /path/to/repo     # or: argus audit <repo>  (Phase 1 + Phase 2)
```

This only works for stacks Argus can confidently recognize (Django, Flask,
FastAPI, Rails, Node/Express/Next/Vite, or a `docker-compose.yml` with a
published port) — otherwise it tells you to start the app yourself and use
`--url`.

## What's next

- **Behind a login?** See [Authenticated Scanning](authenticated-scanning.md).
- **Wiring this into CI?** See [CI Integration](ci-integration.md).
- **Something not working?** See [Troubleshooting](troubleshooting.md).
- **Turning Argus on an existing repo with a backlog?** `argus scan
  --write-baseline .argus-baseline.json` once, then scan with `--baseline
  .argus-baseline.json` going forward — only genuinely new findings are
  reported.
- **Want it in your editor?** `pip install 'argus-panoptes[mcp]'` then `argus
  mcp-server` — see the main README's "Run it from your editor" section.
