# ARGUS — Full Project Context for Claude Code

> This file is the single source of truth for building Argus.
> Read every section before writing any code.
> Do not deviate from the architecture, stack, design system, or naming conventions defined here.

---

## 1. WHAT ARGUS IS

Argus is an AI-powered security audit agent for developers. Named after Argus Panoptes — the hundred-eyed giant of Greek mythology who never slept and saw everything.

**Tagline:** *Point it at a repo. It reads the code, spins up the app, and attacks it.*

**The problem it solves:** Vibe coding is exploding. Developers ship AI-generated code they don't fully understand. That code has predictable, repeatable vulnerability patterns. Existing tools (Snyk, SonarQube, Semgrep, Burp Suite) are either too expensive, too noisy, require security expertise, or only do static analysis — none actively attack the running app and none explain findings in plain English tailored to that specific codebase.

**Two delivery surfaces:**
- `argus` — CLI tool (Python, installable via pipx)
- Argus Desktop — Tauri + React GUI wrapping the same engine

---

## 2. TARGET AUDIENCE

- Solo devs shipping side projects fast
- Vibe coders using Cursor, Bolt, v0, Lovable who want a safety check before going live
- Early stage startups before first security audit
- Open source maintainers who accept PRs from strangers
- Junior developers without security expertise
- CTF players and junior security researchers

---

## 3. CORE ARCHITECTURE — TWO PHASES

```
Phase 1 — Static Analysis    → reads and understands the codebase without running it
Phase 2 — Attack Agent       → spins up the app in Docker, actively attacks it
```

Both phases are powered by an LLM reasoning layer on top of deterministic tooling.

### CLI Commands

```bash
argus setup                              # first time setup wizard
argus scan <repo-url>                    # phase 1 only
argus scan <repo-url> --deep             # phase 1 with full LLM free-form review
argus scan /local/path                   # local repo
argus attack <repo-url>                  # phase 2 only
argus attack --url http://localhost:3000 # against already-running app
argus attack --url https://staging.app  # against live staging
argus audit <repo-url>                   # phase 1 + phase 2 full pipeline
argus audit <repo-url> --fix             # suggest fixes after
argus attack <repo-url> --agents injector,authbreaker  # specific agents only
argus report --format html               # export last scan
argus report --format json
argus report --format pdf
argus report --format markdown
argus config --provider groq --key YOUR_KEY
argus config --provider local
argus config --show
```

---

## 4. LLM STRATEGY — WORKS FOR EVERYONE

This is the key architectural decision. Argus must work on any machine regardless of hardware.

### Local GPU Path (privacy-first users)

Argus detects GPU automatically on `argus setup` and recommends the best model fitting available VRAM:

```python
VRAM_MODEL_MAP = {
    4:  "qwen2.5-coder:3b",      # 4GB VRAM
    6:  "qwen2.5-coder:7b",      # 6GB VRAM
    8:  "llama3.1:8b",           # 8GB VRAM
    12: "qwen2.5-coder:14b",     # 12GB VRAM (RTX 4070 tier)
    16: "qwen2.5:32b-q4_K_M",   # 16GB VRAM
    24: "llama3.3:70b-q4_K_M",  # 24GB VRAM
    40: "llama3.1:70b",          # 40GB+ VRAM
}
```

Detection order: nvidia-smi → ROCm → Apple Silicon (uses unified RAM × 0.75)
Backend: Ollama

### Cloud Path (everyone else — BYOK)

Supported providers (user brings their own key):
- **Groq** — free tier, fast, Llama 3.1 70B (recommended default for cloud)
- **Gemini 1.5 Flash** — free tier, 1M context window (best for large repos)
- **Claude API** — best reasoning quality
- **OpenRouter** — single key, routes to cheapest available

### Provider Priority Chain

```
user_preferred → local_gpu (if configured + model fits) →
groq (if key set) → gemini (if key set) →
claude (if key set) → openrouter (if key set) →
raw_scan_only (no LLM, just deterministic findings)
```

Raw scan without LLM is still valuable — full Semgrep + dependency audit + secret detection runs regardless.

### Config File

Location: `~/.argus/config.toml`

```toml
[provider]
preferred = "local"          # local | groq | gemini | claude | openrouter

[local]
model = "qwen2.5-coder:14b"
backend = "ollama"

[cloud]
groq_key = ""
gemini_key = ""
claude_key = ""
openrouter_key = ""

[scan]
auto_attack = false
sandbox = "docker"
default_depth = "standard"   # quick | standard | deep

[report]
output_dir = "./argus-report"
default_format = "html"
```

---

## 5. PHASE 1 — STATIC ANALYSIS ENGINE

### Step 1 — Ingestion

Clone repo to isolated temp directory. Build codebase map:
- Language and framework detection (reads package.json, requirements.txt, go.mod, Gemfile, pom.xml, build.gradle)
- Entry points — routes, controllers, main files
- Auth layer location — where authentication and authorization live
- Database layer — ORM usage, raw queries, connection handling
- External calls — third party APIs, webhooks, fetch/request calls
- Config files — .env, docker-compose.yml, nginx.conf, k8s manifests, .github/workflows
- Dependencies — all package manifests
- Frontend vs backend separation
- Admin vs public surface area

### Step 2 — Rule-Based Scan (Semgrep)

Runs Semgrep with custom Argus ruleset layered on community rules. Zero LLM cost, fully offline, deterministic.

Custom rules cover:
- All injection patterns (SQL, NoSQL, command, SSTI, LDAP, XPath, CRLF, XXE, SMTP, CSV formula)
- Auth antipatterns (hardcoded secrets, JWT misuse, session misconfig, weak crypto)
- Dangerous function usage per language (eval, exec, system, subprocess, etc.)
- Framework-specific sinks (dangerouslySetInnerHTML, v-html, bypassSecurityTrust)
- Missing security controls (no rate limiting middleware, no CSRF protection, no input validation)
- Insecure defaults (debug=True, CORS wildcard, permissive file upload)

### Step 3 — Dependency Audit

Per-language wrappers:
- Node: `npm audit` + `retire.js`
- Python: `pip-audit` + `safety`
- Ruby: `bundler-audit`
- Go: `govulncheck`
- Java: `gradle-audit` / `mvn dependency-check`

Map CVEs to actual usage in codebase — don't just report "lodash has a vuln", report exactly where the vulnerable function is called.

### Step 4 — Secret Detection

- All major API key format regexes (AWS AKIA, GCP service accounts, Stripe sk_live_, Twilio, SendGrid, GitHub ghp_/gho_, Slack xoxb-, etc.)
- Private key formats (RSA, EC, PGP, SSH)
- JWT secrets hardcoded
- Database connection strings with embedded credentials
- Passwords in config files and code comments
- Shannon entropy analysis on strings > 20 chars (catches unknown key formats)
- Git history scan — `git log -p` to find secrets deleted in later commits but still in history
- Docker and CI config secret leaks
- Secrets in client-side JS bundles (webpack, vite output)

### Step 5 — LLM Reasoning Layer

Takes raw Semgrep findings + dependency audit + secret scan + codebase map. Sends to LLM with structured prompts.

LLM does three jobs:

**Job 1 — Validate and enrich findings**
- Confirm real vulnerability vs false positive
- Explain in plain English in context of THIS specific codebase
- Rate severity with justification (not just pattern-matched severity)
- Show exact exploit scenario
- Provide concrete fix with code diff

**Job 2 — Free-form review of high-risk files**
Auth middleware, payment handlers, admin routes, file upload handlers — LLM reads in full looking for logic flaws:
- Broken access control logic
- Race conditions in business logic
- Auth bypass through parameter manipulation
- Missing ownership checks
- Insecure design patterns

**Job 3 — Business logic analysis**
- Negative price/quantity abuse paths
- Coupon/discount stacking
- Workflow step bypass
- Free trial abuse patterns
- Frontend-only validation
- Price rounding exploitation
- Referral system self-abuse

### Step 6 — Phase 1 Output

Terminal (Rich):
```
ARGUS STATIC SCAN — github.com/user/myapp
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Risk Score: 74/100  [HIGH]

CRITICAL   2   Hardcoded JWT secret, SQLi in /api/users
HIGH       5   Missing auth on 3 admin routes, XSS in search
MEDIUM     8   Outdated deps with CVEs, weak session config
LOW       12   Missing security headers, verbose errors
INFO       6   Dependency suggestions, code quality notes

Run `argus attack` to actively exploit these findings.
Full report → ./argus-report/index.html
```

---

## 6. PHASE 2 — ATTACK AGENT

### Setup

Detect stack from repo. Spin up in isolated Docker network. If no Dockerfile/docker-compose exists, generate one. User can also point at already-running app.

### ReconBot (runs first, before any attacks)

Intelligence gathering pass:
- Read ALL config files across repo
- Scan git log for accidentally committed secrets
- Map every environment variable referenced anywhere
- Identify all third-party services integrated
- Detect deployment target (Vercel, Railway, Heroku, AWS, GCP, Azure)
- Find all commented-out code (often contains debug backdoors, old credentials, bypass flags)
- Detect debug flags, feature flags, admin bypasses left in code
- Check test files for credentials that might exist in production
- Fingerprint exact stack from response headers and config
- Map complete attack surface — every endpoint, every parameter, every input vector
- Identify admin vs public endpoints
- Find GraphQL, WebSocket, gRPC if present
- Crawl all routes (reads route files + actual HTTP crawl)

### LLM Orchestrator

Reads Phase 1 findings + ReconBot intelligence. Decides:
- Which agents to deploy
- Priority order (Phase 1 found JWT issues → AuthBreaker goes first)
- Which endpoints to focus on
- How deep to go per attack class
- When to pivot based on what agents find
- When attack surface is exhausted

Runs in a continuous loop — agents report findings back in structured format, orchestrator reasons over results, directs follow-up attacks on confirmed vulnerabilities, adapts strategy in real time.

### The 13 Attack Agents

---

#### Agent 1 — Injector

**SQL Injection**
- Classic, blind boolean, time-based blind (SLEEP/pg_sleep), error-based, union-based, out-of-band (DNS exfil), second-order (stored, fires later), ORM misuse

**NoSQL Injection**
- MongoDB operator injection ($gt, $where, $regex, $ne)
- Redis command injection
- CouchDB injection
- Elasticsearch injection
- Firebase rules bypass

**Command Injection**
- Direct shell (os.system, subprocess, exec, shell_exec, system())
- Blind time-based (sleep payloads)
- Blind DNS-based (callback server)
- Argument injection (injecting flags)

**Template Injection (SSTI)**
- Jinja2, Twig, Freemarker, Pebble, Velocity, Handlebars, ERB, Smarty

**LDAP Injection**
- Auth bypass, information disclosure, blind LDAP

**XPath Injection**
- Auth bypass, data extraction

**Header Injection**
- HTTP response splitting, CRLF injection, log injection

**XML Injection / XXE**
- XXE, billion laughs DoS, blind XXE out-of-band, XXE via file upload (SVG, DOCX, XLSX, PDF)

**Email / SMTP Injection**
- Header injection via contact forms

**Formula Injection**
- CSV export injection (=cmd|' /C calc'!A0 variants)

**GraphQL Injection**
- Deeply nested query DoS, alias-based auth bypass, batching abuse

---

#### Agent 2 — AuthBreaker

**Password Attacks**
- Bruteforce with no lockout detection
- Credential stuffing (top 10k common passwords)
- Default credentials (500 most common combos)
- Password spraying
- Username enumeration via timing and response differences

**JWT Attacks**
- Algorithm confusion (RS256 → HS256)
- None algorithm bypass (alg: none)
- Weak secret bruteforce (rockyou top 10k)
- Key confusion (public key used as HMAC secret)
- Kid parameter injection (SQLi and path traversal in kid field)
- JKU/X5U header injection (point to attacker-controlled JWKS)
- JWT expiry not validated
- JWT not validated at all

**Session Attacks**
- Session fixation
- Predictable session token entropy analysis
- Session not invalidated on logout
- Session not invalidated on password change
- Cookie flag analysis (Secure, HttpOnly, SameSite)
- Cookie scope too broad (domain=.example.com)
- Concurrent session abuse

**MFA Bypass**
- OTP bruteforce (no rate limit)
- OTP reuse (used OTP still valid)
- Response manipulation (mfa_required: true → false)
- MFA not enforced on all paths

**OAuth / SSO**
- Redirect URI manipulation
- State parameter CSRF bypass
- Authorization code interception
- Token leakage in referrer/logs
- PKCE bypass
- Open redirect chained with OAuth
- Account linking abuse (pre-account takeover)

**Password Reset**
- Predictable reset tokens
- Long-lived tokens (never expire)
- Token not invalidated after use
- Token in URL (leaks in logs/referrer)
- Host header injection → reset link to attacker domain

**Account Takeover Chains**
- XSS → session hijack
- CSRF → email change
- Open redirect → OAuth token steal

---

#### Agent 3 — IDORHunter

- Creates two test accounts (User A, User B)
- User A accesses their own resources, captures all IDs
- Attempts every resource as User B
- Sequential integer ID enumeration
- UUID prediction
- Base64 encoded ID manipulation (decode → change → re-encode)
- Weak hash-based ID cracking
- Parameter pollution (?userId=A&userId=B)
- Mass assignment (send isAdmin: true, role: admin in request body)
- Horizontal privilege escalation (same role, different user's data)
- Vertical privilege escalation (regular user accessing admin resources)
- HTTP method switching on restricted endpoints
- API version bypass (/api/v2/admin less protected than /api/v1/admin)

---

#### Agent 4 — CrawlerBot

- Wordlist-based path fuzzing (SecLists subset bundled)
- Parameter discovery on all known endpoints
- HTTP method fuzzing (GET endpoint accepting POST/PUT/DELETE/PATCH?)
- API versioning discovery (/v1/ → /v2/ → /v0/ → /v-beta/)
- Backup file discovery (.bak, .old, ~, .swp, .orig)
- Git exposure (/.git/config, /.git/HEAD, /.git/COMMIT_EDITMSG)
- Common admin panels (/admin, /dashboard, /phpmyadmin, /wp-admin, /jenkins)
- Debug endpoints (/debug, /metrics, /actuator, /health with full info)
- GraphQL introspection if GraphQL detected
- Swagger/OpenAPI endpoint leakage
- Robots.txt and sitemap analysis
- Source map files (.js.map — can expose original source)
- Common sensitive files (.env, config.json, secrets.json, database.yml)

---

#### Agent 5 — Fuzzer

- Oversized inputs (buffer overflow attempts)
- Unicode edge cases (null bytes, RTL override, zero-width characters)
- Format string payloads (%s %p %x %n)
- Negative numbers where positive expected
- Type confusion (string where int expected, array where string)
- Missing required fields (one at a time, all at once)
- Extra unexpected fields
- Duplicate parameters
- Boundary values (0, -1, MAX_INT, MAX_INT+1)
- HTTP request smuggling (CL.TE and TE.CL variants)
- ReDoS (catastrophic backtracking regex payloads)
- JSON deeply nested objects
- XML billion laughs variants
- Large file upload (no size limit detection)

---

#### Agent 6 — HeaderPoker

- X-Forwarded-For: 127.0.0.1 (bypass IP restrictions)
- X-Real-IP: 127.0.0.1
- X-Original-URL: /admin (URL override attacks)
- X-HTTP-Method-Override: DELETE
- Host: evil.com (host header injection)
- Origin: null (CORS null origin)
- Origin: https://evil.com (CORS misconfiguration)
- Origin: https://trusted.evil.com (subdomain CORS bypass)
- Referer manipulation
- Content-Type confusion
- Cache poisoning via unkeyed headers
- HTTP/2 header injection
- Hop-by-hop header abuse

---

#### Agent 7 — FileAttacker

**Upload**
- No file type validation (upload .php, .py, .sh, .jsp)
- Extension-only validation bypass (shell.php.jpg)
- MIME-only validation bypass (polyglot files — valid image + valid PHP)
- Null byte injection (shell.php%00.jpg)
- Double extension (shell.php.jpg)
- Path traversal in filename (../../../etc/cron.d/shell)
- Zip slip (malicious zip with path traversal entries)
- Malicious SVG with embedded XSS
- Malicious XML with XXE payload
- ImageMagick shell injection via malicious image
- Oversized file upload (no limit DoS)

**Download**
- Path traversal in download endpoint
- Direct object reference to private files
- No authentication on file download endpoints
- Sensitive files in webroot

---

#### Agent 8 — RaceCondition

- Double spend on payment and credits endpoints
- Account creation race (two accounts with same email)
- Inventory overselling (buy more than available stock)
- Coupon/voucher reuse via parallel requests
- Like/vote count manipulation
- Rate limit bypass via parallel requests (200 concurrent login attempts)
- TOCTOU on file write operations
- Uses asyncio + httpx, fires 50-500 concurrent requests

---

#### Agent 9 — SSRFProber

- Basic SSRF to internal services (localhost:6379 Redis, localhost:5432 Postgres)
- Cloud metadata: 169.254.169.254 (AWS), 100.100.100.200 (Alibaba), metadata.google.internal (GCP)
- Blind SSRF via DNS callback (uses callback server)
- SSRF filter bypass (open redirects, DNS rebinding, IPv6, decimal IP, URL encoding)
- SSRF via PDF generators
- SSRF via webhook endpoints
- SSRF via image URL fetching
- SSRF via file import (CSV, XML, JSON)
- SSRF via SVG processing

---

#### Agent 10 — XSSHunter

- Reflected XSS (GET params, POST body, headers)
- Stored XSS (comments, profiles, filenames, markdown editors, JSON stored and reflected)
- DOM XSS (innerHTML, document.write, eval, location.hash, postMessage without origin check)
- XSS filter bypasses (case variation, tag breaking, event handlers, javascript: protocol, data URIs, encoded payloads)
- Blind XSS (payloads that fire in admin panels — uses callback server)
- XSS in SVG uploads
- XSS in filename displayed in UI
- Polyglot XSS payloads
- XSS → full exploitation chains (cookie stealing, session hijack, keylogging)

---

#### Agent 11 — WebSocketAgent

- No auth on WebSocket upgrade request
- CSRF on WebSocket (no Origin header check)
- Message injection
- No rate limiting on WebSocket messages
- Replay attacks on WebSocket messages
- Malformed message handling

---

#### Agent 12 — GraphQLAgent

- Introspection enabled in production (full schema leak)
- No query depth limit (deeply nested DoS)
- No query complexity limit
- Batching attack (1000 login attempts in one request body)
- Field suggestion enumeration (leaks schema even without introspection)
- Mutation rate limiting missing
- Authorization missing on mutations
- Subscription abuse

---

#### Agent 13 — CSRFHunter

- Missing CSRF token
- CSRF token not validated server-side
- CSRF token tied to session but not to request
- CSRF token in URL (leaked in referrer)
- SameSite cookie misconfiguration
- CORS misconfiguration enabling CSRF
- Clickjacking (missing X-Frame-Options / CSP frame-ancestors)
- JSON CSRF (endpoints accepting text/plain)

---

### Complete Vulnerability Coverage Matrix

Every vulnerability class Argus covers:

| Category | Detection Method |
|---|---|
| All injection types (SQL, NoSQL, Command, SSTI, LDAP, XPath, CRLF, XXE, SMTP, CSV, GraphQL) | Semgrep rules + Injector agent payloads |
| Authentication & Session (all JWT attacks, session, MFA bypass, OAuth, password reset) | Static pattern + AuthBreaker agent |
| Access Control, IDOR, privilege escalation | IDORHunter agent + LLM code review |
| XSS (reflected, stored, DOM, blind, filter bypass) | Semgrep rules + XSSHunter agent |
| SSRF (all variants, cloud metadata, blind) | Semgrep rules + SSRFProber agent |
| CSRF, clickjacking | Static check + CSRFHunter agent |
| Security misconfiguration (headers, CORS, TLS, error handling, debug mode) | Static check + HTTP probe |
| Cryptographic failures (weak hashing, encryption, randomness, sensitive data exposure) | Semgrep rules + static analysis |
| Business logic flaws | LLM reasoning only (cannot be pattern-matched) |
| DoS (rate limiting, ReDoS, GraphQL complexity, zip bomb, file size) | Fuzzer agent + static rules |
| File handling (upload bypass, zip slip, path traversal in download) | FileAttacker agent |
| API specific (REST mass assignment, GraphQL all attacks, WebSocket, gRPC) | Dedicated agents |
| Dependency CVEs | pip-audit, npm audit, govulncheck, bundler-audit |
| Secret detection (all formats, git history, entropy analysis) | Secret scanner module |
| Infrastructure (exposed ports, admin panels, debug endpoints, K8s misconfig) | CrawlerBot + static config analysis |
| Client-side (localStorage, API keys in JS bundle, prototype pollution, DOM sinks) | Semgrep rules + static analysis |

---

## 7. REPORTING

Every audit generates:

**Terminal output (Rich):**
- Color-coded severity table
- Risk score 0-100
- Per-finding: what, where, severity, quick fix

**HTML Report:**
- Executive summary with risk gauge
- Full vulnerability table sortable by severity
- Per-vuln detail: explanation, exploit scenario, HTTP evidence, reproduction steps, code diff fix
- Dependency audit section
- Attack log (every payload sent, what worked)
- Argus branding with Greek key borders

**JSON Report:**
- Machine-readable, CI/CD integration ready
- Full finding objects with all metadata

**PDF Report:**
- Shareable, professional
- Same content as HTML

**Markdown Report:**
- For GitHub issues, PRs, documentation

---

## 8. TECH STACK — CLI

| Layer | Technology | Reason |
|---|---|---|
| CLI framework | Python + Typer | Best CLI DX, rich help text |
| Terminal UI | Rich | Beautiful output, progress bars, color tables |
| Static analysis | Semgrep + custom rules | Industry standard, extensible |
| AST parsing | tree-sitter | Language-agnostic, fast, accurate |
| HTTP client | httpx + asyncio | Async, fast, HTTP/2, concurrent requests |
| Attack orchestration | Custom agent loop | LangGraph if complexity grows |
| LLM local | Ollama | Easiest local model management |
| LLM cloud | Anthropic / Groq / Gemini SDK | BYOK unified interface |
| Sandboxing | Docker SDK for Python | Isolate target app completely |
| Dependency audit | pip-audit, npm audit, govulncheck | Per-language subprocess wrappers |
| Payload lists | SecLists subset bundled | Industry standard wordlists |
| Callback server | Lightweight Python HTTP server | Blind XSS, blind SSRF, blind SQLi |
| Report generation | Jinja2 + HTML templates | Clean exportable reports |
| Config | TOML + platformdirs | Cross-platform config paths |
| Packaging | PyPI + pipx | pipx install argus-sec |
| Git analysis | GitPython | Repo history scanning |
| Entropy analysis | Custom Shannon implementation | Secret detection |
| GPU detection | subprocess (nvidia-smi, rocm-smi) + psutil | VRAM measurement |

---

## 9. TECH STACK — DESKTOP GUI

| Layer | Technology | Reason |
|---|---|---|
| Desktop framework | Tauri 2.0 | Lightweight native, same stack as Mimir |
| Frontend | React 18 + TypeScript | Component model, type safety |
| Styling | Tailwind CSS | Utility-first, fast iteration |
| Charts | Recharts | Risk gauge, severity breakdown |
| State management | Zustand | Lightweight, no Redux overhead |
| IPC | Tauri commands | Frontend calls Python CLI engine |
| Build | Vite | Fast HMR, modern bundler |
| Distribution | GitHub Actions | Auto-build .exe/.dmg/.AppImage on tag |

The GUI calls the CLI engine via Tauri commands / sidecar. The Python engine is bundled inside the Tauri app. GUI is a display layer — all intelligence lives in the Python core.

---

## 10. PROJECT STRUCTURE

```
argus/
├── ARGUS_CONTEXT.md              ← this file
├── pyproject.toml                ← Python package config
├── README.md
├── .github/
│   └── workflows/
│       ├── ci.yml                ← test + lint on PR
│       └── release.yml           ← build binaries on tag
│
├── argus/                        ← Python package (CLI + engine)
│   ├── __init__.py
│   ├── cli/
│   │   ├── __init__.py
│   │   ├── main.py               ← Typer app, all commands
│   │   └── output.py             ← Rich formatting, progress, tables
│   │
│   ├── scanner/                  ← Phase 1
│   │   ├── __init__.py
│   │   ├── ingestion.py          ← clone repo, build codebase map
│   │   ├── semgrep_runner.py     ← run semgrep, parse results
│   │   ├── dependencies.py       ← npm audit, pip-audit wrappers
│   │   ├── secrets.py            ← entropy analysis, regex, git history
│   │   └── rules/                ← custom Argus semgrep ruleset (.yaml files)
│   │       ├── injection.yaml
│   │       ├── auth.yaml
│   │       ├── crypto.yaml
│   │       ├── secrets.yaml
│   │       ├── misconfig.yaml
│   │       └── client_side.yaml
│   │
│   ├── llm/                      ← LLM abstraction
│   │   ├── __init__.py
│   │   ├── provider.py           ← unified interface (Ollama/Groq/Claude/Gemini)
│   │   ├── detector.py           ← GPU detection, VRAM measurement, model recommendation
│   │   ├── prompts.py            ← all system + user prompts
│   │   └── orchestrator.py       ← attack agent orchestration loop
│   │
│   ├── agents/                   ← Phase 2 attack agents
│   │   ├── __init__.py
│   │   ├── base.py               ← BaseAgent class, shared HTTP utils
│   │   ├── reconbot.py
│   │   ├── injector.py
│   │   ├── authbreaker.py
│   │   ├── idorhunter.py
│   │   ├── crawlerbot.py
│   │   ├── fuzzer.py
│   │   ├── headerpoker.py
│   │   ├── fileattacker.py
│   │   ├── racecondition.py
│   │   ├── ssrfprober.py
│   │   ├── xsshunter.py
│   │   ├── websocketagent.py
│   │   ├── graphqlagent.py
│   │   └── csrfhunter.py
│   │
│   ├── sandbox/                  ← Docker management
│   │   ├── __init__.py
│   │   ├── docker_manager.py     ← spin up target in Docker
│   │   ├── network.py            ← isolated network management
│   │   └── callback_server.py    ← blind vuln detection (XSS, SSRF, SQLi)
│   │
│   ├── report/
│   │   ├── __init__.py
│   │   ├── generator.py          ← compile all findings into report object
│   │   ├── exporters.py          ← HTML, JSON, PDF, Markdown exporters
│   │   └── templates/
│   │       └── report.html.j2    ← Jinja2 HTML report template
│   │
│   └── config/
│       ├── __init__.py
│       ├── settings.py           ← config read/write (TOML)
│       └── defaults.py           ← default values, model mappings, payload lists
│
├── payloads/                     ← bundled payload lists (subset of SecLists)
│   ├── sql_injection.txt
│   ├── xss.txt
│   ├── command_injection.txt
│   ├── path_traversal.txt
│   ├── common_passwords.txt
│   ├── common_paths.txt
│   └── common_headers.txt
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/                 ← vulnerable test apps for integration tests
│
└── gui/                          ← Tauri desktop app
    ├── src-tauri/
    │   ├── Cargo.toml
    │   ├── tauri.conf.json
    │   └── src/
    │       └── main.rs           ← Tauri commands, Python sidecar bridge
    └── src/                      ← React frontend
        ├── main.tsx
        ├── App.tsx
        ├── components/
        │   ├── ArgusEye.tsx       ← animated SVG logo component
        │   ├── RiskGauge.tsx      ← 0-100 score gauge, animates count-up
        │   ├── SeverityBadge.tsx  ← Critical/High/Medium/Low/Info
        │   ├── AgentStatusRow.tsx ← name, progress bar, count, state
        │   ├── LiveFeedBlock.tsx  ← scrolling terminal output
        │   ├── FindingRow.tsx     ← table row, clickable
        │   ├── FindingDetail.tsx  ← slide-in detail panel
        │   ├── ProviderCard.tsx   ← LLM provider selection
        │   ├── GreekKeyBorder.tsx ← animated SVG meander border
        │   ├── CodeViewer.tsx     ← syntax-highlighted code + vuln markers
        │   └── ProgressBar.tsx    ← bronze fill, animated
        └── screens/
            ├── Dashboard.tsx
            ├── NewScan.tsx
            ├── LiveAttack.tsx     ← HERO SCREEN
            ├── Reports.tsx
            ├── CodeView.tsx
            └── Settings.tsx
```

---

## 11. BUILD PHASES — WHAT TO BUILD IN ORDER

**DO NOT skip phases. Do not build GUI before CLI engine is working.**

### Phase 0 — Foundation (Week 1-2)
- [ ] Typer CLI scaffold with all commands registered (even if they're stubs)
- [ ] Rich output system (progress bars, tables, color-coded severity)
- [ ] Config system (TOML read/write, platformdirs)
- [ ] Repo ingestion — clone, build codebase map
- [ ] GPU detection and model recommendation logic
- [ ] Provider abstraction layer (unified LLM interface)
- [ ] Ollama integration (local)
- [ ] Groq integration (cloud)

### Phase 1 — Static Analysis Complete (Week 3-4)
- [ ] Semgrep integration + custom ruleset (start with 20 high-value rules)
- [ ] Dependency audit wrappers (npm, pip at minimum)
- [ ] Secret detection (regex + entropy analysis)
- [ ] Git history scanner
- [ ] LLM reasoning layer over Semgrep findings
- [ ] HTML report export (Jinja2)
- [ ] JSON report export
- [ ] `argus scan` command fully working end-to-end

### Phase 2 — Attack Agent MVP (Week 5-7)
- [ ] Docker sandbox manager
- [ ] Callback server for blind vulnerability detection
- [ ] ReconBot agent
- [ ] Base agent class + HTTP client utilities
- [ ] Injector agent (SQLi first, then expand)
- [ ] AuthBreaker agent (JWT attacks first)
- [ ] Basic LLM orchestrator loop
- [ ] Phase 2 report format
- [ ] `argus attack` command working end-to-end

### Phase 3 — Full Agent Swarm (Week 8-10)
- [ ] All 13 agents implemented
- [ ] IDORHunter (needs two-account test setup)
- [ ] RaceCondition agent (async concurrent requests)
- [ ] XSSHunter (with blind XSS callback)
- [ ] SSRFProber (with cloud metadata targets)
- [ ] GraphQLAgent
- [ ] WebSocketAgent
- [ ] CSRFHunter
- [ ] Smart orchestrator that adapts based on findings
- [ ] `argus audit` full pipeline (Phase 1 + Phase 2)

### Phase 4 — GUI (Week 11-13)
- [ ] Tauri project scaffold
- [ ] React component library (all components listed above)
- [ ] Dashboard screen
- [ ] NewScan / configuration screen
- [ ] LiveAttack screen (hero screen — most effort here)
- [ ] Reports screen with finding detail panel
- [ ] Settings screen
- [ ] Tauri ↔ Python IPC bridge
- [ ] GitHub Actions build pipeline (Windows .exe, Mac .dmg, Linux .AppImage)

### Phase 5 — Polish and Ship (Week 14-15)
- [ ] PyPI packaging (argus-sec)
- [ ] Comprehensive README with demo GIF
- [ ] Test suite (unit + integration against DVWA and Juice Shop)
- [ ] Demo recording (show it finding SQLi, auth bypass, RCE end-to-end)
- [ ] Docs site
- [ ] Show HN, r/netsec, r/LocalLLaMA launch

---

## 12. GUI DESIGN SYSTEM — "CARVED IN STONE"

The design concept: *a war room inside the Parthenon.* Ancient intelligence meets modern threat detection. Stone, bronze, parchment — not neon, not cyber, not SaaS.

### Color Tokens

```css
--color-obsidian:        #08080C;   /* true background */
--color-stone-dark:      #0F0F15;   /* cards, panels */
--color-stone-carved:    #171720;   /* sidebar */
--color-relief-shadow:   #1E1E2A;   /* borders, dividers */
--color-goldenrod:       #B8860B;   /* PRIMARY ACCENT — Argus eye, active states */
--color-bronze:          #CD7F32;   /* secondary accent, hover, progress fills */
--color-crimson:         #8B0000;   /* CRITICAL severity ONLY */
--color-sienna:          #8B4513;   /* HIGH severity ONLY */
--color-gold-pale:       #D4A853;   /* large numbers, major headings */
--color-parchment:       #C4A882;   /* primary body text — warm, NOT cold white */
--color-stone-text:      #6B5A45;   /* secondary text, timestamps, metadata */
--color-ember:           #2A1F0E;   /* hover background tint */
--color-weathered:       #4A4035;   /* LOW severity */
```

**Banned colors (never use):**
- Any shade of green
- Any shade of blue
- Any shade of purple
- Neon or bright reds (#DC2626 etc)
- Cold whites (#E2E8F0, #F8F8F8 etc)

### Severity Color Mapping

```
CRITICAL  →  #8B0000  Deep crimson
HIGH      →  #8B4513  Burnt sienna
MEDIUM    →  #B8860B  Dark goldenrod
LOW       →  #4A4035  Weathered stone
INFO      →  #2A2A3A  Almost invisible
```

Severity indicators are square dots (border-radius: 3px max), NOT circles.

### Typography

```css
/* Import in index.html */
@import url('https://fonts.googleapis.com/css2?family=Cinzel:wght@400;600;700&family=Cormorant+Garamond:ital,wght@0,400;0,500;1,400&family=JetBrains+Mono:wght@400;500&display=swap');

--font-display:  'Cinzel', serif;           /* headers, labels, logo */
--font-body:     'Cormorant Garamond', serif; /* descriptions, body, italic meta */
--font-code:     'JetBrains Mono', monospace; /* all terminal, code, payloads */
```

**Type scale:**

| Role | Font | Size | Color | Treatment |
|---|---|---|---|---|
| Risk score number | Cinzel | 72px | --color-gold-pale | Bold |
| App name | Cinzel | 20px | --color-goldenrod | Uppercase, tracking 0.2em |
| Section headers | Cinzel | 15px | --color-parchment | Uppercase, tracking 0.2em |
| Agent names | Cinzel | 12px | --color-goldenrod | Uppercase, tracking 0.15em |
| Body text | Cormorant Garamond | 16px | --color-parchment | Regular |
| Descriptions | Cormorant Garamond | 15px | --color-parchment | Regular |
| Timestamps / meta | Cormorant Garamond | 13px | --color-stone-text | Italic |
| Code / payloads | JetBrains Mono | 13px | --color-parchment | Regular |
| Monospace labels | JetBrains Mono | 12px | --color-stone-text | Regular |

### Layout Rules

- **Zero border-radius on cards and panels** (sharp corners = stone, not plastic)
- Maximum 3px border-radius on small interactive elements (checkboxes, badges)
- 1px borders in `--color-relief-shadow` on all panels
- 8px base grid, generous spacing
- Golden ratio (1.618) for sidebar-to-content width ratio
- No box shadows — use borders and texture for depth
- Hairline gold dividers (`#B8860B` at 12% opacity) between table rows

### Stone Texture

Every panel must have a subtle noise texture:

```css
.panel {
  background-color: var(--color-stone-dark);
  background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)' opacity='0.03'/%3E%3C/svg%3E");
}
```

Opacity: 2-4% maximum. Evokes polished obsidian, not wallpaper.

### The Argus Eye Component

SVG constructed from concentric angular/hexagonal shapes — NOT circles, NOT an illustration. Pure geometry. Dark goldenrod on obsidian.

```
Appears:
- Top-left sidebar as app logo (32×32px)
- Large watermark behind dashboard stats (200×200px, 8% opacity)
- Animated during live attack: each agent activation adds one outer geometric ring
- On app load: eye draws itself outward from center, bronze to gold, 1.5s
```

### Greek Key (Meander) Border Component

Animated SVG border that traces the meander pattern clockwise:
- Used on: Live Feed panel during active attack
- Color: `--color-bronze` (#CD7F32), 2px stroke
- Animation: traces clockwise, stops on scan completion
- Also used as static hairline divider between report sections (no animation)

### Animation Spec

| Trigger | Animation | Duration | Easing |
|---|---|---|---|
| App load | Argus eye draws outward, bronze to gold | 1.5s | ease-out |
| Attack starts | Greek key begins tracing on live feed border | continuous | linear |
| Agent activates | Eye gains one outer geometric ring | 0.8s | ease |
| Running agent indicator | Square pulses opacity 0.3 → 1.0 | 1.8s | ease-in-out, infinite |
| Exploit confirmed | Row background flashes crimson once | 300ms | immediate |
| Risk score on report load | Counts up from 0 to final value | 1.5s | ease-out |
| Detail panel open | Slides from right edge | 180ms | ease-out |
| Row hover | Ember background + goldenrod left border | 100ms | ease |
| Scan complete | Greek key stops tracing | — | — |

All animations must include:
```css
@media (prefers-reduced-motion: reduce) {
  * { animation: none !important; transition: none !important; }
}
```

### Screens

#### Dashboard
- Argus eye watermark large and centered behind stats (8% opacity)
- Recent audits table: repo in JetBrains Mono, score in Cinzel pale gold large, severity in Cormorant Garamond uppercase, 4px-tall progress bar in severity color, sharp corners
- Stats: four panels, Cinzel numerals 80px+, pale gold for totals, crimson for critical count, bronze for fixed
- "NEW SCAN" button: bronze border, goldenrod text, Cinzel, no fill, sharp, hover fills ember

#### New Scan / Configuration
- Target input: stone texture, bronze border, parchment text, JetBrains Mono
- Phase toggles: goldenrod when active
- Agent grid: 13 agents, Cinzel name small, goldenrod checked state
- Depth: three pill buttons, sharp corners, bronze border, goldenrod fill when selected
- LAUNCH AUDIT: full-width, goldenrod background, obsidian text, Cinzel uppercase large

#### Live Attack (Hero Screen)
- Header: target in JetBrains Mono, "ATTACKING" pulsing in crimson
- Risk score: enormous Cinzel pale gold number, thin progress bar shifts goldenrod → sienna → crimson
- Confirmed exploits: enormous Cinzel crimson number, flashes on increment
- Agent panel: Cinzel name goldenrod, square status indicator (empty/pulsing bronze/filled goldenrod), bronze progress bar, JetBrains Mono counts
- Live feed: JetBrains Mono, parchment for normal probes, crimson for confirmed (✓ prefix), bronze for agent transitions. Greek key border animates.
- Eye in sidebar gains ring per agent

#### Reports
- Risk score centered, enormous Cinzel, severity color
- Severity summary row: four counts with square dots
- Findings table: square dot, Cormorant Garamond vuln name, JetBrains Mono endpoint, Cinzel agent small, Cormorant italic timestamp
- Row hover: ember tint + goldenrod left border
- Detail panel: severity badge, Cinzel name, CVSS, Cormorant Garamond explanation, JetBrains Mono HTTP evidence, code diff
- "EXPORT REPORT": Cinzel, bronze border

#### Settings
- Section headers: Cinzel uppercase goldenrod
- Provider cards: stone texture, bronze border on selected, goldenrod active dot
- VRAM bar: bronze fill
- All inputs: stone texture, bronze border

---

## 13. NAMING AND BRANDING

**App name:** Argus  
**Mythology:** Argus Panoptes — hundred-eyed giant of Greek mythology, never slept, saw everything  
**CLI command:** `argus`  
**PyPI package:** `argus-sec`  
**Domain:** `argussec.dev`  
**GitHub:** `argus-sec/argus`  
**Logo text symbol (fallback):** `◈`

**Fits existing mythology portfolio:**
- Mimir (Norse — wisdom, study agent)
- Apollo (Greek — light, speech emotion)
- Siren (Greek — sound, speech disentanglement)
- Argus (Greek — sight, security)

---

## 14. COMPETITIVE POSITIONING

| Tool | Static | Active Attack | LLM Reasoning | Free | Local Model | Open Source |
|---|---|---|---|---|---|---|
| Snyk | ✓ | ✗ | ✗ | Partial | ✗ | ✗ |
| SonarQube | ✓ | ✗ | ✗ | Partial | ✗ | Partial |
| Semgrep | ✓ | ✗ | ✗ | ✓ | ✗ | ✓ |
| Burp Suite | ✗ | ✓ | ✗ | Partial | ✗ | ✗ |
| OWASP ZAP | ✗ | ✓ | ✗ | ✓ | ✗ | ✓ |
| **Argus** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

Nobody combines all six. That is the gap Argus owns.

**Positioning statement:** The security tool built for the vibe coding era.

---

## 15. LAUNCH STRATEGY

**Demo targets:**
- DVWA (Damn Vulnerable Web App) — purpose-built, legal to attack
- OWASP Juice Shop — realistic Node.js app with known vulns
- WebGoat — Java-based training app

Record Argus finding SQLi, auth bypass, RCE, IDOR end-to-end in one terminal session. This is the primary marketing asset.

**Launch channels:**
- Show HN (security + AI + CLI is strong for HN)
- r/netsec (attack agent will resonate)
- r/LocalLLaMA (local model angle)
- r/webdev and r/programming (vibe coder audience)
- Twitter/X security community

---

## 16. KEY DECISIONS AND RATIONALE

**Why Python for the engine?**
Security tooling ecosystem is Python-native. Semgrep, pip-audit, GitPython, Docker SDK all have first-class Python support. Typer + Rich produce the best CLI DX in Python.

**Why Tauri for the GUI?**
Same stack as Mimir. Lightweight binary compared to Electron. Ships as native .exe/.dmg/.AppImage. The Python engine runs as a sidecar.

**Why not Electron?**
300MB baseline vs Tauri's ~10MB. For a CLI-first tool the overhead is unjustifiable.

**Why BYOK instead of hosted LLM?**
Security tool trust model is different from consumer apps. Devs already send code to Snyk, GitHub, Dependabot — cloud LLM is acceptable. BYOK means zero LLM infrastructure cost and no margin to maintain.

**Why Qwen2.5-Coder for local?**
Code-specialized model. Understands ASTs, SQL sinks, auth flows better than general models at equivalent size. Consistently outperforms Llama on code tasks. For security scanning, code understanding matters more than general reasoning.

**Why not just wrap existing tools?**
Semgrep is one component of Phase 1. The LLM reasoning layer, the active attack agent swarm, and the orchestration loop are all novel. No existing tool does all three together.

**Build CLI first, GUI second.**
GUI is a display layer over the CLI engine. CLI must be stable before GUI is built. This ensures a shippable product at every phase.

---

## 17. WHAT NOT TO BUILD (YET)

- Web SaaS version (post-MVP)
- Team collaboration features (post-MVP)
- GitHub Action (post-MVP, easy to add once CLI is solid)
- Watch mode for continuous monitoring (post-MVP)
- Mobile app (never)
- Windows-specific features (Tauri handles cross-platform)

---

## 18. TESTING STRATEGY

**Unit tests:** Every agent has unit tests with mock HTTP responses. Every LLM prompt has output format tests. Config read/write tested.

**Integration tests:** Run against DVWA and Juice Shop in Docker. Assert known vulnerabilities are found. Regression tests on false positive rate.

**Security of Argus itself:** Argus must not be exploitable by the repos it scans. Sandboxing is critical — all target app execution inside isolated Docker network with no host access.

---

*End of ARGUS_CONTEXT.md*
*Last updated: June 2026*
*Version: 1.0 — pre-build*
