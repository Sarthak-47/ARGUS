# Changelog

All notable changes to Argus are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [1.2.7] — 2026-07-11

### Fixed
- **Windows: every backend call flashed a visible console window.** Spawning
  `argus`/`python` from a GUI app on Windows opens a console window for each
  subprocess unless explicitly suppressed — the desktop app never suppressed
  it, so every check flickered a cmd window open and closed.
- **The same failed check re-ran the entire detection probe from scratch,
  repeatedly.** Only a *successful* CLI resolution was cached; a failure
  wasn't, so every screen's mount effect (New Scan, Settings, the sidebar)
  independently re-probed the full candidate list — the `argus` script, three
  Python interpreters, two fallback paths — on every navigation. Combined with
  the console-flash bug, this is what showed up as a storm of windows opening
  and closing before the app settled back into the same unresolved state.
  Both outcomes (found and not-found) are now cached for the session, and
  reset only when the user explicitly saves or clears a manual CLI path in
  Settings.

## [1.2.6] — 2026-07-11

### Fixed
- **Saving an Argus CLI path in Settings crashed with a raw JS error**
  (`Cannot read properties of undefined (reading 'invoke')`) outside the
  desktop app — the new field added in v1.2.5 wasn't guarded the way every
  other desktop-only action in the store is. Found by driving every button in
  the actual browser preview end-to-end.
- **The "Argus CLI" status showed "checking…" forever** in the browser
  preview, since there's no backend there to ever resolve it — it now reads
  "desktop app only" and the path field/buttons are disabled with a clear
  explanation, instead of implying a check is perpetually in progress.

## [1.2.5] — 2026-07-11

### Fixed
- **Desktop app couldn't find `argus` when it isn't on the system PATH at
  all** — v1.2.4's auto-detection (the `argus` script, `python -m argus`, a
  couple of user-bin locations) still can't find an install that lives
  nowhere but a project's own venv, which no path-probing heuristic can guess.
  Settings now has an "Argus CLI" field: paste the exact path to your `argus`
  executable (e.g. a venv's `Scripts\argus.exe` or `bin/argus`), it's
  validated with `--version` before saving, persisted, and takes effect
  immediately — no restart needed. New Scan's "not found" message now links
  straight to Settings instead of a dead end.

## [1.2.4] — 2026-07-11

### Fixed
- **Desktop app couldn't find the `argus` CLI** — a GUI launched from the
  Dock/Start menu doesn't inherit the shell PATH, so a pip-installed `argus` was
  invisible to the packaged app: it reported "argus was not found on PATH" and
  couldn't detect or select the local LLM provider, even though `argus` worked
  fine in a terminal. The Tauri backend now probes the `argus` script, then
  `python -m argus`, then the usual user-site bin locations, and caches the
  first that answers `--version`. Adds `argus/__main__.py` for the module
  fallback.
- **SQL injection missed when the query is built into a variable first** — the
  rule only flagged string-building done inside the `execute(...)` call, so the
  common `q = "SELECT … " + name; execute(q)` pattern slipped through. A new
  `py-sql-build` rule catches concatenation, `%`-format, and f-string query
  construction, requiring real SQL structure (SELECT…FROM etc.) so ordinary
  strings and parameterised queries don't trip it (verified: zero false
  positives on a clean control file).

### Docs
- README lists the DataExposure agent and corrects the swarm count.

## [1.2.3] — 2026-07-10

### Fixed
- **Risk score no longer saturates at 100.** It was a plain saturating sum of
  severity weights, so almost any real app maxed out and the number carried no
  information. The score now stays inside the worst finding's severity band (a
  single MEDIUM reads 45, HIGH 70, CRITICAL 85) and climbs toward the top of
  that band with additional findings via diminishing returns — so it actually
  discriminates between scans, and the band always matches the worst finding
  (no "CRITICAL" with zero critical findings).
- **Wide-window layout.** New Scan, Settings, and Dashboard capped their content
  narrowly with no centering, so on a maximized/ultrawide window everything
  jammed to the left under a full-width header. Content now fills the width and
  the New Scan agent grid flows responsively (3 columns at 1280px, 5 at 1920px).
- Dropped the redundant "demo" / "not configured" sub-label under the sidebar
  provider; the model name shows only when a real provider is resolved.

## [1.2.2] — 2026-07-10

### Added
- **DataExposure agent** (CWE-200) — a new attack agent that flags sensitive
  fields (password hashes, secrets, API keys, PII) returned in JSON responses,
  the excessive-data-exposure class no other agent covered. Takes the VAmPI
  benchmark from 40% to 60%.
- **REST path-template IDOR** — IDORHunter now enumerates object identifiers in
  path templates (`/users/v1/{username}`, `/api/items/{id}`), harvesting real
  ids from the collection endpoint's JSON when they can't be guessed. It
  previously did nothing against a modern REST API. Takes the VAmPI benchmark
  from 20% to 40%.
- **Wildcard CORS detection** — HeaderPoker flags a static
  `Access-Control-Allow-Origin: *` at LOW severity, distinct from the HIGH
  reflected-origin/credentials case (which never fired for a plain wildcard).
  Takes the Juice Shop benchmark from 29% to 43%.
- A no-crash smoke guard (`tests/unit/test_agent_smoke.py`) that runs every
  registered attack agent against a live local server and asserts it returns a
  report rather than raising — so a refactor can't silently break an agent
  whose crash the orchestrator would otherwise swallow into an "error" report.

### Fixed
- **SPA false positives** — CrawlerBot no longer flags a single-page app's
  catch-all as an exposed file: an HTML body for a path that should be
  JSON/config/binary (`/.env`, `/backup.sql`, `/.git/*`) is the SPA fallback,
  not the real file. Cut Juice Shop's crawler findings from 66 to 10.
- **Session JWT never analysed** — AuthBreaker now also inspects the
  authenticated session's own bearer token (applied via `--auth`), not just
  tokens the homepage returns; the token most worth checking was being skipped.
- **Report detail polish** — a static finding (no HTTP response, reproduction,
  or CVSS) no longer renders an empty RESPONSE box, empty REPRODUCTION section,
  or a bare "CVSS —"; sections appear only when they carry content, and the
  code evidence is labelled "CODE" rather than "REQUEST".

## [1.2.1] — 2026-07-10

### Fixed
- **Authenticated-target attack coverage** — five engine fixes, each verified
  against a live DVWA container, that take the DVWA benchmark from 2/6 to 6/6
  (SQL injection, reflected XSS, command injection, CSRF, path traversal,
  missing headers) with no target-specific hacks:
  - Never crawl or attack session-destroying endpoints (logout/signout). One
    agent following a logout link mid-run silently logged the whole session
    out, so every later agent tested the login page instead of the
    authenticated surface — this was hiding reflected XSS behind auth.
  - Injection/XSS agents now send an endpoint's other form params (a submit
    button, etc.) when fuzzing one, so pages that guard on a submit being
    present (`isset($_GET['Submit'])`) actually reach the vulnerable path.
  - Injection/XSS agents skip static assets and test endpoints with real
    declared params before guessed ones, so the work cap reaches injectable
    endpoints instead of being spent on `.css`/`.png` URLs.
  - ReconBot resolves a sub-page's relative links and form actions against
    that page's own URL, not the site root, so a form with `action="#"` or a
    relative `?id=` link binds to the right (vulnerable) endpoint.
  - The benchmark's DVWA setup posts the setup form's CSRF token and verifies
    DB creation — without it the database was never created and every page
    redirected to `setup.php`, leaving the whole target unusable.

## [1.2.0] — 2026-07-10

### Added
- **Desktop GUI redesign** — a red-figure-pottery visual language (matte
  black-glaze + terracotta + oxblood, the Argus eye as its motif) across all
  six screens. The report's "hundred eyes" are the ~50 vulnerability classes
  Argus checks for: red eye = caught something, tan eye = checked and clean,
  and every eye is hoverable, naming its class. Findings render as
  severity-tinted eyes; New Scan presents the agents as eyes you open/close;
  Live Attack shows the running agents' eyes breathing over the elapsed clock.
  Hash routing makes each screen a real addressable page. Engine untouched —
  a theme + component layer over the existing React screens.
- **Live attack feed** — the engine now emits machine-readable per-agent
  events when `ARGUS_EVENT_STREAM=1` (a `@@ARGUS_EVENT@@` sentinel + JSON
  line); the desktop shell runs the audit with stdout piped and forwards each
  as an `argus://event`, and Live Attack renders whatever actually streamed —
  falling back to the eyes + clock when nothing has, so the feed is a live
  nicety and never load-bearing.
- **CWE-precise eye mapping** — findings light their vulnerability-class eye
  by canonical (unambiguous) CWE first, with title-keyword fallback for the
  shared CWEs, so a finding maps to the right eye instead of a fuzzy sibling.
- Repo professionalization: `CODE_OF_CONDUCT.md`, GitHub issue templates
  (bug report / feature request, with security reports redirected to
  private advisories), and a PR template.
- A branded SVG hero banner and social-preview card for the README (using
  the real Argus logo), plus a dedicated callout elevating the MCP-server-
  scanning and prompt-injection-testing angle that was previously buried
  mid-paragraph.
- `docs/dev/SCREENSHOTS.md`: verified, reproducible steps to generate a
  real (non-fabricated) populated report and capture GUI screenshots.

### Changed
- Desktop GUI upgraded to React 19.
- Moved the internal build spec (`ARGUS_CONTEXT.md`) and the superseded
  pre-1.0 backlog (`UPGRADE.md`) into `docs/dev/` so the repo root only
  shows what a new visitor needs.
- `pyproject.toml` classifiers bumped from Alpha to Beta and expanded
  (explicit Python 3.10–3.12, license, OS-independent) to match the
  project's actual maturity (446 tests, benchmark-proven detection).

### Fixed
- README's benchmark section and `CONTRIBUTING.md`'s release steps were
  stale (referenced pre-JS-crawling gaps and a tag-triggered PyPI publish
  that was deliberately changed to manual `workflow_dispatch`).

## [1.1.0] — 2026-07-08

### Added
- **LLM taint-tracing mode** (ROADMAP v0.4.6): new `argus scan --taint` traces
  full source-to-sink call chains within each high-risk file (a VulnHuntr-
  style pass), reporting a finding only when the whole chain — source, every
  intermediate hop, and the sink — is visible; a partial chain is dropped
  rather than guessed. A natural extension of the existing `--deep`
  free-form review pass.
- **JS-aware crawling** (ROADMAP v1.0.1 follow-up A): ReconBot now reuses
  DomXSSHunter's optional Playwright dependency to render the root page in a
  real headless browser (no flag needed, silently skipped when the `browser`
  extra isn't installed) and mine both the post-JS DOM and every XHR/fetch
  call it fires — the Angular/React/Vue SPA gap that hid Juice Shop's
  client-routed surface from a regex-over-server-HTML crawl. Verified live
  against a real server whose only link and only API call exist purely
  inside a `<script>` tag. Confirmed against the real target, with a caveat:
  across three re-runs on GitHub's shared runners, `juice_shop` scored 29%
  (2/7) twice and 14% (1/7) once — the crawl wins its race against Angular's
  bootstrap time in the common case but can lose it on a busier runner.
- **Behavioral dependency analysis** (ROADMAP v0.4.5): install-script
  analysis deepened beyond the original curl-piped-to-shell check — a
  download-then-execute two-step, a base64-decoded payload piped to a
  shell, environment-secret exfiltration (a secret-shaped env var read
  alongside an outbound POST/upload), and writes to a sensitive filesystem
  path (~/.ssh, ~/.npmrc, ~/.aws, ...) are all now flagged. Static and
  offline throughout — Argus never executes an install script to profile
  it. Also now checks `preuninstall`/`postuninstall`, not just
  `pre`/`postinstall`.
- **VEX output** (ROADMAP v0.4.4): `argus report --format vex` writes a
  CycloneDX 1.5 VEX document (`vex.cdx.json`) — a per-dependency-finding
  exploitability statement (`exploitable` / `not_affected` with
  `code_not_reachable` justification) driven by the existing reachability
  analysis (v0.4.2), consumable alongside the plain `--format sbom`.

## [1.0.0] — 2026-07-08

### Added
- **Docs site + MCP hardening** (ROADMAP v1.0.3): new `docs/` guide set
  (getting started, authenticated scanning, CI integration, troubleshooting)
  covering ground the README doesn't have room for. `argus_scan`/
  `argus_attack`/`argus_fix` (the MCP server tools) now return a structured
  `{"error": "..."}` dict on failure — a bad path, an unreachable repo URL —
  instead of letting a raw exception propagate through the MCP protocol,
  matching the pattern `argus_fix` already used for "no provider configured".
- **Integrations** (ROADMAP v1.0.2): DefectDojo needed no new code — its
  built-in SARIF import type already accepts `argus scan --format sarif`.
  New `argus report --format jira` writes a Jira-importable CSV (one issue per
  finding: Summary, Description with evidence/fix/CWE/compliance, Priority
  mapped from severity, Labels) for Jira's built-in CSV importer — no API
  token or live Jira instance needed.
- **Post-login step for authenticated sessions**: `AuthConfig` gained
  `post_login_url`/`post_login_data` — an optional extra request that runs on
  the same session right after login, for apps that need one more step before
  the session is fully usable (a security-level toggle, a tenant/org picker).
  Found necessary while closing the CSRF-login gap below: DVWA's login alone
  wasn't enough, since its vulnerable pages stay patched at "impossible"
  difficulty per-session until a separate POST to `/security.php`. Verified
  live against a real server whose gated resource only unlocks after both the
  login *and* the post-login step complete on the same session.
- **CSRF-aware form login** (ROADMAP v1.0.1 follow-up B): `AuthConfig`'s form
  login gained an optional `csrf_field` — Argus GETs the login page first,
  scrapes a named hidden input's value (regardless of attribute order), and
  echoes it back in the POST body. Closes a real gap the benchmark found: DVWA's
  login form requires a rotating `user_token` field that the previous
  fixed-field-dict POST could never satisfy. Verified live against a real
  threaded server that genuinely validates the token server-side (rejects a
  stale/wrong one), not just a mock. The benchmark's `dvwa` case now wires this
  with DVWA's documented default credentials plus the one-time DB-setup POST a
  fresh container needs.
- **Auto-discover a target's own OpenAPI spec** (ROADMAP v1.0.1 follow-up C):
  ReconBot now probes well-known spec paths (`/openapi.json`, `/swagger.json`,
  `/api/openapi.json`, `/.well-known/openapi.json`, …) and, on a hit, parses it
  through the same engine `--api-spec` uses and seeds every declared endpoint —
  no flag needed. Closes a real gap the benchmark suite found: an API-only
  target with no crawlable HTML (like VAmPI) previously had its whole surface
  invisible to the swarm. Verified live: with zero flags, the swarm discovered
  and attacked an endpoint that existed *only* in a spec. Confirmed against the
  real target too — re-running the benchmark suite moved `vampi` from 0% (0/5)
  to **20% (1/5)**, with total findings up from 3 to 11.

## [0.6.0] — 2026-07-08

### Added
- **Argus as an MCP server** (ROADMAP D3): `argus mcp-server` (new optional
  `argus-sec[mcp]` extra) exposes `argus_scan`/`argus_attack`/`argus_fix` as
  MCP tools, so an MCP-capable editor agent (Copilot/Cursor/Claude Code) can
  run a real scan/attack/fix directly instead of shelling out and pasting
  results back in. Every tool runs the engine with stdout redirected away
  (required — the stdio transport *is* stdout, so any stray print would
  corrupt the protocol) and returns structured JSON via `ScanResult.to_dict()`/
  `Finding.to_dict()`. Verified live through the real MCP `call_tool` path:
  zero stdout leakage, real findings returned against both a static target and
  a live server (a real XSS confirmed via `argus_attack`) — this also caught
  and fixed a genuine bug, `argus_attack` calling the sync `asyncio.run()`
  wrapper from inside a tool call that's already running in an event loop.
- **Benchmark suite** (ROADMAP v1.0.1): new `argus benchmark` command runs the
  full attack swarm against known-vulnerable apps — OWASP Juice Shop, DVWA,
  VAmPI, and Argus's own bundled demo target (the only case that needs no
  Docker) — and reports a real detection rate against a hand-curated ground
  truth scoped to what Argus's detectors actually target. New
  `.github/workflows/benchmark.yml` runs the full suite (Docker cases
  included) on every release and publishes results as a job summary + build
  artifact. Building this surfaced and fixed a real gap: the bundled demo
  target's crafted SQL error text didn't match any of Injector's real-world
  error-based-SQLi signatures, so `argus demo`'s advertised
  `INJECTOR:SQLI-ERROR` output was never actually firing — now it does
  (100% detection rate on the local case, verified live). Triggering the
  workflow against real Docker targets on GitHub's runners also caught a
  ground-truth bug (a category mismatch on the missing-headers entries, fixed)
  and surfaced three honest, understood gaps now tracked as concrete
  follow-ups in ROADMAP.md: Juice Shop's Angular SPA needs JS-aware crawling,
  DVWA's login needs a CSRF-token-scraping form login, and VAmPI (API-only,
  no crawlable HTML) needs its own OpenAPI spec auto-discovered. First
  published numbers, after that fix: `argus_demo` 100% (14/14), `dvwa` 33%
  (2/6), `juice_shop` 14% (1/7), `vampi` 0% (0/5) — published as-is, not
  smoothed over.
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

[Unreleased]: https://github.com/Sarthak-47/ARGUS/compare/v1.2.7...HEAD
[1.2.7]: https://github.com/Sarthak-47/ARGUS/compare/v1.2.6...v1.2.7
[1.2.6]: https://github.com/Sarthak-47/ARGUS/compare/v1.2.5...v1.2.6
[1.2.5]: https://github.com/Sarthak-47/ARGUS/compare/v1.2.4...v1.2.5
[1.2.4]: https://github.com/Sarthak-47/ARGUS/compare/v1.2.3...v1.2.4
[1.2.3]: https://github.com/Sarthak-47/ARGUS/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/Sarthak-47/ARGUS/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/Sarthak-47/ARGUS/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/Sarthak-47/ARGUS/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Sarthak-47/ARGUS/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Sarthak-47/ARGUS/compare/v0.6.0...v1.0.0
[0.6.0]: https://github.com/Sarthak-47/ARGUS/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/Sarthak-47/ARGUS/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Sarthak-47/ARGUS/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Sarthak-47/ARGUS/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Sarthak-47/ARGUS/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Sarthak-47/ARGUS/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Sarthak-47/ARGUS/releases/tag/v0.1.0
