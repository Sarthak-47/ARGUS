# Argus Roadmap — v1.2.9 and beyond

> **Status: the 1.0 bar below is fully shipped**, plus everything under
> Milestone v0.4 that originally wasn't gating it (VEX, behavioral
> supply-chain analysis, LLM taint-tracing) and both benchmark follow-ups.
> Current release: see [CHANGELOG.md](CHANGELOG.md). This file is kept as
> the historical record of *why* each decision was made — read it for
> context on a specific feature, not as "what's left to build."

Historical roadmap showing how Argus reached v1.0; current releases are tracked
in the changelog. This supersedes
[`UPGRADE.md`](docs/dev/UPGRADE.md) (the v0.1→v0.2 backlog, now largely
shipped) as the forward-looking plan.

It's grounded in what the 2026 market leaders are actually shipping — XBOW,
Aikido, Snyk, Escape, StackHawk, Invicti, Horizon3 — filtered hard for Argus's
real audience: **solo developers and small teams**, local-first, no enterprise
sprawl. Enterprise-flavoured features (org asset graphs, CSPM fleets, SIEM
correlation) are deliberately out of scope for 1.0.

## Historical snapshot (v0.2.0)

Shipped and solid: two-phase engine (static scan + real attack swarm with
confirmed PoCs), LLM reasoning, **exploit chaining**, secret/IaC/supply-chain
detection, ASVS/PCI compliance tags, SBOM, SARIF, policy-as-code gating,
diff-aware + baseline CI gating, `argus fix` (dry-run/apply with reverify),
history/compare/suppress, a Tauri desktop app, and cross-platform installers.

Honest gaps that block "1.0": Argus can only attack the **unauthenticated**
surface, doesn't understand an app's **API schema**, its static scan is
**noisy** (lockfile/bundle entropy hits), and there's **no published proof** it
detects what it claims. The whole 2026 market has converged on
authenticated + API-native + reachability-filtered + benchmark-proven. Those
are the spine below.

---

## The 1.0 definition of done

> Argus 1.0 can **authenticate to a real app**, **ingest its API surface**,
> attack it **auth-aware**, produce **low-noise** findings with
> **reachability-filtered** dependency CVEs, **open a fix PR**, and ships with
> **published benchmark numbers** against known-vulnerable apps proving its
> detection rate and false-positive rate.

Everything else is polish around that sentence.

---

## Milestone v0.3 — Reach real apps (authenticated + API-aware)

The single biggest gap. Right now Argus attacks only what an anonymous user can
reach; almost every real app hides its interesting surface behind a login.

- **v0.3.1 · Authenticated attack sessions.** ✅ **Done.** `--auth
  .argus-auth.toml` (auto-discovered): bearer token, headers, session cookies,
  HTTP basic, form login (session-cookie or token-from-JSON), and OAuth2
  client-credentials. Applied once to the shared httpx client, so every agent
  and ReconBot's crawl carry the logged-in session. Verified end-to-end: the
  swarm sends the credential on every request to a real server.
- **v0.3.2 · API schema ingestion.** ✅ **Done.** `--api-spec <file|url>` seeds
  the surface from OpenAPI 3.x / Swagger 2.0 / Postman v2 / GraphQL introspection;
  paths resolve against the target URL and compose with the surface inventory.
  Verified: the swarm attacks a spec-only endpoint with no inbound links.
- **v0.3.3 · BOLA/BFLA with real auth.** ✅ **Done.** New AuthzTester agent +
  `--auth-b` second identity. Compares anonymous / identity-A / identity-B per
  endpoint and flags only the protected-from-anonymous-yet-reachable-cross-user
  pattern — BOLA (CWE-639) and BFLA (CWE-285). Verified to fire on a vulnerable
  app and stay silent on a correctly-authorized one.
- **v0.3.4 · Deeper MCP-security scanning.** ✅ **Done.** MCPSecurityAgent now
  inspects the exposed catalog: **tool poisoning** (hidden instructions in tool
  descriptions, CWE-94), **dangerous-capability** classification on
  unauthenticated tools (shell/file/network/db/eval, CWE-306), and
  **resources/prompts** enumeration. Verified to flag a poisoned, shell-capable
  server and stay quiet (disclosure-only) on a benign one.

## Milestone v0.4 — Trust the output (cut noise, prove reachability)

Your DBMS audit surfaced ~229 false-positive entropy hits. Noise is the fastest
way to lose a user; the market's answer is reachability + smarter filtering.

- **v0.4.1 · Secret-scan noise reduction.** ✅ **Done.** The entropy pass now
  skips lockfiles, minified bundles, `.map` files, and vendored/build dirs, and
  ignores checksum-length hex digests; the high-confidence pattern pass still
  runs everywhere. Verified: a lockfile full of integrity hashes yields zero
  entropy noise while a real key in it (and a genuine secret in normal source)
  is still flagged.
- **v0.4.2 · SCA reachability analysis.** ✅ **Done.** A vulnerable dependency
  not imported anywhere in first-party code is downgraded one severity and
  annotated "likely transitive/unused"; imported ones keep severity and are
  marked reachable. Import-level pass over Python + JS/TS with dist→import
  aliases. Verified: an imported CVE stays CRITICAL, an unimported one drops to
  HIGH with the note.
- **v0.4.3 · Container image CVE scanning.** ✅ **Done.** `argus scan` extracts
  base image(s) from the repo's Dockerfile(s) and scans them for OS-package CVEs
  via Trivy when installed (multi-stage / digest-pinned / stage-alias aware,
  ignores `scratch`); graceful skip-with-note otherwise. Verified: extraction +
  Trivy-JSON parsing + the no-Trivy skip path.
- **v0.4.4 · VEX output.** ✅ **Done.** `argus report --format vex` writes a
  CycloneDX 1.5 VEX document (`vex.cdx.json`) alongside the plain SBOM — one
  exploitability statement per dependency finding, `exploitable` or
  `not_affected`/`code_not_reachable`, driven directly by the reachability
  analysis v0.4.2 already computes. Matches each finding to its SBOM component
  by (ecosystem, package name) rather than exact version, since the
  auditor-resolved version (npm audit's lockfile-pinned version) and the
  declared-manifest version the SBOM uses can legitimately differ.
- **v0.4.5 · Behavioral dependency analysis.** ✅ **Done.** Deepened the
  install-script check beyond the original curl-piped-to-shell pattern:
  a download-then-execute two-step (fetch a binary, `chmod +x`, run it —
  split across commands to dodge the piped-shell check), a base64-decoded
  payload piped to a shell (obfuscation), environment-secret exfiltration (a
  token/key/secret-shaped env var read alongside an outbound POST/upload),
  and writes to a sensitive filesystem path (`~/.ssh`, `~/.npmrc`, `~/.aws`,
  shell profiles). All static, offline, pattern-based analysis of the
  manifest's own scripts — Argus never executes an install script to profile
  it, since actually running untrusted code is the exact thing a security
  scanner shouldn't do. Now also checks `preuninstall`/`postuninstall`, not
  just `pre`/`postinstall`. Verified: each new check fires on a crafted
  malicious pattern and stays silent on benign scripts (e.g. `node-gyp
  rebuild`).
- **v0.4.6 · LLM taint-tracing mode.** ✅ **Done.** New `argus scan --taint`:
  a VulnHuntr-style pass over each high-risk file that asks the LLM to trace
  the full path from an untrusted input source to a dangerous sink
  (SQLi/SSRF/command-injection/deserialization/eval/...), reported only when
  the *entire* chain — source, every intermediate hop, and the sink — is
  visible in the code shown; a partial chain (a sink with no visible source,
  or vice versa) is explicitly instructed to be dropped rather than guessed.
  A natural extension of the existing `freeform_review` (`--deep`) pass, and
  plays directly to Argus's LLM-reasoning strength rather than a pattern
  match. File-scoped (not a full interprocedural call graph) to stay
  tractable — same scope discipline as the reachability analysis (v0.4.2).
  Findings carry the resolved call chain in `metadata.call_chain`.

## Milestone v0.5 — Close the loop (CI-native remediation)

Argus already generates and reverifies fixes; 1.0 needs to *deliver* them where
developers live.

- **v0.5.1 · Auto-fix pull requests.** ✅ **Done.** `argus fix --apply --pr`
  commits reverified patches to a new branch, pushes it, and opens a real GitHub
  PR via the `gh` CLI. Opt-in, requires explicit GitHub auth (`gh auth login` or
  `GH_TOKEN`/`GITHUB_TOKEN`), refuses on a dirty tree/detached HEAD/no origin.
  Verified end-to-end against a throwaway local remote. *Aikido AI AutoFix / Snyk.*
- **v0.5.2 · PR review comments.** ✅ **Done.** New `pr-comments` Action input +
  `argus pr-comment` command posts each new finding as an inline PR review
  comment via the REST API — zero extra setup in GitHub Actions, idempotent
  (fingerprinted, never double-posts), degrades gracefully for lines outside
  the diff. *GitHub Advanced Security parity.*
- **v0.5.3 · Broaden auto-sandbox stack detection.** ✅ **Done.** Added Flask,
  FastAPI, and Rails detection (each via an unambiguous framework convention,
  never a filename guess); Node now builds before start when a `build` script
  exists and falls back to a dev-server command (next/vite/react-scripts) when
  there's no production start script; and a `docker-compose.yml` with an
  explicitly published port is now a supported sandbox path (`docker compose up
  -d --build` / `down -v`) for multi-service repos a single Dockerfile can't
  represent. Verified: 29 dockerfile_gen tests + 7 compose-logic tests
  (subprocess mocked, no real Docker daemon needed).

## Milestone v1.0 — Prove it, then ship it

- **v1.0.1 · Benchmark suite + published numbers.** ✅ **Done** (Juice Shop,
  DVWA, VAmPI + the local demo case; WebGoat/NodeGoat are good candidates for a
  future expansion). `argus benchmark` + `.github/workflows/benchmark.yml`
  publish detection/unmatched rates on every release. **The credibility
  unlock** — building it already found and fixed a real gap (the demo target's
  SQLi signature never actually matched Injector's patterns), and a real
  ground-truth bug (a category mismatch on the missing-headers entries).
  **First published numbers** (run against real Docker targets on GitHub's
  runners, not simulated): `argus_demo` 100% (14/14 — the fully self-contained
  case), `dvwa` 33% (2/6), `juice_shop` 14% (1/7), `vampi` 0% (0/5) — after
  finding and fixing a ground-truth category bug the first run exposed.
  Published as-is, not smoothed over — the three external misses are real,
  understood gaps (below), which is exactly what a benchmark is supposed to
  surface.
  - **Follow-up A — JS-aware crawling.** ✅ **Done.** ReconBot now reuses
    DomXSSHunter's optional Playwright dependency: when installed (`pip
    install 'argus-panoptes[browser]'`), it renders the root page in a real
    headless browser (no flag needed — same zero-flag philosophy as follow-up
    C's OpenAPI auto-discovery) and mines both the post-JS DOM (for links/
    forms that only exist after client-side rendering) and every XHR/fetch
    call it observes firing during load — the exact Angular/React/Vue SPA gap
    that left Juice Shop's client-routed surface invisible to a regex-over-
    server-HTML crawl. Silently skipped, zero cost, when the `browser` extra
    isn't installed — same graceful-degrade pattern as Semgrep/domxss.
    Verified live against a real threaded server whose only link and only API
    endpoint exist purely inside a `<script>` tag (a DOM write + a `fetch()`
    call, nothing in the server-rendered HTML) — both genuinely discovered.
    `.github/workflows/benchmark.yml` now installs the `browser` extra plus
    Chromium so the real `juice_shop` benchmark case exercises this. **Confirmed
    against the real target, with an honest caveat:** across three re-runs on
    GitHub's shared runners, `juice_shop` scored 29% (2/7) twice and 14% (1/7)
    once — the JS-aware crawl catches SQL injection (Juice Shop only exposes it
    behind Angular's client-side router) when it wins the race against
    Angular's bootstrap time within the 10s `networkidle` wait, and silently
    falls back to the static-only result on a run where a busier shared runner
    doesn't clear that window in time. A real, reproducible improvement in the
    common case, not a guaranteed one on every run — published as observed,
    not rounded up to the better number.
  - **Follow-up B — CSRF-aware form login.** ✅ **Done.** `AuthConfig`'s form
    login gained an optional `csrf_field`: Argus GETs the login page first,
    scrapes a named hidden input's value regardless of attribute order, and
    echoes it back in the POST body. Verified live against a real threaded
    server that genuinely validates the token server-side (rejects a stale/
    wrong one with 403) — not just a mock that always accepts. The benchmark's
    `dvwa` case now wires this with DVWA's documented default credentials
    (admin/password) plus the one-time DB-setup POST a fresh container needs.
    First real-target run stayed flat (login alone wasn't the whole story —
    DVWA's vulnerable pages are patched at "impossible" difficulty per-session
    until you separately POST to `/security.php`), so `AuthConfig` gained a
    general **post-login step** (`post_login_url`/`post_login_data`, runs on
    the same session after login — useful for any app with a similar
    unlock-after-login pattern, not just DVWA) and the benchmark wires it.
    **Honest result:** the real `dvwa` benchmark score stayed at 33% (2/6)
    across both fixes, even though both mechanisms are independently verified
    working against a real server that validates them server-side. The
    remaining gap is a `vulnerables/web-dvwa`-image-specific detail not yet
    root-caused (candidates: MySQL init lagging the web server becoming
    reachable, so the DB-setup POST races an unready database; or this
    image's exact field names differing from the classic DVWA form) — not
    something debuggable without interactive access to the ephemeral CI
    container. The CSRF-login and post-login mechanisms themselves are real,
    general-purpose, shipped features regardless; this specific target's
    number is an open follow-up, published as such rather than implied fixed.
  - **Follow-up C — auto-discover a target's own OpenAPI spec.** ✅ **Done.**
    ReconBot now probes well-known spec paths (`/openapi.json`,
    `/swagger.json`, `/api/openapi.json`, `/.well-known/openapi.json`, …) and,
    on a hit, parses it through the same engine `--api-spec` uses and seeds
    every endpoint it declares — no flag needed. Verified live: with zero
    flags, the swarm discovered and attacked an endpoint that existed *only*
    in a spec (no HTML link anywhere), the exact VAmPI-style gap this closes.
    Confirmed against the real target: re-running the benchmark moved `vampi`
    from 0% (0/5) to **20% (1/5)**, findings up from 3 to 11.
- **v1.0.2 · Integrations.** ✅ **Done.** DefectDojo needed no new code — its
  built-in **SARIF** import type already accepts Argus's existing
  `--format sarif` output. New `argus report --format jira` writes a
  Jira-importable CSV (one issue per finding, mapped Summary/Description/
  Priority/Labels) for Jira's built-in CSV importer — no API/credentials
  needed. Verified live via the CLI against a real scan.
- **v1.0.3 · Docs site + hardening.** ✅ **Done.** New `docs/` guide set
  (getting started, authenticated scanning, CI integration, troubleshooting).
  MCP server tools (`argus_scan`/`argus_attack`/`argus_fix`) now return a
  structured `{"error": ...}` dict on failure instead of a raw exception
  through the protocol, matching `argus_fix`'s existing pattern.

---

## Distribution & ecosystem — adoption multipliers (parallel track)

These don't gate 1.0 on the engine side, but they're how Argus actually gets
*used*: each one puts Argus in front of new developers or makes it a daily
habit. Build them in parallel with the milestones above — cheapest-first.

- **D1 · `pre-commit` hook.** ✅ **Done (v0.2.0+).** `argus precommit` +
  `.pre-commit-hooks.yaml` (`id: argus`, `argus-strict`) gate commits on secrets
  and vulnerable patterns using the fast deterministic passes only. The
  most-loved shift-left pattern of 2026, and every install is a developer using
  Argus *daily*.
- **D2 · "Scanned by Argus" README badge.** ✅ **Done.** A static shields.io
  badge with copy-pasteable markdown, documented in the README — free social
  proof and backlinks that compound forever.
- **D3 · Argus as an MCP server.** ✅ **Done.** `argus mcp-server` (optional
  `argus-panoptes[mcp]` extra) exposes `argus_scan`/`argus_attack`/`argus_fix` as MCP
  tools so Copilot/Cursor/Claude Code can run Argus from inside the editor.
  Every tool redirects the engine's Rich console output away from stdout
  (required — stdio *is* the JSON-RPC transport) and returns structured JSON.
  Verified live through the real MCP `call_tool` protocol path: zero stdout
  leakage, real findings returned, including a genuine async-nesting bug found
  and fixed (`argus_attack` must `await` the orchestrator directly rather than
  going through its sync `asyncio.run()` wrapper, since the tool call already
  runs inside an event loop).
- **D4 · GitHub App / PR bot.** One-click install that auto-scans PRs and posts
  inline comments (shares plumbing with v0.5.2). This is how a tool spreads
  through a team virally — one dev installs it, everyone sees Argus on every PR.
  *Medium-high.*
- **D5 · VS Code / IDE extension.** Inline findings in the editor (the deferred
  UPGRADE.md #12). Big adoption lever, but only ship once it can be verified in
  a real editor host. *High.*

## Proof is marketing (why v1.0.1 is also the growth engine)

The benchmark suite (v1.0.1) isn't just an engineering gate — it's the best
content Argus can publish. "We pointed Argus at Juice Shop / DVWA and here's
what it caught, with the exploit PoCs" is exactly the peer-trust, proof-over-
claims material that earns stars in security circles. Ship it early, publish the
numbers, refresh them each release, and pair the launch sequence (Show HN →
Reddit r/netsec → dev.to → Product Hunt) with real detection data rather than a
pitch. The instant-try `argus demo` + published benchmarks + the pre-commit
habit is a stronger growth engine than any amount of posting.

---

## Explicitly NOT in 1.0 (scope discipline)

- Org-wide asset graphs / exposure-management dashboards (enterprise).
- CSPM / cloud-account posture scanning (different product).
- SIEM/Sentinel correlation, multi-tenant SaaS, RBAC/teams.
- A hosted service — Argus stays local-first and self-hosted.
- Mobile app testing (XBOW's 2026 item; not Argus's audience).

## Priority at a glance

| Priority | Item | Milestone | Why it's ranked here |
|---|---|---|---|
| **P0** | Authenticated attack sessions | v0.3.1 | Unlocks attacking real apps at all |
| **P0** | Secret-scan noise reduction | v0.4.1 | Cheapest fix for the biggest visible flaw |
| **P0** | Benchmark suite | v1.0.1 | The only thing that *proves* Argus works |
| **P0** | `pre-commit` hook + README badge | D1, D2 | Cheapest adoption wins — daily use + social proof |
| **P1** | API schema ingestion | v0.3.2 | Modern surface is API-first |
| **P1** | SCA reachability | v0.4.2 | Kills the majority of dep false positives |
| **P1** | Auto-fix PRs | v0.5.1 | Closes the remediation loop in CI |
| **P1** | Argus as an MCP server | D3 | Rides the biggest 2026 distribution trend |
| **P2** | BOLA/BFLA, image CVEs, PR comments, sandbox stacks | v0.3–0.5 | Depth once the spine exists |
| **P2** | VEX, behavioral dep analysis, LLM taint-tracing, deeper MCP | v0.3–0.4 | On-trend detection depth |
| **P2** | GitHub App, VS Code extension, integrations, docs | D4–D5, v1.0 | Reach + polish |
| **P2** | JS-aware crawling, CSRF-aware login, auto-discover OpenAPI spec | v1.0.1 follow-ups | Real gaps the benchmark surfaced |

---

*Sources for the market survey behind this plan: XBOW, Aikido, Snyk, Escape,
StackHawk, Invicti, Checkmarx, and OX Security public materials (2026). Argus
remains scoped for individual developers and small teams, not enterprise
security organizations.*
