# Argus Upgrade Roadmap

A prioritized backlog of features worth adding next, grounded in a competitive
survey of XBOW, PentAGI, Corgea, Aikido Security, CloudSEK, Snyk, Semgrep
AppSec Platform, GitHub Advanced Security, and Wiz (see each item's "Inspired
by" note). Ranked for Argus's actual audience — solo developers and small,
fast-moving teams — not enterprise security orgs, so several
enterprise-flavored competitor features (heavyweight compliance scoring,
org-wide asset graphs) are deliberately deprioritized or scoped down.

Each item notes: what it is, why it's worth building, rough effort, and
whether it's a GUI-only addition or needs engine work.

---

## Tier 1 — GUI-only, cheap, high-visibility

These need no new engine capability — Argus already produces the underlying
data (a `ScanResult` per run, persisted via `argus/state.py`); these are
purely about presenting it better.

### 1. Scan-over-time risk trend graph — ✅ Done
Show risk score (and finding counts by severity) plotted across a repo's scan
history on the Dashboard, instead of only ever showing the latest scan.
- **Inspired by:** GitHub Advanced Security's per-repo risk trend, Wiz's
  posture-over-time view.
- **Effort:** Low. Needs scan history to be retained (currently only the most
  recent result is persisted per target) and a simple line/area chart.
- **GUI-only:** Yes.
- **Shipped as:** `argus/state.py` history persistence (`~/.argus/scan_history.jsonl`,
  capped at 200 entries) + `argus history` CLI command + a Dashboard trend
  graph and real "Recent Audits" list in the desktop GUI. Falls back to the
  bundled demo data until at least one real scan has run.

### 2. Scan-to-scan comparison view — ✅ Done
"What's new since last scan / what got fixed" — a diff between two
`ScanResult`s by finding signature (category + file/endpoint + normalized
title), not just two independent findings tables side by side.
- **Inspired by:** Semgrep's finding-lifecycle diffing, Snyk's
  remediation-over-time view.
- **Effort:** Low-medium. The signature-matching logic already exists (built
  for fix-and-reverify in `argus/pipeline.py::_signature`) and can be reused
  directly.
- **GUI-only:** Yes (once scan history exists per #1).
- **Shipped as:** turned out to need one small piece of engine work, not pure
  GUI — `argus/state.py` now retains one prior full scan
  (`~/.argus/previous_scan.json`), since the history file from #1 only stores
  summary stats, not full findings. The signature-matching logic moved into a
  new shared `argus/compare.py` (`finding_signature`/`diff_results`), reused
  by both this and fix-and-reverify. New `argus compare` CLI command; the
  Reports screen shows a "SINCE LAST SCAN" panel with new/fixed finding
  titles when a comparison is available. Known scope limit: only compares the
  two most recent scans (not arbitrary historical pairs), and multiple
  findings sharing the same category+file+title collapse to one signature
  (matches the existing fix-and-reverify tradeoff — a fix to *one* of several
  identical-looking findings won't show as a partial fix).

### 3. Executive-summary-first report structure — ✅ Done
Reorder the HTML/PDF report to lead with a one-screen summary (risk score,
critical/high counts, top 3-5 risks by severity) before the full findings
table, instead of the table being the first thing a reader sees.
- **Inspired by:** Wiz's exec-summary-first dashboard, Snyk's categorized
  report tabs.
- **Effort:** Low. Purely a template reorder in
  `argus/report/templates/report.html.j2` plus the PDF path — no new data.
- **GUI-only:** Yes.
- **Shipped as:** a new "Top Risks" section (the top 5 CRITICAL/HIGH findings,
  computed once in `argus/report/exporters.py::_ctx`) rendered right after the
  risk-score summary and before the Codebase/full-findings sections — in both
  the HTML template (PDF reuses the same HTML, so it inherits this for free)
  and the Markdown exporter, for consistency across every format. Omitted
  entirely when there's nothing CRITICAL/HIGH, so a clean scan's summary
  isn't cluttered with an empty section.

---

## Tier 2 — needs real engine work, still high value

### 4. Finding lifecycle states + suppression rules — ✅ Done
Findings gain a state beyond just "present in the latest scan": Open →
Reviewing → Ignored → Fixed. An ignored finding (with a reason) shouldn't
resurface as new on every subsequent scan.
- **Inspired by:** Semgrep AppSec Platform's Open/Reviewing/Ignored/Fixed
  lifecycle.
- **Effort:** Medium. Needs a small persistent store keyed on finding
  signature (reuse `_signature()`), plus GUI affordances to change state and
  a scan-side check against previously-suppressed signatures.
- **Depends on:** pairs naturally with #2 once that exists.
- **Shipped as:** new `argus/suppressions.py` keyed on `finding_signature()`
  (from #2's `argus/compare.py`), persisted per-target in
  `~/.argus/suppressions.json`. `argus scan` now filters ignored findings out
  of the visible results entirely (they no longer count toward risk score)
  and tags "reviewing" findings in metadata. New `argus suppress <search>
  [--status ignored|reviewing|open] [--reason ...]` and `argus suppressions`
  CLI commands; the GUI's Reports detail panel gets an IGNORE button that
  hides the finding from the current view immediately via a new
  `suppress_finding` Tauri command. Found and fixed a real bug during live
  testing: un-suppressing by title search can't search the *visible* scan
  results (an ignored finding is filtered out of them by design) — it has to
  search the suppression records themselves, which `clear_by_title()` does.

### 5. One-click "Generate Fix PR"
Extend `argus fix` so that instead of (or in addition to) writing a local
patch, it can open an actual pull request on GitHub with the diff, commit
message, and explanation — closing the loop all the way to review-ready.
- **Inspired by:** Corgea's core product — this is their entire pitch.
- **Effort:** Medium. The diff-generation and validation logic already
  exists in `argus/fix.py`/`argus/llm/reasoning.py`; this adds a GitHub API
  call (branch, commit, PR) behind a new `--pr` flag. Needs a GitHub token
  (PAT or GitHub App) from the user.

### 6. SBOM export (CycloneDX / SPDX) — ✅ Done (CycloneDX)
Add `argus report --format sbom` (or a dedicated `argus sbom` command)
producing a standard Software Bill of Materials from the dependency data
Argus already collects during supply-chain scanning.
- **Inspired by:** Aikido's one-click SBOM export in CycloneDX/SPDX/CSV.
- **Effort:** Medium. Mostly a new formatter over data
  `argus/scanner/dependencies.py` and `supplychain.py` already gather; the
  hard part is normalizing package versions/licenses into the SBOM spec
  correctly.
- **Shipped as:** `argus scan/report --format sbom` producing a real
  CycloneDX 1.5 JSON SBOM (`sbom.cdx.json`) with correct `purl`s per
  ecosystem. New `argus/sbom.py` extracts a full package inventory (name +
  version + ecosystem) from `package.json`/`requirements.txt` — a genuinely
  new parser, since the existing supply-chain scanner only looks at manifests
  to hunt for vulnerabilities, never to build a complete list of what's
  there. Collected once at scan time and persisted on `ScanResult` so
  `argus report --format sbom` works later without needing the repo on disk
  again. SPDX format not implemented (CycloneDX covers the same need and
  is the more widely adopted of the two) — worth adding later if a
  specific consumer requires SPDX specifically.

### 7. Slack / Discord webhook notifications — ✅ Done
A configurable webhook (`argus config --notify-webhook <url>`) that posts a
short message when a scan completes or a critical finding is confirmed —
sized for a solo dev or small team living in Slack/Discord, not an
enterprise ticketing queue.
- **Inspired by:** Aikido's finding→ticket workflow, scoped down from Jira/
  Linear (overkill for this audience) to a single webhook POST.
- **Effort:** Low-medium. One HTTP POST at the end of `run_scan`/`run_attack`,
  gated by a config flag; no new UI needed beyond a Settings field.
- **Shipped as:** new `argus/notify.py`, a single best-effort POST sending
  both `text` (Slack) and `content` (Discord) keys in one payload — both
  platforms ignore the key they don't use, so no URL-sniffing is needed.
  Wired into both `run_scan` and `run_attack` right after `save_result`, gated
  on `settings.webhook_url` being set. Found and fixed a real secret-leak gap
  along the way: `argus config --show`'s redaction only masked
  `cloud.*_key` fields — a Slack/Discord webhook URL embeds an equivalent
  bearer token in its path and was printing in full. `Settings.redacted()`
  now masks it the same way. GUI Settings-screen field for this is not yet
  wired (CLI-only for now, consistent with the "low-medium effort" scope).

### 8. Risk-based prioritization score — ✅ Done
Blend severity with exploit likelihood signals (e.g. known-CVE + exploit
maturity for dependency findings, "confirmed" flag weight for Phase-2
findings, confidence level) into a single sortable priority score, instead of
sorting purely by CVSS/severity bucket.
- **Inspired by:** Snyk's Risk Score (EPSS + CVSS + exploit maturity +
  reachability blend) — scoped down since full EPSS integration needs an
  external feed Argus doesn't currently consume.
- **Effort:** Medium-high. Start with a simple weighted formula using data
  already on `Finding` (severity, confidence, confirmed, cvss); revisit a
  real EPSS feed later if it proves valuable.
- **Shipped as:** a new `Finding.priority_score` property (confidence +
  confirmed + CVSS, 0-45) used by `sorted_findings()` as the tie-break
  *within* a severity band — deliberately scoped so it can never make a
  lower-severity finding outrank a higher-severity one (a maxed-out HIGH
  still can't beat a bare CRITICAL), so every existing "worst first" report/
  CLI table gets smarter automatically without the top-level severity
  grouping ever looking surprising. A full EPSS-based score that crosses
  severity bands is a bigger, riskier change deferred for now.

---

## Tier 3 — bigger lifts, lower priority for now

### 9. CI policy-as-code gating
Extend `--fail-on` (today: one global severity threshold) to per-rule/
per-category policies — e.g. fail on any confirmed SQLi but only warn on
missing security headers.
- **Inspired by:** Semgrep AppSec Platform's policy-as-code CI gates.
- **Effort:** Medium-high. Needs a small policy config format and CLI/CI
  wiring; genuinely useful but a bigger surface than the Tier 1-2 items.

### 10. Lightweight OWASP ASVS / PCI-DSS tagging
Tag findings with the specific ASVS control or PCI-DSS requirement they
violate, without building a full compliance-scoring product.
- **Inspired by:** Aikido/Snyk's bundled compliance mapping, deliberately
  scoped down from Wiz's 100+-framework auto-scoring (enterprise territory,
  not this audience).
- **Effort:** Medium. Mostly a static mapping table from
  category/CWE → ASVS/PCI control, applied at report-render time.

### 11. Persistent attack-surface inventory across scans
Track discovered endpoints/assets across multiple scans of the same target
as a standing inventory, rather than each scan starting from zero surface
knowledge.
- **Inspired by:** CloudSEK's continuous attack-surface monitoring (scoped
  down from their org-wide/dark-web monitoring, which is out of scope for a
  single-target tool).
- **Effort:** High. Needs persistent endpoint storage keyed per target and
  changes to how ReconBot/CrawlerBot seed their starting surface.
- **Depends on:** natural to build after #1/#2 establish scan history.

### 12. VS Code / IDE plugin
Surface findings inline in the editor as the user writes code, closer to a
live linter than a periodic scan.
- **Inspired by:** the general trend of AppSec tools shipping IDE
  integrations (Semgrep, Snyk, GitHub Advanced Security all have one).
- **Effort:** High. A genuinely new product surface (a whole extension, a
  language-server-style protocol to the engine) — lowest priority given team
  size and the effort-to-audience-value ratio right now.

---

## Suggested build order

1. Tier 1 in full (#1 → #2 → #3) — cheapest, most visible, no engine risk.
2. #4 (lifecycle/suppression) and #7 (webhook) — low-medium effort, pairs well
   with what Tier 1 just built.
3. #5 (fix PRs) and #6 (SBOM) — the two most differentiated engine features
   from this list.
4. #8 (risk score) once the above are settled.
5. Tier 3 items opportunistically, or when a specific user need justifies the
   bigger lift.
