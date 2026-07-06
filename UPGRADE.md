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

### 3. Executive-summary-first report structure
Reorder the HTML/PDF report to lead with a one-screen summary (risk score,
critical/high counts, top 3-5 risks by severity) before the full findings
table, instead of the table being the first thing a reader sees.
- **Inspired by:** Wiz's exec-summary-first dashboard, Snyk's categorized
  report tabs.
- **Effort:** Low. Purely a template reorder in
  `argus/report/templates/report.html.j2` plus the PDF path — no new data.
- **GUI-only:** Yes.

---

## Tier 2 — needs real engine work, still high value

### 4. Finding lifecycle states + suppression rules
Findings gain a state beyond just "present in the latest scan": Open →
Reviewing → Ignored → Fixed. An ignored finding (with a reason) shouldn't
resurface as new on every subsequent scan.
- **Inspired by:** Semgrep AppSec Platform's Open/Reviewing/Ignored/Fixed
  lifecycle.
- **Effort:** Medium. Needs a small persistent store keyed on finding
  signature (reuse `_signature()`), plus GUI affordances to change state and
  a scan-side check against previously-suppressed signatures.
- **Depends on:** pairs naturally with #2 once that exists.

### 5. One-click "Generate Fix PR"
Extend `argus fix` so that instead of (or in addition to) writing a local
patch, it can open an actual pull request on GitHub with the diff, commit
message, and explanation — closing the loop all the way to review-ready.
- **Inspired by:** Corgea's core product — this is their entire pitch.
- **Effort:** Medium. The diff-generation and validation logic already
  exists in `argus/fix.py`/`argus/llm/reasoning.py`; this adds a GitHub API
  call (branch, commit, PR) behind a new `--pr` flag. Needs a GitHub token
  (PAT or GitHub App) from the user.

### 6. SBOM export (CycloneDX / SPDX)
Add `argus report --format sbom` (or a dedicated `argus sbom` command)
producing a standard Software Bill of Materials from the dependency data
Argus already collects during supply-chain scanning.
- **Inspired by:** Aikido's one-click SBOM export in CycloneDX/SPDX/CSV.
- **Effort:** Medium. Mostly a new formatter over data
  `argus/scanner/dependencies.py` and `supplychain.py` already gather; the
  hard part is normalizing package versions/licenses into the SBOM spec
  correctly.

### 7. Slack / Discord webhook notifications
A configurable webhook (`argus config --notify-webhook <url>`) that posts a
short message when a scan completes or a critical finding is confirmed —
sized for a solo dev or small team living in Slack/Discord, not an
enterprise ticketing queue.
- **Inspired by:** Aikido's finding→ticket workflow, scoped down from Jira/
  Linear (overkill for this audience) to a single webhook POST.
- **Effort:** Low-medium. One HTTP POST at the end of `run_scan`/`run_attack`,
  gated by a config flag; no new UI needed beyond a Settings field.

### 8. Risk-based prioritization score
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
