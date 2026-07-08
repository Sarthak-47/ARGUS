# CI Integration

## GitHub Actions

```yaml
- uses: Sarthak-47/ARGUS@main
  id: argus
  with:
    target: "."
    fail-on: "critical"      # fail the build on critical findings
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.argus.outputs.sarif-file }}
```

Full input list:

| Input | Default | What it does |
|---|---|---|
| `target` | `.` | Path or repo URL to scan. |
| `fail-on` | (none) | Fail the job at/above this severity: `critical\|high\|medium\|low`. |
| `policy` | (none) | Path to a `.argus-policy.toml` for per-rule gating (overrides `fail-on`). Auto-detected in the target dir if omitted. |
| `diff-base` | (none) | Only report findings in files changed vs. this git ref — the PR-gate model. |
| `baseline` | (none) | Path to a committed baseline file — only findings absent from it are reported/gated. |
| `format` | `sarif` | Report format: `sarif\|json\|html\|markdown`. |
| `pr-comments` | `false` | Post new findings as inline PR review comments. Needs `permissions: pull-requests: write`. |
| `version` | latest | Pin an Argus version/ref instead of installing latest from PyPI. |

## Policy-as-code (finer than a single threshold)

A single `--fail-on` threshold is coarse — it can't say "fail on any confirmed
SQLi but only warn on missing headers." Drop a `.argus-policy.toml` at your
repo root (or pass `--policy <file>` / the Action's `policy` input) instead.
See [`.argus-policy.example.toml`](../.argus-policy.example.toml) for the full
rule syntax (match by severity, category, detector prefix, or confirmed
status; first match wins). `argus scan` exits 2 on a policy failure.

## Diff-aware scanning (don't fail CI on a pre-existing backlog)

```bash
argus scan . --diff-base main
```

Reports (and gates on) only findings in files the current branch actually
changed vs. `main` — committed, staged, and untracked changes all count. A
huge pre-existing backlog on `main` doesn't drown out or fail the build on what
*this* PR introduced.

## Baseline (adopting Argus on a repo with an existing backlog)

Diff-aware scanning is git-based (per-PR); a baseline is identity-based
(per-adoption) and needs no git history:

```bash
argus scan . --write-baseline .argus-baseline.json   # once, snapshot everything as accepted
git add .argus-baseline.json && git commit -m "adopt argus baseline"

argus scan . --baseline .argus-baseline.json          # every run after: only new findings
```

Matched by the same signature (category + location + normalized title) `argus
compare` uses, so a finding that merely shifts line numbers stays baselined.

## Inline PR review comments

Add `pr-comments: "true"` to the Action (needs `permissions: pull-requests:
write` on the job) and Argus posts each new finding as a review comment right
on the changed line — not just buried in the SARIF-driven Security tab.
Idempotent (a fingerprint is embedded invisibly in each comment, so re-running
CI on the same commit never double-posts) and a clean no-op outside a
`pull_request` event, so it's safe to leave on unconditionally.

Standalone (any CI, not just the Action): run `argus scan --diff-base <base>`
then `argus pr-comment` — it reuses the just-persisted scan result and reads
the standard `GITHUB_TOKEN`/`GITHUB_REPOSITORY`/`GITHUB_EVENT_PATH` environment
GitHub Actions sets automatically.

## Not using GitHub Actions?

Everything above works from any CI as plain CLI commands + exit codes —
`argus scan --fail-on high` (exit 2 on a threshold breach), `--format sarif`
for any SARIF-consuming platform, `--diff-base`/`--baseline` for noise
control. `argus pr-comment` needs a GitHub PR context specifically (it talks to
GitHub's REST API), but every other command is platform-agnostic.

## Sending findings elsewhere

- **DefectDojo**: `argus scan --format sarif` — DefectDojo has a built-in
  SARIF import type, no extra format needed.
- **Jira**: `argus report --format jira` writes a CSV for Jira's built-in CSV
  importer (one issue per finding). No API token needed.
- **Slack/Discord**: `argus config --notify-webhook <url>` posts a scan
  summary (target, risk score/band, critical/high counts) when a scan
  completes.

## Benchmarking Argus itself

`argus benchmark` runs the swarm against known-vulnerable apps (OWASP Juice
Shop, DVWA, VAmPI, plus Argus's own bundled demo target) and reports a real
detection rate. See [`.github/workflows/benchmark.yml`](../.github/workflows/benchmark.yml)
for the CI wiring, or [ROADMAP.md](../ROADMAP.md) for the current published
numbers.
