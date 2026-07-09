# Argus documentation

Guides that go deeper than the [main README](../README.md)'s quick-start. Each
is self-contained — read the one you need.

- **[Getting Started](getting-started.md)** — install, first scan, first
  attack, reading the output.
- **[Authenticated Scanning](authenticated-scanning.md)** — attacking behind a
  login: static credentials, form login, CSRF-protected forms, a post-login
  unlock step, OAuth2, and BOLA/BFLA testing with a second identity.
- **[CI Integration](ci-integration.md)** — the GitHub Action, policy-as-code
  gating, diff-aware and baseline scanning, PR review comments, and wiring
  Argus into a pipeline that isn't GitHub Actions.
- **[Troubleshooting](troubleshooting.md)** — common errors and what they
  mean, from "no LLM provider configured" to a sandbox that never becomes
  reachable.

For the API/architecture-level reference, the code itself is documented at the
module level — start at [`argus/pipeline.py`](../argus/pipeline.py) for the
top-level orchestration, or [`ROADMAP.md`](../ROADMAP.md) for the history of
how the project got here.

## Internal / historical

- **[`dev/ARGUS_CONTEXT.md`](dev/ARGUS_CONTEXT.md)** — the original full
  project spec Argus was built from. Useful if you want the complete
  architecture/design-system rationale in one place.
- **[`dev/UPGRADE.md`](dev/UPGRADE.md)** — the pre-1.0 backlog, superseded by
  [`ROADMAP.md`](../ROADMAP.md) and now fully shipped. Kept for history.
- **[`dev/SCREENSHOTS.md`](dev/SCREENSHOTS.md)** — verified repro steps for
  generating a real (non-fabricated) populated report and capturing GUI
  screenshots for the README/marketing, since the GUI ships with no bundled
  demo data by design.
