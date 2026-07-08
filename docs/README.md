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
top-level orchestration, or [`ROADMAP.md`](../ROADMAP.md) for where the
project is headed.
