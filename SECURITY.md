# Security & Responsible Use

Argus is an **offensive** security tool: its Phase-2 agents actively attack a
target. That power comes with responsibility.

## Authorized use only

**Only run Argus against systems you own or are explicitly authorized to test.**
Attacking systems without permission is illegal in most jurisdictions. You are
solely responsible for how you use this tool.

Argus is built for:

- Auditing your own applications and repositories
- Sanctioned penetration-testing engagements (with written authorization)
- CTF competitions and purpose-built vulnerable targets (DVWA, Juice Shop, WebGoat)
- Security research and education

`argus demo` ships a **bundled, self-contained vulnerable app** so you can see the
full attack flow without touching anything you don't own.

## Safety design

- **Phase 1 (static scan)** never executes target code — it only reads it.
- **Phase 2 (attack)** only touches the target you point it at (`--url`) or an app
  Argus itself spins up in an isolated sandbox. It does not scan or pivot beyond it.
- The callback server used for blind-vulnerability detection binds to localhost.
- Secrets found during scanning are **masked** in output and reports.

## Reporting a vulnerability in Argus

If you find a security issue in Argus itself, please **do not open a public issue**.
Instead, report it privately via GitHub Security Advisories on the repository, or
email the maintainer. We aim to acknowledge reports within a few days.
