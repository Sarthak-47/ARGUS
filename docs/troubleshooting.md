# Troubleshooting

## Phase 2 / sandboxing

**"Couldn't determine how to run this repo automatically..."**
Argus only auto-sandboxes stacks it can confidently recognize: Django
(`manage.py`), Flask/FastAPI (via their own app-instantiation pattern), Rails
(`Gemfile` + `config.ru`), Node with a `start` script (or a recognized
dev-server framework), or a `docker-compose.yml` with an *explicitly published*
port. It deliberately never guesses — a wrong guess would silently produce a
container that never starts, which for a security tool means "zero findings"
gets reported instead of "couldn't test this," a dangerous false negative.
**Fix:** start the app yourself and use `argus attack --url http://localhost:PORT`
instead.

**"docker not installed"** / **"docker installed but daemon not reachable"**
Docker isn't required — it's only used to auto-sandbox a bare repo. Static
scanning (`argus scan`) and attacking an already-running app (`argus attack
--url ...`) both work with zero Docker involvement. If you do want
auto-sandboxing, install Docker Desktop (or the daemon) and make sure it's
running.

**"The sandboxed app never became reachable at ... within Ns"**
The generated/existing Dockerfile built successfully but the app inside never
started listening, or listens on a different port than Argus guessed. Check
the app's actual start command and the Dockerfile's `EXPOSE`.

## Authentication

See [Authenticated Scanning](authenticated-scanning.md#troubleshooting) for
auth-specific errors (bad credentials, a missing CSRF field, needing a
post-login step).

## LLM / `argus fix`

**"No LLM provider configured"**
`argus fix` needs an LLM — there's no deterministic way to write a correct code
patch. Run `argus setup` (detects your GPU, helps pick a local or hosted
model) or `argus config --provider <name> --key <key>` directly. Everything
else (`argus scan`, `argus attack`) works with zero LLM configured via
`--no-llm` / by default respectively for the deterministic passes.

**A patch was skipped: "diff did not match the current file content exactly"**
The LLM's proposed diff didn't content-match the file at patch time (the file
changed, or the LLM's diff was imprecise about context). Argus never guesses a
patch location — a hunk must match exactly once or it's rejected rather than
mis-applied. Re-run `argus fix` to regenerate against the current file state.

## `argus fix --apply --pr`

**"--pr requires --apply"** — a pull request needs the fixes actually written
first; combine both flags.

**"No GitHub authentication found"** — `--pr` needs `gh auth login` (the `gh`
CLI logged in) or a `GH_TOKEN`/`GITHUB_TOKEN` environment variable. Argus never
tries to acquire credentials on your behalf.

**"Working tree has uncommitted changes"** — `--pr` refuses to run against a
dirty repo, so a pre-existing local change never gets swept into the fix
commit. Commit or stash first.

## MCP server

**"The MCP server needs the optional 'mcp' extra"**
`argus mcp-server` needs `pip install 'argus-sec[mcp]'` — it's optional because
the SDK pulls in a fair number of dependencies (pydantic, starlette, uvicorn)
that most CLI-only users don't need.

## Benchmark suite

**A Docker-based case (`juice_shop`/`dvwa`/`vampi`) errors out**
These pull real, sizeable images and need a live Docker daemon — the same
prerequisites as auto-sandboxing above. `argus benchmark --case argus_demo`
runs entirely in-process (no Docker, no network) if you just want to sanity
check the harness itself.

## General

**A scan/attack seems to hang**
Phase 2 against a real target has no progress bar by design — it isn't a
simulation, so there's genuinely nothing to show but elapsed time until an
agent reports something. Very large repos in Phase 1 can also take a while on
the LLM-enrichment step; add `--no-llm` to isolate whether the deterministic
passes alone are fast.

**Still stuck?** Open an issue at
[github.com/Sarthak-47/ARGUS/issues](https://github.com/Sarthak-47/ARGUS/issues)
with the exact command and output.
