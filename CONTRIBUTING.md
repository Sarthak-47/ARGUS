# Contributing to Argus

Thanks for helping build the security tool for the vibe-coding era. Contributions
of all kinds are welcome — new attack agents, Semgrep rules, payload lists, bug
fixes, docs.

## Development setup

```bash
git clone https://github.com/Sarthak-47/ARGUS.git
cd ARGUS
python -m venv .venv
# Windows: .venv\Scripts\activate   |   macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
pytest -q          # run the test suite
ruff check argus tests
```

GUI:

```bash
cd gui && npm install && npm run dev
```

## Adding an attack agent

Attack agents live in `argus/agents/` and subclass `BaseAgent`:

1. Create `argus/agents/youragent.py` with a class implementing `async def run(self, ctx)`.
2. Use `ctx.endpoint_list()` for the discovered surface, `self.get/post(...)` for
   safe requests, and `ctx.report(Finding(...))` to record confirmed issues.
3. Register it in `argus/llm/orchestrator.py` (`AGENT_REGISTRY` + `_DEFAULT_ORDER`).
4. Add a unit test in `tests/unit/` for the pure-logic helpers.

Keep agents **safe and bounded**: cap payload counts, respect the concurrency
semaphore, and never crash the run — degrade instead.

## Adding a static rule

Built-in deterministic rules live in `argus/scanner/rules_builtin.py` (regex,
per-language). High-value, low-false-positive rules are preferred.

## Pull requests

- Keep changes focused; one logical change per PR.
- Run `pytest` and `ruff check` before pushing — CI runs both.
- Match the surrounding code style.
- By contributing you agree your work is licensed under the project's MIT license.

## Ground rules

Argus is an offensive tool. Contributions must not add functionality whose primary
purpose is illegal or malicious use. See [SECURITY.md](SECURITY.md).
