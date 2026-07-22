"""Auto-generates a minimal Dockerfile for the handful of stacks Argus can
confidently guess a start command for, plus detection of an existing
docker-compose file with an explicitly published port.

Deliberately conservative: a wrong guess produces a container that silently
never starts, which for a security tool means an honest target gets reported
as "zero findings" instead of "couldn't sandbox this" — a dangerous false
negative. Better to recognize fewer stacks correctly than more stacks wrong.
Every probe here either finds an unambiguous, near-universal convention (a
framework's own entry-point file, an explicit `ports:` mapping) or declines —
never a best-effort guess at an entrypoint filename.

``generate_dockerfile_via_llm`` is the one exception, and it's only ever
reached after every deterministic probe above has already declined. An LLM
guess is inherently less reliable than a hardcoded convention match — but the
false-negative risk this module is designed around is neutralised one layer
up: ``Sandbox.start()`` actually HTTP-pings the built container and raises a
loud, clear ``SandboxError`` if it never becomes reachable, rather than
quietly proceeding to attack whatever came up. A wrong LLM guess fails the
build or the reachability check; it can't silently produce a false "0
findings, target is clean" the way it could if nothing verified the result.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")


def find_existing_dockerfile(root: Path) -> tuple[str, int] | None:
    """If the repo already ships a Dockerfile, use it as-is.

    Returns (dockerfile_name, guessed_container_port). The port is parsed from
    an ``EXPOSE`` line if present — EXPOSE is documentation only (it doesn't
    actually configure networking), so this is a best-effort guess, not a
    guarantee; falls back to 8080.
    """
    path = root / "Dockerfile"
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8", errors="ignore")
    match = re.search(r"^\s*EXPOSE\s+(\d+)", text, re.MULTILINE | re.IGNORECASE)
    port = int(match.group(1)) if match else 8080
    return "Dockerfile", port


def generate_dockerfile(root: Path) -> tuple[str, int] | None:
    """Returns (dockerfile_content, container_port), or None if the stack
    can't be confidently determined — caller should fall back to ``--url``.
    """
    # _try_static is deliberately last and most permissive (any index.html) —
    # a repo with a real backend framework always matches one of the earlier,
    # narrower probes first, so this can't accidentally shadow a dynamic app
    # and silently turn its findings into "just static HTML, nothing to see".
    for probe in (_try_django, _try_flask, _try_fastapi, _try_rails, _try_node, _try_php, _try_static):
        result = probe(root)
        if result is not None:
            return result
    return None


_MAX_READ_BYTES = 2_000_000  # generous for any real source/manifest/entry-point file


def _read_text(path: Path) -> str:
    try:
        if path.stat().st_size > _MAX_READ_BYTES:
            return ""  # a stray huge file (accidental or adversarial) — skip, don't load it whole
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _try_django(root: Path) -> tuple[str, int] | None:
    # manage.py is a strong, near-universal Django convention — reliable
    # enough to guess "python manage.py runserver" with confidence.
    if not (root / "manage.py").exists():
        return None
    if not (root / "requirements.txt").exists():
        return None
    dockerfile = (
        "FROM python:3.12-slim\n"
        "WORKDIR /app\n"
        "COPY . .\n"
        "RUN pip install --no-cache-dir -r requirements.txt\n"
        "ENV PYTHONUNBUFFERED=1\n"
        "EXPOSE 8000\n"
        'CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]\n'
    )
    return dockerfile, 8000


def _try_flask(root: Path) -> tuple[str, int] | None:
    req = root / "requirements.txt"
    if not req.exists():
        return None
    req_text = _read_text(req).lower()
    if not re.search(r"^\s*flask\b", req_text, re.MULTILINE):
        return None
    # Find the module that instantiates a Flask app — the near-universal
    # `Flask(__name__)` pattern — rather than guessing a filename.
    entry = _find_module_matching(root, re.compile(r"\bFlask\s*\("))
    if entry is None:
        return None
    module = entry.relative_to(root).with_suffix("").as_posix().replace("/", ".")
    dockerfile = (
        "FROM python:3.12-slim\n"
        "WORKDIR /app\n"
        "COPY . .\n"
        "RUN pip install --no-cache-dir -r requirements.txt\n"
        "ENV PYTHONUNBUFFERED=1 FLASK_APP=" + module + "\n"
        "EXPOSE 5000\n"
        'CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]\n'
    )
    return dockerfile, 5000


def _try_fastapi(root: Path) -> tuple[str, int] | None:
    req = root / "requirements.txt"
    if not req.exists():
        return None
    req_text = _read_text(req).lower()
    if "fastapi" not in req_text or "uvicorn" not in req_text:
        return None
    entry = _find_module_matching(root, re.compile(r"\bFastAPI\s*\("))
    if entry is None:
        return None
    module = entry.relative_to(root).with_suffix("").as_posix().replace("/", ".")
    var = _fastapi_app_var(entry) or "app"
    dockerfile = (
        "FROM python:3.12-slim\n"
        "WORKDIR /app\n"
        "COPY . .\n"
        "RUN pip install --no-cache-dir -r requirements.txt\n"
        "ENV PYTHONUNBUFFERED=1\n"
        "EXPOSE 8000\n"
        f'CMD ["uvicorn", "{module}:{var}", "--host", "0.0.0.0", "--port", "8000"]\n'
    )
    return dockerfile, 8000


def _fastapi_app_var(entry: Path) -> str | None:
    m = re.search(r"(\w+)\s*=\s*FastAPI\s*\(", _read_text(entry))
    return m.group(1) if m else None


def _find_module_matching(root: Path, pattern: re.Pattern, max_files: int = 200) -> Path | None:
    """The shallowest Python file (repo root first, then one level down) whose
    content matches ``pattern`` — deliberately shallow so it doesn't wander
    into vendored/test code and misidentify the app's real entry point."""
    candidates: list[Path] = []
    for depth_glob in ("*.py", "*/*.py"):
        candidates.extend(sorted(root.glob(depth_glob)))
        if len(candidates) > max_files:
            break
    skip_dirs = {"tests", "test", "venv", ".venv", "node_modules", "migrations"}
    for path in candidates[:max_files]:
        if set(path.parts) & skip_dirs:
            continue
        if pattern.search(_read_text(path)):
            return path
    return None


def _try_rails(root: Path) -> tuple[str, int] | None:
    gemfile = root / "Gemfile"
    if not gemfile.exists() or not (root / "config.ru").exists():
        return None
    if not re.search(r"^\s*gem\s+['\"]rails['\"]", _read_text(gemfile), re.MULTILINE):
        return None
    dockerfile = (
        "FROM ruby:3.3-slim\n"
        "WORKDIR /app\n"
        "RUN apt-get update -qq && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*\n"
        "COPY . .\n"
        "RUN bundle install\n"
        "ENV RAILS_ENV=development\n"
        "EXPOSE 3000\n"
        'CMD ["bundle", "exec", "rails", "server", "-b", "0.0.0.0"]\n'
    )
    return dockerfile, 3000


# Dev-server frameworks confident enough to run via their own dev command when
# no production "build"+"start" pair exists — each binds and serves immediately,
# unlike a generic "dev" script which could mean anything.
_DEV_SERVER_DEPS = {"next": "next dev", "vite": "vite --host", "react-scripts": "react-scripts start"}


def _try_node(root: Path) -> tuple[str, int] | None:
    pkg = root / "package.json"
    if not pkg.exists():
        return None
    try:
        data = json.loads(_read_text(pkg))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
    deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}

    if "start" in scripts:
        # A production start script often needs a build first (Next.js/Vite
        # apps ship "build" + "start"); run it when present, harmless no-op
        # otherwise (most "start" scripts don't need a preceding build).
        build_step = "RUN npm run build\n" if "build" in scripts else ""
        cmd = "npm start"
    else:
        framework = next((f for f in _DEV_SERVER_DEPS if f in deps), None)
        if framework is None:
            return None
        build_step = ""
        cmd = _DEV_SERVER_DEPS[framework]

    dockerfile = (
        "FROM node:20-slim\n"
        "WORKDIR /app\n"
        "COPY . .\n"
        "RUN npm install\n"
        f"{build_step}"
        "ENV PORT=3000 HOST=0.0.0.0\n"
        "EXPOSE 3000\n"
        f'CMD ["sh", "-c", "{cmd}"]\n'
    )
    return dockerfile, 3000


def _try_php(root: Path) -> tuple[str, int] | None:
    # index.php at the repo root is as near-universal a PHP entry-point
    # convention as manage.py is for Django — this is exactly the shape of a
    # basic student/beginner PHP project (very common on GitHub, and exactly
    # the kind of repo with no Dockerfile that used to get silently skipped).
    if not (root / "index.php").exists():
        return None
    dockerfile = (
        "FROM php:8.3-cli\n"
        "WORKDIR /app\n"
        "COPY . .\n"
        "EXPOSE 8000\n"
        'CMD ["php", "-S", "0.0.0.0:8000"]\n'
    )
    return dockerfile, 8000


_STATIC_ENTRY_NAMES = ("index.html", "index.htm")
_STATIC_SUBDIRS = ("", "public", "dist", "build")


def _try_static(root: Path) -> tuple[str, int] | None:
    """A plain static site (HTML/CSS/JS, no backend) — nothing above matched,
    but there's an index.html to serve. Unambiguous: nginx serves whatever
    files exist, so this can't produce a wrong-but-running container the way
    guessing a backend start command could."""
    for sub in _STATIC_SUBDIRS:
        base = root / sub if sub else root
        if any((base / name).exists() for name in _STATIC_ENTRY_NAMES):
            copy_src = f"{sub} " if sub else ". "
            dockerfile = (
                "FROM nginx:alpine\n"
                f"COPY {copy_src}/usr/share/nginx/html\n"
                "EXPOSE 80\n"
            )
            return dockerfile, 80
    return None


def find_compose_file(root: Path) -> Path | None:
    for name in _COMPOSE_NAMES:
        p = root / name
        if p.exists():
            return p
    return None


def _compose_host_port(port_spec) -> int | None:
    """Extract the host-facing port from one compose `ports:` entry, or None if
    it doesn't publish to the host (e.g. a bare container-only port)."""
    if isinstance(port_spec, dict):
        published = port_spec.get("published")
        try:
            return int(published) if published else None
        except (TypeError, ValueError):
            return None
    if isinstance(port_spec, int):
        return None  # a bare int is container-only, not published to the host
    if isinstance(port_spec, str):
        parts = port_spec.split(":")
        if len(parts) < 2:
            return None  # "8000" alone — container-only
        try:
            return int(parts[-2])  # "host:container" or "bindip:host:container"
        except ValueError:
            return None
    return None


def compose_target(root: Path) -> tuple[Path, int] | None:
    """(compose_file, host_port) for the first service with an explicit
    host-published port, or None — never guesses an unpublished port."""
    path = find_compose_file(root)
    if path is None:
        return None
    try:
        import yaml

        data = yaml.safe_load(_read_text(path)) or {}
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    for svc in (data.get("services") or {}).values():
        if not isinstance(svc, dict):
            continue
        for spec in svc.get("ports") or []:
            port = _compose_host_port(spec)
            if port:
                return path, port
    return None


# Manifest files worth showing the LLM in full (capped) when nothing
# deterministic matched — the near-universal "what stack is this" signal for
# each ecosystem the hardcoded probes above don't already cover.
_MANIFEST_NAMES = (
    "go.mod", "pom.xml", "build.gradle", "build.gradle.kts", "Cargo.toml",
    "composer.json", "pyproject.toml", "setup.py", "mix.exs",
)
_MANIFEST_GLOBS = ("*.csproj", "*.sln")
_FINGERPRINT_SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "vendor", "dist", "build",
    ".next", "target", "bin", "obj", "__pycache__",
}
_MAX_MANIFEST_CHARS = 1500


def _repo_fingerprint(root: Path) -> dict:
    """A compact, cheap-to-send summary of the repo for the LLM prompt: the
    top-level listing plus the contents of whichever manifest files exist.
    Never the full source tree — this is meant to identify the *stack*, not
    review the code."""
    entries: list[str] = []
    try:
        # Cap how many raw directory entries are even looked at (let alone
        # sorted / stat'd for is_dir()) before any of the entries[:60] slicing
        # below would otherwise kick in — a directory with tens of thousands
        # of top-level entries (a data-dump repo, or one shaped to be slow)
        # would otherwise pay that full cost on every attack against it.
        raw = []
        for i, p in enumerate(root.iterdir()):
            if i >= 500:
                break
            raw.append(p)
        for p in sorted(raw, key=lambda x: x.name):
            if p.name in _FINGERPRINT_SKIP_DIRS or p.name.startswith("."):
                continue
            entries.append(p.name + ("/" if p.is_dir() else ""))
    except OSError:
        pass

    manifests: dict[str, str] = {}
    for name in _MANIFEST_NAMES:
        p = root / name
        if p.exists():
            manifests[name] = _read_text(p)[:_MAX_MANIFEST_CHARS]
    for pattern in _MANIFEST_GLOBS:
        for p in root.glob(pattern):
            manifests[p.name] = _read_text(p)[:_MAX_MANIFEST_CHARS]
            break  # one example is enough to identify the stack

    readme_text = ""
    for name in ("README.md", "README", "readme.md"):
        p = root / name
        if p.exists():
            readme_text = "\n".join(_read_text(p).splitlines()[:30])
            break

    return {
        "top_level_entries": entries[:60],
        "manifest_files": manifests,
        "readme_excerpt": readme_text[:1500],
    }


_FROM_LINE = re.compile(r"^\s*FROM\s+", re.MULTILINE | re.IGNORECASE)
_JSON_OBJ = re.compile(r"\{.*\}", re.DOTALL)


def _extract_json_object(text: str) -> dict | None:
    """Pull a JSON object out of an LLM response that may not be pure JSON —
    wrapped in ```json fences, or preceded by a sentence of prose despite
    json_mode/"respond ONLY with valid JSON" instructions. The same regex-
    extraction pattern already used for this exact problem elsewhere in this
    codebase (argus/llm/reasoning.py's _extract_json, argus/agents/
    businesslogic.py's plan parsing) — a raw json.loads() on the untouched
    response text is known, from those, not to be reliable enough on its own,
    especially against smaller local models."""
    m = _JSON_OBJ.search(text)
    if not m:
        return None
    try:
        parsed = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _extract_dockerfile(data) -> tuple[str, int] | None:
    """Validate one LLM response shape. None on anything unusable — never
    raises, so the caller's broad except isn't the only thing standing
    between a malformed response and a crash."""
    if not isinstance(data, dict) or not data.get("confident"):
        return None
    dockerfile = data.get("dockerfile")
    port = data.get("port")
    if not isinstance(dockerfile, str) or not dockerfile.strip():
        return None
    # A quantized/local model in json_mode has been observed elsewhere in
    # this codebase to occasionally emit a number as a string ("8000") even
    # when explicitly told to return an integer — accept that shape rather
    # than discard an otherwise-valid, confident response over it.
    if isinstance(port, str) and port.strip().isdigit():
        port = int(port.strip())
    if not isinstance(port, int) or isinstance(port, bool) or not (0 < port < 65536):
        return None
    if "FROM" not in dockerfile.upper():
        return None  # doesn't even look like a Dockerfile — don't trust it
    return dockerfile, port


def generate_dockerfile_via_llm(root: Path, provider) -> tuple[str, int] | None:
    """Last resort when every deterministic probe above declined: ask the
    configured LLM to identify the stack and write a Dockerfile. Returns None
    on absolutely any failure (network, malformed JSON, the model saying
    it isn't confident) — this must never raise, since a repo Argus simply
    can't sandbox is a completely normal, expected outcome, not an error.
    See the module docstring for why a wrong guess here is safe: the caller
    (Sandbox.start) verifies the container actually becomes reachable before
    trusting it.

    One corrective retry when the first response is a multi-stage build: in
    practice (observed live against a real Go repo with a local 7B model) a
    smaller model doesn't reliably follow the "prefer single-stage" prompt
    instruction on the first try, and multi-stage compiled-language builds
    are exactly where a glibc-builder/musl-final-stage mismatch produces a
    binary that can't even execute — a container that builds fine but the
    app inside never runs. Rather than trust that riskier shape, ask once
    more for something simpler; if the retry is multi-stage too, give up
    rather than gamble on a container the sandbox's reachability check would
    likely have to reject anyway.
    """
    if provider is None:
        return None
    from argus.llm.prompts import DOCKERFILE_SYSTEM, build_dockerfile_user

    try:
        fingerprint = _repo_fingerprint(root)
        if not fingerprint["manifest_files"] and not fingerprint["top_level_entries"]:
            return None
        result = provider.complete(DOCKERFILE_SYSTEM, build_dockerfile_user(fingerprint), json_mode=True)
        data = _extract_json_object(result.text)
    except Exception:  # noqa: BLE001 — any failure here just means "couldn't", not a crash
        return None

    extracted = _extract_dockerfile(data)
    if extracted is None:
        return None
    dockerfile, port = extracted
    if len(_FROM_LINE.findall(dockerfile)) <= 1:
        return dockerfile, port

    # Multi-stage — ask once more for something simpler.
    try:
        retry_user = (
            build_dockerfile_user(fingerprint)
            + "\n\nYour previous suggestion used a multi-stage build:\n```\n"
            + dockerfile[:1500]
            + "\n```\nThat risks a glibc/musl base-image mismatch that would build fine but never "
            "actually run. Return a SINGLE-STAGE Dockerfile instead (exactly one FROM line), even "
            "if the resulting image is larger — reliability matters more here than size."
        )
        result = provider.complete(DOCKERFILE_SYSTEM, retry_user, json_mode=True)
        retry_data = _extract_json_object(result.text)
    except Exception:  # noqa: BLE001
        return None

    retry_extracted = _extract_dockerfile(retry_data)
    if retry_extracted is None:
        return None
    retry_dockerfile, retry_port = retry_extracted
    if len(_FROM_LINE.findall(retry_dockerfile)) > 1:
        return None  # still multi-stage — decline rather than gamble
    return retry_dockerfile, retry_port


# Every generated Dockerfile above does `COPY . .` (the whole repo) into the
# image — for _try_static/_try_php specifically, the resulting container then
# serves any file verbatim from that copy, so a real repo's own `.git/` (git
# history, possibly containing secrets already removed from the working
# tree) or `.env` (live credentials, if the developer is scanning an
# uncommitted local checkout) would be reachable at its literal path for the
# whole duration of the sandboxed attack. Applied to every generated build,
# not just static/PHP, as defense in depth.
_SANDBOX_COPY_EXCLUDES = (".git", ".env", ".env.*", "*.pem", "*.key")


def write_sandbox_dockerignore(root: Path) -> tuple[Path, str | None]:
    """Ensure the sensitive paths above are excluded from the build context
    for the duration of one sandbox build. Writes directly into the target
    repo's own working tree (that's where the Docker build context is), so
    the caller MUST restore the returned (path, original_content) afterward —
    original_content is None if no .dockerignore existed before, in which
    case the caller should delete the file it created rather than leave it
    behind.
    """
    path = root / ".dockerignore"
    original = _read_text(path) if path.exists() else None
    lines = original.splitlines() if original else []
    for entry in _SANDBOX_COPY_EXCLUDES:
        if entry not in lines:
            lines.append(entry)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path, original


def restore_sandbox_dockerignore(path: Path, original: str | None) -> None:
    """Undo write_sandbox_dockerignore — restore the exact prior state."""
    try:
        if original is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(original, encoding="utf-8")
    except OSError:
        pass
