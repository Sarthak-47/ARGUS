"""Default values, model mappings, and static lookup tables.

Single place for the constants the rest of the engine reads so behaviour is easy to
audit and tweak. Mirrors the tables in ARGUS_CONTEXT.md.
"""

from __future__ import annotations

APP_NAME = "argus"

# ---- LLM: local model recommendation by available VRAM (GB) ----
# Pick the largest model whose VRAM key is <= detected VRAM.
VRAM_MODEL_MAP: dict[int, str] = {
    4: "qwen2.5-coder:3b",
    6: "qwen2.5-coder:7b",
    8: "llama3.1:8b",
    12: "qwen2.5-coder:14b",      # RTX 4070 tier
    16: "qwen2.5:32b-q4_K_M",
    24: "llama3.3:70b-q4_K_M",
    40: "llama3.1:70b",
}

# ---- Cloud providers (BYOK) ----
CLOUD_PROVIDERS = ("groq", "gemini", "claude", "openrouter")
ALL_PROVIDERS = ("local",) + CLOUD_PROVIDERS

# Provider priority chain used when preferred provider is unavailable.
PROVIDER_CHAIN = ("local", "groq", "gemini", "claude", "openrouter")

# Default cloud model per provider (sensible, cheap/fast defaults).
DEFAULT_CLOUD_MODELS = {
    "groq": "llama-3.1-70b-versatile",
    "gemini": "gemini-1.5-flash",
    "claude": "claude-3-5-sonnet-latest",
    "openrouter": "meta-llama/llama-3.1-70b-instruct",
}

# API base URLs (httpx-based provider, no heavy SDKs).
PROVIDER_ENDPOINTS = {
    "groq": "https://api.groq.com/openai/v1/chat/completions",
    "openrouter": "https://openrouter.ai/api/v1/chat/completions",
    "claude": "https://api.anthropic.com/v1/messages",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/models",
    "ollama": "http://localhost:11434/api/chat",
}

# ---- The 13 Phase-2 attack agents (name -> one-line role) ----
ATTACK_AGENTS = {
    "reconbot": "maps endpoints & gathers intelligence",
    "injector": "SQL, NoSQL, command & template injection",
    "authbreaker": "auth, JWT, session & MFA flaws",
    "idorhunter": "broken object-level access (IDOR)",
    "crawlerbot": "route & content discovery",
    "fuzzer": "parameter & boundary fuzzing",
    "headerpoker": "header, CORS & cache abuse",
    "fileattacker": "upload bypass & path traversal",
    "racecondition": "concurrency / TOCTOU flaws",
    "ssrfprober": "server-side request forgery",
    "xsshunter": "reflected, stored & DOM XSS",
    "websocketagent": "websocket hijacking & injection",
    "graphqlagent": "schema introspection & query abuse",
    "csrfhunter": "CSRF & clickjacking",
}

DEPTH_LEVELS = ("quick", "standard", "deep")
REPORT_FORMATS = ("html", "json", "pdf", "markdown")

# ---- Default config (written to ~/.argus/config.toml on first run) ----
DEFAULT_CONFIG: dict = {
    "provider": {"preferred": "local"},
    "local": {"model": "qwen2.5-coder:14b", "backend": "ollama"},
    "cloud": {"groq_key": "", "gemini_key": "", "claude_key": "", "openrouter_key": ""},
    "scan": {"auto_attack": False, "sandbox": "docker", "default_depth": "standard"},
    "report": {"output_dir": "./argus-report", "default_format": "html"},
}

# ---- File classification heuristics used during ingestion ----
LANGUAGE_BY_EXT = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript",
    ".tsx": "TypeScript", ".go": "Go", ".rb": "Ruby", ".php": "PHP", ".java": "Java",
    ".kt": "Kotlin", ".rs": "Rust", ".c": "C", ".cpp": "C++", ".cs": "C#",
    ".swift": "Swift", ".scala": "Scala", ".sh": "Shell", ".sql": "SQL",
    ".vue": "Vue", ".svelte": "Svelte", ".html": "HTML", ".css": "CSS",
}

DEPENDENCY_MANIFESTS = {
    "package.json": "node", "package-lock.json": "node", "yarn.lock": "node",
    "pnpm-lock.yaml": "node", "requirements.txt": "python", "pyproject.toml": "python",
    "Pipfile": "python", "poetry.lock": "python", "go.mod": "go", "go.sum": "go",
    "Gemfile": "ruby", "Gemfile.lock": "ruby", "pom.xml": "java",
    "build.gradle": "java", "composer.json": "php", "Cargo.toml": "rust",
}

# Substrings (lowercased path) that flag a file as security-relevant / high-risk.
AUTH_HINTS = ("auth", "login", "session", "jwt", "token", "passport", "oauth", "permission", "rbac")
DB_HINTS = ("model", "schema", "query", "repository", "dao", "orm", "migration", "database", "db")
ADMIN_HINTS = ("admin", "dashboard", "superuser", "manage", "internal")
PAYMENT_HINTS = ("payment", "checkout", "billing", "stripe", "charge", "invoice", "subscription")
UPLOAD_HINTS = ("upload", "file", "attachment", "media", "import")
CONFIG_FILES = (
    ".env", ".env.local", ".env.production", "docker-compose.yml", "docker-compose.yaml",
    "dockerfile", "nginx.conf", "settings.py", "config.py", "config.js", "config.json",
    "vercel.json", "netlify.toml", "railway.json", "serverless.yml",
)

# Directories never worth scanning.
IGNORE_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
    ".next", ".nuxt", "target", "vendor", ".idea", ".vscode", "coverage",
    "site-packages", ".mypy_cache", ".pytest_cache", ".ruff_cache", "_design_export",
}
