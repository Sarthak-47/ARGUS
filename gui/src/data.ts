// Static configuration for the UI. This holds only *real* engine facts — the
// agent roster, their one-line roles, and the selectable LLM providers — plus
// the view-model types. All live findings/history/status come from the Python
// engine at runtime (see store.ts + adapter.ts); the app ships with no
// fabricated findings, audits, or scripted attack timelines.

import type { Severity } from "./theme";

export const AGENTS = [
  "ReconBot", "Injector", "AuthBreaker", "IDORHunter", "CrawlerBot", "Fuzzer",
  "HeaderPoker", "FileAttacker", "RaceCondition", "SSRFProber", "XSSHunter",
  "WebSocketAgent", "GraphQLAgent",
] as const;

export type AgentName = (typeof AGENTS)[number];

export const DESC: Record<string, string> = {
  ReconBot: "maps endpoints",
  Injector: "SQL & command injection",
  AuthBreaker: "auth & JWT flaws",
  IDORHunter: "broken object access",
  CrawlerBot: "route discovery",
  Fuzzer: "parameter fuzzing",
  HeaderPoker: "header & CORS abuse",
  FileAttacker: "upload & traversal",
  RaceCondition: "concurrency flaws",
  SSRFProber: "server-side requests",
  XSSHunter: "cross-site scripting",
  WebSocketAgent: "socket hijacking",
  GraphQLAgent: "schema introspection",
};

export interface AgentState {
  status: "queued" | "running" | "complete";
  sent: number;
  confirmed: number;
  progress: number;
}

export interface FeedLine {
  agent: string;
  text: string;
  sev: "ok" | "high" | "crit";
  id: number;
}

export interface Finding {
  id: number;
  severity: Severity;
  name: string;
  endpoint: string;
  agent: string;
  cvss: string;
  whatIs: string;
  request: string;
  response: string;
  repro: string;
  fix: string;
  file?: string | null;
  line?: number | null;
  cwe?: string | null;        // bare number, e.g. "89"
  category?: string | null;   // engine category, e.g. "injection"
  compliance?: { asvs: string; pci_dss: string; label: string } | null;
  // Present only on synthesized exploit-chain findings: how many confirmed
  // findings the chain compounds. Drives the ⛓ badge in Reports.
  chainOf?: number;
}

// The catalogue of vulnerability classes Argus actually checks for — the
// "hundred eyes". Each entry is one real check (grounded in the engine's CWE
// map, the attack agents, the static rules, and the supply-chain/IaC passes).
// `match` are lowercase substrings tested against a finding's title; a class
// with ≥1 matching finding is "found" (a red eye), the rest came back clean
// (a tan eye). This is a visual, not the scoring logic — so a fuzzy title
// match is fine.
export interface VulnCheck {
  name: string;
  group: string;
  match: string[];
}

export const VULN_CHECKS: VulnCheck[] = [
  // ── Injection ──
  { name: "SQL injection", group: "Injection", match: ["sql injection"] },
  { name: "NoSQL injection", group: "Injection", match: ["nosql"] },
  { name: "OS command injection", group: "Injection", match: ["command injection"] },
  { name: "Code / template injection (SSTI)", group: "Injection", match: ["template injection", "ssti", "code injection"] },
  { name: "LDAP / XPath injection", group: "Injection", match: ["ldap injection", "xpath"] },
  // ── Cross-site scripting ──
  { name: "Reflected XSS", group: "XSS", match: ["reflected xss", "reflected cross-site"] },
  { name: "Stored XSS", group: "XSS", match: ["stored xss"] },
  { name: "DOM-based XSS", group: "XSS", match: ["dom xss", "dom-based"] },
  // ── Server & request-forgery ──
  { name: "Server-Side Request Forgery", group: "SSRF & XXE", match: ["server-side request forgery", "ssrf"] },
  { name: "XML external entity (XXE)", group: "SSRF & XXE", match: ["xxe", "xml external"] },
  { name: "Open redirect", group: "SSRF & XXE", match: ["open redirect"] },
  // ── Files ──
  { name: "Path traversal", group: "Files", match: ["path traversal", "traversal"] },
  { name: "Unrestricted file upload", group: "Files", match: ["file upload", "unrestricted upload"] },
  { name: "Backup / temp file exposure", group: "Files", match: ["backup file", "temp file"] },
  { name: "Exposed .git / secrets path", group: "Files", match: [".git", "exposed .env", "exposed config"] },
  // ── Access control ──
  { name: "Insecure Direct Object Reference", group: "Access control", match: ["idor", "direct object"] },
  { name: "Broken object-level authz (BOLA)", group: "Access control", match: ["bola", "object-level"] },
  { name: "Broken function-level authz (BFLA)", group: "Access control", match: ["bfla", "function-level"] },
  { name: "Authentication bypass", group: "Access control", match: ["authentication bypass", "auth bypass"] },
  { name: "Missing authentication", group: "Access control", match: ["missing authentication"] },
  // ── Session & tokens ──
  { name: "JWT weak secret", group: "Session & tokens", match: ["weak secret"] },
  { name: "JWT alg=none", group: "Session & tokens", match: ["alg none", "alg=none", "jwt none"] },
  { name: "JWT missing expiry", group: "Session & tokens", match: ["no expiry", "exp claim", "no exp"] },
  { name: "Insufficient session expiration", group: "Session & tokens", match: ["session expiration"] },
  { name: "Insecure session cookie flags", group: "Session & tokens", match: ["cookie missing", "security flags", "httponly"] },
  // ── Request integrity ──
  { name: "Cross-Site Request Forgery", group: "Request integrity", match: ["csrf", "cross-site request", "without csrf"] },
  { name: "Clickjacking", group: "Request integrity", match: ["clickjacking", "framing"] },
  { name: "Permissive CORS", group: "Request integrity", match: ["cors"] },
  { name: "Missing security headers", group: "Request integrity", match: ["security headers"] },
  { name: "Race condition / no rate limit", group: "Request integrity", match: ["race", "rate limit"] },
  // ── APIs ──
  { name: "GraphQL introspection exposed", group: "APIs", match: ["introspection"] },
  { name: "WebSocket origin validation", group: "APIs", match: ["websocket"] },
  { name: "Excessive data exposure", group: "APIs", match: ["excessive data", "information exposure", "info exposure"] },
  // ── Crypto & data ──
  { name: "Unsafe deserialization", group: "Crypto & data", match: ["deserial", "yaml.load", "pickle"] },
  { name: "Weak hash algorithm", group: "Crypto & data", match: ["weak hash", "md5", "sha1"] },
  { name: "Broken / weak encryption", group: "Crypto & data", match: ["broken crypto", "weak encryption", "weak cipher"] },
  { name: "Weak randomness (PRNG)", group: "Crypto & data", match: ["prng", "weak random", "insecure random"] },
  // ── Secrets & config ──
  { name: "Hardcoded secret / credentials", group: "Secrets & config", match: ["hardcoded secret", "hardcoded cred", "generic secret"] },
  { name: "High-entropy secret", group: "Secrets & config", match: ["high-entropy", "high entropy"] },
  { name: "Debug mode enabled", group: "Secrets & config", match: ["debug mode", "debug code", "debug"] },
  { name: "Runs with unneeded privilege", group: "Secrets & config", match: ["unnecessary privilege", "all interfaces", "0.0.0.0"] },
  // ── AI / agent surface ──
  { name: "Prompt injection", group: "AI surface", match: ["prompt injection"] },
  { name: "MCP tool poisoning", group: "AI surface", match: ["tool poisoning"] },
  { name: "MCP dangerous capability", group: "AI surface", match: ["dangerous capability", "unauthenticated tool"] },
  // ── Business logic ──
  { name: "Business-logic abuse", group: "Business logic", match: ["business logic", "coupon", "workflow bypass", "negative"] },
  // ── Supply chain ──
  { name: "Vulnerable dependency (CVE)", group: "Supply chain", match: ["vulnerable dependency", "known vulnerabilit"] },
  { name: "Typosquat dependency", group: "Supply chain", match: ["typosquat"] },
  { name: "Unpinned dependency", group: "Supply chain", match: ["unpinned"] },
  { name: "Malicious install script", group: "Supply chain", match: ["install script"] },
  { name: "Container base-image CVE", group: "Supply chain", match: ["base image", "image cve", "os-package"] },
  { name: "IaC / Dockerfile misconfig", group: "Supply chain", match: ["dockerfile", "iac", "container config"] },
];

// Precise finding → eye mapping: an unambiguous CWE (one that maps to exactly
// one class above) lights that class directly, bypassing title matching.
// Shared CWEs (79 across all XSS, 347 across JWT, 639 across IDOR/BOLA, 94
// across code-injection/MCP) are deliberately omitted — they'd light the wrong
// sibling eye, so those classes stay on title matching, which distinguishes them.
export const CWE_TO_CHECK: Record<string, string> = {
  "89": "SQL injection",
  "77": "OS command injection", "78": "OS command injection",
  "918": "Server-Side Request Forgery",
  "611": "XML external entity (XXE)",
  "601": "Open redirect",
  "22": "Path traversal",
  "434": "Unrestricted file upload",
  "530": "Backup / temp file exposure",
  "285": "Broken function-level authz (BFLA)",
  "290": "Authentication bypass",
  "1004": "Insecure session cookie flags",
  "352": "Cross-Site Request Forgery",
  "1021": "Clickjacking",
  "942": "Permissive CORS",
  "693": "Missing security headers",
  "362": "Race condition / no rate limit",
  "1385": "WebSocket origin validation",
  "200": "Excessive data exposure",
  "502": "Unsafe deserialization",
  "338": "Weak randomness (PRNG)",
  "798": "Hardcoded secret / credentials",
  "489": "Debug mode enabled",
  "250": "Runs with unneeded privilege",
  "841": "Business-logic abuse",
  "1395": "Vulnerable dependency (CVE)",
  "1357": "Typosquat dependency",
  "1104": "Unpinned dependency",
  "506": "Malicious install script",
};

// `id` matches the engine's provider identifiers (argus/config/defaults.py's
// ALL_PROVIDERS) so a selection here can round-trip through `argus config
// --provider <id>` — the display name alone (e.g. "Local GPU") doesn't.
export const PROVIDERS = [
  { id: "local", name: "Local GPU", speed: "12 t/s" },
  { id: "groq", name: "Groq", speed: "280 t/s" },
  { id: "gemini", name: "Gemini", speed: "90 t/s" },
  { id: "claude", name: "Claude", speed: "55 t/s" },
  { id: "openrouter", name: "OpenRouter", speed: "varies" },
];
