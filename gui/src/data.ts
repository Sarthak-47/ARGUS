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
  compliance?: { asvs: string; pci_dss: string; label: string } | null;
  // Present only on synthesized exploit-chain findings: how many confirmed
  // findings the chain compounds. Drives the ⛓ badge in Reports.
  chainOf?: number;
}

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
