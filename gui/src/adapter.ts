// Maps the Python engine's JSON report (ScanResult.to_dict) into the GUI view
// models. This is the bridge between the engine and the UI: drop a report.json
// (from `argus scan --format json` / `argus report --format json`) into gui/public
// and the app renders real findings instead of the bundled demo data.

import type { Severity } from "./theme";
import type { Finding } from "./data";

export interface EngineFinding {
  title: string;
  severity: string;
  category?: string;
  detector?: string;
  description?: string;
  file?: string | null;
  line?: number | null;
  endpoint?: string | null;
  evidence?: string;
  exploit?: string;
  fix?: string;
  cvss?: number | null;
  cwe?: string | null;
  confidence?: string;
  confirmed?: boolean;
  poc?: { type?: string; curl?: string; request?: string; response?: string } | null;
  compliance?: { asvs: string; pci_dss: string; label: string } | null;
}

export interface EngineReport {
  target: string;
  phase: string;
  risk_score: number;
  risk_band: string;
  counts: Record<string, number>;
  findings: EngineFinding[];
  llm_provider?: string | null;
}

export interface LoadedReport {
  target: string;
  phase: string;
  riskScore: number;
  band: string;
  counts: Record<string, number>;
  findings: Finding[];
  provider?: string | null;
}

// Map a detector id to a human agent/source label.
function detectorToAgent(detector?: string): string {
  if (!detector) return "Argus";
  const d = detector.toLowerCase();
  const map: Record<string, string> = {
    injector: "Injector", authbreaker: "AuthBreaker", reconbot: "ReconBot",
    crawlerbot: "CrawlerBot", xsshunter: "XSSHunter", ssrfprober: "SSRFProber",
    headerpoker: "HeaderPoker", csrfhunter: "CSRFHunter", fileattacker: "FileAttacker",
    fuzzer: "Fuzzer", racecondition: "RaceCondition", graphqlagent: "GraphQLAgent",
    websocketagent: "WebSocketAgent", idorhunter: "IDORHunter",
  };
  const head = d.split(":")[0];
  if (map[head]) return map[head];
  if (d.startsWith("rule:") || d.startsWith("semgrep")) return "Static scan";
  if (d.startsWith("secrets")) return "Secret scan";
  if (d.startsWith("npm") || d.startsWith("pip")) return "Dependency audit";
  return "Static scan";
}

function locationOf(f: EngineFinding): string {
  if (f.endpoint) return f.endpoint;
  if (f.file && f.line) return `${f.file}:${f.line}`;
  return f.file || "—";
}

function coerceSeverity(s: string): Severity {
  const up = (s || "INFO").toUpperCase();
  return (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(up) ? up : "INFO") as Severity;
}

export interface EngineHistoryEntry {
  target: string;
  phase: string;
  finished_at: number | null;
  risk_score: number;
  risk_band: string;
  counts: Record<string, number>;
}

export interface HistoryEntry {
  target: string;
  phase: string;
  finishedAt: number | null;
  riskScore: number;
  band: string;
  counts: Record<string, number>;
}

export function mapHistory(json: EngineHistoryEntry[]): HistoryEntry[] {
  return (json || []).map((e) => ({
    target: e.target,
    phase: e.phase,
    finishedAt: e.finished_at,
    riskScore: e.risk_score,
    band: e.risk_band,
    counts: e.counts || {},
  }));
}

export interface ComparisonFinding {
  title: string;
  severity: string;
  category: string;
  file: string | null;
  line: number | null;
  endpoint: string | null;
}

export interface EngineComparison {
  old_target: string | null;
  new_target: string;
  new_findings: ComparisonFinding[];
  fixed_findings: ComparisonFinding[];
  unchanged_count: number;
}

export interface StatusInfo {
  resolved_provider: string | null;
  preferred_provider: string;
  model: string | null;
  available: boolean;
  gpu: { vendor: string; name: string; vram_gb: number; detected: boolean };
  recommended_model: string | null;
  scan_defaults: { depth: string };
  report_defaults: { output_dir: string; format: string };
  agent_count: number;
}

export function mapReport(json: EngineReport): LoadedReport {
  const findings: Finding[] = (json.findings || []).map((f, i) => ({
    id: i + 1,
    severity: coerceSeverity(f.severity),
    name: f.title,
    endpoint: locationOf(f),
    agent: detectorToAgent(f.detector),
    cvss: f.cvss != null ? String(f.cvss) : "—",
    whatIs: f.description || "",
    // Prefer a real captured proof-of-concept (Step 2) over generic evidence —
    // it's a reproducible request/response, not just a matched snippet.
    request: f.poc?.request || f.evidence || "",
    response: f.poc?.response || (f.confirmed ? "Exploit confirmed by Argus." : ""),
    repro: f.poc?.curl || f.exploit || "",
    fix: f.fix || "",
    file: f.file,
    line: f.line,
    compliance: f.compliance,
  }));

  return {
    target: json.target,
    phase: json.phase,
    riskScore: json.risk_score,
    band: json.risk_band,
    counts: json.counts || {},
    findings,
    provider: json.llm_provider,
  };
}
