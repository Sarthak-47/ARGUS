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

export function mapReport(json: EngineReport): LoadedReport {
  const findings: Finding[] = (json.findings || []).map((f, i) => ({
    id: i + 1,
    severity: coerceSeverity(f.severity),
    name: f.title,
    endpoint: locationOf(f),
    agent: detectorToAgent(f.detector),
    cvss: f.cvss != null ? String(f.cvss) : "—",
    whatIs: f.description || "",
    // Phase-1 findings carry a code/evidence snippet rather than HTTP; Phase-2
    // findings put request/response detail in evidence. Show what we have.
    request: f.evidence || "",
    response: f.confirmed ? "Exploit confirmed by Argus." : "",
    repro: f.exploit || "",
    fix: f.fix || "",
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
