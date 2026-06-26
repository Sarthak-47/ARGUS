// Design tokens and helpers ported from the "carved in stone" system.

export const C = {
  obsidian: "#08080C",
  stoneDark: "#0F0F15",
  stoneCarved: "#171720",
  relief: "#1E1E2A",
  goldenrod: "#B8860B",
  bronze: "#CD7F32",
  crimson: "#8B0000",
  sienna: "#8B4513",
  goldPale: "#D4A853",
  parchment: "#C4A882",
  stoneText: "#6B5A45",
  ember: "#2A1F0E",
  weathered: "#4A4035",
} as const;

export const FONT = {
  display: "'Cinzel', serif",
  body: "'Cormorant Garamond', serif",
  code: "'JetBrains Mono', monospace",
} as const;

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export function sevColor(sev: string): string {
  return (
    {
      CRITICAL: "#8B0000",
      HIGH: "#8B4513",
      MEDIUM: "#B8860B",
      LOW: "#4A4035",
      INFO: "#2A2A3A",
    } as Record<string, string>
  )[sev] || "#4A4035";
}

export function bandColor(score: number): string {
  return score >= 70 ? "#8B0000" : score >= 45 ? "#8B4513" : "#B8860B";
}

export function bandLabel(score: number): string {
  return score >= 70 ? "Critical" : score >= 45 ? "High" : score >= 25 ? "Medium" : "Low";
}
