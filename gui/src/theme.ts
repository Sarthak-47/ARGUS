// Design tokens — "Panoptes" red-figure system (branch: redesign/panoptes).
// Rooted in Attic red-figure pottery, how Argus was actually depicted: black
// glaze ground, reserved terracotta figures, oxblood accents. Matte, flat, no
// glow. Key names are kept identical to the previous obsidian/gold system so
// every existing component recolours automatically.

export const C = {
  obsidian: "#0d0906",     // deepest reserve / ground
  stoneDark: "#17110a",    // black glaze — panel ground
  stoneCarved: "#1b140c",  // raised panel
  relief: "#5c3a1e",       // diluted-brown borders / dividers
  goldenrod: "#c56a33",    // reserved terracotta — the primary "figure" accent
  bronze: "#a9552a",       // deeper terracotta
  crimson: "#a5382a",      // oxblood — a wound (critical)
  sienna: "#c07a2c",       // ochre — high
  goldPale: "#e0a163",     // buff highlight
  parchment: "#cbbb9c",    // inscription text
  stoneText: "#9d7c54",    // muted clay text
  ember: "#221a10",        // dark inset panel / active fill
  weathered: "#7d4f28",    // diluted brown
} as const;

// A few extra tokens the new components lean on (additive; nothing depends on
// these existing, so they don't break the old surfaces).
export const RF = {
  glaze: "#17110a",
  glazeLo: "#0d0906",
  clay: "#c56a33",
  clayHi: "#e0a163",
  clayLo: "#a9552a",
  dilute: "#7d4f28",
  diluteLo: "#5c3a1e",
  oxblood: "#a5382a",
  oxbloodHi: "#c24a30",
  ember: "#c07a2c",
  ivory: "#ece0c6",
  parchment: "#cbbb9c",
  dust: "#9d7c54",
} as const;

export const FONT = {
  display: "'Cinzel', 'Trajan Pro', Georgia, serif",
  body: "'Cormorant Garamond', Palatino, Georgia, serif",
  code: "'JetBrains Mono', 'Consolas', monospace",
} as const;

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export function sevColor(sev: string): string {
  return (
    {
      CRITICAL: "#c24a30", // oxblood (bright)
      HIGH: "#c07a2c",     // ochre
      MEDIUM: "#c56a33",   // terracotta
      LOW: "#7d4f28",      // diluted brown
      INFO: "#5c3a1e",
    } as Record<string, string>
  )[sev] || "#7d4f28";
}

// Thresholds must match argus.models.ScanResult.risk_band exactly (85/70/45) —
// this drifted out of sync with the backend once already: a scan that the
// engine correctly banded HIGH (e.g. score 77) rendered as "CRITICAL" on
// Dashboard, which recomputes the band locally, while Reports (which prefers
// the backend's own `band` field when present) showed the correct label for
// the very same scan. Found by clicking through the real packaged app.
export function bandColor(score: number): string {
  return score >= 85 ? "#c24a30" : score >= 70 ? "#c07a2c" : score >= 45 ? "#c56a33" : "#7d4f28";
}

export function bandLabel(score: number): string {
  return score >= 85 ? "Critical" : score >= 70 ? "High" : score >= 45 ? "Medium" : "Low";
}
