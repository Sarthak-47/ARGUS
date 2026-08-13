// Design tokens — "Panoptes" red-figure system (branch: redesign/panoptes).
// Rooted in Attic red-figure pottery, how Argus was actually depicted: black
// glaze ground, reserved terracotta figures, oxblood accents. Matte, flat, no
// glow. Key names are kept identical to the previous obsidian/gold system so
// every existing component recolours automatically.

export const C = {
  obsidian: "#08080A",     // ground
  stoneDark: "#131318",    // raised plane
  stoneCarved: "#212127",  // raised plane, higher
  relief: "#17171C",       // hairline
  goldenrod: "#C9A227",    // gold — the single accent
  bronze: "#7A6520",       // gold, dormant
  crimson: "#8E2B20",      // grave
  sienna: "#C9A227",
  goldPale: "#EDEAE4",     // lit text
  parchment: "#B7B4BD",    // secondary text
  stoneText: "#8B8996",    // labels, muted
  ember: "#2a1215",        // grave-tinted inset panel
  weathered: "#23232A",
} as const;

// A few extra tokens the new components lean on (additive; nothing depends on
// these existing, so they don't break the old surfaces).
// "Ichor & Verdigris". The all-terracotta scheme was a single muddy hue —
// brown text on brown panels on brown ground — so nothing could ever be
// bright, and depth had to come from borders instead of light. This keeps the
// mythology but gives it a temperature: a cold, near-black ground (blue-black,
// not brown-black), ichor gold as the luminous warm accent, and verdigris —
// what bronze actually becomes as it ages — as the cold counterpoint. Warm
// against cold is what lets an interface glow instead of sit flat.
// The keeper's watch-ledger. Pinned by DESIGN.md, and every value below is
// lifted verbatim from the user's actual Claude Design export (Argus.html),
// not guessed: a cool graphite/charcoal ground — not warm brown — with a
// single old-gold accent and grave red reserved for critical findings.
export const RF = {
  glaze: "#17171C",      // raised plane / subtle rule
  glazeLo: "#08080A",    // ground
  clay: "#C9A227",       // gold — the single accent
  clayHi: "#EDEAE4",     // lit text (the export lights to bone, not brighter gold)
  clayLo: "#7A6520",     // gold, dormant
  dilute: "#23232A",     // hairline, stronger
  diluteLo: "#17171C",   // hairline
  oxblood: "#8E2B20",    // grave
  oxbloodHi: "#B4392A",  // grave, the "alive"/pulse tone — verified, not an invented bright red
  ember: "#2a1215",      // grave-tinted inset panel
  patina: "#C9A227",     // no second accent: resolved reads as gold
  patinaHi: "#EDEAE4",
  ivory: "#EDEAE4",      // reading text
  parchment: "#B7B4BD",  // secondary (cool grey, not warm)
  dust: "#8B8996",       // labels, muted (cool grey, not warm)
} as const;

// Modern + mythological: the classical serif is reserved for *moments* —
// screen titles, big numbers, the wordmark — while everything you actually
// read or scan (labels, descriptions, rows, buttons) is a modern sans. The
// previous all-serif setting, italic Cormorant microcopy included, is what
// read as costume-drama rather than a contemporary tool with a myth behind it.
// Verified against the user's actual Claude Design export (Argus.html): the
// serif is Bodoni Moda — a Didone, thin/thick contrast, not the soft
// old-style Cormorant Garamond guessed earlier — and the mono is IBM Plex
// Mono, not JetBrains. See DESIGN.md.
export const FONT = {
  display: "'Bodoni Moda', Didot, Georgia, serif", // masthead + numerals
  body: "'Bodoni Moda', Didot, Georgia, serif",    // reading text
  code: "'IBM Plex Mono', 'Consolas', monospace",  // labels, meta, paths
  ui: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif", // controls only
} as const;

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

// Grave (oxblood) is the one alarm colour, reserved for CRITICAL alone —
// verified against the reference's own SEV map (GRAVE/HIGH/MIDDLING/SLIGHT),
// where only GRAVE breaks from gold → bone → dim. Everything else in this
// world reads as an intensity of gold or bone, never a second alarm hue.
export function sevColor(sev: string): string {
  return (
    {
      CRITICAL: "#8E2B20", // grave
      HIGH: "#C9A227",     // gold — still urgent, not a second red
      MEDIUM: "#B7B4BD",   // bone, dimmer
      LOW: "#6C6A76",
      INFO: "#55545C",
    } as Record<string, string>
  )[sev] || "#55545C";
}

// The grave "alive" pulse — critical/wounded eyes alternate between these two
// oxblood tones rather than glowing, per the reference's drawWounds/drawSphere.
export const GRAVE_PULSE = ["#8E2B20", "#B4392A"] as const;

// Thresholds must match argus.models.ScanResult.risk_band exactly (85/70/45) —
// this drifted out of sync with the backend once already: a scan that the
// engine correctly banded HIGH (e.g. score 77) rendered as "CRITICAL" on
// Dashboard, which recomputes the band locally, while Reports (which prefers
// the backend's own `band` field when present) showed the correct label for
// the very same scan. Found by clicking through the real packaged app.
export function bandColor(score: number): string {
  return score >= 85 ? "#8E2B20" : score >= 70 ? "#C9A227" : score >= 45 ? "#B7B4BD" : "#6C6A76";
}

export function bandLabel(score: number): string {
  return score >= 85 ? "Critical" : score >= 70 ? "High" : score >= 45 ? "Medium" : "Low";
}
