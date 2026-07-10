// Panoptes red-figure primitives: the logo masked flat into terracotta (so it
// reads as a painted figure, not a gilded badge), the eye glyph, and the
// "hundred eyes" field where each wounded eye maps to a real finding and
// reveals it on hover.

import { useState, useMemo, type CSSProperties } from "react";
import { RF, sevColor, type Severity } from "../theme";
import { VULN_CHECKS, CWE_TO_CHECK } from "../data";
import type { Finding } from "../data";
import { MeanderLip } from "./Decor";

/** The real Argus logo, masked into a flat terracotta silhouette. */
export function TerracottaMark({ size = 34, color = RF.clay, style }: { size?: number; color?: string; style?: CSSProperties }) {
  return (
    <span
      aria-label="Argus"
      style={{
        display: "inline-block", width: size, height: size, background: color,
        WebkitMaskImage: "url(/argus-logo.png)", maskImage: "url(/argus-logo.png)",
        WebkitMaskSize: "contain", maskSize: "contain",
        WebkitMaskRepeat: "no-repeat", maskRepeat: "no-repeat",
        WebkitMaskPosition: "center", maskPosition: "center",
        ...style,
      }}
    />
  );
}

/** A single red-figure eye. Wounded = oxblood; watching = terracotta; sleeping =
 * a closed lid. Pass `tone` to tint a wounded eye to a finding's severity. */
export function EyeGlyph({ wounded = false, sleeping = false, tone, w = 24, h = 15 }: { wounded?: boolean; sleeping?: boolean; tone?: string; w?: number; h?: number }) {
  if (sleeping) {
    return (
      <svg viewBox="0 0 24 15" width={w} height={h} aria-hidden="true">
        <path d="M2 8 Q12 12 22 8" fill="none" stroke={RF.diluteLo} strokeWidth="1.6" />
      </svg>
    );
  }
  const col = tone ?? (wounded ? RF.oxbloodHi : RF.clay);
  const iris = tone ?? (wounded ? RF.oxblood : RF.dilute);
  return (
    <svg viewBox="0 0 24 15" width={w} height={h} aria-hidden="true">
      <g fill="none" stroke={col} strokeWidth="1.6">
        <path d="M2 7.5 Q12 1 22 7.5 Q12 14 2 7.5 Z" />
        <circle cx="12" cy="7.5" r={wounded ? 3 : 2.6} fill={iris} stroke="none" />
      </g>
    </svg>
  );
}

/** Consistent screen top: the meander lip, a title + subtitle, and an optional
 * right-side action. Used on every screen so the chrome reads as one system. */
export function ScreenHeader({ title, subtitle, action }: { title: string; subtitle?: string; action?: React.ReactNode }) {
  return (
    <>
      <MeanderLip />
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "18px 34px", borderBottom: "1px solid rgba(125,79,40,0.3)" }}>
        <div>
          <div style={{ fontFamily: "'Cinzel', Georgia, serif", fontSize: 20, letterSpacing: "0.16em", textTransform: "uppercase", color: RF.clayHi }}>{title}</div>
          {subtitle && <div style={{ fontFamily: "'Cormorant Garamond', Georgia, serif", fontStyle: "italic", fontSize: 14, color: RF.dust, marginTop: 2 }}>{subtitle}</div>}
        </div>
        {action}
      </div>
    </>
  );
}

interface EyeState {
  name: string;
  group: string;
  hits: Finding[];      // findings that lit this check
  worst: Severity | null;
}

/**
 * The hundred eyes = every vulnerability class Argus checks for. A class that
 * caught something is a red eye; one that came back clean is a tan eye. Every
 * eye is hoverable — red names what it caught, tan says it was checked and
 * clean. Clicking a red eye opens its first finding.
 */
export function EyeField({ findings, onSelect }: { findings: Finding[]; onSelect?: (id: number) => void }) {
  const [hover, setHover] = useState<EyeState | null>(null);

  const eyes: EyeState[] = useMemo(() => {
    const rank: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
    return VULN_CHECKS.map((c) => {
      const hits = findings.filter((f) => {
        // Precise: an unambiguous CWE lights exactly its class.
        if (f.cwe && CWE_TO_CHECK[f.cwe] === c.name) return true;
        // Fallback: title keyword (covers static findings without a CWE and
        // the sibling classes intentionally left off the CWE map).
        const t = f.name.toLowerCase();
        return c.match.some((m) => t.includes(m));
      });
      let worst: Severity | null = null;
      for (const h of hits) if (!worst || (rank[h.severity] || 0) > (rank[worst] || 0)) worst = h.severity;
      return { name: c.name, group: c.group, hits, worst };
    });
  }, [findings]);

  const found = eyes.filter((e) => e.hits.length > 0).length;

  return (
    <div style={{ position: "relative" }}>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "11px 14px" }}>
        {eyes.map((e, i) => {
          const wounded = e.hits.length > 0;
          return (
            <span
              key={i}
              onMouseEnter={() => setHover(e)}
              onMouseLeave={() => setHover(null)}
              onClick={() => wounded && onSelect?.(e.hits[0].id)}
              style={{ display: "inline-flex", cursor: wounded && onSelect ? "pointer" : "default", lineHeight: 0, opacity: wounded ? 1 : 0.82 }}
              title={wounded ? `${e.name} — ${e.hits.length} found` : `${e.name} — checked, clean`}
            >
              <EyeGlyph wounded={wounded} />
            </span>
          );
        })}
      </div>

      <div style={{ marginTop: 14, minHeight: 34, display: "flex", alignItems: "center" }}>
        {hover ? (
          <div style={{ display: "inline-flex", alignItems: "center", gap: 10, padding: "9px 14px", background: RF.glazeLo, border: `1px solid ${RF.diluteLo}` }}>
            <span style={{ width: 9, height: 9, borderRadius: "50%", background: hover.hits.length ? sevColor(hover.worst || "HIGH") : RF.dilute, flex: "0 0 auto" }} />
            <span style={{ fontFamily: "'Cormorant Garamond', Georgia, serif", fontSize: 17, color: RF.ivory }}>{hover.name}</span>
            <span style={{ fontFamily: "'Cinzel', Georgia, serif", fontSize: 9.5, letterSpacing: "0.1em", textTransform: "uppercase", color: hover.hits.length ? sevColor(hover.worst || "HIGH") : RF.dust }}>
              {hover.hits.length ? `· ${hover.hits.length} found${hover.worst ? ` · worst: ${hover.worst.toLowerCase()}` : ""}` : "· checked, clean"}
            </span>
          </div>
        ) : (
          <span style={{ fontFamily: "'Cormorant Garamond', Georgia, serif", fontStyle: "italic", fontSize: 14, color: RF.dust }}>
            {VULN_CHECKS.length} vulnerability classes checked · {found} found something · hover any eye
          </span>
        )}
      </div>
    </div>
  );
}

