// Panoptes red-figure primitives: the logo masked flat into terracotta (so it
// reads as a painted figure, not a gilded badge), the eye glyph, and the
// "hundred eyes" field where each wounded eye maps to a real finding and
// reveals it on hover.

import { useState, useMemo, type CSSProperties } from "react";
import { RF, FONT, sevColor, type Severity } from "../theme";
import { VULN_CHECKS, CWE_TO_CHECK, AGENTS } from "../data";
import type { Finding } from "../data";

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

/**
 * The screen opening: a small kicker, the title set large in Cinzel, and the
 * subtitle as running prose. No rule, no lip — the type and the whitespace do
 * the work, which is what lets a screen breathe instead of starting with a
 * band of chrome. `action` sits opposite the title.
 */
export function PageHead({ kicker, title, subtitle, action }: { kicker: string; title: string; subtitle?: string; action?: React.ReactNode }) {
  return (
    <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", gap: 32, padding: "40px 46px 26px", maxWidth: 1500 }}>
      <div style={{ minWidth: 0 }}>
        <p style={{ fontFamily: FONT.ui, fontSize: 11, fontWeight: 500, letterSpacing: "0.18em", textTransform: "uppercase", color: RF.clay, margin: "0 0 9px" }}>
          {kicker}
        </p>
        <h1 style={{ fontFamily: FONT.display, fontSize: 38, fontWeight: 500, color: RF.ivory, margin: 0, letterSpacing: "0.015em", lineHeight: 1.06, textWrap: "balance" }}>
          {title}
        </h1>
        {subtitle && (
          <p style={{ fontFamily: FONT.ui, fontSize: 14.5, color: RF.dust, margin: "11px 0 0", maxWidth: "58ch", lineHeight: 1.55 }}>{subtitle}</p>
        )}
      </div>
      {action && <div style={{ flex: "0 0 auto" }}>{action}</div>}
    </div>
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
        // the sibling classes intentionally left off the CWE map). Guarded —
        // a finding arriving without a title would otherwise throw here and
        // take the whole screen down with it.
        const t = (f.name ?? "").toLowerCase();
        return t.length > 0 && c.match.some((m) => t.includes(m));
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
              // No native `title` here on purpose: it was firing alongside the
              // custom hover panel below (its own delayed OS tooltip stacking
              // on top of the instant custom one, sometimes outliving the
              // mouseleave that should've cleared it) — the panel already
              // shows everything the title attribute would have.
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
            <span style={{ fontFamily: FONT.display, fontSize: 17, color: RF.ivory }}>{hover.name}</span>
            <span style={{ fontFamily: FONT.code, fontSize: 9.5, letterSpacing: "0.1em", textTransform: "uppercase", color: hover.hits.length ? sevColor(hover.worst || "HIGH") : RF.dust }}>
              {hover.hits.length ? `· ${hover.hits.length} found${hover.worst ? ` · worst: ${hover.worst.toLowerCase()}` : ""}` : "· checked, clean"}
            </span>
          </div>
        ) : (
          <span style={{ fontFamily: FONT.display, fontStyle: "italic", fontSize: 14, color: RF.dust }}>
            {VULN_CHECKS.length} vulnerability classes checked · {found} found something · hover any eye
          </span>
        )}
      </div>
    </div>
  );
}

// A readable spread of the real roster (data.ts's AGENTS, minus the always-on
// ReconBot which already anchors the EyeField above) — eight names around the
// mark reads as a watch, twenty would just be noise.
const HERO_AGENTS = AGENTS.filter((n) => n !== "ReconBot").slice(0, 8);

/**
 * The Dashboard hero: the mark at the centre, the swarm's eyes orbiting it.
 * Asleep until a scan has actually run (`active`); once one has, they open —
 * real agent names from the real roster, not decorative filler.
 */
export function SentinelRing({ active }: { active: boolean }) {
  const cx = 50, cy = 50; // percent of the container
  const rx = 40, ry = 36;
  return (
    <div style={{ position: "relative", width: "100%", height: "100%" }}>
      {/* Concentric guide rings — the orbits the eyes sit on. Faint enough to
          read as structure rather than ornament, and they give the mark
          somewhere to sit rather than floating in empty space. */}
      {[
        { w: "94%", h: "104%", dash: false, o: 0.5 },
        { w: "68%", h: "76%", dash: true, o: 0.7 },
        { w: "42%", h: "47%", dash: false, o: 0.5 },
      ].map((ring, i) => (
        <div
          key={i}
          aria-hidden="true"
          style={{
            position: "absolute", left: "50%", top: "50%", width: ring.w, height: ring.h,
            transform: "translate(-50%,-50%)", borderRadius: "50%",
            border: `1px ${ring.dash ? "dashed" : "solid"} rgba(125,79,40,${ring.o * 0.5})`,
            pointerEvents: "none",
          }}
        />
      ))}
      <TerracottaMark
        size={86}
        color="rgba(197,106,51,0.9)"
        style={{
          position: "absolute", left: "50%", top: "50%", transform: "translate(-50%,-50%)",
          animation: active ? "argusBreathe 5.5s ease-in-out infinite" : "none",
        }}
      />
      {HERO_AGENTS.map((name, i) => {
        const angle = (i / HERO_AGENTS.length) * Math.PI * 2 - Math.PI / 2;
        const left = cx + Math.cos(angle) * rx;
        const top = cy + Math.sin(angle) * ry;
        return (
          <div
            key={name}
            className="sentinel-node"
            title={name}
            style={{
              position: "absolute", left: `${left}%`, top: `${top}%`, transform: "translate(-50%,-50%)",
              animationDelay: `${i * 45}ms`,
              width: 50, height: 50, borderRadius: "50%",
              background: RF.glazeLo, border: `1px solid ${active ? RF.dilute : RF.diluteLo}`,
              display: "flex", alignItems: "center", justifyContent: "center",
            }}
          >
            <EyeGlyph sleeping={!active} w={27} h={17} />
          </div>
        );
      })}
    </div>
  );
}

