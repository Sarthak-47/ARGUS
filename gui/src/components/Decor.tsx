// Small decorative primitives: stone-grain noise overlay and the Greek-key divider.

const NOISE =
  "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E";

const MEANDER =
  "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='44' height='16' viewBox='0 0 44 16'%3E%3Cg fill='none' stroke='%23c56a33' stroke-width='1.4'%3E%3Cpath d='M0 13 H44 M5 13 V4 H17 V10 H10 V7 M27 13 V4 H39 V10 H32 V7'/%3E%3C/g%3E%3C/svg%3E";

export function NoiseOverlay() {
  return (
    <div
      style={{
        position: "fixed", inset: 0, pointerEvents: "none", zIndex: 60,
        opacity: 0.04, mixBlendMode: "overlay",
        backgroundImage: `url("${NOISE}")`,
      }}
    />
  );
}

/** A full-width meander band — the vessel's lip. Sits at the top of a screen's
 * main area, the one place ornament is used structurally rather than sprinkled. */
export function MeanderLip() {
  return (
    <div
      style={{
        height: 16, opacity: 0.8, borderBottom: "1px solid #5c3a1e",
        backgroundRepeat: "repeat-x", backgroundPosition: "center",
        backgroundImage: `url("${MEANDER}")`,
      }}
    />
  );
}

export function GreekKeyDivider({ margin = "18px 0" }: { margin?: string }) {
  return (
    <div
      style={{
        height: 14, margin, opacity: 0.5,
        backgroundRepeat: "repeat-x", backgroundPosition: "left center",
        backgroundImage: `url("${MEANDER}")`,
      }}
    />
  );
}
