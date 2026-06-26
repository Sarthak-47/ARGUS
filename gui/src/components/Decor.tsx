// Small decorative primitives: stone-grain noise overlay and the Greek-key divider.

const NOISE =
  "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E";

const MEANDER =
  "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='44' height='14'%3E%3Cpath d='M1 12 V4 H12 V12 H7 V8 H9 M22 12 V4 H33 V12 H28 V8 H30 M43 12 V4' stroke='%23B8860B' fill='none' stroke-width='1.3'/%3E%3C/svg%3E";

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
