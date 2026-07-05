// The Argus mark — the real logo artwork, not a redrawn approximation.

import type { CSSProperties } from "react";

interface Props {
  size?: number;
  draw?: boolean;             // play the draw-in animation on mount
  rings?: number;             // activity level (live attack) — drives a subtle glow
  style?: CSSProperties;
  opacity?: number;
}

export function ArgusEye({ size = 34, draw = false, rings, style, opacity }: Props) {
  const glow = rings === undefined ? 0 : Math.min(1, rings / 12);

  return (
    <img
      src="/argus-logo.png"
      alt="Argus"
      width={size}
      height={size}
      style={{
        objectFit: "contain",
        filter: glow > 0 ? `drop-shadow(0 0 ${4 + glow * 6}px rgba(184,134,11,${0.35 + glow * 0.4}))` : "none",
        ...(draw ? { animation: "argusEyeDraw 1.5s cubic-bezier(.2,.7,.2,1) both" } : {}),
        ...(opacity !== undefined ? { opacity } : {}),
        ...style,
      }}
    />
  );
}
