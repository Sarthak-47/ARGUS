// The Argus eye — concentric angular geometry, never circles. Ported from the design.

import type { CSSProperties } from "react";

interface Props {
  size?: number;
  draw?: boolean;             // play the draw-outward animation on mount
  rings?: number;             // how many outer rings are lit (live attack)
  style?: CSSProperties;
  opacity?: number;
}

export function ArgusEye({ size = 34, draw = false, rings, style, opacity }: Props) {
  // When `rings` is provided, light rings progressively (activated/2 in the design).
  const ringOpacity = (idx: number): number => {
    if (rings === undefined) return idx === 0 ? 1 : 0.7;
    return rings > idx * 2 ? 1 : 0.12;
  };
  const t = "opacity 0.8s ease";

  return (
    <svg
      viewBox="0 0 100 100"
      width={size}
      height={size}
      fill="none"
      style={{
        ...(draw ? { animation: "argusEyeDraw 1.5s cubic-bezier(.2,.7,.2,1) both" } : {}),
        ...(opacity !== undefined ? { opacity } : {}),
        ...style,
      }}
    >
      <polygon points="6,50 28,28 72,28 94,50 72,72 28,72" stroke="#B8860B" strokeWidth="2.5"
        style={{ opacity: ringOpacity(0), transition: t }} />
      <polygon points="50,20 80,50 50,80 20,50" stroke="#B8860B" strokeWidth="2"
        style={{ opacity: ringOpacity(1), transition: t }} />
      <polygon points="50,30 70,50 50,70 30,50" stroke="#B8860B" strokeWidth="2"
        style={{ opacity: ringOpacity(2), transition: t }} />
      <polygon points="50,38 62,50 50,62 38,50" stroke="#B8860B" strokeWidth="2"
        style={{ opacity: ringOpacity(3), transition: t }} />
      <rect x="45" y="45" width="10" height="10" transform="rotate(45 50 50)" fill="#B8860B" />
    </svg>
  );
}
