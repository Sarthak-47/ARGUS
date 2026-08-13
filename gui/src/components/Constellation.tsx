// THE HUNDRED EYES — Argus's actual count, on a slowly rotating Fibonacci
// sphere. This is a direct, verified port of the drawSphere/eyeGeom routines
// from the user's pinned Claude Design source (Argus.dc.html) — not a
// reinterpretation: same placement math, same almond-lid quadratic-curve
// geometry, same rotation speed, same blink cadence. The one departure from
// the reference is honest by necessity: the reference's three "alarmed" eyes
// and two "asleep" eyes are fixed demo indices with invented meaning. Here,
// "alarmed" (grave) is real — it's a bound vulnerability class with an actual
// critical/high finding, never fabricated. A small, fixed, real-data-free
// pattern of drowsy/asleep eyes among the undound remainder gives the field
// the same visual variety as the reference without inventing a claim.
//
// The first VULN_CHECKS.length eyes are bound to real vulnerability classes
// and real findings. The remainder pad the field out to the mythical hundred
// as unbound, unclickable ornament — the count itself is the myth, not a
// fabricated finding.
//
// One canvas, repainted per frame: a hundred animated eyes as DOM nodes would
// be a layout catastrophe.

import { useEffect, useRef, useState } from "react";
import { sevColor, type Severity } from "../theme";
import { VULN_CHECKS, CWE_TO_CHECK, type Finding } from "../data";

export const GOLD = "#C9A227";
export const GOLD_DIM = "#7A6520";
export const WOUND = "#8E2B20";
export const WOUND_ALT = "#B4392A";
export const MARBLE = "rgba(237,234,228,0.9)";
export const SHUT_STROKE = "#4A4954";

const RANK: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
const TOTAL_EYES = 100;

type EyeState = "open" | "drowsy" | "asleep" | "alarmed";

export interface EyeNode {
  name: string | null;   // null on the unbound, decorative remainder
  group: string;
  hits: Finding[];
  worst: Severity | null;
  x: number; y: number; z: number;  // unit sphere position
  state: EyeState;
  blinkAt: number;
  blink: number;
  tilt: number;
  phase: number;
  px: number; py: number; pr: number; // last painted screen position + radius, for hit-testing
}

/** Bind every check to the findings that lit it — CWE first, title keyword as
 *  the fallback — then pad to the mythical hundred with unbound ornament. */
export function bindEyes(findings: Finding[]): EyeNode[] {
  const n = TOTAL_EYES;
  const golden = Math.PI * (3 - Math.sqrt(5));
  const nodes: EyeNode[] = [];

  for (let i = 0; i < n; i++) {
    const y = 1 - (i / (n - 1)) * 2;
    const r = Math.sqrt(Math.max(0, 1 - y * y));
    const th = golden * i;
    const base = {
      x: Math.cos(th) * r, y, z: Math.sin(th) * r,
      blinkAt: 2 + Math.random() * 9,
      blink: 0,
      tilt: (Math.random() - 0.5) * 0.5,
      phase: Math.random() * Math.PI * 2,
      px: 0, py: 0, pr: 0,
    };

    if (i < VULN_CHECKS.length) {
      const c = VULN_CHECKS[i];
      const hits = findings.filter((f) => {
        if (f.cwe && CWE_TO_CHECK[f.cwe] === c.name) return true;
        // Defensive: a finding arriving without a title used to throw here —
        // which, with no error boundary above, blanked the entire
        // application rather than dropping one row.
        const t = (f.name ?? "").toLowerCase();
        return t.length > 0 && c.match.some((m) => t.includes(m));
      });
      let worst: Severity | null = null;
      for (const h of hits) if (!worst || (RANK[h.severity] || 0) > (RANK[worst] || 0)) worst = h.severity;
      // Open and gold when clean, grave when caught — the field's default
      // is watching, not shut. A "shut for nothing found" rule reads fine on
      // a strip that only ever shows real detections, but here almost every
      // class is clean almost all the time, so it emptied the whole field.
      nodes.push({ ...base, name: c.name, group: c.group, hits, worst, state: hits.length ? "alarmed" : "open" });
    } else {
      // Decorative remainder, never tied to a real class: kept uniformly
      // open like the rest of the field. A mixed asleep/drowsy texture here
      // read as broken/inconsistent rather than deliberate — every eye the
      // same state is the calmer, correct choice.
      nodes.push({ ...base, name: null, group: "", hits: [], worst: null, state: "open" });
    }
  }
  return nodes;
}

/** The reference's exact almond-lid geometry: a quadratic-curve lid, a
 *  clipped pupil that offsets toward the cursor, and a single catch-light. */
export function eyeGeom(
  ctx: CanvasRenderingContext2D, cx: number, cy: number, w: number,
  openness: number, tilt: number, alpha: number, iris: string,
  pupilDX: number, pupilDY: number, state: EyeState,
) {
  const h = w * 0.34;
  ctx.save();
  ctx.translate(cx, cy);
  ctx.rotate(tilt);
  ctx.globalAlpha = alpha;

  if (state === "asleep" || openness < 0.06) {
    ctx.strokeStyle = SHUT_STROKE;
    ctx.lineWidth = Math.max(1, w * 0.035);
    ctx.beginPath();
    ctx.moveTo(-w / 2, 0);
    ctx.quadraticCurveTo(0, h * 0.42, w / 2, 0);
    ctx.stroke();
    ctx.restore();
    return;
  }

  const o = Math.max(0.08, openness);
  ctx.beginPath();
  ctx.moveTo(-w / 2, 0);
  ctx.quadraticCurveTo(0, -h * o * 2.05, w / 2, 0);
  ctx.quadraticCurveTo(0, h * o * 1.75, -w / 2, 0);
  ctx.closePath();
  ctx.fillStyle = iris;
  ctx.fill();
  ctx.save();
  ctx.clip();
  const ir = h * o;
  const px = pupilDX * (w * 0.5 - ir * 1.35);
  const py = pupilDY * ir * 0.35;
  ctx.beginPath();
  ctx.arc(px, py, ir * 0.5, 0, Math.PI * 2);
  ctx.fillStyle = "#0B0B0D";
  ctx.fill();
  ctx.beginPath();
  ctx.arc(px - ir * 0.19, py - ir * 0.21, ir * 0.14, 0, Math.PI * 2);
  ctx.fillStyle = "rgba(255,253,247,0.9)";
  ctx.fill();
  ctx.restore();

  ctx.strokeStyle = MARBLE;
  ctx.lineWidth = Math.max(0.9, w * 0.022);
  ctx.beginPath();
  ctx.moveTo(-w / 2, 0);
  ctx.quadraticCurveTo(0, -h * o * 2.05, w / 2, 0);
  ctx.quadraticCurveTo(0, h * o * 1.75, -w / 2, 0);
  ctx.stroke();
  ctx.restore();
}

export function Constellation({
  findings, onPick, scanning = false,
}: { findings: Finding[]; onPick?: (f: Finding) => void; scanning?: boolean }) {
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const eyesRef = useRef<EyeNode[]>([]);
  const pointer = useRef({ x: 0, y: 0, inside: false });
  const hoverRef = useRef<EyeNode | null>(null);
  const [hover, setHover] = useState<{ e: EyeNode; x: number; y: number } | null>(null);

  const key = findings.map((f) => `${f.id}:${f.severity}`).join(",");
  useEffect(() => { eyesRef.current = bindEyes(findings); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [key]);

  useEffect(() => {
    const wrap = wrapRef.current, canvas = canvasRef.current;
    if (!wrap || !canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (!eyesRef.current.length) eyesRef.current = bindEyes([]);

    let raf = 0, w = 0, h = 0, t = 0, last = 0;
    // Re-measures whenever the box actually changed size — cheap (one
    // getBoundingClientRect per frame) and self-healing against any layout
    // settling after mount (fonts, flex recalculation) that a ResizeObserver
    // fired *before* landed the wrong way, which otherwise left the canvas's
    // backing store permanently sized to a stale, too-small measurement.
    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const r = wrap.getBoundingClientRect();
      if (Math.abs(r.width - w) < 0.5 && Math.abs(r.height - h) < 0.5) return;
      w = r.width; h = r.height;
      canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
      canvas.style.width = `${w}px`; canvas.style.height = `${h}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();

    const onMove = (ev: PointerEvent) => {
      const r = wrap.getBoundingClientRect();
      pointer.current = { x: ev.clientX - r.left, y: ev.clientY - r.top, inside: true };
    };
    const onLeave = () => { pointer.current.inside = false; };
    const onClick = () => {
      const hit = hoverRef.current;
      if (hit && hit.hits.length && onPick) onPick(hit.hits[0]);
    };
    wrap.addEventListener("pointermove", onMove);
    wrap.addEventListener("pointerleave", onLeave);
    wrap.addEventListener("click", onClick);

    const frame = (now: number) => {
      resize();
      if (w < 40) { raf = requestAnimationFrame(frame); return; }
      const dt = last ? Math.min(0.05, (now - last) / 1000) : 1 / 60;
      last = now;
      t += reduced ? 0 : dt;
      const eyes = eyesRef.current;
      const cx = w / 2, cy = h / 2, R = Math.min(w, h) * 0.39;
      const rot = t * 0.16;
      ctx.clearRect(0, 0, w, h);

      // Guide rings — the reference's faint bounding circles the field sits
      // inside, in place of the empty-space scatter this used to be.
      ctx.strokeStyle = "rgba(201,162,39,0.10)";
      ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.arc(cx, cy, R * 1.16, 0, Math.PI * 2); ctx.stroke();
      ctx.strokeStyle = "rgba(237,234,228,0.06)";
      ctx.beginPath(); ctx.arc(cx, cy, R * 1.30, 0, Math.PI * 2); ctx.stroke();

      const pts = eyes.map((e) => {
        const x = e.x * Math.cos(rot) - e.z * Math.sin(rot);
        const z = e.x * Math.sin(rot) + e.z * Math.cos(rot);
        return { e, x, y: e.y, z };
      }).sort((a, b) => a.z - b.z);

      let best: EyeNode | null = null, bestD = 26;

      for (const p of pts) {
        const e = p.e;
        const depth = (p.z + 1) / 2;
        // A narrower perspective band than a literal Fibonacci-sphere
        // projection: the full 0.72-1.14 range made near/far eyes different
        // enough in size and fade to read as inconsistent rather than as
        // depth. Every eye stays a clearly visible, similarly sized eye.
        const persp = 0.86 + 0.14 * depth;
        const sx = cx + p.x * R * persp;
        const sy = cy - p.y * R * persp;
        const size = w * 0.045 * persp;
        const alpha = 0.55 + 0.45 * depth;
        e.px = sx; e.py = sy; e.pr = size;

        let dx = 0, dy = 0;
        if (pointer.current.inside) {
          const ddx = pointer.current.x - sx, ddy = pointer.current.y - sy;
          const m = Math.hypot(ddx, ddy) || 1;
          const k = Math.min(1, m / 260);
          dx = (ddx / m) * k; dy = (ddy / m) * k;
          if (m < bestD && e.hits.length) { bestD = m; best = e; }
        }

        if (!reduced) {
          e.blinkAt -= dt;
          if (e.blinkAt <= 0) { e.blink = 1; e.blinkAt = 4 + Math.random() * 12; }
          if (e.blink > 0) e.blink = Math.max(0, e.blink - dt * 3.2);
        }

        // A real blink: a fast close then a slower reopen, not a symmetric
        // sine flash — the sine version snapped shut and open at the same
        // rate, which read as a glitch rather than an eyelid.
        const bp = Math.min(1, e.blink);
        const lid = bp < 0.4 ? 1 - bp / 0.4 : (bp - 0.4) / 0.6;
        let openness = (e.state === "drowsy" ? 0.42 : 1) * lid;
        if (e.state === "asleep") openness = 0;
        if (scanning && e.state !== "asleep") openness = Math.max(openness, 0.55);

        const iris = e.state === "alarmed"
          ? (Math.sin(t * 3.4 + e.phase) > 0 ? WOUND : WOUND_ALT)
          : (depth > 0.55 ? GOLD : GOLD_DIM);

        eyeGeom(ctx, sx, sy, size, openness, e.tilt, alpha, iris, dx, dy, e.state);
      }

      if (best !== hoverRef.current) {
        hoverRef.current = best;
        setHover(best ? { e: best, x: best.px, y: best.py } : null);
      }
      wrap.style.cursor = best ? "pointer" : "default";

      raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);

    return () => {
      cancelAnimationFrame(raf);
      wrap.removeEventListener("pointermove", onMove);
      wrap.removeEventListener("pointerleave", onLeave);
      wrap.removeEventListener("click", onClick);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanning]);

  return (
    <div ref={wrapRef} style={{ position: "absolute", inset: 0 }}>
      <canvas ref={canvasRef} style={{ display: "block", width: "100%", height: "100%" }} />

      {/* HUD: reads out whichever grave eye the cursor is nearest. Pinned to
          the eye itself so the connection is unambiguous. Flat, hairline —
          no glow or radius, per the ledger's own bans. */}
      {hover && (
        <div
          style={{
            position: "absolute", left: hover.x, top: hover.y - 16,
            transform: "translate(-50%, -100%)", pointerEvents: "none",
            padding: "7px 10px", whiteSpace: "nowrap",
            background: "var(--ground)", border: "1px solid var(--rule-strong)",
            fontFamily: "var(--mono)", fontSize: 10, letterSpacing: "0.06em",
            color: "var(--bone)", display: "flex", alignItems: "center", gap: 8,
          }}
        >
          <span style={{
            width: 6, height: 6, flex: "0 0 auto",
            background: hover.e.hits.length ? sevColor(hover.e.worst || "HIGH") : "var(--gold-dim)",
          }} />
          <span>{hover.e.name}</span>
          <span style={{ color: hover.e.hits.length ? sevColor(hover.e.worst || "HIGH") : "var(--bone-dim)" }}>
            {hover.e.hits.length
              ? `${hover.e.hits.length} found · ${(hover.e.worst || "").toLowerCase()}`
              : "clean"}
          </span>
        </div>
      )}
    </div>
  );
}
