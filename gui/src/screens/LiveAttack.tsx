import { useEffect, useRef } from "react";
import { C, FONT, bandColor, bandLabel } from "../theme";
import { AGENTS } from "../data";
import { useStore } from "../store";
import { ArgusEye } from "../components/ArgusEye";

export function LiveAttack() {
  const s = useStore();
  const feedRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = feedRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [s.feed.length]);

  return (
    <section style={{ padding: "28px 40px 42px 40px", height: "100%", display: "flex", flexDirection: "column", minHeight: 0 }}>
      {/* header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24, flex: "0 0 auto" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <ArgusEye size={38} rings={s.activated} />
          <span style={{ fontFamily: FONT.code, fontSize: 13, color: C.stoneText }}>
            {s.report?.target || s.target || "github.com/user/ecommerce-app"}
          </span>
          <span style={{
            fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.22em", color: C.crimson,
            border: `1px solid ${C.crimson}`, padding: "5px 12px",
            animation: s.attackRunning ? "argusPulse 1.5s ease-in-out infinite" : "none",
          }}>
            {s.attackRunning ? "ATTACKING" : "COMPLETE"}
          </span>
        </div>
        <button
          className="btn-outline"
          onClick={() => s.setScreen("report")}
          style={{ fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.18em", color: C.crimson, background: "transparent", border: `1px solid ${C.relief}`, padding: "10px 20px", cursor: "pointer" }}
        >
          STOP
        </button>
      </div>

      {/* metrics */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 1, background: C.relief, border: `1px solid ${C.relief}`, marginBottom: 20, flex: "0 0 auto" }}>
        <div style={{ background: C.stoneDark, padding: "22px 26px" }}>
          <Cap>RISK SCORE</Cap>
          <div style={{ display: "flex", alignItems: "flex-end", gap: 20 }}>
            <span style={{ fontFamily: FONT.display, fontSize: 60, fontWeight: 700, color: C.goldPale, lineHeight: 0.8 }}>{s.riskScore}</span>
            <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 9, paddingBottom: 8 }}>
              <span style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 14, color: bandColor(s.riskScore) }}>{bandLabel(s.riskScore)}</span>
              <span style={{ height: 5, background: C.relief, width: "100%" }}>
                <span style={{ display: "block", height: "100%", width: `${Math.min(100, Math.round((s.riskScore / 74) * 100))}%`, background: bandColor(s.riskScore), transition: "width 0.4s ease, background 0.4s ease" }} />
              </span>
            </div>
          </div>
        </div>
        <div style={{ background: C.stoneDark, padding: "22px 26px" }}>
          <Cap>CONFIRMED EXPLOITS</Cap>
          <div style={{ display: "flex", alignItems: "flex-end", gap: 20 }}>
            <span
              key={s.confFlash}
              style={{ fontFamily: FONT.display, fontSize: 60, fontWeight: 700, color: C.crimson, lineHeight: 0.8, animation: s.confFlash ? "argusFlashNum 0.4s ease-out" : "none" }}
            >
              {s.confirmed}
            </span>
            <span style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 14, color: C.stoneText, paddingBottom: 10 }}>
              {s.attackRunning ? "and rising" : "final"}
            </span>
          </div>
        </div>
      </div>

      {/* agents + feed */}
      <div style={{ display: "grid", gridTemplateColumns: "0.618fr 1fr", gap: 20, flex: 1, minHeight: 0 }}>
        <div style={{ background: C.stoneDark, border: `1px solid ${C.relief}`, display: "flex", flexDirection: "column", minHeight: 0 }}>
          <div style={{ ...panelHeader }}>AGENTS</div>
          <div style={{ overflowY: "auto", overflowX: "hidden", flex: 1, minHeight: 0 }}>
            {AGENTS.map((n) => {
              const a = s.agents[n];
              const running = a.status === "running";
              const complete = a.status === "complete";
              return (
                <div key={n} style={{ display: "grid", gridTemplateColumns: "12px 1fr auto", alignItems: "center", gap: 12, padding: "12px 18px", borderBottom: "1px solid rgba(184,134,11,0.12)" }}>
                  <span style={{
                    width: 12, height: 12, borderRadius: 2, flex: "0 0 auto",
                    border: complete ? "none" : `1.5px solid ${running ? C.bronze : C.relief}`,
                    background: complete ? C.goldenrod : running ? C.bronze : "transparent",
                    animation: running ? "argusPulse 1.8s ease-in-out infinite" : "none",
                  }} />
                  <div style={{ display: "flex", flexDirection: "column", gap: 6, minWidth: 0 }}>
                    <div style={{ display: "flex", alignItems: "baseline", gap: 9, minWidth: 0 }}>
                      <span style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.08em", color: a.status === "queued" ? C.weathered : C.goldenrod, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", minWidth: 0 }}>
                        {n.toUpperCase()}
                      </span>
                      <span style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 12, color: C.stoneText, flex: "0 0 auto" }}>{a.status}</span>
                    </div>
                    <div style={{ height: 3, background: C.relief, width: "100%" }}>
                      <span style={{ display: "block", height: "100%", width: `${a.progress || 0}%`, background: C.bronze, transition: "width 0.4s ease" }} />
                    </div>
                  </div>
                  <div style={{ textAlign: "right", display: "flex", flexDirection: "column", gap: 3 }}>
                    <span style={{ fontFamily: FONT.code, fontSize: 11, color: a.confirmed ? C.crimson : C.weathered }}>{a.confirmed ? `${a.confirmed} hit` : "0"}</span>
                    <span style={{ fontFamily: FONT.code, fontSize: 10, color: C.stoneText }}>{a.sent ? `${a.sent} sent` : a.status === "queued" ? "queued" : "—"}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div style={{ position: "relative", background: "#0B0B10", border: `1px solid ${C.relief}`, display: "flex", flexDirection: "column", minHeight: 0 }}>
          <svg style={{ position: "absolute", inset: 0, width: "100%", height: "100%", pointerEvents: "none", zIndex: 2 }} preserveAspectRatio="none">
            <rect x="1" y="1" width="99.6%" height="99.4%" fill="none" stroke={C.bronze} strokeWidth="2" pathLength={480} strokeDasharray="6 5"
              style={{ opacity: 0.6, animation: s.attackRunning ? "argusTrace 4s linear infinite" : "none" }} />
          </svg>
          <div style={{ ...panelHeader, position: "relative", zIndex: 3 }}>LIVE FEED</div>
          <div ref={feedRef} style={{ overflowY: "auto", flex: 1, minHeight: 0, padding: "8px 0", position: "relative", zIndex: 3, fontFamily: FONT.code, fontSize: 12.5, lineHeight: 1.55 }}>
            {s.feed.map((l) => {
              const crit = l.sev === "crit";
              const high = l.sev === "high";
              const textColor = crit ? C.crimson : high ? C.sienna : C.parchment;
              return (
                <div key={l.id} style={{
                  display: "flex", gap: 10, padding: "4px 18px",
                  borderLeft: `2px solid ${crit ? C.crimson : high ? C.sienna : "transparent"}`,
                  background: crit ? "rgba(139,0,0,0.10)" : high ? "rgba(139,69,19,0.08)" : "transparent",
                  animation: crit ? "argusCrimson 0.45s ease-out" : "none",
                }}>
                  <span style={{ color: C.bronze }}>[{l.agent}]</span>
                  <span style={{ color: textColor, fontWeight: crit || high ? 500 : 400 }}>{crit || high ? "✓ " : ""}{l.text}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}

const panelHeader = {
  fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.22em", color: C.stoneText,
  padding: "14px 18px", borderBottom: `1px solid ${C.relief}`, flex: "0 0 auto" as const,
};

function Cap({ children }: { children: React.ReactNode }) {
  return <div style={{ fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.22em", color: C.stoneText, marginBottom: 14 }}>{children}</div>;
}
