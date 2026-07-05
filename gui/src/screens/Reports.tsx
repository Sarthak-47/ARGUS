import { C, FONT, sevColor, bandColor } from "../theme";
import { FINDINGS } from "../data";
import { useStore } from "../store";
import { GreekKeyDivider } from "../components/Decor";

export function Reports() {
  const s = useStore();
  const live = s.report;
  const allFindings = live ? live.findings : FINDINGS;
  const target = live ? live.target : "github.com/user/ecommerce-app";

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 } as Record<string, number>;
  allFindings.forEach((f) => (counts[f.severity] = (counts[f.severity] || 0) + 1));
  const filtered = s.filter === "All" ? allFindings : allFindings.filter((f) => f.severity === s.filter.toUpperCase());
  const sel = allFindings.find((f) => f.id === s.selectedId) || null;

  return (
    <section style={{ display: "flex", height: "100%", minHeight: 0, position: "relative", overflow: "hidden" }}>
      <div style={{ flex: 1, minWidth: 0, overflowY: "auto", padding: "32px 42px 64px 42px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 28 }}>
          <div style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.22em", color: C.stoneText, display: "flex", alignItems: "center", gap: 10 }}>
            <span>
              ARGUS <span style={{ color: C.relief }}>/</span>{" "}
              <span style={{ fontFamily: FONT.code, letterSpacing: 0, fontSize: 12, color: C.parchment }}>{target}</span>{" "}
              <span style={{ color: C.relief }}>/</span> <span style={{ color: C.goldenrod }}>REPORT</span>
            </span>
            <span style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 12, letterSpacing: 0, color: live ? C.goldenrod : C.stoneText }}>
              {live ? "● live data" : "○ demo data"}
            </span>
          </div>
          <button className="btn-ghost" style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.16em", color: C.bronze, background: "transparent", border: `1px solid ${C.bronze}`, padding: "10px 18px", cursor: "pointer" }}>
            EXPORT REPORT
          </button>
        </div>

        {/* summary */}
        <div style={{ border: `1px solid ${C.relief}`, background: C.stoneDark, padding: 38, display: "flex", alignItems: "center", gap: 52, marginBottom: 6 }}>
          <div style={{ textAlign: "center", paddingRight: 52, borderRight: `1px solid ${C.relief}` }}>
            <div style={{ fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.22em", color: C.stoneText, marginBottom: 12 }}>RISK SCORE</div>
            <div style={{ fontFamily: FONT.display, fontSize: 78, fontWeight: 700, color: live ? bandColor(live.riskScore) : C.sienna, lineHeight: 0.8 }}>
              {live ? live.riskScore : s.reportRisk}
            </div>
            <div style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 16, letterSpacing: "0.04em", color: live ? bandColor(live.riskScore) : C.sienna, marginTop: 10 }}>
              {live ? live.band : "High"}
            </div>
          </div>
          <div style={{ display: "flex", gap: 44, flex: 1 }}>
            {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((lbl) => (
              <div key={lbl} style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
                  <span style={{ width: 10, height: 10, borderRadius: 2, background: sevColor(lbl) }} />
                  <span style={{ fontFamily: FONT.display, fontSize: 38, fontWeight: 600, color: sevColor(lbl), lineHeight: 0.8 }}>{counts[lbl] || 0}</span>
                </div>
                <div style={{ fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.18em", color: C.stoneText }}>{lbl}</div>
              </div>
            ))}
          </div>
        </div>

        <GreekKeyDivider />

        {/* filter tabs */}
        <div style={{ display: "flex", gap: 8, margin: "0 0 14px" }}>
          {["All", "Critical", "High", "Medium", "Low"].map((t) => {
            const on = s.filter === t;
            return (
              <button key={t} onClick={() => s.setFilter(t)} style={{
                fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.14em", padding: "9px 18px", cursor: "pointer",
                background: on ? C.ember : "transparent", border: `1px solid ${on ? C.goldenrod : C.relief}`, color: on ? C.goldPale : C.stoneText,
              }}>
                {t}
              </button>
            );
          })}
        </div>

        {/* findings */}
        <div style={{ border: `1px solid ${C.relief}`, background: C.stoneDark }}>
          {filtered.map((f) => {
            const isSel = s.selectedId === f.id;
            return (
              <button key={f.id} className="row-hover" onClick={() => s.select(f.id)} style={{
                display: "flex", alignItems: "center", gap: 16, width: "100%", textAlign: "left", cursor: "pointer",
                padding: "15px 22px", border: "none", borderBottom: "1px solid rgba(184,134,11,0.12)",
                borderLeft: `2px solid ${isSel ? C.goldenrod : "transparent"}`, background: isSel ? C.ember : "transparent",
              }}>
                <span style={{ display: "flex", alignItems: "center", gap: 11, minWidth: 108, flex: "0 0 auto" }}>
                  <span style={{ width: 9, height: 9, borderRadius: 2, background: sevColor(f.severity), flex: "0 0 auto" }} />
                  <span style={{ fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.12em", color: sevColor(f.severity) }}>{f.severity}</span>
                </span>
                <span style={{ fontFamily: FONT.body, fontSize: 17, color: C.parchment, flex: "1 1 0", minWidth: 150, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.name}</span>
                <span style={{ fontFamily: FONT.code, fontSize: 11.5, color: C.stoneText, width: 168, flex: "0 0 auto", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.endpoint}</span>
                <span style={{ fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.06em", color: C.bronze, width: 100, flex: "0 0 auto" }}>{f.agent}</span>
                <span style={{ fontFamily: FONT.code, fontSize: 11, color: C.stoneText, width: 50, flex: "0 0 auto", textAlign: "right" }}>{f.cvss}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* detail panel */}
      <div style={{
        position: "absolute", top: 0, right: 0, bottom: 0, width: 448, background: "#0B0B10", borderLeft: `1px solid ${C.relief}`,
        transform: sel ? "translateX(0)" : "translateX(100%)", transition: "transform 0.18s ease-out", zIndex: 5,
      }}>
        {sel && (
          <div style={{ display: "flex", flexDirection: "column", height: "100%", minHeight: 0 }}>
            <div style={{ padding: "24px 26px", borderBottom: `1px solid ${C.relief}`, flex: "0 0 auto" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
                <span style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <span style={{ width: 10, height: 10, borderRadius: 2, background: sevColor(sel.severity) }} />
                  <span style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.18em", color: sevColor(sel.severity) }}>{sel.severity}</span>
                </span>
                <button onClick={() => s.select(null)} style={{ background: "none", border: "none", color: C.stoneText, fontSize: 18, cursor: "pointer", lineHeight: 1 }}>✕</button>
              </div>
              <div style={{ fontFamily: FONT.display, fontSize: 17, letterSpacing: "0.04em", color: C.goldPale, marginBottom: 10 }}>{sel.name}</div>
              <span style={{ fontFamily: FONT.code, fontSize: 12, color: C.bronze }}>{sel.endpoint}</span>
              <div style={{ display: "flex", gap: 20, marginTop: 14, fontFamily: FONT.body, fontStyle: "italic", fontSize: 14, color: C.stoneText }}>
                <span>Found by <span style={{ fontStyle: "normal", color: C.bronze, fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.06em" }}>{sel.agent}</span></span>
                <span>CVSS <span style={{ fontStyle: "normal", color: sevColor(sel.severity), fontFamily: FONT.code }}>{sel.cvss}</span></span>
              </div>
              {sel.file && sel.line != null && (
                <button
                  onClick={() => s.openCodeView(sel.file!, sel.line!)}
                  style={{ marginTop: 16, fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.16em", color: C.bronze, background: "transparent", border: `1px solid ${C.bronze}`, padding: "9px 16px", cursor: "pointer" }}
                >
                  VIEW IN CODE
                </button>
              )}
            </div>
            <div style={{ overflowY: "auto", flex: 1, minHeight: 0, padding: "4px 0" }}>
              <Section title="WHAT IS IT"><div style={{ fontFamily: FONT.body, fontSize: 16, lineHeight: 1.55, color: C.parchment }}>{sel.whatIs}</div></Section>
              <Section title="EVIDENCE">
                <SubCap color={C.goldenrod}>REQUEST</SubCap>
                <Pre>{sel.request}</Pre>
                <div style={{ height: 12 }} />
                <SubCap color={C.crimson}>RESPONSE</SubCap>
                <Pre>{sel.response}</Pre>
              </Section>
              <Section title="REPRODUCTION"><div style={{ fontFamily: FONT.code, fontSize: 12, lineHeight: 1.7, color: C.parchment, whiteSpace: "pre-wrap" }}>{sel.repro}</div></Section>
              <Section title="FIX" last><Pre>{sel.fix}</Pre></Section>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}

function Section({ title, children, last }: { title: string; children: React.ReactNode; last?: boolean }) {
  return (
    <div style={{ padding: "20px 26px", borderBottom: last ? "none" : "1px solid rgba(184,134,11,0.12)" }}>
      <div style={{ fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.22em", color: C.stoneText, marginBottom: 10 }}>{title}</div>
      {children}
    </div>
  );
}

function SubCap({ children, color }: { children: React.ReactNode; color: string }) {
  return <div style={{ fontFamily: FONT.display, fontSize: 9, letterSpacing: "0.18em", color, marginBottom: 6 }}>{children}</div>;
}

function Pre({ children }: { children: React.ReactNode }) {
  return (
    <pre style={{ margin: 0, background: C.obsidian, border: `1px solid ${C.relief}`, padding: "12px 14px", fontFamily: FONT.code, fontSize: 11.5, color: C.parchment, whiteSpace: "pre-wrap", wordBreak: "break-word", lineHeight: 1.5 }}>
      {children}
    </pre>
  );
}
