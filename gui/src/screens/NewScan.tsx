// II · SET THE WATCH — commissioning a sweep: ground/depth/strike/mind as
// dotted leaders on the left, the agent roster on the right. Every count and
// duration is computed from real store state — never a scripted figure.
// See DESIGN.md.

import { useEffect } from "react";
import { C, RF, FONT } from "../theme";
import { AGENTS, DESC } from "../data";
import { useStore } from "../store";
const DEPTH_NOTE: Record<string, string> = {
  Quick: "A look from the outside. Known signatures and the obvious doors.",
  Standard: "Authenticated crawl, dependencies resolved to source, each agent one pass.",
  Deep: "Every lid open. Fuzzing, chained findings, and a second pass over anything that flinched.",
};
const DEPTH_MULT: Record<string, number> = { Quick: 0.4, Standard: 2.2, Deep: 21 };

function estimateWatch(openCount: number, depth: string): string {
  const mins = Math.max(2, Math.round(openCount * (DEPTH_MULT[depth] ?? 2.2)));
  return mins > 90 ? `${(mins / 60).toFixed(1)} h` : `${mins} min`;
}

export function NewScan() {
  const s = useStore();
  const isCode = s.scanMode === "code";
  const openCount = AGENTS.filter((n) => s.scanChecked[n]).length;
  const canStart = isCode ? !!s.target.trim() : !!s.targetUrl.trim();
  const providerReachable = s.isDesktop && s.status?.resolved_provider === s.provider && s.status?.available;
  const estimate = estimateWatch(openCount, s.depth);

  useEffect(() => {
    if (s.isDesktop) s.checkArgusAvailable();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s.isDesktop]);

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <div style={{
        display: "flex", justifyContent: "space-between", padding: "20px 40px 14px", flex: "0 0 auto",
        borderBottom: "1px solid var(--rule-strong)", fontFamily: "var(--mono)", fontSize: 9.5,
        letterSpacing: "0.16em", textTransform: "uppercase", color: "var(--bone-dim-2)",
      }}>
        <span>{openCount} OF {AGENTS.length} AGENTS SELECTED</span>
        <span>{s.depth.toUpperCase()} · {estimate.toUpperCase()} · {s.phase2 && isCode ? "STRIKING" : "READING ONLY"}</span>
      </div>

      <div style={{
        padding: "18px 40px 24px", display: "grid",
        gridTemplateColumns: "minmax(420px,1.15fr) minmax(320px,1fr)", gap: 58, alignItems: "stretch",
        flex: "1 1 auto", minHeight: 0, overflow: "hidden",
      }}>
        <div style={{ minHeight: 0, overflowY: "auto" }}>
          <div style={{ fontFamily: "var(--serif)", fontSize: 34, letterSpacing: "0.02em" }}>Set the watch</div>
          <div style={{ fontFamily: "var(--serif)", fontStyle: "italic", fontSize: 19, color: "var(--bone-dim)", marginTop: 2 }}>name the ground, and the eyes will turn to it</div>

          <div className="col-head" style={{ marginTop: 22 }}>What manner of ground</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 4, paddingTop: 10 }}>
            <button onClick={() => s.setScanMode("code")} style={{
              cursor: "pointer", display: "flex", alignItems: "baseline", gap: 15, background: "none",
              border: "none", padding: "3px 0", textAlign: "left", transition: "all 160ms ease",
            }}>
              <span style={{ fontSize: 13, color: isCode ? RF.clay : "var(--shut)", flex: "0 0 auto" }}>{isCode ? "●" : "○"}</span>
              <span style={{ fontFamily: "var(--serif)", fontSize: isCode ? 30 : 21, lineHeight: 1.15, color: isCode ? "var(--bone)" : "var(--bone-dim-3)", flex: "0 0 auto", transition: "font-size 160ms ease" }}>A repository</span>
              {isCode && <span style={{ fontFamily: "var(--serif)", fontStyle: "italic", fontSize: 18, color: "var(--bone-dim-3)" }}>— a git remote, or a folder on this machine</span>}
            </button>
            <button onClick={() => s.setScanMode("web")} style={{
              cursor: "pointer", display: "flex", alignItems: "baseline", gap: 15, background: "none",
              border: "none", padding: "3px 0", textAlign: "left", transition: "all 160ms ease",
            }}>
              <span style={{ fontSize: 13, color: !isCode ? RF.clay : "var(--shut)", flex: "0 0 auto" }}>{!isCode ? "●" : "○"}</span>
              <span style={{ fontFamily: "var(--serif)", fontSize: !isCode ? 30 : 21, lineHeight: 1.15, color: !isCode ? "var(--bone)" : "var(--bone-dim-3)", flex: "0 0 auto", transition: "font-size 160ms ease" }}>A living target</span>
              {!isCode && <span style={{ fontFamily: "var(--serif)", fontStyle: "italic", fontSize: 18, color: "var(--bone-dim-3)" }}>— a running URL, answering now</span>}
            </button>
          </div>

          <div style={{ fontFamily: "var(--mono)", fontSize: 10, letterSpacing: "0.24em", textTransform: "uppercase", color: "var(--bone-dim)", marginTop: 20 }}>
            {isCode ? "The remote or path" : "The URL"}
          </div>
          <input
            className="line-input"
            value={isCode ? s.target : s.targetUrl}
            onChange={(e) => (isCode ? s.setTarget(e.target.value) : s.setTargetUrl(e.target.value))}
            placeholder={isCode ? "github.com/user/app" : "https://your-app.example.com"}
            spellCheck={false}
            style={{ fontSize: 20, letterSpacing: "0.02em", color: "var(--gold)", borderBottomColor: "var(--bone)", padding: "9px 0 8px" }}
          />

          <div style={{ marginTop: 20, borderTop: "1px solid var(--rule-strong)" }}>
            {isCode && (
              <div className="leader" style={{ padding: "9px 0" }}>
                <span className="k">Also strike after reading</span>
                <span className="dots" />
                <span style={{ display: "flex", gap: 20 }}>
                  {[["no", false], ["yes", true]].map(([label, val]) => (
                    <button key={label as string} className={`pick${s.phase2 === val ? " on" : ""}`} style={{ fontSize: 22 }}
                      onClick={() => { if (s.phase2 !== val) s.togglePhase("phase2"); }}>
                      {label}
                    </button>
                  ))}
                </span>
              </div>
            )}

            <div className="leader" style={{ padding: "9px 0" }}>
              <span className="k">Depth of the sweep</span>
              <span className="dots" />
              <span style={{ display: "flex", gap: 20 }}>
                {(["Quick", "Standard", "Deep"] as const).map((d) => (
                  <button key={d} className={`pick${s.depth === d ? " on" : ""}`} style={{ fontSize: 22 }} onClick={() => s.setDepth(d)}>
                    {d.toLowerCase()}
                  </button>
                ))}
              </span>
            </div>
            <div style={{ fontFamily: "var(--serif)", fontStyle: "italic", fontSize: 15, lineHeight: 1.4, color: "var(--bone-dim-3)", padding: "6px 0 0" }}>{DEPTH_NOTE[s.depth]}</div>

            <div className="leader" style={{ marginTop: 8, padding: "9px 0" }}>
              <span className="k">Which mind reasons</span>
              <span className="dots" />
              <span style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
                <span style={{ width: 6, height: 6, background: providerReachable ? RF.patina : C.crimson, flex: "0 0 auto" }} />
                <span style={{ fontFamily: "var(--serif)", fontSize: 22, color: "var(--bone)" }}>{s.isDesktop && s.provider ? s.provider : "none"}</span>
                <button className="pick" style={{ fontSize: 13 }} onClick={() => s.setScreen("settings")}>change</button>
              </span>
            </div>
            <div style={{ display: "flex", gap: 24, fontSize: 10, letterSpacing: "0.16em", padding: "6px 0 0" }}>
              <span style={{ color: providerReachable ? "var(--gold)" : "var(--grave)" }}>
                {providerReachable ? "REACHABLE" : "UNVERIFIED"}
              </span>
              <span style={{ color: "var(--bone-dim-2)" }}>KEY IN KEEPER VAULT</span>
            </div>
          </div>

          <p style={{ fontFamily: "var(--serif)", fontStyle: "italic", fontSize: 17, lineHeight: 1.5, color: "var(--bone-dim-3)", marginTop: 18 }}>
            Io was watched by one keeper with a hundred eyes, and not one of them was told what to look for.
          </p>

          {s.isDesktop && (s.argusAvailable === false || s.auditError) && (
            <p style={{ fontFamily: FONT.ui, fontSize: 13.5, color: RF.oxbloodHi, lineHeight: 1.6, marginTop: 14 }}>
              {s.argusAvailable === false && (
                <>
                  `argus` could not be reached. Install it with <code>pip install argus-panoptes</code>, or set its path in{" "}
                  <button onClick={() => s.setScreen("settings")} className="pick" style={{ fontSize: 13.5, color: RF.oxbloodHi }}>Settings</button>.
                </>
              )}
              {s.auditError && <span style={{ display: "block", marginTop: 6 }}>{s.auditError}</span>}
            </p>
          )}
        </div>

        <div style={{ display: "flex", flexDirection: "column", minHeight: 0 }}>
          <div className="col-head" style={{ flex: "0 0 auto" }}>The eyes to be opened</div>
          <div className="posture" style={{ padding: "12px 0 18px", flex: "0 0 auto" }}>
            <span className="posture-num" style={{ fontSize: 88 }}>{openCount}</span>
            <span className="posture-of">of<br />{AGENTS.length}</span>
          </div>

          {/* The roster is the one list here long enough to outgrow a short
              window — it scrolls in its own lane so the count above and the
              commit action below stay pinned and visible without the page
              itself ever scrolling. */}
          <div style={{ flex: "1 1 auto", minHeight: 0, overflowY: "auto", paddingTop: 10, borderTop: "1px solid var(--rule-strong)" }}>
            {AGENTS.map((n) => {
              const on = s.scanChecked[n];
              return (
                <button key={n} onClick={() => s.toggleAgent(n)} style={{
                  cursor: "pointer", height: 34, display: "flex", alignItems: "center", gap: 12, width: "100%",
                  background: "none", border: "none", borderBottom: "1px solid var(--ground-raised)", textAlign: "left",
                }}>
                  <span style={{ fontSize: 11, color: on ? "var(--gold)" : "var(--shut)", flex: "0 0 auto" }}>{on ? "●" : "○"}</span>
                  <span style={{ fontFamily: "var(--serif)", fontSize: 19, lineHeight: 1, color: on ? "var(--bone)" : "var(--shut)", flex: "0 0 auto", whiteSpace: "nowrap" }}>{n}</span>
                  <span style={{ flex: 1, borderBottom: "1px dotted var(--rule-dotted)" }} />
                  <span style={{ fontFamily: "var(--mono)", fontSize: 11, letterSpacing: "0.04em", color: on ? "var(--bone-dim)" : "var(--bone-dim-2)", flex: "0 0 auto" }}>{DESC[n]}</span>
                </button>
              );
            })}
          </div>

          <div className="leader" style={{ borderBottom: "none", paddingTop: 16, flex: "0 0 auto" }}>
            <span className="k">Estimated watch</span>
            <span className="dots" />
            <span className="v gold">{estimate}</span>
          </div>

          <button
            className="commit"
            style={{ marginTop: 16, width: "100%", justifyContent: "space-between", fontSize: 25, letterSpacing: "0.22em", borderTop: "1px solid var(--rule-strong)", borderBottom: "none", paddingTop: 22, flex: "0 0 auto" }}
            disabled={s.auditRunning || !canStart}
            onClick={() => { if (s.isDesktop) s.runRealAudit(); else s.setScreen("live"); }}
          >
            {s.auditRunning ? "Watching…" : "Begin the sweep"} <span className="arrow">→</span>
          </button>
        </div>
      </div>
    </div>
  );
}
