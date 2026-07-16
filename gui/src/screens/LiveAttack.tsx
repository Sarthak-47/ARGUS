import { RF, FONT } from "../theme";
import { AGENTS } from "../data";
import { useStore } from "../store";
import { EyeGlyph, TerracottaMark, ScreenHeader } from "../components/Panoptes";

export function LiveAttack() {
  const s = useStore();

  // While an audit runs, the engine streams real per-agent events (desktop
  // only). We render whatever it has actually emitted — no fabricated feed —
  // and fall back to the eyes + clock when nothing has streamed yet.
  if (s.auditRunning) {
    const mins = Math.floor(s.auditElapsedSec / 60);
    const secs = s.auditElapsedSec % 60;
    const elapsed = `${mins}:${secs.toString().padStart(2, "0")}`;
    const opened = AGENTS.filter((n) => s.scanChecked[n]);
    const phaseLabel = s.phase1 && s.phase2 ? "Phase 1 + Phase 2" : s.phase1 ? "Phase 1" : "Phase 2";
    const effectiveTarget = !s.phase1 && s.phase2 && s.targetUrl.trim() ? s.targetUrl : s.target;

    return (
      <section>
        <ScreenHeader
          title="Live Attack"
          subtitle={`${phaseLabel} against ${effectiveTarget}`}
          action={
            <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
              <span style={{ width: 9, height: 9, borderRadius: "50%", background: RF.oxbloodHi, animation: "argusPulse 1.4s ease-in-out infinite" }} />
              <span style={{ fontFamily: FONT.display, fontSize: 28, fontWeight: 700, color: RF.clay, letterSpacing: "0.04em", fontVariantNumeric: "tabular-nums" }}>{elapsed}</span>
              {s.isDesktop && (
                <button
                  disabled={s.auditCanceling}
                  onClick={() => s.cancelAudit()}
                  style={{
                    fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.14em", textTransform: "uppercase",
                    color: RF.dust, background: "transparent", border: `1px solid ${RF.diluteLo}`, padding: "8px 16px",
                    cursor: s.auditCanceling ? "wait" : "pointer",
                  }}
                >
                  {s.auditCanceling ? "Canceling…" : "Cancel"}
                </button>
              )}
            </div>
          }
        />

        <div style={{ padding: "30px 46px" }}>
          <div style={{ fontFamily: FONT.display, fontSize: 10.5, letterSpacing: "0.2em", textTransform: "uppercase", color: RF.dust, marginBottom: 18 }}>
            Agents running · {opened.length} live
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: "12px 16px", marginBottom: 32 }}>
            {AGENTS.map((n, i) => {
              const on = s.scanChecked[n];
              return (
                <div key={n} style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 12px", background: RF.glazeLo, border: `1px solid ${on ? RF.dilute : RF.diluteLo}`, opacity: on ? 1 : 0.4 }}>
                  <span style={{ display: "inline-flex", lineHeight: 0, animation: on ? `argusBreathe 2.6s ease-in-out ${(i % 5) * 0.3}s infinite` : "none" }}>
                    <EyeGlyph sleeping={!on} w={22} h={14} />
                  </span>
                  <span style={{ fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.06em", textTransform: "uppercase", color: on ? RF.clayHi : RF.dust }}>{n}</span>
                </div>
              );
            })}
          </div>
          {s.feed.length > 0 ? (
            <div>
              <div style={{ fontFamily: FONT.display, fontSize: 10.5, letterSpacing: "0.2em", textTransform: "uppercase", color: RF.dust, marginBottom: 14 }}>
                Live feed · {s.feed.length}
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 3, maxHeight: 320, overflowY: "auto", paddingRight: 8 }}>
                {s.feed.slice().reverse().map((l) => {
                  const crit = l.sev === "crit";
                  return (
                    <div key={l.id} style={{ display: "flex", alignItems: "baseline", gap: 12, padding: "5px 0", borderBottom: `1px solid ${RF.diluteLo}` }}>
                      <span style={{ flex: "0 0 auto", width: 6, height: 6, borderRadius: "50%", marginTop: 6, background: crit ? RF.oxbloodHi : RF.dilute }} />
                      <span style={{ flex: "0 0 118px", fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.06em", textTransform: "uppercase", color: RF.clay }}>{l.agent}</span>
                      <span style={{ fontFamily: FONT.body, fontSize: 14.5, color: crit ? RF.parchment : RF.dust }}>
                        {crit ? "✓ " : ""}{l.text}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          ) : (
            <p style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 15, color: RF.dust, maxWidth: "60ch" }}>
              {s.phase2
                ? "Argus is attacking a real target. The live feed will fill in as the agents confirm findings."
                : "Reading and mapping the code — this is usually quick."}
            </p>
          )}
        </div>
      </section>
    );
  }

  // Idle
  return (
    <section>
      <ScreenHeader title="Live Attack" />
      <div style={{ height: "calc(100% - 71px)", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 22, padding: 40 }}>
        <TerracottaMark size={72} color={RF.dilute} />
        <div style={{ fontFamily: FONT.display, fontSize: 13, letterSpacing: "0.22em", textTransform: "uppercase", color: RF.clayHi }}>Nothing running</div>
        <div style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 15, color: RF.dust, maxWidth: 440, textAlign: "center", lineHeight: 1.6 }}>
          Start a scan with <span style={{ color: RF.parchment }}>Strike the app</span> enabled and Argus spins the target up and attacks it live. Progress shows here while it runs.
        </div>
        <button onClick={() => s.setScreen("scan")} style={{ fontFamily: FONT.display, fontSize: 12, letterSpacing: "0.18em", textTransform: "uppercase", color: RF.clay, background: "transparent", border: `1px solid ${RF.dilute}`, padding: "12px 24px", cursor: "pointer" }}>
          New scan
        </button>
      </div>
    </section>
  );
}
