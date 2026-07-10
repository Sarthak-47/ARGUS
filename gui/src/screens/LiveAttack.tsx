import { RF, FONT } from "../theme";
import { AGENTS } from "../data";
import { useStore } from "../store";
import { EyeGlyph, TerracottaMark, ScreenHeader } from "../components/Panoptes";

export function LiveAttack() {
  const s = useStore();

  // A real desktop audit runs the CLI as an opaque subprocess — there's no
  // per-agent telemetry to stream, so we show an honest running state: the eyes
  // that were opened, keeping watch, and the clock. No fabricated feed.
  if (s.auditRunning) {
    const mins = Math.floor(s.auditElapsedSec / 60);
    const secs = s.auditElapsedSec % 60;
    const elapsed = `${mins}:${secs.toString().padStart(2, "0")}`;
    const opened = AGENTS.filter((n) => s.scanChecked[n]);

    return (
      <section>
        <ScreenHeader
          title="Live Attack"
          subtitle={`${s.phase2 ? "Phase 1 + Phase 2" : "Phase 1"} against ${s.target}`}
          action={
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <span style={{ width: 9, height: 9, borderRadius: "50%", background: RF.oxbloodHi, animation: "argusPulse 1.4s ease-in-out infinite" }} />
              <span style={{ fontFamily: FONT.display, fontSize: 28, fontWeight: 700, color: RF.clay, letterSpacing: "0.04em", fontVariantNumeric: "tabular-nums" }}>{elapsed}</span>
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
          <p style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 15, color: RF.dust, maxWidth: "60ch" }}>
            {s.phase2
              ? "Argus is attacking a real target. It's not a simulation, so there's no scripted feed — just the elapsed clock while the agents work."
              : "Reading and mapping the code — this is usually quick."}
          </p>
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
