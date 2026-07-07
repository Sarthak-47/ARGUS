import { C, FONT } from "../theme";
import { useStore } from "../store";
import { ArgusEye } from "../components/ArgusEye";

export function LiveAttack() {
  const s = useStore();

  // A real desktop audit runs the CLI as an opaque subprocess — there's no
  // per-agent telemetry to stream, so we show an honest running state (elapsed
  // clock) rather than a simulated feed.
  if (s.auditRunning) {
    const mins = Math.floor(s.auditElapsedSec / 60);
    const secs = s.auditElapsedSec % 60;
    const elapsed = `${mins}:${secs.toString().padStart(2, "0")}`;
    return (
      <section style={{ padding: "28px 40px 42px 40px", height: "100%", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 26 }}>
        <ArgusEye size={64} draw />
        <div style={{ fontFamily: FONT.display, fontSize: 13, letterSpacing: "0.22em", color: C.goldPale }}>
          ARGUS IS RUNNING
        </div>
        <div style={{ fontFamily: FONT.code, fontSize: 14, color: C.stoneText, textAlign: "center" }}>
          {s.phase2 ? "Phase 1 + Phase 2" : "Phase 1"} against <span style={{ color: C.parchment }}>{s.target}</span>
        </div>
        <div style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 13, color: C.stoneText, maxWidth: 420, textAlign: "center" }}>
          {s.phase2
            ? "Active attack agents can take a while against a real target — this isn't a simulation, so there's no progress bar to show, just the clock."
            : "Reading and mapping the codebase — this is usually quick."}
        </div>
        <div style={{ fontFamily: FONT.display, fontSize: 34, fontWeight: 700, color: C.goldenrod, letterSpacing: "0.04em" }}>
          {elapsed}
        </div>
      </section>
    );
  }

  // Idle — nothing running. Point the user at New Scan.
  return (
    <section style={{ padding: "28px 40px 42px 40px", height: "100%", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 24 }}>
      <ArgusEye size={72} opacity={0.5} />
      <div style={{ fontFamily: FONT.display, fontSize: 13, letterSpacing: "0.22em", color: C.goldPale }}>
        NO ATTACK RUNNING
      </div>
      <div style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 15, color: C.stoneText, maxWidth: 440, textAlign: "center", lineHeight: 1.6 }}>
        Start a scan with <span style={{ color: C.parchment }}>Phase 2</span> enabled and Argus will spin the
        target up in a sandbox and attack it live. Progress shows here while it runs.
      </div>
      <button
        onClick={() => s.setScreen("scan")}
        style={{ fontFamily: FONT.display, fontSize: 12, letterSpacing: "0.18em", fontWeight: 600, color: C.goldenrod, background: "transparent", border: `1px solid ${C.bronze}`, padding: "12px 24px", cursor: "pointer" }}
      >
        NEW SCAN
      </button>
    </section>
  );
}
