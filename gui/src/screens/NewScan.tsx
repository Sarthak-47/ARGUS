import { useEffect } from "react";
import { C, RF, FONT } from "../theme";
import { AGENTS, DESC } from "../data";
import { useStore } from "../store";
import { EyeGlyph, ScreenHeader } from "../components/Panoptes";

export function NewScan() {
  const s = useStore();
  const allOn = AGENTS.every((n) => s.scanChecked[n]);

  useEffect(() => {
    if (s.isDesktop) s.checkArgusAvailable();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s.isDesktop]);

  return (
    <section>
      <ScreenHeader title="New Scan" subtitle="point Argus at a target" />

      <div style={{ padding: "22px 46px 64px", maxWidth: 1500 }}>
        <Label>Target</Label>
        <div style={{ display: "flex", gap: 10, marginBottom: s.isDesktop ? 10 : 34 }}>
          <input
            value={s.target}
            onChange={(e) => s.setTarget(e.target.value)}
            placeholder="github.com/user/app or a local path"
            style={{ flex: 1, background: RF.glazeLo, border: `1px solid ${RF.dilute}`, color: RF.ivory, fontFamily: FONT.code, fontSize: 14, padding: "13px 16px", outline: "none" }}
          />
          <button className="btn-outline" style={ghostBtn}>Browse local</button>
        </div>

        {s.isDesktop && (
          <div style={{ marginBottom: 32, fontFamily: FONT.body, fontStyle: "italic", fontSize: 13 }}>
            {s.argusAvailable === false && (
              <span style={{ color: C.crimson }}>
                `argus` couldn't be reached — install it with <code style={{ fontStyle: "normal" }}>pip install argus-panoptes</code>,
                or set its exact path in{" "}
                <button onClick={() => s.setScreen("settings")} style={{ background: "none", border: "none", padding: 0, color: C.crimson, textDecoration: "underline", fontStyle: "italic", fontSize: 13, cursor: "pointer" }}>
                  Settings
                </button>.
              </span>
            )}
            {s.argusAvailable && <span style={{ color: RF.dust }}>Desktop shell detected — this invokes the real Argus engine, not demo data.</span>}
            {s.auditError && <div style={{ color: C.crimson, marginTop: 6 }}>{s.auditError}</div>}
          </div>
        )}

        <Label>Scan mode</Label>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 34 }}>
          {([
            { key: "phase1" as const, num: "I", title: "Read the code", desc: "static analysis · never runs it" },
            { key: "phase2" as const, num: "II", title: "Strike the app", desc: "the swarm attacks it, live" },
          ]).map((p) => {
            const on = s[p.key];
            return (
              <button key={p.key} onClick={() => s.togglePhase(p.key)} style={{
                display: "flex", alignItems: "center", gap: 12, padding: "15px 16px", cursor: "pointer", textAlign: "left",
                background: on ? `linear-gradient(180deg, ${RF.ember}, ${RF.glazeLo})` : RF.glazeLo,
                border: `1px solid ${on ? RF.clay : RF.diluteLo}`, position: "relative",
              }}>
                <span style={{ fontFamily: FONT.display, fontSize: 14, color: RF.clay, width: 22 }}>{p.num}</span>
                <span style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                  <span style={{ fontFamily: FONT.body, fontSize: 18, color: on ? RF.ivory : RF.dust }}>{p.title}</span>
                  <span style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 13, color: RF.dust }}>{p.desc}</span>
                </span>
                <span style={{ marginLeft: "auto", width: 10, height: 10, borderRadius: "50%", background: on ? RF.clay : RF.diluteLo, boxShadow: on ? `0 0 0 3px rgba(197,106,51,0.16)` : "none" }} />
              </button>
            );
          })}
        </div>

        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
          <span style={{ fontFamily: FONT.display, fontSize: 10.5, letterSpacing: "0.2em", textTransform: "uppercase", color: RF.dust }}>Attack agents — the eyes you open</span>
          <button onClick={s.selectAllAgents} style={{ background: "none", border: "none", color: RF.clay, fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.14em", textTransform: "uppercase", cursor: "pointer" }}>
            {allOn ? "Deselect all" : "Select all"}
          </button>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(250px, 1fr))", gap: 9, marginBottom: 34 }}>
          {AGENTS.map((n) => {
            const on = s.scanChecked[n];
            return (
              <button key={n} onClick={() => s.toggleAgent(n)} style={{
                display: "flex", alignItems: "center", gap: 11, padding: "12px 14px", cursor: "pointer", textAlign: "left",
                background: RF.glazeLo, border: `1px solid ${on ? RF.dilute : RF.diluteLo}`, opacity: on ? 1 : 0.5,
              }}>
                <EyeGlyph sleeping={!on} w={24} h={15} />
                <span style={{ display: "flex", flexDirection: "column", gap: 1 }}>
                  <span style={{ fontFamily: FONT.display, fontSize: 10.5, letterSpacing: "0.06em", textTransform: "uppercase", color: on ? RF.clayHi : RF.dust }}>{n}</span>
                  <span style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 12.5, color: RF.dust }}>{DESC[n]}</span>
                </span>
              </button>
            );
          })}
        </div>

        <div style={{ display: "flex", gap: 50, marginBottom: 36, alignItems: "flex-end" }}>
          <div>
            <Label>Depth</Label>
            <div style={{ display: "flex", gap: 8 }}>
              {(["Quick", "Standard", "Deep"] as const).map((d) => {
                const on = s.depth === d;
                return (
                  <button key={d} onClick={() => s.setDepth(d)} style={{
                    fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.1em", textTransform: "uppercase", padding: "10px 20px", cursor: "pointer",
                    border: `1px solid ${on ? RF.clay : RF.diluteLo}`, background: on ? `linear-gradient(180deg, ${RF.clayHi}, ${RF.clay})` : "transparent", color: on ? RF.glaze : RF.dust,
                  }}>{d}</button>
                );
              })}
            </div>
          </div>
          <div>
            <Label>LLM provider</Label>
            <div style={{ display: "flex", alignItems: "center", gap: 12, background: RF.glazeLo, border: `1px solid ${RF.diluteLo}`, padding: "11px 16px" }}>
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: s.isDesktop && s.status?.resolved_provider && s.status.available ? RF.clay : C.crimson }} />
              <span style={{ fontFamily: FONT.display, fontSize: 12, letterSpacing: "0.1em", textTransform: "uppercase", color: RF.clayHi }}>
                {(s.isDesktop && s.status?.resolved_provider ? s.provider : "no provider").toUpperCase()}
              </span>
            </div>
          </div>
        </div>

        <button
          className="btn-solid"
          disabled={s.auditRunning}
          onClick={() => { if (s.isDesktop && s.target.trim()) s.runRealAudit(); else s.setScreen("live"); }}
          style={{
            width: "100%", display: "flex", alignItems: "center", justifyContent: "center", gap: 14,
            fontFamily: FONT.display, fontSize: 14, letterSpacing: "0.24em", textTransform: "uppercase", fontWeight: 600,
            color: RF.glaze, background: `linear-gradient(180deg, ${RF.clayHi}, ${RF.clay})`, border: "none", padding: 17,
            cursor: s.auditRunning ? "wait" : "pointer", opacity: s.auditRunning ? 0.6 : 1,
          }}
        >
          {s.auditRunning ? "Running…" : "Start scan"} <span style={{ fontSize: 13 }}>&#8594;</span>
        </button>
      </div>
    </section>
  );
}

const ghostBtn = {
  background: RF.glazeLo, border: `1px solid ${RF.diluteLo}`, color: RF.dust,
  fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.12em", textTransform: "uppercase" as const, padding: "0 20px",
  cursor: "pointer", whiteSpace: "nowrap" as const,
};

function Label({ children }: { children: React.ReactNode }) {
  return <div style={{ fontFamily: FONT.display, fontSize: 10.5, letterSpacing: "0.2em", textTransform: "uppercase", color: RF.dust, marginBottom: 12 }}>{children}</div>;
}
