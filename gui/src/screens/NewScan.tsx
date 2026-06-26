import { C, FONT } from "../theme";
import { AGENTS, DESC } from "../data";
import { useStore } from "../store";

export function NewScan() {
  const s = useStore();
  const allOn = AGENTS.every((n) => s.scanChecked[n]);

  return (
    <section style={{ padding: "36px 46px 64px 46px", maxWidth: 900 }}>
      <div style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.24em", color: C.stoneText, marginBottom: 34 }}>
        ARGUS <span style={{ color: C.relief }}>/</span> <span style={{ color: C.goldenrod }}>NEW AUDIT</span>
      </div>

      <Label>TARGET</Label>
      <div style={{ display: "flex", gap: 10, marginBottom: 38 }}>
        <input
          defaultValue="https://github.com/user/ecommerce-app"
          style={{
            flex: 1, background: C.stoneDark, border: `1px solid ${C.bronze}`, color: C.parchment,
            fontFamily: FONT.code, fontSize: 13, padding: "14px 16px", outline: "none",
          }}
        />
        <button className="btn-outline" style={ghostBtn}>BROWSE LOCAL</button>
      </div>

      <Label>AUDIT MODE</Label>
      <div style={{ display: "flex", flexDirection: "column", gap: 10, marginBottom: 38 }}>
        {([
          { key: "phase1" as const, title: "PHASE 1 · STATIC ANALYSIS", desc: "Read the source. Map the attack surface." },
          { key: "phase2" as const, title: "PHASE 2 · ACTIVE ATTACK", desc: "Launch agents. Confirm exploits live." },
        ]).map((p) => {
          const on = s[p.key];
          return (
            <div key={p.key} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", background: C.stoneDark, border: `1px solid ${C.relief}`, padding: "16px 20px" }}>
              <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                <span style={{ fontFamily: FONT.display, fontSize: 12, letterSpacing: "0.12em", color: C.parchment }}>{p.title}</span>
                <span style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 14, color: C.stoneText }}>{p.desc}</span>
              </div>
              <button
                onClick={() => s.togglePhase(p.key)}
                style={{
                  width: 44, height: 22, borderRadius: 2, border: `1px solid ${on ? C.goldenrod : C.relief}`,
                  background: on ? "rgba(184,134,11,0.18)" : C.obsidian, position: "relative", cursor: "pointer", padding: 0, flex: "0 0 auto",
                }}
              >
                <span style={{ position: "absolute", top: 2, left: on ? 24 : 2, width: 16, height: 16, borderRadius: 1, background: on ? C.goldenrod : C.weathered, transition: "left 0.18s ease, background 0.18s ease" }} />
              </button>
            </div>
          );
        })}
      </div>

      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
        <span style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.22em", color: C.goldPale }}>ATTACK AGENTS</span>
        <button onClick={s.selectAllAgents} style={{ background: "none", border: "none", color: C.bronze, fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.14em", cursor: "pointer" }}>
          {allOn ? "Deselect All" : "Select All"}
        </button>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 8, marginBottom: 38 }}>
        {AGENTS.map((n) => {
          const on = s.scanChecked[n];
          return (
            <button
              key={n}
              onClick={() => s.toggleAgent(n)}
              style={{
                display: "flex", alignItems: "flex-start", gap: 10, padding: "13px 14px", cursor: "pointer", textAlign: "left",
                background: C.stoneDark, border: `1px solid ${on ? "rgba(184,134,11,0.45)" : C.relief}`, color: on ? C.parchment : C.stoneText,
              }}
            >
              <span style={{
                width: 16, height: 16, display: "flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto", borderRadius: 2,
                border: `1px solid ${on ? C.goldenrod : C.relief}`, background: on ? C.goldenrod : "transparent", color: C.obsidian, fontSize: 11, lineHeight: 1,
              }}>
                {on ? "✓" : ""}
              </span>
              <span style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                <span style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.08em" }}>{n}</span>
                <span style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 12, color: C.stoneText }}>{DESC[n]}</span>
              </span>
            </button>
          );
        })}
      </div>

      <div style={{ display: "flex", gap: 50, marginBottom: 42 }}>
        <div>
          <Label>DEPTH</Label>
          <div style={{ display: "flex", gap: 8 }}>
            {(["Quick", "Standard", "Deep"] as const).map((d) => {
              const on = s.depth === d;
              return (
                <button
                  key={d}
                  onClick={() => s.setDepth(d)}
                  style={{
                    fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.1em", padding: "10px 22px", cursor: "pointer",
                    border: `1px solid ${on ? C.goldenrod : C.relief}`, background: on ? C.goldenrod : "transparent", color: on ? C.obsidian : C.stoneText,
                  }}
                >
                  {d}
                </button>
              );
            })}
          </div>
        </div>
        <div>
          <Label>LLM PROVIDER</Label>
          <div style={{ display: "flex", alignItems: "center", gap: 12, background: C.stoneDark, border: `1px solid ${C.relief}`, padding: "11px 16px" }}>
            <span style={{ width: 7, height: 7, borderRadius: 2, background: C.goldenrod }} />
            <span style={{ fontFamily: FONT.display, fontSize: 12, letterSpacing: "0.1em", color: C.parchment }}>{s.provider.toUpperCase()}</span>
            <span style={{ color: C.stoneText, fontSize: 10 }}>▾</span>
          </div>
        </div>
      </div>

      <button
        className="btn-solid"
        onClick={() => s.setScreen("live")}
        style={{
          width: "100%", display: "flex", alignItems: "center", justifyContent: "center", gap: 14,
          fontFamily: FONT.display, fontSize: 15, letterSpacing: "0.24em", fontWeight: 600,
          color: C.obsidian, background: C.goldenrod, border: "none", padding: 18, cursor: "pointer",
        }}
      >
        LAUNCH AUDIT <span style={{ fontSize: 15 }}>◆</span>
      </button>
    </section>
  );
}

const ghostBtn = {
  background: C.stoneDark, border: `1px solid ${C.relief}`, color: C.stoneText,
  fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.12em", padding: "0 20px",
  cursor: "pointer", whiteSpace: "nowrap" as const,
};

function Label({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.22em", color: C.goldPale, marginBottom: 14 }}>
      {children}
    </div>
  );
}
