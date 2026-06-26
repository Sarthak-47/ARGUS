import { C, FONT, bandColor, bandLabel } from "../theme";
import { AUDITS, STATS } from "../data";
import { useStore } from "../store";
import { ArgusEye } from "../components/ArgusEye";

export function Dashboard() {
  const setScreen = useStore((s) => s.setScreen);

  return (
    <section style={{ padding: "36px 46px 64px 46px", maxWidth: 1180, position: "relative" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 40 }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 16 }}>
          <h1 style={{ margin: 0, fontFamily: FONT.display, fontWeight: 600, fontSize: 16, letterSpacing: "0.3em", color: C.goldPale }}>
            OVERVIEW
          </h1>
          <span style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 15, color: C.stoneText }}>
            Argus never sleeps
          </span>
        </div>
        <button
          className="btn-ghost"
          onClick={() => setScreen("scan")}
          style={{
            fontFamily: FONT.display, fontSize: 12, letterSpacing: "0.18em", fontWeight: 600,
            color: C.goldenrod, background: "transparent", border: `1px solid ${C.bronze}`,
            padding: "12px 22px", cursor: "pointer",
          }}
        >
          NEW SCAN
        </button>
      </div>

      <div style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.26em", color: C.stoneText, marginBottom: 16 }}>
        RECENT AUDITS
      </div>
      <div style={{ display: "flex", flexDirection: "column", border: `1px solid ${C.relief}`, background: C.stoneDark, marginBottom: 52 }}>
        {AUDITS.map((a) => (
          <button
            key={a.name}
            className="row-hover"
            onClick={() => setScreen("report")}
            style={{
              position: "relative", display: "grid", gridTemplateColumns: "1fr 60px 132px 70px",
              alignItems: "center", gap: 22, padding: "18px 24px", background: "transparent",
              border: "none", borderBottom: "1px solid rgba(184,134,11,0.12)", cursor: "pointer",
              textAlign: "left", width: "100%",
            }}
          >
            <span style={{ fontFamily: FONT.code, fontSize: 13, color: C.parchment, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {a.name}
            </span>
            <span style={{ fontFamily: FONT.display, fontSize: 26, fontWeight: 600, color: C.goldPale, textAlign: "right" }}>
              {a.score}
            </span>
            <span style={{ display: "flex", flexDirection: "column", gap: 6, width: 132 }}>
              <span style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 13, letterSpacing: "0.04em", color: bandColor(a.score) }}>
                {bandLabel(a.score)}
              </span>
              <span style={{ height: 4, background: C.relief, width: "100%" }}>
                <span style={{ display: "block", height: "100%", width: `${a.score}%`, background: bandColor(a.score) }} />
              </span>
            </span>
            <span style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 13, color: C.stoneText, textAlign: "right" }}>
              {a.time}
            </span>
          </button>
        ))}
      </div>

      <div style={{ position: "relative" }}>
        <ArgusEye
          size={320}
          opacity={0.08}
          style={{ position: "absolute", left: "50%", top: "50%", transform: "translate(-50%,-50%)", pointerEvents: "none", zIndex: 0 }}
        />
        <div style={{ position: "relative", zIndex: 1, display: "flex", gap: 1, background: C.relief, border: `1px solid ${C.relief}` }}>
          {STATS.map((st) => (
            <div key={st.label} style={{ flex: 1, background: "rgba(15,15,21,0.86)", padding: "30px 28px" }}>
              <div style={{ fontFamily: FONT.display, fontSize: 82, fontWeight: 700, color: st.color, lineHeight: 0.85 }}>
                {st.value}
              </div>
              <div style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.2em", color: C.stoneText, marginTop: 14 }}>
                {st.label}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
