import { C, FONT } from "../theme";
import { PROVIDERS } from "../data";
import { useStore } from "../store";

export function Settings() {
  const provider = useStore((s) => s.provider);
  const setProvider = useStore((s) => s.setProvider);

  const scanDefaults = [
    { label: "Default depth", value: "Standard" },
    { label: "Default agents", value: "All 13" },
    { label: "Report output path", value: "~/argus/reports" },
  ];

  return (
    <section style={{ padding: "36px 46px 64px 46px", maxWidth: 940 }}>
      <div style={{ fontFamily: FONT.display, fontSize: 16, letterSpacing: "0.3em", color: C.goldPale, marginBottom: 36 }}>SETTINGS</div>

      <Head>LLM PROVIDER</Head>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5,1fr)", gap: 8, marginBottom: 18 }}>
        {PROVIDERS.map((p) => {
          const active = provider === p.name;
          return (
            <button key={p.name} onClick={() => setProvider(p.name)} style={{
              display: "flex", flexDirection: "column", gap: 10, alignItems: "flex-start", padding: 16, cursor: "pointer",
              background: C.stoneDark, border: `1px solid ${active ? C.bronze : C.relief}`,
            }}>
              <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ width: 7, height: 7, borderRadius: 2, background: active ? C.goldenrod : C.relief, boxShadow: active ? "0 0 6px rgba(184,134,11,0.6)" : "none" }} />
                <span style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.08em", color: active ? C.goldPale : C.parchment }}>{p.name}</span>
              </span>
              <span style={{ fontFamily: FONT.code, fontSize: 10, color: C.stoneText }}>{p.speed}</span>
            </button>
          );
        })}
      </div>
      <div style={{ display: "flex", gap: 10, marginBottom: 44 }}>
        <input
          defaultValue="gsk_••••••••••••••••••••••••"
          style={{ flex: 1, background: C.stoneDark, border: `1px solid ${C.bronze}`, color: C.stoneText, fontFamily: FONT.code, fontSize: 12, padding: "12px 15px", outline: "none" }}
        />
        <button className="btn-ghost" style={{ background: C.stoneDark, border: `1px solid ${C.bronze}`, color: C.bronze, fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.12em", padding: "0 20px", cursor: "pointer" }}>
          TEST CONNECTION
        </button>
      </div>

      <Head>LOCAL MODEL</Head>
      <div style={{ border: `1px solid ${C.relief}`, background: C.stoneDark, padding: "24px 26px", marginBottom: 44 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
          <span style={{ fontFamily: FONT.code, fontSize: 13, color: C.parchment }}>RTX 4070 · 12GB VRAM</span>
          <span style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 14, color: C.goldenrod }}>● detected</span>
        </div>
        <div style={{ height: 6, background: C.relief, marginBottom: 10 }}>
          <div style={{ height: "100%", width: "64%", background: C.bronze }} />
        </div>
        <div style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 14, color: C.stoneText }}>
          Recommended: <span style={{ fontStyle: "normal", color: C.goldenrod, fontFamily: FONT.code, fontSize: 12 }}>Qwen2.5-Coder 14B</span> · 7.6GB / 12GB
        </div>
      </div>

      <Head>SCAN DEFAULTS</Head>
      <div style={{ border: `1px solid ${C.relief}`, background: C.stoneDark }}>
        {scanDefaults.map((r, i) => (
          <div key={r.label} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "16px 24px", borderBottom: i < 2 ? "1px solid rgba(184,134,11,0.12)" : "none" }}>
            <span style={{ fontFamily: FONT.body, fontSize: 16, color: C.parchment }}>{r.label}</span>
            <span style={{ fontFamily: FONT.code, fontSize: 12, color: C.goldenrod }}>{r.value}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function Head({ children }: { children: React.ReactNode }) {
  return <div style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.22em", color: C.goldenrod, marginBottom: 16 }}>{children}</div>;
}
