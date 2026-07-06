import { useEffect, useState } from "react";
import { C, FONT } from "../theme";
import { PROVIDERS } from "../data";
import { useStore } from "../store";

const CLOUD_IDS = new Set(["groq", "gemini", "claude", "openrouter"]);

export function Settings() {
  const s = useStore();
  const [keyInput, setKeyInput] = useState("");

  useEffect(() => {
    if (s.isDesktop) s.loadStatus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s.isDesktop]);

  const selectedId = s.provider.toLowerCase();
  const live = s.isDesktop && s.status;

  return (
    <section style={{ padding: "36px 46px 64px 46px", maxWidth: 940 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 36 }}>
        <div style={{ fontFamily: FONT.display, fontSize: 16, letterSpacing: "0.3em", color: C.goldPale }}>SETTINGS</div>
        <span style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 12, color: live ? C.goldenrod : C.stoneText }}>
          {live ? "● live config" : "○ demo preview — open in the desktop app for real config"}
        </span>
      </div>

      <Head>LLM PROVIDER</Head>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5,1fr)", gap: 8, marginBottom: 18 }}>
        {PROVIDERS.map((p) => {
          const active = selectedId === p.id;
          return (
            <button key={p.id} onClick={() => s.setProvider(p.id)} style={{
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

      {CLOUD_IDS.has(selectedId) && (
        <div style={{ display: "flex", gap: 10, marginBottom: 18 }}>
          <input
            value={keyInput}
            onChange={(e) => setKeyInput(e.target.value)}
            placeholder={`${selectedId} API key…`}
            type="password"
            style={{ flex: 1, background: C.stoneDark, border: `1px solid ${C.bronze}`, color: C.parchment, fontFamily: FONT.code, fontSize: 12, padding: "12px 15px", outline: "none" }}
          />
          <button
            className="btn-ghost"
            disabled={!s.isDesktop || s.savingKey || !keyInput.trim()}
            onClick={async () => { await s.saveProviderKey(selectedId, keyInput); setKeyInput(""); }}
            style={{ background: C.stoneDark, border: `1px solid ${C.bronze}`, color: C.bronze, fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.12em", padding: "0 20px", cursor: s.isDesktop ? "pointer" : "not-allowed" }}
          >
            {s.savingKey ? "SAVING…" : "SAVE KEY"}
          </button>
        </div>
      )}

      <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 44 }}>
        <button
          className="btn-ghost"
          disabled={!s.isDesktop}
          onClick={() => s.testConnection()}
          style={{ background: C.stoneDark, border: `1px solid ${C.bronze}`, color: C.bronze, fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.12em", padding: "10px 20px", cursor: s.isDesktop ? "pointer" : "not-allowed" }}
        >
          TEST CONNECTION
        </button>
        {s.connectionTestResult && (
          <span style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 13, color: s.connectionTestResult === "ok" ? C.goldenrod : C.crimson }}>
            {s.connectionTestResult === "ok" ? "● reachable" : "● configured but unreachable"}
          </span>
        )}
      </div>

      <Head>{selectedId === "local" ? "LOCAL MODEL" : "MODEL"}</Head>
      <div style={{ border: `1px solid ${C.relief}`, background: C.stoneDark, padding: "24px 26px", marginBottom: 44 }}>
        {live ? (
          <>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
              <span style={{ fontFamily: FONT.code, fontSize: 13, color: C.parchment }}>
                {s.status!.gpu.detected ? `${s.status!.gpu.name} · ${s.status!.gpu.vram_gb} GB VRAM` : "No GPU detected"}
              </span>
              <span style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 14, color: s.status!.gpu.detected ? C.goldenrod : C.stoneText }}>
                {s.status!.gpu.detected ? "● detected" : "○ not found"}
              </span>
            </div>
            <div style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 14, color: C.stoneText }}>
              {s.status!.resolved_provider
                ? <>Active model: <span style={{ fontStyle: "normal", color: C.goldenrod, fontFamily: FONT.code, fontSize: 12 }}>{s.status!.model}</span></>
                : "No LLM provider configured — Argus runs static-scan-only."}
            </div>
            {s.status!.recommended_model && (
              <div style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 14, color: C.stoneText, marginTop: 6 }}>
                Recommended local model: <span style={{ fontStyle: "normal", color: C.goldenrod, fontFamily: FONT.code, fontSize: 12 }}>{s.status!.recommended_model}</span>
              </div>
            )}
          </>
        ) : (
          <div style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 14, color: C.stoneText }}>
            GPU detection and active-model info appear here in the desktop app.
          </div>
        )}
      </div>

      <Head>SCAN DEFAULTS</Head>
      <div style={{ border: `1px solid ${C.relief}`, background: C.stoneDark }}>
        {(live
          ? [
              { label: "Default depth", value: capitalize(s.status!.scan_defaults.depth) },
              { label: "Attack agents available", value: String(s.status!.agent_count) },
              { label: "Report output path", value: s.status!.report_defaults.output_dir },
            ]
          : [
              { label: "Default depth", value: "—" },
              { label: "Attack agents available", value: "—" },
              { label: "Report output path", value: "—" },
            ]
        ).map((r, i) => (
          <div key={r.label} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "16px 24px", borderBottom: i < 2 ? "1px solid rgba(184,134,11,0.12)" : "none" }}>
            <span style={{ fontFamily: FONT.body, fontSize: 16, color: C.parchment }}>{r.label}</span>
            <span style={{ fontFamily: FONT.code, fontSize: 12, color: C.goldenrod }}>{r.value}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function Head({ children }: { children: React.ReactNode }) {
  return <div style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.22em", color: C.goldenrod, marginBottom: 16 }}>{children}</div>;
}
