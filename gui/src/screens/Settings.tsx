import { useEffect, useState } from "react";
import { C, RF, FONT } from "../theme";
import { PROVIDERS } from "../data";
import { useStore } from "../store";
import { ScreenHeader } from "../components/Panoptes";

const CLOUD_IDS = new Set(["groq", "gemini", "claude", "openrouter"]);

export function Settings() {
  const s = useStore();
  const [keyInput, setKeyInput] = useState("");

  useEffect(() => {
    if (s.isDesktop) { s.loadStatus(); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s.isDesktop]);

  const selectedId = s.provider.toLowerCase();
  const live = s.isDesktop && s.status;

  return (
    <section>
      <ScreenHeader title="Settings" subtitle={live ? "how Argus is configured" : "demo preview — open in the desktop app for real config"} />

      <div style={{ padding: "24px 46px 64px", maxWidth: 1200 }}>
        <Head>LLM provider</Head>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5,1fr)", gap: 8, marginBottom: 18 }}>
          {PROVIDERS.map((p) => {
            const active = selectedId === p.id;
            return (
              <button key={p.id} onClick={() => s.setProvider(p.id)} style={{
                display: "flex", flexDirection: "column", gap: 10, alignItems: "flex-start", padding: 16, cursor: "pointer",
                background: active ? `linear-gradient(180deg, ${RF.ember}, ${RF.glazeLo})` : RF.glazeLo, border: `1px solid ${active ? RF.clay : RF.diluteLo}`,
              }}>
                <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ width: 8, height: 8, borderRadius: "50%", background: active ? RF.clay : RF.diluteLo, boxShadow: active ? "0 0 0 3px rgba(197,106,51,0.18)" : "none" }} />
                  <span style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.06em", color: active ? RF.clayHi : RF.parchment }}>{p.name}</span>
                </span>
                <span style={{ fontFamily: FONT.code, fontSize: 10, color: RF.dust }}>{p.speed}</span>
              </button>
            );
          })}
        </div>

        {CLOUD_IDS.has(selectedId) && (
          <div style={{ display: "flex", gap: 10, marginBottom: 18 }}>
            <input value={keyInput} onChange={(e) => setKeyInput(e.target.value)} placeholder={`${selectedId} key…`} type="password"
              style={{ flex: 1, background: RF.glazeLo, border: `1px solid ${RF.dilute}`, color: RF.parchment, fontFamily: FONT.code, fontSize: 12, padding: "12px 15px", outline: "none" }} />
            <button disabled={!s.isDesktop || s.savingKey || !keyInput.trim()} onClick={async () => { await s.saveProviderKey(selectedId, keyInput); setKeyInput(""); }}
              style={{ background: RF.glazeLo, border: `1px solid ${RF.dilute}`, color: RF.clay, fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.12em", textTransform: "uppercase", padding: "0 20px", cursor: s.isDesktop ? "pointer" : "not-allowed" }}>
              {s.savingKey ? "Saving…" : "Save key"}
            </button>
          </div>
        )}

        <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 44 }}>
          <button disabled={!s.isDesktop} onClick={() => s.testConnection()}
            style={{ background: RF.glazeLo, border: `1px solid ${RF.dilute}`, color: RF.clay, fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.12em", textTransform: "uppercase", padding: "10px 20px", cursor: s.isDesktop ? "pointer" : "not-allowed" }}>
            Test connection
          </button>
          {s.connectionTestResult && (
            <span style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 13, color: s.connectionTestResult === "ok" ? RF.clay : C.crimson }}>
              {s.connectionTestResult === "ok" ? "● reachable" : "● configured but unreachable"}
            </span>
          )}
        </div>

        {live && (
          <>
            <Head>{selectedId === "local" ? "Local model" : "Model"}</Head>
            <div style={{ border: `1px solid ${RF.diluteLo}`, background: RF.glaze, padding: "24px 26px", marginBottom: 44 }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
                <span style={{ fontFamily: FONT.code, fontSize: 13, color: RF.parchment }}>
                  {s.status!.gpu.detected ? `${s.status!.gpu.name} · ${s.status!.gpu.vram_gb} GB VRAM` : "No GPU detected"}
                </span>
                <span style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 14, color: s.status!.gpu.detected ? RF.clay : RF.dust }}>
                  {s.status!.gpu.detected ? "● detected" : "○ not found"}
                </span>
              </div>
              <div style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 14, color: RF.dust }}>
                {s.status!.resolved_provider
                  ? <>Active model: <span style={{ fontStyle: "normal", color: RF.clay, fontFamily: FONT.code, fontSize: 12 }}>{s.status!.model}</span></>
                  : "No provider configured — Argus still runs the deterministic scan."}
              </div>
              {s.status!.recommended_model && (
                <div style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 14, color: RF.dust, marginTop: 6 }}>
                  Recommended local model: <span style={{ fontStyle: "normal", color: RF.clay, fontFamily: FONT.code, fontSize: 12 }}>{s.status!.recommended_model}</span>
                </div>
              )}

              {s.status!.local_models.length > 0 && (
                <div style={{ marginTop: 18 }}>
                  <div style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 14, color: RF.dust, marginBottom: 10 }}>
                    Installed models — pick one to use:
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                    {s.status!.local_models.map((m) => {
                      const active = s.status!.model === m;
                      return (
                        <button key={m} disabled={s.savingModel} onClick={() => s.setLocalModel(m)}
                          style={{
                            display: "flex", alignItems: "center", gap: 10, textAlign: "left", padding: "10px 14px", cursor: s.savingModel ? "wait" : "pointer",
                            background: active ? `linear-gradient(180deg, ${RF.ember}, ${RF.glazeLo})` : RF.glazeLo,
                            border: `1px solid ${active ? RF.clay : RF.diluteLo}`,
                          }}>
                          <span style={{ width: 7, height: 7, borderRadius: "50%", background: active ? RF.clay : RF.diluteLo }} />
                          <span style={{ fontFamily: FONT.code, fontSize: 12, color: active ? RF.clayHi : RF.parchment }}>{m}</span>
                        </button>
                      );
                    })}
                  </div>
                  {s.modelSaveError && (
                    <div style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 13, color: C.crimson, marginTop: 10 }}>{s.modelSaveError}</div>
                  )}
                </div>
              )}
            </div>

            <Head>Scan defaults</Head>
            <div style={{ border: `1px solid ${RF.diluteLo}`, background: RF.glaze }}>
              {[
                { label: "Default depth", value: capitalize(s.status!.scan_defaults.depth) },
                { label: "Attack agents available", value: String(s.status!.agent_count) },
                { label: "Report output path", value: s.status!.report_defaults.output_dir },
              ].map((r, i) => (
                <div key={r.label} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "16px 24px", borderBottom: i < 2 ? `1px solid rgba(125,79,40,0.22)` : "none" }}>
                  <span style={{ fontFamily: FONT.body, fontSize: 16, color: RF.parchment }}>{r.label}</span>
                  <span style={{ fontFamily: FONT.code, fontSize: 12, color: RF.clay }}>{r.value}</span>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </section>
  );
}

function capitalize(s: string): string { return s.charAt(0).toUpperCase() + s.slice(1); }
function Head({ children }: { children: React.ReactNode }) {
  return <div style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.2em", textTransform: "uppercase", color: RF.clay, marginBottom: 16 }}>{children}</div>;
}
