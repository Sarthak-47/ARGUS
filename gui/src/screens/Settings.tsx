import { useEffect, useState } from "react";
import { C, RF, FONT } from "../theme";
import { PROVIDERS } from "../data";
import { useStore } from "../store";
import { ScreenHeader } from "../components/Panoptes";

const CLOUD_IDS = new Set(["groq", "gemini", "claude", "openrouter"]);

export function Settings() {
  const s = useStore();
  const [keyInput, setKeyInput] = useState("");
  const [pathInput, setPathInput] = useState("");

  useEffect(() => {
    if (s.isDesktop) { s.loadStatus(); s.checkArgusAvailable(); s.loadArgusPath(); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s.isDesktop]);

  useEffect(() => {
    setPathInput(s.argusPathSaved ?? "");
  }, [s.argusPathSaved]);

  const selectedId = s.provider.toLowerCase();
  const live = s.isDesktop && s.status;

  return (
    <section>
      <ScreenHeader title="Settings" subtitle={live ? "how Argus is configured" : "demo preview — open in the desktop app for real config"} />

      <div style={{ padding: "24px 46px 64px", maxWidth: 1200 }}>
        {s.isDesktop && s.argusAvailable === false && (
          <div style={{ border: `1px solid ${C.crimson}`, background: "rgba(165,56,42,0.1)", padding: "16px 20px", marginBottom: 26 }}>
            <div style={{ fontFamily: FONT.body, fontSize: 14, color: C.crimson, marginBottom: 10 }}>
              Argus couldn't be reached, so nothing below can save or run yet — set the exact path to
              your <code style={{ fontFamily: FONT.code }}>argus</code> executable and it'll take effect immediately.
            </div>
            <ArgusPathField s={s} pathInput={pathInput} setPathInput={setPathInput} />
          </div>
        )}

        <Head>Argus CLI</Head>
        <div style={{ border: `1px solid ${RF.diluteLo}`, background: RF.glaze, padding: "20px 24px", marginBottom: 44 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
            <span style={{
              width: 8, height: 8, borderRadius: "50%",
              background: !s.isDesktop ? RF.diluteLo : s.argusAvailable ? RF.clay : s.argusAvailable === null ? RF.dust : C.crimson,
            }} />
            <span style={{
              fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.1em", textTransform: "uppercase",
              color: !s.isDesktop ? RF.dust : s.argusAvailable ? RF.clayHi : s.argusAvailable === null ? RF.dust : C.crimson,
            }}>
              {!s.isDesktop ? "desktop app only" : s.argusAvailable === null ? "checking…" : s.argusAvailable ? "found" : "not found"}
            </span>
            {s.argusPathSaved && (
              <span style={{ fontFamily: FONT.code, fontSize: 11, color: RF.dust }}>— using manually-set path</span>
            )}
          </div>
          {s.argusAvailable !== false && <ArgusPathField s={s} pathInput={pathInput} setPathInput={setPathInput} />}
          <div style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 12, color: RF.dust, marginTop: 10 }}>
            Auto-detected by default. Set this if Argus lives somewhere non-standard — e.g. a project
            venv's <code style={{ fontFamily: FONT.code }}>Scripts\argus.exe</code> or <code style={{ fontFamily: FONT.code }}>bin/argus</code>.
          </div>
        </div>

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

        <Head>{selectedId === "local" ? "Local model" : "Model"}</Head>
        <div style={{ border: `1px solid ${RF.diluteLo}`, background: RF.glaze, padding: "24px 26px", marginBottom: 44 }}>
          {live ? (
            <>
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
            </>
          ) : (
            <div style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 14, color: RF.dust }}>GPU detection and active-model info appear here in the desktop app.</div>
          )}
        </div>

        <Head>Scan defaults</Head>
        <div style={{ border: `1px solid ${RF.diluteLo}`, background: RF.glaze }}>
          {(live
            ? [
                { label: "Default depth", value: capitalize(s.status!.scan_defaults.depth) },
                { label: "Attack agents available", value: String(s.status!.agent_count) },
                { label: "Report output path", value: s.status!.report_defaults.output_dir },
              ]
            : [{ label: "Default depth", value: "—" }, { label: "Attack agents available", value: "—" }, { label: "Report output path", value: "—" }]
          ).map((r, i) => (
            <div key={r.label} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "16px 24px", borderBottom: i < 2 ? `1px solid rgba(125,79,40,0.22)` : "none" }}>
              <span style={{ fontFamily: FONT.body, fontSize: 16, color: RF.parchment }}>{r.label}</span>
              <span style={{ fontFamily: FONT.code, fontSize: 12, color: RF.clay }}>{r.value}</span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function ArgusPathField({
  s, pathInput, setPathInput,
}: {
  s: ReturnType<typeof useStore.getState>;
  pathInput: string;
  setPathInput: (v: string) => void;
}) {
  return (
    <>
      <div style={{ display: "flex", gap: 10 }}>
        <input
          value={pathInput}
          onChange={(e) => setPathInput(e.target.value)}
          disabled={!s.isDesktop}
          placeholder={s.isDesktop ? "e.g. C:\\path\\to\\.venv\\Scripts\\argus.exe or /usr/local/bin/argus" : "only settable in the desktop app"}
          style={{ flex: 1, background: RF.glazeLo, border: `1px solid ${RF.dilute}`, color: RF.parchment, fontFamily: FONT.code, fontSize: 12, padding: "12px 15px", outline: "none", opacity: s.isDesktop ? 1 : 0.6 }}
        />
        <button
          disabled={!s.isDesktop || s.argusPathSaving || !pathInput.trim()}
          onClick={() => s.setArgusPathOverride(pathInput.trim())}
          style={{ background: RF.glazeLo, border: `1px solid ${RF.dilute}`, color: RF.clay, fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.12em", textTransform: "uppercase", padding: "0 20px", cursor: s.isDesktop && pathInput.trim() ? "pointer" : "not-allowed" }}
        >
          {s.argusPathSaving ? "Testing…" : "Save & test"}
        </button>
        {s.argusPathSaved && (
          <button
            disabled={!s.isDesktop}
            onClick={() => { s.clearArgusPathOverride(); setPathInput(""); }}
            style={{ background: "transparent", border: `1px solid ${RF.diluteLo}`, color: RF.dust, fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.12em", textTransform: "uppercase", padding: "0 16px", cursor: s.isDesktop ? "pointer" : "not-allowed" }}
          >
            Reset
          </button>
        )}
      </div>
      {s.argusPathError && (
        <div style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 13, color: C.crimson, marginTop: 10 }}>{s.argusPathError}</div>
      )}
    </>
  );
}

function capitalize(s: string): string { return s.charAt(0).toUpperCase() + s.slice(1); }
function Head({ children }: { children: React.ReactNode }) {
  return <div style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.2em", textTransform: "uppercase", color: RF.clay, marginBottom: 16 }}>{children}</div>;
}
