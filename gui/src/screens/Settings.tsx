// Settings, in the ledger's own idiom: dotted-leader rows, lit choices as
// text, a bare line for the key. No cards — see DESIGN.md.

import { useEffect, useState } from "react";
import { C, RF, FONT } from "../theme";
import { PROVIDERS } from "../data";
import { useStore } from "../store";

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
  // Ollama's own local API has been observed taking 2+ seconds to answer even
  // when already running, so a status refresh here is a real multi-second
  // wait — without surfacing it, every provider switch looked like a freeze.
  const busy = s.statusLoading || s.savingModel || s.savingKey;

  return (
    <div style={{ maxWidth: 720, margin: "0 auto", padding: "38px 40px 60px", height: "100%", overflowY: "auto" }}>
      <p className="aside" style={{ marginBottom: 4 }}>
        Which mind reasons over what the eyes find.
      </p>
      {busy && (
        <p style={{ fontFamily: FONT.code, fontSize: 11, letterSpacing: "0.1em", color: "var(--bone-dim)", display: "flex", alignItems: "center", gap: 8, margin: "10px 0 0" }}>
          <span style={{ width: 6, height: 6, borderRadius: "50%", background: RF.clay, animation: "argusPulse 1.2s ease-in-out infinite" }} />
          REFRESHING…
        </p>
      )}

      <div className="leader" style={{ alignItems: "baseline", marginTop: 22 }}>
        <span className="k" style={{ paddingTop: 4 }}>Provider</span>
        <div style={{ flex: 1, display: "flex", flexWrap: "wrap", rowGap: 4 }}>
          {PROVIDERS.map((p, i) => (
            <span key={p.id}>
              {i > 0 && <span className="pick-sep">/</span>}
              <button className={`pick${selectedId === p.id ? " on" : ""}`} style={{ fontSize: 16 }} onClick={() => s.setProvider(p.id)}>
                {p.name}
              </button>
            </span>
          ))}
        </div>
      </div>

      {CLOUD_IDS.has(selectedId) && (
        <div style={{ padding: "8px 0 4px" }}>
          <label style={{ display: "block", fontFamily: FONT.code, fontSize: 10, letterSpacing: "0.17em", textTransform: "uppercase", color: "var(--bone-dim)", marginBottom: 8 }}>
            {selectedId} api key
          </label>
          <div style={{ display: "flex", alignItems: "baseline", gap: 16 }}>
            <input
              className="line-input"
              style={{ flex: 1 }}
              value={keyInput}
              onChange={(e) => setKeyInput(e.target.value)}
              placeholder={`${selectedId} key`}
              type="password"
            />
            <button className="pick on" style={{ fontSize: 15 }} disabled={!s.isDesktop || s.savingKey || !keyInput.trim()}
              onClick={async () => { await s.saveProviderKey(selectedId, keyInput); setKeyInput(""); }}>
              {s.savingKey ? "saving…" : "save"}
            </button>
          </div>
        </div>
      )}

      <div className="leader">
        <span className="k">Reach</span>
        <span className="dots" />
        <button className="pick" style={{ fontSize: 15 }} disabled={!s.isDesktop} onClick={() => s.testConnection()}>test connection</button>
      </div>
      {s.connectionTestResult && (
        <p style={{ fontFamily: FONT.ui, fontSize: 13.5, color: s.connectionTestResult === "ok" ? RF.patina : C.crimson, margin: "-4px 0 0" }}>
          {s.connectionTestResult === "ok" ? "Reachable." : s.connectionTestResult === "needs-key" ? "Selected — add an API key above to activate it." : "Configured but unreachable."}
        </p>
      )}

      {live && (
        <>
          <p className="aside" style={{ marginTop: 30, marginBottom: 4 }}>
            The engine itself.
          </p>
          <div className="leader">
            <span className="k">GPU</span><span className="dots" />
            <span className={`v${s.status!.gpu.detected ? " gold" : ""}`} style={{ fontSize: 16 }}>
              {s.status!.gpu.detected ? `${s.status!.gpu.name} · ${s.status!.gpu.vram_gb} GB` : "none detected"}
            </span>
          </div>
          <div className="leader">
            <span className="k">Active model</span><span className="dots" />
            <span className="v" style={{ fontFamily: FONT.code, fontSize: 15 }}>
              {s.status!.resolved_provider ? (s.status!.model ?? "—") : "none — deterministic scan only"}
            </span>
          </div>
          {s.status!.recommended_model && (
            <div className="leader">
              <span className="k">Recommended</span><span className="dots" />
              <span className="v" style={{ fontFamily: FONT.code, fontSize: 15 }}>{s.status!.recommended_model}</span>
            </div>
          )}
          <div className="leader">
            <span className="k">Default depth</span><span className="dots" />
            <span className="v" style={{ fontSize: 16 }}>{capitalize(s.status!.scan_defaults.depth)}</span>
          </div>
          <div className="leader">
            <span className="k">Agents available</span><span className="dots" />
            <span className="v gold" style={{ fontSize: 20 }}>{s.status!.agent_count}</span>
          </div>
          <div className="leader">
            <span className="k">Reports saved to</span><span className="dots" />
            <span className="v" style={{ fontFamily: FONT.code, fontSize: 12.5 }}>{s.status!.report_defaults.output_dir}</span>
          </div>

          {s.status!.local_models.length > 0 && (
            <>
              <p className="aside" style={{ marginTop: 26, marginBottom: 10 }}>Installed local models.</p>
              <div style={{ borderTop: "1px solid var(--rule)" }}>
                {s.status!.local_models.map((m) => {
                  const active = s.status!.model === m;
                  return (
                    <button key={m} disabled={s.savingModel} onClick={() => s.setLocalModel(m)} style={{
                      display: "flex", alignItems: "baseline", gap: 12, width: "100%", textAlign: "left",
                      background: "none", border: "none", borderBottom: "1px solid var(--rule)",
                      padding: "9px 0", cursor: s.savingModel ? "wait" : "pointer",
                    }}>
                      <span style={{ fontFamily: FONT.code, fontSize: 9.5, color: active ? RF.clay : "var(--bone-dim)" }}>{active ? "●" : "○"}</span>
                      <span style={{ fontFamily: FONT.code, fontSize: 13, color: active ? "var(--bone)" : "var(--bone-dim)" }}>{m}</span>
                    </button>
                  );
                })}
              </div>
              {s.modelSaveError && (
                <p style={{ fontFamily: FONT.ui, fontSize: 12.5, color: C.crimson, marginTop: 10 }}>{s.modelSaveError}</p>
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}

function capitalize(s: string): string { return s.charAt(0).toUpperCase() + s.slice(1); }
