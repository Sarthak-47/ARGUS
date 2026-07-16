// Left spine: the Argus mark in terracotta, inscribed nav with roman numerals,
// and the oracle lamp (provider) at the foot.

import { RF, FONT } from "../theme";
import { useStore, type Screen } from "../store";
import { TerracottaMark, EyeGlyph } from "./Panoptes";

const NAV: { key: Screen; label: string; glyph: string }[] = [
  { key: "dashboard", label: "Dashboard", glyph: "I" },
  { key: "scan", label: "New Scan", glyph: "II" },
  { key: "live", label: "Live Attack", glyph: "III" },
  { key: "report", label: "Reports", glyph: "IV" },
  { key: "settings", label: "Settings", glyph: "V" },
];

export function Sidebar() {
  const screen = useStore((s) => s.screen);
  const setScreen = useStore((s) => s.setScreen);
  const provider = useStore((s) => s.provider);
  const isDesktop = useStore((s) => s.isDesktop);
  const status = useStore((s) => s.status);
  const live = isDesktop && status;
  // Same bug as Settings/New Scan: `status.resolved_provider` falls back to
  // "local" whenever a cloud provider has no key saved yet, so gating the
  // whole badge on it made a real selection read as "no provider" here too.
  // "configured" = the user picked something at all; "active" = that pick is
  // actually resolved+reachable right now (only "active" unlocks the model
  // sub-line, since a model is only meaningful once truly resolved).
  const configured = !!(live && provider);
  const active = !!(live && status!.resolved_provider === provider && status!.available);
  const providerLabel = configured ? provider : "no provider";
  const modelLabel = active ? status!.model : "";

  return (
    <aside
      style={{
        width: 224, flex: "0 0 224px", zIndex: 10,
        borderRight: `1px solid ${RF.diluteLo}`,
        display: "flex", flexDirection: "column",
        backgroundImage:
          `repeating-linear-gradient(90deg, rgba(0,0,0,0.22) 0 1px, rgba(197,106,51,0.03) 1px 2px, transparent 2px 24px), linear-gradient(180deg, #1b140c, ${RF.glazeLo})`,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 11, padding: "22px 18px 18px", borderBottom: `1px solid rgba(125,79,40,0.35)` }}>
        <TerracottaMark size={30} />
        <span style={{ fontFamily: FONT.display, fontWeight: 700, fontSize: 19, letterSpacing: "0.32em", color: RF.clayHi }}>ARGUS</span>
      </div>

      <nav style={{ display: "flex", flexDirection: "column", padding: "12px 0", gap: 1, flex: 1 }}>
        {NAV.map((n) => {
          const active = screen === n.key;
          return (
            <button
              key={n.key}
              className="nav-item"
              onClick={() => setScreen(n.key)}
              style={{
                position: "relative", display: "flex", alignItems: "center", gap: 12,
                padding: "12px 18px", border: "none", cursor: "pointer", textAlign: "left", width: "100%",
                fontFamily: FONT.display, fontSize: 11.5, letterSpacing: "0.14em", textTransform: "uppercase",
                color: active ? RF.clayHi : RF.dust,
                background: active ? "linear-gradient(90deg, rgba(0,0,0,0.35), transparent)" : "transparent",
                boxShadow: active ? "inset 0 1px 3px rgba(0,0,0,0.5)" : "none",
              }}
            >
              <span style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: 3, background: active ? RF.clay : "transparent" }} />
              <span style={{ fontSize: 9, width: 18, color: RF.diluteLo }}>{n.glyph}</span>
              <span>{n.label}</span>
            </button>
          );
        })}
      </nav>

      <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "14px 16px", borderTop: `1px solid rgba(125,79,40,0.35)` }}>
        <EyeGlyph sleeping={!active} w={18} h={12} />
        <div style={{ display: "flex", flexDirection: "column" }}>
          <span style={{ fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.1em", color: RF.clay, textTransform: "uppercase" }}>{providerLabel}</span>
          <span style={{ fontFamily: FONT.code, fontSize: 9, color: RF.dust }}>{modelLabel}</span>
        </div>
      </div>
    </aside>
  );
}
