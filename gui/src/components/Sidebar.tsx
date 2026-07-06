// Left sidebar: Argus logo, screen nav, active provider chip.

import { ArgusEye } from "./ArgusEye";
import { C, FONT } from "../theme";
import { useStore, type Screen } from "../store";

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
  const modelLabel = live
    ? (status!.resolved_provider ? status!.model : "no provider configured")
    : "demo";
  const dotColor = live
    ? (status!.resolved_provider && status!.available ? C.goldenrod : C.crimson)
    : C.goldenrod;

  return (
    <aside
      style={{
        width: 232, flex: "0 0 232px", background: C.stoneCarved,
        borderRight: `1px solid ${C.relief}`, display: "flex", flexDirection: "column", zIndex: 10,
      }}
    >
      <div
        style={{
          display: "flex", alignItems: "center", gap: 13,
          padding: "24px 22px 22px 22px", borderBottom: `1px solid ${C.relief}`,
        }}
      >
        <ArgusEye size={34} draw />
        <span style={{ fontFamily: FONT.display, fontWeight: 700, fontSize: 21, letterSpacing: "0.28em", color: C.goldPale }}>
          ARGUS
        </span>
      </div>

      <nav style={{ display: "flex", flexDirection: "column", padding: "16px 0", gap: 1, flex: 1 }}>
        {NAV.map((n) => {
          const active = screen === n.key;
          return (
            <button
              key={n.key}
              className="nav-item"
              onClick={() => setScreen(n.key)}
              style={{
                position: "relative", display: "flex", alignItems: "center", gap: 10,
                padding: "13px 22px", background: active ? C.relief : "transparent",
                border: "none", cursor: "pointer", textAlign: "left", width: "100%",
                color: active ? C.goldPale : C.stoneText,
              }}
            >
              <span style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: 3, background: active ? C.goldenrod : "transparent" }} />
              <span style={{ fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.1em", width: 24, opacity: 0.65 }}>{n.glyph}</span>
              <span style={{ fontFamily: FONT.display, fontSize: 12, letterSpacing: "0.16em" }}>{n.label}</span>
            </button>
          );
        })}
      </nav>

      <div style={{ padding: "18px 22px", borderTop: `1px solid ${C.relief}`, display: "flex", alignItems: "center", gap: 11 }}>
        <span style={{ width: 8, height: 8, borderRadius: 2, background: dotColor, boxShadow: `0 0 7px ${dotColor}99` }} />
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <span style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.1em", color: C.parchment }}>{provider.toUpperCase()}</span>
          <span style={{ fontFamily: FONT.code, fontSize: 10, color: C.stoneText }}>{modelLabel}</span>
        </div>
      </div>
    </aside>
  );
}
