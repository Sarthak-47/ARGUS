import { C, FONT } from "./theme";
import { useStore } from "./store";
import { Sidebar } from "./components/Sidebar";
import { NoiseOverlay } from "./components/Decor";
import { Dashboard } from "./screens/Dashboard";
import { NewScan } from "./screens/NewScan";
import { LiveAttack } from "./screens/LiveAttack";
import { Reports } from "./screens/Reports";
import { Settings } from "./screens/Settings";

export default function App() {
  const screen = useStore((s) => s.screen);

  return (
    <div style={{ position: "fixed", inset: 0, display: "flex", background: C.obsidian, color: C.parchment, fontFamily: FONT.body, overflow: "hidden" }}>
      <NoiseOverlay />
      <Sidebar />
      <main style={{ flex: 1, minWidth: 0, overflowY: "auto", overflowX: "hidden", position: "relative" }}>
        {screen === "dashboard" && <Dashboard />}
        {screen === "scan" && <NewScan />}
        {screen === "live" && <LiveAttack />}
        {screen === "report" && <Reports />}
        {screen === "settings" && <Settings />}
      </main>
    </div>
  );
}
