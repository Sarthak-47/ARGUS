import { useEffect } from "react";
import { C, FONT } from "./theme";
import { useStore, type Screen } from "./store";
import { Sidebar } from "./components/Sidebar";
import { NoiseOverlay } from "./components/Decor";
import { Dashboard } from "./screens/Dashboard";
import { NewScan } from "./screens/NewScan";
import { LiveAttack } from "./screens/LiveAttack";
import { Reports } from "./screens/Reports";
import { Settings } from "./screens/Settings";
import { CodeView } from "./screens/CodeView";

const SCREENS: Screen[] = ["dashboard", "scan", "live", "report", "settings", "code"];

export default function App() {
  const screen = useStore((s) => s.screen);
  const setScreen = useStore((s) => s.setScreen);
  const loadReport = useStore((s) => s.loadReport);
  const loadHistory = useStore((s) => s.loadHistory);
  const loadStatus = useStore((s) => s.loadStatus);
  const loadArgusPath = useStore((s) => s.loadArgusPath);

  useEffect(() => {
    loadReport();
    loadHistory();
    loadStatus();
    loadArgusPath();
  }, [loadReport, loadHistory, loadStatus, loadArgusPath]);

  // Hash routing: each screen is a separate page (#/reports, #/scan, …), with
  // working back/forward and deep links.
  useEffect(() => {
    const apply = () => {
      const h = window.location.hash.replace(/^#\/?/, "") as Screen;
      if (SCREENS.includes(h) && h !== useStore.getState().screen) setScreen(h);
    };
    apply();
    window.addEventListener("hashchange", apply);
    return () => window.removeEventListener("hashchange", apply);
  }, [setScreen]);

  return (
    <div style={{ position: "fixed", inset: 0, display: "flex", background: C.obsidian, color: C.parchment, fontFamily: FONT.body, overflow: "hidden" }}>
      <NoiseOverlay />
      <Sidebar />
      {/* key={screen} remounts on navigation so the entrance animation replays
          each time — the smooth "traversal" between screens. It also resets
          scroll to the top of the new screen, which is the right default. */}
      <main key={screen} className="screen-enter" style={{ flex: 1, minWidth: 0, overflowY: "auto", overflowX: "hidden", position: "relative" }}>
        {screen === "dashboard" && <Dashboard />}
        {screen === "scan" && <NewScan />}
        {screen === "live" && <LiveAttack />}
        {screen === "report" && <Reports />}
        {screen === "settings" && <Settings />}
        {screen === "code" && <CodeView />}
      </main>
    </div>
  );
}
