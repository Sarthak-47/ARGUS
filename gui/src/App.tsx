// The keeper's watch-ledger shell. No sidebar: the masthead carries identity
// and the roman-numeral nav, the meta rule beneath states what is true right
// now. See DESIGN.md — this structure is pinned by the Claude Design
// reference, not a personal layout choice.

import { useEffect } from "react";
import { useStore, type Screen } from "./store";
import { Dashboard } from "./screens/Dashboard";
import { NewScan } from "./screens/NewScan";
import { LiveAttack } from "./screens/LiveAttack";
import { Reports } from "./screens/Reports";
import { Settings } from "./screens/Settings";
import { CodeView } from "./screens/CodeView";

const SCREENS: Screen[] = ["dashboard", "scan", "live", "report", "settings", "code"];

const NAV: { key: Screen; num: string; label: string }[] = [
  { key: "dashboard", num: "I", label: "The Watch" },
  { key: "scan", num: "II", label: "Set the Watch" },
  { key: "report", num: "III", label: "The Register" },
];

function timeAgo(ts: number | null): string {
  if (!ts) return "—";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export default function App() {
  const screen = useStore((s) => s.screen);
  const setScreen = useStore((s) => s.setScreen);
  const loadReport = useStore((s) => s.loadReport);
  const loadHistory = useStore((s) => s.loadHistory);
  const loadStatus = useStore((s) => s.loadStatus);
  const loadArgusPath = useStore((s) => s.loadArgusPath);
  const isDesktop = useStore((s) => s.isDesktop);
  const status = useStore((s) => s.status);
  const provider = useStore((s) => s.provider);
  const history = useStore((s) => s.history);
  const report = useStore((s) => s.report);

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

  const now = new Date();
  const dateStr = now.toLocaleDateString("en-GB", { weekday: "short", day: "2-digit", month: "short", year: "numeric" }).toUpperCase();
  const timeStr = now.toISOString().slice(11, 16) + " UTC";
  const last = history && history.length ? history[history.length - 1] : null;
  const findingCount = report?.findings?.length ?? 0;
  const active = !!(isDesktop && status && status.resolved_provider === provider && status.available);
  // The active screen maps onto the pinned three-item nav — Live Attack,
  // Settings and Code View are real screens without a numeral of their own,
  // so none of the three lights up while one of them is open.
  const navKey: Screen | null = screen === "dashboard" || screen === "scan" || screen === "report" ? screen : null;

  return (
    <div style={{ position: "fixed", inset: 0, display: "flex", flexDirection: "column", background: "var(--ground)", color: "var(--bone)", overflow: "hidden" }}>
      <header className="masthead">
        <div className="masthead-left">
          <span className="wordmark">ARGUS</span>
          <span className="tagline">Panoptes — the guard that does not sleep</span>
        </div>
        <nav className="watch-nav">
          {NAV.map((n) => (
            <button key={n.key} className={navKey === n.key ? "on" : ""} onClick={() => setScreen(n.key)}>
              <span className="num">{n.num}</span>{n.label}
            </button>
          ))}
        </nav>
      </header>

      <div className="meta-rule">
        <span>{dateStr} · {timeStr} · KEEPER {(isDesktop ? provider : "GUEST") || "UNSET"}</span>
        <span>
          {last ? `LAST SWEEP ${timeAgo(last.finishedAt).toUpperCase()}` : "NO SWEEP YET"}
          {" · "}
          <span className={active ? "lit" : ""}>{active ? "WATCH ARMED" : "WATCH UNARMED"}</span>
          {findingCount > 0 && <> · <span className="grave">{findingCount} RECORDED</span></>}
        </span>
      </div>

      {/* key={screen} remounts on navigation so the entrance animation
          replays. The shell itself never scrolls — flex:1/minHeight:0 hands
          each screen exactly the remaining viewport, and any list long
          enough to overflow scrolls inside its own lane instead. */}
      <main key={screen} className="screen-enter" style={{ flex: 1, minHeight: 0, overflow: "hidden" }}>
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
