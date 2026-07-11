// Global UI state. All findings/history/status come from the real Python engine
// (via Tauri IPC in the desktop app, or a dropped-in report.json in the browser
// dev build). There is no scripted/simulated data here.

import { create } from "zustand";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { AGENTS, type FeedLine } from "./data";
import { mapReport, mapHistory, type LoadedReport, type HistoryEntry, type EngineComparison, type StatusInfo } from "./adapter";

export type Screen = "dashboard" | "scan" | "live" | "report" | "settings" | "code";

function allChecked(v: boolean): Record<string, boolean> {
  const o: Record<string, boolean> = {};
  AGENTS.forEach((n) => (o[n] = v));
  return o;
}

interface State {
  screen: Screen;
  // scan config
  scanChecked: Record<string, boolean>;
  depth: "Quick" | "Standard" | "Deep";
  phase1: boolean;
  phase2: boolean;
  // report
  filter: string;
  selectedId: number | null;
  // code view (drill-down from a static finding)
  codeSnippet: { startLine: number; lines: string[] } | null;
  codeError: string | null;
  codeLoading: boolean;
  // settings
  provider: string;
  savingModel: boolean;
  modelSaveError: string | null;
  // real engine data (null => nothing scanned yet)
  report: LoadedReport | null;
  // real scan history (null => no scans recorded yet)
  history: HistoryEntry[] | null;
  // what's new/fixed since the previous scan (null => not available yet)
  comparison: EngineComparison | null;
  // real resolved provider/model/GPU/defaults (null => desktop-only, not loaded yet)
  status: StatusInfo | null;
  statusLoading: boolean;
  connectionTestResult: "ok" | "unreachable" | null;
  savingKey: boolean;
  // real desktop-invoked scan (only possible inside the Tauri shell)
  target: string;
  isDesktop: boolean;
  auditRunning: boolean;
  auditElapsedSec: number;
  auditError: string | null;
  argusAvailable: boolean | null;
  // manual "Argus CLI path" override (Settings' escape hatch for when
  // auto-detection can't find argus — e.g. a project venv install)
  argusPathSaved: string | null;
  argusPathSaving: boolean;
  argusPathError: string | null;
  // live per-agent events streamed from the running engine (desktop only).
  // Empty when nothing has streamed yet — Live Attack falls back to the clock.
  feed: FeedLine[];
  // ids of findings just suppressed in this session — hidden from the
  // current view immediately, without waiting for a re-scan
  suppressedIds: Set<number>;
  suppressionError: string | null;

  setScreen: (s: Screen) => void;
  loadReport: () => Promise<void>;
  loadHistory: () => Promise<void>;
  loadComparison: () => Promise<void>;
  loadStatus: () => Promise<void>;
  testConnection: () => Promise<void>;
  saveProviderKey: (provider: string, key: string) => Promise<void>;
  suppressFinding: (id: number, title: string, status: "ignored" | "reviewing", reason?: string) => Promise<void>;
  setTarget: (t: string) => void;
  runRealAudit: () => Promise<void>;
  checkArgusAvailable: () => Promise<void>;
  loadArgusPath: () => Promise<void>;
  setArgusPathOverride: (path: string) => Promise<void>;
  clearArgusPathOverride: () => Promise<void>;
  toggleAgent: (n: string) => void;
  selectAllAgents: () => void;
  togglePhase: (p: "phase1" | "phase2") => void;
  setDepth: (d: "Quick" | "Standard" | "Deep") => void;
  setFilter: (f: string) => void;
  select: (id: number | null) => void;
  setProvider: (p: string) => void;
  setLocalModel: (name: string) => Promise<void>;
  openCodeView: (file: string, line: number) => Promise<void>;
}

let auditTimer: ReturnType<typeof setInterval> | null = null;

export const useStore = create<State>((set, get) => ({
  screen: "dashboard",
  scanChecked: allChecked(true),
  depth: "Standard",
  phase1: true,
  phase2: true,
  filter: "All",
  selectedId: null,
  codeSnippet: null,
  codeError: null,
  codeLoading: false,
  provider: "",
  savingModel: false,
  modelSaveError: null,
  report: null,
  history: null,
  comparison: null,
  status: null,
  statusLoading: false,
  connectionTestResult: null,
  savingKey: false,
  target: "",
  isDesktop: isTauri(),
  auditRunning: false,
  auditElapsedSec: 0,
  auditError: null,
  argusAvailable: null,
  argusPathSaved: null,
  argusPathSaving: false,
  argusPathError: null,
  feed: [],
  suppressedIds: new Set(),
  suppressionError: null,

  setTarget: (t) => set({ target: t }),

  suppressFinding: async (id, title, status, reason = "") => {
    if (!isTauri()) return;
    set({ suppressionError: null });
    try {
      await invoke("suppress_finding", { search: title, status, reason });
      set((s) => ({ suppressedIds: new Set(s.suppressedIds).add(id), selectedId: null }));
    } catch (err) {
      set({ suppressionError: String(err) });
    }
  },

  checkArgusAvailable: async () => {
    if (!isTauri()) return;
    try {
      const ok = await invoke<boolean>("check_argus_available");
      set({ argusAvailable: ok });
    } catch {
      set({ argusAvailable: false });
    }
  },

  loadArgusPath: async () => {
    if (!isTauri()) return;
    try {
      const saved = await invoke<string | null>("get_argus_path");
      set({ argusPathSaved: saved ?? null });
    } catch {
      /* nothing saved yet */
    }
  },

  // Point the app at a specific argus executable — the fix for when
  // auto-detection can't find it (a project venv, a non-standard install).
  // Re-checks availability/status/history immediately on success so every
  // screen that depends on the engine being reachable updates at once.
  setArgusPathOverride: async (path) => {
    if (!isTauri()) {
      set({ argusPathError: "Setting a CLI path only works in the desktop app." });
      return;
    }
    set({ argusPathSaving: true, argusPathError: null });
    try {
      await invoke("set_argus_path", { path });
      set({ argusPathSaved: path, argusPathSaving: false });
      await get().checkArgusAvailable();
      await get().loadStatus();
      await get().loadHistory();
    } catch (err) {
      set({ argusPathSaving: false, argusPathError: String(err) });
    }
  },

  clearArgusPathOverride: async () => {
    if (!isTauri()) return;
    try {
      await invoke("clear_argus_path");
      set({ argusPathSaved: null, argusPathError: null });
      await get().checkArgusAvailable();
      await get().loadStatus();
    } catch (err) {
      set({ argusPathError: String(err) });
    }
  },

  runRealAudit: async () => {
    const { target, phase1, phase2, scanChecked } = get();
    if (!target.trim()) {
      set({ auditError: "Enter a target path or URL first." });
      return;
    }
    set({ auditRunning: true, auditError: null, auditElapsedSec: 0, feed: [], screen: "live" });
    if (auditTimer) clearInterval(auditTimer);
    auditTimer = setInterval(() => set((s) => ({ auditElapsedSec: s.auditElapsedSec + 1 })), 1000);
    try {
      const mode = phase2 ? "audit" : "scan";
      const agents = phase1 && phase2
        ? Object.entries(scanChecked).filter(([, on]) => on).map(([n]) => n).join(",")
        : undefined;
      const json = await invoke<string>("run_audit", { target: target.trim(), mode, agents });
      const report = mapReport(JSON.parse(json));
      if (auditTimer) { clearInterval(auditTimer); auditTimer = null; }
      set({ report, auditRunning: false, screen: "report" });
      get().loadHistory();
      get().loadComparison();
    } catch (err) {
      if (auditTimer) { clearInterval(auditTimer); auditTimer = null; }
      set({ auditRunning: false, auditError: String(err), screen: "scan" });
    }
  },

  loadReport: async () => {
    // Pull a real Argus report if one was dropped into the app's public dir
    // (browser dev build). Ships absent, so a fresh app simply has no report.
    try {
      const res = await fetch("report.json", { cache: "no-store" });
      if (!res.ok) return;
      const json = await res.json();
      if (json && Array.isArray(json.findings)) {
        set({ report: mapReport(json) });
      }
    } catch {
      /* no report available — the app shows its empty state */
    }
  },

  loadHistory: async () => {
    if (!isTauri()) return;
    try {
      const json = await invoke<string>("read_scan_history", { limit: 50 });
      const parsed = JSON.parse(json);
      if (Array.isArray(parsed) && parsed.length > 0) {
        set({ history: mapHistory(parsed) });
      }
    } catch {
      /* no history yet, or not running in the desktop shell */
    }
  },

  loadComparison: async () => {
    if (!isTauri()) return;
    try {
      const json = await invoke<string>("read_scan_comparison");
      const parsed = JSON.parse(json) as EngineComparison;
      if (parsed && Array.isArray(parsed.new_findings)) {
        set({ comparison: parsed });
      }
    } catch {
      /* no comparison available yet — the Reports screen just won't show it */
    }
  },

  loadStatus: async () => {
    if (!isTauri()) return;
    set({ statusLoading: true });
    try {
      const json = await invoke<string>("read_status");
      const parsed = JSON.parse(json) as StatusInfo;
      set({
        status: parsed, statusLoading: false,
        provider: parsed.resolved_provider || parsed.preferred_provider,
        connectionTestResult: parsed.resolved_provider ? (parsed.available ? "ok" : "unreachable") : null,
      });
    } catch {
      set({ statusLoading: false });
    }
  },

  testConnection: async () => {
    await get().loadStatus();
  },

  saveProviderKey: async (provider, key) => {
    if (!isTauri() || !key.trim()) return;
    set({ savingKey: true });
    try {
      await invoke("save_provider_key", { name: provider, key: key.trim() });
    } finally {
      set({ savingKey: false });
      get().loadStatus();
    }
  },

  setScreen: (s) => {
    set({ screen: s, selectedId: null });
    // Each screen is its own page — reflect it in the URL hash so back/forward
    // and deep links work. Setting the hash to its current value is a no-op and
    // won't re-fire the hashchange listener in App.
    if (typeof window !== "undefined" && window.location.hash !== `#/${s}`) {
      window.location.hash = `/${s}`;
    }
    if (s === "report") get().loadComparison();
  },

  openCodeView: async (file, line) => {
    set({ screen: "code", codeSnippet: null, codeError: null, codeLoading: true });
    if (typeof window !== "undefined" && window.location.hash !== "#/code") window.location.hash = "/code";
    const { isDesktop, report } = get();
    const root = report?.target;
    if (!isDesktop || !root || /^https?:\/\//i.test(root)) {
      set({
        codeLoading: false,
        codeError: !isDesktop
          ? "Reading source files only works in the desktop app."
          : "This finding's scan target wasn't a local path, so there's no file to read.",
      });
      return;
    }
    try {
      const [startLine, lines] = await invoke<[number, string[]]>("read_source_snippet", {
        root, file, line, context: 8,
      });
      set({ codeSnippet: { startLine, lines }, codeLoading: false });
    } catch (err) {
      set({ codeError: String(err), codeLoading: false });
    }
  },

  toggleAgent: (n) =>
    set((st) => ({ scanChecked: { ...st.scanChecked, [n]: !st.scanChecked[n] } })),

  selectAllAgents: () =>
    set((st) => {
      const v = !AGENTS.every((n) => st.scanChecked[n]);
      return { scanChecked: allChecked(v) };
    }),

  togglePhase: (p) => set((st) => ({ [p]: !st[p] }) as Partial<State>),
  setDepth: (d) => set({ depth: d }),
  setFilter: (f) => set({ filter: f }),
  select: (id) => set({ selectedId: id }),
  setProvider: (p) => {
    set({ provider: p });
    if (isTauri()) {
      invoke("set_provider", { name: p.toLowerCase() })
        .then(() => get().loadStatus())
        .catch(() => { /* keep the local selection even if persisting failed */ });
    }
  },
  setLocalModel: async (name) => {
    if (!isTauri()) return;
    set({ savingModel: true, modelSaveError: null });
    try {
      await invoke("set_local_model", { name });
      await get().loadStatus();
    } catch (err) {
      set({ modelSaveError: String(err) });
    } finally {
      set({ savingModel: false });
    }
  },
}));

// Subscribe once to the engine's live per-agent event stream (desktop only).
// Each `argus://event` carries one `{agent, text, sev}` line the running audit
// emitted; we append it to the feed the Live Attack screen renders. If we're
// not in the Tauri shell there's no emitter, so this is simply a no-op.
if (isTauri()) {
  let feedId = 0;
  listen<string>("argus://event", (e) => {
    try {
      const p = JSON.parse(e.payload) as { agent: string; text: string; sev: FeedLine["sev"] };
      const line: FeedLine = { agent: p.agent, text: p.text, sev: p.sev, id: feedId++ };
      // Cap the retained feed so a long audit can't grow it without bound.
      useStore.setState((s) => ({ feed: [...s.feed.slice(-199), line] }));
    } catch {
      /* malformed line — ignore it rather than break the feed */
    }
  });
}
