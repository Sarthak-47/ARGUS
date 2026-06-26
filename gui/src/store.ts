// Global UI state + the live-attack demo engine, ported from the design's DCLogic.

import { create } from "zustand";
import { AGENTS, TIMELINE, type AgentState, type FeedLine } from "./data";

export type Screen = "dashboard" | "scan" | "live" | "report" | "settings";

function freshAgents(): Record<string, AgentState> {
  const o: Record<string, AgentState> = {};
  AGENTS.forEach((n) => (o[n] = { status: "queued", sent: 0, confirmed: 0, progress: 0 }));
  return o;
}

function allChecked(v: boolean): Record<string, boolean> {
  const o: Record<string, boolean> = {};
  AGENTS.forEach((n) => (o[n] = v));
  return o;
}

interface State {
  screen: Screen;
  // live attack
  attackRunning: boolean;
  riskScore: number;
  confirmed: number;
  confFlash: number;
  tick: number;
  activated: number;
  agents: Record<string, AgentState>;
  feed: FeedLine[];
  // scan config
  scanChecked: Record<string, boolean>;
  depth: "Quick" | "Standard" | "Deep";
  phase1: boolean;
  phase2: boolean;
  // report
  filter: string;
  selectedId: number | null;
  reportRisk: number;
  // settings
  provider: string;

  setScreen: (s: Screen) => void;
  toggleAgent: (n: string) => void;
  selectAllAgents: () => void;
  togglePhase: (p: "phase1" | "phase2") => void;
  setDepth: (d: "Quick" | "Standard" | "Deep") => void;
  setFilter: (f: string) => void;
  select: (id: number | null) => void;
  setProvider: (p: string) => void;
  startAttack: () => void;
  resetAttack: () => void;
  countReport: () => void;
}

let attackTimer: ReturnType<typeof setInterval> | null = null;
let reportTimer: ReturnType<typeof setInterval> | null = null;
const reduceMotion =
  typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;

export const useStore = create<State>((set, get) => ({
  screen: "dashboard",
  attackRunning: false,
  riskScore: 0,
  confirmed: 0,
  confFlash: 0,
  tick: 0,
  activated: 0,
  agents: freshAgents(),
  feed: [],
  scanChecked: allChecked(true),
  depth: "Standard",
  phase1: true,
  phase2: true,
  filter: "All",
  selectedId: null,
  reportRisk: 0,
  provider: "Groq",

  setScreen: (s) => {
    set({ screen: s, selectedId: null });
    if (s === "live") get().startAttack();
    if (s === "report") get().countReport();
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
  setProvider: (p) => set({ provider: p }),

  resetAttack: () => {
    if (attackTimer) clearInterval(attackTimer);
    attackTimer = null;
    set({
      attackRunning: false, riskScore: 0, confirmed: 0, confFlash: 0, tick: 0,
      activated: 0, agents: freshAgents(), feed: [],
    });
  },

  startAttack: () => {
    get().resetAttack();
    set({ attackRunning: true });

    const finishInstant = () => {
      set((s) => {
        const agents = { ...s.agents };
        let feed = [...s.feed];
        TIMELINE.forEach((ev, i) => {
          if (ev.a) {
            const [n, upd] = ev.a;
            agents[n] = { ...agents[n], ...upd };
          }
          feed = feed.concat([{ agent: ev.f[0], text: ev.f[1], sev: ev.f[2], id: i }]);
        });
        Object.keys(agents).forEach((n) => {
          if (agents[n].status === "running") agents[n] = { ...agents[n], status: "complete", progress: 100 };
        });
        return { agents, feed, riskScore: 74, confirmed: 8, activated: 18, attackRunning: false };
      });
    };

    if (reduceMotion) {
      finishInstant();
      return;
    }

    attackTimer = setInterval(() => {
      const s = get();
      if (s.tick >= TIMELINE.length) {
        if (attackTimer) clearInterval(attackTimer);
        attackTimer = null;
        const agents = { ...s.agents };
        Object.keys(agents).forEach((n) => {
          if (agents[n].status === "running") agents[n] = { ...agents[n], status: "complete", progress: 100 };
        });
        set({ agents, attackRunning: false });
        return;
      }
      const ev = TIMELINE[s.tick];
      const agents = { ...s.agents };
      if (ev.a) {
        const [n, upd] = ev.a;
        agents[n] = { ...agents[n], ...upd };
      }
      set({
        tick: s.tick + 1,
        agents,
        feed: s.feed.concat([{ agent: ev.f[0], text: ev.f[1], sev: ev.f[2], id: s.tick }]),
        riskScore: ev.risk ? Math.min(74, s.riskScore + ev.risk) : s.riskScore,
        confirmed: ev.conf ? s.confirmed + ev.conf : s.confirmed,
        confFlash: ev.conf ? s.confFlash + 1 : s.confFlash,
        activated: s.activated + (ev.act || 0),
      });
    }, 780);
  },

  countReport: () => {
    if (reportTimer) clearInterval(reportTimer);
    if (reduceMotion) {
      set({ reportRisk: 74 });
      return;
    }
    set({ reportRisk: 0 });
    const start = Date.now();
    reportTimer = setInterval(() => {
      const p = Math.min(1, (Date.now() - start) / 1500);
      set({ reportRisk: Math.round(74 * (1 - Math.pow(1 - p, 2))) });
      if (p >= 1 && reportTimer) clearInterval(reportTimer);
    }, 40);
  },
}));
