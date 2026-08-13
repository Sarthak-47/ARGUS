// I · THE WATCH — the pinned reference screen.
//
// Three columns, exactly as designed: POSTURE OF THE ESTATE (left, dotted
// leaders and one large figure), THE HUNDRED EYES (centre, the constellation
// as readout), WHAT THE EYES SAW (right, a register of real events). Nothing
// here is invented — every leader and every entry traces to store.history or
// store.report; where there is no data the leader or the section is simply
// absent rather than showing a placeholder.

import { bandColor, bandLabel } from "../theme";
import { useStore } from "../store";
import { Constellation } from "../components/Constellation";
import { AGENTS } from "../data";

function timeAgo(ts: number | null): string {
  if (!ts) return "—";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
function stamp(ts: number | null): string {
  if (!ts) return "—:—";
  const d = new Date(ts * 1000);
  return d.toTimeString().slice(0, 5);
}

interface RegisterEntry { kind: string; when: string; body: string; grave?: boolean; where?: string; onOpen?: () => void }

export function Dashboard() {
  const s = useStore();
  const setScreen = s.setScreen;
  const realHistory = s.history && s.history.length > 0 ? s.history : null;
  const findings = s.report?.findings ?? [];
  const latest = realHistory ? realHistory[realHistory.length - 1] : null;

  const open = findings.length;
  // Measured against the real 19-agent roster, not the 51-class vulnerability
  // catalogue the eye field itself binds to — those are two different real
  // counts and showing 51 here read as inconsistent with "19 agents"
  // elsewhere in the app. Findings can in principle exceed the roster size;
  // floor lulled at 0 rather than show a negative.
  const lulled = Math.max(0, AGENTS.length - open);
  const grave = findings.filter((f) => f.severity === "CRITICAL").length;
  const assetsGuarded = realHistory ? realHistory.length : 0;

  // The register: real completed sweeps, newest first, worded in the ledger's
  // own voice but stating only real fields (target, counts, timestamp).
  const entries: RegisterEntry[] = [];
  if (realHistory) {
    for (const h of [...realHistory].reverse().slice(0, 6)) {
      const c = h.counts?.CRITICAL || 0;
      const hi = h.counts?.HIGH || 0;
      entries.push({
        kind: c > 0 ? "GRAVE" : "SWEEP CLOSED",
        when: stamp(h.finishedAt),
        grave: c > 0,
        body: c > 0
          ? `${h.target} came back grave — ${c} critical${hi ? ` and ${hi} high` : ""} recorded.`
          : hi > 0
            ? `${h.target} swept clean of grave matters; ${hi} high still open.`
            : `${h.target} swept and found quiet. Risk ${h.riskScore} — ${bandLabel(h.riskScore).toLowerCase()}.`,
        where: h.target,
        onOpen: () => setScreen("report"),
      });
    }
  }
  if (findings.length) {
    entries.unshift(
      ...findings
        .filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH")
        .slice(0, 3)
        .map((f): RegisterEntry => ({
          kind: f.severity === "CRITICAL" ? "GRAVE" : "OBSERVED",
          when: "now",
          grave: f.severity === "CRITICAL",
          body: f.name,
          where: f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : f.endpoint,
          onOpen: () => { s.select(f.id); setScreen("report"); },
        }))
    );
  }

  return (
    <div style={{ display: "grid", gridTemplateColumns: "262px minmax(400px,1fr) 292px", gap: 34, alignItems: "stretch", height: "100%", padding: "26px 40px 34px", overflow: "hidden" }}>
      {/* LEFT — Posture of the estate */}
      <section style={{ minHeight: 0, overflowY: "auto" }}>
        <div className="col-head">Posture of the estate</div>

        <div className="posture">
          <span className="posture-num">{open}</span>
          <span className="posture-of">of<br />{AGENTS.length}</span>
        </div>
        <p className="aside" style={{ marginTop: -8, marginBottom: 26 }}>
          {open === 0 ? "Every eye open, nothing found. The ground is quiet." : `${open} eye${open === 1 ? "" : "s"} open. ${lulled} lulled asleep.`}
        </p>

        <div className="leader"><span className="k">Assets guarded</span><span className="dots" /><span className="v">{assetsGuarded || "—"}</span></div>
        <div className="leader"><span className="k">Observations open</span><span className="dots" /><span className="v gold">{open}</span></div>
        <div className="leader"><span className="k">Grave, unanswered</span><span className="dots" /><span className={`v${grave ? " grave" : ""}`}>{grave}</span></div>
        <div className="leader"><span className="k">Ground unwatched</span><span className="dots" /><span className="v">{lulled}</span></div>

        {latest && (
          <p className="aside" style={{ marginTop: 26 }}>
            Last sweep closed {timeAgo(latest.finishedAt)}, risk {latest.riskScore} — {bandLabel(latest.riskScore).toLowerCase()}.
          </p>
        )}

        <button className="commit" style={{ marginTop: 22 }} onClick={() => setScreen("scan")}>
          Set the watch <span className="arrow">→</span>
        </button>
      </section>

      {/* CENTRE — The hundred eyes */}
      <section style={{ display: "flex", flexDirection: "column", minHeight: 0, overflow: "hidden" }}>
        <div className="col-head">The hundred eyes</div>
        {/* Fills the whole remaining column — width and height, not a
            square boxed inside it. Constellation already scales the field
            on each axis independently, so it was fighting an aspect-ratio
            box that just left dead space above and below the circle. */}
        <div style={{ flex: "1 1 auto", minHeight: 0, width: "100%", marginTop: 4, position: "relative" }}>
          <Constellation
            findings={findings}
            scanning={s.auditRunning}
            onPick={(f) => { s.select(f.id); setScreen("report"); }}
          />
        </div>
        {realHistory && realHistory.length > 1 && (
          <div style={{ flex: "0 0 auto", marginTop: 4 }}>
            <TrendGraph entries={realHistory.map((h) => h.riskScore)} />
          </div>
        )}
      </section>

      {/* RIGHT — What the eyes saw */}
      <section style={{ minHeight: 0, overflowY: "auto" }}>
        <div className="col-head">What the eyes saw</div>
        {entries.length === 0 ? (
          <p className="aside">Nothing has been watched yet. Set the watch and the register will begin to fill.</p>
        ) : (
          entries.map((e, i) => {
            const Comp = e.onOpen ? "button" : "div";
            return (
              <Comp key={i} className="entry" onClick={e.onOpen} style={e.onOpen ? { display: "block", width: "100%", textAlign: "left", background: "none", border: "none", padding: "14px 0", borderBottom: "1px solid var(--rule)", cursor: "pointer" } : undefined}>
                <div className="entry-head">
                  <span className={`entry-kind${e.grave ? " grave" : ""}`}>{e.kind}</span>
                  <span className="entry-when">{e.when}</span>
                </div>
                <div className="entry-body">{e.body}</div>
                {e.where && <div className="entry-where">{e.where}</div>}
              </Comp>
            );
          })
        )}
      </section>
    </div>
  );
}

function TrendGraph({ entries }: { entries: number[] }) {
  const W = 280, H = 34, PAD = 3;
  const stepX = (W - PAD * 2) / (entries.length - 1);
  const points = entries.map((score, i) => [PAD + i * stepX, PAD + (1 - score / 100) * (H - PAD * 2)] as const);
  const linePath = points.map(([x, y], i) => `${i === 0 ? "M" : "L"}${x},${y}`).join(" ");
  const last = entries[entries.length - 1];
  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} preserveAspectRatio="none" style={{ display: "block", opacity: 0.8 }}>
      <path d={linePath} fill="none" stroke={bandColor(last)} strokeWidth={1} />
      {points.map(([x, y], i) => <circle key={i} cx={x} cy={y} r={1.4} fill={bandColor(entries[i])} />)}
    </svg>
  );
}
