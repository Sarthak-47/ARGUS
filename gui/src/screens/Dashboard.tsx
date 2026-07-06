import { C, FONT, bandColor, bandLabel } from "../theme";
import { AUDITS, STATS } from "../data";
import { useStore } from "../store";
import { ArgusEye } from "../components/ArgusEye";
import type { HistoryEntry } from "../adapter";

function timeAgo(ts: number | null): string {
  if (!ts) return "—";
  const seconds = Math.max(0, Date.now() / 1000 - ts);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function Dashboard() {
  const s = useStore();
  const setScreen = s.setScreen;
  const realHistory = s.history && s.history.length > 0 ? s.history : null;

  // Most recent first for the list; real data replaces the bundled demo rows
  // the moment at least one real scan has been recorded.
  const audits = realHistory
    ? [...realHistory].reverse().slice(0, 6).map((e) => ({
        name: e.target, score: e.riskScore, time: timeAgo(e.finishedAt),
      }))
    : AUDITS;

  return (
    <section style={{ padding: "36px 46px 64px 46px", maxWidth: 1180, position: "relative" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 40 }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 16 }}>
          <h1 style={{ margin: 0, fontFamily: FONT.display, fontWeight: 600, fontSize: 16, letterSpacing: "0.3em", color: C.goldPale }}>
            OVERVIEW
          </h1>
          <span style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 15, color: C.stoneText }}>
            Argus never sleeps
          </span>
        </div>
        <button
          className="btn-ghost"
          onClick={() => setScreen("scan")}
          style={{
            fontFamily: FONT.display, fontSize: 12, letterSpacing: "0.18em", fontWeight: 600,
            color: C.goldenrod, background: "transparent", border: `1px solid ${C.bronze}`,
            padding: "12px 22px", cursor: "pointer",
          }}
        >
          NEW SCAN
        </button>
      </div>

      <div style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.26em", color: C.stoneText, marginBottom: 16 }}>
        RISK TREND
      </div>
      <TrendGraph entries={realHistory} />

      <div style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.26em", color: C.stoneText, marginBottom: 16, marginTop: 40 }}>
        RECENT AUDITS
      </div>
      <div style={{ display: "flex", flexDirection: "column", border: `1px solid ${C.relief}`, background: C.stoneDark, marginBottom: 52 }}>
        {audits.map((a, i) => (
          <button
            key={`${a.name}-${i}`}
            className="row-hover"
            onClick={() => setScreen("report")}
            style={{
              position: "relative", display: "grid", gridTemplateColumns: "1fr 60px 132px 70px",
              alignItems: "center", gap: 22, padding: "18px 24px", background: "transparent",
              border: "none", borderBottom: "1px solid rgba(184,134,11,0.12)", cursor: "pointer",
              textAlign: "left", width: "100%",
            }}
          >
            <span style={{ fontFamily: FONT.code, fontSize: 13, color: C.parchment, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {a.name}
            </span>
            <span style={{ fontFamily: FONT.display, fontSize: 26, fontWeight: 600, color: C.goldPale, textAlign: "right" }}>
              {a.score}
            </span>
            <span style={{ display: "flex", flexDirection: "column", gap: 6, width: 132 }}>
              <span style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 13, letterSpacing: "0.04em", color: bandColor(a.score) }}>
                {bandLabel(a.score)}
              </span>
              <span style={{ height: 4, background: C.relief, width: "100%" }}>
                <span style={{ display: "block", height: "100%", width: `${a.score}%`, background: bandColor(a.score) }} />
              </span>
            </span>
            <span style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 13, color: C.stoneText, textAlign: "right" }}>
              {a.time}
            </span>
          </button>
        ))}
      </div>

      <div style={{ position: "relative" }}>
        <ArgusEye
          size={320}
          opacity={0.08}
          style={{ position: "absolute", left: "50%", top: "50%", transform: "translate(-50%,-50%)", pointerEvents: "none", zIndex: 0 }}
        />
        <div style={{ position: "relative", zIndex: 1, display: "flex", gap: 1, background: C.relief, border: `1px solid ${C.relief}` }}>
          {STATS.map((st) => (
            <div key={st.label} style={{ flex: 1, background: "rgba(15,15,21,0.86)", padding: "30px 28px" }}>
              <div style={{ fontFamily: FONT.display, fontSize: 82, fontWeight: 700, color: st.color, lineHeight: 0.85 }}>
                {st.value}
              </div>
              <div style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.2em", color: C.stoneText, marginTop: 14 }}>
                {st.label}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function TrendGraph({ entries }: { entries: HistoryEntry[] | null }) {
  const W = 1080;
  const H = 140;
  const PAD = 20;

  if (!entries || entries.length < 2) {
    return (
      <div style={{
        border: `1px solid ${C.relief}`, background: C.stoneDark, marginBottom: 40,
        padding: "34px 28px", fontFamily: FONT.body, fontStyle: "italic", fontSize: 14, color: C.stoneText,
        textAlign: "center",
      }}>
        {entries && entries.length === 1
          ? "One scan recorded so far — the trend line appears after your next one."
          : "Run a few real scans to see your risk trend here."}
      </div>
    );
  }

  const scores = entries.map((e) => e.riskScore);
  const stepX = (W - PAD * 2) / (entries.length - 1);
  const points = scores.map((score, i) => {
    const x = PAD + i * stepX;
    const y = PAD + (1 - score / 100) * (H - PAD * 2);
    return [x, y] as const;
  });
  const linePath = points.map(([x, y], i) => `${i === 0 ? "M" : "L"}${x},${y}`).join(" ");
  const areaPath = `${linePath} L${points[points.length - 1][0]},${H - PAD} L${points[0][0]},${H - PAD} Z`;
  const latest = entries[entries.length - 1];

  return (
    <div style={{ border: `1px solid ${C.relief}`, background: C.stoneDark, marginBottom: 40, padding: "20px 24px" }}>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} preserveAspectRatio="none">
        <path d={areaPath} fill={bandColor(latest.riskScore)} opacity={0.12} />
        <path d={linePath} fill="none" stroke={bandColor(latest.riskScore)} strokeWidth={2} />
        {points.map(([x, y], i) => (
          <circle key={i} cx={x} cy={y} r={3.5} fill={bandColor(scores[i])} />
        ))}
      </svg>
      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 8, fontFamily: FONT.code, fontSize: 11, color: C.stoneText }}>
        <span>{timeAgo(entries[0].finishedAt)}</span>
        <span style={{ color: bandColor(latest.riskScore) }}>latest: {latest.riskScore} ({bandLabel(latest.riskScore)})</span>
        <span>{timeAgo(latest.finishedAt)}</span>
      </div>
    </div>
  );
}
