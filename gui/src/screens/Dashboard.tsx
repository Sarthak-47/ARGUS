import { RF, FONT, bandColor, bandLabel, sevColor } from "../theme";
import { useStore } from "../store";
import { TerracottaMark, EyeGlyph, ScreenHeader } from "../components/Panoptes";
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

  const audits = realHistory
    ? [...realHistory].reverse().slice(0, 6).map((e) => ({ name: e.target, score: e.riskScore, time: timeAgo(e.finishedAt), counts: e.counts }))
    : [];
  const latest = realHistory ? realHistory[realHistory.length - 1] : null;
  const stats = realHistory && latest
    ? [
        { label: "Scans", value: String(realHistory.length), color: RF.clay },
        { label: "Latest risk", value: String(latest.riskScore), color: bandColor(latest.riskScore) },
        { label: "Critical", value: String(latest.counts?.CRITICAL || 0), color: sevColor("CRITICAL") },
        { label: "High", value: String(latest.counts?.HIGH || 0), color: sevColor("HIGH") },
      ]
    : null;

  return (
    <section>
      <ScreenHeader
        title="Dashboard"
        subtitle="recent scans and risk over time"
        action={
          <button onClick={() => setScreen("scan")} style={{ fontFamily: FONT.display, fontSize: 12, letterSpacing: "0.16em", textTransform: "uppercase", color: RF.clayHi, background: "transparent", border: `1px solid ${RF.dilute}`, padding: "11px 20px", cursor: "pointer" }}>
            New scan
          </button>
        }
      />

      <div style={{ padding: "26px 46px 64px", maxWidth: 1500, position: "relative" }}>
        {/* Two ways in: scan code, or scan a live website. Each jumps into New
            Scan pre-set to that mode (see setScanMode). */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 34 }}>
          {([
            { mode: "code" as const, title: "Scan code", desc: "a repo URL or local folder" },
            { mode: "web" as const, title: "Scan a website", desc: "a live URL — attack it" },
          ]).map((m) => (
            <button key={m.mode} onClick={() => { s.setScanMode(m.mode); setScreen("scan"); }} style={{
              display: "flex", alignItems: "center", gap: 14, padding: "18px 20px", cursor: "pointer", textAlign: "left",
              background: `linear-gradient(180deg, ${RF.ember}, ${RF.glazeLo})`, border: `1px solid ${RF.dilute}`,
            }}>
              <EyeGlyph w={30} h={19} />
              <span style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                <span style={{ fontFamily: FONT.display, fontSize: 15, letterSpacing: "0.06em", textTransform: "uppercase", color: RF.clayHi }}>{m.title}</span>
                <span style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 13, color: RF.dust }}>{m.desc}</span>
              </span>
            </button>
          ))}
        </div>

        <div style={{ fontFamily: FONT.display, fontSize: 10.5, letterSpacing: "0.2em", textTransform: "uppercase", color: RF.dust, marginBottom: 14 }}>
          Risk over time — each scan, coloured by severity
        </div>
        <TrendGraph entries={realHistory} />

        <div style={{ fontFamily: FONT.display, fontSize: 10.5, letterSpacing: "0.2em", textTransform: "uppercase", color: RF.dust, margin: "40px 0 14px" }}>Recent scans</div>
        <div style={{ display: "flex", flexDirection: "column", border: `1px solid ${RF.diluteLo}`, background: RF.glaze, marginBottom: 52 }}>
          {audits.length === 0 && (
            <div style={{ padding: "34px 28px", fontFamily: FONT.body, fontStyle: "italic", fontSize: 14, color: RF.dust, textAlign: "center" }}>
              No scans yet — run one and it'll appear here.
            </div>
          )}
          {audits.map((a, i) => (
            <button key={`${a.name}-${i}`} className="row-hover" onClick={() => setScreen("report")} style={{
              display: "grid", gridTemplateColumns: "34px 1fr 68px 150px 70px", alignItems: "center", gap: 20, padding: "16px 22px",
              background: "transparent", border: "none", borderBottom: `1px solid rgba(125,79,40,0.22)`, cursor: "pointer", textAlign: "left", width: "100%",
            }}>
              <EyeGlyph wounded={a.score >= 70} w={28} h={18} />
              <span style={{ fontFamily: FONT.code, fontSize: 13, color: RF.ivory, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.name}</span>
              {/* fontVariantNumeric keeps every digit the same width and the
                  wider column stops "100" (3 digits) from crowding the bar/
                  band-label column next to it the way a single-digit score
                  wouldn't — same fixed width, inconsistent visual weight
                  depending on the value, is what read as "bad alignment". */}
              <span style={{ fontFamily: FONT.display, fontSize: 26, fontWeight: 700, color: bandColor(a.score), textAlign: "right", fontVariantNumeric: "tabular-nums" }}>{a.score}</span>
              <span style={{ display: "flex", flexDirection: "column", gap: 6, width: 150 }}>
                <span style={{ fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.14em", textTransform: "uppercase", color: bandColor(a.score) }}>{bandLabel(a.score)}</span>
                <span style={{ height: 4, background: RF.diluteLo, width: "100%" }}>
                  <span style={{ display: "block", height: "100%", width: `${a.score}%`, background: bandColor(a.score) }} />
                </span>
              </span>
              <span style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 13, color: RF.dust, textAlign: "right" }}>{a.time}</span>
            </button>
          ))}
        </div>

        <div style={{ position: "relative" }}>
          <TerracottaMark size={300} color="rgba(197,106,51,0.09)" style={{ position: "absolute", left: "50%", top: "50%", transform: "translate(-50%,-50%)", pointerEvents: "none", zIndex: 0 }} />
          {stats ? (
            <div style={{ position: "relative", zIndex: 1, display: "flex", gap: 1, background: RF.diluteLo, border: `1px solid ${RF.diluteLo}` }}>
              {stats.map((st) => (
                <div key={st.label} style={{ flex: 1, background: "rgba(13,9,6,0.86)", padding: "28px 26px" }}>
                  <div style={{ fontFamily: FONT.display, fontSize: 76, fontWeight: 700, color: st.color, lineHeight: 0.85 }}>{st.value}</div>
                  <div style={{ fontFamily: FONT.display, fontSize: 10.5, letterSpacing: "0.18em", textTransform: "uppercase", color: RF.dust, marginTop: 12 }}>{st.label}</div>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ position: "relative", zIndex: 1, border: `1px solid ${RF.diluteLo}`, background: "rgba(13,9,6,0.86)", padding: "40px 28px", textAlign: "center", fontFamily: FONT.body, fontStyle: "italic", fontSize: 14, color: RF.dust }}>
              Stats appear here after your first scan.
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function TrendGraph({ entries }: { entries: HistoryEntry[] | null }) {
  const W = 1080, H = 140, PAD = 20;
  if (!entries || entries.length < 2) {
    return (
      <div style={{ border: `1px solid ${RF.diluteLo}`, background: RF.glaze, marginBottom: 40, padding: "34px 28px", fontFamily: FONT.body, fontStyle: "italic", fontSize: 14, color: RF.dust, textAlign: "center" }}>
        {entries && entries.length === 1 ? "One scan so far — the trend line appears after your next one." : "Run a few scans to see risk over time."}
      </div>
    );
  }
  const scores = entries.map((e) => e.riskScore);
  const stepX = (W - PAD * 2) / (entries.length - 1);
  const points = scores.map((score, i) => [PAD + i * stepX, PAD + (1 - score / 100) * (H - PAD * 2)] as const);
  const linePath = points.map(([x, y], i) => `${i === 0 ? "M" : "L"}${x},${y}`).join(" ");
  const areaPath = `${linePath} L${points[points.length - 1][0]},${H - PAD} L${points[0][0]},${H - PAD} Z`;
  const latest = entries[entries.length - 1];
  return (
    <div style={{ border: `1px solid ${RF.diluteLo}`, background: RF.glaze, marginBottom: 40, padding: "20px 24px" }}>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} preserveAspectRatio="none">
        <path d={areaPath} fill={bandColor(latest.riskScore)} opacity={0.12} />
        <path d={linePath} fill="none" stroke={bandColor(latest.riskScore)} strokeWidth={2} />
        {points.map(([x, y], i) => <circle key={i} cx={x} cy={y} r={3.5} fill={bandColor(scores[i])} />)}
      </svg>
      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 8, fontFamily: FONT.code, fontSize: 11, color: RF.dust }}>
        <span>{timeAgo(entries[0].finishedAt)}</span>
        <span style={{ color: bandColor(latest.riskScore) }}>latest: {latest.riskScore} ({bandLabel(latest.riskScore)})</span>
        <span>{timeAgo(latest.finishedAt)}</span>
      </div>
    </div>
  );
}
