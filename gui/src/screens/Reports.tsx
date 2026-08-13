// III · THE REGISTER — a direct, verified port of the pinned Claude Design
// handoff's own layout (Argus.dc.html): severity counts as big serif
// numerals, a roster strip and a wounded-eyes band drawn on canvas, text
// SHOW filters, and a ledger list with its detail panel inline (not an
// overlay). Every count, eye and line of evidence traces to a real Finding
// from store.report — nothing here is scripted. See DESIGN.md.

import { FONT, sevColor, bandColor, bandLabel } from "../theme";
import { useStore } from "../store";
import type { Finding } from "../data";
import type { ComparisonFinding } from "../adapter";

const RANK: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
const SEV_LABEL: Record<string, string> = { CRITICAL: "GRAVE", HIGH: "HIGH", MEDIUM: "MIDDLING", LOW: "SLIGHT", INFO: "SLIGHT" };
const SEV_WEIGHT: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 2 };
const FILTERS: { key: string; label: string }[] = [
  { key: "All", label: "ALL" }, { key: "Critical", label: "GRAVE" }, { key: "High", label: "HIGH" },
  { key: "Medium", label: "MIDDLING" }, { key: "Low", label: "SLIGHT" },
];

const hasText = (v?: string | null): boolean =>
  !!v && v.trim().length > 0 && v.trim() !== "—" && v.trim().toLowerCase() !== "n/a";

/** Top findings, worst-first, one static dot each, real severity colour. */
function RosterStrip({ findings }: { findings: Finding[] }) {
  const shown = [...findings].sort((a, b) => (RANK[b.severity] || 0) - (RANK[a.severity] || 0)).slice(0, 18);
  if (!shown.length) return null;
  return (
    <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
      {shown.map((f) => (
        <span key={f.id} style={{ width: 7, height: 7, flex: "0 0 auto", background: sevColor(f.severity) }} />
      ))}
    </div>
  );
}

/** The wound tally: ranked grave-to-slight, weighted by severity, as a
 * static row of tick marks — the selected finding's ticks taller. */
function WoundBand({ findings, selectedId }: { findings: Finding[]; selectedId: number | null }) {
  const order: Finding["severity"][] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const ticks: { color: string; tall: boolean }[] = [];
  order.forEach((sev) => {
    findings.filter((f) => f.severity === sev || (sev === "LOW" && f.severity === "INFO")).forEach((f) => {
      for (let j = 0; j < SEV_WEIGHT[f.severity]; j++) {
        ticks.push({ color: sevColor(f.severity), tall: f.id === selectedId });
      }
    });
  });
  if (!ticks.length) return null;
  return (
    <div style={{ display: "flex", alignItems: "flex-end", gap: 5, height: 48, padding: "0 40px" }}>
      {ticks.map((t, i) => (
        <span key={i} style={{ width: 6, height: t.tall ? 40 : 26, flex: "0 0 auto", background: t.color }} />
      ))}
    </div>
  );
}

export function Reports() {
  const s = useStore();
  const live = s.report;
  if (!live) return <NoReport onScan={() => s.setScreen("scan")} />;
  const allFindings = live.findings.filter((f) => !s.suppressedIds.has(f.id));
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 } as Record<string, number>;
  allFindings.forEach((f) => (counts[f.severity] = (counts[f.severity] || 0) + 1));
  const filtered = s.filter === "All" ? allFindings : allFindings.filter((f) =>
    s.filter === "Low" ? f.severity === "LOW" || f.severity === "INFO" : f.severity === s.filter.toUpperCase());
  const sel = allFindings.find((f) => f.id === s.selectedId) || filtered[0] || null;

  const comp = s.comparison;
  const showComparison = !!comp && (!comp.old_target || comp.old_target === comp.new_target);

  const COUNTS = [
    { k: "GRAVE", v: counts.CRITICAL, color: "var(--grave)" },
    { k: "HIGH", v: counts.HIGH, color: "var(--gold)" },
    { k: "MIDDLING", v: counts.MEDIUM, color: "var(--bone)" },
    { k: "SLIGHT", v: counts.LOW + counts.INFO, color: "var(--bone-dim-3)" },
  ];

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <div style={{
        display: "flex", alignItems: "flex-end", justifyContent: "space-between",
        padding: "20px 40px 14px", borderBottom: "1px solid var(--rule-strong)", flex: "0 0 auto",
      }}>
        <div style={{ display: "flex", alignItems: "flex-end", gap: 50 }}>
          {COUNTS.map((c, i) => (
            <div key={c.k}>
              <div style={{ fontFamily: "var(--serif)", fontSize: i === 0 ? 88 : 56, lineHeight: 0.85, color: c.color }}>{c.v}</div>
              <div style={{ fontFamily: "var(--mono)", fontSize: 9.5, letterSpacing: "0.22em", color: "var(--bone-dim)", paddingTop: 10 }}>{c.k}</div>
            </div>
          ))}
          {live.riskScore != null && (
            <div>
              <div style={{ fontFamily: "var(--serif)", fontSize: 30, lineHeight: 0.9, color: bandColor(live.riskScore) }}>{live.riskScore}<span style={{ fontSize: 15, color: "var(--bone-dim-2)" }}>/100</span></div>
              <div style={{ fontFamily: "var(--mono)", fontSize: 9.5, letterSpacing: "0.22em", color: "var(--bone-dim)", paddingTop: 10 }}>{(live.band || bandLabel(live.riskScore)).toUpperCase()}</div>
            </div>
          )}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          {s.exportReportResult && <span style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--gold)" }}>{s.exportReportResult}</span>}
          {s.exportReportError && <span style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--grave-lit)" }}>{s.exportReportError}</span>}
          <button className="pick" style={{ fontSize: 13 }} disabled={s.exportingReport} onClick={() => s.exportReport("html")}>
            {s.exportingReport ? "exporting…" : "export report"}
          </button>
          <RosterStrip findings={allFindings} />
        </div>
      </div>

      <div style={{ flex: "0 0 auto" }}>
        <WoundBand findings={filtered} selectedId={sel?.id ?? null} />
        <div style={{
          display: "flex", justifyContent: "space-between", padding: "0 40px 10px",
          borderBottom: "1px solid var(--rule)", fontFamily: "var(--mono)", fontSize: 9.5,
          letterSpacing: "0.16em", textTransform: "uppercase", color: "var(--bone-dim-2)",
        }}>
          <span>THE WOUNDED EYES · RANKED GRAVE TO SLIGHT, LEFT TO RIGHT</span>
          <span>{filtered.length} SHOWN{sel ? ` · SELECTED ARG-${sel.id}` : ""}</span>
        </div>

        <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", padding: "14px 40px 10px" }}>
          <div style={{ fontFamily: "var(--serif)", fontSize: 26 }}>What the eyes have recorded</div>
          <div style={{ display: "flex", alignItems: "baseline", gap: 24 }}>
            <span style={{ fontFamily: "var(--mono)", fontSize: 9.5, letterSpacing: "0.22em", color: "var(--bone-dim-2)" }}>SHOW</span>
            {FILTERS.map((f) => {
              const on = s.filter === f.key;
              return (
                <button key={f.key} onClick={() => s.setFilter(f.key)} style={{
                  cursor: "pointer", background: "none", border: "none", display: "flex", alignItems: "baseline", gap: 7,
                  fontFamily: "var(--mono)", fontSize: 10, letterSpacing: "0.2em", color: on ? "var(--bone)" : "var(--bone-dim)",
                }}>
                  <span style={{ color: on ? "var(--gold)" : "var(--shut)" }}>{on ? "●" : "○"}</span>{f.label}
                </button>
              );
            })}
          </div>
        </div>

        {showComparison && comp && (comp.new_findings.length > 0 || comp.fixed_findings.length > 0) && (
          <div style={{ display: "flex", gap: 40, padding: "0 40px 10px" }}>
            <ChangeList label="Newly opened" color="var(--grave)" items={comp.new_findings} />
            <ChangeList label="Closed since" color="var(--gold)" items={comp.fixed_findings} />
          </div>
        )}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "minmax(520px,1.3fr) minmax(430px,1fr)", gap: 48, alignItems: "stretch", padding: "0 40px 20px", flex: "1 1 auto", minHeight: 0, overflow: "hidden" }}>
        <div style={{ borderTop: "1px solid var(--bone)", minHeight: 0, overflowY: "auto" }}>
          {filtered.length === 0 ? (
            <p className="aside" style={{ padding: "20px 0" }}>Nothing recorded at this severity.</p>
          ) : filtered.map((f) => {
            const isSel = sel?.id === f.id;
            return (
              <button key={f.id} onClick={() => s.select(f.id)} style={{
                cursor: "pointer", display: "block", width: "100%", textAlign: "left", background: "none", border: "none",
                padding: "15px 0 15px 14px", borderBottom: "1px solid var(--rule)", borderLeft: `2px solid ${isSel ? "var(--gold)" : "transparent"}`,
              }}>
                <div style={{ display: "flex", alignItems: "baseline", gap: 16 }}>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 9.5, letterSpacing: "0.22em", color: sevColor(f.severity), flex: "0 0 auto", width: 92 }}>{SEV_LABEL[f.severity]}</span>
                  <span style={{ fontFamily: "var(--serif)", fontSize: 20, lineHeight: 1.25, color: isSel ? "var(--bone)" : "var(--bone-dim-3)" }}>{f.name}</span>
                  <span style={{ flex: 1, borderBottom: "1px dotted var(--rule-dotted)", transform: "translateY(-5px)" }} />
                  <span style={{ fontFamily: "var(--mono)", fontSize: 9.5, letterSpacing: "0.14em", color: "var(--bone-dim-2)", flex: "0 0 auto" }}>ARG-{f.id}</span>
                </div>
                {(f.file || f.endpoint) && (
                  <div style={{ paddingLeft: 108, paddingTop: 7 }}>
                    <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: isSel ? "var(--gold)" : "var(--bone-dim-3)" }}>
                      {f.file ? `${f.file}${f.line ? ` : ${f.line}` : ""}` : f.endpoint}
                    </span>
                  </div>
                )}
                {f.whatIs && (
                  <div style={{ fontFamily: "var(--serif)", fontSize: 16.5, lineHeight: 1.5, color: "var(--bone-dim)", paddingLeft: 108, paddingTop: 5 }}>{f.whatIs}</div>
                )}
              </button>
            );
          })}
        </div>

        <div style={{ minHeight: 0, overflowY: "auto" }}>
          {sel ? (
            <>
              <div style={{ borderTop: "1px solid var(--bone)", paddingTop: 16 }}>
                <div style={{ display: "flex", alignItems: "baseline", gap: 16 }}>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 9.5, letterSpacing: "0.22em", color: sevColor(sel.severity) }}>{SEV_LABEL[sel.severity]}</span>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 9.5, letterSpacing: "0.16em", color: "var(--bone-dim-2)" }}>ARG-{sel.id} · {sel.agent}</span>
                </div>
                <div style={{ fontFamily: "var(--serif)", fontSize: 42, lineHeight: 1.1, marginTop: 16 }}>{sel.name}</div>
                {(sel.file || sel.endpoint) && (
                  <div style={{ fontSize: 11.5, color: "var(--gold)", marginTop: 10 }}>{sel.file ? `${sel.file}${sel.line ? ` : ${sel.line}` : ""}` : sel.endpoint}</div>
                )}
                {sel.whatIs && (
                  <div style={{ fontFamily: "var(--serif)", fontSize: 17.5, lineHeight: 1.6, color: "var(--bone-dim)", marginTop: 14 }}>{sel.whatIs}</div>
                )}
                {sel.chainOf ? (
                  <div style={{ fontFamily: "var(--mono)", fontSize: 10, letterSpacing: "0.1em", color: "var(--grave-lit)", border: "1px solid var(--grave-border)", background: "var(--grave-panel)", padding: "6px 10px", marginTop: 12, display: "inline-block" }}>
                    ⛓ CHAIN — COMPOUNDS {sel.chainOf} FINDINGS
                  </div>
                ) : null}
              </div>

              {(hasText(sel.request) || hasText(sel.response)) && (
                <>
                  <div className="col-head" style={{ marginTop: 30 }}>The evidence</div>
                  <div style={{ paddingTop: 12 }}>
                    {hasText(sel.request) && (
                      <>
                        <div style={{ fontFamily: "var(--mono)", fontSize: 9, letterSpacing: "0.18em", color: "var(--gold)", marginBottom: 4 }}>{hasText(sel.response) ? "REQUEST" : "CODE"}</div>
                        <pre style={{ margin: "0 0 12px", fontFamily: "var(--mono)", fontSize: 11.5, lineHeight: 1.85, color: "var(--bone)", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{sel.request}</pre>
                      </>
                    )}
                    {hasText(sel.response) && (
                      <>
                        <div style={{ fontFamily: "var(--mono)", fontSize: 9, letterSpacing: "0.18em", color: "var(--grave-lit)", marginBottom: 4 }}>RESPONSE</div>
                        <pre style={{ margin: 0, fontFamily: "var(--mono)", fontSize: 11.5, lineHeight: 1.85, color: "var(--bone-dim)", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{sel.response}</pre>
                      </>
                    )}
                  </div>
                </>
              )}

              {hasText(sel.repro) && (
                <>
                  <div className="col-head" style={{ marginTop: 28 }}>To see it again</div>
                  <div style={{ paddingTop: 10 }}>
                    {sel.repro.split("\n").filter((l) => l.trim()).map((line, i) => (
                      <div key={i} style={{ display: "flex", gap: 12, padding: "5px 0" }}>
                        <span style={{ fontFamily: "var(--serif)", fontSize: 15, color: "var(--bone-dim-2)", flex: "0 0 auto" }}>{i + 1}.</span>
                        <span style={{ fontFamily: "var(--serif)", fontSize: 17, lineHeight: 1.5, color: "var(--bone-dim)" }}>{line.replace(/^\d+[.)]\s*/, "")}</span>
                      </div>
                    ))}
                  </div>
                </>
              )}

              {hasText(sel.fix) && (
                <>
                  <div className="col-head" style={{ marginTop: 28 }}>What will close the lid</div>
                  <div style={{ fontFamily: "var(--serif)", fontSize: 17.5, lineHeight: 1.6, color: "var(--bone-dim)", paddingTop: 12 }}>{sel.fix}</div>
                </>
              )}

              <div style={{ display: "flex", gap: 34, marginTop: 22, borderTop: "1px solid var(--rule-strong)", paddingTop: 18 }}>
                {sel.file && sel.line != null && (
                  <button className="pick" style={{ fontSize: 20, letterSpacing: "0.02em" }} onClick={() => s.openCodeView(sel.file!, sel.line!)}>
                    view in code
                  </button>
                )}
                {s.isDesktop && (
                  <button className="pick" style={{ fontSize: 20, letterSpacing: "0.02em" }} onClick={() => s.suppressFinding(sel.id, sel.name, "ignored", "dismissed from Reports")}>
                    close the lid
                  </button>
                )}
              </div>
              {s.suppressionError && (
                <div style={{ marginTop: 10, fontFamily: "var(--mono)", fontSize: 11, color: "var(--grave-lit)" }}>{s.suppressionError}</div>
              )}
            </>
          ) : (
            <p className="aside">Select a finding to open its record.</p>
          )}
        </div>
      </div>
    </div>
  );
}

function NoReport({ onScan }: { onScan: () => void }) {
  return (
    <div style={{ padding: "38px 40px 60px" }}>
      <div className="col-head">III · The Register</div>
      <p className="aside" style={{ marginTop: 20, maxWidth: "48ch" }}>
        Nothing has been recorded yet. Set the watch, and Argus writes what it finds here — the risk score, every
        observation with its proof, and a way to reproduce it.
      </p>
      <button className="commit" style={{ marginTop: 22 }} onClick={onScan}>
        Set the watch <span className="arrow">→</span>
      </button>
    </div>
  );
}

function ChangeList({ label, color, items }: { label: string; color: string; items: ComparisonFinding[] }) {
  if (items.length === 0) return null;
  const shown = items.slice(0, 3);
  const extra = items.length - shown.length;
  return (
    <div>
      <span style={{ fontFamily: "var(--mono)", fontSize: 10, letterSpacing: "0.14em", textTransform: "uppercase", color }}>{label} ({items.length})</span>
      <ul style={{ margin: "6px 0 0", padding: 0, listStyle: "none" }}>
        {shown.map((f, i) => (
          <li key={i} style={{ fontFamily: FONT.body, fontSize: 13, color: "var(--bone-dim)", padding: "2px 0" }}>{f.title}</li>
        ))}
        {extra > 0 && <li style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--bone-dim-2)" }}>+{extra} more</li>}
      </ul>
    </div>
  );
}
