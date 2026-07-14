import { C, RF, FONT, sevColor, bandColor, bandLabel } from "../theme";
import { useStore } from "../store";
import { EyeGlyph, EyeField, TerracottaMark, ScreenHeader } from "../components/Panoptes";
import type { ComparisonFinding } from "../adapter";

const SEV_NAME: Record<string, string> = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low", INFO: "Info" };

// A field is worth showing only if it carries real content — static findings
// have no HTTP response or reproduction, so those sections should stay hidden
// rather than render an empty box.
const hasText = (v?: string | null): boolean =>
  !!v && v.trim().length > 0 && v.trim() !== "—" && v.trim().toLowerCase() !== "n/a";

export function Reports() {
  const s = useStore();
  const live = s.report;
  if (!live) return <NoReport onScan={() => s.setScreen("scan")} />;
  const allFindings = live.findings.filter((f) => !s.suppressedIds.has(f.id));
  const target = live.target;

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 } as Record<string, number>;
  allFindings.forEach((f) => (counts[f.severity] = (counts[f.severity] || 0) + 1));
  const filtered = s.filter === "All" ? allFindings : allFindings.filter((f) => f.severity === s.filter.toUpperCase());
  const sel = allFindings.find((f) => f.id === s.selectedId) || null;
  const mortal = counts.CRITICAL || 0;

  return (
    <section style={{ display: "flex", height: "100%", minHeight: 0, position: "relative", overflow: "hidden" }}>
      <div style={{ flex: 1, minWidth: 0, overflowY: "auto" }}>
        <ScreenHeader
          title="Report"
          subtitle={target}
          action={
            <button style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.16em", textTransform: "uppercase", color: RF.clayHi, background: "transparent", border: `1px solid ${RF.dilute}`, padding: "10px 16px", cursor: "pointer" }}>
              Export report
            </button>
          }
        />

        {/* verdict body: tondo + counts */}
        <div style={{ display: "grid", gridTemplateColumns: "340px 1fr" }}>
          <div style={{ padding: "22px 26px 26px 30px", borderRight: `1px solid ${RF.diluteLo}` }}>
            <div style={{ width: 260, height: 260, position: "relative" }}>
              <div style={{ position: "absolute", inset: 0, borderRadius: "50%", background: RF.glazeLo, boxShadow: `0 0 0 2px ${RF.dilute}, inset 0 0 0 9px ${RF.clayLo}` }} />
              <TerracottaMark size={172} style={{ position: "absolute", left: 44, top: 44 }} />
            </div>
            <div style={{ marginTop: 22 }}>
              <div style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.3em", textTransform: "uppercase", color: RF.dust }}>Risk score</div>
              <div style={{ fontFamily: FONT.display, fontWeight: 700, fontSize: 66, lineHeight: 0.9, color: bandColor(live.riskScore) }}>
                {live.riskScore}<span style={{ fontSize: 20, color: RF.diluteLo }}> / 100</span>
              </div>
              <div style={{ fontFamily: FONT.display, fontSize: 13, letterSpacing: "0.34em", textTransform: "uppercase", color: bandColor(live.riskScore), marginTop: 4 }}>
                {live.band || bandLabel(live.riskScore)}
              </div>
            </div>
          </div>

          <div style={{ padding: "22px 30px 24px" }}>
            <div style={{ fontFamily: FONT.display, fontSize: 10.5, letterSpacing: "0.2em", textTransform: "uppercase", color: RF.dust, marginBottom: 16 }}>
              Findings by severity
            </div>
            <div style={{ display: "flex", gap: 34, marginBottom: 22 }}>
              {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((lbl) => (
                <div key={lbl} style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
                    <span style={{ width: 12, height: 12, borderRadius: "50%", background: sevColor(lbl) }} />
                    <span style={{ fontFamily: FONT.display, fontSize: 30, fontWeight: 700, color: sevColor(lbl), lineHeight: 0.8 }}>{counts[lbl] || 0}</span>
                  </div>
                  <span style={{ fontFamily: FONT.display, fontSize: 9.5, letterSpacing: "0.16em", textTransform: "uppercase", color: RF.dust }}>{SEV_NAME[lbl]}</span>
                </div>
              ))}
            </div>
            <p style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 16, color: RF.dust, margin: 0, maxWidth: "44ch" }}>
              Argus opened {allFindings.length} eye{allFindings.length === 1 ? "" : "s"} on this target
              {mortal > 0 ? ` — ${mortal} of them critical.` : "."}
            </p>

            {s.comparison && (
              <div style={{ marginTop: 20, paddingTop: 18, borderTop: `1px solid rgba(125,79,40,0.3)` }}>
                {s.comparison.new_findings.length === 0 && s.comparison.fixed_findings.length === 0 ? (
                  <p style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 13, color: C.stoneText, margin: 0 }}>
                    No change since the last scan of this target
                    {s.comparison.unchanged_count > 0 ? ` — ${s.comparison.unchanged_count} finding${s.comparison.unchanged_count === 1 ? "" : "s"} carried over.` : "."}
                  </p>
                ) : (
                  <>
                    <div style={{ display: "flex", gap: 34 }}>
                      <ChangeList label="Newly opened" color={C.crimson} items={s.comparison.new_findings} />
                      <ChangeList label="Closed since" color="#6f9e57" items={s.comparison.fixed_findings} />
                    </div>
                    {s.comparison.unchanged_count > 0 && (
                      <p style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 12, color: C.stoneText, margin: "10px 0 0" }}>
                        {s.comparison.unchanged_count} other finding{s.comparison.unchanged_count === 1 ? "" : "s"} unchanged.
                      </p>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
        </div>

        {/* the hundred eyes — hover names the wound */}
        <div style={{ padding: "16px 30px 22px", borderTop: `1px solid ${RF.diluteLo}` }}>
          <div style={{ fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.18em", textTransform: "uppercase", color: RF.dust, marginBottom: 12 }}>
            The checks Argus ran — <span style={{ color: RF.clay }}>red caught something, tan came back clean · hover any eye</span>
          </div>
          <EyeField findings={allFindings} onSelect={(id) => s.select(id)} />
        </div>

        {/* filter + the catalogue of wounds */}
        <div style={{ padding: "6px 30px 60px" }}>
          <div style={{ display: "flex", gap: 8, margin: "6px 0 14px" }}>
            {["All", "Critical", "High", "Medium", "Low"].map((t) => {
              const on = s.filter === t;
              return (
                <button key={t} onClick={() => s.setFilter(t)} style={{
                  fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.14em", textTransform: "uppercase", padding: "9px 16px", cursor: "pointer",
                  background: on ? `linear-gradient(180deg, ${RF.clayHi}, ${RF.clay})` : "transparent",
                  border: `1px solid ${on ? RF.clay : RF.diluteLo}`, color: on ? RF.glaze : RF.dust,
                }}>{t}</button>
              );
            })}
          </div>

          <div style={{ display: "flex", flexDirection: "column" }}>
            {filtered.map((f) => {
              const isSel = s.selectedId === f.id;
              return (
                <button key={f.id} className="row-hover" onClick={() => s.select(f.id)} style={{
                  display: "grid", gridTemplateColumns: "34px 1fr 190px 130px", alignItems: "center", gap: 16, width: "100%", textAlign: "left", cursor: "pointer",
                  padding: "14px 8px", border: "none", borderBottom: `1px solid rgba(125,79,40,0.26)`,
                  borderLeft: `3px solid ${isSel ? RF.clay : "transparent"}`, background: isSel ? RF.ember : "transparent",
                }}>
                  <span style={{ display: "inline-flex", lineHeight: 0 }}><EyeGlyph wounded tone={sevColor(f.severity)} w={30} h={19} /></span>
                  <span style={{ fontFamily: FONT.body, fontSize: 19, color: RF.ivory, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "flex", alignItems: "center", gap: 8 }}>
                    {f.chainOf ? <span title={`Bound into a chain of ${f.chainOf} findings`} style={{ color: C.crimson, flex: "0 0 auto" }}>⛓</span> : null}
                    {f.name}
                  </span>
                  <span style={{ fontFamily: FONT.code, fontSize: 11.5, color: RF.dust, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.endpoint}</span>
                  <span style={{ fontFamily: FONT.display, fontSize: 9.5, letterSpacing: "0.14em", textTransform: "uppercase", textAlign: "right", color: sevColor(f.severity) }}>
                    {SEV_NAME[f.severity]}
                    <span style={{ display: "block", fontSize: 8.5, letterSpacing: "0.08em", color: RF.diluteLo, marginTop: 3 }}>found by {f.agent}</span>
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* detail panel (unchanged behaviour, palette carries the reskin) */}
      <div style={{
        position: "absolute", top: 0, right: 0, bottom: 0, width: 448, background: RF.glazeLo, borderLeft: `1px solid ${RF.diluteLo}`,
        transform: sel ? "translateX(0)" : "translateX(100%)", transition: "transform 0.18s ease-out", zIndex: 5,
      }}>
        {sel && (
          <div style={{ display: "flex", flexDirection: "column", height: "100%", minHeight: 0 }}>
            <div style={{ padding: "24px 26px", borderBottom: `1px solid ${C.relief}`, flex: "0 0 auto" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
                <span style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <EyeGlyph wounded tone={sevColor(sel.severity)} w={26} h={16} />
                  <span style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.18em", textTransform: "uppercase", color: sevColor(sel.severity) }}>{SEV_NAME[sel.severity]}</span>
                </span>
                <button onClick={() => s.select(null)} style={{ background: "none", border: "none", color: C.stoneText, fontSize: 18, cursor: "pointer", lineHeight: 1 }}>✕</button>
              </div>
              <div style={{ fontFamily: FONT.display, fontSize: 17, letterSpacing: "0.04em", color: C.goldPale, marginBottom: 10 }}>{sel.name}</div>
              {sel.chainOf ? (
                <div style={{ fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.14em", color: C.crimson, border: `1px solid ${C.crimson}`, background: "rgba(165,56,42,0.14)", padding: "6px 10px", marginBottom: 10, display: "inline-flex", alignItems: "center", gap: 8 }}>
                  <span>⛓</span> ATTACK CHAIN — COMPOUNDS {sel.chainOf} FINDINGS
                </div>
              ) : null}
              <span style={{ fontFamily: FONT.code, fontSize: 12, color: C.bronze }}>{sel.endpoint}</span>
              <div style={{ display: "flex", gap: 20, marginTop: 14, fontFamily: FONT.body, fontStyle: "italic", fontSize: 14, color: C.stoneText }}>
                <span>Found by <span style={{ fontStyle: "normal", color: C.bronze, fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.06em" }}>{sel.agent}</span></span>
                {sel.cvss && String(sel.cvss).trim() && String(sel.cvss).trim() !== "—" && (
                  <span>CVSS <span style={{ fontStyle: "normal", color: sevColor(sel.severity), fontFamily: FONT.code }}>{sel.cvss}</span></span>
                )}
              </div>
              {sel.compliance && (
                <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap" }}>
                  {[sel.compliance.asvs, sel.compliance.pci_dss].map((tag) => (
                    <span key={tag} style={{ fontFamily: FONT.code, fontSize: 10, color: C.goldPale, background: C.ember, border: `1px solid ${C.relief}`, padding: "4px 9px", letterSpacing: "0.04em" }}>{tag}</span>
                  ))}
                </div>
              )}
              <div style={{ display: "flex", gap: 10, marginTop: 16 }}>
                {sel.file && sel.line != null && (
                  <button onClick={() => s.openCodeView(sel.file!, sel.line!)} style={{ fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.16em", color: C.bronze, background: "transparent", border: `1px solid ${C.bronze}`, padding: "9px 16px", cursor: "pointer" }}>
                    VIEW IN CODE
                  </button>
                )}
                {s.isDesktop && (
                  <button onClick={() => s.suppressFinding(sel.id, sel.name, "ignored", "dismissed from Reports")} style={{ fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.16em", color: C.stoneText, background: "transparent", border: `1px solid ${C.relief}`, padding: "9px 16px", cursor: "pointer" }}>
                    IGNORE
                  </button>
                )}
              </div>
              {s.suppressionError && (
                <div style={{ marginTop: 10, fontFamily: FONT.body, fontStyle: "italic", fontSize: 12, color: C.crimson }}>{s.suppressionError}</div>
              )}
            </div>
            <div style={{ overflowY: "auto", flex: 1, minHeight: 0, padding: "4px 0" }}>
              {sel.whatIs && sel.whatIs.trim() && (
                <Section title="WHAT IS IT"><div style={{ fontFamily: FONT.body, fontSize: 16, lineHeight: 1.55, color: C.parchment }}>{sel.whatIs}</div></Section>
              )}
              {(hasText(sel.request) || hasText(sel.response)) && (
                <Section title="EVIDENCE">
                  {hasText(sel.request) && (<>
                    <SubCap color={C.goldenrod}>{hasText(sel.response) ? "REQUEST" : "CODE"}</SubCap>
                    <Pre>{sel.request}</Pre>
                  </>)}
                  {hasText(sel.response) && (<>
                    {hasText(sel.request) && <div style={{ height: 12 }} />}
                    <SubCap color={C.crimson}>RESPONSE</SubCap>
                    <Pre>{sel.response}</Pre>
                  </>)}
                </Section>
              )}
              {hasText(sel.repro) && (
                <Section title="REPRODUCTION"><div style={{ fontFamily: FONT.code, fontSize: 12, lineHeight: 1.7, color: C.parchment, whiteSpace: "pre-wrap" }}>{sel.repro}</div></Section>
              )}
              {hasText(sel.fix) && (
                <Section title="FIX" last><Pre>{sel.fix}</Pre></Section>
              )}
            </div>
          </div>
        )}
      </div>
    </section>
  );
}

function NoReport({ onScan }: { onScan: () => void }) {
  return (
    <section style={{ height: "100%", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 24, padding: 40 }}>
      <TerracottaMark size={72} color={RF.dilute} />
      <div style={{ fontFamily: FONT.display, fontSize: 13, letterSpacing: "0.22em", textTransform: "uppercase", color: C.goldPale }}>No report yet</div>
      <div style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 15, color: C.stoneText, maxWidth: 420, textAlign: "center", lineHeight: 1.6 }}>
        Run a scan and Argus renders its findings here — the risk score, every vulnerability with its proof, and a reproducible exploit.
      </div>
      <button onClick={onScan} style={{ fontFamily: FONT.display, fontSize: 12, letterSpacing: "0.18em", textTransform: "uppercase", color: C.goldenrod, background: "transparent", border: `1px solid ${C.bronze}`, padding: "12px 24px", cursor: "pointer" }}>
        New scan
      </button>
    </section>
  );
}

function Section({ title, children, last }: { title: string; children: React.ReactNode; last?: boolean }) {
  return (
    <div style={{ padding: "20px 26px", borderBottom: last ? "none" : `1px solid rgba(125,79,40,0.22)` }}>
      <div style={{ fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.22em", color: C.stoneText, marginBottom: 10 }}>{title}</div>
      {children}
    </div>
  );
}
function SubCap({ children, color }: { children: React.ReactNode; color: string }) {
  return <div style={{ fontFamily: FONT.display, fontSize: 9, letterSpacing: "0.18em", color, marginBottom: 6 }}>{children}</div>;
}
function ChangeList({ label, color, items }: { label: string; color: string; items: ComparisonFinding[] }) {
  if (items.length === 0) {
    return (
      <div style={{ flex: 1, fontFamily: FONT.body, fontStyle: "italic", fontSize: 13, color: C.stoneText }}>
        <span style={{ fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.14em", textTransform: "uppercase", color: C.stoneText, marginRight: 8 }}>{label}</span>none
      </div>
    );
  }
  const shown = items.slice(0, 3);
  const extra = items.length - shown.length;
  return (
    <div style={{ flex: 1 }}>
      <span style={{ fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.14em", textTransform: "uppercase", color }}>{label} ({items.length})</span>
      <ul style={{ margin: "6px 0 0", padding: 0, listStyle: "none", display: "flex", flexDirection: "column", gap: 4 }}>
        {shown.map((f, i) => (
          <li key={i} style={{ display: "flex", alignItems: "center", gap: 7, fontFamily: FONT.body, fontSize: 13, color: C.parchment, overflow: "hidden" }}>
            <span style={{ flex: "0 0 auto", width: 7, height: 7, borderRadius: "50%", background: sevColor(f.severity) }} />
            <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.title}</span>
          </li>
        ))}
        {extra > 0 && <li style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 12, color: C.stoneText, marginLeft: 14 }}>+{extra} more</li>}
      </ul>
    </div>
  );
}
function Pre({ children }: { children: React.ReactNode }) {
  return (
    <pre style={{ margin: 0, background: C.obsidian, border: `1px solid ${C.relief}`, padding: "12px 14px", fontFamily: FONT.code, fontSize: 11.5, color: C.parchment, whiteSpace: "pre-wrap", wordBreak: "break-word", lineHeight: 1.5 }}>{children}</pre>
  );
}
