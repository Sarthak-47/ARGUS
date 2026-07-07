import { C, FONT, sevColor } from "../theme";
import { useStore } from "../store";

export function CodeView() {
  const s = useStore();
  const allFindings = s.report?.findings ?? [];
  const finding = allFindings.find((f) => f.id === s.selectedId) || null;

  return (
    <section style={{ padding: "28px 42px 64px 42px", height: "100%", overflowY: "auto" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 28 }}>
        <div style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.22em", color: C.stoneText }}>
          ARGUS <span style={{ color: C.relief }}>/</span> <span style={{ color: C.goldenrod }}>CODE VIEW</span>
        </div>
        <button
          onClick={() => s.setScreen("report")}
          style={{ fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.18em", color: C.bronze, background: "transparent", border: `1px solid ${C.relief}`, padding: "10px 20px", cursor: "pointer" }}
        >
          ← BACK TO REPORT
        </button>
      </div>

      {!finding && (
        <Empty>No finding selected — go back to the report and click a finding with a file location.</Empty>
      )}

      {finding && (
        <>
          <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 4 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, background: sevColor(finding.severity), flex: "0 0 auto" }} />
            <span style={{ fontFamily: FONT.display, fontSize: 17, letterSpacing: "0.04em", color: C.goldPale }}>{finding.name}</span>
          </div>
          <div style={{ fontFamily: FONT.code, fontSize: 13, color: C.bronze, marginBottom: 26 }}>
            {finding.file || finding.endpoint}{finding.line ? `:${finding.line}` : ""}
          </div>

          {s.codeLoading && <Empty>Reading source…</Empty>}
          {!s.codeLoading && s.codeError && <Empty>{s.codeError}</Empty>}
          {!s.codeLoading && !s.codeError && s.codeSnippet && (
            <div style={{ border: `1px solid ${C.relief}`, background: C.obsidian, overflow: "hidden" }}>
              {s.codeSnippet.lines.map((text, i) => {
                const lineNo = s.codeSnippet!.startLine + i;
                const isTarget = lineNo === finding.line;
                return (
                  <div
                    key={lineNo}
                    style={{
                      display: "flex", fontFamily: FONT.code, fontSize: 13, lineHeight: 1.7,
                      background: isTarget ? "rgba(139,0,0,0.18)" : "transparent",
                      borderLeft: `3px solid ${isTarget ? C.crimson : "transparent"}`,
                    }}
                  >
                    <span style={{ width: 52, flex: "0 0 auto", textAlign: "right", paddingRight: 14, color: isTarget ? C.crimson : C.weathered, userSelect: "none" }}>
                      {lineNo}
                    </span>
                    <span style={{ whiteSpace: "pre", color: isTarget ? C.parchment : C.stoneText, paddingRight: 20 }}>
                      {text || " "}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </>
      )}
    </section>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 15, color: C.stoneText, padding: "60px 0", textAlign: "center" }}>
      {children}
    </div>
  );
}
