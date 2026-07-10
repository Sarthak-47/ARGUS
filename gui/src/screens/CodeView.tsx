import { RF, FONT, sevColor } from "../theme";
import { useStore } from "../store";
import { ScreenHeader, EyeGlyph } from "../components/Panoptes";

export function CodeView() {
  const s = useStore();
  const allFindings = s.report?.findings ?? [];
  const finding = allFindings.find((f) => f.id === s.selectedId) || null;

  return (
    <section>
      <ScreenHeader
        title="In the code"
        subtitle={finding ? finding.name : "the line that caught it"}
        action={
          <button
            onClick={() => s.setScreen("report")}
            style={{ fontFamily: FONT.display, fontSize: 11, letterSpacing: "0.16em", textTransform: "uppercase", color: RF.clayHi, background: "transparent", border: `1px solid ${RF.dilute}`, padding: "10px 16px", cursor: "pointer" }}
          >
            &#8592; Back to report
          </button>
        }
      />

      <div style={{ padding: "24px 34px 64px" }}>
        {!finding && (
          <Empty>No finding selected — go back to the report and open one with a file location.</Empty>
        )}

        {finding && (
          <>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 6 }}>
              <EyeGlyph wounded tone={sevColor(finding.severity)} w={28} h={18} />
              <span style={{ fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.16em", textTransform: "uppercase", color: sevColor(finding.severity) }}>{finding.severity}</span>
              <span style={{ fontFamily: FONT.code, fontSize: 12.5, color: RF.parchment }}>
                {finding.file || finding.endpoint}{finding.line ? `:${finding.line}` : ""}
              </span>
            </div>

            {s.codeLoading && <Empty>Reading source…</Empty>}
            {!s.codeLoading && s.codeError && <Empty>{s.codeError}</Empty>}
            {!s.codeLoading && !s.codeError && s.codeSnippet && (
              <div style={{ border: `1px solid ${RF.diluteLo}`, background: RF.glazeLo, overflow: "hidden", marginTop: 14 }}>
                {s.codeSnippet.lines.map((text, i) => {
                  const lineNo = s.codeSnippet!.startLine + i;
                  const isTarget = lineNo === finding.line;
                  return (
                    <div
                      key={lineNo}
                      style={{
                        display: "flex", fontFamily: FONT.code, fontSize: 13, lineHeight: 1.75,
                        background: isTarget ? "rgba(165,56,42,0.16)" : "transparent",
                        borderLeft: `3px solid ${isTarget ? RF.oxbloodHi : "transparent"}`,
                      }}
                    >
                      <span style={{ width: 52, flex: "0 0 auto", textAlign: "right", paddingRight: 14, color: isTarget ? RF.oxbloodHi : RF.diluteLo, userSelect: "none" }}>
                        {lineNo}
                      </span>
                      <span style={{ whiteSpace: "pre", color: isTarget ? RF.ivory : RF.dust, paddingRight: 20 }}>
                        {text || " "}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}

            {finding.fix && !s.codeLoading && !s.codeError && (
              <div style={{ marginTop: 22 }}>
                <div style={{ fontFamily: FONT.display, fontSize: 10, letterSpacing: "0.2em", textTransform: "uppercase", color: RF.dust, marginBottom: 8 }}>The fix</div>
                <div style={{ fontFamily: FONT.body, fontSize: 16, lineHeight: 1.55, color: RF.parchment, maxWidth: "70ch" }}>{finding.fix}</div>
              </div>
            )}
          </>
        )}
      </div>
    </section>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ fontFamily: FONT.body, fontStyle: "italic", fontSize: 15, color: RF.dust, padding: "60px 0", textAlign: "center" }}>
      {children}
    </div>
  );
}
