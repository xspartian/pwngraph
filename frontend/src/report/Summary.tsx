import type { AsrBucket, ScanReport } from "../api/types";
import { AsrBar, SeverityBadge, Section, StatTile } from "../components/ui";
import { GRADE_COLORS, SEVERITY_COLORS, SEVERITY_ORDER } from "../theme/colors";

const OWASP_STATUS_STYLE: Record<string, string> = {
  detected: "owasp-detected",
  tested: "owasp-tested",
  partial: "owasp-partial",
  "out-of-scope": "owasp-oos",
};

/** The verdict half of the report: grade, headline numbers, ASR, OWASP
 * coverage and tool surface. The findings themselves follow it in the
 * document, so this deliberately stops at the summary. */
export function ReportSummary({ report: data }: { report: ScanReport }) {
  const grade = data.risk_grade ?? {};
  const gradeLetter = grade.grade ?? "?";
  const gradeColor = GRADE_COLORS[gradeLetter] ?? "#6b7785";
  const overall = data.asr?.overall;
  const byClass = Object.entries(data.asr?.by_class ?? {}).sort(
    (a, b) => (b[1]?.asr ?? 0) - (a[1]?.asr ?? 0),
  );
  const sevCounts = countBySeverity(data);
  const detectedOwasp = data.owasp_coverage.filter((r) => r.status === "detected").length;
  const testableOwasp = data.owasp_coverage.filter((r) => r.status !== "out-of-scope").length;

  return (
    <div className="page-body">
      {/* Hero — the single verdict, then the numbers behind it. */}
      <div className="verdict-card">
        <div className="verdict-grade" style={{ borderColor: gradeColor, color: gradeColor }}>
          <span className="verdict-letter">{gradeLetter}</span>
          <span className="verdict-scale">risk grade</span>
        </div>
        <div className="verdict-body">
          <div className="verdict-headline">{grade.interpretation ?? "No interpretation."}</div>
          <div className="verdict-score-row">
            <div className="verdict-score-track">
              <div
                className="verdict-score-fill"
                style={{
                  width: `${Math.min(100, grade.score ?? 0)}%`,
                  background: gradeColor,
                }}
              />
            </div>
            <span className="verdict-score-text">
              {grade.score ?? 0}
              <span className="muted"> / {grade.max_score ?? 100}</span>
            </span>
          </div>
          <div className="verdict-meta">
            <span>
              target <strong>{data.target_name || "unknown"}</strong>
            </span>
            <span>
              {data.tool_inventory.length} tool{data.tool_inventory.length === 1 ? "" : "s"}
            </span>
            {data.scanned_at && <span>{formatDate(data.scanned_at)}</span>}
          </div>
        </div>
      </div>

      <div className="stat-row">
        <StatTile
          label="Findings"
          value={data.findings.length}
          sub={
            data.findings.length > 0 ? <a href="#findings">see all below ↓</a> : "none confirmed"
          }
        />
        <StatTile
          label="Max severity"
          value={
            data.findings.length ? (
              <SeverityBadge severity={maxSeverity(data)} />
            ) : (
              <span className="muted">—</span>
            )
          }
        />
        <StatTile
          label="Attack success rate"
          value={overall ? `${Math.round(overall.asr * 100)}%` : "—"}
          sub={
            overall
              ? `95% CI ${pct(overall.wilson_low)}–${pct(overall.wilson_high)} · ${overall.successes}/${overall.trials} trials`
              : undefined
          }
        />
        <StatTile
          label="OWASP detected"
          value={detectedOwasp}
          sub={`of ${testableOwasp} testable categories`}
        />
      </div>

      {/* Severity distribution — a status-coloured magnitude bar per bucket. */}
      {data.findings.length > 0 && (
        <Section title="Severity distribution" hint="Confirmed findings, by CVSS-aligned bucket.">
          <div className="sev-dist">
            {SEVERITY_ORDER.filter((s) => sevCounts[s]).map((s) => {
              const share = sevCounts[s] / data.findings.length;
              return (
                <div className="sev-row" key={s}>
                  <div className="sev-row-label">
                    <SeverityBadge severity={s} />
                  </div>
                  <div className="sev-row-bar">
                    <div
                      className="sev-row-fill"
                      style={{ width: `${share * 100}%`, background: SEVERITY_COLORS[s] }}
                    />
                  </div>
                  <div className="sev-row-count">{sevCounts[s]}</div>
                </div>
              );
            })}
          </div>
        </Section>
      )}

      {/* ASR by attack class — magnitude across categories, with the interval. */}
      {byClass.length > 0 && (
        <Section
          title="Attack success rate by class"
          hint="Bars show the observed rate; the lighter span is the Wilson 95% confidence interval — a wide span means too few trials to be precise, not a precise middling result."
        >
          <table className="data-table asr-table">
            <thead>
              <tr>
                <th>Attack class</th>
                <th className="num">ASR</th>
                <th className="bar-col">Rate &amp; 95% CI</th>
                <th className="num">succ / trials</th>
                <th>Max severity</th>
              </tr>
            </thead>
            <tbody>
              {byClass.map(([cls, b]) => (
                <tr key={cls}>
                  <td className="mono">{cls.replace(/_/g, " ")}</td>
                  <td className="num strong">{Math.round((b?.asr ?? 0) * 100)}%</td>
                  <td className="bar-col">
                    <AsrBar
                      value={b?.asr ?? 0}
                      low={b?.wilson_low}
                      high={b?.wilson_high}
                      color={SEVERITY_COLORS[b?.max_severity ?? "info"] ?? "#3987e5"}
                    />
                  </td>
                  <td className="num muted">
                    {b?.successes ?? 0} / {b?.trials ?? 0}
                  </td>
                  <td>
                    <SeverityBadge severity={b?.max_severity ?? "info"} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      )}

      {/* OWASP coverage — a state matrix, so status colour + the word both show. */}
      {data.owasp_coverage.length > 0 && (
        <Section
          title="OWASP LLM Top 10 (2025) coverage"
          hint="Out-of-scope categories are marked honestly rather than silently passed — a runtime fuzzer cannot test supply-chain or training-time risks."
        >
          <div className="owasp-grid">
            {data.owasp_coverage.map((row) => (
              <div key={row.id} className={`owasp-cell ${OWASP_STATUS_STYLE[row.status] ?? ""}`}>
                <div className="owasp-id">{row.id}</div>
                <div className="owasp-name">{row.name}</div>
                <div className="owasp-status">
                  {row.status === "detected" ? `detected (${row.count ?? 0})` : row.status}
                </div>
              </div>
            ))}
          </div>
        </Section>
      )}

      {data.tool_inventory.length > 0 && (
        <Section title="Tool surface" hint="Every tool PwnGraph could reach on this target.">
          <div className="chip-row">
            {data.tool_inventory.map((t) => (
              <span className="chip mono" key={t}>
                {t}
              </span>
            ))}
          </div>
        </Section>
      )}
    </div>
  );
}

function pct(v: number | undefined): string {
  return `${Math.round((v ?? 0) * 100)}%`;
}

function countBySeverity(report: ScanReport): Record<string, number> {
  const counts: Record<string, number> = {};
  report.findings.forEach((f) => {
    const s = (f.severity || "info").toLowerCase();
    counts[s] = (counts[s] ?? 0) + 1;
  });
  return counts;
}

function maxSeverity(report: ScanReport): string {
  for (const s of SEVERITY_ORDER) {
    if (report.findings.some((f) => (f.severity || "").toLowerCase() === s)) return s;
  }
  return "info";
}

function formatDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export type { AsrBucket };
