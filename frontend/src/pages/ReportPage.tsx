import { Link, useNavigate } from "react-router-dom";

import { api, exportUrl } from "../api/client";
import type { ScanReport } from "../api/types";
import { useResource } from "../api/useResource";
import { EmptyState, Spinner } from "../components/ui";
import { ReportCompare } from "../report/Compare";
import { ReportEvidence } from "../report/Evidence";
import { ReportFindings } from "../report/Findings";
import { ReportQueries } from "../report/Queries";
import { ReportSummary } from "../report/Summary";

const SECTIONS = [
  { id: "summary", label: "Summary" },
  { id: "findings", label: "Findings" },
  { id: "evidence", label: "Evidence" },
  { id: "queries", label: "Queries" },
  { id: "compare", label: "Compare" },
];

/**
 * The whole report as one scrolling document — the in-app replacement for the
 * `report.html` PwnGraph used to write to disk. Sections are anchors rather
 * than tabs: a report is read top to bottom and shared by link, and tabs hide
 * two thirds of it behind a click.
 *
 * One fetch feeds both the summary and the findings list (they read the same
 * stored report); the evidence ladder is a separate endpoint and fetches its
 * own.
 */
export function ReportPage({ scanId }: { scanId: string }) {
  const { data, error, status, loading } = useResource<ScanReport>(
    () => api.getReport(scanId),
    [scanId],
  );
  const navigate = useNavigate();

  if (loading) return <Spinner label="Loading report…" />;
  if (status === 404) {
    return (
      <EmptyState
        title="No stored report for this scan"
        detail={
          <>
            This scan ran before PwnGraph started persisting reports, or its process ended early.
            The <Link to={`/scans/${encodeURIComponent(scanId)}`}>attack graph</Link> is still fully
            browsable — re-run the scan to generate a report.
          </>
        }
      />
    );
  }
  if (error || !data) return <EmptyState title="Failed to load report" detail={error} />;

  return (
    <div className="report-doc">
      <nav className="report-nav">
        {SECTIONS.map((s) => (
          <a key={s.id} href={`#${s.id}`} className="report-nav-link">
            {s.label}
          </a>
        ))}
        <span className="report-nav-spacer" />
        <a className="report-nav-link" href={exportUrl(scanId, "graph.json")}>
          ⭳ graph.json
        </a>
        <a className="report-nav-link" href={exportUrl(scanId, "findings.sarif")}>
          ⭳ SARIF
        </a>
        <a className="report-nav-link" href={exportUrl(scanId, "poc.zip")}>
          ⭳ PoC bundle
        </a>
      </nav>

      <section id="summary" className="report-section">
        <ReportSummary report={data} />
      </section>

      <section id="findings" className="report-section">
        <h2 className="report-section-title">
          Findings
          <span className="report-section-count">{data.findings.length}</span>
        </h2>
        <ReportFindings
          scanId={scanId}
          report={data}
          onOpenChain={(findingId) =>
            navigate(
              `/scans/${encodeURIComponent(scanId)}?finding=${encodeURIComponent(findingId)}`,
            )
          }
        />
      </section>

      <section id="evidence" className="report-section">
        <h2 className="report-section-title">Evidence ladder</h2>
        <ReportEvidence scanId={scanId} />
      </section>

      <section id="queries" className="report-section">
        <ReportQueries scanId={scanId} />
      </section>

      <section id="compare" className="report-section">
        <ReportCompare scanId={scanId} targetName={data.target_name} />
      </section>
    </div>
  );
}
