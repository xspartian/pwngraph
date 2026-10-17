import { useNavigate } from "react-router-dom";

import { api } from "../api/client";
import type { ScanReport } from "../api/types";
import { useResource } from "../api/useResource";
import { EmptyState, Spinner } from "../components/ui";
import { ReportFindings } from "../report/Findings";

/**
 * The Findings tab — just findings, nothing else. `ReportPage`'s /report
 * route still has its own findings section (part of the full scrolling
 * write-up), but that page opens on the risk-grade summary; this one exists
 * for "I just want the list," one click from the header instead of a scroll
 * down from the top of the report.
 *
 * Clicking a finding routes to the graph view with its attack chain focused
 * — see GraphExplorer's handling of the `finding` query param.
 */
export function FindingsPage({ scanId }: { scanId: string }) {
  const { data, error, loading } = useResource<ScanReport>(() => api.getReport(scanId), [scanId]);
  const navigate = useNavigate();

  if (loading) return <Spinner label="Loading findings…" />;
  if (error || !data) return <EmptyState title="Failed to load findings" detail={error} />;

  return (
    <ReportFindings
      scanId={scanId}
      report={data}
      onOpenChain={(findingId) =>
        navigate(`/scans/${encodeURIComponent(scanId)}?finding=${encodeURIComponent(findingId)}`)
      }
    />
  );
}
