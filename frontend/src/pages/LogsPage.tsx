import { ReportLogs } from "../report/Logs";

/**
 * The Logs tab — the raw execution log (every probe, in the order it ran)
 * with NEXUS's own reasoning layered on top when this scan ran in adaptive
 * mode. See report/Logs.tsx; this wrapper exists only to match the
 * FindingsPage/ReportPage routing pattern in ScanDetailPage.
 */
export function LogsPage({ scanId }: { scanId: string }) {
  return <ReportLogs scanId={scanId} />;
}
