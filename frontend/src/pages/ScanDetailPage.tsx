import { Navigate, Route, Routes, useParams } from "react-router-dom";

import { GraphExplorer } from "../components/GraphExplorer";
import { FindingsPage } from "./FindingsPage";
import { LogsPage } from "./LogsPage";
import { ProfilePage } from "./ProfilePage";
import { ReportPage } from "./ReportPage";

/**
 * A scan's 5 tabs. The shell (top bar, sidebar with the tab nav + scan
 * identity card) is owned by AppShell/Sidebar now — this component is just
 * the routing for what renders in <main> for a given tab. See
 * components/AppShell.tsx for the layout route this mounts under.
 */
export function ScanDetailPage() {
  const { scanId } = useParams<{ scanId: string }>();
  if (!scanId) return <div className="pg-status pg-error">No scan id in the URL.</div>;

  const base = `/scans/${encodeURIComponent(scanId)}`;

  return (
    <Routes>
      <Route index element={<GraphExplorer scanId={scanId} />} />
      <Route path="profile" element={<ProfilePage scanId={scanId} />} />
      <Route path="findings" element={<FindingsPage scanId={scanId} />} />
      <Route path="report" element={<ReportPage scanId={scanId} />} />
      <Route path="logs" element={<LogsPage scanId={scanId} />} />
      {/* The report used to be three separate tabs; keep those links alive. */}
      <Route path="graph" element={<Navigate to={base} replace />} />
      <Route path="overview" element={<Navigate to={`${base}/report`} replace />} />
      <Route path="evidence" element={<Navigate to={`${base}/report`} replace />} />
    </Routes>
  );
}
