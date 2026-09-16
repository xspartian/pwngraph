import { ReportProfile } from "../report/Profile";

/**
 * The Profile tab — recon's pre-attack findings for this scan. See
 * report/Profile.tsx; this wrapper exists only to match the
 * FindingsPage/ReportPage/LogsPage routing pattern in ScanDetailPage.
 */
export function ProfilePage({ scanId }: { scanId: string }) {
  return <ReportProfile scanId={scanId} />;
}
