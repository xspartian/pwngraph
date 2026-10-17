import {
  FileText,
  Home,
  ListChecks,
  ScrollText,
  ShieldAlert,
  Waypoints,
} from "lucide-react";
import { NavLink } from "react-router-dom";

import { api } from "../api/client";
import type { ScanReport } from "../api/types";
import { useResource } from "../api/useResource";
import { SeverityBadge } from "./ui";
import { GRADE_COLORS } from "../theme/colors";

const SCAN_TABS = [
  { to: "profile", label: "Profile", icon: ShieldAlert },
  { to: "", label: "Attack graph", icon: Waypoints, end: true },
  { to: "findings", label: "Findings", icon: ListChecks },
  { to: "logs", label: "Logs", icon: ScrollText },
  { to: "report", label: "Report", icon: FileText },
];

/**
 * The persistent left nav. Contextual: a bare global entry when browsing
 * the scan list, or the current scan's identity + its 5 tabs (replacing the
 * old top tab-bar) when inside a scan — see AppShell for how scanId flows in.
 */
export function Sidebar({ scanId }: { scanId: string | null }) {
  return (
    <nav className="sidebar">
      <NavLink
        to="/"
        end
        className={({ isActive }) => `sidebar-link ${isActive && !scanId ? "active" : ""}`}
      >
        <Home size={16} />
        All scans
      </NavLink>

      {scanId && (
        <>
          <div className="sidebar-divider" />
          <ScanContext scanId={scanId} />
          <div className="sidebar-tabs">
            {SCAN_TABS.map((tab) => (
              <NavLink
                key={tab.to}
                to={tab.to ? `/scans/${encodeURIComponent(scanId)}/${tab.to}` : `/scans/${encodeURIComponent(scanId)}`}
                end={tab.end}
                className={({ isActive }) => `sidebar-link ${isActive ? "active" : ""}`}
              >
                <tab.icon size={16} />
                {tab.label}
              </NavLink>
            ))}
          </div>
        </>
      )}
    </nav>
  );
}

function ScanContext({ scanId }: { scanId: string }) {
  const { data: report } = useResource<ScanReport>(() => api.getReport(scanId), [scanId]);
  const grade = report?.risk_grade?.grade;

  return (
    <div className="sidebar-context">
      <div className="sidebar-context-target">{report?.target_name || "scan"}</div>
      <div className="sidebar-context-id mono">{scanId}</div>
      {report && (
        <div className="sidebar-context-badges">
          {grade && (
            <span
              className="sidebar-context-grade"
              style={{ borderColor: GRADE_COLORS[grade], color: GRADE_COLORS[grade] }}
            >
              {grade}
            </span>
          )}
          {report.findings.length > 0 && <SeverityBadge severity={maxSeverity(report)} />}
          <span className="muted">
            {report.findings.length} finding{report.findings.length === 1 ? "" : "s"}
          </span>
        </div>
      )}
    </div>
  );
}

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

function maxSeverity(report: ScanReport): string {
  for (const s of SEV_ORDER) {
    if (report.findings.some((f) => (f.severity || "").toLowerCase() === s)) return s;
  }
  return "info";
}
