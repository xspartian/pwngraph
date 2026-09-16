import { useMemo, useState } from "react";
import { Link } from "react-router-dom";

import { api } from "../api/client";
import type { ScanSummary } from "../api/types";
import { useResource } from "../api/useResource";
import { EmptyState, SeverityBadge, Spinner } from "../components/ui";
import { GRADE_COLORS } from "../theme/colors";

// How many cards render before "Show more" — enough to fill a screen or two
// without paying for hundreds of DOM nodes up front on a database that's
// been scanning the same target daily for months.
const PAGE_SIZE = 24;

export function ScanListPage() {
  const { data: scans, error, loading } = useResource<ScanSummary[]>(() => api.listScans(), []);
  const [query, setQuery] = useState("");
  const [visible, setVisible] = useState(PAGE_SIZE);

  const filtered = useMemo(() => {
    const all = scans ?? [];
    const needle = query.trim().toLowerCase();
    if (!needle) return all;
    return all.filter((s) =>
      `${s.target_name ?? ""} ${s.target_id ?? ""} ${s.scan_id}`.toLowerCase().includes(needle),
    );
  }, [scans, query]);

  const shown = filtered.slice(0, visible);

  return (
    <div className="page">
      <header className="page-head">
        <h1 className="page-head-title">All scans</h1>
        <p className="page-head-sub">
          Read live from Neo4j, the same database every <code>pwngraph scan</code> writes to.
        </p>
      </header>

      {loading && <Spinner label="Loading scans…" />}
      {error && <EmptyState title="Could not reach the API" detail={error} />}
      {scans && scans.length === 0 && (
        <EmptyState
          title="No scans in this database yet"
          detail={
            <>
              Run one first: <code>pwngraph scan --target adapter.py:build_agent</code>
            </>
          }
        />
      )}

      {scans && scans.length > 0 && (
        <>
          <div className="scan-list-toolbar">
            <input
              className="pwn-search wide"
              placeholder="Search by target or scan id…"
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setVisible(PAGE_SIZE);
              }}
            />
            <span className="graph-stats mono">
              {filtered.length} of {scans.length} scan{scans.length === 1 ? "" : "s"}
            </span>
          </div>

          {filtered.length === 0 ? (
            <EmptyState title={`Nothing matches “${query.trim()}”`} />
          ) : (
            <>
              <div className="scan-grid">
                {shown.map((s) => (
                  <Link
                    key={s.scan_id}
                    to={`/scans/${encodeURIComponent(s.scan_id)}`}
                    className="scan-card"
                  >
                    <div className="scan-card-head">
                      <span className="scan-card-target">
                        {s.target_name || s.target_id || "unknown target"}
                      </span>
                      {s.risk_grade && (
                        <span
                          className="scan-card-grade"
                          style={{
                            borderColor: GRADE_COLORS[s.risk_grade] ?? "#6b7785",
                            color: GRADE_COLORS[s.risk_grade] ?? "#6b7785",
                          }}
                        >
                          {s.risk_grade}
                        </span>
                      )}
                    </div>
                    <div className="scan-card-id mono">{s.scan_id}</div>
                    <div className="scan-card-stats">
                      <span>
                        <strong>{s.finding_count ?? s.dangerous_outcomes}</strong>{" "}
                        {s.finding_count != null ? "findings" : "outcomes"}
                      </span>
                      <span className="muted">{s.nodes} nodes</span>
                      {s.max_severity && <SeverityBadge severity={s.max_severity} />}
                    </div>
                    {s.scanned_at && <div className="scan-card-date">{formatDate(s.scanned_at)}</div>}
                  </Link>
                ))}
              </div>

              {visible < filtered.length && (
                <div className="scan-list-more">
                  <button className="pwn-btn" onClick={() => setVisible((v) => v + PAGE_SIZE)}>
                    Show more ({filtered.length - visible} remaining)
                  </button>
                </div>
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}

function formatDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}
