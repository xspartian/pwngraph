import { useState } from "react";

import { api } from "../api/client";
import { EmptyState, Section, Spinner } from "../components/ui";

/**
 * A curated subset of `pwngraph.queries.QUERY_REGISTRY` — the same library
 * `pwngraph query <name>` runs from the CLI, exposed here as click-to-run
 * buttons instead of a command. `scans` (a cross-scan discovery query, not
 * scoped to this one) and `blast-radius` (needs a --tool argument this
 * click-and-view panel has no input for) are left out on purpose; blast
 * radius already has its own dedicated, visual action on the graph's node
 * inspector.
 */
const QUERIES: { name: string; label: string; hint: string }[] = [
  {
    name: "dangerous-outcomes",
    label: "Dangerous outcomes",
    hint: "Every confirmed dangerous outcome, most severe first.",
  },
  {
    name: "high-confidence-findings",
    label: "High-confidence only",
    hint: "Excludes the low-confidence 'verify manually' class.",
  },
  {
    name: "exfil-findings",
    label: "Data exfiltration",
    hint: "Outcomes where data left the trust boundary (DATA_EXFIL).",
  },
  {
    name: "severity-breakdown",
    label: "Severity breakdown",
    hint: "Count of dangerous outcomes per severity bucket.",
  },
  {
    name: "edge-breakdown",
    label: "Edge-type breakdown",
    hint: "Count of dangerous outcomes per triggering edge type.",
  },
  {
    name: "evidence-coverage",
    label: "Evidence coverage",
    hint: "The static tool surface by evidence state (possible/observed/validated/exploited).",
  },
  {
    name: "possible-only-tools",
    label: "Never touched",
    hint: "Tools discovered in source but never exercised by this scan.",
  },
  {
    name: "exploited-tools",
    label: "Exploited tools",
    hint: "Tools that were part of a confirmed, reportable finding.",
  },
  {
    name: "coverage-ratio",
    label: "Coverage ratio",
    hint: "Fraction of the discovered tool surface confirmed at runtime.",
  },
];

export function ReportQueries({ scanId }: { scanId: string }) {
  const [active, setActive] = useState<string | null>(null);
  const [rows, setRows] = useState<Record<string, unknown>[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = (name: string) => {
    setActive(name);
    setLoading(true);
    setError(null);
    api
      .runQuery(scanId, name)
      .then(setRows)
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false));
  };

  return (
    <Section
      title="Queries"
      hint="Predefined questions against this scan's graph — the same library `pwngraph query <name>` runs from the CLI."
    >
      <div className="filter-chips">
        {QUERIES.map((q) => (
          <button
            key={q.name}
            className={`filter-chip ${active === q.name ? "active" : ""}`}
            onClick={() => run(q.name)}
            title={q.hint}
          >
            {q.label}
          </button>
        ))}
      </div>

      {active && (
        <div className="query-result">
          {loading && <Spinner label="Running query…" />}
          {!loading && error && <EmptyState title="Query failed" detail={error} />}
          {!loading && !error && rows && <QueryResultTable rows={rows} />}
        </div>
      )}
    </Section>
  );
}

function QueryResultTable({ rows }: { rows: Record<string, unknown>[] }) {
  if (rows.length === 0) {
    return <EmptyState title="No rows" detail="This query matched nothing in this scan." />;
  }
  const columns = Object.keys(rows[0]);
  return (
    <div className="data-table-wrap">
      <table className="data-table">
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c}>{c.replace(/_/g, " ")}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i}>
              {columns.map((c) => (
                <td key={c} className="mono">
                  {formatCell(row[c])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function formatCell(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "yes" : "no";
  return String(value);
}
