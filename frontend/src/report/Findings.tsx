import { useMemo, useState } from "react";

import { api } from "../api/client";
import type { Finding, ScanReport } from "../api/types";
import { EmptyState, SeverityBadge } from "../components/ui";
import { SEVERITY_COLORS, SEVERITY_ORDER } from "../theme/colors";

const TRIAGE_LABEL: Record<string, string> = {
  open: "Open",
  false_positive: "False positive",
  accepted_risk: "Accepted risk",
  fixed: "Fixed",
};

// Plain-English labels for a CVSS 3.1 base vector's metric values — see
// pwngraph.cvss for how the vector itself gets built. Purely a display
// concern (the score/vector are computed server-side); this just turns
// "AV:N/AC:L/..." into the "✓ Network-reachable" style checklist a reader
// asking "why is this critical?" actually wants.
const CVSS_METRIC_LABELS: Record<string, Record<string, string>> = {
  AV: {
    N: "Network-reachable — no local access needed",
    A: "Reachable from an adjacent network",
    L: "Requires local access",
    P: "Requires physical access",
  },
  AC: { L: "Low attack complexity", H: "High attack complexity" },
  PR: {
    N: "No privileges required",
    L: "Low privileges required",
    H: "High privileges required",
  },
  UI: { N: "No user interaction needed", R: "Requires user interaction" },
  S: { U: "Impact confined to the vulnerable component", C: "Impact extends beyond it (scope changed)" },
  C: {
    N: "No confidentiality impact",
    L: "Some confidentiality impact",
    H: "Total confidentiality impact",
  },
  I: { N: "No integrity impact", L: "Some integrity impact", H: "Total integrity impact" },
  A: { N: "No availability impact", L: "Some availability impact", H: "Total availability impact" },
};

function parseCvssVector(vector: string): { code: string; label: string }[] {
  return vector
    .split("/")
    .filter((part) => part.includes(":"))
    .map((part) => {
      const [code, value] = part.split(":");
      return { code, label: CVSS_METRIC_LABELS[code]?.[value] ?? `${code}:${value}` };
    })
    .filter((m) => m.code in CVSS_METRIC_LABELS);
}

export function ReportFindings({
  scanId,
  report: data,
  onOpenChain,
}: {
  scanId: string;
  report: ScanReport;
  /** Called with a finding_id when its "View attack chain →" action is
   * clicked — the caller owns navigation (see FindingsPage/ReportPage, both
   * of which route to the graph view with ?finding=<id> so GraphExplorer
   * can fetch and focus that specific chain). */
  onOpenChain: (findingId: string) => void;
}) {
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [query, setQuery] = useState("");
  // Optimistic triage overrides, keyed by finding_id — avoids re-fetching the
  // whole report just to reflect a status the POST already confirmed.
  const [triageOverrides, setTriageOverrides] = useState<Record<string, string>>({});

  const findings = useMemo(() => {
    const all = data.findings;
    const needle = query.trim().toLowerCase();
    return all.filter((f) => {
      if (severityFilter !== "all" && (f.severity || "").toLowerCase() !== severityFilter) {
        return false;
      }
      if (!needle) return true;
      return `${f.title} ${f.attack_class} ${f.summary} ${(f.owasp ?? []).join(" ")}`
        .toLowerCase()
        .includes(needle);
    });
  }, [data, severityFilter, query]);

  if (data.findings.length === 0) {
    return (
      <EmptyState
        title="No confirmed findings"
        detail="This scan produced no high-confidence dangerous paths. Consider raising --budget or widening the attack classes."
      />
    );
  }

  const counts = data.findings.reduce<Record<string, number>>((acc, f) => {
    const s = (f.severity || "info").toLowerCase();
    acc[s] = (acc[s] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <div className="page-body">
      <div className="filter-row">
        <input
          className="pwn-search wide"
          placeholder="Filter findings (title, class, OWASP)…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <div className="filter-chips">
          <button
            className={`filter-chip ${severityFilter === "all" ? "active" : ""}`}
            onClick={() => setSeverityFilter("all")}
          >
            All ({data.findings.length})
          </button>
          {SEVERITY_ORDER.filter((s) => counts[s]).map((s) => (
            <button
              key={s}
              className={`filter-chip ${severityFilter === s ? "active" : ""}`}
              onClick={() => setSeverityFilter(s)}
              style={
                severityFilter === s
                  ? {
                      background: SEVERITY_COLORS[s],
                      borderColor: SEVERITY_COLORS[s],
                      color: "#fff",
                    }
                  : undefined
              }
            >
              {s} ({counts[s]})
            </button>
          ))}
        </div>
      </div>

      {findings.length === 0 ? (
        <EmptyState title="Nothing matches that filter" />
      ) : (
        <div className="finding-list">
          {findings.map((f) => (
            <FindingCard
              key={f.finding_id}
              finding={f}
              status={triageOverrides[f.finding_id] ?? f.triage_status ?? "open"}
              onOpenChain={() => onOpenChain(f.finding_id)}
              onStatusChange={(status) => {
                setTriageOverrides((prev) => ({ ...prev, [f.finding_id]: status }));
                api.setFindingTriage(scanId, f.finding_id, status).catch(() => {
                  // Revert on failure — the write didn't actually land.
                  setTriageOverrides((prev) => ({
                    ...prev,
                    [f.finding_id]: f.triage_status ?? "open",
                  }));
                });
              }}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function FindingCard({
  finding: f,
  status,
  onStatusChange,
  onOpenChain,
}: {
  finding: Finding;
  status: string;
  onStatusChange: (status: string) => void;
  onOpenChain: () => void;
}) {
  const [open, setOpen] = useState(false);
  const color = SEVERITY_COLORS[(f.severity || "info").toLowerCase()] ?? "#6b7785";
  const asr = f.evidence?.attack_success_rate as number | undefined;
  const trials = f.evidence?.trials as number | undefined;
  const successes = f.evidence?.successes as number | undefined;
  // The oracle's own plain-English reason a sink got flagged (see
  // BehavioralOracle's `signals` in oracle.py) — already human-readable, it
  // just wasn't surfaced as its own explanation before.
  const sinkReason = typeof f.evidence?.sink === "string" ? (f.evidence.sink as string) : undefined;
  const cvssMetrics = f.cvss_vector ? parseCvssVector(f.cvss_vector) : [];

  return (
    <article className={`finding-card triage-${status}`} style={{ borderLeftColor: color }}>
      <header className="finding-card-head" onClick={() => setOpen((o) => !o)}>
        <div className="finding-card-title-row">
          <SeverityBadge severity={f.severity} />
          {f.cvss_score != null && (
            <span className="cvss-chip" title={f.cvss_vector ?? undefined}>
              CVSS {f.cvss_score}
            </span>
          )}
          {(f.owasp ?? []).map((o) => (
            <span className="owasp-chip" key={o}>
              {o}
            </span>
          ))}
          {f.cwe && <span className="owasp-chip">{f.cwe}</span>}
          <span className="spacer" />
          <select
            className={`triage-select triage-select-${status}`}
            value={status}
            onClick={(e) => e.stopPropagation()}
            onChange={(e) => onStatusChange(e.target.value)}
          >
            {Object.entries(TRIAGE_LABEL).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
          <span className="disclosure">{open ? "−" : "+"}</span>
        </div>
        <h3 className="finding-card-title">{f.title}</h3>
        <p className="finding-card-summary">{f.summary}</p>
        <div className="finding-card-meta">
          <span className="mono">{f.attack_class.replace(/_/g, " ")}</span>
          {asr !== undefined && (
            <span>
              ASR {Math.round(asr * 100)}%
              {trials ? (
                <span className="muted">
                  {" "}
                  ({successes ?? 0}/{trials})
                </span>
              ) : null}
            </span>
          )}
          <span className="muted mono">payload {f.payload_id}</span>
          <button
            className="pwn-btn finding-chain-btn"
            onClick={(e) => {
              e.stopPropagation();
              onOpenChain();
            }}
          >
            View attack chain →
          </button>
        </div>
      </header>

      {open && (
        <div className="finding-card-body">
          <div className="detail-block why-block">
            <div className="detail-label">Why {(f.severity || "").toLowerCase() || "this severity"}?</div>
            {sinkReason && <p className="why-reason">{sinkReason}</p>}
            {cvssMetrics.length > 0 && (
              <ul className="why-checklist">
                {cvssMetrics.map((m) => (
                  <li key={m.code}>{m.label}</li>
                ))}
              </ul>
            )}
            {asr !== undefined && (
              <p className="why-asr muted">
                Reproduced in {Math.round(asr * 100)}% of attempts
                {trials !== undefined ? ` (${successes ?? 0}/${trials} trials)` : ""}.
              </p>
            )}
          </div>

          {f.cvss_vector && (
            <div className="detail-block">
              <div className="detail-label">CVSS 3.1 vector</div>
              <code className="vector">{f.cvss_vector}</code>
            </div>
          )}

          {f.steps_to_reproduce?.length > 0 && (
            <div className="detail-block">
              <div className="detail-label">Steps to reproduce</div>
              <ol className="repro-list">
                {f.steps_to_reproduce.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ol>
            </div>
          )}

          <div className="detail-block">
            <div className="detail-label">Impact</div>
            <p>{f.impact}</p>
          </div>

          <div className="detail-block remediation">
            <div className="detail-label">Remediation</div>
            <p>{f.remediation}</p>
          </div>

          {f.references && f.references.length > 0 && (
            <div className="detail-block">
              <div className="detail-label">References</div>
              <ul className="ref-list">
                {f.references.map((r) => (
                  <li key={r}>
                    <a href={r} target="_blank" rel="noreferrer noopener">
                      {r}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </article>
  );
}
