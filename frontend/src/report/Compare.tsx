import { useEffect, useState } from "react";

import { api } from "../api/client";
import type { Finding, ScanCompare, ScanSummary } from "../api/types";
import { EmptyState, Section, SeverityBadge, Spinner, StatTile } from "../components/ui";
import { GRADE_COLORS } from "../theme/colors";

/**
 * The read-only counterpart to `pwngraph diff`'s CI regression gate — pick
 * an earlier scan of the same target and see what changed. See
 * `pwngraph.compare` for how findings are matched across two independently
 * persisted reports (approximate — by attack class + title, not the exact
 * path-signature identity two *live* scans in one process can compare by).
 */
export function ReportCompare({ scanId, targetName }: { scanId: string; targetName: string }) {
  const [candidates, setCandidates] = useState<ScanSummary[] | null>(null);
  const [against, setAgainst] = useState<string>("");
  const [compare, setCompare] = useState<ScanCompare | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .listScans()
      .then((rows) => {
        if (cancelled) return;
        setCandidates(
          rows.filter(
            (r) => r.scan_id !== scanId && !!r.target_name && r.target_name === targetName,
          ),
        );
      })
      .catch(() => !cancelled && setCandidates([]));
    return () => {
      cancelled = true;
    };
  }, [scanId, targetName]);

  useEffect(() => {
    if (!against) {
      setCompare(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .compareScans(scanId, against)
      .then((c) => !cancelled && setCompare(c))
      .catch((err) => !cancelled && setError(err instanceof Error ? err.message : String(err)))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [scanId, against]);

  const picker = (
    <select
      className="pwn-search"
      value={against}
      onChange={(e) => setAgainst(e.target.value)}
      disabled={!candidates || candidates.length === 0}
    >
      <option value="">
        {candidates === null
          ? "Loading other scans…"
          : candidates.length === 0
            ? "No other scan of this target"
            : "Compare against…"}
      </option>
      {candidates?.map((c) => (
        <option key={c.scan_id} value={c.scan_id}>
          {formatDate(c.scanned_at)} — {c.scan_id} {c.risk_grade ? `(${c.risk_grade})` : ""}
        </option>
      ))}
    </select>
  );

  return (
    <Section
      title="Compare"
      hint="Diff this scan's persisted report against an earlier scan of the same target — the same regression question `pwngraph diff` gates CI on, read back without re-running either scan."
      actions={picker}
    >
      {!against && (
        <EmptyState
          title="Pick a scan to compare against"
          detail={
            candidates && candidates.length === 0
              ? "This is the only stored report for this target so far — re-run the scan later to build a comparison."
              : undefined
          }
        />
      )}
      {against && loading && <Spinner label="Comparing…" />}
      {against && !loading && error && <EmptyState title="Could not compare scans" detail={error} />}
      {against && !loading && compare && <CompareResult compare={compare} />}
    </Section>
  );
}

function CompareResult({ compare }: { compare: ScanCompare }) {
  const verdictCopy: Record<ScanCompare["verdict"], { label: string; tone: string }> = {
    improved: { label: "Improved — risk score went down", tone: "#0ca30c" },
    regressed: { label: "Regressed — risk score went up", tone: "#d03b3b" },
    unchanged: { label: "No change in risk score", tone: "#8b949e" },
  };
  const v = verdictCopy[compare.verdict];
  const beforeGrade = compare.before.risk_grade?.grade;
  const afterGrade = compare.after.risk_grade?.grade;

  return (
    <div className="compare-result">
      <div className="compare-verdict" style={{ borderColor: v.tone, color: v.tone }}>
        {v.label}
      </div>

      <div className="stat-row">
        <StatTile
          label="Risk grade"
          value={
            <span className="compare-grade-pair">
              <GradePill grade={beforeGrade} /> <span className="muted">→</span>{" "}
              <GradePill grade={afterGrade} />
            </span>
          }
          sub={`score ${compare.before.risk_grade?.score ?? "?"} → ${compare.after.risk_grade?.score ?? "?"} (${signed(compare.score_delta)})`}
        />
        <StatTile
          label="ASR"
          value={`${Math.round(compare.before.asr * 100)}% → ${Math.round(compare.after.asr * 100)}%`}
          sub={`${signed(Math.round(compare.asr_delta * 100))} pts`}
        />
        <StatTile
          label="Findings"
          value={`${compare.before.finding_count} → ${compare.after.finding_count}`}
          sub={`${compare.findings_persisting_count} persisting`}
        />
      </div>

      <div className="compare-findings-cols">
        <div>
          <div className="compare-findings-head">
            New since {compare.before.scan_id}
            <span className="report-section-count">{compare.findings_added.length}</span>
          </div>
          {compare.findings_added.length === 0 ? (
            <p className="muted">None.</p>
          ) : (
            <CompareFindingList findings={compare.findings_added} />
          )}
        </div>
        <div>
          <div className="compare-findings-head">
            Closed since {compare.before.scan_id}
            <span className="report-section-count">{compare.findings_removed.length}</span>
          </div>
          {compare.findings_removed.length === 0 ? (
            <p className="muted">None.</p>
          ) : (
            <CompareFindingList findings={compare.findings_removed} />
          )}
        </div>
      </div>

      <p className="compare-caveat muted">
        Findings matched by attack class + title — an approximation, not the exact path-identity
        match two live scans in one process get from <code>pwngraph diff</code>.
      </p>
    </div>
  );
}

function CompareFindingList({ findings }: { findings: Finding[] }) {
  return (
    <ul className="compare-finding-list">
      {findings.map((f) => (
        <li key={f.finding_id}>
          <SeverityBadge severity={f.severity} />
          <span className="compare-finding-title">{f.title}</span>
          <span className="mono muted">{f.attack_class.replace(/_/g, " ")}</span>
        </li>
      ))}
    </ul>
  );
}

function GradePill({ grade }: { grade?: string }) {
  const g = grade || "?";
  const color = GRADE_COLORS[g] ?? "#6b7785";
  return (
    <span className="compare-grade-pill" style={{ borderColor: color, color }}>
      {g}
    </span>
  );
}

function signed(n: number): string {
  return n > 0 ? `+${n}` : `${n}`;
}

function formatDate(iso: string | null): string {
  if (!iso) return "unknown date";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}
