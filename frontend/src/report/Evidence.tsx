import { api } from "../api/client";
import type { EvidenceSummary } from "../api/types";
import { useResource } from "../api/useResource";
import { EmptyState, Section, Spinner, StatTile } from "../components/ui";

const STATE_ORDER = ["possible", "observed", "validated", "exploited"] as const;

const STATE_COLOR: Record<string, string> = {
  possible: "#6b7785",
  observed: "#3987e5",
  validated: "#fab219",
  exploited: "#d03b3b",
};

const STATE_MEANING: Record<string, string> = {
  possible: "Found in source code. Never confirmed at runtime.",
  observed: "The agent actually invoked this tool during the scan.",
  validated: "The behavioral oracle saw a divergence signal here.",
  exploited: "Part of a confirmed, reportable finding.",
};

export function ReportEvidence({ scanId }: { scanId: string }) {
  const { data, error, loading } = useResource<EvidenceSummary>(
    () => api.getEvidence(scanId),
    [scanId],
  );

  if (loading) return <Spinner label="Loading evidence ladder…" />;
  if (error || !data) return <EmptyState title="Failed to load evidence" detail={error} />;

  const total = STATE_ORDER.reduce((sum, s) => sum + (data.coverage[s] ?? 0), 0);
  if (total === 0) {
    return (
      <EmptyState
        title="No static surface recorded"
        detail="The evidence ladder is only built for a target PwnGraph could parse statically — a file locator like agent.py:build_agent. Module-style targets skip it."
      />
    );
  }

  return (
    <div className="page-body">
      <div className="stat-row">
        <StatTile
          label="Runtime coverage"
          value={`${Math.round(data.coverage_ratio * 100)}%`}
          sub="of the discovered tool surface confirmed at runtime"
        />
        <StatTile label="Tools discovered" value={total} sub="from static source analysis" />
        <StatTile
          label="Exploited"
          value={data.exploited.length}
          sub="part of a confirmed finding"
          accent={data.exploited.length ? STATE_COLOR.exploited : undefined}
        />
        <StatTile
          label="Never reached"
          value={data.possible_only.length}
          sub="untested attack surface"
        />
      </div>

      <Section
        title="Evidence ladder"
        hint="Evidence only ever strengthens — a tool's state never regresses, within a scan or across re-scans of the same target."
      >
        <div className="ladder">
          {STATE_ORDER.map((state) => {
            const count = data.coverage[state] ?? 0;
            const share = total ? count / total : 0;
            return (
              <div className="ladder-row" key={state}>
                <div className="ladder-label">
                  <span className="swatch" style={{ background: STATE_COLOR[state] }} />
                  <strong>{state}</strong>
                  <span className="ladder-meaning">{STATE_MEANING[state]}</span>
                </div>
                <div className="ladder-bar">
                  <div
                    className="ladder-fill"
                    style={{ width: `${share * 100}%`, background: STATE_COLOR[state] }}
                  />
                </div>
                <div className="ladder-count">{count}</div>
              </div>
            );
          })}
        </div>
      </Section>

      {data.exploited.length > 0 && (
        <Section title="Exploited tools" hint="These were part of a confirmed, reportable finding.">
          <div className="chip-row">
            {data.exploited.map((t) => (
              <span className="chip mono chip-danger" key={t}>
                {t}
              </span>
            ))}
          </div>
        </Section>
      )}

      {data.possible_only.length > 0 && (
        <Section
          title="Never touched by this scan"
          hint="These tools exist in the source but no payload reached them — the part of the attack surface a higher --budget or a different attack class might still cover. A clean result here is not proof of safety."
        >
          <div className="chip-row">
            {data.possible_only.map((t) => (
              <span className="chip mono" key={t}>
                {t}
              </span>
            ))}
          </div>
        </Section>
      )}
    </div>
  );
}
