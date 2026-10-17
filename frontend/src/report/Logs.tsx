import { useMemo, useState } from "react";

import { api } from "../api/client";
import type {
  LogsResponse,
  NexusObservationRow,
  NexusStateResponse,
  RunLog,
  ScanReport,
} from "../api/types";
import { useResource } from "../api/useResource";
import { EmptyState, Section, Spinner, StatTile } from "../components/ui";
import { NODE_COLORS, NODE_TYPE_LABEL } from "../theme/colors";

/**
 * The raw execution log, one card per probe, in the order it actually ran —
 * "what did PwnGraph actually do to this agent?" without needing to untangle
 * it from the attack graph. For a NEXUS-mode scan, each adversarial probe's
 * card is annotated with NEXUS's own decision (action + rationale) for it,
 * matched by payload_id — see pwngraph.report_store.persist_nexus_state.
 *
 * Three independent fetches: /logs is always expected to exist for any scan
 * with events; /nexus 404s (a normal outcome, not a fault) for a static-mode
 * scan or one that predates this feature, in which case the log still
 * renders fully, just without the reasoning annotations; /report supplies
 * the actual confirmed findings so a run only glows red here when it's a
 * *real* finding — matching Findings tab, not just "NEXUS thought this one
 * succeeded" or "this was an adversarial probe."
 */
export function ReportLogs({ scanId }: { scanId: string }) {
  const { data: logs, error, status, loading } = useResource<LogsResponse>(
    () => api.getLogs(scanId),
    [scanId],
  );
  const nexusRes = useResource<NexusStateResponse>(() => api.getNexusState(scanId), [scanId]);
  const nexus = nexusRes.status === 404 ? null : nexusRes.data;
  const reportRes = useResource<ScanReport>(() => api.getReport(scanId), [scanId]);
  const report = reportRes.status === 404 ? null : reportRes.data;

  if (loading) return <Spinner label="Loading execution log…" />;
  if (status === 404 || (logs && logs.runs.length === 0)) {
    return (
      <EmptyState
        title="No log recorded"
        detail="This scan produced no trace events, or predates this feature."
      />
    );
  }
  if (error || !logs) return <EmptyState title="Failed to load log" detail={error} />;

  return <LogsBody logs={logs} nexus={nexus} report={report} />;
}

function LogsBody({
  logs,
  nexus,
  report,
}: {
  logs: LogsResponse;
  nexus: NexusStateResponse | null;
  report: ScanReport | null;
}) {
  const observationsByPayload = useMemo(() => {
    const m = new Map<string, NexusObservationRow>();
    for (const o of nexus?.observations ?? []) m.set(o.payload_id, o);
    return m;
  }, [nexus]);
  // A run "glows" red only when it's a real, reported finding — the same bar
  // the Findings tab uses — not merely an adversarial probe or a NEXUS
  // success guess that never made it into the report.
  const findingPayloadIds = useMemo(() => {
    const s = new Set<string>();
    for (const f of report?.findings ?? []) s.add(f.payload_id);
    return s;
  }, [report]);

  const adversarialCount = logs.runs.filter((r) => r.is_adversarial).length;
  const totalEvents = logs.runs.reduce((n, r) => n + r.events.length, 0);

  return (
    <div className="page-body">
      <div className="stat-row">
        <StatTile
          label="Probes"
          value={logs.runs.length}
          sub={`${adversarialCount} adversarial, ${logs.runs.length - adversarialCount} baseline`}
        />
        <StatTile label="Events" value={totalEvents} sub="user input, tool calls/results, LLM steps" />
        {nexus && (
          <StatTile
            label="NEXUS"
            value={nexus.status.replace(/_/g, " ")}
            sub={`${nexus.iteration}/${nexus.budget} iterations · confidence ${Math.round(nexus.confidence * 100)}%`}
          />
        )}
      </div>

      {nexus && nexus.hypotheses.length > 0 && (
        <Section
          title="Hypotheses NEXUS formed"
          hint="What NEXUS concluded from the probes so far, in the order it formed them."
        >
          <ul className="repro-list">
            {nexus.hypotheses.map((h, i) => (
              <li key={i}>
                {h.text}{" "}
                <span className="muted">
                  ({h.attack_class.replace(/_/g, " ")}, confidence {Math.round(h.confidence * 100)}%)
                </span>
              </li>
            ))}
          </ul>
        </Section>
      )}

      <Section
        title="Execution log"
        hint="Every probe PwnGraph ran, in the order it actually happened. Click a probe to see its events."
      >
        <div className="finding-list">
          {logs.runs.map((run, i) => (
            <RunCard
              key={run.run_id}
              index={i}
              run={run}
              observation={run.payload_id ? observationsByPayload.get(run.payload_id) : undefined}
              isFinding={!!run.payload_id && findingPayloadIds.has(run.payload_id)}
            />
          ))}
        </div>
      </Section>
    </div>
  );
}

function RunCard({
  index,
  run,
  observation,
  isFinding,
}: {
  index: number;
  run: RunLog;
  observation?: NexusObservationRow;
  isFinding: boolean;
}) {
  const [open, setOpen] = useState(false);
  const borderColor = isFinding ? "#d03b3b" : !run.is_adversarial ? "#3987e5" : "#6b7785";

  return (
    <article
      className={`finding-card ${isFinding ? "log-run-finding" : ""}`}
      style={{ borderLeftColor: borderColor }}
    >
      <header className="finding-card-head" onClick={() => setOpen((o) => !o)}>
        <div className="finding-card-title-row">
          <span className={`badge ${run.is_adversarial ? "badge-danger" : "badge-muted"}`}>
            {run.is_adversarial ? "adversarial" : "baseline"}
          </span>
          {isFinding && <span className="badge badge-danger">confirmed finding</span>}
          {run.attack_class && <span className="chip mono">{run.attack_class.replace(/_/g, " ")}</span>}
          {observation?.action && <span className="chip">{observation.action.replace(/_/g, " ")}</span>}
          <span className="spacer" />
          <span className="disclosure">{open ? "−" : "+"}</span>
        </div>
        <h3 className="finding-card-title">
          Probe #{index + 1}
          {run.payload_id && <span className="muted mono"> · {run.payload_id}</span>}
        </h3>
        {observation?.rationale && <p className="finding-card-summary">{observation.rationale}</p>}
        <div className="finding-card-meta">
          <span className="muted mono">run {run.run_id}</span>
          <span className="muted">
            {run.events.length} event{run.events.length === 1 ? "" : "s"}
          </span>
          {observation && (
            <span>
              {observation.success ? "✓ succeeded" : "resisted"}{" "}
              <span className="muted">({observation.confidence} confidence)</span>
            </span>
          )}
        </div>
      </header>

      {open && (
        <div className="finding-card-body">
          <div className="log-event-list">
            {run.events.map((ev) => (
              <div className="log-event" key={ev.node_id}>
                <span
                  className="log-event-dot"
                  style={{ background: NODE_COLORS[ev.node_type] ?? "#6b7785" }}
                />
                <div className="log-event-body">
                  <div className="log-event-head">
                    <strong>{NODE_TYPE_LABEL[ev.node_type] ?? ev.node_type}</strong>
                    {ev.name && <span className="muted mono">{ev.name}</span>}
                  </div>
                  <EventContent content={ev.content} />
                </div>
              </div>
            ))}
          </div>

          {observation && observation.signals.length > 0 && (
            <div className="detail-block">
              <div className="detail-label">Oracle signals</div>
              <ul className="repro-list">
                {observation.signals.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </article>
  );
}

const CONTENT_PREVIEW_LEN = 320;

function EventContent({ content }: { content: string }) {
  const [expanded, setExpanded] = useState(false);
  const long = content.length > CONTENT_PREVIEW_LEN;
  const shown = !long || expanded ? content : content.slice(0, CONTENT_PREVIEW_LEN) + "…";

  if (!content) return null;
  return (
    <div className="log-event-content-wrap">
      <pre className="log-event-content">{shown}</pre>
      {long && (
        <button className="pwn-btn log-event-toggle" onClick={() => setExpanded((e) => !e)}>
          {expanded ? "Show less" : "Show more"}
        </button>
      )}
    </div>
  );
}
