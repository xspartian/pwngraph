import { api } from "../api/client";
import type { ChainHypothesisRow, ScanProfile, ToolProfileRow } from "../api/types";
import { useResource } from "../api/useResource";
import { EmptyState, Section, Spinner, StatTile } from "../components/ui";
import { ToolTopology } from "./ToolTopology";

/**
 * The Profile tab — what recon learned about this agent before any
 * adversarial payload was sent: its elicited purpose (as the literal Q&A
 * transcript), the discovered tool surface with observed (not just guessed)
 * behavior, confirmed/possible tool chains with their supporting evidence,
 * and the resulting attack plan. Read back from pwngraph.recon.TargetProfile
 * via pwngraph.report_store.persist_target_profile.
 *
 * 404s for a scan run with recon disabled (`--recon-budget 0`) or one that
 * predates this feature — the graph/findings/report for such a scan are
 * still fully available, only this tab is absent.
 */
export function ReportProfile({ scanId }: { scanId: string }) {
  const { data, error, status, loading } = useResource<ScanProfile>(
    () => api.getProfile(scanId),
    [scanId],
  );

  if (loading) return <Spinner label="Loading recon profile…" />;
  if (status === 404) {
    return (
      <EmptyState
        title="No recon profile for this scan"
        detail="This scan ran with recon disabled (--recon-budget 0), or predates this feature."
      />
    );
  }
  if (error || !data) return <EmptyState title="Failed to load profile" detail={error} />;

  return <ProfileBody profile={data} />;
}

function ProfileBody({ profile }: { profile: ScanProfile }) {
  // Defensive normalization: pwngraph serve's backend and this bundle can
  // be upgraded independently (see frontend/README.md), so a scan recorded
  // by an older server version may be missing a field this build expects
  // (e.g. a pre-rename `purpose_probes`). Degrade to an empty list rather
  // than crash the whole tab on a schema mismatch.
  const tools = profile.tools ?? [];
  const chains = profile.chains ?? [];
  const purposeProbes = profile.purpose_probes ?? [];
  const attackPlan = profile.attack_plan ?? [];

  const confirmedChains = chains.filter((c) => c.kind === "confirmed_chain");
  const possibleChains = chains.filter((c) => c.kind !== "confirmed_chain");
  const observedTools = tools.filter((t) => t.observed_called).length;
  const actionSinks = tools.filter((t) => t.is_action_sink).length;

  return (
    <div className="page-body">
      {/* Hero — the synthesized objective driving the attack plan below. */}
      <div className="objective-card">
        <div className="objective-icon">◎</div>
        <div>
          <div className="objective-eyebrow">Recon objective</div>
          <p className="objective-text">{profile.objective}</p>
        </div>
      </div>

      <ToolTopology tools={tools} chains={chains} />

      <div className="stat-row">
        <StatTile
          label="Tools discovered"
          value={tools.length}
          sub={`${observedTools} observed in action during recon`}
        />
        <StatTile
          label="Action sinks"
          value={actionSinks}
          sub="tools that take real-world action"
        />
        <StatTile
          label="Confirmed chains"
          value={confirmedChains.length}
          sub={`${possibleChains.length} more structurally possible, unconfirmed`}
          accent={confirmedChains.length ? "#d03b3b" : undefined}
        />
        <StatTile
          label="Recon calls spent"
          value={profile.calls_used}
          sub="before any adversarial payload"
        />
      </div>

      {purposeProbes.length > 0 && (
        <Section
          title="Reconnaissance probes"
          hint="Plain, benign questions asked before any attack, and the agent's literal answers — the actual transcript recon's purpose elicitation ran, not a summary of it."
        >
          <div className="probe-transcript">
            {purposeProbes.map((p, i) => (
              <div className="probe-item" key={i}>
                <div className="probe-q">
                  <span className="probe-q-mark">Q</span>
                  <span>{p.question}</span>
                </div>
                <div className="probe-a">
                  <span className="probe-a-mark">A</span>
                  <p className="probe-a-text">{p.answer}</p>
                </div>
              </div>
            ))}
          </div>
        </Section>
      )}

      <Section
        title="Discovered tool surface"
        hint="is_data_sink/is_action_sink are name+description heuristics; 'observed' means recon actually saw the tool called during a benign probe, upgrading the guess to a fact."
      >
        <div className="tool-grid">
          {tools.map((t) => (
            <ToolCard tool={t} key={t.name} />
          ))}
        </div>
      </Section>

      <Section
        title="Tool chain analysis"
        hint="A confirmed chain means recon actually made the agent call the target tool as a consequence of the source tool's result — not a guess from tags. Evidence is the literal reasoning recorded for each link."
      >
        {chains.length === 0 ? (
          <EmptyState
            title="No chains found"
            detail="Fewer than two data/action-sink tools, or no probe budget left for chain testing."
          />
        ) : (
          <div className="chain-list">
            {chains.map((c, i) => (
              <ChainRow chain={c} key={i} />
            ))}
          </div>
        )}
      </Section>

      <Section
        title="Attack plan"
        hint="What PwnGraph is about to try, ranked highest-priority first. The top target tool for each class is only preferred for its first payload — coverage never narrows to one tool."
      >
        <div className="data-table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th className="num">Rank</th>
                <th>Attack class</th>
                <th>Target tool</th>
                <th>Priority</th>
                <th>Rationale</th>
              </tr>
            </thead>
            <tbody>
              {attackPlan.map((item) => {
                const maxPriority = Math.max(1, ...attackPlan.map((p) => p.priority));
                return (
                  <tr key={item.attack_class}>
                    <td className="num">{item.rank}</td>
                    <td className="mono">{item.attack_class.replace(/_/g, " ")}</td>
                    <td className="mono">{item.target_tool ?? "—"}</td>
                    <td>
                      <div className="priority-cell">
                        <div className="priority-track">
                          <div
                            className="priority-fill"
                            style={{ width: `${(item.priority / maxPriority) * 100}%` }}
                          />
                        </div>
                        <span className="muted mono">{item.priority.toFixed(0)}</span>
                      </div>
                    </td>
                    <td>{item.rationale}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Section>
    </div>
  );
}

function ToolCard({ tool }: { tool: ToolProfileRow }) {
  return (
    <div className="tool-card">
      <div className="tool-card-head">
        <span className="tool-card-name">{tool.name}</span>
        <span className={`badge ${tool.observed_called ? "badge-danger" : "badge-muted"}`}>
          {tool.observed_called ? "observed" : "guessed only"}
        </span>
      </div>
      <p className="tool-card-desc">{tool.description || "(no description provided)"}</p>
      <div className="tool-card-roles">
        {tool.is_action_sink && <span className="chip chip-danger">action sink</span>}
        {tool.is_data_sink && <span className="chip">data sink</span>}
        {tool.looks_outbound && <span className="chip chip-danger">outbound-shaped</span>}
        {tool.tags.map((tag) => (
          <span className="chip mono" key={tag}>
            {tag}
          </span>
        ))}
      </div>
      {tool.observed_sample ? (
        <pre className="tool-card-sample">{tool.observed_sample}</pre>
      ) : (
        <div className="tool-card-unobserved">Not called during recon's baseline probes.</div>
      )}
    </div>
  );
}

function ChainRow({ chain }: { chain: ChainHypothesisRow }) {
  const confirmed = chain.kind === "confirmed_chain";
  return (
    <div className={`chain-row ${confirmed ? "confirmed" : "possible"}`}>
      <span className="chain-node">{chain.source_tool}</span>
      <span className="chain-arrow">→</span>
      <span className="chain-node">{chain.target_tool}</span>
      <span className={`badge ${confirmed ? "badge-danger" : "badge-muted"}`}>
        {confirmed ? "confirmed" : "possible"}
      </span>
      <span className="muted mono">confidence {Math.round(chain.confidence * 100)}%</span>
      {chain.evidence && <div className="chain-evidence">{chain.evidence}</div>}
    </div>
  );
}
