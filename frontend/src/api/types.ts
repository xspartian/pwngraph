// Hand-written types mirroring pwngraph/api/schemas.py — kept in sync
// manually for now; OpenAPI codegen is a documented follow-up, not required
// for this build (see the PwnGraph build plan).

export interface ScanSummary {
  scan_id: string;
  target_id: string | null;
  scanned_at: string | null;
  nodes: number;
  dangerous_outcomes: number;
  // Present only for scans that persisted a report (see pwngraph/report_store.py).
  target_name?: string | null;
  risk_grade?: string | null;
  risk_score?: number | null;
  finding_count?: number | null;
  max_severity?: string | null;
}

/** One entry of the ASR rollup — overall, or per attack class. */
export interface AsrBucket {
  asr: number;
  successes: number;
  trials: number;
  wilson_low: number;
  wilson_high: number;
  max_severity?: string;
  payloads_total?: number;
  payloads_successful?: number;
}

export interface Asr {
  overall?: AsrBucket;
  by_class?: Record<string, AsrBucket>;
  by_payload?: Record<string, AsrBucket>;
}

export interface OwaspRow {
  id: string;
  name: string;
  status: string; // detected | tested | partial | out-of-scope
  count?: number;
}

export interface RiskGrade {
  grade: string;
  score: number;
  max_score?: number;
  severity_pts?: number;
  asr_pts?: number;
  breadth_pts?: number;
  interpretation?: string;
}

/** A serialized pwngraph.types.Finding (minus `paths`). Loosely typed on
 * purpose — the API hands back exactly what the scan wrote, so an older
 * scan's report stays readable when Finding gains a field. */
export interface Finding {
  finding_id: string;
  title: string;
  severity: string;
  cvss_vector?: string | null;
  cvss_score?: number | null;
  target_system: string;
  attack_class: string;
  owasp: string[];
  payload_id: string;
  summary: string;
  steps_to_reproduce: string[];
  impact: string;
  remediation: string;
  cwe?: string | null;
  references?: string[];
  evidence?: Record<string, unknown>;
  // Set via POST /scans/{id}/findings/{finding_id}/triage — absent (treat as
  // "open") for any finding never triaged. See pwngraph/report_store.py.
  triage_status?: string | null;
  triage_note?: string | null;
}

/** One side of a GET /scans/{id}/compare response. */
export interface CompareSide {
  scan_id: string;
  scanned_at: string | null;
  risk_grade: RiskGrade;
  asr: number;
  finding_count: number;
}

/** Response of GET /scans/{id}/compare?against=<id> — see pwngraph.compare
 * for how findings are matched across two independently-persisted reports. */
export interface ScanCompare {
  before: CompareSide;
  after: CompareSide;
  asr_delta: number;
  score_delta: number;
  verdict: "improved" | "regressed" | "unchanged";
  findings_added: Finding[];
  findings_removed: Finding[];
  findings_persisting_count: number;
  match_method: string;
}

export interface ScanReport {
  scan_id: string;
  target_name: string;
  scanned_at: string;
  tool_inventory: string[];
  findings: Finding[];
  asr: Asr;
  owasp_coverage: OwaspRow[];
  risk_grade: RiskGrade;
  summary: Record<string, unknown>;
}

export interface GraphNode {
  id: string;
  label: string;
  color: string;
  shape: string;
  node_type: string;
  is_adversarial: boolean;
  name: string;
  content: string;
  payload_id: string;
  severity: string;
  confidence: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  color: string;
  label: string;
  edge_type: string;
  is_adversarial: boolean;
  dashes: boolean;
}

export interface GraphFinding {
  i: number;
  severity: string;
  confidence: string;
  label: string;
  nodes: string[];
}

export interface GraphView {
  scan_id: string;
  target_name: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  findings: GraphFinding[];
}

export interface FindingRow {
  node_id: string;
  name: string;
  severity: string;
  confidence: string;
  edge_type: string;
  run_id: string;
  payload_id: string;
  description: string;
}

/** Response of GET /scans/{id}/findings/{finding_id}/chain — see
 * pwngraph.attackpath.chain_for_payload. */
export interface FindingChain {
  nodes: string[];
}

export interface EvidenceSummary {
  coverage: Record<string, number>;
  coverage_ratio: number;
  possible_only: string[];
  exploited: string[];
}

/** One trace event within a run — see pwngraph.queries.scan_log. */
export interface LogEvent {
  node_id: string;
  node_type: string;
  name: string;
  content: string;
  timestamp: number;
}

/** One probe (baseline or adversarial), its events in the order they
 * actually happened — see GET /scans/{id}/logs. */
export interface RunLog {
  run_id: string;
  is_adversarial: boolean;
  payload_id: string | null;
  attack_class: string | null;
  events: LogEvent[];
}

export interface LogsResponse {
  scan_id: string;
  runs: RunLog[];
}

/** One probe's worth of NEXUS's own reasoning — matched to a RunLog by
 * payload_id. Mirrors pwngraph.nexus.state.Observation. */
export interface NexusObservationRow {
  iteration: number;
  payload_id: string;
  attack_class: string;
  target_tool: string | null;
  action: string | null;
  rationale: string;
  success: boolean;
  confidence: string;
  signals: string[];
}

export interface NexusHypothesisRow {
  text: string;
  confidence: number;
  attack_class: string;
  supporting_iterations: number[];
}

/** One tool's shape plus what recon observed it do — mirrors
 * pwngraph.recon.ToolProfile. */
export interface ToolProfileRow {
  name: string;
  description: string;
  tags: string[];
  is_data_sink: boolean;
  is_action_sink: boolean;
  observed_called: boolean;
  observed_sample: string | null;
  looks_outbound: boolean;
}

/** One hypothesized or confirmed tool-to-tool chain — mirrors
 * pwngraph.recon.ChainHypothesis. */
export interface ChainHypothesisRow {
  source_tool: string;
  target_tool: string;
  kind: "possible_chain" | "confirmed_chain";
  confidence: number;
  evidence: string;
}

/** One ranked entry in recon's derived attack plan — mirrors
 * pwngraph.recon.AttackPlanItem. */
export interface AttackPlanItemRow {
  rank: number;
  attack_class: string;
  target_tool: string | null;
  priority: number;
  rationale: string;
}

/** One benign meta-question recon asked, paired with the agent's literal
 * answer — mirrors pwngraph.recon.PurposeProbe. */
export interface PurposeProbeRow {
  question: string;
  answer: string;
}

/** Response of GET /scans/{id}/profile — what recon learned about the
 * target before any adversarial payload was sent. 404s for a scan that ran
 * with recon disabled or predates this feature; see
 * pwngraph.report_store.load_target_profile. */
export interface ScanProfile {
  scan_id: string;
  target_name: string;
  objective: string;
  calls_used: number;
  purpose_probes: PurposeProbeRow[];
  tools: ToolProfileRow[];
  chains: ChainHypothesisRow[];
  attack_plan: AttackPlanItemRow[];
}

/** Response of GET /scans/{id}/nexus — 404s for a static-mode scan or one
 * that predates this feature; see pwngraph.report_store.load_nexus_state. */
export interface NexusStateResponse {
  scan_id: string;
  status: string;
  iteration: number;
  budget: number;
  confidence: number;
  level: number;
  observations: NexusObservationRow[];
  hypotheses: NexusHypothesisRow[];
  successful_techniques: string[];
  failed_techniques: string[];
  discovered_capabilities: string[];
}
