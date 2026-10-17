"""Typed response shapes for the PwnGraph API.

Thin wrappers only: every field here mirrors a dict shape a function under
``pwngraph.queries`` or ``pwngraph.reporter.graph_export`` already returns.
No new business logic lives in this module — it exists purely so the
OpenAPI schema (and the types the frontend hand-writes against it) are
accurate. Endpoints returning a query-registry row or a plain count
breakdown skip a named model on purpose — those shapes are already
heterogeneous / registry-driven, see ``pwngraph.queries.QUERY_REGISTRY``.
"""

from __future__ import annotations

from pydantic import BaseModel


class ScanSummary(BaseModel):
    scan_id: str
    target_id: str | None = None
    scanned_at: str | None = None
    nodes: int = 0
    dangerous_outcomes: int = 0
    # Enriched from the scan's persisted report when it has one (see
    # pwngraph.report_store); absent for scans that predate it.
    target_name: str | None = None
    risk_grade: str | None = None
    risk_score: int | None = None
    finding_count: int | None = None
    max_severity: str | None = None


class GraphNode(BaseModel):
    id: str
    label: str
    color: str
    shape: str
    node_type: str
    is_adversarial: bool = False
    name: str = ""
    content: str = ""
    payload_id: str = ""
    severity: str = ""
    confidence: str = ""


class GraphEdge(BaseModel):
    source: str
    target: str
    color: str
    label: str = ""
    edge_type: str = ""
    is_adversarial: bool = False
    dashes: bool = False


class GraphFinding(BaseModel):
    i: int
    severity: str
    confidence: str
    label: str
    nodes: list[str]


class GraphView(BaseModel):
    scan_id: str
    target_name: str = ""
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    findings: list[GraphFinding]


class FindingRow(BaseModel):
    node_id: str
    name: str
    severity: str
    confidence: str
    edge_type: str
    run_id: str
    payload_id: str
    description: str


class EvidenceSummary(BaseModel):
    coverage: dict[str, int]
    coverage_ratio: float
    possible_only: list[str]
    exploited: list[str]


class HealthStatus(BaseModel):
    ok: bool
    nodes: int | None = None
    error: str | None = None


class ScanReport(BaseModel):
    """A scan's reportable layer, as persisted by ``pwngraph.report_store``.

    ``findings`` are whole serialized :class:`pwngraph.types.Finding` records
    (CVSS, steps to reproduce, impact, remediation, OWASP tags, ASR evidence)
    minus their ``paths`` — see that module for why. Left loosely typed here
    on purpose: this endpoint's job is to hand back exactly what the scan
    wrote, and pinning a rigid schema would make an older scan's report
    unreadable the moment ``Finding`` gains a field.
    """

    scan_id: str
    target_name: str = ""
    scanned_at: str = ""
    tool_inventory: list[str] = []
    findings: list[dict] = []
    asr: dict = {}
    owasp_coverage: list[dict] = []
    risk_grade: dict = {}
    summary: dict = {}


class TriageUpdate(BaseModel):
    """Body of ``POST /api/scans/{scan_id}/findings/{finding_id}/triage`` —
    see ``pwngraph.report_store.TRIAGE_STATES`` for valid ``status`` values."""

    status: str
    note: str | None = None


class FindingChain(BaseModel):
    """Response of ``GET /api/scans/{scan_id}/findings/{finding_id}/chain`` —
    node ids for the graph view to highlight and fit its camera to. See
    ``pwngraph.attackpath.chain_for_payload``."""

    nodes: list[str] = []


class LogEvent(BaseModel):
    """One trace event within a run — see ``pwngraph.queries.scan_log``."""

    node_id: str
    node_type: str
    name: str
    content: str
    timestamp: float = 0.0


class RunLog(BaseModel):
    """One probe (baseline or adversarial), its events in order — the unit
    ``GET /api/scans/{scan_id}/logs`` groups ``pwngraph.queries.scan_log``'s
    flat rows into."""

    run_id: str
    is_adversarial: bool = False
    payload_id: str | None = None
    attack_class: str | None = None
    events: list[LogEvent] = []


class LogsResponse(BaseModel):
    """Response of ``GET /api/scans/{scan_id}/logs`` — the raw execution
    log, one run per probe, in chronological order."""

    scan_id: str
    runs: list[RunLog] = []


class NexusObservationRow(BaseModel):
    """One probe's worth of NEXUS's own reasoning — mirrors
    ``pwngraph.nexus.state.Observation``, as persisted by
    ``pwngraph.report_store.persist_nexus_state``. ``rationale`` is the
    human-readable "why" behind the ``NexusDecision`` that produced this
    probe; matched to a ``RunLog`` by ``payload_id``."""

    iteration: int
    payload_id: str
    attack_class: str
    target_tool: str | None = None
    action: str | None = None
    rationale: str = ""
    success: bool = False
    confidence: str = "low"
    signals: list[str] = []


class NexusHypothesisRow(BaseModel):
    """One working theory NEXUS formed — mirrors ``pwngraph.nexus.state.Hypothesis``."""

    text: str
    confidence: float = 0.0
    attack_class: str = ""
    supporting_iterations: list[int] = []


class NexusStateResponse(BaseModel):
    """Response of ``GET /api/scans/{scan_id}/nexus`` — NEXUS's decision
    history for a scan run in adaptive mode. 404s for a static-mode scan or
    one that predates this feature; see ``pwngraph.report_store.load_nexus_state``."""

    scan_id: str
    status: str = ""
    iteration: int = 0
    budget: int = 0
    confidence: float = 0.0
    level: int = 1
    observations: list[NexusObservationRow] = []
    hypotheses: list[NexusHypothesisRow] = []
    successful_techniques: list[str] = []
    failed_techniques: list[str] = []
    discovered_capabilities: list[str] = []


class ToolProfileRow(BaseModel):
    """One tool's shape plus what recon observed it do — mirrors
    ``pwngraph.recon.ToolProfile``."""

    name: str
    description: str = ""
    tags: list[str] = []
    is_data_sink: bool = False
    is_action_sink: bool = False
    observed_called: bool = False
    observed_sample: str | None = None
    looks_outbound: bool = False


class ChainHypothesisRow(BaseModel):
    """One hypothesized or confirmed tool-to-tool chain — mirrors
    ``pwngraph.recon.ChainHypothesis``."""

    source_tool: str
    target_tool: str
    kind: str = "possible_chain"
    confidence: float = 0.3
    evidence: str = ""


class AttackPlanItemRow(BaseModel):
    """One ranked entry in recon's derived attack plan — mirrors
    ``pwngraph.recon.AttackPlanItem``."""

    rank: int
    attack_class: str
    target_tool: str | None = None
    priority: float = 0.0
    rationale: str = ""


class PurposeProbeRow(BaseModel):
    """One benign meta-question recon asked, paired with the agent's literal
    answer — mirrors ``pwngraph.recon.PurposeProbe``."""

    question: str
    answer: str


class ScanProfile(BaseModel):
    """Response of ``GET /api/scans/{scan_id}/profile`` — what recon learned
    about the target before any adversarial payload was sent: its elicited
    purpose, observed tool behavior, confirmed/possible chains, and the
    resulting attack plan. 404s for a scan that skipped recon or predates
    this feature; see ``pwngraph.report_store.load_target_profile``."""

    scan_id: str
    target_name: str = ""
    objective: str = ""
    calls_used: int = 0
    purpose_probes: list[PurposeProbeRow] = []
    tools: list[ToolProfileRow] = []
    chains: list[ChainHypothesisRow] = []
    attack_plan: list[AttackPlanItemRow] = []


class ScanCompare(BaseModel):
    """Response of ``GET /api/scans/{scan_id}/compare`` — see
    ``pwngraph.compare.compare_reports`` for the matching caveat."""

    before: dict
    after: dict
    asr_delta: float
    score_delta: int
    verdict: str
    findings_added: list[dict] = []
    findings_removed: list[dict] = []
    findings_persisting_count: int = 0
    match_method: str
