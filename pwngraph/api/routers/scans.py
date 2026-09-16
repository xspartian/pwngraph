"""``/api/scans`` routes — read-only access to a scan's graph, findings, and
evidence, straight out of Neo4j through the ``GraphBackend`` ABC.

Every handler is a thin wrapper around an existing function in
``pwngraph.queries`` / ``pwngraph.attackpath`` /
``pwngraph.reporter.graph_export`` — no analysis logic is duplicated here.
"""

from __future__ import annotations

import io
import json
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response

from pwngraph import queries as q
from pwngraph.api.deps import get_backend
from pwngraph.api.schemas import (
    EvidenceSummary,
    FindingChain,
    FindingRow,
    GraphView,
    LogsResponse,
    NexusStateResponse,
    ScanCompare,
    ScanProfile,
    ScanReport,
    ScanSummary,
    TriageUpdate,
)
from pwngraph.attackpath import blast_radius, chain_for_payload
from pwngraph.backend import GraphBackend
from pwngraph.compare import compare_reports
from pwngraph.poc import export_all_pocs
from pwngraph.report_store import (
    KIND_SCAN_REPORT,
    TRIAGE_STATES,
    load_nexus_state,
    load_scan_report,
    load_target_profile,
    report_node_id,
    set_finding_triage,
)
from pwngraph.reporter.graph_export import build_graph_view
from pwngraph.sarif import to_sarif
from pwngraph.types import Finding

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.get("", response_model=list[ScanSummary])
def list_scans(backend: GraphBackend = Depends(get_backend)) -> list[dict[str, Any]]:
    """Every scan_id currently in the database, most recent first — start
    here before any of the scan-scoped routes below.

    Each row is enriched with its scan's persisted report headline (target
    name, risk grade, finding count) when one exists, so the scan list can
    show what a scan actually found without a request per row.
    """
    rows = q.list_scans(backend)
    for row in rows:
        attrs = backend.node_attrs(report_node_id(row["scan_id"]))
        if attrs.get("kind") != KIND_SCAN_REPORT:
            continue
        row["target_name"] = attrs.get("target_name") or None
        row["risk_grade"] = attrs.get("risk_grade") or None
        row["risk_score"] = attrs.get("risk_score")
        row["finding_count"] = attrs.get("finding_count")
        row["max_severity"] = attrs.get("max_severity") or None
    return rows


@router.get("/{scan_id}/graph", response_model=GraphView)
def get_graph(scan_id: str, backend: GraphBackend = Depends(get_backend)) -> dict[str, Any]:
    """Nodes/edges/findings for one scan's runtime trace graph — the live
    payload the frontend's Sigma.js/Graphology view renders.

    No ``dangerous_paths`` list is available here (this is a fresh read, not
    a live ``PwnGraph.scan()`` in this same process), so the findings list
    comes from the persisted report when this scan has one — the same
    deduplicated set the Findings/Report tabs show, via
    ``build_graph_view``'s ``report_findings`` path — falling back to
    walking every dangerous sink node only for a scan that predates
    ``report_store``. See ``build_graph_view``.
    """
    report = load_scan_report(backend, scan_id)
    view = build_graph_view(
        backend, scan_id, report_findings=report["findings"] if report else None
    )
    if not view["nodes"]:
        raise HTTPException(status_code=404, detail=f"No graph found for scan_id={scan_id!r}")
    target_name = report["target_name"] if report else ""
    return {"scan_id": scan_id, "target_name": target_name, **view}


@router.get("/{scan_id}/report", response_model=ScanReport)
def get_report(scan_id: str, backend: GraphBackend = Depends(get_backend)) -> dict[str, Any]:
    """This scan's full report — findings with CVSS/steps/remediation, ASR,
    OWASP coverage, and risk grade — as the scan itself persisted it.

    404s for a scan that never wrote one (any scan predating
    ``pwngraph.report_store``, or one whose process died mid-run). The graph
    for such a scan is still fully browsable; only this richer layer is absent.
    """
    report = load_scan_report(backend, scan_id)
    if report is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"No stored report for scan_id={scan_id!r}. Re-run the scan to "
                f"generate one — the graph for this scan is still available."
            ),
        )
    return report


@router.get("/{scan_id}/findings", response_model=list[FindingRow])
def get_findings(
    scan_id: str,
    confidence: str | None = Query(
        default=None,
        description="Filter to a confidence level — currently only 'high' is meaningful.",
    ),
    exfil: bool = Query(default=False, description="Only findings reached via a DATA_EXFIL edge."),
    backend: GraphBackend = Depends(get_backend),
) -> list[dict[str, Any]]:
    if exfil:
        return q.exfil_findings(backend, scan_id=scan_id)
    if confidence == "high":
        return q.high_confidence_findings(backend, scan_id=scan_id)
    return q.dangerous_outcomes(backend, scan_id=scan_id)


@router.get("/{scan_id}/evidence", response_model=EvidenceSummary)
def get_evidence(scan_id: str, backend: GraphBackend = Depends(get_backend)) -> dict[str, Any]:
    return {
        "coverage": q.evidence_coverage(backend, scan_id=scan_id),
        "coverage_ratio": q.coverage_ratio(backend, scan_id=scan_id),
        "possible_only": q.possible_only_tools(backend, scan_id=scan_id),
        "exploited": q.exploited_tools(backend, scan_id=scan_id),
    }


@router.get("/{scan_id}/logs", response_model=LogsResponse)
def get_logs(scan_id: str, backend: GraphBackend = Depends(get_backend)) -> dict[str, Any]:
    """The raw execution log — every probe (baseline + adversarial), in the
    order they actually ran, each with its events in causal order. See
    ``pwngraph.queries.scan_log`` for the underlying read. For a NEXUS-mode
    scan, pair this with ``GET /{scan_id}/nexus`` (matched by ``payload_id``)
    to show *why* NEXUS chose each adversarial probe alongside what happened.
    """
    rows = q.scan_log(backend, scan_id)
    if not rows:
        raise HTTPException(status_code=404, detail=f"No log found for scan_id={scan_id!r}")

    runs: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for row in rows:
        rid = row["run_id"]
        if rid not in runs:
            runs[rid] = {
                "run_id": rid,
                "is_adversarial": False,
                "payload_id": None,
                "attack_class": None,
                "events": [],
            }
            order.append(rid)
        run = runs[rid]
        if row["is_adversarial"]:
            run["is_adversarial"] = True
        if row["payload_id"]:
            run["payload_id"] = row["payload_id"]
        if row["attack_class"]:
            run["attack_class"] = row["attack_class"]
        run["events"].append(
            {
                "node_id": row["node_id"],
                "node_type": row["node_type"],
                "name": row["name"],
                "content": row["content"],
                "timestamp": row["timestamp"],
            }
        )
    return {"scan_id": scan_id, "runs": [runs[rid] for rid in order]}


@router.get("/{scan_id}/nexus", response_model=NexusStateResponse)
def get_nexus_state(scan_id: str, backend: GraphBackend = Depends(get_backend)) -> dict[str, Any]:
    """NEXUS's own decision history for this scan — each probe's action and
    rationale, plus the hypotheses it formed. 404s for a static-mode scan or
    one that predates this feature (adaptive mode is opt-in, and this data
    is only ever written by ``pwngraph.core.PwnGraph._run_nexus_loop``) —
    that's the honest answer, not an error; pair with ``GET
    /{scan_id}/logs`` (matched by ``payload_id``) which is always available.
    See ``pwngraph.report_store.load_nexus_state``.
    """
    state = load_nexus_state(backend, scan_id)
    if state is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"No NEXUS data for scan_id={scan_id!r} — this scan either ran in static "
                f"mode or predates this feature. The raw log is still available at "
                f"/{scan_id}/logs."
            ),
        )
    return state


@router.get("/{scan_id}/profile", response_model=ScanProfile)
def get_profile(scan_id: str, backend: GraphBackend = Depends(get_backend)) -> dict[str, Any]:
    """This scan's pre-attack recon profile — the agent's elicited purpose,
    observed tool behavior, confirmed/possible chains, and the resulting
    attack plan. 404s for a scan that ran with ``recon_budget=0`` or
    predates this feature — that's the honest answer, not an error; the
    graph and report for such a scan are still fully available.
    """
    profile = load_target_profile(backend, scan_id)
    if profile is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"No recon profile for scan_id={scan_id!r} — this scan either ran with "
                f"recon disabled or predates this feature."
            ),
        )
    return profile


@router.get("/{scan_id}/severity-breakdown")
def get_severity_breakdown(
    scan_id: str, backend: GraphBackend = Depends(get_backend)
) -> dict[str, int]:
    return q.severity_breakdown(backend, scan_id=scan_id)


@router.get("/{scan_id}/edge-breakdown")
def get_edge_breakdown(
    scan_id: str, backend: GraphBackend = Depends(get_backend)
) -> dict[str, int]:
    return q.adversarial_edge_breakdown(backend, scan_id=scan_id)


@router.get("/{scan_id}/blast-radius")
def get_blast_radius(
    scan_id: str,
    tool: str = Query(..., description="Tool name to compute the blast radius for."),
    backend: GraphBackend = Depends(get_backend),
) -> list[str]:
    """ "If an attacker fully controlled this tool's output, what else did
    the agent go on to touch?" — see ``pwngraph.attackpath.blast_radius``."""
    return blast_radius(backend, tool, scan_id=scan_id)


@router.get("/{scan_id}/compare", response_model=ScanCompare)
def compare_scans(
    scan_id: str,
    against: str = Query(..., description="scan_id of the earlier/baseline scan to diff against."),
    backend: GraphBackend = Depends(get_backend),
) -> dict[str, Any]:
    """Diff this scan's persisted report against an earlier one — the
    ``pwngraph diff`` regression story, read back without re-running either
    scan. See ``pwngraph.compare`` for how findings are matched across two
    reports that may have run in entirely separate processes."""
    after = load_scan_report(backend, scan_id)
    if after is None:
        raise HTTPException(status_code=404, detail=f"No stored report for scan_id={scan_id!r}")
    before = load_scan_report(backend, against)
    if before is None:
        raise HTTPException(status_code=404, detail=f"No stored report for scan_id={against!r}")
    return compare_reports(before, after)


@router.post("/{scan_id}/findings/{finding_id}/triage")
def update_finding_triage(
    scan_id: str,
    finding_id: str,
    body: TriageUpdate,
    backend: GraphBackend = Depends(get_backend),
) -> dict[str, Any]:
    """Set a finding's triage status — the one write path in this router.

    Every other route reads through ``GraphBackend``; this exists because
    findings otherwise have nowhere to accumulate the open/false-positive/
    accepted-risk/fixed lifecycle a scanner used past a single run needs.
    See ``pwngraph.report_store.set_finding_triage``.
    """
    if body.status not in TRIAGE_STATES:
        raise HTTPException(
            status_code=400,
            detail=f"invalid status {body.status!r}; must be one of {sorted(TRIAGE_STATES)}",
        )
    findings = set_finding_triage(backend, scan_id, finding_id, body.status, body.note)
    if findings is None:
        raise HTTPException(
            status_code=404, detail=f"No finding {finding_id!r} in scan_id={scan_id!r}"
        )
    return {"finding_id": finding_id, "status": body.status, "note": body.note}


@router.get("/{scan_id}/findings/{finding_id}/chain", response_model=FindingChain)
def get_finding_chain(
    scan_id: str, finding_id: str, backend: GraphBackend = Depends(get_backend)
) -> dict[str, Any]:
    """Node ids for the attack chain(s) behind one finding — what the
    graph view's "go to this finding" action fits its camera to. See
    ``pwngraph.attackpath.chain_for_payload`` for why this is keyed off the
    finding's ``payload_id`` rather than its (dropped) ``AttackPath``.
    """
    report = load_scan_report(backend, scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"No stored report for scan_id={scan_id!r}")
    finding = next((f for f in report["findings"] if f.get("finding_id") == finding_id), None)
    if finding is None:
        raise HTTPException(
            status_code=404, detail=f"No finding {finding_id!r} in scan_id={scan_id!r}"
        )
    nodes = chain_for_payload(backend, scan_id, finding["payload_id"])
    if not nodes:
        raise HTTPException(
            status_code=404, detail="No graph chain found for this finding's payload."
        )
    return {"nodes": nodes}


@router.get("/{scan_id}/export/graph.json")
def export_graph(scan_id: str, backend: GraphBackend = Depends(get_backend)) -> Response:
    """The same payload as ``GET /graph``, as a downloadable file — the
    browser-facing equivalent of ``pwngraph graph --scan-id``."""
    view = build_graph_view(backend, scan_id)
    if not view["nodes"]:
        raise HTTPException(status_code=404, detail=f"No graph found for scan_id={scan_id!r}")
    report = load_scan_report(backend, scan_id)
    payload = {"scan_id": scan_id, "target_name": report["target_name"] if report else "", **view}
    return Response(
        content=json.dumps(payload, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="graph-{scan_id}.json"'},
    )


@router.get("/{scan_id}/export/findings.sarif")
def export_findings_sarif(scan_id: str, backend: GraphBackend = Depends(get_backend)) -> Response:
    """This scan's findings as SARIF 2.1.0 — the browser-facing equivalent of
    the ``findings.sarif`` a CLI scan writes to ``--out``."""
    report = load_scan_report(backend, scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"No stored report for scan_id={scan_id!r}")
    findings = [Finding.model_validate(f) for f in report["findings"]]
    return Response(
        content=json.dumps(to_sarif(findings), indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="findings-{scan_id}.sarif"'},
    )


@router.get("/{scan_id}/export/poc.zip")
def export_poc_zip(scan_id: str, backend: GraphBackend = Depends(get_backend)) -> Response:
    """Every confirmed finding's PoC bundle (payload, replay command,
    write-up), zipped — the browser-facing equivalent of the CLI's ``poc/``
    output directory. Built on the fly; nothing is cached server-side."""
    report = load_scan_report(backend, scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"No stored report for scan_id={scan_id!r}")
    findings = [Finding.model_validate(f) for f in report["findings"]]
    if not findings:
        raise HTTPException(status_code=404, detail="This scan has no findings to export.")

    with tempfile.TemporaryDirectory() as tmp:
        poc_dir = Path(tmp) / "poc"
        export_all_pocs(findings, poc_dir)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in sorted(poc_dir.rglob("*")):
                if f.is_file():
                    zf.write(f, f.relative_to(poc_dir))
        body = buf.getvalue()

    return Response(
        content=body,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="poc-{scan_id}.zip"'},
    )


@router.get("/{scan_id}/query/{name}")
def run_named_query(
    scan_id: str,
    name: str,
    tool: str | None = Query(default=None),
    backend: GraphBackend = Depends(get_backend),
) -> list[dict[str, Any]]:
    """Generic dispatch through ``pwngraph.queries.QUERY_REGISTRY`` — any
    query registered there (present or future) is automatically reachable
    here with no new route needed."""
    if name not in q.QUERY_REGISTRY:
        raise HTTPException(status_code=404, detail=f"Unknown query {name!r}")
    try:
        return q.run(name, backend, scan_id=scan_id, tool=tool)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
