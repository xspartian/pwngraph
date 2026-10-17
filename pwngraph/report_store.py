"""Persist a scan's *report* — findings, ASR, OWASP coverage, risk grade — into
the graph backend, so it can be read back long after the scanning process exits.

Why this exists
---------------
``GraphBuilder`` persists the runtime trace graph (events, edges, and
``DangerousOutcome`` sink nodes carrying a severity/confidence subset). It does
*not* persist the reportable layer built on top of that: a :class:`Finding`'s
CVSS vector and score, steps to reproduce, impact, remediation, OWASP tags, and
ASR evidence are all synthesized in memory by ``PwnGraph._synthesize_findings``
and then handed straight to the Jinja2 reporter. Once the process ended, the
only copy lived in ``report.html``.

That was fine when the report was a file you opened. It isn't fine for
``pwngraph serve``, which reads a *past* scan out of Neo4j and has no in-memory
scan to draw from — the same gap ``build_graph_view``'s sink-walk fallback
works around for the graph. Rather than re-deriving findings from sink nodes
(which structurally cannot recover a CVSS vector or remediation text), the scan
now writes its finished report alongside the graph.

Shape
-----
One node per scan, ``kind="scan_report"``, id ``report::<scan_id>``. Neo4j
properties must be primitives or arrays of primitives, so the nested structures
(findings, ASR rollup, OWASP matrix, risk grade) are JSON-encoded into string
properties and decoded on read. Scalars worth querying directly
(``finding_count``, ``max_severity``, ``risk_grade``, ``target_name``) are also
stored as plain properties.

The node deliberately carries **no** ``node_type``, which is what keeps it out
of the runtime trace graph: ``build_graph_view`` skips any node without one, the
same way it already skips ``pwngraph.static``'s ``kind="tool"`` surface nodes.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from pwngraph.backend import GraphBackend

log = logging.getLogger(__name__)

KIND_SCAN_REPORT = "scan_report"

# Finding.paths carries the full AttackPath -> TraceEvent tree, which is both
# large and already fully represented by the trace graph itself (and rendered
# far better by the graph view than by any JSON blob). Steps to reproduce —
# the part of a path a reader actually needs — are already flattened onto the
# finding by _steps_for(), so dropping paths here loses no reportable detail.
_FINDING_EXCLUDE = {"paths"}


def report_node_id(scan_id: str) -> str:
    return f"report::{scan_id}"


def persist_scan_report(
    backend: GraphBackend,
    scan_id: str,
    *,
    target_name: str,
    tool_inventory: list[str],
    findings: list[Any],
    asr: dict[str, Any],
    owasp_coverage: list[dict[str, Any]],
    risk_grade: dict[str, Any],
    summary: dict[str, Any],
    scanned_at: str = "",
) -> str:
    """Write this scan's report into *backend*. Returns the node id.

    ``findings`` are :class:`pwngraph.types.Finding` models (anything with
    ``model_dump`` works). Re-persisting the same ``scan_id`` overwrites the
    previous report — ``add_node`` merges, and a scan's report is a complete
    snapshot rather than something accumulated incrementally.
    """
    finding_dicts = [
        f.model_dump(mode="json", exclude=_FINDING_EXCLUDE) if hasattr(f, "model_dump") else dict(f)
        for f in findings
    ]

    node_id = report_node_id(scan_id)
    backend.add_node(
        node_id,
        scan_id=scan_id,
        scanned_at=scanned_at,
        kind=KIND_SCAN_REPORT,
        target_name=target_name,
        # Queryable scalars — the summary a scan list can show without
        # decoding any of the JSON payloads below.
        finding_count=len(finding_dicts),
        risk_grade=str(risk_grade.get("grade", "")),
        risk_score=int(risk_grade.get("score", 0)),
        max_severity=_max_severity(finding_dicts),
        # Nested structures — JSON-encoded, see the module docstring.
        tool_inventory_json=json.dumps(list(tool_inventory)),
        findings_json=json.dumps(finding_dicts, default=str),
        asr_json=json.dumps(asr, default=str),
        owasp_json=json.dumps(owasp_coverage, default=str),
        risk_grade_json=json.dumps(risk_grade, default=str),
        summary_json=json.dumps(summary, default=str),
    )
    log.info(
        "Persisted scan report for scan_id=%s (%d finding(s), grade %s)",
        scan_id,
        len(finding_dicts),
        risk_grade.get("grade", "?"),
    )
    return node_id


def load_scan_report(backend: GraphBackend, scan_id: str) -> dict[str, Any] | None:
    """Read back a scan's report, or ``None`` when the scan never wrote one.

    ``None`` is the honest answer for any scan run before this module existed,
    or one whose process died before finishing — callers should treat it as
    "no report available for this scan", not an error.
    """
    attrs = backend.node_attrs(report_node_id(scan_id))
    if not attrs or attrs.get("kind") != KIND_SCAN_REPORT:
        return None

    return {
        "scan_id": scan_id,
        "target_name": attrs.get("target_name", ""),
        "scanned_at": attrs.get("scanned_at", ""),
        "tool_inventory": _load_json(attrs.get("tool_inventory_json"), []),
        "findings": _load_json(attrs.get("findings_json"), []),
        "asr": _load_json(attrs.get("asr_json"), {}),
        "owasp_coverage": _load_json(attrs.get("owasp_json"), []),
        "risk_grade": _load_json(attrs.get("risk_grade_json"), {}),
        "summary": _load_json(attrs.get("summary_json"), {}),
    }


KIND_NEXUS_STATE = "nexus_state"


def nexus_state_node_id(scan_id: str) -> str:
    return f"nexus_state::{scan_id}"


def persist_nexus_state(backend: GraphBackend, scan_id: str, state: Any) -> str:
    """Write a NEXUS-mode scan's decision history into *backend*. Returns the
    node id.

    ``state`` is a :class:`pwngraph.nexus.state.AttackState` (anything with
    ``model_dump`` works, same convention as ``persist_scan_report``'s
    ``findings``). NEXUS's own reasoning — each ``Observation.rationale``
    and the hypotheses it formed along the way — is otherwise purely
    in-memory and lost the moment the scanning process exits; this is what
    lets ``pwngraph serve``'s Logs tab show *why* NEXUS chose each probe for
    a scan it didn't run in-process. Static-mode scans simply never call
    this — a scan with no such node is not an error, see ``load_nexus_state``.
    """
    dumped = state.model_dump(mode="json") if hasattr(state, "model_dump") else dict(state)
    observations = dumped.get("observations", [])
    hypotheses = dumped.get("hypotheses", [])

    node_id = nexus_state_node_id(scan_id)
    backend.add_node(
        node_id,
        scan_id=scan_id,
        kind=KIND_NEXUS_STATE,
        # Queryable scalars.
        status=str(dumped.get("status", "")),
        iteration=int(dumped.get("iteration", 0)),
        budget=int(dumped.get("budget", 0)),
        confidence=float(dumped.get("confidence", 0.0)),
        level=int(dumped.get("level", 1)),
        # Nested structures — JSON-encoded, same convention as
        # persist_scan_report's findings/asr/owasp payloads.
        observations_json=json.dumps(observations, default=str),
        hypotheses_json=json.dumps(hypotheses, default=str),
        successful_techniques_json=json.dumps(dumped.get("successful_techniques", []), default=str),
        failed_techniques_json=json.dumps(dumped.get("failed_techniques", []), default=str),
        discovered_capabilities_json=json.dumps(
            dumped.get("discovered_capabilities", []), default=str
        ),
    )
    log.info(
        "Persisted NEXUS state for scan_id=%s (%d observation(s), %d hypothesis/es, status=%s)",
        scan_id,
        len(observations),
        len(hypotheses),
        dumped.get("status", "?"),
    )
    return node_id


def load_nexus_state(backend: GraphBackend, scan_id: str) -> dict[str, Any] | None:
    """Read back a scan's NEXUS decision history, or ``None`` when the scan
    never ran in NEXUS mode (or predates this feature) — callers should
    treat ``None`` as "no NEXUS data for this scan", not an error, same as
    ``load_scan_report``.
    """
    attrs = backend.node_attrs(nexus_state_node_id(scan_id))
    if not attrs or attrs.get("kind") != KIND_NEXUS_STATE:
        return None

    return {
        "scan_id": scan_id,
        "status": attrs.get("status", ""),
        "iteration": attrs.get("iteration", 0),
        "budget": attrs.get("budget", 0),
        "confidence": attrs.get("confidence", 0.0),
        "level": attrs.get("level", 1),
        "observations": _load_json(attrs.get("observations_json"), []),
        "hypotheses": _load_json(attrs.get("hypotheses_json"), []),
        "successful_techniques": _load_json(attrs.get("successful_techniques_json"), []),
        "failed_techniques": _load_json(attrs.get("failed_techniques_json"), []),
        "discovered_capabilities": _load_json(attrs.get("discovered_capabilities_json"), []),
    }


KIND_TARGET_PROFILE = "target_profile"


def target_profile_node_id(scan_id: str) -> str:
    return f"profile::{scan_id}"


def persist_target_profile(backend: GraphBackend, scan_id: str, profile: Any) -> str:
    """Write a scan's pre-attack recon profile into *backend*. Returns the
    node id.

    ``profile`` is a :class:`pwngraph.recon.TargetProfile` (anything with
    ``model_dump`` works, same convention as ``persist_nexus_state``'s
    ``state``). Recon's findings — the elicited purpose, per-tool observed
    behavior, confirmed/possible chains, and the derived attack plan — are
    otherwise purely in-memory and lost the moment the scanning process
    exits; this is what lets ``pwngraph serve``'s Profile tab show them for a
    scan it didn't run in-process. A scan that skipped recon (or predates
    this feature) simply never calls this — not an error, see
    ``load_target_profile``.
    """
    dumped = profile.model_dump(mode="json") if hasattr(profile, "model_dump") else dict(profile)

    node_id = target_profile_node_id(scan_id)
    backend.add_node(
        node_id,
        scan_id=scan_id,
        kind=KIND_TARGET_PROFILE,
        # Queryable scalars.
        target_name=str(dumped.get("target_name", "")),
        objective=str(dumped.get("objective", "")),
        calls_used=int(dumped.get("calls_used", 0)),
        tool_count=len(dumped.get("tools", [])),
        confirmed_chain_count=sum(
            1 for c in dumped.get("chains", []) if c.get("kind") == "confirmed_chain"
        ),
        # Nested structures — JSON-encoded, same convention as
        # persist_nexus_state's observations/hypotheses payloads.
        purpose_probes_json=json.dumps(dumped.get("purpose_probes", []), default=str),
        tools_json=json.dumps(dumped.get("tools", []), default=str),
        chains_json=json.dumps(dumped.get("chains", []), default=str),
        attack_plan_json=json.dumps(dumped.get("attack_plan", []), default=str),
    )
    log.info(
        "Persisted target profile for scan_id=%s (%d tool(s), objective=%r)",
        scan_id,
        len(dumped.get("tools", [])),
        dumped.get("objective", ""),
    )
    return node_id


def load_target_profile(backend: GraphBackend, scan_id: str) -> dict[str, Any] | None:
    """Read back a scan's recon profile, or ``None`` when the scan skipped
    recon (or predates this feature) — callers should treat ``None`` as "no
    profile for this scan", not an error, same as ``load_nexus_state``.
    """
    attrs = backend.node_attrs(target_profile_node_id(scan_id))
    if not attrs or attrs.get("kind") != KIND_TARGET_PROFILE:
        return None

    return {
        "scan_id": scan_id,
        "target_name": attrs.get("target_name", ""),
        "objective": attrs.get("objective", ""),
        "calls_used": attrs.get("calls_used", 0),
        "purpose_probes": _load_json(attrs.get("purpose_probes_json"), []),
        "tools": _load_json(attrs.get("tools_json"), []),
        "chains": _load_json(attrs.get("chains_json"), []),
        "attack_plan": _load_json(attrs.get("attack_plan_json"), []),
    }


TRIAGE_STATES = {"open", "false_positive", "accepted_risk", "fixed"}


def set_finding_triage(
    backend: GraphBackend,
    scan_id: str,
    finding_id: str,
    status: str,
    note: str | None = None,
) -> list[dict[str, Any]] | None:
    """Set a finding's triage status (and optional note) in its persisted
    report. Returns the updated findings list, or ``None`` if the scan has
    no stored report or no finding with that id.

    This is the one write path in ``pwngraph.api`` — everything else under
    ``/api`` only ever reads through ``GraphBackend``. Findings live inside
    the report node's ``findings_json`` blob (see the module docstring), so
    "update one finding" means read the blob, patch the matching entry, and
    write the whole list back — there's no per-finding node to address
    directly. ``add_node`` merges, so this only overwrites ``findings_json``
    and leaves every other property on the report node untouched.
    """
    node_id = report_node_id(scan_id)
    attrs = backend.node_attrs(node_id)
    if not attrs or attrs.get("kind") != KIND_SCAN_REPORT:
        return None

    findings = _load_json(attrs.get("findings_json"), [])
    updated = False
    for f in findings:
        if f.get("finding_id") == finding_id:
            f["triage_status"] = status
            if note is not None:
                f["triage_note"] = note
            updated = True
            break
    if not updated:
        return None

    backend.add_node(node_id, findings_json=json.dumps(findings, default=str))
    return findings


def _load_json(raw: Any, fallback: Any) -> Any:
    """Decode a JSON property, degrading to *fallback* rather than raising.

    A malformed payload should cost the reader that one section, not the whole
    report — the same "degrade honestly" stance the static extractor takes on a
    syntax error.
    """
    if not raw:
        return fallback
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        log.warning("Malformed JSON in scan report property; returning empty.")
        return fallback


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _max_severity(findings: list[dict[str, Any]]) -> str:
    best = ""
    best_rank = -1
    for f in findings:
        sev = str(f.get("severity", ""))
        rank = _SEVERITY_RANK.get(sev, -1)
        if rank > best_rank:
            best_rank = rank
            best = sev
    return best
