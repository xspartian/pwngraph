"""Graph-view assembly for one scan's runtime trace graph.

Reads a scan's runtime graph directly out of its
:class:`~pwngraph.backend.GraphBackend` (Neo4j in practice) and shapes it
into a plain nodes/edges/findings payload — no rendering library involved.
:func:`build_graph_view` is the single source of truth for that shaping,
shared by two consumers that must never drift apart:

* :func:`export_graph_json` — writes ``graph.json``, an offline/CI artifact
  (``pwngraph scan`` / ``pwngraph graph --scan-id``).
* ``GET /api/scans/{id}/graph`` (``pwngraph/api/routers/scans.py``) — the
  live view ``pwngraph serve``'s React/Sigma.js/Graphology frontend renders.
  That live view always reads Neo4j directly through this same function; it
  never depends on ``graph.json`` having been written first.

This module previously rendered ``graph.html`` via pyvis (which pulled
NetworkX back in transitively as one of its own dependencies, even though
nothing here ever built an in-memory graph with it). That rendering layer —
and pyvis/NetworkX as dependencies — has been removed entirely now that the
live viewer covers the same ground directly from Neo4j. The BloodHound-style
control surface pyvis used to carry (findings panel, search, "attack paths
only"/"critical only" filters, "find choke point", a workflow view,
click-to-trace) is ported to the React/Graphology frontend, not lost.

Deliberately excludes the static-analysis surface (``kind="tool"`` nodes from
``pwngraph.static.persist``): those aren't connected by any edge (static
extraction and runtime tracing are separate passes — see
``pwngraph.static.reconcile``), so they'd only add disconnected dots with no
relationships to show. That surface already has its own view
(``evidence_ladder.json``, ``pwngraph query evidence-coverage``).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from pwngraph.backend import GraphBackend
from pwngraph.types import NodeType

log = logging.getLogger(__name__)

_SEV_SCORE = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def build_graph_view(
    backend: GraphBackend,
    scan_id: str,
    *,
    dangerous_paths: list[Any] | None = None,
    report_findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Assemble ``{"nodes": [...], "edges": [...], "findings": [...]}`` for
    one scan's runtime trace graph.

    Reads directly from *backend* at call time — always a live snapshot of
    what's actually in the database for ``scan_id``, never cached or
    recomputed. This is the shared payload both ``export_graph_json`` and
    the ``/api/scans/{id}/graph`` route return, so the offline artifact and
    the live view stay identical.

    Three ways to get the findings list, tried in this order:

    * ``dangerous_paths`` — a scan's ``list[AttackPath]`` (``pg.paths``),
      available only in the same process a scan just ran in. Each path's
      ``events`` are ``TraceEvent``s whose ``event_id`` is the same id used
      as the graph node id, so a path's node sequence maps directly onto
      exported node ids with no extra lookup — the exact set
      ``PwnGraph._synthesize_findings`` turned into the persisted report.
    * ``report_findings`` — the scan's persisted ``Finding`` records (see
      ``pwngraph.report_store``), for every other reader: a ``pwngraph
      serve`` read of a past scan, or the standalone ``pwngraph graph
      --scan-id`` re-export. Each finding's chain is reconstructed via
      ``pwngraph.attackpath.chain_for_payload`` — the same payload_id join
      "View attack chain" already uses — so the graph's findings list is
      *exactly* the report's findings list, not a second, independently
      -computed approximation of it. This is what keeps "7 findings" in the
      report and "7 chains" in the graph from ever disagreeing.
    * Neither — a scan that predates ``report_store`` (or whose process died
      before persisting one). Findings are reconstructed by walking backward
      from every ``dangerous`` sink node through the graph itself. This is
      the weakest of the three: without ``AttackPath.signature()``'s exact
      dedup, a chain whose surrounding reasoning steps vary between two
      otherwise-identical trials can still show up as more than one row.
    """
    node_ids = backend.find_nodes(scan_id=scan_id)

    nodes: list[dict[str, Any]] = []
    runtime_ids: set[str] = set()
    for nid in node_ids:
        attrs = backend.node_attrs(nid)
        ntype = attrs.get("node_type")
        if ntype is None:
            continue  # static-surface node — not part of the runtime trace graph
        runtime_ids.add(nid)

        color = attrs.get("color") or "#3498DB"
        if ntype == NodeType.DANGEROUS_OUTCOME.value:
            # The near-black sink colour is invisible on a dark canvas —
            # make the most important node the brightest one on screen.
            color = "#FF2E63"

        nodes.append(
            {
                "id": nid,
                "label": attrs.get("label") or nid[:8],
                "color": color,
                "shape": attrs.get("shape") or "dot",
                "node_type": ntype,
                "is_adversarial": bool(attrs.get("is_adversarial")),
                "name": attrs.get("name") or "",
                "content": attrs.get("content") or "",
                "payload_id": attrs.get("payload_id") or "",
                "severity": attrs.get("outcome_severity") or "",
                "confidence": attrs.get("confidence") or "",
            }
        )

    edges: list[dict[str, Any]] = []
    for src, dst, attrs in backend.edges():
        if src not in runtime_ids or dst not in runtime_ids:
            continue
        edges.append(
            {
                "source": src,
                "target": dst,
                "color": attrs.get("color") or "#BDC3C7",
                "label": attrs.get("label") or "",
                "edge_type": attrs.get("edge_type") or "",
                "is_adversarial": bool(attrs.get("is_adversarial")),
                "dashes": bool(attrs.get("dashes")),
            }
        )

    if dangerous_paths:
        findings = _findings_from_paths(dangerous_paths, runtime_ids)
    elif report_findings is not None:
        findings = _findings_from_report(backend, scan_id, report_findings, runtime_ids)
    else:
        findings = _findings_from_sinks(backend, scan_id, runtime_ids)

    return {"nodes": nodes, "edges": edges, "findings": findings}


def export_graph_json(
    backend: GraphBackend,
    scan_id: str,
    output_path: Path,
    *,
    target_name: str = "",
    dangerous_paths: list[Any] | None = None,
) -> Path:
    """Write one scan's runtime graph to *output_path* as plain JSON.

    An offline/CI artifact only — ``pwngraph serve`` always reads Neo4j
    directly through :func:`build_graph_view`, never this file. See that
    function for the live-snapshot guarantee and ``dangerous_paths``
    semantics.
    """
    report_findings = None
    if dangerous_paths is None:
        # No live scan handed findings over directly (the standalone
        # `pwngraph graph --scan-id` re-export case) — read them from the
        # persisted report instead of re-deriving an approximation, exactly
        # like the live API route does. See build_graph_view's "three ways".
        from pwngraph.report_store import load_scan_report

        report = load_scan_report(backend, scan_id)
        if report is not None:
            report_findings = report["findings"]
            if not target_name:
                target_name = report["target_name"]

    view = build_graph_view(
        backend, scan_id, dangerous_paths=dangerous_paths, report_findings=report_findings
    )
    payload = {"scan_id": scan_id, "target_name": target_name, **view}

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    log.info(
        "Graph exported to %s (%d nodes, %d edges, %d findings)",
        output_path,
        len(view["nodes"]),
        len(view["edges"]),
        len(view["findings"]),
    )
    return output_path


def _findings_from_paths(dangerous_paths: list[Any], runtime_ids: set[str]) -> list[dict[str, Any]]:
    """Findings list entries from a scan's real, deduped ``AttackPath``s —
    same shape the pre-migration ``_findings_payload`` produced.

    Only ``confidence == "high"`` paths qualify — the exact gate
    ``PwnGraph._synthesize_findings`` uses to turn a path into a persisted
    ``Finding``. Without this, a live scan's own ``graph.json`` (this
    function's only caller with real ``dangerous_paths`` in hand) could show
    more "findings" than the report it's sitting next to: a low-confidence
    "canary echoed in the final answer, verify manually" path is a real
    dangerous *path* — GraphBuilder counts it as one of the scan's N unique
    paths — but was never reportable as a *finding*, and shouldn't look like
    one here either.
    """
    ranked = sorted(
        (p for p in dangerous_paths if getattr(p, "confidence", "high") == "high"),
        key=lambda p: -p.severity.score,
    )
    out: list[dict[str, Any]] = []
    for p in ranked:
        node_ids = [ev.event_id for ev in p.events if ev.event_id in runtime_ids]
        if not node_ids:
            continue
        tool_chain = [ev.name for ev in p.events if ev.node_type is NodeType.TOOL_CALL]
        label = (
            " → ".join(tool_chain) if tool_chain else (p.events[-1].name if p.events else "path")
        )
        out.append(
            {
                "i": len(out),
                "severity": getattr(p.severity, "value", str(p.severity)),
                "confidence": p.confidence,
                "label": label,
                "nodes": node_ids,
            }
        )
    return out


def _findings_from_report(
    backend: GraphBackend,
    scan_id: str,
    report_findings: list[dict[str, Any]],
    runtime_ids: set[str],
) -> list[dict[str, Any]]:
    """Findings list entries built from the scan's own persisted, already-
    deduplicated ``Finding`` records — see the "three ways" note on
    :func:`build_graph_view`. Every persisted ``Finding`` was synthesized
    only from a ``confidence == "high"`` path (see
    ``PwnGraph._synthesize_findings``), so every row here is confidence
    "high" too — there is no lower-confidence case a persisted Finding
    could represent.
    """
    from pwngraph.attackpath import chain_for_payload

    out: list[dict[str, Any]] = []
    for f in report_findings:
        payload_id = f.get("payload_id")
        if not payload_id:
            continue
        node_ids = [n for n in chain_for_payload(backend, scan_id, payload_id) if n in runtime_ids]
        if not node_ids:
            continue
        out.append(
            {
                "i": len(out),
                "severity": str(f.get("severity", "medium")),
                "confidence": "high",
                "label": str(f.get("title") or f.get("attack_class") or "finding"),
                "nodes": node_ids,
            }
        )
    out.sort(key=lambda r: -_SEV_SCORE.get(r["severity"], 0))
    for i, r in enumerate(out):
        r["i"] = i
    return out


def _findings_from_sinks(
    backend: GraphBackend, scan_id: str, runtime_ids: set[str]
) -> list[dict[str, Any]]:
    """Fallback findings for a live read with no ``AttackPath`` list to draw
    from — reconstructed by walking backward from each ``dangerous`` sink
    node through the graph.

    Deduplicated by structural shape (the ``(node_type, name)`` sequence
    along the chain — the same signature ``AttackPath.signature()`` uses).
    A live scan's own path-finding already collapses structurally identical
    chains down to one instance (``GraphBuilder.find_dangerous_paths``'s
    "many fuzz iterations produce structurally identical paths" dedup —
    every ``trials > 1`` re-delivery of the same payload is exactly this
    case), but this fallback — the only path a ``pwngraph serve`` read of a
    past scan ever takes, since there's no in-memory ``dangerous_paths`` to
    hand over — walked every sink independently and had no such dedup, so a
    scan with real repetition showed as many multiples of the same chain
    shape as it had successful trials. Keeps the highest-severity instance
    of each shape.
    """
    rev_adj: dict[str, list[str]] = {}
    for src, dst, _attrs in backend.edges():
        if src in runtime_ids and dst in runtime_ids:
            rev_adj.setdefault(dst, []).append(src)

    sinks = backend.find_nodes(scan_id=scan_id, node_type=NodeType.DANGEROUS_OUTCOME.value)
    by_signature: dict[str, dict[str, Any]] = {}
    for nid in sinks:
        attrs = backend.node_attrs(nid)
        seen = {nid}
        order = [nid]
        queue = [nid]
        while queue:
            cur = queue.pop(0)
            for src in rev_adj.get(cur, []):
                if src not in seen:
                    seen.add(src)
                    order.append(src)
                    queue.append(src)
        order.reverse()

        tool_names = []
        sig_parts = []
        for oid in order:
            oattrs = backend.node_attrs(oid)
            sig_parts.append(f"{oattrs.get('node_type', '')}:{oattrs.get('name', '')}")
            if oattrs.get("node_type") == NodeType.TOOL_CALL.value:
                tool_names.append(oattrs.get("name") or "")
        label = " → ".join(n for n in tool_names if n) or attrs.get("label") or "path"
        signature = "|".join(sig_parts)

        row: dict[str, Any] = {
            "severity": attrs.get("outcome_severity") or "medium",
            "confidence": attrs.get("confidence") or "medium",
            "label": label,
            "nodes": order,
        }
        existing = by_signature.get(signature)
        if existing is None or _SEV_SCORE.get(row["severity"], 0) > _SEV_SCORE.get(
            existing["severity"], 0
        ):
            by_signature[signature] = row

    rows = list(by_signature.values())
    rows.sort(key=lambda r: -_SEV_SCORE.get(r["severity"], 0))
    for i, r in enumerate(rows):
        r["i"] = i
    return rows
