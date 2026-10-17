"""Merge a static structural surface with a completed scan's runtime graph.

This is the reconciliation step the roadmap calls out as the hard part of
Phase 1: a statically-found ``ExtractedTool`` and a runtime-observed tool name
must resolve to the *same* :class:`~pwngraph.static.schema.StructuralNode`, or
evidence never promotes and every tool looks perpetually unconfirmed.

Deliberately decoupled from ``pwngraph.core``: this module only consumes a
:class:`~pwngraph.backend.GraphBackend` and a list of
:class:`~pwngraph.types.AttackPath`, both of which a completed
``PwnGraph.scan()`` already produces (``pg.graph_builder.graph`` and
``pg.paths``). Nothing here needs to know how the scan was run.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from pwngraph.backend import GraphBackend
from pwngraph.static.identity import StructuralKey
from pwngraph.static.langchain_extractor import ExtractedTool
from pwngraph.static.schema import KIND_TOOL, EvidenceState, StructuralNode, promote
from pwngraph.types import AttackPath, NodeType


@dataclass
class StructuralGraph:
    """The reconciled surface for one scanned target."""

    target_id: str
    nodes: dict[str, StructuralNode] = field(default_factory=dict)

    def by_evidence(self, state: EvidenceState) -> list[StructuralNode]:
        return [n for n in self.nodes.values() if n.evidence is state]

    @property
    def possible_only(self) -> list[StructuralNode]:
        """Tools that exist in code but the scan never triggered.

        The question no runtime-only graph can answer: this list is the part
        of the attack surface a scan with more iterations, a better delivery
        prompt, or a different attack class might still reach.
        """
        return self.by_evidence(EvidenceState.POSSIBLE)

    def coverage(self) -> dict[str, int]:
        """Node count per evidence state, e.g. ``{"possible": 3, "exploited": 1}``.

        States with zero nodes are omitted, not zero-filled — callers that
        need all four present should use ``EvidenceState`` directly.
        """
        counts: dict[str, int] = {}
        for node in self.nodes.values():
            counts[node.evidence.value] = counts.get(node.evidence.value, 0) + 1
        return counts

    def to_summary(self) -> dict[str, Any]:
        """A plain-dict, JSON-serializable view of this graph.

        Sorted by evidence rank (highest first) then name, so the most
        interesting nodes — the exploited ones — lead a printed or written
        summary rather than sitting wherever dict iteration happened to land.
        """
        nodes = sorted(self.nodes.values(), key=lambda n: (-n.evidence.rank, n.name))
        return {
            "target_id": self.target_id,
            "coverage": self.coverage(),
            "nodes": [
                {
                    "name": n.name,
                    "kind": n.kind,
                    "evidence": n.evidence.value,
                    "source": n.source,
                    "description": n.description,
                }
                for n in nodes
            ],
        }


def reconcile(
    target_id: str,
    static_tools: Iterable[ExtractedTool],
    runtime_backend: GraphBackend,
    dangerous_paths: Iterable[AttackPath],
    scan_id: str | None = None,
) -> StructuralGraph:
    """Build a :class:`StructuralGraph` by promoting static findings with runtime evidence.

    Three passes, each strictly additive — a node's evidence only ever moves
    up the ladder (see :func:`~pwngraph.static.schema.promote`):

    1. Seed one node per statically-extracted tool, at ``possible``.
    2. Promote to ``observed`` every tool name that appears on a ``tool_call``
       node in the runtime graph — including tools the static pass missed
       (a dynamically bound tool, say), which are registered fresh here with
       ``source="runtime"`` rather than dropped.
    3. Promote to ``validated`` or ``exploited`` using the dangerous paths a
       scan already found: ``exploited`` for a high-confidence path (a
       reportable finding), ``validated`` for a lower-confidence one (the
       oracle saw a divergence, but it didn't clear the bar for a finding).

    ``scan_id``, when given, scopes step 2 to nodes this scan itself wrote
    (``GraphBuilder.scan_id``). ``runtime_backend`` is a persistent, shared
    Neo4j graph, not a fresh in-process one — without this, a tool that
    happened to share a name with one called in a *different* scan of a
    *different* target on the same server would get promoted to ``observed``
    on no evidence from this scan at all.
    """
    graph = StructuralGraph(target_id=target_id)

    for tool in static_tools:
        key = StructuralKey(target_id, KIND_TOOL, tool.name)
        graph.nodes[key.digest()] = StructuralNode(
            key=key,
            kind=KIND_TOOL,
            name=tool.name,
            description=tool.description,
            evidence=EvidenceState.POSSIBLE,
            source="static",
            metadata={"lineno": tool.lineno, "pattern": tool.pattern},
        )

    _promote_observed(graph, target_id, runtime_backend, scan_id)
    _promote_from_paths(graph, target_id, dangerous_paths)

    return graph


def _promote_observed(
    graph: StructuralGraph, target_id: str, backend: GraphBackend, scan_id: str | None
) -> None:
    match: dict[str, Any] = {"node_type": NodeType.TOOL_CALL.value}
    if scan_id is not None:
        match["scan_id"] = scan_id
    called_names = {
        backend.node_attrs(node_id).get("name") for node_id in backend.find_nodes(**match)
    }
    called_names.discard(None)
    for name in called_names:
        if name is None:
            continue
        _touch(graph, target_id, name, EvidenceState.OBSERVED, source_if_new="runtime")


def _promote_from_paths(
    graph: StructuralGraph, target_id: str, dangerous_paths: Iterable[AttackPath]
) -> None:
    for path in dangerous_paths:
        target_state = (
            EvidenceState.EXPLOITED if path.confidence == "high" else EvidenceState.VALIDATED
        )
        for ev in path.events:
            if ev.node_type is not NodeType.TOOL_CALL:
                continue
            _touch(graph, target_id, ev.name, target_state, source_if_new="runtime")


def _touch(
    graph: StructuralGraph,
    target_id: str,
    tool_name: str,
    candidate: EvidenceState,
    *,
    source_if_new: str,
) -> None:
    key = StructuralKey(target_id, KIND_TOOL, tool_name)
    node_id = key.digest()
    existing = graph.nodes.get(node_id)

    if existing is None:
        graph.nodes[node_id] = StructuralNode(
            key=key,
            kind=KIND_TOOL,
            name=tool_name,
            evidence=candidate,
            source=source_if_new,
        )
        return

    new_evidence = promote(existing.evidence, candidate)
    new_source = existing.source if existing.source == source_if_new else "static+runtime"
    if new_evidence is not existing.evidence or new_source != existing.source:
        existing.evidence = new_evidence
        existing.source = new_source
