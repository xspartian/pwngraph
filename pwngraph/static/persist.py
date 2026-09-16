"""Persist a reconciled StructuralGraph into any GraphBackend.

Closes the loop between the static analysis layer (``pwngraph.static``) and
the storage layer (``pwngraph.backend``): once :func:`~pwngraph.static.reconcile.reconcile`
has built a :class:`~pwngraph.static.reconcile.StructuralGraph`, this writes
every node into a backend through the same :class:`~pwngraph.backend.GraphBackend`
contract used everywhere else, so it works unmodified against
``Neo4jBackend`` for a persistent graph a later scan (or a diff) can reopen.
"""

from __future__ import annotations

from pwngraph.backend import GraphBackend
from pwngraph.static.reconcile import StructuralGraph
from pwngraph.static.schema import EvidenceState, promote


def persist_structural_graph(
    graph: StructuralGraph, backend: GraphBackend, *, scan_id: str | None = None
) -> int:
    """Write every node in *graph* into *backend*. Returns the count written.

    A :class:`StructuralNode`'s id is a stable digest of ``(target_id, kind,
    name)`` (see ``StructuralKey``), so re-scanning the same target writes the
    *same* node again rather than a new one — that is how evidence persists
    across scans. But :func:`~pwngraph.static.reconcile.reconcile` only knows
    about *this* scan's runtime graph, so a re-scan that doesn't happen to
    re-trigger a tool an earlier scan proved ``exploited`` would otherwise
    silently overwrite that evidence back down to ``possible``. Before writing,
    each node's evidence and source are merged with whatever is already in the
    backend for that id, so evidence here obeys the same "only ever
    strengthens" rule the in-memory reconciliation already guarantees within a
    single scan (:func:`~pwngraph.static.schema.promote`).

    ``scan_id``, when given, is stamped onto every node so query-layer callers
    (``pwngraph.queries``) can scope a read to "the surface as of this scan"
    the same way ``GraphBuilder`` already scopes the runtime graph.
    """
    count = 0
    for node in graph.nodes.values():
        existing = backend.node_attrs(node.node_id)

        evidence = node.evidence
        source = node.source
        if existing:
            existing_evidence = existing.get("evidence")
            if existing_evidence:
                evidence = promote(EvidenceState(existing_evidence), evidence)
            existing_source = existing.get("source")
            if existing_source and existing_source != source:
                source = "static+runtime"

        meta_attrs = {f"meta_{k}": v for k, v in node.metadata.items()}
        attrs = {
            "target_id": graph.target_id,
            "kind": node.kind,
            "name": node.name,
            "description": node.description,
            "evidence": evidence.value,
            "source": source,
            **meta_attrs,
        }
        if scan_id is not None:
            attrs["scan_id"] = scan_id
        backend.add_node(node.node_id, **attrs)
        count += 1
    return count
