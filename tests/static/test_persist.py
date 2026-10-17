"""Tests for pwngraph.static.persist — writing a StructuralGraph into a backend."""

from __future__ import annotations

from _fake_backend import FakeGraphBackend

from pwngraph.static.identity import StructuralKey
from pwngraph.static.persist import persist_structural_graph
from pwngraph.static.reconcile import StructuralGraph
from pwngraph.static.schema import KIND_TOOL, EvidenceState, StructuralNode

_TARGET = "target-1"


def _node(name: str, evidence: EvidenceState, **metadata) -> StructuralNode:
    key = StructuralKey(_TARGET, KIND_TOOL, name)
    return StructuralNode(key=key, kind=KIND_TOOL, name=name, evidence=evidence, metadata=metadata)


def test_persist_writes_one_backend_node_per_structural_node():
    graph = StructuralGraph(target_id=_TARGET)
    a = _node("read_file", EvidenceState.POSSIBLE)
    b = _node("send_email", EvidenceState.EXPLOITED)
    graph.nodes = {a.node_id: a, b.node_id: b}

    backend = FakeGraphBackend()
    count = persist_structural_graph(graph, backend)

    assert count == 2
    assert backend.node_count == 2


def test_persist_preserves_evidence_and_name():
    graph = StructuralGraph(target_id=_TARGET)
    node = _node("send_email", EvidenceState.EXPLOITED)
    graph.nodes = {node.node_id: node}

    backend = FakeGraphBackend()
    persist_structural_graph(graph, backend)

    attrs = backend.node_attrs(node.node_id)
    assert attrs["name"] == "send_email"
    assert attrs["evidence"] == "exploited"
    assert attrs["kind"] == KIND_TOOL
    assert attrs["target_id"] == _TARGET


def test_persist_flattens_metadata_with_meta_prefix():
    graph = StructuralGraph(target_id=_TARGET)
    node = _node("read_file", EvidenceState.POSSIBLE, lineno=42, pattern="decorator")
    graph.nodes = {node.node_id: node}

    backend = FakeGraphBackend()
    persist_structural_graph(graph, backend)

    attrs = backend.node_attrs(node.node_id)
    assert attrs["meta_lineno"] == 42
    assert attrs["meta_pattern"] == "decorator"


def test_persist_empty_graph_writes_nothing():
    graph = StructuralGraph(target_id=_TARGET)
    backend = FakeGraphBackend()
    assert persist_structural_graph(graph, backend) == 0
    assert backend.node_count == 0


def test_persist_node_id_matches_structural_key_digest():
    graph = StructuralGraph(target_id=_TARGET)
    node = _node("send_email", EvidenceState.OBSERVED)
    graph.nodes = {node.node_id: node}

    backend = FakeGraphBackend()
    persist_structural_graph(graph, backend)

    assert backend.has_node(node.key.digest())


def test_persist_stamps_scan_id_when_given():
    graph = StructuralGraph(target_id=_TARGET)
    node = _node("read_file", EvidenceState.POSSIBLE)
    graph.nodes = {node.node_id: node}

    backend = FakeGraphBackend()
    persist_structural_graph(graph, backend, scan_id="scan-42")

    assert backend.node_attrs(node.node_id)["scan_id"] == "scan-42"


def test_persist_omits_scan_id_when_not_given():
    graph = StructuralGraph(target_id=_TARGET)
    node = _node("read_file", EvidenceState.POSSIBLE)
    graph.nodes = {node.node_id: node}

    backend = FakeGraphBackend()
    persist_structural_graph(graph, backend)

    assert "scan_id" not in backend.node_attrs(node.node_id)


def test_persist_never_regresses_evidence_across_scans():
    """A tool proved 'exploited' by an earlier scan must stay 'exploited'
    even if a later scan's own reconciliation only got it to 'possible' —
    e.g. the LLM didn't reproduce the finding this run."""
    backend = FakeGraphBackend()

    first = StructuralGraph(target_id=_TARGET)
    exploited_node = _node("send_email", EvidenceState.EXPLOITED)
    first.nodes = {exploited_node.node_id: exploited_node}
    persist_structural_graph(first, backend, scan_id="scan-1")

    second = StructuralGraph(target_id=_TARGET)
    # Same StructuralKey (target_id, kind, name) => same node_id, but this
    # run's reconciliation only re-discovered it statically.
    regressed_node = _node("send_email", EvidenceState.POSSIBLE)
    second.nodes = {regressed_node.node_id: regressed_node}
    persist_structural_graph(second, backend, scan_id="scan-2")

    attrs = backend.node_attrs(exploited_node.node_id)
    assert attrs["evidence"] == "exploited"
    assert attrs["scan_id"] == "scan-2"  # scan_id itself does move forward


def test_persist_promotes_when_new_evidence_is_stronger():
    backend = FakeGraphBackend()

    first = StructuralGraph(target_id=_TARGET)
    possible_node = _node("read_file", EvidenceState.POSSIBLE)
    first.nodes = {possible_node.node_id: possible_node}
    persist_structural_graph(first, backend, scan_id="scan-1")

    second = StructuralGraph(target_id=_TARGET)
    observed_node = _node("read_file", EvidenceState.OBSERVED)
    second.nodes = {observed_node.node_id: observed_node}
    persist_structural_graph(second, backend, scan_id="scan-2")

    assert backend.node_attrs(possible_node.node_id)["evidence"] == "observed"


def test_persist_merges_source_when_it_disagrees_with_prior_scan():
    backend = FakeGraphBackend()

    first = StructuralGraph(target_id=_TARGET)
    static_node = _node("read_file", EvidenceState.POSSIBLE)
    static_node.source = "static"
    first.nodes = {static_node.node_id: static_node}
    persist_structural_graph(first, backend)

    second = StructuralGraph(target_id=_TARGET)
    runtime_node = _node("read_file", EvidenceState.OBSERVED)
    runtime_node.source = "runtime"
    second.nodes = {runtime_node.node_id: runtime_node}
    persist_structural_graph(second, backend)

    assert backend.node_attrs(static_node.node_id)["source"] == "static+runtime"
