"""Tests for pwngraph.static.reconcile — merging static and runtime evidence."""

from __future__ import annotations

from _fake_backend import FakeGraphBackend

from pwngraph.static.identity import StructuralKey
from pwngraph.static.langchain_extractor import ExtractedTool
from pwngraph.static.reconcile import reconcile
from pwngraph.static.schema import KIND_TOOL, EvidenceState
from pwngraph.types import AttackPath, EdgeType, NodeType, TraceEvent

_TARGET = "target-1"


def _static(*names: str) -> list[ExtractedTool]:
    return [ExtractedTool(name=n, description="", lineno=1, pattern="decorator") for n in names]


def _tool_call_node(backend: FakeGraphBackend, node_id: str, name: str) -> None:
    backend.add_node(node_id, node_type=NodeType.TOOL_CALL.value, name=name)


def _path_with_tool_call(name: str, confidence: str) -> AttackPath:
    ev = TraceEvent(run_id="r1", node_type=NodeType.TOOL_CALL, name=name, content="args")
    return AttackPath(events=[ev], edge_types=[EdgeType.TOOL_MANIPULATION], confidence=confidence)


# ---------------------------------------------------------------------------
# Baseline: static-only stays possible
# ---------------------------------------------------------------------------


def test_tool_never_touched_at_runtime_stays_possible():
    backend = FakeGraphBackend()
    graph = reconcile(_TARGET, _static("never_called"), backend, [])

    key = StructuralKey(_TARGET, KIND_TOOL, "never_called")
    node = graph.nodes[key.digest()]

    assert node.evidence is EvidenceState.POSSIBLE
    assert node.source == "static"


def test_possible_only_lists_untouched_tools():
    backend = FakeGraphBackend()
    _tool_call_node(backend, "n1", "used_tool")
    graph = reconcile(_TARGET, _static("used_tool", "unused_tool"), backend, [])

    names = {n.name for n in graph.possible_only}
    assert names == {"unused_tool"}


# ---------------------------------------------------------------------------
# Promotion to observed
# ---------------------------------------------------------------------------


def test_runtime_tool_call_promotes_to_observed():
    backend = FakeGraphBackend()
    _tool_call_node(backend, "n1", "read_file")
    graph = reconcile(_TARGET, _static("read_file"), backend, [])

    key = StructuralKey(_TARGET, KIND_TOOL, "read_file")
    node = graph.nodes[key.digest()]

    assert node.evidence is EvidenceState.OBSERVED
    assert node.source == "static+runtime"


def test_tool_observed_at_runtime_but_missing_from_static_pass_is_registered():
    # e.g. a dynamically bound tool the AST walk could not see.
    backend = FakeGraphBackend()
    _tool_call_node(backend, "n1", "bound_tool")
    graph = reconcile(_TARGET, _static(), backend, [])

    key = StructuralKey(_TARGET, KIND_TOOL, "bound_tool")
    node = graph.nodes[key.digest()]

    assert node.evidence is EvidenceState.OBSERVED
    assert node.source == "runtime"


def test_non_tool_call_nodes_do_not_affect_reconciliation():
    backend = FakeGraphBackend()
    backend.add_node("n1", node_type=NodeType.FINAL_ANSWER.value, name="agent")
    graph = reconcile(_TARGET, _static("read_file"), backend, [])

    key = StructuralKey(_TARGET, KIND_TOOL, "read_file")
    assert graph.nodes[key.digest()].evidence is EvidenceState.POSSIBLE


# ---------------------------------------------------------------------------
# Promotion from dangerous paths — validated / exploited
# ---------------------------------------------------------------------------


def test_high_confidence_path_promotes_to_exploited():
    backend = FakeGraphBackend()
    path = _path_with_tool_call("send_email", confidence="high")
    graph = reconcile(_TARGET, _static("send_email"), backend, [path])

    key = StructuralKey(_TARGET, KIND_TOOL, "send_email")
    assert graph.nodes[key.digest()].evidence is EvidenceState.EXPLOITED


def test_low_confidence_path_promotes_to_validated_not_exploited():
    backend = FakeGraphBackend()
    path = _path_with_tool_call("send_email", confidence="low")
    graph = reconcile(_TARGET, _static("send_email"), backend, [path])

    key = StructuralKey(_TARGET, KIND_TOOL, "send_email")
    assert graph.nodes[key.digest()].evidence is EvidenceState.VALIDATED


def test_evidence_never_regresses_across_passes():
    # observed (from the runtime graph) then exploited (from a dangerous
    # path) must end at exploited, never fall back down.
    backend = FakeGraphBackend()
    _tool_call_node(backend, "n1", "send_email")
    path = _path_with_tool_call("send_email", confidence="high")

    graph = reconcile(_TARGET, _static("send_email"), backend, [path])

    key = StructuralKey(_TARGET, KIND_TOOL, "send_email")
    assert graph.nodes[key.digest()].evidence is EvidenceState.EXPLOITED


def test_full_ladder_across_three_tools_in_one_scan():
    """The demonstrative case: one static surface, three different outcomes."""
    backend = FakeGraphBackend()
    _tool_call_node(backend, "n1", "read_file")  # called, never exploited
    _tool_call_node(backend, "n2", "send_email")  # called and exploited
    exploited_path = _path_with_tool_call("send_email", confidence="high")

    graph = reconcile(
        _TARGET,
        _static("read_file", "send_email", "run_code"),  # run_code never touched
        backend,
        [exploited_path],
    )

    def evidence_of(name: str) -> EvidenceState:
        return graph.nodes[StructuralKey(_TARGET, KIND_TOOL, name).digest()].evidence

    assert evidence_of("read_file") is EvidenceState.OBSERVED
    assert evidence_of("send_email") is EvidenceState.EXPLOITED
    assert evidence_of("run_code") is EvidenceState.POSSIBLE


# ---------------------------------------------------------------------------
# StructuralGraph helpers
# ---------------------------------------------------------------------------


def test_by_evidence_filters_correctly():
    backend = FakeGraphBackend()
    _tool_call_node(backend, "n1", "observed_tool")
    graph = reconcile(_TARGET, _static("observed_tool", "possible_tool"), backend, [])

    assert {n.name for n in graph.by_evidence(EvidenceState.OBSERVED)} == {"observed_tool"}
    assert {n.name for n in graph.by_evidence(EvidenceState.POSSIBLE)} == {"possible_tool"}


def test_reconcile_with_no_static_tools_still_registers_runtime_only_tools():
    backend = FakeGraphBackend()
    _tool_call_node(backend, "n1", "surprise_tool")
    graph = reconcile(_TARGET, [], backend, [])

    assert len(graph.nodes) == 1
    node = next(iter(graph.nodes.values()))
    assert node.name == "surprise_tool"
    assert node.source == "runtime"


# ---------------------------------------------------------------------------
# StructuralGraph.coverage() / to_summary()
# ---------------------------------------------------------------------------


def test_coverage_counts_per_state():
    backend = FakeGraphBackend()
    _tool_call_node(backend, "n1", "observed_tool")
    graph = reconcile(_TARGET, _static("observed_tool", "a", "b"), backend, [])

    assert graph.coverage() == {"observed": 1, "possible": 2}


def test_coverage_empty_graph_returns_empty_dict():
    graph = reconcile(_TARGET, [], FakeGraphBackend(), [])
    assert graph.coverage() == {}


def test_to_summary_shape():
    backend = FakeGraphBackend()
    _tool_call_node(backend, "n1", "read_file")
    graph = reconcile(_TARGET, _static("read_file"), backend, [])

    summary = graph.to_summary()

    assert summary["target_id"] == _TARGET
    assert summary["coverage"] == {"observed": 1}
    assert summary["nodes"] == [
        {
            "name": "read_file",
            "kind": KIND_TOOL,
            "evidence": "observed",
            "source": "static+runtime",
            "description": "",
        }
    ]


def test_to_summary_is_json_serializable():
    import json

    backend = FakeGraphBackend()
    graph = reconcile(_TARGET, _static("a", "b"), backend, [])
    json.dumps(graph.to_summary())  # raises if anything isn't a plain type


def test_to_summary_sorts_highest_evidence_first():
    backend = FakeGraphBackend()
    exploited_path = _path_with_tool_call("send_email", confidence="high")
    graph = reconcile(_TARGET, _static("read_file", "send_email"), backend, [exploited_path])

    names_in_order = [n["name"] for n in graph.to_summary()["nodes"]]
    assert names_in_order[0] == "send_email"  # exploited outranks possible
