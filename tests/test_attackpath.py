"""Tests for pwngraph.attackpath — ranking, blast radius, and cross-scan diffing."""

from __future__ import annotations

from _fake_backend import FakeGraphBackend

from pwngraph.attackpath import (
    PathDiff,
    blast_radius,
    chain_for_payload,
    diff_paths,
    finding_rank,
    newly_reachable_severities,
    path_rank,
    rank_findings,
    rank_paths,
    reachable_from,
)
from pwngraph.types import AttackPath, EdgeType, Finding, NodeType, Severity, TraceEvent

# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------


def _path(severity: Severity, confidence: str) -> AttackPath:
    ev = TraceEvent(run_id="r1", node_type=NodeType.TOOL_CALL, name="x", content="c")
    return AttackPath(
        events=[ev],
        edge_types=[EdgeType.TOOL_MANIPULATION],
        severity=severity,
        confidence=confidence,
    )


def test_path_rank_scales_by_confidence():
    high_conf = _path(Severity.CRITICAL, "high")
    low_conf = _path(Severity.CRITICAL, "low")
    assert path_rank(high_conf) > path_rank(low_conf)


def test_path_rank_low_confidence_critical_can_be_outranked_by_high_confidence_high():
    low_conf_critical = _path(Severity.CRITICAL, "low")  # 9.5 * 0.3 = 2.85
    high_conf_high = _path(Severity.HIGH, "high")  # 7.5 * 1.0 = 7.5
    assert path_rank(high_conf_high) > path_rank(low_conf_critical)


def test_path_rank_unknown_confidence_defaults_to_low_weight():
    p = _path(Severity.HIGH, "unknown-value")
    assert path_rank(p) == Severity.HIGH.score * 0.3


def test_rank_paths_sorts_highest_first():
    low = _path(Severity.LOW, "high")
    high = _path(Severity.CRITICAL, "high")
    ranked = rank_paths([low, high])
    assert ranked == [high, low]


def _finding(severity: Severity, asr: float | None) -> Finding:
    evidence = {} if asr is None else {"attack_success_rate": asr}
    return Finding(
        title="t",
        severity=severity,
        target_system="x",
        attack_class="shell_injection",
        payload_id="p1",
        summary="s",
        steps_to_reproduce=[],
        impact="i",
        remediation="r",
        evidence=evidence,
    )


def test_finding_rank_scales_by_asr():
    high_asr = _finding(Severity.HIGH, 0.9)
    low_asr = _finding(Severity.HIGH, 0.1)
    assert finding_rank(high_asr) > finding_rank(low_asr)


def test_finding_rank_missing_asr_treated_as_fully_confirmed():
    no_asr = _finding(Severity.HIGH, None)
    assert finding_rank(no_asr) == Severity.HIGH.score


def test_rank_findings_sorts_highest_first():
    weak = _finding(Severity.CRITICAL, 0.05)
    strong = _finding(Severity.HIGH, 1.0)
    ranked = rank_findings([weak, strong])
    assert ranked[0] is strong


# ---------------------------------------------------------------------------
# reachable_from
# ---------------------------------------------------------------------------


def test_reachable_from_simple_chain():
    b = FakeGraphBackend()
    b.add_edge("a", "b")
    b.add_edge("b", "c")
    assert reachable_from(b, "a") == {"b", "c"}


def test_reachable_from_missing_node_returns_empty_set():
    b = FakeGraphBackend()
    assert reachable_from(b, "ghost") == set()


def test_reachable_from_leaf_node_returns_empty_set():
    b = FakeGraphBackend()
    b.add_edge("a", "b")
    assert reachable_from(b, "b") == set()


def test_reachable_from_handles_cycles_without_looping_forever():
    b = FakeGraphBackend()
    b.add_edge("a", "b")
    b.add_edge("b", "c")
    b.add_edge("c", "a")
    assert reachable_from(b, "a") == {"a", "b", "c"}


def test_reachable_from_branches_merge_correctly():
    b = FakeGraphBackend()
    b.add_edge("a", "b1")
    b.add_edge("a", "b2")
    b.add_edge("b1", "c")
    b.add_edge("b2", "c")
    assert reachable_from(b, "a") == {"b1", "b2", "c"}


# ---------------------------------------------------------------------------
# blast_radius
# ---------------------------------------------------------------------------


def _tool_call(backend: FakeGraphBackend, node_id: str, name: str) -> None:
    backend.add_node(node_id, node_type=NodeType.TOOL_CALL.value, name=name)


def test_blast_radius_finds_downstream_tool():
    b = FakeGraphBackend()
    _tool_call(b, "call_a", "read_file")
    _tool_call(b, "call_b", "send_email")
    b.add_edge("call_a", "call_b")

    assert blast_radius(b, "read_file") == ["send_email"]


def test_blast_radius_excludes_the_tool_itself():
    b = FakeGraphBackend()
    _tool_call(b, "call_a", "read_file")
    _tool_call(b, "call_b", "read_file")  # called twice
    b.add_edge("call_a", "call_b")

    assert blast_radius(b, "read_file") == []


def test_blast_radius_untouched_tool_has_empty_radius():
    b = FakeGraphBackend()
    _tool_call(b, "call_a", "read_file")
    assert blast_radius(b, "never_called") == []


def test_blast_radius_deduplicates_multiple_paths_to_same_tool():
    b = FakeGraphBackend()
    _tool_call(b, "call_a", "read_file")
    _tool_call(b, "call_b1", "log_it")
    _tool_call(b, "call_b2", "log_it")
    _tool_call(b, "call_c", "send_email")
    b.add_edge("call_a", "call_b1")
    b.add_edge("call_a", "call_b2")
    b.add_edge("call_b1", "call_c")
    b.add_edge("call_b2", "call_c")

    assert blast_radius(b, "read_file") == ["log_it", "send_email"]


def test_blast_radius_ignores_non_tool_call_nodes():
    b = FakeGraphBackend()
    _tool_call(b, "call_a", "read_file")
    b.add_node("final", node_type=NodeType.FINAL_ANSWER.value, name="agent")
    b.add_edge("call_a", "final")

    assert blast_radius(b, "read_file") == []


def test_blast_radius_scoped_to_scan_id_ignores_other_scans():
    """A tool name shared across two unrelated scans of the same persistent
    backend must not have its radius computed from both at once."""
    b = FakeGraphBackend()
    b.add_node("call_a1", node_type=NodeType.TOOL_CALL.value, name="read_file", scan_id="scan-1")
    b.add_node("call_b1", node_type=NodeType.TOOL_CALL.value, name="send_email", scan_id="scan-1")
    b.add_edge("call_a1", "call_b1")

    b.add_node("call_a2", node_type=NodeType.TOOL_CALL.value, name="read_file", scan_id="scan-2")
    b.add_node("call_b2", node_type=NodeType.TOOL_CALL.value, name="run_code", scan_id="scan-2")
    b.add_edge("call_a2", "call_b2")

    assert blast_radius(b, "read_file", scan_id="scan-1") == ["send_email"]
    assert blast_radius(b, "read_file", scan_id="scan-2") == ["run_code"]
    # Unscoped still sees the union across both scans.
    assert blast_radius(b, "read_file") == ["run_code", "send_email"]


# ---------------------------------------------------------------------------
# chain_for_payload — "take me to this finding's attack chain"
# ---------------------------------------------------------------------------


def _chain_backend() -> FakeGraphBackend:
    b = FakeGraphBackend()
    b.add_node("u1", node_type=NodeType.USER_INPUT.value, scan_id="scan-1")
    b.add_node("t1", node_type=NodeType.TOOL_CALL.value, scan_id="scan-1")
    b.add_node(
        "sink::t1",
        node_type=NodeType.DANGEROUS_OUTCOME.value,
        scan_id="scan-1",
        payload_id="p1",
    )
    b.add_edge("u1", "t1")
    b.add_edge("t1", "sink::t1")
    return b


def test_chain_for_payload_walks_back_from_the_matching_sink():
    b = _chain_backend()
    assert chain_for_payload(b, "scan-1", "p1") == ["sink::t1", "t1", "u1"]


def test_chain_for_payload_no_matching_sink_returns_empty():
    b = _chain_backend()
    assert chain_for_payload(b, "scan-1", "no-such-payload") == []


def test_chain_for_payload_unions_multiple_sinks_sharing_a_payload_id():
    """trials > 1 can re-deliver the same payload successfully more than
    once — each success gets its own DangerousOutcome node, and every one of
    them is a real occurrence of the finding, not a duplicate to drop."""
    b = _chain_backend()
    b.add_node("u2", node_type=NodeType.USER_INPUT.value, scan_id="scan-1")
    b.add_node("t2", node_type=NodeType.TOOL_CALL.value, scan_id="scan-1")
    b.add_node(
        "sink::t2",
        node_type=NodeType.DANGEROUS_OUTCOME.value,
        scan_id="scan-1",
        payload_id="p1",
    )
    b.add_edge("u2", "t2")
    b.add_edge("t2", "sink::t2")

    assert chain_for_payload(b, "scan-1", "p1") == ["sink::t1", "sink::t2", "t1", "t2", "u1", "u2"]


def test_chain_for_payload_scoped_to_scan_id():
    b = _chain_backend()
    b.add_node("u9", node_type=NodeType.USER_INPUT.value, scan_id="scan-2")
    b.add_node(
        "sink::other",
        node_type=NodeType.DANGEROUS_OUTCOME.value,
        scan_id="scan-2",
        payload_id="p1",
    )
    b.add_edge("u9", "sink::other")

    assert chain_for_payload(b, "scan-1", "p1") == ["sink::t1", "t1", "u1"]


# ---------------------------------------------------------------------------
# diff_paths / PathDiff
# ---------------------------------------------------------------------------


def _named_path(name: str, severity: Severity = Severity.HIGH) -> AttackPath:
    ev = TraceEvent(run_id="r1", node_type=NodeType.TOOL_CALL, name=name, content="c")
    return AttackPath(events=[ev], edge_types=[EdgeType.TOOL_MANIPULATION], severity=severity)


def test_diff_paths_detects_new():
    before = [_named_path("send_email")]
    after = [_named_path("send_email"), _named_path("run_code")]
    diff = diff_paths(before, after)
    assert {p.events[0].name for p in diff.new} == {"run_code"}
    assert diff.removed == []


def test_diff_paths_detects_removed():
    before = [_named_path("send_email"), _named_path("run_code")]
    after = [_named_path("send_email")]
    diff = diff_paths(before, after)
    assert {p.events[0].name for p in diff.removed} == {"run_code"}
    assert diff.new == []


def test_diff_paths_persisting_ignores_content_differences():
    # Same structural shape (tool_call: send_email), different literal
    # content — a signature-based diff must treat this as persisting, not new.
    before = [_named_path("send_email")]
    ev = TraceEvent(
        run_id="r2", node_type=NodeType.TOOL_CALL, name="send_email", content="different content"
    )
    after = [AttackPath(events=[ev], edge_types=[EdgeType.TOOL_MANIPULATION])]

    diff = diff_paths(before, after)

    assert len(diff.persisting) == 1
    assert diff.new == []
    assert diff.removed == []


def test_path_diff_regressed_true_when_only_new_appears():
    diff = PathDiff(new=[_named_path("run_code")], removed=[], persisting=[])
    assert diff.regressed is True
    assert diff.improved is False


def test_path_diff_improved_true_when_only_removed():
    diff = PathDiff(new=[], removed=[_named_path("run_code")], persisting=[])
    assert diff.improved is True
    assert diff.regressed is False


def test_path_diff_neither_when_both_new_and_removed():
    diff = PathDiff(new=[_named_path("a")], removed=[_named_path("b")], persisting=[])
    assert diff.regressed is False
    assert diff.improved is False


def test_path_diff_summary_counts():
    diff = PathDiff(
        new=[_named_path("a")], removed=[_named_path("b"), _named_path("c")], persisting=[]
    )
    assert diff.summary() == {"new": 1, "removed": 2, "persisting": 0}


def test_newly_reachable_severities():
    diff = PathDiff(new=[_named_path("a", Severity.CRITICAL), _named_path("b", Severity.LOW)])
    assert newly_reachable_severities(diff) == [Severity.CRITICAL, Severity.LOW]


def test_diff_paths_empty_scans():
    diff = diff_paths([], [])
    assert diff.summary() == {"new": 0, "removed": 0, "persisting": 0}
    assert diff.regressed is False
    assert diff.improved is False
