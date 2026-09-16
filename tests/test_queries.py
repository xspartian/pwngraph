"""Tests for pwngraph.queries — the Phase 2 query library.

Runs entirely against FakeGraphBackend, on purpose: every query here reads
through the GraphBackend ABC only, so passing here is the actual guarantee
that the same call works unmodified against Neo4jBackend later.
"""

from __future__ import annotations

from _fake_backend import FakeGraphBackend

from pwngraph.queries import (
    QUERY_REGISTRY,
    adversarial_edge_breakdown,
    coverage_ratio,
    dangerous_outcomes,
    delete_scan,
    evidence_coverage,
    exfil_findings,
    exploited_tools,
    high_confidence_findings,
    list_scans,
    possible_only_tools,
    run,
    scan_log,
    severity_breakdown,
    tools_by_evidence,
)
from pwngraph.static.schema import KIND_TOOL

# ---------------------------------------------------------------------------
# Evidence queries
# ---------------------------------------------------------------------------


def _seed(backend: FakeGraphBackend, tools: dict[str, str], scan_id: str | None = None) -> None:
    """tools: {name: evidence_state}"""
    for name, state in tools.items():
        attrs = {"kind": KIND_TOOL, "name": name, "evidence": state}
        if scan_id is not None:
            attrs["scan_id"] = scan_id
        # node id must be unique across separate _seed() calls in the same
        # test (e.g. one per scan_id) — a bare per-call counter would let a
        # second call silently overwrite the first call's nodes.
        backend.add_node(f"n-{scan_id}-{name}", **attrs)


def test_evidence_coverage_counts_per_state():
    backend = FakeGraphBackend()
    _seed(
        backend,
        {"a": "possible", "b": "possible", "c": "observed", "d": "exploited"},
    )
    assert evidence_coverage(backend) == {"possible": 2, "observed": 1, "exploited": 1}


def test_evidence_coverage_empty_graph():
    assert evidence_coverage(FakeGraphBackend()) == {}


def test_evidence_coverage_scoped_to_scan_id():
    backend = FakeGraphBackend()
    _seed(backend, {"a": "exploited"}, scan_id="scan-1")
    _seed(backend, {"b": "possible", "c": "possible"}, scan_id="scan-2")

    assert evidence_coverage(backend, scan_id="scan-1") == {"exploited": 1}
    assert evidence_coverage(backend, scan_id="scan-2") == {"possible": 2}
    # Unscoped sees everything, across both scans
    assert evidence_coverage(backend) == {"exploited": 1, "possible": 2}


def test_possible_only_tools_lists_untouched_names():
    backend = FakeGraphBackend()
    _seed(backend, {"read_file": "possible", "send_email": "exploited"})
    assert possible_only_tools(backend) == ["read_file"]


def test_possible_only_tools_ignores_non_tool_kind():
    backend = FakeGraphBackend()
    backend.add_node("n1", kind="agent", name="my_agent", evidence="possible")
    assert possible_only_tools(backend) == []


def test_exploited_tools_lists_only_exploited():
    backend = FakeGraphBackend()
    _seed(
        backend,
        {"a": "possible", "b": "observed", "c": "exploited", "d": "exploited"},
    )
    assert exploited_tools(backend) == ["c", "d"]


def test_tools_by_evidence_arbitrary_state():
    backend = FakeGraphBackend()
    _seed(backend, {"a": "validated", "b": "observed"})
    assert tools_by_evidence(backend, "validated") == ["a"]


def test_coverage_ratio_all_confirmed():
    backend = FakeGraphBackend()
    _seed(backend, {"a": "observed", "b": "exploited"})
    assert coverage_ratio(backend) == 1.0


def test_coverage_ratio_none_confirmed():
    backend = FakeGraphBackend()
    _seed(backend, {"a": "possible", "b": "possible"})
    assert coverage_ratio(backend) == 0.0


def test_coverage_ratio_partial():
    backend = FakeGraphBackend()
    _seed(backend, {"a": "possible", "b": "observed", "c": "exploited", "d": "possible"})
    assert coverage_ratio(backend) == 0.5


def test_coverage_ratio_empty_graph_is_zero_not_a_division_error():
    assert coverage_ratio(FakeGraphBackend()) == 0.0


# ---------------------------------------------------------------------------
# Finding queries — DangerousOutcome sinks
# ---------------------------------------------------------------------------


def _seed_sink(
    backend: FakeGraphBackend,
    trigger_id: str,
    *,
    severity: str,
    confidence: str,
    edge_type: str,
    scan_id: str | None = None,
) -> str:
    """Mirrors GraphBuilder's sink-attachment shape: a 'sink::<trigger>' node
    reached from the triggering event by exactly one classified edge."""
    backend.add_node(trigger_id, scan_id=scan_id)
    sink_id = f"sink::{trigger_id}"
    attrs = {
        "node_type": "dangerous",
        "name": "DangerousOutcome",
        "outcome_severity": severity,
        "confidence": confidence,
        "run_id": "run-1",
        "payload_id": "p1",
        "description": f"{trigger_id} -> {edge_type}",
    }
    if scan_id is not None:
        attrs["scan_id"] = scan_id
    backend.add_node(sink_id, **attrs)
    backend.add_edge(trigger_id, sink_id, edge_type=edge_type)
    return sink_id


def test_dangerous_outcomes_sorted_most_severe_first():
    backend = FakeGraphBackend()
    _seed_sink(backend, "ev-low", severity="low", confidence="low", edge_type="context_poisoning")
    _seed_sink(backend, "ev-crit", severity="critical", confidence="high", edge_type="data_exfil")
    rows = dangerous_outcomes(backend)
    assert [r["severity"] for r in rows] == ["critical", "low"]
    assert rows[0]["edge_type"] == "data_exfil"


def test_dangerous_outcomes_scoped_to_scan_id():
    backend = FakeGraphBackend()
    _seed_sink(
        backend,
        "ev-a",
        severity="high",
        confidence="high",
        edge_type="tool_manipulation",
        scan_id="scan-1",
    )
    _seed_sink(
        backend,
        "ev-b",
        severity="critical",
        confidence="high",
        edge_type="data_exfil",
        scan_id="scan-2",
    )
    assert len(dangerous_outcomes(backend, scan_id="scan-1")) == 1
    assert len(dangerous_outcomes(backend, scan_id="scan-2")) == 1
    assert len(dangerous_outcomes(backend)) == 2


def test_exfil_findings_filters_to_data_exfil_edge():
    backend = FakeGraphBackend()
    _seed_sink(backend, "ev-a", severity="high", confidence="high", edge_type="tool_manipulation")
    _seed_sink(backend, "ev-b", severity="critical", confidence="high", edge_type="data_exfil")
    rows = exfil_findings(backend)
    assert len(rows) == 1
    assert rows[0]["node_id"] == "sink::ev-b"


def test_high_confidence_findings_excludes_low_confidence():
    backend = FakeGraphBackend()
    _seed_sink(backend, "ev-a", severity="low", confidence="low", edge_type="context_poisoning")
    _seed_sink(backend, "ev-b", severity="high", confidence="high", edge_type="tool_manipulation")
    rows = high_confidence_findings(backend)
    assert len(rows) == 1
    assert rows[0]["node_id"] == "sink::ev-b"


def test_severity_breakdown_counts_by_bucket():
    backend = FakeGraphBackend()
    _seed_sink(backend, "ev-a", severity="high", confidence="high", edge_type="tool_manipulation")
    _seed_sink(backend, "ev-b", severity="high", confidence="high", edge_type="tool_manipulation")
    _seed_sink(backend, "ev-c", severity="critical", confidence="high", edge_type="data_exfil")
    assert severity_breakdown(backend) == {"high": 2, "critical": 1}


def test_adversarial_edge_breakdown_counts_by_edge_type():
    backend = FakeGraphBackend()
    _seed_sink(backend, "ev-a", severity="critical", confidence="high", edge_type="data_exfil")
    _seed_sink(backend, "ev-b", severity="high", confidence="high", edge_type="tool_manipulation")
    _seed_sink(backend, "ev-c", severity="high", confidence="high", edge_type="tool_manipulation")
    assert adversarial_edge_breakdown(backend) == {"tool_manipulation": 2, "data_exfil": 1}


def test_dangerous_outcomes_empty_graph():
    assert dangerous_outcomes(FakeGraphBackend()) == []


# ---------------------------------------------------------------------------
# Scan discovery
# ---------------------------------------------------------------------------


def test_list_scans_groups_by_scan_id_with_counts():
    backend = FakeGraphBackend()
    backend.add_node(
        "n1", scan_id="scan-1", target_id="target-a", scanned_at="2026-01-01T00:00:00+00:00"
    )
    backend.add_node(
        "n2", scan_id="scan-1", target_id="target-a", scanned_at="2026-01-01T00:00:00+00:00"
    )
    backend.add_node(
        "n3",
        scan_id="scan-1",
        node_type="dangerous",
        scanned_at="2026-01-01T00:00:00+00:00",
    )
    backend.add_node(
        "n4", scan_id="scan-2", target_id="target-b", scanned_at="2026-06-01T00:00:00+00:00"
    )

    rows = list_scans(backend)

    by_id = {r["scan_id"]: r for r in rows}
    assert by_id["scan-1"]["nodes"] == 3
    assert by_id["scan-1"]["target_id"] == "target-a"
    assert by_id["scan-1"]["dangerous_outcomes"] == 1
    assert by_id["scan-2"]["nodes"] == 1
    assert by_id["scan-2"]["dangerous_outcomes"] == 0


def test_list_scans_most_recent_first():
    backend = FakeGraphBackend()
    backend.add_node("old", scan_id="scan-old", scanned_at="2020-01-01T00:00:00+00:00")
    backend.add_node("new", scan_id="scan-new", scanned_at="2026-01-01T00:00:00+00:00")

    rows = list_scans(backend)
    assert [r["scan_id"] for r in rows] == ["scan-new", "scan-old"]


def test_list_scans_ignores_nodes_without_a_scan_id():
    backend = FakeGraphBackend()
    backend.add_node("orphan", name="not part of any scan")
    assert list_scans(backend) == []


def test_list_scans_empty_graph():
    assert list_scans(FakeGraphBackend()) == []


# ---------------------------------------------------------------------------
# delete_scan
# ---------------------------------------------------------------------------


def test_delete_scan_removes_every_node_tagged_with_that_scan_id():
    backend = FakeGraphBackend()
    backend.add_node("n1", scan_id="scan-1", name="a")
    backend.add_node("n2", scan_id="scan-1", name="b")
    backend.add_edge("n1", "n2", edge_type="normal_flow")

    deleted = delete_scan(backend, "scan-1")

    assert deleted == 2
    assert backend.node_count == 0
    assert backend.edge_count == 0


def test_delete_scan_leaves_other_scans_untouched():
    backend = FakeGraphBackend()
    backend.add_node("n1", scan_id="scan-1")
    backend.add_node("n2", scan_id="scan-2")

    delete_scan(backend, "scan-1")

    assert backend.has_node("n1") is False
    assert backend.has_node("n2") is True


def test_delete_scan_also_removes_the_persisted_report_node():
    """The report node carries scan_id too (see report_store.py) — a single
    delete_scan sweep must take it out along with the runtime trace graph,
    not leave an orphaned report behind."""
    from pwngraph.report_store import load_scan_report, persist_scan_report

    backend = FakeGraphBackend()
    backend.add_node("n1", scan_id="scan-1")
    persist_scan_report(
        backend,
        "scan-1",
        target_name="lab_agent",
        tool_inventory=[],
        findings=[],
        asr={},
        owasp_coverage=[],
        risk_grade={"grade": "A", "score": 0},
        summary={},
    )

    delete_scan(backend, "scan-1")

    assert load_scan_report(backend, "scan-1") is None


def test_delete_scan_unknown_scan_id_deletes_nothing():
    backend = FakeGraphBackend()
    backend.add_node("n1", scan_id="scan-1")
    assert delete_scan(backend, "no-such-scan") == 0
    assert backend.node_count == 1


# ---------------------------------------------------------------------------
# Named query registry
# ---------------------------------------------------------------------------


def test_registry_contains_expected_names():
    expected = {
        "scans",
        "evidence-coverage",
        "possible-only-tools",
        "exploited-tools",
        "coverage-ratio",
        "dangerous-outcomes",
        "exfil-findings",
        "high-confidence-findings",
        "severity-breakdown",
        "edge-breakdown",
        "blast-radius",
    }
    assert expected <= set(QUERY_REGISTRY)


def test_run_scans_ignores_scan_id_filter():
    backend = FakeGraphBackend()
    backend.add_node("n1", scan_id="scan-1", scanned_at="2026-01-01T00:00:00+00:00")
    # Passing a scan_id to "scans" should not filter it down to nothing —
    # discovery is always whole-database.
    rows = run("scans", backend, scan_id="some-other-scan")
    assert len(rows) == 1
    assert rows[0]["scan_id"] == "scan-1"


def test_run_dispatches_to_registered_query():
    backend = FakeGraphBackend()
    _seed(backend, {"a": "exploited"})
    rows = run("exploited-tools", backend)
    assert rows == [{"tool": "a"}]


def test_run_unknown_name_raises_key_error():
    import pytest

    with pytest.raises(KeyError):
        run("does-not-exist", FakeGraphBackend())


def test_every_registered_query_returns_row_list_shape():
    backend = FakeGraphBackend()
    _seed(backend, {"a": "exploited", "b": "possible"})
    _seed_sink(backend, "ev-a", severity="critical", confidence="high", edge_type="data_exfil")

    for name, qdef in QUERY_REGISTRY.items():
        kwargs = {"tool": "some_tool"} if qdef.requires_tool else {}
        rows = run(name, backend, **kwargs)
        assert isinstance(rows, list)
        assert all(isinstance(r, dict) for r in rows)


def test_blast_radius_query_requires_tool():
    import pytest

    with pytest.raises(ValueError):
        run("blast-radius", FakeGraphBackend())


def test_blast_radius_query_returns_downstream_tools():
    backend = FakeGraphBackend()
    backend.add_node("call_a", node_type="tool_call", name="read_file", scan_id="scan-1")
    backend.add_node("call_b", node_type="tool_call", name="send_email", scan_id="scan-1")
    backend.add_edge("call_a", "call_b")

    rows = run("blast-radius", backend, tool="read_file", scan_id="scan-1")
    assert rows == [{"tool": "send_email"}]


# ---------------------------------------------------------------------------
# scan_log
# ---------------------------------------------------------------------------


def _seed_run(
    backend: FakeGraphBackend,
    scan_id: str,
    run_id: str,
    *,
    is_adversarial: bool,
    attack_class: str | None = None,
    payload_id: str | None = None,
    start_ts: float = 0.0,
) -> None:
    """Seed a minimal 3-event run: user input -> tool call -> tool result."""
    backend.add_node(
        f"{run_id}-user",
        scan_id=scan_id,
        node_type="user_input",
        name="user",
        content="hi",
        run_id=run_id,
        is_adversarial=is_adversarial,
        payload_id=payload_id,
        attack_class=attack_class,
        timestamp=start_ts,
    )
    backend.add_node(
        f"{run_id}-call",
        scan_id=scan_id,
        node_type="tool_call",
        name="read_file",
        content="args",
        run_id=run_id,
        is_adversarial=is_adversarial,
        payload_id=payload_id,
        timestamp=start_ts + 1,
    )
    backend.add_node(
        f"{run_id}-result",
        scan_id=scan_id,
        node_type="tool_result",
        name="read_file",
        content="output",
        run_id=run_id,
        is_adversarial=is_adversarial,
        payload_id=payload_id,
        timestamp=start_ts + 2,
    )


def test_scan_log_orders_events_within_a_run_by_timestamp():
    backend = FakeGraphBackend()
    _seed_run(backend, "scan-1", "run-a", is_adversarial=False, start_ts=100.0)

    rows = scan_log(backend, "scan-1")
    assert [r["node_type"] for r in rows] == ["user_input", "tool_call", "tool_result"]
    assert [r["timestamp"] for r in rows] == [100.0, 101.0, 102.0]


def test_scan_log_orders_runs_by_when_they_actually_happened_not_run_id_string():
    """run_id is a random hex string, not sequential — sorting must use each
    run's own earliest timestamp, or cross-run order would be scrambled."""
    backend = FakeGraphBackend()
    # 'zzzz' would sort after 'aaaa' alphabetically, but it happened first.
    _seed_run(backend, "scan-1", "zzzz", is_adversarial=False, start_ts=0.0)
    _seed_run(
        backend,
        "scan-1",
        "aaaa",
        is_adversarial=True,
        attack_class="indirect_injection",
        start_ts=50.0,
    )

    rows = scan_log(backend, "scan-1")
    run_order = list(dict.fromkeys(r["run_id"] for r in rows))
    assert run_order == ["zzzz", "aaaa"]


def test_scan_log_carries_adversarial_and_attack_class_metadata():
    backend = FakeGraphBackend()
    _seed_run(
        backend,
        "scan-1",
        "run-a",
        is_adversarial=True,
        attack_class="tool_poisoning",
        payload_id="p1",
        start_ts=0.0,
    )

    rows = scan_log(backend, "scan-1")
    assert all(r["is_adversarial"] for r in rows)
    assert rows[0]["attack_class"] == "tool_poisoning"
    assert all(r["payload_id"] == "p1" for r in rows)


def test_scan_log_scoped_to_scan_id():
    backend = FakeGraphBackend()
    _seed_run(backend, "scan-1", "run-a", is_adversarial=False)
    _seed_run(backend, "scan-2", "run-b", is_adversarial=False)

    rows = scan_log(backend, "scan-1")
    assert all(r["run_id"] == "run-a" for r in rows)


def test_scan_log_empty_for_unknown_scan():
    backend = FakeGraphBackend()
    assert scan_log(backend, "never-scanned") == []
