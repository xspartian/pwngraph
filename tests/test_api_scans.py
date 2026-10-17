"""Tests for the read-only /api/scans routes — FastAPI TestClient against
FakeGraphBackend, no live Neo4j needed. Mirrors the "logic tested without a
live server" guarantee pwngraph.queries's own tests already have; every
route here is a thin wrapper around functions already covered there.
"""

from __future__ import annotations

from _fake_backend import FakeGraphBackend
from fastapi.testclient import TestClient

from pwngraph.api.app import create_app


def _client(backend: FakeGraphBackend) -> TestClient:
    return TestClient(create_app(backend))


def _add_trace_node(backend, node_id, *, scan_id="scan-1", node_type="user_input", **extra):
    backend.add_node(
        node_id,
        scan_id=scan_id,
        node_type=node_type,
        name=extra.pop("name", node_id),
        label=extra.pop("label", node_id),
        color=extra.pop("color", "#123456"),
        shape=extra.pop("shape", "dot"),
        is_adversarial=extra.pop("is_adversarial", False),
        **extra,
    )


def test_health_ok():
    resp = _client(FakeGraphBackend()).get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


def test_list_scans_empty():
    resp = _client(FakeGraphBackend()).get("/api/scans")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_scans_returns_scan_summary():
    backend = FakeGraphBackend()
    _add_trace_node(backend, "n1", scan_id="scan-1", target_id="my-agent", scanned_at="2026-01-01")
    resp = _client(backend).get("/api/scans")
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 1
    assert rows[0]["scan_id"] == "scan-1"
    assert rows[0]["target_id"] == "my-agent"


def test_get_graph_returns_nodes_edges_findings():
    backend = FakeGraphBackend()
    _add_trace_node(backend, "u1", node_type="user_input")
    _add_trace_node(backend, "t1", node_type="tool_call")
    backend.add_edge("u1", "t1", edge_type="direct_injection")

    resp = _client(backend).get("/api/scans/scan-1/graph")
    assert resp.status_code == 200
    body = resp.json()
    assert {n["id"] for n in body["nodes"]} == {"u1", "t1"}
    assert len(body["edges"]) == 1
    assert body["edges"][0]["edge_type"] == "direct_injection"


def test_get_graph_404s_for_unknown_scan():
    resp = _client(FakeGraphBackend()).get("/api/scans/does-not-exist/graph")
    assert resp.status_code == 404


def test_get_findings_dangerous_outcomes():
    backend = FakeGraphBackend()
    backend.add_node(
        "sink::t1",
        scan_id="scan-1",
        node_type="dangerous",
        outcome_severity="critical",
        confidence="high",
    )
    resp = _client(backend).get("/api/scans/scan-1/findings")
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 1
    assert rows[0]["severity"] == "critical"


def test_get_findings_high_confidence_filter():
    backend = FakeGraphBackend()
    backend.add_node(
        "sink::a",
        scan_id="scan-1",
        node_type="dangerous",
        outcome_severity="high",
        confidence="high",
    )
    backend.add_node(
        "sink::b",
        scan_id="scan-1",
        node_type="dangerous",
        outcome_severity="low",
        confidence="low",
    )
    resp = _client(backend).get("/api/scans/scan-1/findings", params={"confidence": "high"})
    rows = resp.json()
    assert len(rows) == 1
    assert rows[0]["confidence"] == "high"


def test_get_evidence_summary():
    backend = FakeGraphBackend()
    backend.add_node(
        "tool::a", scan_id="scan-1", kind="tool", name="read_file", evidence="possible"
    )
    backend.add_node(
        "tool::b", scan_id="scan-1", kind="tool", name="send_email", evidence="exploited"
    )
    resp = _client(backend).get("/api/scans/scan-1/evidence")
    assert resp.status_code == 200
    body = resp.json()
    assert body["possible_only"] == ["read_file"]
    assert body["exploited"] == ["send_email"]
    assert 0.0 <= body["coverage_ratio"] <= 1.0


def test_blast_radius_requires_tool_query_param():
    resp = _client(FakeGraphBackend()).get("/api/scans/scan-1/blast-radius")
    assert resp.status_code == 422  # missing required query param


def test_blast_radius_returns_reachable_tool_names():
    backend = FakeGraphBackend()
    backend.add_node("call1", scan_id="scan-1", node_type="tool_call", name="search")
    backend.add_node("call2", scan_id="scan-1", node_type="tool_call", name="send_email")
    backend.add_edge("call1", "call2", edge_type="normal_flow")
    resp = _client(backend).get("/api/scans/scan-1/blast-radius", params={"tool": "search"})
    assert resp.status_code == 200
    assert resp.json() == ["send_email"]


def test_run_named_query_dispatches_through_registry():
    resp = _client(FakeGraphBackend()).get("/api/scans/scan-1/query/scans")
    assert resp.status_code == 200


def test_run_named_query_unknown_name_404s():
    resp = _client(FakeGraphBackend()).get("/api/scans/scan-1/query/not-a-real-query")
    assert resp.status_code == 404


def test_run_named_query_blast_radius_without_tool_400s():
    resp = _client(FakeGraphBackend()).get("/api/scans/scan-1/query/blast-radius")
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Report endpoint — the layer `pwngraph serve` needs to show a full report for
# a past scan (see pwngraph.report_store).
# ---------------------------------------------------------------------------


def _persist_demo_report(backend, scan_id="scan-1"):
    from pwngraph.report_store import persist_scan_report
    from pwngraph.types import Finding, Severity

    persist_scan_report(
        backend,
        scan_id,
        target_name="lab_agent",
        tool_inventory=["read_file", "send_email"],
        findings=[
            Finding(
                title="Critical agent hijack",
                severity=Severity.CRITICAL,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
                cvss_score=9.6,
                target_system="lab_agent",
                attack_class="tool_poisoning",
                owasp=["LLM01"],
                payload_id="p1",
                summary="canary reached send_email",
                steps_to_reproduce=["Deliver payload"],
                impact="Exfiltration",
                remediation="Allow-list destinations",
            )
        ],
        asr={"overall": {"asr": 0.3, "successes": 12, "trials": 40}},
        owasp_coverage=[{"id": "LLM01", "name": "Prompt Injection", "status": "detected"}],
        risk_grade={"grade": "C", "score": 42, "interpretation": "Elevated"},
        summary={"paths_dangerous": 3},
        scanned_at="2026-08-19T00:00:00Z",
    )


def test_get_report_returns_the_persisted_report():
    backend = FakeGraphBackend()
    _persist_demo_report(backend)

    resp = _client(backend).get("/api/scans/scan-1/report")
    assert resp.status_code == 200
    body = resp.json()
    assert body["target_name"] == "lab_agent"
    assert body["risk_grade"]["grade"] == "C"
    assert len(body["findings"]) == 1
    assert body["findings"][0]["cvss_score"] == 9.6
    assert body["findings"][0]["remediation"] == "Allow-list destinations"


def test_get_report_404s_when_the_scan_stored_none():
    """Normal for any scan predating report persistence — the graph is still
    browsable, so this must be a clean 404 rather than a 500."""
    resp = _client(FakeGraphBackend()).get("/api/scans/no-such-scan/report")
    assert resp.status_code == 404


def test_scan_list_is_enriched_with_report_headline():
    backend = FakeGraphBackend()
    _add_trace_node(backend, "n1", scan_id="scan-1")
    _persist_demo_report(backend)

    row = _client(backend).get("/api/scans").json()[0]
    assert row["risk_grade"] == "C"
    assert row["finding_count"] == 1
    assert row["max_severity"] == "critical"
    assert row["target_name"] == "lab_agent"


def test_scan_list_row_stays_valid_without_a_report():
    backend = FakeGraphBackend()
    _add_trace_node(backend, "n1", scan_id="scan-1")

    row = _client(backend).get("/api/scans").json()[0]
    assert row["scan_id"] == "scan-1"
    assert row["risk_grade"] is None
    assert row["finding_count"] is None


def test_graph_findings_match_the_persisted_report_when_one_exists():
    """The graph's own findings list must not disagree with the Report/
    Findings tabs — both come from the same persisted Finding records now
    (see graph_export._findings_from_report), not two independently
    -computed approximations that can drift apart."""
    backend = FakeGraphBackend()
    _add_trace_node(backend, "u1", scan_id="scan-1", node_type="user_input")
    _add_trace_node(backend, "t1", scan_id="scan-1", node_type="tool_call", name="send_email")
    backend.add_node(
        "sink::t1",
        scan_id="scan-1",
        node_type="dangerous",
        outcome_severity="critical",
        confidence="high",
        payload_id="p1",
    )
    backend.add_edge("u1", "t1")
    backend.add_edge("t1", "sink::t1")
    _persist_demo_report(backend)  # its one finding has payload_id="p1"

    report = _client(backend).get("/api/scans/scan-1/report").json()
    graph = _client(backend).get("/api/scans/scan-1/graph").json()

    assert len(graph["findings"]) == len(report["findings"]) == 1
    assert graph["findings"][0]["severity"] == report["findings"][0]["severity"]


def test_graph_target_name_comes_from_the_report_when_present():
    backend = FakeGraphBackend()
    _add_trace_node(backend, "n1", scan_id="scan-1")
    _persist_demo_report(backend)

    assert _client(backend).get("/api/scans/scan-1/graph").json()["target_name"] == "lab_agent"


# ---------------------------------------------------------------------------
# Export routes — browser-facing equivalents of the CLI's --out artifacts.
# ---------------------------------------------------------------------------


def test_export_graph_json_is_downloadable():
    backend = FakeGraphBackend()
    _add_trace_node(backend, "n1", scan_id="scan-1")
    resp = _client(backend).get("/api/scans/scan-1/export/graph.json")
    assert resp.status_code == 200
    assert "attachment" in resp.headers["content-disposition"]
    assert resp.json()["nodes"][0]["id"] == "n1"


def test_export_graph_json_404s_for_unknown_scan():
    resp = _client(FakeGraphBackend()).get("/api/scans/does-not-exist/export/graph.json")
    assert resp.status_code == 404


def test_export_findings_sarif():
    backend = FakeGraphBackend()
    _persist_demo_report(backend)
    resp = _client(backend).get("/api/scans/scan-1/export/findings.sarif")
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == "2.1.0"
    assert body["runs"][0]["results"][0]["properties"]["attack_class"] == "tool_poisoning"


def test_export_findings_sarif_404s_without_a_report():
    resp = _client(FakeGraphBackend()).get("/api/scans/no-such-scan/export/findings.sarif")
    assert resp.status_code == 404


def test_export_poc_zip():
    import zipfile
    from io import BytesIO

    backend = FakeGraphBackend()
    _persist_demo_report(backend)
    resp = _client(backend).get("/api/scans/scan-1/export/poc.zip")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"
    zf = zipfile.ZipFile(BytesIO(resp.content))
    names = zf.namelist()
    assert any(n.endswith("poc.md") for n in names)
    assert any(n.endswith("poc.json") for n in names)


def test_export_poc_zip_404s_with_no_findings():
    backend = FakeGraphBackend()
    from pwngraph.report_store import persist_scan_report

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
    resp = _client(backend).get("/api/scans/scan-1/export/poc.zip")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Findings triage — the one write route.
# ---------------------------------------------------------------------------


def test_triage_update_sets_status_and_note():
    backend = FakeGraphBackend()
    _persist_demo_report(backend)
    finding_id = (
        _client(backend).get("/api/scans/scan-1/report").json()["findings"][0]["finding_id"]
    )

    resp = _client(backend).post(
        f"/api/scans/scan-1/findings/{finding_id}/triage",
        json={"status": "accepted_risk", "note": "known, tracked in JIRA-123"},
    )
    assert resp.status_code == 200
    assert resp.json() == {
        "finding_id": finding_id,
        "status": "accepted_risk",
        "note": "known, tracked in JIRA-123",
    }

    report = _client(backend).get("/api/scans/scan-1/report").json()
    assert report["findings"][0]["triage_status"] == "accepted_risk"
    assert report["findings"][0]["triage_note"] == "known, tracked in JIRA-123"


def test_triage_update_rejects_unknown_status():
    backend = FakeGraphBackend()
    _persist_demo_report(backend)
    finding_id = (
        _client(backend).get("/api/scans/scan-1/report").json()["findings"][0]["finding_id"]
    )
    resp = _client(backend).post(
        f"/api/scans/scan-1/findings/{finding_id}/triage", json={"status": "not-a-real-status"}
    )
    assert resp.status_code == 400


def test_triage_update_404s_for_unknown_finding():
    backend = FakeGraphBackend()
    _persist_demo_report(backend)
    resp = _client(backend).post(
        "/api/scans/scan-1/findings/does-not-exist/triage", json={"status": "fixed"}
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Scan comparison — the read-only counterpart to `pwngraph diff`.
# ---------------------------------------------------------------------------


def test_compare_scans_reports_deltas_and_added_removed_findings():
    backend = FakeGraphBackend()
    _persist_demo_report(backend, scan_id="scan-before")

    from pwngraph.report_store import persist_scan_report
    from pwngraph.types import Finding, Severity

    persist_scan_report(
        backend,
        "scan-after",
        target_name="lab_agent",
        tool_inventory=["read_file"],
        findings=[
            Finding(
                title="New file-read leak",
                severity=Severity.HIGH,
                target_system="lab_agent",
                attack_class="file_read_injection",
                payload_id="p2",
                summary="leaked /etc/passwd",
                steps_to_reproduce=[],
                impact="Disclosure",
                remediation="Sandbox reads",
            )
        ],
        asr={"overall": {"asr": 0.5, "successes": 20, "trials": 40}},
        owasp_coverage=[],
        risk_grade={"grade": "D", "score": 60},
        summary={},
        scanned_at="2026-08-20T00:00:00Z",
    )

    resp = _client(backend).get("/api/scans/scan-after/compare", params={"against": "scan-before"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "regressed"
    assert body["score_delta"] == 18
    assert len(body["findings_added"]) == 1
    assert body["findings_added"][0]["attack_class"] == "file_read_injection"
    assert len(body["findings_removed"]) == 1
    assert body["findings_removed"][0]["attack_class"] == "tool_poisoning"


def test_finding_chain_returns_the_node_ids_behind_it():
    backend = FakeGraphBackend()
    _persist_demo_report(backend)  # payload_id="p1" on its one finding
    _add_trace_node(backend, "u1", node_type="user_input")
    _add_trace_node(backend, "t1", node_type="tool_call")
    backend.add_node("sink::t1", scan_id="scan-1", node_type="dangerous", payload_id="p1")
    backend.add_edge("u1", "t1")
    backend.add_edge("t1", "sink::t1")

    finding_id = (
        _client(backend).get("/api/scans/scan-1/report").json()["findings"][0]["finding_id"]
    )
    resp = _client(backend).get(f"/api/scans/scan-1/findings/{finding_id}/chain")
    assert resp.status_code == 200
    assert set(resp.json()["nodes"]) == {"u1", "t1", "sink::t1"}


def test_finding_chain_404s_for_unknown_finding():
    backend = FakeGraphBackend()
    _persist_demo_report(backend)
    resp = _client(backend).get("/api/scans/scan-1/findings/does-not-exist/chain")
    assert resp.status_code == 404


def test_finding_chain_404s_when_no_matching_sink_exists():
    """The finding's report says it happened, but no DangerousOutcome sink
    with its payload_id survives in the graph — a clean 404, not a crash."""
    backend = FakeGraphBackend()
    _persist_demo_report(backend)
    finding_id = (
        _client(backend).get("/api/scans/scan-1/report").json()["findings"][0]["finding_id"]
    )
    resp = _client(backend).get(f"/api/scans/scan-1/findings/{finding_id}/chain")
    assert resp.status_code == 404


def test_compare_scans_404s_when_either_report_missing():
    backend = FakeGraphBackend()
    _persist_demo_report(backend, scan_id="scan-1")
    resp = _client(backend).get("/api/scans/scan-1/compare", params={"against": "no-such-scan"})
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# /logs and /nexus
# ---------------------------------------------------------------------------


def test_get_logs_groups_events_into_runs():
    backend = FakeGraphBackend()
    _add_trace_node(
        backend,
        "u1",
        node_type="user_input",
        content="hi",
        run_id="run-a",
        is_adversarial=True,
        payload_id="p1",
        attack_class="indirect_injection",
        timestamp=0.0,
    )
    _add_trace_node(
        backend,
        "c1",
        node_type="tool_call",
        content="args",
        run_id="run-a",
        is_adversarial=True,
        payload_id="p1",
        timestamp=1.0,
    )

    resp = _client(backend).get("/api/scans/scan-1/logs")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_id"] == "scan-1"
    assert len(body["runs"]) == 1
    run = body["runs"][0]
    assert run["run_id"] == "run-a"
    assert run["is_adversarial"] is True
    assert run["payload_id"] == "p1"
    assert run["attack_class"] == "indirect_injection"
    assert [e["node_type"] for e in run["events"]] == ["user_input", "tool_call"]


def test_get_logs_404s_for_unknown_scan():
    resp = _client(FakeGraphBackend()).get("/api/scans/no-such-scan/logs")
    assert resp.status_code == 404


def test_get_nexus_state_returns_persisted_data():
    from pwngraph.nexus.state import AttackState, Observation
    from pwngraph.report_store import persist_nexus_state

    backend = FakeGraphBackend()
    state = AttackState(attack_classes=["indirect_injection"], level=2, budget=10)
    state.record_observation(
        Observation(
            iteration=0,
            payload_id="p1",
            attack_class="indirect_injection",
            success=True,
            confidence="high",
            action="explore",
            rationale="first probe — starting with 'indirect_injection'",
        )
    )
    persist_nexus_state(backend, "scan-1", state)

    resp = _client(backend).get("/api/scans/scan-1/nexus")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_id"] == "scan-1"
    assert body["iteration"] == 1
    assert len(body["observations"]) == 1
    assert (
        body["observations"][0]["rationale"] == "first probe — starting with 'indirect_injection'"
    )


def test_get_nexus_state_404s_for_a_static_mode_scan():
    """A scan that never ran NEXUS mode has no such node — clean 404, not a crash."""
    backend = FakeGraphBackend()
    _persist_demo_report(backend, scan_id="scan-1")
    resp = _client(backend).get("/api/scans/scan-1/nexus")
    assert resp.status_code == 404
