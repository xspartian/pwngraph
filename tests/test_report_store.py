"""Tests for pwngraph.report_store — persisting a scan's reportable layer
(findings/ASR/OWASP/risk grade) into the graph backend so `pwngraph serve`
can read it back after the scanning process exits.

Runs against FakeGraphBackend: report_store reads and writes only through the
GraphBackend ABC, same guarantee as pwngraph.queries.
"""

from __future__ import annotations

from _fake_backend import FakeGraphBackend

from pwngraph.nexus.state import AttackState, Hypothesis, NexusStatus, Observation
from pwngraph.report_store import (
    KIND_SCAN_REPORT,
    load_nexus_state,
    load_scan_report,
    nexus_state_node_id,
    persist_nexus_state,
    persist_scan_report,
    report_node_id,
)
from pwngraph.types import Finding, Severity


def _finding(**over):
    defaults = dict(
        title="Critical agent hijack via tool poisoning",
        severity=Severity.CRITICAL,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
        cvss_score=9.6,
        target_system="lab_agent",
        attack_class="tool_poisoning",
        owasp=["LLM01", "LLM06"],
        payload_id="p1",
        summary="canary reached send_email",
        steps_to_reproduce=["Deliver the payload", "Agent calls send_email"],
        impact="Data exfiltration",
        remediation="Allow-list outbound destinations",
        evidence={"attack_success_rate": 0.6, "trials": 5, "successes": 3},
    )
    defaults.update(over)
    return Finding(**defaults)


def _persist(backend, scan_id="scan-1", **over):
    kwargs = dict(
        target_name="lab_agent",
        tool_inventory=["read_file", "send_email"],
        findings=[_finding()],
        asr={"overall": {"asr": 0.3, "successes": 12, "trials": 40}},
        owasp_coverage=[{"id": "LLM01", "name": "Prompt Injection", "status": "detected"}],
        risk_grade={"grade": "C", "score": 42, "interpretation": "Elevated"},
        summary={"paths_dangerous": 3},
        scanned_at="2026-08-19T00:00:00Z",
    )
    kwargs.update(over)
    return persist_scan_report(backend, scan_id, **kwargs)


def test_roundtrips_every_section():
    backend = FakeGraphBackend()
    _persist(backend)

    report = load_scan_report(backend, "scan-1")
    assert report is not None
    assert report["scan_id"] == "scan-1"
    assert report["target_name"] == "lab_agent"
    assert report["tool_inventory"] == ["read_file", "send_email"]
    assert report["asr"]["overall"]["trials"] == 40
    assert report["owasp_coverage"][0]["id"] == "LLM01"
    assert report["risk_grade"]["grade"] == "C"
    assert report["summary"]["paths_dangerous"] == 3


def test_finding_detail_survives_the_roundtrip():
    """The whole point of persisting: CVSS/steps/remediation cannot be
    re-derived from the trace graph's sink nodes."""
    backend = FakeGraphBackend()
    _persist(backend)

    f = load_scan_report(backend, "scan-1")["findings"][0]
    assert f["cvss_score"] == 9.6
    assert f["cvss_vector"].startswith("CVSS:3.1/")
    assert f["steps_to_reproduce"] == ["Deliver the payload", "Agent calls send_email"]
    assert f["remediation"] == "Allow-list outbound destinations"
    assert f["owasp"] == ["LLM01", "LLM06"]
    assert f["evidence"]["attack_success_rate"] == 0.6


def test_paths_are_excluded_from_persisted_findings():
    """Finding.paths carries the full event tree, which the trace graph already
    holds and renders far better — see the module docstring."""
    backend = FakeGraphBackend()
    _persist(backend)
    assert "paths" not in load_scan_report(backend, "scan-1")["findings"][0]


def test_missing_report_returns_none_not_an_error():
    backend = FakeGraphBackend()
    assert load_scan_report(backend, "never-scanned") is None


def test_a_plain_graph_node_is_not_mistaken_for_a_report():
    backend = FakeGraphBackend()
    backend.add_node(report_node_id("scan-1"), scan_id="scan-1", node_type="user_input")
    assert load_scan_report(backend, "scan-1") is None


def test_queryable_scalars_are_stored_alongside_the_json():
    backend = FakeGraphBackend()
    node_id = _persist(backend)

    attrs = backend.node_attrs(node_id)
    assert attrs["kind"] == KIND_SCAN_REPORT
    assert attrs["finding_count"] == 1
    assert attrs["risk_grade"] == "C"
    assert attrs["risk_score"] == 42
    assert attrs["max_severity"] == "critical"
    assert attrs["target_name"] == "lab_agent"


def test_max_severity_picks_the_worst_finding():
    backend = FakeGraphBackend()
    _persist(
        backend,
        findings=[
            _finding(severity=Severity.LOW),
            _finding(severity=Severity.HIGH),
            _finding(severity=Severity.MEDIUM),
        ],
    )
    assert backend.node_attrs(report_node_id("scan-1"))["max_severity"] == "high"


def test_report_node_carries_no_node_type_so_it_stays_out_of_the_trace_graph():
    """build_graph_view skips nodes without a node_type — that is what keeps
    this snapshot from appearing as a stray dot in the rendered graph."""
    from pwngraph.reporter.graph_export import build_graph_view

    backend = FakeGraphBackend()
    backend.add_node(
        "ev1",
        scan_id="scan-1",
        node_type="user_input",
        name="u",
        label="User",
        color="#199e70",
        shape="dot",
    )
    _persist(backend)

    view = build_graph_view(backend, "scan-1")
    assert [n["id"] for n in view["nodes"]] == ["ev1"]


def test_re_persisting_overwrites_rather_than_accumulating():
    backend = FakeGraphBackend()
    _persist(backend)
    _persist(backend, findings=[_finding(title="second run"), _finding()])

    report = load_scan_report(backend, "scan-1")
    assert len(report["findings"]) == 2
    assert backend.node_attrs(report_node_id("scan-1"))["finding_count"] == 2


def test_empty_scan_report_roundtrips():
    backend = FakeGraphBackend()
    _persist(backend, findings=[], asr={}, owasp_coverage=[], risk_grade={"grade": "A", "score": 0})

    report = load_scan_report(backend, "scan-1")
    assert report["findings"] == []
    assert report["risk_grade"]["grade"] == "A"
    assert backend.node_attrs(report_node_id("scan-1"))["max_severity"] == ""


def test_malformed_json_degrades_to_empty_rather_than_raising():
    """A corrupt payload should cost the reader that one section, not the
    whole report."""
    backend = FakeGraphBackend()
    _persist(backend)
    backend.add_node(report_node_id("scan-1"), findings_json="{not json")

    report = load_scan_report(backend, "scan-1")
    assert report["findings"] == []
    # Everything else still decodes.
    assert report["risk_grade"]["grade"] == "C"


# ---------------------------------------------------------------------------
# NEXUS state persistence
# ---------------------------------------------------------------------------


def _attack_state() -> AttackState:
    state = AttackState(
        attack_classes=["indirect_injection", "tool_poisoning"],
        level=4,
        budget=20,
    )
    state.record_observation(
        Observation(
            iteration=0,
            payload_id="p1",
            attack_class="indirect_injection",
            target_tool="read_file",
            tools_called=["read_file"],
            success=True,
            severity="high",
            confidence="high",
            signals=["injected content reached a tool-call argument"],
            action="explore",
            rationale="first probe — starting with 'indirect_injection'",
        )
    )
    state.hypotheses.append(
        Hypothesis(
            text="'indirect_injection' reaches attacker-influenced behavior via 'read_file'",
            confidence=0.3,
            attack_class="indirect_injection",
            supporting_iterations=[0],
        )
    )
    state.status = NexusStatus.STOPPED_BUDGET
    return state


def test_nexus_state_roundtrips():
    backend = FakeGraphBackend()
    persist_nexus_state(backend, "scan-1", _attack_state())

    loaded = load_nexus_state(backend, "scan-1")
    assert loaded is not None
    assert loaded["scan_id"] == "scan-1"
    assert loaded["status"] == "stopped_budget"
    assert loaded["iteration"] == 1
    assert loaded["budget"] == 20
    assert loaded["level"] == 4
    assert loaded["successful_techniques"] == ["indirect_injection"]

    obs = loaded["observations"]
    assert len(obs) == 1
    assert obs[0]["payload_id"] == "p1"
    assert obs[0]["action"] == "explore"
    assert obs[0]["rationale"] == "first probe — starting with 'indirect_injection'"

    hyps = loaded["hypotheses"]
    assert len(hyps) == 1
    assert hyps[0]["attack_class"] == "indirect_injection"
    assert hyps[0]["supporting_iterations"] == [0]


def test_missing_nexus_state_returns_none_not_an_error():
    """A static-mode scan (or one that predates this feature) has no NEXUS
    node — that's the honest answer, not an error."""
    backend = FakeGraphBackend()
    assert load_nexus_state(backend, "never-ran-nexus") is None


def test_nexus_state_and_scan_report_coexist_independently():
    """Both node kinds can live under the same scan_id without colliding —
    persisting one must not disturb the other."""
    backend = FakeGraphBackend()
    _persist(backend, scan_id="scan-1")
    persist_nexus_state(backend, "scan-1", _attack_state())

    assert load_scan_report(backend, "scan-1") is not None
    assert load_nexus_state(backend, "scan-1") is not None
    assert nexus_state_node_id("scan-1") != report_node_id("scan-1")


def test_a_scan_report_node_is_not_mistaken_for_nexus_state():
    backend = FakeGraphBackend()
    _persist(backend, scan_id="scan-1")
    # The report node exists, but has kind="scan_report", not "nexus_state".
    assert load_nexus_state(backend, "scan-1") is None
