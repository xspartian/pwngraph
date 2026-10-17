"""Tests for pwngraph.poc — delivered-vs-defended tracking and PoC export."""

from __future__ import annotations

from pwngraph.poc import delivery_report, delivery_status, export_poc
from pwngraph.types import AttackPath, EdgeType, Finding, NodeType, Severity, TraceEvent


def _events(target_called: bool) -> list[TraceEvent]:
    events = [TraceEvent(run_id="r1", node_type=NodeType.USER_INPUT, name="user", content="hi")]
    if target_called:
        events.append(
            TraceEvent(
                run_id="r1", node_type=NodeType.TOOL_CALL, name="send_email", content="body=x"
            )
        )
    return events


def test_delivery_status_delivered():
    assert delivery_status(_events(True), "send_email") == "delivered"


def test_delivery_status_not_called():
    assert delivery_status(_events(False), "send_email") == "not_called"


def test_delivery_status_unknown_without_target():
    assert delivery_status(_events(True), None) == "unknown"


class _FakePayload:
    def __init__(self, target_tool: str | None):
        self.metadata = {"target_tool": target_tool}


class _FakeRecord:
    def __init__(self, adversarial, events, attack_class, payload):
        self.adversarial = adversarial
        self.events = events
        self.attack_class = attack_class
        self.payload = payload


def test_delivery_report_rollup():
    records = [
        _FakeRecord(True, _events(True), "tool_poisoning", _FakePayload("send_email")),
        _FakeRecord(True, _events(False), "tool_poisoning", _FakePayload("send_email")),
        _FakeRecord(False, _events(True), None, None),  # baseline run — excluded
    ]
    report = delivery_report(records)
    assert report["total_adv_runs"] == 2
    assert report["delivered"] == 1
    assert report["not_called"] == 1
    assert report["unknown"] == 0
    assert report["delivery_rate"] == 0.5
    assert report["undelivered_classes"] == {"tool_poisoning": 1}


def test_delivery_report_empty_input():
    report = delivery_report([])
    assert report["total_adv_runs"] == 0
    assert report["delivery_rate"] == 0.0


def _finding_with_path() -> Finding:
    canary = "PWN-DEADBEEF"
    events = [
        TraceEvent(
            run_id="r1",
            node_type=NodeType.USER_INPUT,
            name="user",
            content=f"do it {canary}",
            is_adversarial=True,
        ),
        TraceEvent(
            run_id="r1",
            node_type=NodeType.TOOL_CALL,
            name="send_email",
            content=f"body={canary}",
        ),
    ]
    path = AttackPath(
        events=events, edge_types=[EdgeType.TOOL_MANIPULATION], severity=Severity.HIGH
    )
    return Finding(
        title="Hijack",
        severity=Severity.HIGH,
        target_system="x",
        attack_class="tool_poisoning",
        payload_id="p1",
        summary="s",
        steps_to_reproduce=["step 1"],
        impact="i",
        remediation="r",
        paths=[path],
        evidence={"sink": f"canary {canary} reached tool"},
    )


def test_export_poc_writes_full_bundle(tmp_path):
    finding = _finding_with_path()
    poc_dir = export_poc(finding, tmp_path)

    assert (poc_dir / "poc.md").exists()
    assert (poc_dir / "poc.json").exists()
    assert (poc_dir / "payload.txt").exists()

    md = (poc_dir / "poc.md").read_text()
    assert "PWN-DEADBEEF" in md
    assert "Hijack" in md

    import json

    record = json.loads((poc_dir / "poc.json").read_text())
    assert record["canary"] == "PWN-DEADBEEF"
    assert record["attack_class"] == "tool_poisoning"
    assert "pwngraph scan" in record["replay_command"]
