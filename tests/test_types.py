"""Tests for pwngraph.types — Severity buckets, TraceEvent, AttackPath, Finding."""

from __future__ import annotations

import pytest

from pwngraph.types import (
    AttackPath,
    EdgeType,
    Finding,
    NodeType,
    Severity,
    TraceEvent,
)


@pytest.mark.parametrize(
    "score, expected",
    [
        (0.0, Severity.INFO),
        (2.0, Severity.LOW),
        (3.9, Severity.LOW),
        (4.0, Severity.MEDIUM),
        (6.9, Severity.MEDIUM),
        (7.0, Severity.HIGH),
        (8.9, Severity.HIGH),
        (9.0, Severity.CRITICAL),
        (10.0, Severity.CRITICAL),
    ],
)
def test_severity_from_cvss_boundaries(score, expected):
    assert Severity.from_cvss(score) is expected


def test_severity_score_is_monotonically_increasing():
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    scores = [s.score for s in order]
    assert scores == sorted(scores)
    assert len(set(scores)) == len(scores)


def test_trace_event_short_truncates_and_strips_newlines():
    ev = TraceEvent(
        run_id="r1",
        node_type=NodeType.TOOL_CALL,
        name="send_email",
        content="line one\nline two\n" * 10,
    )
    s = ev.short()
    assert "\n" not in s
    assert "send_email" in s
    assert "tool_call" in s


def test_edge_type_is_adversarial():
    assert EdgeType.NORMAL_FLOW.is_adversarial is False
    assert EdgeType.DATA_EXFIL.is_adversarial is True
    assert EdgeType.DIRECT_INJECTION.is_adversarial is True
    assert EdgeType.CONTEXT_POISONING.is_adversarial is True
    assert EdgeType.TOOL_MANIPULATION.is_adversarial is True


def _path_events() -> list[TraceEvent]:
    return [
        TraceEvent(run_id="r1", node_type=NodeType.USER_INPUT, name="user", content="hi"),
        TraceEvent(run_id="r1", node_type=NodeType.TOOL_CALL, name="send_email", content="body=x"),
    ]


def test_attack_path_length_and_hop_count():
    path = AttackPath(events=_path_events(), edge_types=[EdgeType.TOOL_MANIPULATION])
    assert path.length == 2
    assert path.hop_count == 1


def test_attack_path_hop_count_never_negative():
    path = AttackPath(events=[], edge_types=[])
    assert path.hop_count == 0


def test_attack_path_is_adversarial_reflects_events():
    events = _path_events()
    assert AttackPath(events=events, edge_types=[EdgeType.NORMAL_FLOW]).is_adversarial is False
    events[1].is_adversarial = True
    assert AttackPath(events=events, edge_types=[EdgeType.TOOL_MANIPULATION]).is_adversarial is True


def test_attack_path_signature_stable_for_same_shape():
    path_a = AttackPath(events=_path_events(), edge_types=[EdgeType.TOOL_MANIPULATION])
    path_b = AttackPath(events=_path_events(), edge_types=[EdgeType.TOOL_MANIPULATION])
    assert path_a.signature() == path_b.signature()


def test_attack_path_signature_differs_for_different_shape():
    path_a = AttackPath(events=_path_events(), edge_types=[EdgeType.TOOL_MANIPULATION])
    other_events = _path_events()
    other_events.append(
        TraceEvent(run_id="r1", node_type=NodeType.FINAL_ANSWER, name="agent", content="done")
    )
    path_b = AttackPath(
        events=other_events,
        edge_types=[EdgeType.TOOL_MANIPULATION, EdgeType.NORMAL_FLOW],
    )
    assert path_a.signature() != path_b.signature()


def test_finding_construction_defaults():
    finding = Finding(
        title="t",
        severity=Severity.HIGH,
        target_system="x",
        attack_class="shell_injection",
        payload_id="p1",
        summary="s",
        steps_to_reproduce=["a"],
        impact="i",
        remediation="r",
    )
    assert finding.severity is Severity.HIGH
    assert finding.owasp == []
    assert finding.paths == []
    assert finding.evidence == {}
