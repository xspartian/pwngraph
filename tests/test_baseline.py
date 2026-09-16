"""Tests for pwngraph.baseline — round-tripping AttackPaths through JSON."""

from __future__ import annotations

from pwngraph.attackpath import diff_paths
from pwngraph.baseline import load_baseline, save_baseline
from pwngraph.types import AttackPath, EdgeType, NodeType, Severity, TraceEvent


def _path(name: str, severity: Severity = Severity.HIGH) -> AttackPath:
    ev = TraceEvent(
        run_id="r1",
        node_type=NodeType.TOOL_CALL,
        name=name,
        content="body=x",
        is_adversarial=True,
        metadata={"note": "test"},
    )
    return AttackPath(
        events=[ev],
        edge_types=[EdgeType.TOOL_MANIPULATION],
        severity=severity,
        description="a path",
        confidence="high",
    )


def test_round_trip_preserves_path_count(tmp_path):
    paths = [_path("send_email"), _path("run_code", Severity.CRITICAL)]
    f = save_baseline(paths, tmp_path / "baseline.json")
    reloaded = load_baseline(f)
    assert len(reloaded) == 2


def test_round_trip_preserves_severity_and_confidence(tmp_path):
    paths = [_path("send_email", Severity.CRITICAL)]
    f = save_baseline(paths, tmp_path / "baseline.json")
    reloaded = load_baseline(f)
    assert reloaded[0].severity is Severity.CRITICAL
    assert reloaded[0].confidence == "high"


def test_round_trip_preserves_event_fields(tmp_path):
    paths = [_path("send_email")]
    f = save_baseline(paths, tmp_path / "baseline.json")
    reloaded = load_baseline(f)
    ev = reloaded[0].events[0]
    assert ev.name == "send_email"
    assert ev.node_type is NodeType.TOOL_CALL
    assert ev.is_adversarial is True
    assert ev.metadata == {"note": "test"}


def test_round_trip_preserves_signature(tmp_path):
    # signature() is what diff_paths keys on — it must survive the round trip
    # byte-for-byte or every reloaded baseline would show as entirely new.
    original = _path("send_email")
    f = save_baseline([original], tmp_path / "baseline.json")
    reloaded = load_baseline(f)
    assert reloaded[0].signature() == original.signature()


def test_empty_baseline_round_trips(tmp_path):
    f = save_baseline([], tmp_path / "baseline.json")
    assert load_baseline(f) == []


def test_diff_against_a_reloaded_baseline_matches_in_process_diff(tmp_path):
    before = [_path("send_email")]
    after = [_path("send_email"), _path("run_code")]

    f = save_baseline(before, tmp_path / "baseline.json")
    reloaded_before = load_baseline(f)

    diff = diff_paths(reloaded_before, after)

    assert {p.events[0].name for p in diff.new} == {"run_code"}
    assert len(diff.persisting) == 1


# ---------------------------------------------------------------------------
# Grade sidecar
# ---------------------------------------------------------------------------


def test_baseline_grade_round_trips(tmp_path):
    from pwngraph.baseline import load_baseline_grade, save_baseline_grade

    grade = {"grade": "C", "score": 42, "max_score": 100}
    baseline_path = save_baseline([_path("send_email")], tmp_path / "baseline.json")
    save_baseline_grade(grade, baseline_path)

    assert load_baseline_grade(baseline_path) == grade


def test_baseline_without_a_saved_grade_returns_none(tmp_path):
    from pwngraph.baseline import load_baseline_grade

    baseline_path = save_baseline([_path("send_email")], tmp_path / "baseline.json")
    # No save_baseline_grade() call — mirrors a baseline saved before grade
    # tracking existed, or with --save-baseline but no grade sidecar.
    assert load_baseline_grade(baseline_path) is None


def test_baseline_grade_sidecar_does_not_disturb_the_baseline_file_itself(tmp_path):
    from pwngraph.baseline import save_baseline_grade

    baseline_path = save_baseline([_path("send_email")], tmp_path / "baseline.json")
    save_baseline_grade({"grade": "A", "score": 5}, baseline_path)

    # The baseline itself still round-trips exactly as before.
    reloaded = load_baseline(baseline_path)
    assert len(reloaded) == 1
    assert reloaded[0].events[0].name == "send_email"
