"""Tests for pwngraph.preflight — doctor() environment checks and dry_run()."""

from __future__ import annotations

from pwngraph.connector.base import ToolSpec
from pwngraph.preflight import Check, doctor, dry_run, summarize


def test_doctor_python_check_passes_on_supported_version():
    checks = doctor()
    py_check = next(c for c in checks if c.name == "python")
    assert py_check.ok is True
    assert py_check.level == "required"


def test_doctor_required_dependency_imports_are_ok_in_test_env():
    """Every *importable* required dep should import cleanly here.

    Deliberately excludes ``neo4j-connection``: that check needs a live
    server, which this sandbox doesn't have (see the module docstring in
    pwngraph/preflight.py) — its own behavior is covered separately below via
    monkeypatch, without depending on real infrastructure.
    """
    checks = doctor()
    required_deps = [c for c in checks if c.level == "required" and c.name.startswith("dep:")]
    assert required_deps  # sanity: the required-dep-check set isn't empty
    assert all(c.ok for c in required_deps)


def test_doctor_neo4j_connection_check_is_required_and_present():
    checks = doctor()
    neo4j_check = next(c for c in checks if c.name == "neo4j-connection")
    assert neo4j_check.level == "required"


def test_doctor_neo4j_connection_check_passes_when_reachable(monkeypatch):
    class _StubBackend:
        def __init__(self, **_kwargs):
            pass

        @property
        def node_count(self):
            return 0

        def close(self):
            pass

    monkeypatch.setattr("pwngraph.backend.neo4j_backend.Neo4jBackend", _StubBackend)

    checks = doctor()
    neo4j_check = next(c for c in checks if c.name == "neo4j-connection")
    assert neo4j_check.ok is True
    assert "connected" in neo4j_check.detail


def test_doctor_neo4j_connection_check_fails_with_actionable_detail_when_unreachable(monkeypatch):
    class _StubBackend:
        def __init__(self, **_kwargs):
            raise ConnectionError("refused")

    monkeypatch.setattr("pwngraph.backend.neo4j_backend.Neo4jBackend", _StubBackend)

    checks = doctor()
    neo4j_check = next(c for c in checks if c.name == "neo4j-connection")
    assert neo4j_check.ok is False
    assert "docker compose up" in neo4j_check.detail


def test_check_fatal_property():
    assert Check("x", False, "required", "boom").fatal is True
    assert Check("x", True, "required", "ok").fatal is False
    assert Check("x", False, "optional", "meh").fatal is False


def test_summarize_ready_when_no_fatal_checks():
    ready, msg = summarize([Check("python", True, "required", "ok")])
    assert ready is True
    assert "READY" in msg


def test_summarize_not_ready_on_fatal_check():
    ready, msg = summarize([Check("python", False, "required", "too old")])
    assert ready is False
    assert "NOT READY" in msg


def test_summarize_ready_with_warning_when_optional_check_fails():
    ready, msg = summarize(
        [Check("python", True, "required", "ok"), Check("langchain", False, "optional", "missing")]
    )
    assert ready is True
    assert "warning" in msg.lower()


class _FakeConnector:
    def __init__(self, tools):
        self._tools = tools

    def list_tools(self):
        return self._tools

    def target_name(self):
        return "FakeAgent"


def test_dry_run_warns_on_zero_tools():
    result = dry_run(_FakeConnector([]))
    assert result.testable is False
    assert any("0 tools" in w for w in result.warnings)


def test_dry_run_warns_on_no_action_sinks():
    tools = [ToolSpec(name="read_file", description="Read a file")]
    result = dry_run(_FakeConnector(tools))
    assert result.testable is True
    assert any("action sinks" in w for w in result.warnings)


def test_dry_run_warns_on_no_data_sinks():
    tools = [ToolSpec(name="send_email", description="Send an email")]
    result = dry_run(_FakeConnector(tools))
    assert any("data sinks" in w for w in result.warnings)


def test_dry_run_clean_with_both_sink_types():
    tools = [
        ToolSpec(name="read_file", description="Read a file"),
        ToolSpec(name="send_email", description="Send an email"),
    ]
    result = dry_run(_FakeConnector(tools))
    assert result.warnings == []
    assert result.data_sinks == ["read_file"]
    assert result.action_sinks == ["send_email"]
