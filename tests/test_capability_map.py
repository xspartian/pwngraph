"""Unit tests for pwngraph.nexus.capability_map — the ENUMERATE artifact."""

from __future__ import annotations

from pwngraph.connector.base import ToolSpec
from pwngraph.nexus.capability_map import AgentCapabilityMap
from pwngraph.types import NodeType, TraceEvent


def _tools() -> list[ToolSpec]:
    return [
        ToolSpec(name="read_file", description="read a file from disk", tags=["file"]),
        ToolSpec(name="web_search", description="search the web", tags=["web"]),
        ToolSpec(name="send_email", description="send an email", tags=["email"]),
    ]


def test_build_wraps_tools_and_seeds_possible_chains():
    cap_map = AgentCapabilityMap.build("test-agent", _tools())

    assert set(cap_map.tools.keys()) == {"read_file", "web_search", "send_email"}
    assert cap_map.tools["read_file"].is_data_sink is True
    assert cap_map.tools["send_email"].is_action_sink is True
    assert "read_file" in cap_map.data_sinks
    assert "web_search" in cap_map.data_sinks
    assert "send_email" in cap_map.action_sinks

    # Every (data_sink, action_sink) pair seeded as a possible_chain — 2
    # data sinks x 1 action sink here.
    pairs = {(r.source_tool, r.target_tool) for r in cap_map.relationships}
    assert pairs == {("read_file", "send_email"), ("web_search", "send_email")}
    assert all(r.kind == "possible_chain" for r in cap_map.relationships)


def test_build_with_no_action_sinks_seeds_no_relationships():
    tools = [ToolSpec(name="read_file", description="read a file", tags=["file"])]
    cap_map = AgentCapabilityMap.build("test-agent", tools)
    assert cap_map.relationships == []


def test_record_confirmed_relationship_promotes_existing_hypothesis():
    cap_map = AgentCapabilityMap.build("test-agent", _tools())
    cap_map.record_confirmed_relationship("read_file", "send_email", evidence="observed")

    matches = [
        r
        for r in cap_map.relationships
        if r.source_tool == "read_file" and r.target_tool == "send_email"
    ]
    assert len(matches) == 1
    assert matches[0].kind == "confirmed_chain"
    assert matches[0].confidence >= 0.9


def test_record_confirmed_relationship_adds_new_when_not_hypothesized():
    cap_map = AgentCapabilityMap.build("test-agent", _tools())
    # web_search -> read_file wasn't seeded (read_file isn't an action sink).
    cap_map.record_confirmed_relationship("web_search", "read_file", evidence="observed anyway")

    matches = [
        r
        for r in cap_map.relationships
        if r.source_tool == "web_search" and r.target_tool == "read_file"
    ]
    assert len(matches) == 1
    assert matches[0].kind == "confirmed_chain"


def test_record_confirmed_relationships_from_events_detects_real_causality():
    cap_map = AgentCapabilityMap.build("test-agent", _tools())

    root = TraceEvent(run_id="r1", node_type=NodeType.USER_INPUT, name="user", content="hi")
    call_a = TraceEvent(
        run_id="r1",
        node_type=NodeType.TOOL_CALL,
        name="read_file",
        content="x",
        parent_event_id=root.event_id,
    )
    result_a = TraceEvent(
        run_id="r1",
        node_type=NodeType.TOOL_RESULT,
        name="read_file",
        content="poisoned",
        parent_event_id=call_a.event_id,
    )
    # send_email called as a descendant of read_file's result — real 2-hop causality.
    call_b = TraceEvent(
        run_id="r1",
        node_type=NodeType.TOOL_CALL,
        name="send_email",
        content="y",
        parent_event_id=result_a.event_id,
    )
    events = [root, call_a, result_a, call_b]

    found = cap_map.record_confirmed_relationships_from_events(events)
    assert found == [("read_file", "send_email")]

    confirmed = [r for r in cap_map.relationships if r.kind == "confirmed_chain"]
    assert len(confirmed) == 1
    assert confirmed[0].source_tool == "read_file"
    assert confirmed[0].target_tool == "send_email"


def test_record_confirmed_relationships_ignores_same_tool_self_calls():
    cap_map = AgentCapabilityMap.build("test-agent", _tools())
    root = TraceEvent(run_id="r1", node_type=NodeType.USER_INPUT, name="user", content="hi")
    call_a = TraceEvent(
        run_id="r1",
        node_type=NodeType.TOOL_CALL,
        name="read_file",
        content="x",
        parent_event_id=root.event_id,
    )
    result_a = TraceEvent(
        run_id="r1",
        node_type=NodeType.TOOL_RESULT,
        name="read_file",
        content="y",
        parent_event_id=call_a.event_id,
    )
    events = [root, call_a, result_a]
    found = cap_map.record_confirmed_relationships_from_events(events)
    assert found == []


def test_ranked_action_sinks_prioritizes_confirmed_then_possible_then_rest():
    tools = [
        ToolSpec(name="read_file", description="read a file", tags=["file"]),
        ToolSpec(name="send_email", description="send an email", tags=["email"]),
        ToolSpec(name="run_code", description="execute code", tags=["code"]),
    ]
    cap_map = AgentCapabilityMap.build("test-agent", tools)
    # Both send_email and run_code start as "possible" from read_file.
    cap_map.record_confirmed_relationship("read_file", "run_code", evidence="observed")

    ranked = cap_map.ranked_action_sinks(from_tool="read_file")
    assert ranked[0] == "run_code"  # confirmed wins
    assert "send_email" in ranked


def test_ranked_action_sinks_prefers_untouched_within_a_tier():
    tools = [
        ToolSpec(name="read_file", description="read a file", tags=["file"]),
        ToolSpec(name="send_email", description="send an email", tags=["email"]),
        ToolSpec(name="run_code", description="execute code", tags=["code"]),
    ]
    cap_map = AgentCapabilityMap.build("test-agent", tools)
    # Both are "possible" from read_file (same tier) — prefer the untouched one.
    ranked = cap_map.ranked_action_sinks(from_tool="read_file", prefer_untouched={"run_code"})
    assert ranked[0] == "run_code"
