"""Unit tests for pwngraph.nexus — the adaptive attack-intelligence layer.

Builds RunRecord/RunVerdict objects directly (the same types the real Oracle
produces — see pwngraph.oracle) so these tests exercise Nexus.observe() and
Nexus.decide_next() exactly as pwngraph.core._run_nexus_loop drives them,
without needing a live agent or Neo4j.
"""

from __future__ import annotations

from pwngraph.connector.base import ToolSpec
from pwngraph.fuzzer.payload import AttackClass, Payload
from pwngraph.nexus import (
    AttackState,
    DeterministicReasoner,
    Nexus,
    NexusAction,
    NexusDecision,
    NexusStatus,
    Observation,
)
from pwngraph.oracle import RunRecord, RunVerdict
from pwngraph.types import NodeType, Severity, TraceEvent


def _record(attack_class: str, tool_name: str | None, payload_id: str = "p1") -> RunRecord:
    events = [
        TraceEvent(run_id="r1", node_type=NodeType.USER_INPUT, name="user", content="hi"),
    ]
    if tool_name is not None:
        events.append(
            TraceEvent(run_id="r1", node_type=NodeType.TOOL_CALL, name=tool_name, content="args")
        )
    payload = Payload(
        payload_id=payload_id,
        attack_class=AttackClass(attack_class),
        delivery_input="deliver",
        injection_text="inject",
        canary="PWN-DEADBEEF",
        target_tool=tool_name,
    )
    return RunRecord.from_events(
        events, adversarial=True, attack_class=attack_class, payload=payload
    )


def _verdict(
    success: bool,
    confidence: str = "high",
    severity: Severity = Severity.HIGH,
    attack_class: str = "indirect_injection",
    payload_id: str = "p1",
) -> RunVerdict:
    return RunVerdict(
        run_id="r1",
        payload_id=payload_id,
        attack_class=attack_class,
        success=success,
        severity=severity,
        confidence=confidence,
        signals=["test signal"],
    )


# ---------------------------------------------------------------------------
# AttackState
# ---------------------------------------------------------------------------


def test_record_observation_tracks_success_and_capabilities():
    state = AttackState(attack_classes=["indirect_injection"], budget=10)
    obs = Observation(
        iteration=0,
        payload_id="p1",
        attack_class="indirect_injection",
        target_tool="read_file",
        tools_called=["read_file"],
        success=True,
        severity="high",
        confidence="high",
        signals=["hit"],
        new_capability=True,
        action="follow_path",
    )
    state.record_observation(obs)

    assert state.iteration == 1
    assert state.payload_history == ["p1"]
    assert state.tool_history == ["read_file"]
    assert state.discovered_capabilities == ["read_file"]
    assert state.successful_techniques == ["indirect_injection"]
    assert state.failed_techniques == []
    assert state.current_path == ["indirect_injection"]
    assert state.focus_attack_class == "indirect_injection"
    assert state.focus_tool == "read_file"


def test_current_path_only_grows_on_follow_path_pivots():
    """Ordinary breadth exploration (EXPLORE/ESCALATE/VALIDATE landing on a
    different class) must not count as chain progress — only a deliberate
    NexusAction.FOLLOW_PATH pivot does. Otherwise max_chain_depth caps
    breadth exploration instead of actual chain length."""
    state = AttackState(attack_classes=["a", "b", "c"], budget=10)
    state.record_observation(
        Observation(
            iteration=0,
            payload_id="p1",
            attack_class="a",
            success=True,
            confidence="high",
            action="explore",
        )
    )
    state.record_observation(
        Observation(
            iteration=1,
            payload_id="p2",
            attack_class="b",
            success=True,
            confidence="high",
            action="try_alternative",
        )
    )
    assert state.current_path == []

    state.record_observation(
        Observation(
            iteration=2,
            payload_id="p3",
            attack_class="c",
            success=True,
            confidence="high",
            action="follow_path",
        )
    )
    assert state.current_path == ["c"]
    assert state.confidence > 0.0


def test_record_observation_failure_then_success_clears_failed_technique():
    state = AttackState(attack_classes=["shell_injection"], budget=10)
    fail = Observation(iteration=0, payload_id="p1", attack_class="shell_injection", success=False)
    state.record_observation(fail)
    assert state.failed_techniques == ["shell_injection"]

    win = Observation(
        iteration=1,
        payload_id="p2",
        attack_class="shell_injection",
        success=True,
        confidence="high",
    )
    state.record_observation(win)
    assert state.successful_techniques == ["shell_injection"]
    assert state.failed_techniques == []


def test_consecutive_failures_resets_across_class_switch():
    state = AttackState(attack_classes=["a", "b"], budget=10)
    state.record_observation(
        Observation(iteration=0, payload_id="p1", attack_class="a", success=False)
    )
    state.record_observation(
        Observation(iteration=1, payload_id="p2", attack_class="a", success=False)
    )
    assert state.consecutive_failures("a") == 2

    state.record_observation(
        Observation(iteration=2, payload_id="p3", attack_class="b", success=False)
    )
    assert state.consecutive_failures("a") == 0
    assert state.consecutive_failures("b") == 1


# ---------------------------------------------------------------------------
# Nexus — decision state machine
# ---------------------------------------------------------------------------


def _tools() -> list[ToolSpec]:
    return [
        ToolSpec(name="read_file", description="read a file from disk", tags=["file"]),
        ToolSpec(name="send_email", description="send an email", tags=["email"]),
    ]


def test_first_decision_is_explore():
    nexus = Nexus(attack_classes=["indirect_injection", "tool_poisoning"], tools=_tools(), budget=5)
    decision = nexus.decide_next()
    assert decision.action is NexusAction.EXPLORE
    assert decision.attack_class == "indirect_injection"


def _satisfy_floor_for_other_classes(
    nexus: Nexus, other_classes: list[str], tool_name: str
) -> None:
    """Test helper: give every class in ``other_classes`` one (failing)
    attempt so the joint coverage floor no longer has anything to say about
    them, letting a test isolate reactive behavior for the one class it
    cares about. Also touches ``tool_name`` so it doesn't dangle as
    'never touched' either."""
    for cls in other_classes:
        nexus.observe(
            _record(cls, tool_name),
            _verdict(success=False, confidence="low", attack_class=cls),
            action=NexusAction.EXPLORE,
        )


def test_high_confidence_success_harvests_untried_tool_before_escalating():
    """Once the joint class/tool coverage floor is satisfied, a confirmed
    class isn't 'done' after one tool — a different tool is a structurally
    distinct finding, so NEXUS tries it before hardening or switching
    classes (this is the fix for the 8-findings-vs-2-findings regression:
    NEXUS was moving on after one tool per class)."""
    classes = ["indirect_injection", "tool_poisoning", "prompt_exfiltration"]
    nexus = Nexus(attack_classes=classes, tools=_tools(), budget=10, level=1)
    _satisfy_floor_for_other_classes(nexus, ["tool_poisoning", "prompt_exfiltration"], "send_email")

    nexus.observe(
        _record("indirect_injection", "read_file"),
        _verdict(success=True, confidence="high", attack_class="indirect_injection"),
        action=NexusAction.EXPLORE,
    )
    assert not nexus._never_touched_classes()
    assert not nexus._never_touched_tools()

    decision = nexus.decide_next()
    assert decision.action is NexusAction.EXPLORE
    assert decision.attack_class == "indirect_injection"
    assert decision.tools_hint == ["send_email"]


def test_high_confidence_success_escalates_once_tool_surface_is_a_single_tool():
    single_tool = [ToolSpec(name="read_file", description="read a file", tags=["file"])]
    nexus = Nexus(attack_classes=["indirect_injection"], tools=single_tool, budget=5, level=1)
    record = _record("indirect_injection", "read_file")
    verdict = _verdict(success=True, confidence="high", attack_class="indirect_injection")
    nexus.observe(record, verdict, action=NexusAction.EXPLORE)

    # Only one tool and one class exist, so the coverage floor is already
    # satisfied and there's nothing left to harvest — falls through to the
    # hardening behavior.
    decision = nexus.decide_next()
    assert decision.action is NexusAction.ESCALATE
    assert decision.attack_class == "indirect_injection"
    assert decision.tools_hint == ["read_file"]


def test_high_confidence_success_pivots_to_follow_path_after_tool_surface_exhausted():
    classes = ["indirect_injection", "tool_poisoning", "prompt_exfiltration"]
    nexus = Nexus(attack_classes=classes, tools=_tools(), budget=10, level=4)
    _satisfy_floor_for_other_classes(nexus, ["tool_poisoning", "prompt_exfiltration"], "send_email")

    for tool_name, pid in (("read_file", "p1"), ("send_email", "p2")):
        record = _record("indirect_injection", tool_name, payload_id=pid)
        verdict = _verdict(success=True, confidence="high", attack_class="indirect_injection")
        nexus.observe(record, verdict, action=NexusAction.EXPLORE)

    # Both the joint floor and indirect_injection's own 2-tool surface are
    # fully covered — only now should it pivot to a different class for
    # chain pursuit, instead of pivoting after the very first success (which
    # used to skip same-class breadth entirely).
    decision = nexus.decide_next()
    assert decision.action is NexusAction.FOLLOW_PATH
    assert decision.attack_class == "tool_poisoning"


def test_first_success_does_not_pivot_before_harvesting_even_with_chains_enabled():
    """Regression guard: level 4/5 must not skip same-class tool coverage —
    FOLLOW_PATH firing on the very first success meant higher levels covered
    LESS of a confirmed class's tool surface than lower ones."""
    classes = ["indirect_injection", "tool_poisoning", "prompt_exfiltration"]
    nexus = Nexus(attack_classes=classes, tools=_tools(), budget=10, level=4)
    _satisfy_floor_for_other_classes(nexus, ["tool_poisoning", "prompt_exfiltration"], "send_email")

    record = _record("indirect_injection", "read_file")
    verdict = _verdict(success=True, confidence="high", attack_class="indirect_injection")
    nexus.observe(record, verdict, action=NexusAction.EXPLORE)

    decision = nexus.decide_next()
    assert decision.action is NexusAction.EXPLORE
    assert decision.attack_class == "indirect_injection"
    assert decision.tools_hint == ["send_email"]


def test_chain_depth_limit_stops_pivoting_but_not_the_whole_scan():
    """Regression guard: hitting max_chain_depth used to STOP the entire
    NEXUS loop, even with budget left and classes never attempted. It should
    only stop *extending that chain* — the scan keeps exploring breadth."""
    tools_list = _tools()  # read_file, send_email
    classes = ["indirect_injection", "tool_poisoning", "prompt_exfiltration", "shell_injection"]
    nexus = Nexus(attack_classes=classes, tools=tools_list, budget=30, level=4)  # max_chain_depth=3

    # Simulate 3 successful FOLLOW_PATH-driven pivots across 3 classes, each
    # with its 2-tool surface fully harvested (both tools tried).
    for cls, pid in [
        ("indirect_injection", "p1"),
        ("tool_poisoning", "p2"),
        ("prompt_exfiltration", "p3"),
    ]:
        for tool_name, is_pivot in [("read_file", True), ("send_email", False)]:
            rec = _record(cls, tool_name, payload_id=f"{pid}-{tool_name}")
            v = _verdict(success=True, confidence="high", attack_class=cls)
            nexus.observe(rec, v, action=NexusAction.FOLLOW_PATH if is_pivot else None)

    assert len(nexus.state.current_path) == 3  # chain depth cap reached

    decision = nexus.decide_next()
    assert decision.action is not NexusAction.FOLLOW_PATH
    assert not decision.is_stop
    assert not nexus.should_stop()
    assert decision.attack_class == "shell_injection"  # the untried class remains reachable


def test_untouched_tool_takes_priority_over_same_class_failure_retry():
    """The tool-coverage floor beats reactive failure-retry: an untouched
    tool gets tried (with whichever class has the least evidence so far)
    before NEXUS retries the class that just failed against a different
    tool. This is the fix for action-sink tools (send_email/http_post/
    run_code) going completely untouched for an entire scan."""
    nexus = Nexus(
        attack_classes=["indirect_injection", "tool_poisoning"], tools=_tools(), budget=10, level=1
    )
    record = _record("indirect_injection", "read_file")
    verdict = _verdict(success=False, confidence="low", attack_class="indirect_injection")
    nexus.observe(record, verdict)

    decision = nexus.decide_next()
    assert decision.action is NexusAction.EXPLORE
    assert decision.tools_hint == ["send_email"]
    assert decision.attack_class == "tool_poisoning"  # least-tried class, nothing has succeeded yet


def test_medium_confidence_success_validates_before_moving_on():
    nexus = Nexus(
        attack_classes=["indirect_injection", "tool_poisoning"], tools=_tools(), budget=8, level=2
    )
    # Satisfy the joint coverage floor (tool_poisoning gets its one attempt),
    # then cover both tools for indirect_injection at medium confidence so
    # this exercises the validate-before-escalate mechanic in isolation.
    _satisfy_floor_for_other_classes(nexus, ["tool_poisoning"], "send_email")
    for tool_name in ("read_file", "send_email"):
        record = _record("indirect_injection", tool_name)
        verdict = _verdict(success=True, confidence="medium", attack_class="indirect_injection")
        nexus.observe(record, verdict, action=NexusAction.EXPLORE)

    decision = nexus.decide_next()
    assert decision.action is NexusAction.VALIDATE
    assert decision.attack_class == "indirect_injection"


def test_repeated_failure_switches_to_alternative():
    nexus = Nexus(
        attack_classes=["indirect_injection", "tool_poisoning"], tools=_tools(), budget=10, level=1
    )
    # Satisfy the joint coverage floor first (so it doesn't intercept), then
    # drive indirect_injection's failures to level 1's tolerance of 2.
    _satisfy_floor_for_other_classes(nexus, ["tool_poisoning"], "read_file")
    for tool_name in ("read_file", "send_email"):
        record = _record("indirect_injection", tool_name)
        verdict = _verdict(success=False, confidence="low", attack_class="indirect_injection")
        nexus.observe(record, verdict, action=NexusAction.EXPLORE)

    decision = nexus.decide_next()
    assert decision.action is NexusAction.TRY_ALTERNATIVE
    assert decision.attack_class == "tool_poisoning"


def test_stops_when_budget_exhausted():
    nexus = Nexus(attack_classes=["indirect_injection"], tools=_tools(), budget=1, level=1)
    record = _record("indirect_injection", None)
    verdict = _verdict(success=False, confidence="low", attack_class="indirect_injection")
    nexus.observe(record, verdict)

    assert nexus.should_stop()
    decision = nexus.decide_next()
    assert decision.action is NexusAction.STOP
    assert nexus.state.status is NexusStatus.STOPPED_BUDGET


def test_confidence_alone_does_not_stop_while_a_tool_remains_untouched():
    """Objective-achieved must require every tool to have been tried too —
    otherwise NEXUS can declare victory having left a tool (e.g. an
    unexplored action sink) sitting completely untouched."""
    nexus = Nexus(attack_classes=["indirect_injection"], tools=_tools(), budget=20, level=1)
    # Three high-confidence hits (0.3 each) clear level 1's 0.80 threshold,
    # but every one of them targets the same tool.
    for i in range(3):
        record = _record("indirect_injection", "read_file", payload_id=f"p{i}")
        verdict = _verdict(success=True, confidence="high", attack_class="indirect_injection")
        nexus.observe(record, verdict)
    assert nexus.state.confidence >= nexus.cfg.stop_confidence

    decision = nexus.decide_next()
    assert decision.action is not NexusAction.STOP
    assert decision.tools_hint == ["send_email"]


def test_stops_when_confidence_threshold_reached_and_every_tool_is_covered():
    nexus = Nexus(attack_classes=["indirect_injection"], tools=_tools(), budget=20, level=1)
    for i, tool_name in enumerate(["read_file", "send_email", "read_file"]):
        record = _record("indirect_injection", tool_name, payload_id=f"p{i}")
        verdict = _verdict(success=True, confidence="high", attack_class="indirect_injection")
        nexus.observe(record, verdict)

    decision = nexus.decide_next()
    assert decision.action is NexusAction.STOP
    assert nexus.state.status is NexusStatus.STOPPED_OBJECTIVE


def test_observe_extracts_tools_called_and_new_capability():
    nexus = Nexus(attack_classes=["tool_poisoning"], tools=_tools(), budget=5, level=1)
    record = _record("tool_poisoning", "send_email")
    verdict = _verdict(success=True, confidence="high", attack_class="tool_poisoning")
    obs = nexus.observe(record, verdict)

    assert obs.tools_called == ["send_email"]
    assert obs.new_capability is True
    assert nexus.state.discovered_capabilities == ["send_email"]

    # A second observation calling the same tool is no longer a new capability.
    record2 = _record("tool_poisoning", "send_email", payload_id="p2")
    verdict2 = _verdict(success=False, confidence="low", attack_class="tool_poisoning")
    obs2 = nexus.observe(record2, verdict2)
    assert obs2.new_capability is False


# ---------------------------------------------------------------------------
# DeterministicReasoner
# ---------------------------------------------------------------------------


def test_deterministic_reasoner_prefers_already_successful_class():
    state = AttackState(attack_classes=["a", "b"], budget=10)
    state.record_observation(
        Observation(iteration=0, payload_id="p1", attack_class="a", success=True, confidence="high")
    )

    candidates = [
        NexusDecision(action=NexusAction.EXPLORE, attack_class="b", rationale="unexplored"),
        NexusDecision(action=NexusAction.ESCALATE, attack_class="a", rationale="already won"),
    ]
    ranked = DeterministicReasoner().rank(state, candidates)
    assert ranked[0].attack_class == "a"


def test_deterministic_reasoner_is_a_noop_for_single_candidate():
    state = AttackState(attack_classes=["a"], budget=10)
    candidates = [NexusDecision(action=NexusAction.EXPLORE, attack_class="a")]
    assert DeterministicReasoner().rank(state, candidates) == candidates


# ---------------------------------------------------------------------------
# Capability map / plan integration
# ---------------------------------------------------------------------------


def test_plan_is_built_at_construction_and_drains_as_probes_land():
    tools = _tools()  # read_file, send_email
    nexus = Nexus(attack_classes=["indirect_injection", "tool_poisoning"], tools=tools, budget=10)

    assert len(nexus.plan) == 2  # min(#classes, #tools)
    assert nexus.plan[0].attack_class == "indirect_injection"
    assert nexus.plan[0].tool == "send_email"  # action sinks sorted first

    assert nexus.capability_map.target_name == "unknown"
    assert set(nexus.capability_map.tools.keys()) == {"read_file", "send_email"}


def test_plan_records_dynamic_coverage_decisions_too():
    tools = _tools()
    nexus = Nexus(attack_classes=["indirect_injection", "tool_poisoning"], tools=tools, budget=10)
    initial_len = len(nexus.plan)

    decision = nexus.decide_next()
    assert decision.action is NexusAction.EXPLORE
    # _coverage_probe appends what it actually decided, growing the plan
    # into a real record of NEXUS's choices, not just the upfront sweep.
    assert len(nexus.plan) >= initial_len


def _two_hop_record(source_tool: str, target_tool: str, attack_class: str) -> RunRecord:
    """A probe whose trace shows target_tool genuinely called as a
    descendant of source_tool's own result — real causality, not a guess."""
    root = TraceEvent(run_id="r1", node_type=NodeType.USER_INPUT, name="user", content="hi")
    call_a = TraceEvent(
        run_id="r1",
        node_type=NodeType.TOOL_CALL,
        name=source_tool,
        content="x",
        parent_event_id=root.event_id,
    )
    result_a = TraceEvent(
        run_id="r1",
        node_type=NodeType.TOOL_RESULT,
        name=source_tool,
        content="poisoned",
        parent_event_id=call_a.event_id,
    )
    call_b = TraceEvent(
        run_id="r1",
        node_type=NodeType.TOOL_CALL,
        name=target_tool,
        content="y",
        parent_event_id=result_a.event_id,
    )
    events = [root, call_a, result_a, call_b]
    payload = Payload(
        payload_id="p1",
        attack_class=AttackClass(attack_class),
        delivery_input="d",
        injection_text="i",
        canary="PWN-DEADBEEF",
        target_tool=source_tool,
    )
    return RunRecord.from_events(
        events, adversarial=True, attack_class=attack_class, payload=payload
    )


def test_observe_confirms_relationship_from_real_trace_causality():
    tools = _tools()
    nexus = Nexus(attack_classes=["indirect_injection", "tool_poisoning"], tools=tools, budget=10)

    record = _two_hop_record("read_file", "send_email", "indirect_injection")
    verdict = _verdict(success=True, confidence="high", attack_class="indirect_injection")
    nexus.observe(record, verdict, action=NexusAction.EXPLORE)

    confirmed = [r for r in nexus.capability_map.relationships if r.kind == "confirmed_chain"]
    assert len(confirmed) == 1
    assert confirmed[0].source_tool == "read_file"
    assert confirmed[0].target_tool == "send_email"


def test_observe_always_forms_a_hypothesis_even_at_level_1():
    """REASON is a real, always-on step, not decorative — previously
    hypothesize() only ran when cfg.use_reasoner (level >= 3)."""
    nexus = Nexus(attack_classes=["indirect_injection"], tools=_tools(), budget=10, level=1)
    record = _record("indirect_injection", "read_file")
    verdict = _verdict(success=True, confidence="high", attack_class="indirect_injection")
    nexus.observe(record, verdict, action=NexusAction.EXPLORE)

    assert len(nexus.state.hypotheses) >= 1


# ---------------------------------------------------------------------------
# Exhaustive mode
# ---------------------------------------------------------------------------


def test_exhaustive_mode_skips_the_confidence_based_early_stop():
    """Regression guard for the 'one class got 11 probes, four classes got
    exactly 1 each' gap: with exhaustive=True, satisfying breadth+confidence
    must NOT stop the scan — only budget exhaustion or a genuine dead end may."""
    nexus = Nexus(
        attack_classes=["indirect_injection"], tools=_tools(), budget=20, level=1, exhaustive=True
    )
    for i, tool_name in enumerate(["read_file", "send_email", "read_file"]):
        record = _record("indirect_injection", tool_name, payload_id=f"p{i}")
        verdict = _verdict(success=True, confidence="high", attack_class="indirect_injection")
        nexus.observe(record, verdict, action=NexusAction.EXPLORE)
    # Full breadth (only class attempted, both tools touched) + confidence
    # threshold cleared — the exact conditions that stop a non-exhaustive run.
    assert nexus.state.confidence >= nexus.cfg.stop_confidence
    assert not nexus._never_touched_tools()
    assert nexus.state.breadth_complete()

    decision = nexus.decide_next()
    assert decision.action is not NexusAction.STOP
    assert nexus.state.status is NexusStatus.RUNNING
    assert not nexus.should_stop()


def test_non_exhaustive_mode_still_stops_at_the_objective_gate():
    """Default behavior (exhaustive=False) is unchanged."""
    nexus = Nexus(attack_classes=["indirect_injection"], tools=_tools(), budget=20, level=1)
    for i, tool_name in enumerate(["read_file", "send_email", "read_file"]):
        record = _record("indirect_injection", tool_name, payload_id=f"p{i}")
        verdict = _verdict(success=True, confidence="high", attack_class="indirect_injection")
        nexus.observe(record, verdict, action=NexusAction.EXPLORE)

    decision = nexus.decide_next()
    assert decision.action is NexusAction.STOP
    assert nexus.state.status is NexusStatus.STOPPED_OBJECTIVE


def test_observe_stores_the_decision_rationale_on_the_observation():
    """The Logs tab shows NEXUS's own "why" next to each probe — it has to
    survive from the transient NexusDecision onto the persisted Observation."""
    nexus = Nexus(attack_classes=["indirect_injection"], tools=_tools(), budget=5, level=1)
    decision = nexus.decide_next()
    record = _record("indirect_injection", "read_file")
    verdict = _verdict(success=True, confidence="high", attack_class="indirect_injection")
    obs = nexus.observe(record, verdict, action=decision.action, rationale=decision.rationale)

    assert obs.rationale == decision.rationale
    assert obs.rationale != ""
    assert nexus.state.observations[-1].rationale == decision.rationale
