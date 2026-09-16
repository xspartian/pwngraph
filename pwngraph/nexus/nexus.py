"""Nexus — decides what to probe next, from everything observed so far.

This is the loop's brain, not another payload generator. It consumes the
same ``RunRecord``/``RunVerdict`` types the rest of the engine already uses
(``pwngraph.oracle``) and hands back a :class:`~pwngraph.nexus.decision.NexusDecision`
naming an attack class and, optionally, which tools the Fuzzer should prefer
— never payload content. See ``pwngraph.core.PwnGraph._run_nexus_loop`` for
how a scan drives this: probe (Fuzzer + ``_run_one``, both unchanged) ->
observe (this module, fed the Oracle's own verdict) -> decide -> probe again.

Deterministic decision logic always runs and always produces a usable
candidate; a :class:`~pwngraph.nexus.reasoner.NexusReasoner` is only
consulted (default: :class:`~pwngraph.nexus.reasoner.DeterministicReasoner`,
itself LLM-free) when the active level's config says to, and only to
re-rank candidates this module already generated — see
``pwngraph/nexus/levels.py`` for what each level actually changes.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from pwngraph.nexus.capability_map import AgentCapabilityMap
from pwngraph.nexus.decision import NexusAction, NexusDecision, PlanItem
from pwngraph.nexus.levels import level_config
from pwngraph.nexus.reasoner import DeterministicReasoner, NexusReasoner
from pwngraph.nexus.state import AttackState, NexusStatus, Observation
from pwngraph.types import NodeType

if TYPE_CHECKING:
    from pwngraph.connector.base import ToolSpec
    from pwngraph.oracle import RunRecord, RunVerdict
    from pwngraph.recon import TargetProfile

log = logging.getLogger(__name__)


class Nexus:
    """Adaptive attack-intelligence layer sitting between Oracle and Builder.

    Follows an explicit ENUMERATE -> PLAN -> (PROBE -> OBSERVE -> EVALUATE ->
    REASON -> ADAPT -> GENERATE) loop:

    * ENUMERATE / PLAN happen once, in ``__init__`` — ``self.capability_map``
      wraps the target's tool surface (see ``pwngraph.nexus.capability_map``)
      and ``self.plan`` is the resulting prioritized queue (see
      ``_build_plan``). Probing (Fuzzer + ``_run_one``, both unchanged) and
      evaluation (the shared ``BehavioralOracle``) happen entirely outside
      this class — see ``pwngraph.core.PwnGraph._run_nexus_loop``.
    * REASON / ADAPT happen in ``observe()`` (folds one completed probe into
      ``self.state`` and ``self.capability_map``, forming a hypothesis about
      what was just learned) and ``decide_next()`` (answers "what's the most
      useful next thing to test?" — draining ``self.plan`` first, then the
      reactive escalate/validate/chain logic, which can extend the plan with
      new items as evidence accrues).
    * GENERATE is the caller's job: it hands the returned ``NexusDecision``
      to the (unchanged) ``Fuzzer``, which is the only thing that ever
      produces payload content.
    """

    def __init__(
        self,
        attack_classes: list[str],
        tools: list[ToolSpec],
        budget: int,
        level: int = 1,
        reasoner: NexusReasoner | None = None,
        target_name: str = "unknown",
        exhaustive: bool = False,
        target_profile: TargetProfile | None = None,
    ) -> None:
        self.tools = tools
        self.cfg = level_config(level)
        self.reasoner = reasoner or DeterministicReasoner()
        # When True, disables the confidence-based early stop below — NEXUS
        # keeps cycling every class/tool (retrying failures up to the
        # level's own tolerance, harvesting successes, chaining) until the
        # budget is actually exhausted or genuinely nothing is left to try
        # (STOPPED_NO_PROGRESS), instead of quitting once breadth+confidence
        # look "good enough." Without this, a class that failed its very
        # first probe could go untouched for the rest of the scan if
        # something else satisfied the objective gate first — exactly what
        # happened when 4 classes got exactly one attempt each while a
        # confirmed one got harvested across every tool.
        self.exhaustive = exhaustive

        # Recon-derived ranking (pwngraph.recon.run_recon), when available —
        # reorder so decide_next()'s tie-breaks (_next_unexplored_class sorts
        # by attempt count, stable on ties) reach for the highest-value class
        # first instead of whatever order the caller happened to pass.
        # Falls back to the caller's own order untouched when recon found
        # nothing (or wasn't run) — same "absence changes nothing" stance as
        # every other recon integration point.
        ordered_classes = list(attack_classes)
        if target_profile is not None and target_profile.attack_plan:
            rank_of = {item.attack_class: item.rank for item in target_profile.attack_plan}
            ordered_classes.sort(key=lambda c: rank_of.get(c, len(rank_of) + 1))

        self.state = AttackState(
            attack_classes=ordered_classes,
            level=self.cfg.level,
            budget=max(0, int(budget)),
        )
        if target_profile is not None and target_profile.objective:
            self.state.objective = target_profile.objective

        # ENUMERATE: wrap the tool surface into a structured map — no new
        # calls against the target, tools is already-fetched Connector output.
        self.capability_map = AgentCapabilityMap.build(target_name, tools)
        # Fold in any chain recon already confirmed pre-attack (see
        # pwngraph.recon.run_recon's own chain-probing step) — REASON then
        # only has to *add* evidence from here on, not start from zero.
        if target_profile is not None:
            for chain in target_profile.chains:
                if chain.kind == "confirmed_chain":
                    self.capability_map.record_confirmed_relationship(
                        chain.source_tool, chain.target_tool, chain.evidence
                    )
        # PLAN: the guaranteed joint coverage sweep, built once from what's
        # knowable before any probing (see _build_plan). Later
        # evidence-driven items (leftover-axis pairing, chain pursuit) get
        # appended to this same list as they're decided, so it stays a real,
        # inspectable record of NEXUS's plan rather than a one-shot list.
        self.plan: list[PlanItem] = self._build_plan()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def should_stop(self) -> bool:
        if self.state.status is not NexusStatus.RUNNING:
            return True
        if self.state.iteration >= self.state.budget:
            self.state.status = NexusStatus.STOPPED_BUDGET
            return True
        return False

    def decide_next(self) -> NexusDecision:
        """Pick the next strategy from everything observed so far."""
        if self.should_stop():
            return NexusDecision(
                action=NexusAction.STOP,
                rationale=f"stopped: {self.state.status.value}",
            )

        # A confidence-based stop requires both the full attack-class breadth
        # AND every discovered tool to have been probed at least once — not
        # just the one technique/tool combo that happens to have scored
        # highest. Without this gate, confirming a single class against a
        # single tool at high confidence would end the scan having never even
        # tried the other classes, or worse, left a tool (e.g. an action sink
        # like send_email/http_post/run_code) completely untouched.
        # "Objective achieved" on one bug is not the same as having scanned
        # the surface. See _generate_candidates' tool-coverage floor and
        # _candidates_after_success's matching cap on re-hardening one class.
        #
        # self.exhaustive skips this gate entirely: "every class/tool has at
        # least one attempt" is not the same as "every class got a real,
        # multi-attempt shot" — a class that failed its one probe before the
        # objective gate fired never gets its own failure-tolerance cycle
        # (see _candidates_after_failure). Exhaustive mode only stops on
        # budget exhaustion or genuine STOPPED_NO_PROGRESS.
        if (
            not self.exhaustive
            and self.state.confidence >= self.cfg.stop_confidence
            and self.state.successful_techniques
            and self.state.breadth_complete()
            and not self._never_touched_tools()
        ):
            self.state.status = NexusStatus.STOPPED_OBJECTIVE
            return NexusDecision(
                action=NexusAction.STOP,
                rationale=(
                    f"confidence {self.state.confidence:.2f} >= "
                    f"{self.cfg.stop_confidence:.2f} objective threshold, every class and tool probed"
                ),
            )

        candidates = self._generate_candidates()
        if not candidates:
            self.state.status = NexusStatus.STOPPED_NO_PROGRESS
            return NexusDecision(action=NexusAction.STOP, rationale="no candidate strategy left")

        if self.cfg.use_reasoner and len(candidates) > 1:
            candidates = self.reasoner.rank(self.state, candidates)

        return candidates[0]

    def observe(
        self,
        record: RunRecord,
        verdict: RunVerdict,
        action: NexusAction | None = None,
        rationale: str = "",
    ) -> Observation:
        """Fold one completed probe into the attack state; return its Observation.

        ``action`` should be the ``NexusAction`` from the ``NexusDecision``
        that produced this probe (``pwngraph.core._run_nexus_loop`` passes
        ``decision.action``) — it's what lets ``AttackState`` tell a genuine
        chain pivot apart from ordinary breadth exploration. Omit it only for
        observations built outside the normal decide-then-probe flow.
        ``rationale`` should likewise be ``decision.rationale`` — the human
        -readable "why" this probe happened, kept on the Observation so it
        survives into persistence (see ``pwngraph.report_store.persist_nexus_state``).
        """
        tools_called = [e.name for e in record.events if e.node_type is NodeType.TOOL_CALL]
        # Prefer what the agent *actually* called over what the payload
        # merely declared as its intended target — a generator's tools_hint
        # is a bias, not a guarantee, and an agent's own routing logic can
        # send the input somewhere else entirely (e.g. a mock/keyword-driven
        # policy, or a real LLM ignoring the "hint"). Coverage tracking
        # (tried_signatures, discovered_capabilities, the coverage floor)
        # must reflect ground truth, not intention, or NEXUS can credit a
        # tool as "covered" that was never actually exercised — and declare
        # the objective met while real tools sit untouched. Only fall back
        # to the declared target when nothing was actually called at all
        # (e.g. the injection never triggered a tool invocation), so that
        # case still gets *some* attribution for dedup/logging.
        target_tool = (tools_called[0] if tools_called else None) or getattr(
            record.payload, "target_tool", None
        )
        new_capability = any(t not in self.state.discovered_capabilities for t in tools_called)

        obs = Observation(
            iteration=len(self.state.observations),
            payload_id=getattr(record.payload, "payload_id", "") or "",
            attack_class=record.attack_class or "unknown",
            target_tool=target_tool,
            tools_called=tools_called,
            success=verdict.success,
            severity=verdict.severity.value,
            confidence=verdict.confidence,
            signals=list(verdict.signals),
            new_capability=new_capability,
            action=action.value if action is not None else None,
            rationale=rationale,
        )
        self.state.record_observation(obs)

        # REASON, part 1: did this probe prove a real causal link between
        # two tools ("tool A's output made the agent call tool B")? This
        # reads only TraceEvent structure the Tracer already builds for
        # every Connector — generic, not agent-specific. Promotes a
        # hypothesized relationship in the capability map to confirmed,
        # which ranked_action_sinks() then uses to prioritize chain pursuit
        # (see _candidates_after_success's FOLLOW_PATH branch) — this is
        # what makes "follow a discovered tool relationship" mean something
        # concrete rather than "try any action sink."
        self.capability_map.record_confirmed_relationships_from_events(record.events)

        # REASON, part 2: what did this probe teach us, in plain terms?
        # Always formed (not gated behind a level), since "what did I learn
        # / what's the next most valuable test" is the loop's whole point at
        # every level — cfg.use_reasoner (see decide_next) only gates
        # whether a *reasoner* additionally re-ranks candidates built from
        # this state, not whether NEXUS bothers to reflect at all.
        hyp = self.reasoner.hypothesize(self.state)
        if hyp is not None and hyp.text not in (h.text for h in self.state.hypotheses):
            self.state.hypotheses.append(hyp)

        return obs

    # ------------------------------------------------------------------
    # Deterministic candidate generation
    # ------------------------------------------------------------------

    def _generate_candidates(self) -> list[NexusDecision]:
        if not self.state.attack_classes:
            return []

        # Joint coverage floor: every discovered tool AND every attack class
        # gets at least one deliberate attempt before NEXUS reacts to the
        # last result at all (escalating, validating, chaining, or switching
        # class). Pairing an uncovered class with an uncovered tool in the
        # same probe means this costs at most max(#tools, #classes) probes
        # to satisfy both axes — not #tools + #classes separately — leaving
        # most of the budget for adaptive deepening afterward. Without this,
        # a real action-sink tool (send_email/http_post/run_code — the
        # actual bug-bounty-relevant targets) could go completely untouched
        # for an entire scan, or entire attack classes could never get a
        # single attempt because budget went into harvesting/escalating
        # whichever classes happened to succeed first. Once both axes are
        # covered, this is a no-op and the normal reactive logic below takes
        # over — including deepening (class, tool) pairs this pass skipped
        # (see _candidates_after_success's own untried-tool harvest).
        if self._never_touched_tools() or self._never_touched_classes():
            return [self._coverage_probe()]

        last = self.state.observations[-1] if self.state.observations else None
        if last is None:
            first_class = self._next_unexplored_class()
            return [
                NexusDecision(
                    action=NexusAction.EXPLORE,
                    attack_class=first_class,
                    rationale=f"first probe — starting with '{first_class}'",
                )
            ]

        if last.success:
            return self._candidates_after_success(last)
        return self._candidates_after_failure(last)

    def _candidates_after_success(self, last: Observation) -> list[NexusDecision]:
        """Build every strategy currently applicable, not just the first one
        that matches — `decide_next` only consults the reasoner when there's
        more than one candidate (see its own docstring), so returning a
        single hardcoded pick here at every branch was silently making
        levels 3-5's reasoner dead code: `_generate_candidates` always
        produced exactly one candidate, so `len(candidates) > 1` was never
        true. Insertion order below still matches the old strict priority
        (harvest > chain > escalate > broaden), so `candidates[0]` is
        unchanged for levels 1-2 (`use_reasoner=False`, no reasoner
        consulted) — only levels 3-5 can now have the reasoner actually
        promote a different real alternative.
        """
        tools_hint = [last.target_tool] if last.target_tool else None
        all_tool_names = [t.name for t in self.tools]

        if last.confidence == "high":
            # Harvest this class's remaining tool surface before hardening,
            # chaining, or switching class entirely. A class that succeeded
            # against one tool is not "done" — a different tool produces a
            # structurally distinct AttackPath (GraphBuilder dedups by the
            # (node_type, name) sequence, and "name" includes the tool). This
            # is deliberately the ONLY candidate while untried tools remain —
            # not offered alongside chain/escalate alternatives — so it stays
            # a hard precondition even at levels 4-5 (a reasoner must never
            # be able to skip same-class breadth in favor of an immediate
            # cross-class pivot; that was the exact regression this guarded
            # against before the reasoner could fire at all).
            untried = self.state.untried_tools_for_class(last.attack_class, all_tool_names)
            if untried:
                next_tool = untried[0]
                return [
                    NexusDecision(
                        action=NexusAction.EXPLORE,
                        attack_class=last.attack_class,
                        tools_hint=[next_tool],
                        rationale=(
                            f"'{last.attack_class}' confirmed via "
                            f"'{last.target_tool or 'inline delivery'}' — harvesting its "
                            f"untried tool surface: trying '{next_tool}'"
                        ),
                    )
                ]

            # This class's own tool surface is fully harvested — from here,
            # chaining, hardening, and broadening are all genuinely live
            # strategies at once; collect whichever apply as real
            # alternatives instead of taking the first that matches.
            candidates: list[NexusDecision] = []

            # Chain pivoting is capped per-chain, not per-scan: once
            # current_path (a real FOLLOW_PATH-built chain — see
            # AttackState.record_observation) hits max_chain_depth, stop
            # extending *that* chain — but that's a reason to not offer this
            # candidate, not a reason to halt the whole scan; other
            # candidates below still apply.
            if self.cfg.pursue_chains and len(self.state.current_path) < self.cfg.max_chain_depth:
                chain_class = self._next_unexplored_class(exclude=last.attack_class)
                if chain_class is not None:
                    # A single, specific action-sink target — ranked by the
                    # capability map's own relationship evidence (confirmed
                    # causal links from last.target_tool first, then
                    # hypothesized ones, then anything else — see
                    # AgentCapabilityMap.ranked_action_sinks), preferring
                    # never-touched tools within each tier. This is what
                    # makes "follow a discovered tool relationship" mean a
                    # concrete, evidence-backed pivot instead of "try any
                    # action sink." A single name is what
                    # context["desired_action_tool"] (see core.py's
                    # _run_nexus_loop and pwngraph.fuzzer.delivery) can
                    # actually bias a generator's payload *content* toward;
                    # a multi-tool hint has nothing concrete to steer at.
                    ranked = self.capability_map.ranked_action_sinks(
                        from_tool=last.target_tool,
                        prefer_untouched=set(self._never_touched_tools()),
                    )
                    target_action = (ranked or [None])[0]
                    candidates.append(
                        NexusDecision(
                            action=NexusAction.FOLLOW_PATH,
                            attack_class=chain_class,
                            tools_hint=[target_action] if target_action else None,
                            rationale=(
                                f"'{last.attack_class}' tool surface exhausted; pivoting to "
                                f"'{chain_class}' to try chaining into an action tool"
                            ),
                        )
                    )

            # Harden a freshly confirmed technique with exactly one more probe
            # (this is its first success) — after that, re-escalating the same
            # class stops producing new information (principle #7/#8: avoid
            # unnecessary repetition, prefer payloads that progress the attack
            # path), so this stops being offered once hardened.
            if self.state.class_success_count(last.attack_class) < 2:
                candidates.append(
                    NexusDecision(
                        action=NexusAction.ESCALATE,
                        attack_class=last.attack_class,
                        tools_hint=tools_hint,
                        rationale=(
                            f"confirmed high-confidence hit on '{last.attack_class}' — "
                            f"hardening it once before moving on"
                        ),
                    )
                )

            # Broaden to a genuinely different class — never the one we're
            # already on (a "broadening to X" decision naming X itself is
            # the exact self-referential bug this guards against; see
            # _next_unexplored_class, which returns None rather than
            # falling back to the excluded class).
            broaden_class = self._next_unexplored_class(exclude=last.attack_class)
            if broaden_class is not None:
                candidates.append(
                    NexusDecision(
                        action=NexusAction.EXPLORE,
                        attack_class=broaden_class,
                        rationale=(
                            f"'{last.attack_class}' already confirmed and hardened — "
                            f"broadening coverage to '{broaden_class}'"
                        ),
                    )
                )

            if candidates:
                return candidates
            # Nothing else applies (no chain, already hardened twice, no
            # other class in scope) — keep hardening this one;
            # should_stop()/the confidence+breadth gate above will end the
            # loop once budget runs out or the objective threshold is met.
            return [
                NexusDecision(
                    action=NexusAction.ESCALATE,
                    attack_class=last.attack_class,
                    tools_hint=tools_hint,
                    rationale=f"'{last.attack_class}' is the only class in scope — continuing to harden it",
                )
            ]

        # medium/low confidence success — validate before moving on, up to the
        # level's tolerance (the tail run length caps how long we'll keep
        # re-probing the same class before conceding it and moving on).
        # "Validate further" and "cut losses and broaden" are both genuinely
        # live options once there's something to broaden into — offered as
        # real alternatives rather than the first one always winning.
        candidates = []
        if self.cfg.validate_before_escalate and len(
            self.state.tail_observations(last.attack_class)
        ) < (self.cfg.max_consecutive_failures_before_switch):
            candidates.append(
                NexusDecision(
                    action=NexusAction.VALIDATE,
                    attack_class=last.attack_class,
                    tools_hint=tools_hint,
                    rationale=(
                        f"'{last.attack_class}' hit at {last.confidence} confidence — "
                        f"re-probing to confirm before moving on"
                    ),
                )
            )
        move_on_class = self._next_unexplored_class(exclude=last.attack_class)
        if move_on_class is not None:
            candidates.append(
                NexusDecision(
                    action=NexusAction.EXPLORE,
                    attack_class=move_on_class,
                    rationale=f"'{last.attack_class}' validated; moving on to '{move_on_class}'",
                )
            )
        if candidates:
            return candidates
        # No other class to move to and validation tolerance is exhausted (or
        # disabled) — keep probing this class against an untried tool rather
        # than fabricating a "moving on to X" that names the same class.
        untried = self.state.untried_tools_for_class(last.attack_class, all_tool_names)
        return [
            NexusDecision(
                action=NexusAction.EXPLORE,
                attack_class=last.attack_class,
                tools_hint=[untried[0]] if untried else tools_hint,
                rationale=(
                    f"'{last.attack_class}' validated and no other class in scope — "
                    + (
                        f"trying untried tool '{untried[0]}'"
                        if untried
                        else "continuing to probe it"
                    )
                ),
            )
        ]

    def _candidates_after_failure(self, last: Observation) -> list[NexusDecision]:
        fails_in_row = self.state.consecutive_failures(last.attack_class)
        # Target an untried tool on retry rather than leaving tool choice to
        # the Fuzzer's own RNG — otherwise "failed 3x" might just mean "hit
        # the same tool 3 times by chance," not "genuinely tried 3 different
        # tools," which makes the failure signal that drives TRY_ALTERNATIVE
        # below noisy. Falls back to no hint (the Fuzzer's own default
        # selection) once every tool has already been tried and failed.
        untried = self.state.untried_tools_for_class(
            last.attack_class, [t.name for t in self.tools]
        )
        alternative_class = self._next_unexplored_class(exclude=last.attack_class)
        if (
            fails_in_row >= self.cfg.max_consecutive_failures_before_switch
            and alternative_class is not None
        ):
            return [
                NexusDecision(
                    action=NexusAction.TRY_ALTERNATIVE,
                    attack_class=alternative_class,
                    rationale=(
                        f"'{last.attack_class}' failed {fails_in_row}x in a row — switching to "
                        f"'{alternative_class}'"
                    ),
                )
            ]
        # Either under tolerance, or over it but with no other class to
        # switch to (a single-class scan) — keep retrying this class against
        # an untried tool rather than fabricating a "switch" to itself or
        # giving up on the whole scan while an untried tool remains.
        return [
            NexusDecision(
                action=NexusAction.EXPLORE,
                attack_class=last.attack_class,
                tools_hint=[untried[0]] if untried else None,
                rationale=(
                    f"'{last.attack_class}' failed ({fails_in_row}/"
                    f"{self.cfg.max_consecutive_failures_before_switch} tolerance) — retrying"
                    + (f" against untried tool '{untried[0]}'" if untried else "")
                ),
            )
        ]

    def _never_touched_tools(self) -> list[str]:
        """Tools with zero attempts across *every* attack class, action sinks
        first — the coverage floor's own candidate list."""
        touched = {sig.split(":", 1)[1] for sig in self.state.tried_signatures}
        untouched = [t for t in self.tools if t.name not in touched]
        untouched.sort(key=lambda t: 0 if t.is_action_sink else 1)
        return [t.name for t in untouched]

    def _never_touched_classes(self) -> list[str]:
        """Attack classes with zero attempts against any tool, in declared order."""
        attempts = self.state.attempts_per_class()
        return [c for c in self.state.attack_classes if attempts.get(c, 0) == 0]

    def _coverage_probe(self) -> NexusDecision:
        """Pick the next probe for the joint tool/class coverage floor.

        Pairing an uncovered class with an uncovered tool in the same probe
        is what keeps this floor cheap (see _generate_candidates). When only
        one axis still has gaps, pick the best partner for it: a technique
        that already proved itself elsewhere is the best bet to transfer to
        a new tool; a never-tried class is best aimed at an action-sink tool
        first, since those are the highest-impact targets.
        """
        never_touched_tools = self._never_touched_tools()
        never_touched_classes = self._never_touched_classes()

        if never_touched_tools and never_touched_classes:
            tool_name = never_touched_tools[0]
            attack_class = never_touched_classes[0]
            reason = f"covers both untried class '{attack_class}' and untouched tool '{tool_name}' in one probe"
        elif never_touched_tools:
            tool_name = never_touched_tools[0]
            preferred = [
                c for c in self.state.successful_techniques if c in self.state.attack_classes
            ]
            attack_class = preferred[0] if preferred else self._next_unexplored_class()
            reason = f"every class has an attempt — '{tool_name}' is still untouched, trying '{attack_class}'"
        else:
            attack_class = never_touched_classes[0]
            action_sinks = [t.name for t in self.tools if t.is_action_sink]
            tool_name = (
                action_sinks[0] if action_sinks else (self.tools[0].name if self.tools else None)
            )
            reason = f"every tool has an attempt — '{attack_class}' is still untried, aiming at '{tool_name}'"

        self.plan.append(
            PlanItem(attack_class=attack_class, tool=tool_name, rationale=reason, priority=1.0)
        )
        return NexusDecision(
            action=NexusAction.EXPLORE,
            attack_class=attack_class,
            tools_hint=[tool_name] if tool_name else None,
            rationale=f"coverage sweep: {reason}",
        )

    def _build_plan(self) -> list[PlanItem]:
        """PLAN step: the guaranteed joint coverage sweep, computed once from
        the capability map before any probing. Round-robin pairs every
        attack class with a tool (action sinks first — the highest-impact
        targets), covering ``min(#classes, #tools)`` pairs deterministically
        — the part knowable before any observation exists.

        This is deliberately *not* the full coverage schedule: once tools
        and classes differ in count, which class pairs with a leftover tool
        (or vice versa) genuinely depends on which classes have already
        succeeded — evidence that doesn't exist yet at construction time.
        ``_coverage_probe`` computes that leftover-axis pairing dynamically
        and appends it to this same list as it's decided (see its own
        docstring), so ``self.plan`` ends up a complete, real record of
        every coverage-floor decision NEXUS made — an upfront plan for the
        knowable part, extended live for the part that isn't.
        """
        classes = self.state.attack_classes
        tool_names = [
            t.name for t in sorted(self.tools, key=lambda t: 0 if t.is_action_sink else 1)
        ]
        if not classes or not tool_names:
            return []
        n = min(len(classes), len(tool_names))
        return [
            PlanItem(
                attack_class=classes[i],
                tool=tool_names[i],
                rationale=f"initial coverage sweep: pair '{classes[i]}' with '{tool_names[i]}'",
                priority=1000.0 - i,
            )
            for i in range(n)
        ]

    def _next_unexplored_class(self, exclude: str | None = None) -> str | None:
        """Least-attempted attack class other than ``exclude``, or ``None``
        when no other class exists to move to.

        Deliberately does *not* fall back to re-including ``exclude`` when
        it's the only class in scope — every caller uses this to decide
        whether there's somewhere genuinely different to go next, and a
        same-class fallback here previously produced decisions that claimed
        to "switch"/"broaden"/"move on" to the class already being probed
        (visible on the Logs tab as e.g. "'X' validated; moving on to 'X'").
        Callers are expected to handle ``None`` by falling through to a
        different action, not by silently re-targeting ``exclude``.
        """
        counts = self.state.attempts_per_class()
        candidates = [c for c in self.state.attack_classes if c != exclude]
        if not candidates:
            return None
        candidates.sort(key=lambda c: counts.get(c, 0))
        return candidates[0]


__all__ = ["Nexus"]
