"""AttackState — what NEXUS knows so far.

This is the memory the adaptive loop reasons over: every payload already
attempted, every tool the agent has been observed calling, which attack
classes have paid off, which have been exhausted, and how confident NEXUS is
that it has found what it's looking for. ``Nexus.observe()`` (see
``pwngraph.nexus.nexus``) is the only code that mutates this after
construction — it turns one completed probe (a ``RunRecord`` + the Oracle's
``RunVerdict`` for it) into an ``Observation`` and folds it in here via
:meth:`AttackState.record_observation`.

Plain ``list[str]`` is used instead of ``set[str]`` throughout, matching the
rest of the codebase's pydantic-JSON-friendly style (``pwngraph.types``,
``pwngraph.oracle`` never use bare sets) — this state is small enough per
scan that membership checks over a list cost nothing real.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class NexusStatus(str, Enum):
    """Why the adaptive loop is (or isn't) still running."""

    RUNNING = "running"
    STOPPED_OBJECTIVE = "stopped_objective"  # confidence threshold reached
    STOPPED_BUDGET = "stopped_budget"  # interaction budget exhausted
    STOPPED_NO_PROGRESS = "stopped_no_progress"  # no candidate strategy left to try
    STOPPED_DEPTH_LIMIT = "stopped_depth_limit"  # attack-chain depth cap reached


class Observation(BaseModel):
    """One probe's worth of evidence — built from a completed run + its verdict."""

    iteration: int
    payload_id: str
    attack_class: str
    target_tool: str | None = None
    tools_called: list[str] = Field(default_factory=list)
    success: bool = False
    severity: str = "info"
    confidence: str = "low"
    signals: list[str] = Field(default_factory=list)
    # A tool called here that had never been observed called before this probe.
    new_capability: bool = False
    # The NexusAction (see decision.py) whose decide_next() call produced the
    # payload this observation is scoring. None for observations recorded
    # without going through the normal decide_next() -> Fuzzer -> _run_one
    # flow. Used to tell a genuine chain pivot (follow_path) apart from
    # ordinary breadth exploration that also happens to land on a different
    # class — see AttackState.record_observation.
    action: str | None = None
    # The NexusDecision.rationale that led to this probe — the human-readable
    # "why" (e.g. "coverage sweep: covers both untried class X and tool Y").
    # Kept on the Observation itself (not just the transient NexusDecision)
    # so it survives into persistence — see pwngraph.report_store's
    # persist_nexus_state, which is what the "Logs" tab reads to show NEXUS's
    # own reasoning next to each probe.
    rationale: str = ""


class Hypothesis(BaseModel):
    """A working theory about the target agent, formed from observations."""

    text: str
    confidence: float = 0.0
    attack_class: str
    supporting_iterations: list[int] = Field(default_factory=list)


# Confidence bump applied to AttackState.confidence per successful observation,
# keyed by the Oracle's own confidence label. A single high-confidence hit
# should move the needle a lot more than a low-confidence echo.
_CONFIDENCE_DELTA = {"high": 0.3, "medium": 0.15, "low": 0.05}


class AttackState(BaseModel):
    """Everything NEXUS has learned about the target agent so far, in one scan."""

    objective: str = "discover exploitable multi-hop attack chains"
    attack_classes: list[str] = Field(default_factory=list)
    level: int = 1
    budget: int = 0

    iteration: int = 0
    payload_history: list[str] = Field(default_factory=list)
    # Dedup key per attempt: f"{attack_class}:{target_tool or '-'}".
    tried_signatures: list[str] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    tool_history: list[str] = Field(default_factory=list)
    successful_techniques: list[str] = Field(default_factory=list)
    failed_techniques: list[str] = Field(default_factory=list)
    discovered_capabilities: list[str] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    # Sequence of attack classes that make up the leading discovered chain.
    current_path: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    status: NexusStatus = NexusStatus.RUNNING
    focus_attack_class: str | None = None
    focus_tool: str | None = None

    def record_observation(self, obs: Observation) -> None:
        """Fold one completed probe's observation into the running state.

        Purely bookkeeping — deciding what to do *next* is NEXUS's job
        (``Nexus.decide_next``), not this model's. This only updates facts.
        """
        self.observations.append(obs)
        self.iteration += 1
        self.payload_history.append(obs.payload_id)

        for tool in obs.tools_called:
            self.tool_history.append(tool)
            if tool not in self.discovered_capabilities:
                self.discovered_capabilities.append(tool)

        # Credit every tool actually called this probe, not just the primary
        # target — a two-hop agent (e.g. read_file's poisoned output makes
        # the agent obey an instruction that calls send_email in the same
        # run) genuinely exercises both, and coverage bookkeeping that only
        # credited the first meant NEXUS kept "discovering" a tool it had
        # already proven, wasting probes re-targeting it via harvest.
        credited = False
        for tool in obs.tools_called:
            sig = f"{obs.attack_class}:{tool}"
            if sig not in self.tried_signatures:
                self.tried_signatures.append(sig)
            credited = True
        if not credited:
            # No real tool call happened at all — fall back to the payload's
            # merely-declared target so this attempt still gets *some*
            # dedup/coverage attribution.
            sig = f"{obs.attack_class}:{obs.target_tool or '-'}"
            if sig not in self.tried_signatures:
                self.tried_signatures.append(sig)

        if obs.success:
            if obs.attack_class not in self.successful_techniques:
                self.successful_techniques.append(obs.attack_class)
            if obs.attack_class in self.failed_techniques:
                self.failed_techniques.remove(obs.attack_class)
            self.confidence = min(1.0, self.confidence + _CONFIDENCE_DELTA.get(obs.confidence, 0.05))
            # current_path is the discovered *chain* — it only grows on a
            # deliberate chain pivot (NexusAction.FOLLOW_PATH), never on
            # ordinary breadth exploration that happens to land on a
            # different class (harvesting a class's tool surface, switching
            # after a failure streak, or plain round-robin EXPLORE). Those
            # are "tried more classes," not "found a longer chain" — keeping
            # them separate is what stops max_chain_depth (a per-chain cap)
            # from prematurely capping the whole scan's breadth.
            if obs.action == "follow_path" and (
                not self.current_path or self.current_path[-1] != obs.attack_class
            ):
                self.current_path.append(obs.attack_class)
            self.focus_attack_class = obs.attack_class
            self.focus_tool = obs.target_tool
        elif (
            obs.attack_class not in self.successful_techniques
            and obs.attack_class not in self.failed_techniques
        ):
            self.failed_techniques.append(obs.attack_class)

    def tail_observations(self, attack_class: str) -> list[Observation]:
        """Trailing run of observations for ``attack_class`` — the most recent
        consecutive attempts at it, oldest first. Empty once a different class
        was tried more recently."""
        run: list[Observation] = []
        for obs in reversed(self.observations):
            if obs.attack_class != attack_class:
                break
            run.append(obs)
        run.reverse()
        return run

    def consecutive_failures(self, attack_class: str) -> int:
        """How many probes at the tail of ``attack_class``'s run failed in a row."""
        count = 0
        for obs in reversed(self.tail_observations(attack_class)):
            if obs.success:
                break
            count += 1
        return count

    def attempts_per_class(self) -> dict[str, int]:
        counts = {c: 0 for c in self.attack_classes}
        for obs in self.observations:
            if obs.attack_class in counts:
                counts[obs.attack_class] += 1
        return counts

    def class_success_count(self, attack_class: str) -> int:
        """How many probes at *any* point (not just the tail) succeeded for
        this class — used to cap how many times NEXUS re-hardens an already
        confirmed technique before moving on to unexplored ground."""
        return sum(1 for o in self.observations if o.attack_class == attack_class and o.success)

    def untried_tools_for_class(self, attack_class: str, tool_names: list[str]) -> list[str]:
        """Which of ``tool_names`` have never been attempted for this class.

        Reads ``tried_signatures`` (``f"{attack_class}:{tool}"``) — every
        probe already records its (class, tool) pair there via
        ``record_observation``, so this needs no extra bookkeeping. Order is
        preserved from ``tool_names`` so callers can pass a priority order
        (e.g. action sinks first) and get it back.
        """
        tried = {sig.split(":", 1)[1] for sig in self.tried_signatures if sig.startswith(f"{attack_class}:")}
        return [name for name in tool_names if name not in tried]

    def breadth_complete(self) -> bool:
        """Has every attack class in scope been probed at least once?

        Used to gate a confidence-based objective stop: confirming one
        technique with high confidence is not the same as having scanned the
        agent's full attack surface, so a pure-confidence stop shouldn't fire
        while classes remain completely untouched and budget remains.
        """
        attempts = self.attempts_per_class()
        return bool(attempts) and all(count > 0 for count in attempts.values())
