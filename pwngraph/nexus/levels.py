"""NEXUS levels — knobs on adaptive *autonomy/depth*, not payload count.

A higher level does not mean "more payloads": ``--budget`` alone controls how
many probes NEXUS gets. The level controls how much reasoning it applies to
each one — whether it pursues multi-step chains, how many times it retries a
shaky hit before moving on, how deep a chain it will follow before stopping,
and whether a :class:`~pwngraph.nexus.reasoner.NexusReasoner` gets consulted
at all. See ``pwngraph/nexus/nexus.py`` for how each field is used.

    Level 1  Basic probe/observe. No chain pursuit, no reasoner, low failure
             tolerance — closest to "one adaptive step at a time".
    Level 2  Adds validation: a shaky hit gets re-probed before NEXUS moves on.
    Level 3  A reasoner (deterministic by default) is consulted when ranking
             candidate strategies; slightly higher failure tolerance.
    Level 4  Chain pursuit turned on — a confirmed hit can pivot NEXUS toward
             a second attack class targeting a different tool.
    Level 5  Deepest chain pursuit and highest failure tolerance — NEXUS keeps
             exploring longer before concluding a path is exhausted.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class NexusLevelConfig:
    level: int
    # Confirmed hits can pivot toward a second attack class/tool (multi-hop
    # chain discovery) rather than just hardening the same one.
    pursue_chains: bool
    # Consult a NexusReasoner (see pwngraph.nexus.reasoner) when ranking
    # candidate decisions, instead of always taking the deterministic top pick.
    use_reasoner: bool
    # Re-probe a low/medium-confidence success before moving on, instead of
    # treating one echo as good enough.
    validate_before_escalate: bool
    # How many probes in a row on one attack class can fail before NEXUS
    # switches to an alternative.
    max_consecutive_failures_before_switch: int
    # Longest attack-class chain NEXUS will keep extending before stopping.
    max_chain_depth: int
    # AttackState.confidence at/above which NEXUS considers the objective met.
    stop_confidence: float


LEVELS: dict[int, NexusLevelConfig] = {
    1: NexusLevelConfig(
        level=1,
        pursue_chains=False,
        use_reasoner=False,
        validate_before_escalate=False,
        max_consecutive_failures_before_switch=2,
        max_chain_depth=1,
        stop_confidence=0.80,
    ),
    2: NexusLevelConfig(
        level=2,
        pursue_chains=False,
        use_reasoner=False,
        validate_before_escalate=True,
        max_consecutive_failures_before_switch=3,
        max_chain_depth=1,
        stop_confidence=0.80,
    ),
    3: NexusLevelConfig(
        level=3,
        pursue_chains=False,
        use_reasoner=True,
        validate_before_escalate=True,
        max_consecutive_failures_before_switch=3,
        max_chain_depth=2,
        stop_confidence=0.85,
    ),
    4: NexusLevelConfig(
        level=4,
        pursue_chains=True,
        use_reasoner=True,
        validate_before_escalate=True,
        max_consecutive_failures_before_switch=4,
        max_chain_depth=3,
        stop_confidence=0.85,
    ),
    5: NexusLevelConfig(
        level=5,
        pursue_chains=True,
        use_reasoner=True,
        validate_before_escalate=True,
        max_consecutive_failures_before_switch=5,
        max_chain_depth=4,
        stop_confidence=0.90,
    ),
}


def level_config(level: int) -> NexusLevelConfig:
    """Clamp an arbitrary requested level into [1, 5] and return its config."""
    return LEVELS[max(1, min(5, int(level)))]
