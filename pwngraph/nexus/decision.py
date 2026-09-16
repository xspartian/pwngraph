"""NexusAction / NexusDecision — what NEXUS hands back to the scan loop.

A decision never carries payload content. It says which attack class to try
next and, optionally, which tools the Fuzzer should prefer when generating
that payload (``tools_hint`` — tool *names*; the caller resolves them back
to ``ToolSpec`` objects against the agent's real tool list). Payload
generation itself stays entirely the Fuzzer's job.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class NexusAction(str, Enum):
    """What kind of move NEXUS wants to make next."""

    EXPLORE = "explore"  # try a class/tool not yet (fully) probed
    VALIDATE = "validate"  # re-probe a low/medium-confidence hit to confirm it
    ESCALATE = "escalate"  # push harder on a confirmed high-confidence hit
    FOLLOW_PATH = "follow_path"  # pivot toward chaining a hit into a second hop
    TRY_ALTERNATIVE = "try_alternative"  # this class is exhausted, switch
    STOP = "stop"  # no further probe is worth the budget


class NexusDecision(BaseModel):
    """One strategy recommendation for the next probe."""

    action: NexusAction
    # None only when action is STOP.
    attack_class: str | None = None
    tools_hint: list[str] | None = None
    rationale: str = ""

    @property
    def is_stop(self) -> bool:
        return self.action is NexusAction.STOP


class PlanItem(BaseModel):
    """One entry in NEXUS's upfront PLAN — the prioritized queue built once
    from the AgentCapabilityMap at ENUMERATE time (see
    ``pwngraph.nexus.nexus.Nexus._build_plan``), before any probing starts.
    Consumed highest-priority-first by ``decide_next()`` until drained, at
    which point the reactive escalate/validate/chain logic takes over."""

    attack_class: str
    tool: str | None = None
    rationale: str = ""
    priority: float = 0.0
