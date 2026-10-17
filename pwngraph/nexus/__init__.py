"""NEXUS — PwnGraph's adaptive attack-intelligence layer.

Sits between the Oracle and the Builder in every scan:

    Connector -> Fuzzer -> Tracer -> Oracle -> NEXUS -> Builder -> Reporter
                              ^                   |
                              +---- feedback ------+ (drives the next Fuzzer call)

NEXUS does not generate payloads — the Fuzzer still does that, unchanged.
NEXUS decides *what to try next*: which attack class, and optionally which
tools to bias the Fuzzer toward, based on an :class:`AttackState` built up
from every probe's :class:`~pwngraph.oracle.RunVerdict` so far. See
``pwngraph.core.PwnGraph._run_nexus_loop`` for the integration point, and
``pwngraph/nexus/nexus.py`` for the decision logic itself.
"""

from pwngraph.nexus.capability_map import AgentCapabilityMap, ToolCapability, ToolRelationship
from pwngraph.nexus.decision import NexusAction, NexusDecision, PlanItem
from pwngraph.nexus.levels import LEVELS, NexusLevelConfig, level_config
from pwngraph.nexus.nexus import Nexus
from pwngraph.nexus.reasoner import DeterministicReasoner, LLMReasoner, NexusReasoner
from pwngraph.nexus.safety import screen_payload
from pwngraph.nexus.state import AttackState, Hypothesis, NexusStatus, Observation

__all__ = [
    "Nexus",
    "NexusAction",
    "NexusDecision",
    "PlanItem",
    "AttackState",
    "Observation",
    "Hypothesis",
    "NexusStatus",
    "NexusLevelConfig",
    "LEVELS",
    "level_config",
    "NexusReasoner",
    "DeterministicReasoner",
    "LLMReasoner",
    "AgentCapabilityMap",
    "ToolCapability",
    "ToolRelationship",
    "screen_payload",
]
