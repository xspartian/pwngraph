"""AgentCapabilityMap — the ENUMERATE step's artifact.

NEXUS's first move against any target is to understand its surface, not to
start firing payloads. This module turns whatever ``Connector.list_tools()``
returns (already fetched by ``pwngraph.core.PwnGraph.scan()`` before a
``Nexus`` is even constructed — building this map makes zero new calls
against the target) into a structured map: per-tool parameters and category
tags, which tools are data sinks vs. action sinks, and — the genuinely new
piece — hypothesized and confirmed *relationships* between tools.

``pwngraph.attackpath``'s own module docstring names this exact gap: *"typed
structural edges (CAN_CALL, CAN_EXECUTE, ...) between tools — those don't
exist yet."* This fills it, scoped to NEXUS's own in-memory reasoning (not
the persisted Neo4j graph, which stays out of scope per attackpath.py's own
boundary).

Nothing here is specific to any lab or agent: every field is derived purely
from ``ToolSpec`` (name, description, tags, is_data_sink, is_action_sink,
tool_schema) — the same generic surface every Connector implementation
already produces.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from pwngraph.connector.base import ToolSpec

# How many hops up a TraceEvent's parent chain to walk when looking for a
# confirmed causal link between two tool calls in the same probe. Bounded so
# a pathologically deep trace can't make relationship detection expensive —
# real obey-chains (poisoned tool result -> agent acts on it) are 1-2 hops.
_RELATIONSHIP_WALK_DEPTH = 5


class ToolCapability(BaseModel):
    """One tool's shape, as understood from the capability map alone."""

    name: str
    description: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    is_data_sink: bool = False
    is_action_sink: bool = False


class ToolRelationship(BaseModel):
    """A hypothesized or confirmed causal link: source_tool's output can (or
    did) lead to target_tool being called."""

    source_tool: str
    target_tool: str
    kind: str = "possible_chain"  # "possible_chain" | "confirmed_chain"
    confidence: float = 0.3
    evidence: str = ""


class AgentCapabilityMap(BaseModel):
    """Everything NEXUS knows about the target's surface, built once at
    ENUMERATE time and refined as REASON draws real evidence from probes."""

    target_name: str = "unknown"
    tools: dict[str, ToolCapability] = Field(default_factory=dict)
    data_sinks: list[str] = Field(default_factory=list)
    action_sinks: list[str] = Field(default_factory=list)
    relationships: list[ToolRelationship] = Field(default_factory=list)

    @classmethod
    def build(cls, target_name: str, tools: list[ToolSpec]) -> AgentCapabilityMap:
        """ENUMERATE: wrap the tool list into a structured map and seed
        every (data_sink, action_sink) pair as a "possible_chain" hypothesis
        — the only a-priori signal available before any probing: a tool
        that returns data the agent will reason over, paired with a tool
        that takes real-world action, is a *plausible*, unproven 2-hop
        chain worth testing.
        """
        capabilities = {
            t.name: ToolCapability(
                name=t.name,
                description=t.description,
                parameters=dict(t.tool_schema or {}),
                tags=list(t.tags),
                is_data_sink=t.is_data_sink,
                is_action_sink=t.is_action_sink,
            )
            for t in tools
        }
        data_sinks = [t.name for t in tools if t.is_data_sink]
        action_sinks = [t.name for t in tools if t.is_action_sink]
        relationships = [
            ToolRelationship(
                source_tool=src,
                target_tool=dst,
                kind="possible_chain",
                confidence=0.3,
                evidence=(
                    f"'{src}' is a data sink and '{dst}' is an action sink — "
                    "structurally plausible 2-hop chain, not yet observed"
                ),
            )
            for src in data_sinks
            for dst in action_sinks
            if src != dst
        ]
        return cls(
            target_name=target_name,
            tools=capabilities,
            data_sinks=data_sinks,
            action_sinks=action_sinks,
            relationships=relationships,
        )

    # ------------------------------------------------------------------
    # REASON: turning real observations into evidence
    # ------------------------------------------------------------------

    def record_confirmed_relationship(self, source: str, target: str, evidence: str) -> None:
        """Promote a hypothesis to confirmed (or add a new one) once a real
        probe's trace shows ``target`` actually got called as a descendant
        of ``source``'s result in the same run — genuine causality, not a
        structural guess.
        """
        for rel in self.relationships:
            if rel.source_tool == source and rel.target_tool == target:
                rel.kind = "confirmed_chain"
                rel.confidence = max(rel.confidence, 0.9)
                rel.evidence = evidence
                return
        self.relationships.append(
            ToolRelationship(
                source_tool=source,
                target_tool=target,
                kind="confirmed_chain",
                confidence=0.9,
                evidence=evidence,
            )
        )

    def record_confirmed_relationships_from_events(self, events: list[Any]) -> list[tuple[str, str]]:
        """Walk one probe's TraceEvents for genuine tool-A-caused-tool-B
        causality and record every link found. Returns the (source, target)
        pairs newly confirmed this call, for logging/observation purposes.

        Reads only ``TraceEvent.node_type``/``.name``/``.parent_event_id`` —
        structure the Tracer already builds for every Connector, not
        anything obey-mechanism- or agent-specific.
        """
        from pwngraph.types import NodeType

        by_id = {e.event_id: e for e in events}
        found: list[tuple[str, str]] = []
        for ev in events:
            if ev.node_type is not NodeType.TOOL_CALL:
                continue
            ancestor_id = ev.parent_event_id
            hops = 0
            while ancestor_id is not None and hops < _RELATIONSHIP_WALK_DEPTH:
                ancestor = by_id.get(ancestor_id)
                if ancestor is None:
                    break
                if ancestor.node_type is NodeType.TOOL_RESULT and ancestor.name != ev.name:
                    self.record_confirmed_relationship(
                        source=ancestor.name,
                        target=ev.name,
                        evidence=(
                            f"observed: '{ev.name}' was called as a descendant of "
                            f"'{ancestor.name}''s result in the same probe"
                        ),
                    )
                    found.append((ancestor.name, ev.name))
                    break
                ancestor_id = ancestor.parent_event_id
                hops += 1
        return found

    # ------------------------------------------------------------------
    # ADAPT: what the map recommends
    # ------------------------------------------------------------------

    def ranked_action_sinks(
        self, from_tool: str | None, prefer_untouched: set[str] | None = None
    ) -> list[str]:
        """Action-sink tool names ranked for chain pursuit *from* ``from_tool``:
        confirmed links from it first, then hypothesized links from it, then
        every other action sink. Replaces a flat "every action sink,
        unranked" list with the map's own evidence.

        ``prefer_untouched`` (typically ``Nexus._never_touched_tools()``)
        breaks ties *within* each evidence tier toward tools nothing has
        reached yet — a confirmed relationship still wins over an untouched
        tool with no evidence at all, but among equally-confirmed (or
        equally-unlinked) candidates, breadth wins.
        """

        def _order(names: list[str]) -> list[str]:
            if not prefer_untouched:
                return names
            return sorted(names, key=lambda n: 0 if n in prefer_untouched else 1)

        confirmed = [
            r.target_tool
            for r in self.relationships
            if r.source_tool == from_tool and r.kind == "confirmed_chain"
        ]
        possible = [
            r.target_tool
            for r in self.relationships
            if r.source_tool == from_tool
            and r.kind == "possible_chain"
            and r.target_tool not in confirmed
        ]
        rest = [t for t in self.action_sinks if t not in confirmed and t not in possible]
        return _order(confirmed) + _order(possible) + _order(rest)


__all__ = ["ToolCapability", "ToolRelationship", "AgentCapabilityMap"]
