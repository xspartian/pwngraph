"""Core type definitions for PwnGraph.

These types are the contract between modules:

    Tracer       produces TraceEvent
    Fuzzer       produces Payload, consumes TraceEvent
    GraphBuilder consumes TraceEvent, produces AttackPath
    Reporter     consumes AttackPath, Finding

Edge and node taxonomies follow the plan:
    Node colors: UserInput(red) → ToolCall(blue) → ToolResult(yellow) →
                 DangerousOutcome(black)
    Edges: DirectInjection | ContextPoisoning | ToolManipulation | DataExfil
"""

from __future__ import annotations

import hashlib
import time
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Node / edge taxonomy
# ---------------------------------------------------------------------------

class NodeType(str, Enum):
    """Node types in the attack graph.

    Colors are the v1 palette used by the pyvis renderer.
    """

    USER_INPUT = "user_input"           # red    — entry point
    TOOL_CALL = "tool_call"             # blue   — agent invoked a tool
    TOOL_RESULT = "tool_result"         # yellow — tool returned data
    AGENT_THOUGHT = "agent_thought"     # gray   — internal reasoning step
    FINAL_ANSWER = "final_answer"       # green  — agent's final response
    DANGEROUS_OUTCOME = "dangerous"     # black  — sink node, attack succeeded

    @property
    def color(self) -> str:
        return _NODE_COLORS[self]

    @property
    def shape(self) -> str:
        return _NODE_SHAPES[self]


_NODE_COLORS = {
    NodeType.USER_INPUT: "#E74C3C",
    NodeType.TOOL_CALL: "#3498DB",
    NodeType.TOOL_RESULT: "#F1C40F",
    NodeType.AGENT_THOUGHT: "#95A5A6",
    NodeType.FINAL_ANSWER: "#2ECC71",
    NodeType.DANGEROUS_OUTCOME: "#1B1B1B",
}

_NODE_SHAPES = {
    NodeType.USER_INPUT: "dot",
    NodeType.TOOL_CALL: "box",
    NodeType.TOOL_RESULT: "ellipse",
    NodeType.AGENT_THOUGHT: "diamond",
    NodeType.FINAL_ANSWER: "dot",
    NodeType.DANGEROUS_OUTCOME: "star",
}


class EdgeType(str, Enum):
    """How information / influence flowed between two nodes."""

    NORMAL_FLOW = "normal_flow"             # ordinary, non-adversarial transition
    DIRECT_INJECTION = "direct_injection"   # attacker text in the user message
    CONTEXT_POISONING = "context_poisoning" # poisoned doc/tool result steered behavior
    TOOL_MANIPULATION = "tool_manipulation" # agent invoked tool with attacker-chosen args
    DATA_EXFIL = "data_exfil"               # sensitive data left the trust boundary

    @property
    def color(self) -> str:
        return _EDGE_COLORS[self]

    @property
    def is_adversarial(self) -> bool:
        return self is not EdgeType.NORMAL_FLOW


_EDGE_COLORS = {
    EdgeType.NORMAL_FLOW: "#BDC3C7",
    EdgeType.DIRECT_INJECTION: "#E74C3C",
    EdgeType.CONTEXT_POISONING: "#9B59B6",
    EdgeType.TOOL_MANIPULATION: "#E67E22",
    EdgeType.DATA_EXFIL: "#C0392B",
}


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """CVSS-aligned severity bucket. Numeric mapping at .score."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> float:
        return {
            Severity.INFO: 0.0,
            Severity.LOW: 3.0,
            Severity.MEDIUM: 5.5,
            Severity.HIGH: 7.5,
            Severity.CRITICAL: 9.5,
        }[self]

    @classmethod
    def from_cvss(cls, cvss: float) -> Severity:
        if cvss <= 0.0:
            return cls.INFO
        if cvss < 4.0:
            return cls.LOW
        if cvss < 7.0:
            return cls.MEDIUM
        if cvss < 9.0:
            return cls.HIGH
        return cls.CRITICAL


# ---------------------------------------------------------------------------
# Trace event — what the Tracer emits
# ---------------------------------------------------------------------------

class TraceEvent(BaseModel):
    """A single observed step inside the agent's execution.

    The Tracer emits one of these per LangChain callback (on_chain_start,
    on_tool_start, on_tool_end, on_llm_end, on_agent_finish). The GraphBuilder
    converts a stream of TraceEvents into nodes and edges.
    """

    event_id: str = Field(default_factory=lambda: _short_id())
    run_id: str
    timestamp: float = Field(default_factory=time.time)

    node_type: NodeType
    name: str                           # tool name, "user", "llm", etc.
    content: str                        # input/output/text payload
    metadata: dict[str, Any] = Field(default_factory=dict)

    # Causality — which earlier event this event was caused by.
    # The GraphBuilder uses this to draw edges.
    parent_event_id: str | None = None

    # Marked True by the Fuzzer when this event introduced a payload, or by
    # the GraphBuilder when this event was observed downstream of a payload.
    is_adversarial: bool = False
    payload_id: str | None = None

    def short(self) -> str:
        snippet = self.content[:60].replace("\n", " ")
        return f"[{self.node_type.value}] {self.name}: {snippet!r}"


# ---------------------------------------------------------------------------
# Attack path — what the GraphBuilder discovers
# ---------------------------------------------------------------------------

class AttackPath(BaseModel):
    """An ordered chain of trace events from an entry point to a sink.

    A path is "dangerous" if it ends at a DangerousOutcome node, was reached
    via at least one adversarial edge, and the GraphBuilder's heuristics
    confirmed observable impact (e.g. sensitive token in final answer,
    tool called with attacker-chosen args, exfiltration sink reached).
    """

    path_id: str = Field(default_factory=lambda: _short_id())
    events: list[TraceEvent]
    edge_types: list[EdgeType]
    severity: Severity = Severity.MEDIUM
    description: str = ""
    # "high"  — injected content reached a tool-call argument (the agent acted on it).
    # "low"   — canary only reflected in the final answer (may be a benign echo;
    #           verify manually before reporting).
    confidence: str = "high"

    @property
    def length(self) -> int:
        return len(self.events)

    @property
    def hop_count(self) -> int:
        return max(0, len(self.events) - 1)

    @property
    def is_adversarial(self) -> bool:
        return any(e.is_adversarial for e in self.events)

    def signature(self) -> str:
        """Stable hash over (node_type, name) tuples — used for dedup."""
        sig = "|".join(f"{e.node_type.value}:{e.name}" for e in self.events)
        return hashlib.sha256(sig.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Finding — what the Reporter writes up
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """A confirmed exploitable attack chain, ready for a bug bounty writeup."""

    finding_id: str = Field(default_factory=lambda: _short_id())
    title: str
    severity: Severity
    cvss_vector: str | None = None
    cvss_score: float | None = None

    target_system: str                  # e.g. "ChatGPT plugins", "Gemini Ext"
    attack_class: str                   # e.g. "indirect_injection"
    owasp: list[str] = Field(default_factory=list)  # e.g. ["LLM01", "LLM06"]
    payload_id: str

    summary: str
    steps_to_reproduce: list[str]
    impact: str
    remediation: str
    cwe: str | None = None
    references: list[str] = Field(default_factory=list)

    paths: list[AttackPath] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)

    discovered_at: float = Field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _short_id() -> str:
    """8-char random id. Not cryptographic — used for log/UI keys only."""
    import secrets
    return secrets.token_hex(4)
