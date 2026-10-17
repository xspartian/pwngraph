"""The evidence ladder and the structural node it applies to.

Node *kind* is deliberately an open string rather than a closed enum — unlike
``pwngraph.types.NodeType`` (which is the fixed, already-load-bearing taxonomy
for the runtime trace graph), the structural layer exists specifically to grow
new kinds (``memory``, ``secret``, ``mcp_server``, ``human_approval``, ...) as
new connectors land, without ever requiring a change to this module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pwngraph.static.identity import StructuralKey

# Known kinds. Not exhaustive by design — any string is a valid kind, this is
# just the vocabulary Phase 1 actually populates.
KIND_TOOL = "tool"
KIND_AGENT = "agent"


class EvidenceState(str, Enum):
    """How strongly a structural element's existence and impact are known.

    Ranks are ordinal, not just labels — :func:`promote` and every reconciler
    compare states by ``.rank``, never by enum identity, so a state can only
    move up the ladder, never silently regress.
    """

    POSSIBLE = "possible"  # found in source; the edge exists in code
    OBSERVED = "observed"  # the agent actually traversed it at runtime
    VALIDATED = "validated"  # the behavioral oracle confirmed influence there
    EXPLOITED = "exploited"  # part of a confirmed, reportable finding

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK: dict[EvidenceState, int] = {
    EvidenceState.POSSIBLE: 0,
    EvidenceState.OBSERVED: 1,
    EvidenceState.VALIDATED: 2,
    EvidenceState.EXPLOITED: 3,
}


def promote(current: EvidenceState, candidate: EvidenceState) -> EvidenceState:
    """The higher-ranked of two states. Evidence only ever strengthens."""
    return candidate if candidate.rank > current.rank else current


@dataclass
class StructuralNode:
    """One node in the structural graph, with its evidence state.

    ``source`` records how this node is currently known — ``"static"`` (found
    in source, never confirmed at runtime), ``"runtime"`` (observed live but
    absent from the static pass — e.g. a dynamically bound tool the AST walk
    could not see), or ``"static+runtime"`` once both agree.
    """

    key: StructuralKey
    kind: str
    name: str
    description: str = ""
    evidence: EvidenceState = EvidenceState.POSSIBLE
    source: str = "static"
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def node_id(self) -> str:
        return self.key.digest()
