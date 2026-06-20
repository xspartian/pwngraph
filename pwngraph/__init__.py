"""PwnGraph — dynamic attack graph discovery for AI agent pipelines.

Public API:

    from pwngraph import PwnGraph
    from pwngraph.types import (
        NodeType, EdgeType, Severity,
        TraceEvent, AttackPath, Finding,
    )
"""

from pwngraph.core import PwnGraph
from pwngraph.types import (
    AttackPath,
    EdgeType,
    Finding,
    NodeType,
    Severity,
    TraceEvent,
)

__version__ = "0.1.0"

__all__ = [
    "PwnGraph",
    "NodeType",
    "EdgeType",
    "Severity",
    "TraceEvent",
    "AttackPath",
    "Finding",
    "__version__",
]
