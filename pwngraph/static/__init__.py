"""Static structural analysis — the Possible rung of the evidence ladder.

The runtime engine (Fuzzer/Tracer/Oracle) only ever sees what it happened to
trigger. A tool the fuzzer never delivered a payload to has no edges in the
runtime graph at all, so any question shaped like "what could this tool
reach" is unanswerable from runtime data alone — it silently reads as zero
rather than "unknown."

This package fills that gap by parsing agent source with the AST, without
executing it, to enumerate the *complete* structural surface. ``reconcile()``
then merges that static surface with a completed scan's runtime graph, so
every tool ends up in one of four states:

    possible   → found in source, never observed at runtime
    observed   → the agent called it during the scan
    validated  → the behavioral oracle confirmed attacker influence there
    exploited  → part of a confirmed, reportable finding

See ``pwngraph/static/schema.py`` for the states themselves and
``pwngraph/static/identity.py`` for how a statically-found tool and a
runtime-observed tool are recognised as the same node.
"""

from pwngraph.static.identity import StructuralKey, normalize_target_id
from pwngraph.static.langchain_extractor import (
    ExtractedTool,
    extract_langchain_tools,
    extract_langchain_tools_from_file,
)
from pwngraph.static.persist import persist_structural_graph
from pwngraph.static.reconcile import StructuralGraph, reconcile
from pwngraph.static.schema import KIND_AGENT, KIND_TOOL, EvidenceState, StructuralNode

__all__ = [
    "StructuralKey",
    "normalize_target_id",
    "ExtractedTool",
    "extract_langchain_tools",
    "extract_langchain_tools_from_file",
    "StructuralGraph",
    "reconcile",
    "persist_structural_graph",
    "KIND_AGENT",
    "KIND_TOOL",
    "EvidenceState",
    "StructuralNode",
]
