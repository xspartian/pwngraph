"""Attack-path analysis: ranking, reachability, and cross-scan diffing.

Everything here builds on structures the engine already produces —
``AttackPath.signature()``, ``Finding.evidence``, and the
:class:`~pwngraph.backend.GraphBackend` ABC — so none of it needed new
infrastructure to become real. That is a deliberate sequencing choice: this
module is "cheap" precisely because Phases 0–2 already did the expensive part
(the abstraction and the evidence ladder).

Two capabilities are named "blast radius" in the roadmap and they are *not*
the same thing:

* A **static** blast radius ("if this tool is compromised, what could it
  reach, whether or not a scan proved it") needs typed structural edges
  (``CAN_CALL``, ``CAN_EXECUTE``, ...) between tools — those don't exist yet;
  Phase 1 only reconciled *nodes*. Building that honestly is future work.
* The **runtime** blast radius this module provides answers a narrower but
  still real question: from an event a scan actually observed, what did the
  agent's own execution reach afterward? That's answerable today, from the
  graph the engine already builds, with zero new schema.

Don't conflate the two — :func:`blast_radius` here is the runtime version.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

from pwngraph.backend import GraphBackend
from pwngraph.types import AttackPath, Finding, NodeType, Severity

# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------

_CONFIDENCE_WEIGHT: dict[str, float] = {"high": 1.0, "medium": 0.6, "low": 0.3}


def path_rank(path: AttackPath) -> float:
    """Severity weighted by confidence — how seriously to take this path.

    A CRITICAL path at "low" confidence (canary buried in a long final
    answer — possibly a benign echo) should not outrank a HIGH path the
    oracle is confident about. Confidence discounts severity rather than
    gating it outright, so a low-confidence critical still surfaces above a
    high-confidence low.
    """
    weight = _CONFIDENCE_WEIGHT.get(path.confidence, 0.3)
    return path.severity.score * weight


def finding_rank(finding: Finding) -> float:
    """Severity weighted by observed Attack Success Rate.

    Uses the ASR the oracle already attached to ``evidence`` when trials > 1;
    a finding with no ASR entry (a single-trial scan) is treated as fully
    confirmed (1.0) rather than penalized for not having repeated the payload.
    """
    asr = finding.evidence.get("attack_success_rate")
    weight = float(asr) if asr is not None else 1.0
    return finding.severity.score * weight


def rank_paths(paths: list[AttackPath]) -> list[AttackPath]:
    """*paths* sorted by :func:`path_rank`, highest first."""
    return sorted(paths, key=path_rank, reverse=True)


def rank_findings(findings: list[Finding]) -> list[Finding]:
    """*findings* sorted by :func:`finding_rank`, highest first."""
    return sorted(findings, key=finding_rank, reverse=True)


# ---------------------------------------------------------------------------
# Runtime reachability / blast radius
# ---------------------------------------------------------------------------


def _bfs(adjacency: dict[str, list[str]], origin: str) -> set[str]:
    seen: set[str] = set()
    queue: deque[str] = deque([origin])
    while queue:
        current = queue.popleft()
        for nxt in adjacency.get(current, []):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return seen


def reachable_from(backend: GraphBackend, node_id: str) -> set[str]:
    """Every node id reachable from *node_id* by any directed route.

    Plain BFS over ``backend.edges()`` — works identically against any
    GraphBackend, in-memory or persistent, with no backend-specific code.
    """
    if not backend.has_node(node_id):
        return set()

    adjacency: dict[str, list[str]] = {}
    for src, dst, _attrs in backend.edges():
        adjacency.setdefault(src, []).append(dst)
    return _bfs(adjacency, node_id)


def blast_radius(backend: GraphBackend, tool_name: str, *, scan_id: str | None = None) -> list[str]:
    """Distinct tool names reachable downstream of any call to *tool_name*.

    "If an attacker fully controlled this tool's output, what else did the
    agent go on to touch during the scan?" Answered from events the scan
    actually observed — see the module docstring for why this is the runtime
    variant, not the (not yet built) static one.

    ``scan_id`` scopes which call sites of *tool_name* count as origins.
    Pass it whenever the backend is a persistent, shared database (the normal
    case — see ``GraphBuilder``'s "Scan scoping" note): without it, a tool
    name that happens to recur across unrelated scans of different targets
    would have its blast radius silently computed from *all* of them at
    once, understating or overstating the real figure for any one scan.
    """
    match: dict[str, Any] = {"node_type": NodeType.TOOL_CALL.value, "name": tool_name}
    if scan_id is not None:
        match["scan_id"] = scan_id
    origins = backend.find_nodes(**match)
    if not origins:
        return []

    # Built once and reused across every origin — cheaper than reachable_from's
    # own per-call edges() scan when a tool has multiple call sites.
    adjacency: dict[str, list[str]] = {}
    for src, dst, _attrs in backend.edges():
        adjacency.setdefault(src, []).append(dst)

    reached_tools: set[str] = set()
    for origin in origins:
        for node_id in _bfs(adjacency, origin):
            attrs = backend.node_attrs(node_id)
            if attrs.get("node_type") == NodeType.TOOL_CALL.value and attrs.get("name"):
                reached_tools.add(attrs["name"])

    reached_tools.discard(tool_name)  # the tool itself isn't part of its own radius
    return sorted(reached_tools)


def chain_for_payload(backend: GraphBackend, scan_id: str, payload_id: str) -> list[str]:
    """Every node id in the dangerous-outcome chain(s) behind one payload.

    A persisted :class:`~pwngraph.types.Finding` drops its ``AttackPath``
    tree entirely (see ``report_store``'s ``_FINDING_EXCLUDE`` — the trace
    graph already represents it, better, than a JSON blob would), so "take
    me to this finding's chain" has nothing to walk from once the scanning
    process has exited. ``payload_id`` survives persistence on both sides —
    the ``Finding`` itself and every ``DangerousOutcome`` sink node
    ``GraphBuilder`` wrote (see ``graph/builder.py``) — so it's the join key
    back into the graph instead of the dropped path.

    ``trials`` > 1 can produce more than one sink sharing the same
    ``payload_id`` (each successful re-delivery gets its own
    ``DangerousOutcome`` node); every one of them is walked and unioned,
    since each is a real occurrence of the same finding, not a duplicate to
    arbitrarily pick one of.
    """
    sinks = backend.find_nodes(
        scan_id=scan_id, node_type=NodeType.DANGEROUS_OUTCOME.value, payload_id=payload_id
    )
    if not sinks:
        return []

    runtime_ids = set(backend.find_nodes(scan_id=scan_id))
    rev_adjacency: dict[str, list[str]] = {}
    for src, dst, _attrs in backend.edges():
        if src in runtime_ids and dst in runtime_ids:
            rev_adjacency.setdefault(dst, []).append(src)

    nodes: set[str] = set()
    for sink in sinks:
        nodes.add(sink)
        nodes |= _bfs(rev_adjacency, sink)
    return sorted(nodes)


# ---------------------------------------------------------------------------
# Cross-scan diffing
# ---------------------------------------------------------------------------


@dataclass
class PathDiff:
    """The result of comparing two scans' dangerous paths by structural signature.

    A path's signature ignores content and only looks at the (node_type,
    name) sequence — see ``AttackPath.signature()`` — so "the same attack
    chain, different canary" correctly counts as *persisting*, not new.
    """

    new: list[AttackPath] = field(default_factory=list)
    removed: list[AttackPath] = field(default_factory=list)
    persisting: list[AttackPath] = field(default_factory=list)

    @property
    def regressed(self) -> bool:
        """True if anything new appeared without anything closing — a CI gate signal."""
        return bool(self.new) and not self.removed

    @property
    def improved(self) -> bool:
        """True if paths closed and nothing new opened — the "defense worked" case."""
        return bool(self.removed) and not self.new

    def summary(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "removed": len(self.removed),
            "persisting": len(self.persisting),
        }


def diff_paths(before: list[AttackPath], after: list[AttackPath]) -> PathDiff:
    """Classify *after* against *before* by structural signature.

    ``before``/``after`` come straight from two ``PwnGraph.paths`` — a
    baseline scan and a rerun after a guardrail change, typically loaded via
    a saved baseline file so the two scans don't need to run back to back.
    """
    before_by_sig = {p.signature(): p for p in before}
    after_by_sig = {p.signature(): p for p in after}

    return PathDiff(
        new=[p for sig, p in after_by_sig.items() if sig not in before_by_sig],
        removed=[p for sig, p in before_by_sig.items() if sig not in after_by_sig],
        persisting=[p for sig, p in after_by_sig.items() if sig in before_by_sig],
    )


def newly_reachable_severities(diff: PathDiff) -> list[Severity]:
    """Severities of every newly-appeared path — what a CI gate typically checks."""
    return [p.severity for p in diff.new]
