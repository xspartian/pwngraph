"""Portable analysis queries over a persisted graph — the Phase 2 query library.

Every function here reads *only* through the :class:`~pwngraph.backend.GraphBackend`
ABC — ``nodes()``, ``find_nodes()``, ``node_attrs()``, ``edges_between()`` —
never Cypher directly. That is a deliberate constraint, not an oversight: it
keeps this module testable against any conformant backend, including a
lightweight test double, without depending on a live database, and it means a
second backend would need zero changes here. Prefer adding to this module over
hand-written Cypher whenever a question is expressible through the portable
interface — reach for raw Cypher only for a pattern the ABC genuinely can't
express, e.g. exploring a graph interactively in Neo4j Browser.

Two families of query live here:

* **Evidence queries** (``evidence_coverage``, ``possible_only_tools``, ...)
  read the *structural* graph — one node per statically-discovered tool,
  carrying an ``evidence`` state (see ``pwngraph.static.schema``). Populated
  by ``pwngraph.static.persist.persist_structural_graph``, which
  ``PwnGraph.run_static_analysis()`` calls automatically.
* **Finding queries** (``dangerous_outcomes``, ``exfil_findings``, ...) read
  the *runtime* trace graph ``GraphBuilder`` writes during a scan — the
  ``DangerousOutcome`` sink nodes a confirmed attack path terminates at, and
  the edge that reached them (see ``pwngraph.graph.builder``).

Every query accepts an optional ``scan_id`` to scope the read to one scan,
since the backend is a persistent, shared database, not a fresh per-process
graph — see ``GraphBuilder``'s "Scan scoping" note. Passing ``None`` (the
default) reads across every scan the backend currently holds.

``QUERY_REGISTRY`` exposes a curated subset as named, table-shaped queries for
``pwngraph query <name>`` and ``pwngraph.queries.run(name, ...)`` — the
richer typed functions above remain the better choice for library callers who
want Python values (``dict``, ``float``) rather than row lists. One query
(``blast-radius``) also takes a ``tool`` name, drawn from
``pwngraph.attackpath`` — the registry's job is uniform CLI/JSON access, not
reimplementing analysis that already lives elsewhere behind the same ABC.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pwngraph.backend import GraphBackend
from pwngraph.static.schema import KIND_TOOL
from pwngraph.types import NodeType, Severity

_EVIDENCE_ORDER = ("possible", "observed", "validated", "exploited")

# ---------------------------------------------------------------------------
# Evidence queries — the static/runtime reconciled surface
# ---------------------------------------------------------------------------


def _structural_nodes(backend: GraphBackend, scan_id: str | None) -> list[tuple[str, dict]]:
    match: dict[str, Any] = {"kind": KIND_TOOL}
    if scan_id is not None:
        match["scan_id"] = scan_id
    return [(nid, backend.node_attrs(nid)) for nid in backend.find_nodes(**match)]


def evidence_coverage(backend: GraphBackend, *, scan_id: str | None = None) -> dict[str, int]:
    """Count of structural nodes per evidence state.

    The proven-vs-theoretical report: how much of the discovered surface is
    still just ``possible`` versus how much a scan actually confirmed.
    """
    counts: dict[str, int] = {}
    for _, attrs in _structural_nodes(backend, scan_id):
        state = attrs.get("evidence")
        if state:
            counts[state] = counts.get(state, 0) + 1
    return counts


def possible_only_tools(backend: GraphBackend, *, scan_id: str | None = None) -> list[str]:
    """Tool names that exist in code but a scan never touched.

    The question a runtime-only graph cannot answer: this is the part of the
    attack surface more iterations, a better delivery prompt, or a different
    attack class might still reach.
    """
    return sorted(
        attrs["name"]
        for _, attrs in _structural_nodes(backend, scan_id)
        if attrs.get("evidence") == "possible"
    )


def exploited_tools(backend: GraphBackend, *, scan_id: str | None = None) -> list[str]:
    """Tool names that were part of a confirmed, reportable finding."""
    return sorted(
        attrs["name"]
        for _, attrs in _structural_nodes(backend, scan_id)
        if attrs.get("evidence") == "exploited"
    )


def tools_by_evidence(
    backend: GraphBackend, state: str, *, scan_id: str | None = None
) -> list[str]:
    """Tool names at exactly the given evidence state (``possible``/``observed``/
    ``validated``/``exploited``)."""
    return sorted(
        attrs["name"]
        for _, attrs in _structural_nodes(backend, scan_id)
        if attrs.get("evidence") == state
    )


def coverage_ratio(backend: GraphBackend, *, scan_id: str | None = None) -> float:
    """Fraction of discovered tools confirmed at runtime (observed or above).

    0.0 means the static surface and the runtime scan never overlapped at
    all; 1.0 means every tool the source defines was actually exercised.
    Returns 0.0 on an empty graph rather than dividing by zero.
    """
    counts = evidence_coverage(backend, scan_id=scan_id)
    total = sum(counts.get(s, 0) for s in _EVIDENCE_ORDER)
    if total == 0:
        return 0.0
    confirmed = sum(counts.get(s, 0) for s in ("observed", "validated", "exploited"))
    return round(confirmed / total, 3)


# ---------------------------------------------------------------------------
# Finding queries — the runtime trace graph's DangerousOutcome sinks
# ---------------------------------------------------------------------------


def _dangerous_outcome_rows(backend: GraphBackend, scan_id: str | None) -> list[dict[str, Any]]:
    match: dict[str, Any] = {"node_type": NodeType.DANGEROUS_OUTCOME.value}
    if scan_id is not None:
        match["scan_id"] = scan_id

    rows: list[dict[str, Any]] = []
    for node_id in backend.find_nodes(**match):
        attrs = backend.node_attrs(node_id)
        # GraphBuilder names every sink "sink::<event_id_that_triggered_it>" —
        # that lets us recover the single edge that reached it (source→sink)
        # without a whole-graph edge scan (see module docstring).
        edge_type = None
        if node_id.startswith("sink::"):
            source_id = node_id[len("sink::") :]
            edges = backend.edges_between(source_id, node_id)
            if edges:
                edge_type = edges[0].get("edge_type")
        rows.append(
            {
                "node_id": node_id,
                "name": attrs.get("name", ""),
                "severity": attrs.get("outcome_severity", ""),
                "confidence": attrs.get("confidence", ""),
                "edge_type": edge_type or "",
                "run_id": attrs.get("run_id", ""),
                "payload_id": attrs.get("payload_id", ""),
                "description": attrs.get("description", ""),
            }
        )
    return rows


def _severity_rank(row: dict[str, Any]) -> float:
    try:
        return Severity(row["severity"]).score
    except ValueError:
        return -1.0


def dangerous_outcomes(
    backend: GraphBackend, *, scan_id: str | None = None
) -> list[dict[str, Any]]:
    """Every confirmed dangerous outcome, most severe first.

    Each row is one sink a real attack path terminated at — the same data
    ``find_dangerous_paths()`` reports, but read back from storage rather
    than recomputed, so it works against a scan from a previous process too.
    """
    rows = _dangerous_outcome_rows(backend, scan_id)
    return sorted(rows, key=lambda r: (-_severity_rank(r), r["node_id"]))


def exfil_findings(backend: GraphBackend, *, scan_id: str | None = None) -> list[dict[str, Any]]:
    """Dangerous outcomes reached via a DATA_EXFIL edge — sensitive data that
    left the trust boundary, not just an internal manipulation. OWASP LLM02."""
    return [
        r for r in dangerous_outcomes(backend, scan_id=scan_id) if r["edge_type"] == "data_exfil"
    ]


def high_confidence_findings(
    backend: GraphBackend, *, scan_id: str | None = None
) -> list[dict[str, Any]]:
    """Dangerous outcomes the oracle is confident about — excludes the
    "canary echoed in the final answer, verify manually" low-confidence class."""
    return [r for r in dangerous_outcomes(backend, scan_id=scan_id) if r["confidence"] == "high"]


def severity_breakdown(backend: GraphBackend, *, scan_id: str | None = None) -> dict[str, int]:
    """Count of dangerous outcomes per severity bucket."""
    counts: dict[str, int] = {}
    for row in _dangerous_outcome_rows(backend, scan_id):
        sev = row["severity"] or "unknown"
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def adversarial_edge_breakdown(
    backend: GraphBackend, *, scan_id: str | None = None
) -> dict[str, int]:
    """Count of dangerous outcomes per triggering edge type (data_exfil,
    tool_manipulation, context_poisoning) — the attack-class mix of a scan's
    confirmed findings. Only the edge that reached a sink is counted, not
    every adversarial edge in the trace; see module docstring."""
    counts: dict[str, int] = {}
    for row in _dangerous_outcome_rows(backend, scan_id):
        et = row["edge_type"] or "unknown"
        counts[et] = counts.get(et, 0) + 1
    return counts


def scan_log(backend: GraphBackend, scan_id: str) -> list[dict[str, Any]]:
    """Every trace event tagged with *scan_id* — the raw execution log
    ``GraphBuilder`` wrote during the scan — as flat rows in chronological
    order (``run_id``, then ``timestamp`` within a run). Callers group these
    by ``run_id`` to render one block per probe — see
    ``pwngraph.api.routers.scans``'s ``/logs`` route, what ``pwngraph
    serve``'s Logs tab reads.

    Unlike most of this module's queries, this one requires a real
    ``scan_id`` rather than defaulting to "every scan" — a flat event log
    across the whole shared database is never what a caller actually wants.
    Reads five ``find_nodes(node_type=..., scan_id=...)`` calls (one per
    real trace ``NodeType``, ``DANGEROUS_OUTCOME`` sink nodes included)
    rather than one broad scan_id-only scan, matching this module's existing
    exact-match idiom (see ``_dangerous_outcome_rows``).
    """
    rows: list[dict[str, Any]] = []
    for node_type in NodeType:
        for node_id in backend.find_nodes(node_type=node_type.value, scan_id=scan_id):
            attrs = backend.node_attrs(node_id)
            rows.append(
                {
                    "node_id": node_id,
                    "run_id": attrs.get("run_id", ""),
                    "node_type": attrs.get("node_type", node_type.value),
                    "name": attrs.get("name", ""),
                    "content": attrs.get("content", ""),
                    "is_adversarial": bool(attrs.get("is_adversarial", False)),
                    "payload_id": attrs.get("payload_id"),
                    "attack_class": attrs.get("attack_class"),
                    "timestamp": attrs.get("timestamp", 0.0) or 0.0,
                }
            )
    # run_id is a random short id (see types._short_id), not sequential —
    # sorting by (run_id, timestamp) directly would keep each run's own
    # events in order but scramble the *cross-run* order runs actually
    # happened in. Sort by each run's own earliest timestamp first, so runs
    # come back in the order they were actually probed.
    run_start: dict[str, float] = {}
    for row in rows:
        rid = row["run_id"]
        run_start[rid] = min(run_start.get(rid, row["timestamp"]), row["timestamp"])
    rows.sort(key=lambda r: (run_start.get(r["run_id"], 0.0), r["run_id"], r["timestamp"]))
    return rows


# ---------------------------------------------------------------------------
# Scan discovery
# ---------------------------------------------------------------------------


def list_scans(backend: GraphBackend) -> list[dict[str, Any]]:
    """One row per scan_id currently in the backend, most recent first.

    Every other query in this module needs a ``scan_id`` to scope to — this
    is how you find one without already knowing it, e.g. before running
    ``pwngraph query dangerous-outcomes --scan-id <id>``.

    The one query here that reads the *whole* graph rather than a scoped
    slice: discovering what scan_ids exist can't itself be scoped to a
    scan_id you don't have yet (see ``GraphBackend.nodes()``, "used for
    whole-graph rendering"). Reserve it for browsing, not a hot path.
    """
    scans: dict[str, dict[str, Any]] = {}
    for _, attrs in backend.nodes():
        sid = attrs.get("scan_id")
        if not sid:
            continue
        row = scans.setdefault(
            sid,
            {
                "scan_id": sid,
                "target_id": None,
                "scanned_at": None,
                "nodes": 0,
                "dangerous_outcomes": 0,
            },
        )
        row["nodes"] += 1
        if attrs.get("target_id") and not row["target_id"]:
            row["target_id"] = attrs["target_id"]
        if attrs.get("scanned_at") and not row["scanned_at"]:
            row["scanned_at"] = attrs["scanned_at"]
        if attrs.get("node_type") == NodeType.DANGEROUS_OUTCOME.value:
            row["dangerous_outcomes"] += 1
    return sorted(scans.values(), key=lambda r: r["scanned_at"] or "", reverse=True)


def delete_scan(backend: GraphBackend, scan_id: str) -> int:
    """Permanently delete every node tagged with *scan_id* — the runtime
    trace graph, its static surface nodes, and its persisted report (see
    ``pwngraph.report_store`` — the report node carries ``scan_id`` too, so
    one sweep gets all three). Returns how many nodes were removed.

    This is the retention lever the database otherwise lacks entirely:
    nothing else in this codebase ever removes a scan once written. See
    ``pwngraph delete-scan`` (``pwngraph.cli.main``) for the operator-facing
    side of this — there is no undo.
    """
    ids = backend.find_nodes(scan_id=scan_id)
    return backend.delete_nodes(ids)


# ---------------------------------------------------------------------------
# Named query registry — `pwngraph query <name>`
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QueryDef:
    name: str
    description: str
    owasp: tuple[str, ...]
    fn: Callable[[GraphBackend, str | None, str | None], list[dict[str, Any]]]
    # Whether this query needs --tool <name> to mean anything (currently only
    # blast-radius). Surfaced so the CLI can give a clear error up front
    # instead of a confusing empty result.
    requires_tool: bool = False


def _rows_from_dict(d: dict[str, int], key: str) -> list[dict[str, Any]]:
    return [{key: k, "count": v} for k, v in sorted(d.items(), key=lambda kv: -kv[1])]


def _q_evidence_coverage(
    backend: GraphBackend, scan_id: str | None, tool: str | None
) -> list[dict[str, Any]]:
    counts = evidence_coverage(backend, scan_id=scan_id)
    return [{"evidence": s, "count": counts[s]} for s in _EVIDENCE_ORDER if s in counts]


def _q_possible_only(
    backend: GraphBackend, scan_id: str | None, tool: str | None
) -> list[dict[str, Any]]:
    return [{"tool": name} for name in possible_only_tools(backend, scan_id=scan_id)]


def _q_exploited_tools(
    backend: GraphBackend, scan_id: str | None, tool: str | None
) -> list[dict[str, Any]]:
    return [{"tool": name} for name in exploited_tools(backend, scan_id=scan_id)]


def _q_coverage_ratio(
    backend: GraphBackend, scan_id: str | None, tool: str | None
) -> list[dict[str, Any]]:
    return [{"coverage_ratio": coverage_ratio(backend, scan_id=scan_id)}]


def _q_dangerous_outcomes(
    backend: GraphBackend, scan_id: str | None, tool: str | None
) -> list[dict[str, Any]]:
    return dangerous_outcomes(backend, scan_id=scan_id)


def _q_exfil_findings(
    backend: GraphBackend, scan_id: str | None, tool: str | None
) -> list[dict[str, Any]]:
    return exfil_findings(backend, scan_id=scan_id)


def _q_high_confidence(
    backend: GraphBackend, scan_id: str | None, tool: str | None
) -> list[dict[str, Any]]:
    return high_confidence_findings(backend, scan_id=scan_id)


def _q_severity_breakdown(
    backend: GraphBackend, scan_id: str | None, tool: str | None
) -> list[dict[str, Any]]:
    return _rows_from_dict(severity_breakdown(backend, scan_id=scan_id), "severity")


def _q_edge_breakdown(
    backend: GraphBackend, scan_id: str | None, tool: str | None
) -> list[dict[str, Any]]:
    return _rows_from_dict(adversarial_edge_breakdown(backend, scan_id=scan_id), "edge_type")


def _q_scans(backend: GraphBackend, scan_id: str | None, tool: str | None) -> list[dict[str, Any]]:
    # Discovery query — always lists every scan; scan_id scoping wouldn't
    # make sense here, so any --scan-id passed is silently ignored.
    return list_scans(backend)


def _q_blast_radius(
    backend: GraphBackend, scan_id: str | None, tool: str | None
) -> list[dict[str, Any]]:
    from pwngraph.attackpath import blast_radius

    if not tool:
        raise ValueError("blast-radius requires --tool <name>")
    return [{"tool": name} for name in blast_radius(backend, tool, scan_id=scan_id)]


QUERY_REGISTRY: dict[str, QueryDef] = {
    q.name: q
    for q in (
        QueryDef(
            "scans",
            "Every scan_id in the database, most recent first — start here.",
            (),
            _q_scans,
        ),
        QueryDef(
            "evidence-coverage",
            "Structural surface by evidence state (possible/observed/validated/exploited).",
            (),
            _q_evidence_coverage,
        ),
        QueryDef(
            "possible-only-tools",
            "Tools discovered in source but never exercised by a scan.",
            (),
            _q_possible_only,
        ),
        QueryDef(
            "exploited-tools",
            "Tools that were part of a confirmed, reportable finding.",
            (),
            _q_exploited_tools,
        ),
        QueryDef(
            "coverage-ratio",
            "Fraction of the discovered tool surface confirmed at runtime.",
            (),
            _q_coverage_ratio,
        ),
        QueryDef(
            "dangerous-outcomes",
            "Every confirmed dangerous outcome, most severe first.",
            ("LLM06",),
            _q_dangerous_outcomes,
        ),
        QueryDef(
            "exfil-findings",
            "Dangerous outcomes where data left the trust boundary (DATA_EXFIL).",
            ("LLM02",),
            _q_exfil_findings,
        ),
        QueryDef(
            "high-confidence-findings",
            "Dangerous outcomes excluding the low-confidence 'verify manually' class.",
            ("LLM06",),
            _q_high_confidence,
        ),
        QueryDef(
            "severity-breakdown",
            "Count of dangerous outcomes per severity bucket.",
            (),
            _q_severity_breakdown,
        ),
        QueryDef(
            "edge-breakdown",
            "Count of dangerous outcomes per triggering edge type.",
            (),
            _q_edge_breakdown,
        ),
        QueryDef(
            "blast-radius",
            "Tools reachable downstream of a call to --tool <name> — 'if this "
            "tool were fully compromised, what else did the agent touch?'",
            (),
            _q_blast_radius,
            requires_tool=True,
        ),
    )
}


def run(
    name: str,
    backend: GraphBackend,
    *,
    scan_id: str | None = None,
    tool: str | None = None,
) -> list[dict[str, Any]]:
    """Run a registered named query by name. Raises ``KeyError`` for an
    unknown name — callers building a CLI should catch this and list
    ``QUERY_REGISTRY`` instead of letting a traceback surface. Raises
    ``ValueError`` if a query with ``requires_tool=True`` (currently only
    ``blast-radius``) is run without ``tool``."""
    return QUERY_REGISTRY[name].fn(backend, scan_id, tool)
