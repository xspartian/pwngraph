"""Neo4j-backed graph — the sole GraphBackend implementation.

Implements the :class:`~pwngraph.backend.base.GraphBackend` contract, so
``GraphBuilder``, the Reporter, and everything built on top of the ABC only
ever see the ABC's vocabulary — nothing here leaks into the rest of the
engine. The ABC itself still exists so the storage choice stays a seam, not a
hardcoded dependency, even though this is currently its only implementation.

Verified against a live server (``docker compose up -d`` + the full
``tests/test_backend_contract.py`` contract suite, plus a real end-to-end
``PwnGraph.scan()``) — no longer "written to spec, unverified."

Design notes
------------
* **Nodes** carry a single label ``PwnNode`` and a unique, indexed
  ``node_id`` property. All other attributes are stored as native properties.
* **Edges** all use one relationship type, ``EDGE``, with an ``edge_type``
  *property* distinguishing them — not the Neo4j relationship type itself.
  The alternative (a dynamic relationship type per ``EdgeType``) would need
  the type name string-formatted into the query, which is both a slight
  injection surface and unnecessary: relationship type doesn't need to be
  queryable as a label the way node kind might later.
* **``add_edge`` auto-creates missing endpoint nodes** via ``MERGE``, matching
  ``MultiDiGraph.add_edge``'s behavior — the contract suite pins this down
  for both backends identically.
* **``find_nodes``** builds a bounded, parameterized ``WHERE`` clause using
  Cypher's dynamic property lookup (``n[$key]``) — the property *names* are
  bound parameters, not string-interpolated, so arbitrary attribute keys
  never touch query text.
* **``simple_paths``** filters to genuinely simple paths (no repeated nodes)
  in pure Cypher — plain variable-length matches allow revisited nodes via
  different relationships, which ``all_simple_paths`` (and this backend's
  contract) explicitly forbid. No APOC dependency.
* The hop ``cutoff`` is the one value formatted directly into query text
  rather than bound as a parameter: Cypher requires a literal integer for a
  variable-length relationship bound in this driver line, not a parameter.
  It is cast through ``int()`` and clamped to a sane range first, so this is
  a validated integer being formatted, never untrusted string interpolation.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

from neo4j import GraphDatabase

from pwngraph.backend.base import DEFAULT_PATH_CUTOFF, GraphBackend

_MAX_CUTOFF = 50  # guards against a pathological hop bound reaching the server


class Neo4jBackend(GraphBackend):
    """Persistent graph backend over a Neo4j instance.

    Parameters
    ----------
    uri, user, password : connection details for ``neo4j.GraphDatabase.driver``.
    database : the Neo4j database name (multi-database deployments only;
        ``None`` uses the server default).
    """

    def __init__(
        self,
        uri: str = "bolt://localhost:7687",
        user: str = "neo4j",
        password: str = "password",
        database: str | None = None,
    ) -> None:
        self._driver = GraphDatabase.driver(uri, auth=(user, password))
        self._database = database
        self._ensure_constraint()

    def _ensure_constraint(self) -> None:
        # A unique constraint on node_id both enforces the identity contract
        # and gives Neo4j an index to satisfy has_node/node_attrs/add_node
        # lookups without a full label scan.
        with self._session() as session:
            session.run(
                "CREATE CONSTRAINT pwnnode_id_unique IF NOT EXISTS "
                "FOR (n:PwnNode) REQUIRE n.node_id IS UNIQUE"
            )

    def _session(self):
        return self._driver.session(database=self._database)

    def close(self) -> None:
        self._driver.close()

    def __enter__(self) -> Neo4jBackend:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def add_node(self, node_id: str, **attrs: Any) -> None:
        with self._session() as session:
            session.run(
                "MERGE (n:PwnNode {node_id: $node_id}) SET n += $attrs",
                node_id=node_id,
                attrs=attrs,
            )

    def add_edge(self, source_id: str, target_id: str, **attrs: Any) -> None:
        with self._session() as session:
            session.run(
                "MERGE (a:PwnNode {node_id: $source_id}) "
                "MERGE (b:PwnNode {node_id: $target_id}) "
                "CREATE (a)-[r:EDGE]->(b) "
                "SET r += $attrs",
                source_id=source_id,
                target_id=target_id,
                attrs=attrs,
            )

    def clear(self) -> None:
        with self._session() as session:
            session.run("MATCH (n:PwnNode) DETACH DELETE n")

    def delete_nodes(self, node_ids: Iterable[str]) -> int:
        ids = list(node_ids)
        if not ids:
            return 0
        with self._session() as session:
            # Counted before deleting rather than via a returning DELETE —
            # simpler to reason about than aggregating around DETACH DELETE
            # in one statement, and this is never a hot path.
            count_result = session.run(
                "MATCH (n:PwnNode) WHERE n.node_id IN $ids RETURN count(n) AS c", ids=ids
            )
            record = count_result.single()
            found = int(record["c"]) if record else 0
            session.run("MATCH (n:PwnNode) WHERE n.node_id IN $ids DETACH DELETE n", ids=ids)
            return found

    # ------------------------------------------------------------------
    # Node reads
    # ------------------------------------------------------------------

    def has_node(self, node_id: str) -> bool:
        with self._session() as session:
            result = session.run(
                "MATCH (n:PwnNode {node_id: $node_id}) RETURN count(n) > 0 AS found",
                node_id=node_id,
            )
            record = result.single()
            return bool(record["found"]) if record else False

    def node_attrs(self, node_id: str) -> dict[str, Any]:
        with self._session() as session:
            result = session.run(
                "MATCH (n:PwnNode {node_id: $node_id}) RETURN properties(n) AS props",
                node_id=node_id,
            )
            record = result.single()
            if record is None:
                return {}
            return _strip_id(dict(record["props"]))

    def nodes(self) -> Iterator[tuple[str, dict[str, Any]]]:
        with self._session() as session:
            result = session.run("MATCH (n:PwnNode) RETURN n.node_id AS id, properties(n) AS props")
            for record in result:
                yield record["id"], _strip_id(dict(record["props"]))

    def find_nodes(self, **match: Any) -> list[str]:
        if not match:
            with self._session() as session:
                result = session.run("MATCH (n:PwnNode) RETURN n.node_id AS id")
                return [record["id"] for record in result]

        # Dynamic property access (n[$key]) keeps attribute *names* bound as
        # parameters — never formatted into query text as identifiers.
        clauses: list[str] = []
        params: dict[str, Any] = {}
        for i, (key, value) in enumerate(match.items()):
            clauses.append(f"n[$k{i}] = $v{i}")
            params[f"k{i}"] = key
            params[f"v{i}"] = value

        query = "MATCH (n:PwnNode) WHERE " + " AND ".join(clauses) + " RETURN n.node_id AS id"
        with self._session() as session:
            result = session.run(query, **params)
            return [record["id"] for record in result]

    # ------------------------------------------------------------------
    # Edge reads
    # ------------------------------------------------------------------

    def edges(self) -> Iterator[tuple[str, str, dict[str, Any]]]:
        with self._session() as session:
            result = session.run(
                "MATCH (a:PwnNode)-[r:EDGE]->(b:PwnNode) "
                "RETURN a.node_id AS src, b.node_id AS dst, properties(r) AS props"
            )
            for record in result:
                yield record["src"], record["dst"], dict(record["props"])

    def edges_between(self, source_id: str, target_id: str) -> list[dict[str, Any]]:
        with self._session() as session:
            result = session.run(
                "MATCH (a:PwnNode {node_id: $source_id})-[r:EDGE]->(b:PwnNode {node_id: $target_id}) "
                "RETURN properties(r) AS props",
                source_id=source_id,
                target_id=target_id,
            )
            return [dict(record["props"]) for record in result]

    # ------------------------------------------------------------------
    # Path queries
    # ------------------------------------------------------------------

    def has_path(self, source_id: str, target_id: str) -> bool:
        # Bounded to the same practical depth as simple_paths' default cutoff
        # — every real caller in this codebase immediately follows a
        # has_path() check with a cutoff-bounded simple_paths() call, so an
        # edge reachable only beyond that depth was never going to be walked
        # anyway. See the module docstring for why the bound is literal text.
        cutoff = _clamp_cutoff(DEFAULT_PATH_CUTOFF)
        with self._session() as session:
            result = session.run(
                f"MATCH (a:PwnNode {{node_id: $source_id}}) "
                f"MATCH (b:PwnNode {{node_id: $target_id}}) "
                f"MATCH p = shortestPath((a)-[:EDGE*1..{cutoff}]->(b)) "
                f"RETURN p IS NOT NULL AS reachable",
                source_id=source_id,
                target_id=target_id,
            )
            record = result.single()
            return bool(record["reachable"]) if record else False

    def simple_paths(
        self,
        source_id: str,
        target_id: str,
        cutoff: int = DEFAULT_PATH_CUTOFF,
    ) -> Iterator[list[str]]:
        cutoff = _clamp_cutoff(cutoff)
        query = (
            f"MATCH p = (a:PwnNode {{node_id: $source_id}})"
            f"-[:EDGE*1..{cutoff}]->(b:PwnNode {{node_id: $target_id}}) "
            # Simple-path filter: every node in the path appears exactly
            # once. Plain variable-length matching only forbids repeating a
            # *relationship*, not a node reached via a different one.
            "WHERE all(n IN nodes(p) WHERE single(x IN nodes(p) WHERE x = n)) "
            "RETURN [n IN nodes(p) | n.node_id] AS path_ids"
        )
        with self._session() as session:
            result = session.run(query, source_id=source_id, target_id=target_id)
            for record in result:
                yield list(record["path_ids"])

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def node_count(self) -> int:
        with self._session() as session:
            result = session.run("MATCH (n:PwnNode) RETURN count(n) AS n")
            record = result.single()
            return int(record["n"]) if record else 0

    @property
    def edge_count(self) -> int:
        with self._session() as session:
            result = session.run("MATCH ()-[r:EDGE]->() RETURN count(r) AS n")
            record = result.single()
            return int(record["n"]) if record else 0


def _strip_id(props: dict[str, Any]) -> dict[str, Any]:
    props.pop("node_id", None)
    return props


def _clamp_cutoff(cutoff: int) -> int:
    return max(1, min(int(cutoff), _MAX_CUTOFF))
