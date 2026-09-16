"""A minimal, dependency-free GraphBackend — test infrastructure only.

Not shipped as part of the product: ``pwngraph.backend`` implements only
``Neo4jBackend`` now that NetworkX/pyvis were removed. This exists purely so
the test suite can verify the *logic* layered on top of the GraphBackend ABC —
GraphBuilder, pwngraph.queries, pwngraph.static.reconcile, pwngraph.attackpath
— without needing a live Neo4j for every single test.

This is deliberately not a product decision disguised as a test helper: it
has no third-party dependency (no networkx, nothing), lives only under
``tests/``, and is never imported by anything under ``pwngraph/``. It proves
the logic above the ABC is correct; it does not and cannot substitute for
running the real ``Neo4jBackend`` against a live server (see
``tests/test_backend_contract.py`` for how to do that).
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Iterator
from typing import Any

from pwngraph.backend.base import DEFAULT_PATH_CUTOFF, GraphBackend


class FakeGraphBackend(GraphBackend):
    """Pure-Python, in-memory implementation of the GraphBackend contract."""

    def __init__(self) -> None:
        self._nodes: dict[str, dict[str, Any]] = {}
        self._edges: list[tuple[str, str, dict[str, Any]]] = []

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def add_node(self, node_id: str, **attrs: Any) -> None:
        self._nodes.setdefault(node_id, {}).update(attrs)

    def add_edge(self, source_id: str, target_id: str, **attrs: Any) -> None:
        # Auto-create missing endpoints, matching MultiDiGraph.add_edge.
        self._nodes.setdefault(source_id, {})
        self._nodes.setdefault(target_id, {})
        self._edges.append((source_id, target_id, dict(attrs)))

    def clear(self) -> None:
        self._nodes.clear()
        self._edges.clear()

    def delete_nodes(self, node_ids: Iterable[str]) -> int:
        ids = set(node_ids)
        found = ids & self._nodes.keys()
        for nid in found:
            del self._nodes[nid]
        self._edges = [(s, d, a) for s, d, a in self._edges if s not in ids and d not in ids]
        return len(found)

    # ------------------------------------------------------------------
    # Node reads
    # ------------------------------------------------------------------

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    def node_attrs(self, node_id: str) -> dict[str, Any]:
        return dict(self._nodes.get(node_id, {}))

    def nodes(self) -> Iterator[tuple[str, dict[str, Any]]]:
        for node_id, attrs in self._nodes.items():
            yield node_id, dict(attrs)

    def find_nodes(self, **match: Any) -> list[str]:
        if not match:
            return list(self._nodes)
        return [
            node_id
            for node_id, attrs in self._nodes.items()
            if all(attrs.get(key) == want for key, want in match.items())
        ]

    # ------------------------------------------------------------------
    # Edge reads
    # ------------------------------------------------------------------

    def edges(self) -> Iterator[tuple[str, str, dict[str, Any]]]:
        for src, dst, attrs in self._edges:
            yield src, dst, dict(attrs)

    def edges_between(self, source_id: str, target_id: str) -> list[dict[str, Any]]:
        return [
            dict(attrs) for src, dst, attrs in self._edges if src == source_id and dst == target_id
        ]

    # ------------------------------------------------------------------
    # Path queries
    # ------------------------------------------------------------------

    def has_path(self, source_id: str, target_id: str) -> bool:
        if source_id not in self._nodes or target_id not in self._nodes:
            return False
        return target_id in self._reachable(source_id)

    def simple_paths(
        self,
        source_id: str,
        target_id: str,
        cutoff: int = DEFAULT_PATH_CUTOFF,
    ) -> Iterator[list[str]]:
        if source_id not in self._nodes or target_id not in self._nodes:
            return iter(())
        return iter(self._simple_paths(source_id, target_id, cutoff))

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _adjacency(self) -> dict[str, list[str]]:
        adj: dict[str, list[str]] = {}
        for src, dst, _attrs in self._edges:
            adj.setdefault(src, []).append(dst)
        return adj

    def _reachable(self, source_id: str) -> set[str]:
        adj = self._adjacency()
        seen: set[str] = set()
        queue: deque[str] = deque([source_id])
        while queue:
            current = queue.popleft()
            for nxt in adj.get(current, []):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)
        return seen

    def _simple_paths(self, source_id: str, target_id: str, cutoff: int) -> list[list[str]]:
        adj = self._adjacency()
        results: list[list[str]] = []

        def dfs(current: str, path: list[str]) -> None:
            if len(path) - 1 >= cutoff:
                return
            for nxt in adj.get(current, []):
                if nxt in path:
                    continue  # simple path: no repeated nodes
                new_path = path + [nxt]
                if nxt == target_id:
                    results.append(new_path)
                else:
                    dfs(nxt, new_path)

        dfs(source_id, [source_id])
        return results
