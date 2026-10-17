"""The GraphBackend contract.

Every method here is expressible in both an in-process graph library and a
graph database. That constraint is deliberate — it is why the API talks about
*nodes matching attributes* and *simple paths under a hop limit* rather than
exposing a library's own graph object.

Two shapes are load-bearing for portability:

* **Parallel edges.** Two events can be connected by more than one edge (a
  ``normal_flow`` and a ``tool_manipulation`` between the same pair). The API
  therefore returns edges *as a list* from :meth:`edges_between`, rather than
  the keyed mapping a multigraph library would hand back. A graph database
  returns a relationship list natively.

* **Attribute matching.** :meth:`find_nodes` takes keyword criteria instead of
  making callers scan :meth:`nodes`. In memory that is a filtered loop; against
  a database it compiles to an indexed query. Callers that iterate everything
  themselves would force the database backend to stream the whole graph.

Node and edge attributes are plain JSON-serialisable dicts. Backends must not
require a fixed attribute set — the typed schema lives a layer above this, so
new node and edge types can land without a backend change.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from typing import Any

# Hop limit applied to path enumeration. Without a cutoff, a dense graph makes
# simple-path enumeration explode combinatorially.
DEFAULT_PATH_CUTOFF = 12


class GraphBackend(ABC):
    """Storage and query interface for the attack graph."""

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    @abstractmethod
    def add_node(self, node_id: str, **attrs: Any) -> None:
        """Insert or update a node. Re-adding an existing id merges attributes."""

    @abstractmethod
    def add_edge(self, source_id: str, target_id: str, **attrs: Any) -> None:
        """Add a directed edge. Parallel edges between the same pair are kept."""

    @abstractmethod
    def clear(self) -> None:
        """Drop all nodes and edges."""

    @abstractmethod
    def delete_nodes(self, node_ids: Iterable[str]) -> int:
        """Remove the given nodes and every edge touching any of them.

        Returns how many of *node_ids* actually existed and were removed —
        an id that was never present is not an error, just not counted. The
        one deletion primitive the ABC exposes; ``pwngraph.queries.delete_scan``
        builds "delete everything tagged with this scan_id" on top of it via
        :meth:`find_nodes`, rather than this method knowing what a "scan" is.
        """

    # ------------------------------------------------------------------
    # Node reads
    # ------------------------------------------------------------------

    @abstractmethod
    def has_node(self, node_id: str) -> bool:
        """Is this node present?"""

    @abstractmethod
    def node_attrs(self, node_id: str) -> dict[str, Any]:
        """Attributes for a node, or an empty dict when it is absent.

        Never raises for a missing node — callers routinely probe synthetic ids.
        """

    @abstractmethod
    def nodes(self) -> Iterator[tuple[str, dict[str, Any]]]:
        """Every ``(node_id, attrs)`` pair. Used for whole-graph rendering."""

    @abstractmethod
    def find_nodes(self, **match: Any) -> list[str]:
        """Ids of nodes whose attributes equal every supplied criterion.

        ``find_nodes(node_type="user_input", is_adversarial=True)`` returns
        adversarial user-input nodes. No criteria returns every node id.
        """

    # ------------------------------------------------------------------
    # Edge reads
    # ------------------------------------------------------------------

    @abstractmethod
    def edges(self) -> Iterator[tuple[str, str, dict[str, Any]]]:
        """Every ``(source_id, target_id, attrs)`` triple."""

    @abstractmethod
    def edges_between(self, source_id: str, target_id: str) -> list[dict[str, Any]]:
        """Attributes of every edge from source to target, or ``[]`` if none."""

    # ------------------------------------------------------------------
    # Path queries
    # ------------------------------------------------------------------

    @abstractmethod
    def has_path(self, source_id: str, target_id: str) -> bool:
        """Is the target reachable from the source by any directed route?"""

    @abstractmethod
    def simple_paths(
        self,
        source_id: str,
        target_id: str,
        cutoff: int = DEFAULT_PATH_CUTOFF,
    ) -> Iterator[list[str]]:
        """Every acyclic route from source to target, at most ``cutoff`` hops.

        Yields node-id lists starting at ``source_id`` and ending at
        ``target_id``. Order is not guaranteed; callers that need determinism
        must sort the result themselves.
        """

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def node_count(self) -> int:
        """Number of nodes currently stored."""

    @property
    @abstractmethod
    def edge_count(self) -> int:
        """Number of edges currently stored, counting parallel edges separately."""

    def __contains__(self, node_id: object) -> bool:
        return isinstance(node_id, str) and self.has_node(node_id)

    def __repr__(self) -> str:  # pragma: no cover — debug affordance
        return f"<{type(self).__name__} " f"nodes={self.node_count} edges={self.edge_count}>"
