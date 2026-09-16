"""Graph storage — Neo4j.

The attack engine (Fuzzer, Tracer, Oracle, GraphBuilder, Reporter) talks to a
:class:`GraphBackend` and never to a concrete graph library. NetworkX/pyvis
(the original zero-infrastructure tier) were removed once Neo4j covered the
same analysis — a scan now requires a reachable Neo4j server; there is no
in-process fallback. Bring one up with ``docker compose up -d`` (see
``docker-compose.yml`` at the repo root).

Connection defaults come from environment variables so the CLI, tests, and
direct API use all agree without repeating connection strings:

    PWNGRAPH_NEO4J_URI       (default: bolt://localhost:7687)
    PWNGRAPH_NEO4J_USER      (default: neo4j)
    PWNGRAPH_NEO4J_PASSWORD  (default: pwngraph-dev — docker-compose.yml's dev password)
"""

from __future__ import annotations

import os

from pwngraph.backend.base import GraphBackend

__all__ = ["GraphBackend", "make_backend"]

_AVAILABLE = ("neo4j",)


def make_backend(kind: str = "neo4j", **kwargs: object) -> GraphBackend:
    """Construct a backend by name.

    Connection kwargs (``uri``/``user``/``password``/``database``) fall back
    to the ``PWNGRAPH_NEO4J_*`` environment variables, then to
    ``docker-compose.yml``'s dev defaults, when not passed explicitly.
    Unknown names raise rather than silently producing a scan that wrote
    nowhere.
    """
    if kind == "neo4j":
        from pwngraph.backend.neo4j_backend import Neo4jBackend

        kwargs.setdefault("uri", os.environ.get("PWNGRAPH_NEO4J_URI", "bolt://localhost:7687"))
        kwargs.setdefault("user", os.environ.get("PWNGRAPH_NEO4J_USER", "neo4j"))
        kwargs.setdefault("password", os.environ.get("PWNGRAPH_NEO4J_PASSWORD", "pwngraph-dev"))
        return Neo4jBackend(**kwargs)
    raise ValueError(f"Unknown graph backend {kind!r}. Available: {', '.join(_AVAILABLE)}.")
