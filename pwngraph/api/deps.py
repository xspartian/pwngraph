"""FastAPI dependencies shared across routers."""

from __future__ import annotations

from fastapi import Request

from pwngraph.backend import GraphBackend


def get_backend(request: Request) -> GraphBackend:
    """The :class:`GraphBackend` this app was created with (see
    ``create_app``).

    Constructed once at startup and stored on ``app.state`` — the Neo4j
    driver is connection-pooled internally, so there's no benefit to
    reopening it per request, only cost.
    """
    return request.app.state.backend
