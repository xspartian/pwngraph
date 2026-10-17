"""``GET /api/health`` — confirms the backend (Neo4j) is actually reachable,
the same guarantee ``pwngraph doctor`` gives from the CLI side."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from pwngraph.api.deps import get_backend
from pwngraph.api.schemas import HealthStatus
from pwngraph.backend import GraphBackend

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health", response_model=HealthStatus)
def health(backend: GraphBackend = Depends(get_backend)) -> dict[str, object]:
    try:
        count = backend.node_count
    except Exception as exc:  # noqa: BLE001 — surface as a health-check failure, not a 500
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "nodes": count}
