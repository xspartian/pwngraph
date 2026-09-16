"""FastAPI app factory for ``pwngraph serve`` — the live graph/findings
viewer.

Almost entirely read-only: nearly every route under ``/api`` reads through
the ``GraphBackend`` ABC (Neo4j in practice), the same database ``pwngraph
scan`` wrote to. No job-trigger or scan-management endpoints exist here by
design — scans still run via the CLI; this app never launches one. The one
exception is ``POST /{scan_id}/findings/{finding_id}/triage``
(``pwngraph.api.routers.scans``), which patches a finding's triage status in
its persisted report — findings otherwise have no lifecycle past the single
scan that found them. See ``pwngraph.report_store.set_finding_triage``.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from pwngraph.backend import GraphBackend, make_backend

# The Vite dev server's own origin — `npm run dev` (frontend/) proxies /api
# to this app's port, but the browser still sees requests as coming from
# 5173, so CORS needs to allow it explicitly for local development.
_DEV_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]


def create_app(
    backend: GraphBackend, *, static_dir: Path | None = None, api_token: str | None = None
) -> FastAPI:
    """Build the FastAPI app around *backend*.

    *backend* is constructed once by the caller (the ``pwngraph serve`` CLI
    command) and stored on ``app.state`` — the Neo4j driver is
    connection-pooled, so one instance is reused across every request
    instead of reopening per call. See ``pwngraph.api.deps.get_backend``.

    *static_dir*, when given and non-empty, is mounted at ``/`` as the built
    React frontend (``frontend/`` — ``npm run build`` output copied into
    ``pwngraph/api/static/``, see ``frontend/README.md``). Omit it to run
    API-only, e.g. while developing the frontend against its own dev server.

    *api_token*, when given, requires every ``/api/*`` request (except
    ``/api/health``) to carry it — see ``pwngraph.api.auth``. Omit it to
    leave the API open, the existing default for a loopback-only server.
    """
    app = FastAPI(
        title="PwnGraph",
        description="Read-only viewer over a PwnGraph scan's Neo4j attack graph.",
        version="1.0.0",
    )
    app.state.backend = backend

    if api_token:
        from pwngraph.api.auth import TokenAuthMiddleware

        app.add_middleware(TokenAuthMiddleware, token=api_token)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_DEV_ORIGINS,
        # POST is here solely for the triage endpoint — see module docstring.
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    from pwngraph.api.routers import health, scans

    app.include_router(health.router)
    app.include_router(scans.router)

    if static_dir is not None and static_dir.is_dir() and any(static_dir.iterdir()):
        _mount_frontend(app, static_dir)

    return app


def _mount_frontend(app: FastAPI, static_dir: Path) -> None:
    """Serve the built SPA, including on a deep link or a hard refresh.

    A plain ``StaticFiles(html=True)`` mount is not enough: it resolves
    ``/`` to ``index.html`` but 404s every client-side route
    (``/scans/<id>/overview``), so the app worked only as long as you never
    reloaded and never pasted a link. React Router owns those paths, so any
    request that isn't an API call or a real file on disk has to fall back to
    ``index.html`` and let the router take it from there.

    Requests that look like files (they have an extension) still 404 when the
    file is missing — the standard SPA rule. Without it a mistyped asset URL
    would quietly return HTML with a 200, which is far harder to debug than a
    404.
    """
    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles

    index_file = static_dir / "index.html"
    resolved_root = static_dir.resolve()

    assets_dir = static_dir / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa_fallback(full_path: str) -> FileResponse:
        # /api is owned by the routers registered above; anything unmatched
        # under it is a genuine 404, not a page to render.
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not found")

        if full_path:
            candidate = (static_dir / full_path).resolve()
            # Containment check — full_path is attacker-supplied in the sense
            # that anything can be typed into a URL bar, and `..` segments
            # must not escape the served directory.
            if candidate.is_file() and resolved_root in candidate.parents:
                return FileResponse(candidate)
            if Path(full_path).suffix:
                raise HTTPException(status_code=404, detail="Not found")

        return FileResponse(index_file)


def create_app_from_env() -> FastAPI:
    """App-factory entry point for uvicorn's ``--reload`` mode.

    uvicorn's autoreloader re-imports the app in a fresh subprocess on every
    change, so it needs a zero-argument, import-string-addressable factory
    rather than an already-built ``FastAPI`` instance. Reads the same
    ``PWNGRAPH_NEO4J_*`` environment variables ``make_backend`` already
    falls back to (see ``pwngraph.backend``), plus ``PWNGRAPH_API_TOKEN`` —
    ``pwngraph serve --reload`` sets all of these from its own resolved
    flags before invoking uvicorn with this as the factory target, so both
    code paths agree on which server (and which token) to use.
    """
    import os

    backend = make_backend("neo4j")
    static_dir = Path(__file__).resolve().parent / "static"
    return create_app(
        backend,
        static_dir=static_dir if static_dir.is_dir() else None,
        api_token=os.environ.get("PWNGRAPH_API_TOKEN") or None,
    )
