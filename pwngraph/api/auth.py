"""Optional bearer-token gate for ``pwngraph serve``.

The API is read-only, but read-only still means it reads back everything a
scan captured — target source, tool arguments, agent responses, and
(post-``pwngraph.redact``) anything that redaction didn't anticipate.
``pwngraph serve`` has no auth by default, which is a reasonable default
bound to ``127.0.0.1``. The moment it's reachable from anywhere else, an API
token is the only thing standing between "my scan data" and "anyone on the
network's scan data". Set ``PWNGRAPH_API_TOKEN`` or pass ``--token`` to
``pwngraph serve`` to require one — see ``pwngraph.cli.main.serve``.
"""

from __future__ import annotations

import hmac

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

# Health checks (load balancers, uptime probes) stay open — it reveals only
# reachability + a node count, and gating it would break the one endpoint
# infra tooling expects to hit without credentials.
_EXEMPT_PATHS = {"/api/health"}

# Opening the viewer once as ``/?token=...`` stores the token in this cookie,
# so the frontend's own same-origin fetches authenticate without a login UI.
COOKIE_NAME = "pwngraph_token"


class TokenAuthMiddleware(BaseHTTPMiddleware):
    """Requires a matching bearer token on every ``/api/*`` request.

    Accepts the token as ``Authorization: Bearer <token>`` (for scripts/CI),
    a ``?token=`` query parameter, or the ``pwngraph_token`` cookie. Loading
    any page with a valid ``?token=`` sets that cookie, which is how the
    browser viewer authenticates its API calls.
    """

    def __init__(self, app, token: str) -> None:
        super().__init__(app)
        self._token = token

    async def dispatch(self, request: Request, call_next):
        if not request.url.path.startswith("/api/"):
            response = await call_next(request)
            supplied = request.query_params.get("token")
            if supplied and hmac.compare_digest(supplied, self._token):
                response.set_cookie(COOKIE_NAME, supplied, httponly=True, samesite="strict")
            return response
        if request.url.path in _EXEMPT_PATHS:
            return await call_next(request)
        supplied = _extract_token(request)
        if supplied is None or not hmac.compare_digest(supplied, self._token):
            return JSONResponse(
                status_code=401, content={"detail": "Missing or invalid API token."}
            )
        return await call_next(request)


def _extract_token(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.query_params.get("token") or request.cookies.get(COOKIE_NAME)
