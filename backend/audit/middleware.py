"""Audit middleware — seeds the per-request audit context + emits X-Request-Id.

Runs before route handlers so `write_audit` can read request_id / method /
path / ip from the audit ContextVar without each handler passing them
explicitly. Also echoes `X-Request-Id` back so clients / logs / SIEMs can
correlate a single HTTP request across audit rows.
"""
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from audit.context import set_request_context


_REQUEST_ID_HEADER = "x-request-id"

# Auth-free, token-gated download/ack endpoints carry the single-use secret in
# the URL path. Redact that segment before it is persisted into the hash-chained
# audit log (and exported verbatim into the LE bundle's Audit_Trail.csv), so a
# reader of the audit trail can't replay a still-live token.
_TOKEN_PATH_PREFIXES = (
    "/api/exports/",
    "/api/audit-exports/",
    "/api/le-package-ack/",
    "/api/collections/",
)


def _redact_path(path: str) -> str:
    for pref in _TOKEN_PATH_PREFIXES:
        if path.startswith(pref):
            rest = path[len(pref):]
            if not rest:
                return path
            _, _, tail = rest.partition("/")
            return pref + "<redacted>" + (f"/{tail}" if tail else "")
    return path


def _client_ip(request: Request) -> str | None:
    """Real client IP, behind a single trusted reverse proxy (Caddy).

    `X-Forwarded-For` may contain a comma-separated chain — the left-most
    entry is the original client. If the header is absent we fall back to
    the immediate peer (which is Caddy in production, or the dev client).
    """
    xff = request.headers.get("x-forwarded-for")
    if xff:
        first = xff.split(",", 1)[0].strip()
        if first:
            return first
    if request.client:
        return request.client.host
    return None


class AuditContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Honour any client-supplied X-Request-Id (useful for end-to-end tracing);
        # otherwise mint a fresh UUID.
        rid = request.headers.get(_REQUEST_ID_HEADER) or str(uuid.uuid4())

        set_request_context(
            request_id=rid,
            request_method=request.method,
            request_path=_redact_path(request.url.path),
            ip_address=_client_ip(request),
        )

        response = await call_next(request)
        response.headers[_REQUEST_ID_HEADER] = rid
        return response
