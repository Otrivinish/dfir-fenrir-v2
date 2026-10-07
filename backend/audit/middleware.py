"""Audit middleware — seeds the per-request audit context + emits X-Request-Id.

Runs before route handlers so `write_audit` can read request_id / method /
path / ip / user agent from the audit ContextVar without each handler passing them
explicitly. Also echoes `X-Request-Id` back so clients / logs / SIEMs can
correlate a single HTTP request across audit rows.
"""
import re
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from audit.context import set_request_context


_REQUEST_ID_HEADER = "x-request-id"
# R130: a client X-Request-Id is kept only in canonical UUID form (36 characters, any version), stored
# lower-cased. Anything else (over-long, non-UUID, CR/LF) is ignored and a fresh uuid4 is minted, so the
# value always fits audit_logs.request_id VARCHAR(36) and can never inject a response header.
_CANONICAL_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")

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
    """Real client IP, as resolved by uvicorn's proxy-headers handling.

    uvicorn rewrites `request.client` from `X-Forwarded-For` ONLY when the TCP
    peer is the trusted Caddy (FORWARDED_ALLOW_IPS, pinned in compose). Never
    parse the header here: any other container reaching the backend directly
    could forge it and poison the audit trail's source IP.
    """
    if request.client:
        return request.client.host
    return None


class AuditContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Honour a client-supplied X-Request-Id only when it is a canonical UUID (end-to-end tracing);
        # otherwise mint a fresh one (R130).
        client_rid = request.headers.get(_REQUEST_ID_HEADER) or ""
        rid = client_rid.lower() if _CANONICAL_UUID.fullmatch(client_rid) else str(uuid.uuid4())

        set_request_context(
            request_id=rid,
            request_method=request.method,
            request_path=_redact_path(request.url.path),
            ip_address=_client_ip(request),
            user_agent=request.headers.get("user-agent"),   # sanitised in set_request_context
        )

        response = await call_next(request)
        response.headers[_REQUEST_ID_HEADER] = rid
        return response
