"""Flat API error body {detail, code} (CLAUDE.md § API-first, rule 6).

Raise `ApiError(status, code, detail)` from a route; the handler registered in
main.py returns exactly `{"detail": "...", "code": "..."}` with that status.
`code` is a stable, machine-readable snake_case string clients branch on;
`detail` is the human-readable message. It subclasses HTTPException, so code
that catches HTTPException keeps working. `extra` adds more top-level keys for
errors that carry data (e.g. 409 gate_unmet adds `gate` and `unmet`); the body
stays flat.
"""
from typing import Any, Optional

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel


class ApiErrorBody(BaseModel):
    """Error response: human-readable `detail` + stable machine-readable `code`."""
    detail: str
    code:   str


class ApiError(HTTPException):
    def __init__(self, status_code: int, code: str, detail: str, extra: Optional[dict[str, Any]] = None) -> None:
        super().__init__(status_code=status_code, detail=detail)
        self.code = code
        self.extra = extra or {}


async def api_error_handler(request: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code,
                        content={**exc.extra, "detail": exc.detail, "code": exc.code})


# ─── L4 (R50/R118/R134): every error is flat ────────────────────────────────────
# A plain HTTPException (not an ApiError) gets a generic code from its status, so a client can
# always branch on `code`; routes that need a precise code raise ApiError. Request validation
# failures get one readable `detail` plus the field-level `errors` (⚠ `detail` was a list before L4).

_STATUS_CODE = {
    400: "bad_request", 401: "not_authenticated", 403: "forbidden", 404: "not_found",
    405: "method_not_allowed", 406: "not_acceptable", 409: "conflict", 410: "gone",
    413: "payload_too_large", 415: "unsupported_media_type", 422: "unprocessable", 423: "locked",
    429: "rate_limited", 500: "internal_error", 501: "not_implemented", 502: "bad_gateway",
    503: "service_unavailable", 504: "gateway_timeout", 507: "insufficient_storage",
}


def code_for_status(status_code: int) -> str:
    return _STATUS_CODE.get(status_code, "http_error")


async def http_error_handler(request: Request, exc) -> Any:
    """Starlette/FastAPI HTTPException that is not an ApiError → {detail, code}. Keeps the
    exception's headers (WWW-Authenticate, Retry-After); a non-string detail and the bodiless
    statuses keep FastAPI's default handling."""
    from fastapi.exception_handlers import http_exception_handler
    if isinstance(exc, ApiError):
        return await api_error_handler(request, exc)
    if not isinstance(exc.detail, str) or exc.status_code in (204, 304) or exc.status_code < 400:
        return await http_exception_handler(request, exc)
    return JSONResponse(status_code=exc.status_code, headers=getattr(exc, "headers", None),
                        content={"detail": exc.detail, "code": code_for_status(exc.status_code)})


_SUMMARY_MAX = 3


def _loc(loc) -> str:
    return ".".join(str(p) for p in loc) or "request"


async def validation_error_handler(request: Request, exc) -> JSONResponse:
    """RequestValidationError → 422 {detail: "<readable summary>", code: "validation_error",
    errors: [{loc, msg, type}]}. The submitted `input` is never echoed back (it can hold secrets)."""
    errors = [{"loc": list(e.get("loc", ())), "msg": str(e.get("msg", "")), "type": str(e.get("type", ""))}
              for e in exc.errors()]
    parts = [f"{_loc(e['loc'])}: {e['msg']}" for e in errors[:_SUMMARY_MAX]]
    more = len(errors) - _SUMMARY_MAX
    detail = "Invalid request: " + "; ".join(parts) + (f" (and {more} more)" if more > 0 else "")
    return JSONResponse(status_code=422,
                        content={"detail": detail, "code": "validation_error", "errors": errors})


class ValidationErrorItem(BaseModel):
    loc:  list[str | int]
    msg:  str
    type: str


class ValidationErrorBody(BaseModel):
    """422 validation_error: a readable `detail`, and `errors` per field (loc, msg, type)."""
    detail: str
    code:   str
    errors: list[ValidationErrorItem]
