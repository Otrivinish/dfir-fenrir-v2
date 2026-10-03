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
