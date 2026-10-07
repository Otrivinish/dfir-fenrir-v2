"""Per-request audit context.

A ContextVar holds the request- and user-level fields that every audit row
should carry. The audit middleware seeds it at request entry (request_id /
method / path / ip / user agent), and the auth dependency enriches it once the session is
resolved (user_id / username / role / session_id). `write_audit` reads from
this context so route handlers don't have to pass every field by hand.
"""
import re
from contextvars import ContextVar
from typing import Any

_EMPTY: dict[str, Any] = {}

_audit_ctx: ContextVar[dict[str, Any]] = ContextVar("audit_ctx", default=_EMPTY)

USER_AGENT_MAX = 512   # = audit_logs.user_agent VARCHAR(512)
# C0 + DEL + C1 (incl. NEL) and the Unicode line/paragraph separators: anything a log
# reader, CSV/syslog consumer or the UI could take as a line break or a control code.
_UA_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029]")


def sanitize_user_agent(value: str | None) -> str | None:
    """The client-supplied User-Agent as it may be stored in (and hashed into) the
    audit chain: control characters out, whitespace collapsed, at most 512
    characters, empty -> None. Idempotent."""
    if not value:
        return None
    s = " ".join(_UA_CONTROL.sub(" ", value).split())[:USER_AGENT_MAX].rstrip()
    return s or None


def set_request_context(*, request_id: str, request_method: str,
                        request_path: str, ip_address: str | None,
                        user_agent: str | None = None) -> None:
    """Called by the audit middleware at request entry."""
    _audit_ctx.set({
        "request_id":     request_id,
        "request_method": request_method,
        "request_path":   request_path,
        "ip_address":     ip_address,
        "user_agent":     sanitize_user_agent(user_agent),
    })


def enrich_user_context(*, user_id, username: str | None,
                        role_at_time: str | None, session_id) -> None:
    """Called by `current_user` / `current_session` once auth succeeds."""
    d = dict(_audit_ctx.get())
    d["user_id"]      = user_id
    d["username"]     = username
    d["role_at_time"] = role_at_time
    d["session_id"]   = session_id
    _audit_ctx.set(d)


def get_audit_context() -> dict[str, Any]:
    return _audit_ctx.get()
