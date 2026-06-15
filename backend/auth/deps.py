"""FastAPI dependencies: current user / require role.

Two auth mechanisms resolve to the same `User` + role checks:
  • Cookie session (browser) — looks up `fenrir_session` in Redis.
  • Bearer token  (MCP / scripts / integrations) — looks up the SHA-256
    fingerprint in `api_tokens`. Effective role is min(user.role, token.role)
    so demoting a user automatically demotes their tokens. The role override
    is applied to the returned User instance only; no DB mutation.
"""
import copy
import json
import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api_tokens.service import effective_role, resolve_token
from audit.context import enrich_user_context
from core.config import settings
from core.database import get_db
from core.redis_client import get_redis
from core.security import hash_token
from models import User, UserSession
from auth.service import SESSION_COOKIE


async def _resolve_cookie(request: Request, db: AsyncSession) -> Optional[Tuple[User, UserSession]]:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    th = hash_token(token)
    r = get_redis()
    raw = await r.get(f"session:{th}")
    if not raw:
        return None
    data = json.loads(raw)
    user_id = uuid.UUID(data["user_id"])
    session_id = uuid.UUID(data["session_id"])

    user_q = await db.execute(select(User).where(User.id == user_id))
    user = user_q.scalar_one_or_none()
    if not user or not user.is_active:
        await r.delete(f"session:{th}")
        return None

    sess_q = await db.execute(select(UserSession).where(UserSession.id == session_id))
    sess = sess_q.scalar_one_or_none()
    if not sess or sess.revoked_at is not None:
        await r.delete(f"session:{th}")
        return None

    # Enforce idle timeout BEFORE refreshing last_seen_at — else the timer resets itself.
    now = datetime.now(timezone.utc)
    if sess.last_seen_at is not None:
        last_seen = sess.last_seen_at
        # last_seen_at is a timestamptz column — tolerate naive values from legacy rows.
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        if (now - last_seen).total_seconds() > settings.inactivity_timeout_minutes * 60:
            sess.revoked_at = now
            sess.revoke_reason = "idle_timeout"
            await r.delete(f"session:{th}")
            return None

    sess.last_seen_at = now
    enrich_user_context(
        user_id=user.id,
        username=user.username,
        role_at_time=user.role,
        session_id=sess.id,
    )
    return user, sess


def _bearer(request: Request) -> Optional[str]:
    h = request.headers.get("authorization") or request.headers.get("Authorization")
    if not h:
        return None
    parts = h.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


async def _resolve_bearer(request: Request, db: AsyncSession) -> Optional[User]:
    plain = _bearer(request)
    if not plain:
        return None
    resolved = await resolve_token(db, plain)
    if not resolved:
        return None
    user, tok = resolved

    # Detach + override role so route-level role checks see the token cap.
    # SQLAlchemy identity map is per-session, so a shallow copy with the role
    # field overwritten is safe and won't be flushed back to DB.
    eff = effective_role(user.role, tok.role)
    if eff != user.role:
        user = copy.copy(user)
        user.role = eff

    enrich_user_context(
        user_id=user.id,
        username=user.username,
        role_at_time=eff,
        session_id=None,
    )
    # Mark request so handlers can distinguish if needed (e.g. block password
    # change endpoints from API tokens). last_used_at update is on tok; flush
    # by the request-scoped db dep at commit time would persist it — but most
    # GET-only endpoints don't commit. Stale by minutes is acceptable.
    request.state.auth_method = "api_token"
    request.state.api_token_id = tok.id
    return user


async def _resolve_session(request: Request, db: AsyncSession) -> Optional[Tuple[User, Optional[UserSession]]]:
    """Try cookie first; fall back to Bearer. Returns (user, session-or-None)."""
    via_cookie = await _resolve_cookie(request, db)
    if via_cookie:
        return via_cookie
    via_bearer = await _resolve_bearer(request, db)
    if via_bearer:
        return via_bearer, None
    return None


# Endpoints a not-yet-enrolled account must still reach to complete TOTP
# enrolment (and to read its own flags / log out). Everything else is blocked.
_FLAG_EXEMPT_PATHS = frozenset({
    "/api/users/me",            # SPA reads force_* flags here to drive the redirect
    "/api/auth/logout",
    "/api/auth/totp/setup",
    "/api/auth/totp/enable",
    "/api/auth/totp/disable",
})


def _enforce_account_flags(request: Request, user: User) -> None:
    """Enforce org-mandated TOTP enrolment in the API itself — not just the SPA —
    so a Bearer/`curl` client can't skip the gate (zero trust; satisfies the
    API-first rule that every workflow is curl-drivable). Without this, a freshly
    created user whose totp is not yet enabled could drive the whole API directly.

    Dev keeps MFA optional: TOTP_REQUIRED=false makes user creation set
    force_totp_enrol=False AND short-circuits the check below, so enrolment is
    never forced when the org policy is off.

    Note: `force_password_change` is intentionally NOT gated here — the SPA drives
    that flow and has no global redirect for it, so enforcing it server-side would
    lock created users out of every page. Left as-is (advisory) to stay surgical.
    """
    if not settings.totp_required:
        return
    if request.url.path in _FLAG_EXEMPT_PATHS:
        return
    if user.force_totp_enrol and not user.totp_enabled:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "TOTP enrolment required before continuing (code: totp_enrolment_required)",
        )


async def current_user(
    request: Request, db: AsyncSession = Depends(get_db)
) -> User:
    resolved = await _resolve_session(request, db)
    if not resolved:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    user = resolved[0]
    _enforce_account_flags(request, user)
    return user


async def current_session(
    request: Request, db: AsyncSession = Depends(get_db)
) -> Tuple[User, UserSession]:
    """Cookie session only. Endpoints needing a *browser session* (e.g. logout,
    revoke-other-sessions) depend on this rather than `current_user`."""
    resolved = await _resolve_cookie(request, db)
    if not resolved:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    return resolved


def require_role(*allowed: str):
    async def _check(user: User = Depends(current_user)) -> User:
        if user.role not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Requires role: {allowed}")
        return user
    return _check


require_admin   = require_role("admin")
require_analyst = require_role("admin", "analyst")
