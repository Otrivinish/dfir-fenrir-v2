"""Auth business logic — session creation/revocation, TOTP, rate limiting."""
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from fastapi import Request, Response
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.redis_client import get_redis
from core.security import hash_token, new_session_token, verify_totp, decrypt_secret
from models import User, UserSession

SESSION_COOKIE = "fenrir_session"
PENDING_TOTP_COOKIE = "fenrir_pending_totp"
PENDING_TOTP_TTL = 5 * 60


# ─── Cookies ─────────────────────────────────────────────────────────────────

def _cookie_kwargs(max_age: int) -> dict:
    return dict(
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
        max_age=max_age,
    )


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(SESSION_COOKIE, token, **_cookie_kwargs(settings.session_ttl_seconds))


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")


def set_pending_totp_cookie(response: Response, token: str) -> None:
    response.set_cookie(PENDING_TOTP_COOKIE, token, **_cookie_kwargs(PENDING_TOTP_TTL))


def clear_pending_totp_cookie(response: Response) -> None:
    response.delete_cookie(PENDING_TOTP_COOKIE, path="/")


# ─── Sessions ────────────────────────────────────────────────────────────────

async def create_session(
    db: AsyncSession, user: User, *, request: Request, label: Optional[str] = None
) -> Tuple[str, UserSession]:
    """Create a new session for the user. Returns (opaque_token, row)."""
    token = new_session_token()
    th = hash_token(token)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=settings.session_ttl_seconds)

    row = UserSession(
        id=uuid.uuid4(),
        user_id=user.id,
        token_hash=th,
        label=label,
        ip_address=request.client.host if request.client else None,
        user_agent=(request.headers.get("user-agent") or "")[:512],
        created_at=now,
        last_seen_at=now,
        expires_at=expires,
    )
    db.add(row)
    user.last_login_at = now
    await db.flush()

    # Enforce concurrent-session cap (oldest active sessions evicted).
    await _enforce_session_cap(db, user.id)

    # Mirror to Redis for fast auth on every request.
    r = get_redis()
    await r.set(
        f"session:{th}",
        json.dumps({"user_id": str(user.id), "session_id": str(row.id)}),
        ex=settings.session_ttl_seconds,
    )
    return token, row


async def _enforce_session_cap(db: AsyncSession, user_id: uuid.UUID) -> None:
    q = await db.execute(
        select(UserSession)
        .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
        .order_by(UserSession.last_seen_at.desc())
    )
    sessions = q.scalars().all()
    excess = sessions[settings.max_sessions_per_user:]
    if not excess:
        return
    r = get_redis()
    now = datetime.now(timezone.utc)
    for s in excess:
        s.revoked_at = now
        s.revoke_reason = "evicted"
        await r.delete(f"session:{s.token_hash}")


async def revoke_session(
    db: AsyncSession, session_row: UserSession, *, reason: str = "user"
) -> None:
    session_row.revoked_at = datetime.now(timezone.utc)
    session_row.revoke_reason = reason
    r = get_redis()
    await r.delete(f"session:{session_row.token_hash}")


async def revoke_other_sessions(
    db: AsyncSession, user_id: uuid.UUID, *, keep_session_id: uuid.UUID
) -> int:
    q = await db.execute(
        select(UserSession).where(
            UserSession.user_id == user_id,
            UserSession.revoked_at.is_(None),
            UserSession.id != keep_session_id,
        )
    )
    n = 0
    r = get_redis()
    now = datetime.now(timezone.utc)
    for s in q.scalars():
        s.revoked_at = now
        s.revoke_reason = "user_revoke_others"
        await r.delete(f"session:{s.token_hash}")
        n += 1
    return n


# ─── TOTP ────────────────────────────────────────────────────────────────────

def verify_user_totp(user: User, code: str) -> bool:
    if not user.totp_enabled or not user.totp_secret_enc:
        return False
    try:
        secret = decrypt_secret(user.totp_secret_enc)
    except Exception:
        return False
    return verify_totp(secret, code)


# ─── Rate limiting / lockouts (Redis) ───────────────────────────────────────

async def record_login_failure(username: str) -> int:
    r = get_redis()
    key = f"login_fail:{username.lower()}"
    n = await r.incr(key)
    if n == 1:
        await r.expire(key, settings.login_lockout_seconds)
    return int(n)


async def is_login_locked(username: str) -> bool:
    r = get_redis()
    n = await r.get(f"login_fail:{username.lower()}")
    return int(n or 0) >= settings.login_max_failures


async def clear_login_failures(username: str) -> None:
    r = get_redis()
    await r.delete(f"login_fail:{username.lower()}")


async def record_totp_failure(user_id: uuid.UUID) -> int:
    r = get_redis()
    key = f"totp_fail:{user_id}"
    n = await r.incr(key)
    if n == 1:
        await r.expire(key, settings.totp_lockout_seconds)
    return int(n)


async def is_totp_locked(user_id: uuid.UUID) -> bool:
    r = get_redis()
    n = await r.get(f"totp_fail:{user_id}")
    return int(n or 0) >= settings.totp_max_failures


async def clear_totp_failures(user_id: uuid.UUID) -> None:
    r = get_redis()
    await r.delete(f"totp_fail:{user_id}")


# ─── Pending TOTP (step 1 → step 2 of login) ─────────────────────────────────

async def issue_pending_totp(user_id: uuid.UUID) -> str:
    """Issue a short-lived token that proves step-1 (password) completed."""
    token = new_session_token()
    r = get_redis()
    await r.set(f"pending_totp:{token}", str(user_id), ex=PENDING_TOTP_TTL)
    return token


async def consume_pending_totp(token: str) -> Optional[uuid.UUID]:
    r = get_redis()
    raw = await r.get(f"pending_totp:{token}")
    if not raw:
        return None
    await r.delete(f"pending_totp:{token}")
    try:
        return uuid.UUID(raw)
    except Exception:
        return None
