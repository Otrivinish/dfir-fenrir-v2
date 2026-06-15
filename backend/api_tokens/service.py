"""API token business logic — issue, resolve, revoke."""
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.security import hash_token
from models import ApiToken, User


# Identifiable prefix so secret scanners (gitleaks, trufflehog, GitHub) can flag
# leaked tokens. `v1` is a format version — bump if we change the token shape.
TOKEN_PREFIX = "fnr_v1_"

# Role hierarchy — higher index = more privilege. A token's effective role is
# min(user.role, token.role): demoting the user automatically demotes their tokens.
_ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}


def role_le(a: str, b: str) -> bool:
    """True iff role `a` ≤ role `b` in the hierarchy."""
    return _ROLE_RANK.get(a, -1) <= _ROLE_RANK.get(b, -1)


def effective_role(user_role: str, token_role: str) -> str:
    """The lower of the two roles wins."""
    return user_role if _ROLE_RANK.get(user_role, -1) <= _ROLE_RANK.get(token_role, -1) else token_role


def _new_token() -> str:
    """`fnr_v1_<43 url-safe chars>` (32 random bytes, base64url, no padding)."""
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


async def issue_token(
    db: AsyncSession,
    *,
    user: User,
    name: str,
    role: str,
    expires_in_days: Optional[int] = None,
) -> Tuple[str, ApiToken]:
    """Create a new token for `user`. Returns (plain_token, row). Plain token shown once."""
    if not role_le(role, user.role):
        raise ValueError(f"Cannot issue token with role '{role}' — exceeds user role '{user.role}'")

    plain = _new_token()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=expires_in_days) if expires_in_days else None

    row = ApiToken(
        id=uuid.uuid4(),
        user_id=user.id,
        name=name,
        token_hash=hash_token(plain),
        token_prefix=plain[: len(TOKEN_PREFIX) + 6],   # "fnr_v1_abcdef"
        role=role,
        created_at=now,
        expires_at=expires_at,
    )
    db.add(row)
    await db.flush()
    return plain, row


async def resolve_token(db: AsyncSession, plain: str) -> Optional[Tuple[User, ApiToken]]:
    """Resolve a Bearer token to (user, token). None if invalid/expired/revoked.

    Caller is responsible for committing the `last_used_at` update if it cares
    about that audit field — we mutate it on the loaded row but don't flush.
    """
    if not plain or not plain.startswith(TOKEN_PREFIX):
        return None
    th = hash_token(plain)
    q = await db.execute(select(ApiToken).where(ApiToken.token_hash == th))
    tok = q.scalar_one_or_none()
    if not tok or tok.revoked_at is not None:
        return None

    now = datetime.now(timezone.utc)
    if tok.expires_at is not None and tok.expires_at <= now:
        return None

    user_q = await db.execute(select(User).where(User.id == tok.user_id))
    user = user_q.scalar_one_or_none()
    if not user or not user.is_active:
        return None

    tok.last_used_at = now
    return user, tok


async def revoke_token(
    db: AsyncSession, token_id: uuid.UUID, *, reason: str = "user"
) -> Optional[ApiToken]:
    q = await db.execute(select(ApiToken).where(ApiToken.id == token_id))
    row = q.scalar_one_or_none()
    if not row or row.revoked_at is not None:
        return None
    row.revoked_at = datetime.now(timezone.utc)
    row.revoke_reason = reason
    return row
