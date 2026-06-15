"""User management: /me, list, create, update, delete, sessions, unlock, activity, teams (all admin)."""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_admin
from auth.service import clear_login_failures, clear_totp_failures
from core.config import settings
from core.database import get_db
from core.redis_client import get_redis
from core.security import ahash_password
from models import AuditLog, Team, User, UserSession, user_team
from schemas import (
    AuditLogEntryOut, ResetPasswordRequest, SessionOut, TeamOut,
    UserAssignable, UserCreate, UserOut, UserUpdate,
)

router = APIRouter()


async def _assert_not_last_admin(db: AsyncSession, target: User, action: str) -> None:
    """Reject an op that would remove the final active admin — otherwise the org
    locks itself out permanently (the bootstrap token is deleted after setup, so
    there is no recovery path). Only relevant when the target is currently an
    active admin."""
    if target.role != "admin" or not target.is_active:
        return
    remaining = (await db.execute(
        select(func.count(User.id)).where(
            User.role == "admin",
            User.is_active == True,  # noqa: E712
            User.id != target.id,
        )
    )).scalar_one()
    if remaining == 0:
        raise HTTPException(400, f"Cannot {action} the last active admin")


@router.get("/me", response_model=UserOut, summary="Get current user")
async def me(user: User = Depends(current_user)) -> UserOut:
    """Return the authenticated caller's own profile. Authenticated user."""
    return UserOut.model_validate(user)


@router.get("/assignable", response_model=list[UserAssignable], summary="List assignable users")
async def list_assignable(_: User = Depends(current_user),
                          db: AsyncSession = Depends(get_db)) -> list[UserAssignable]:
    """Minimal list of active users (id, username, etc.) for assignment pickers,
    ordered by username. Available to any authenticated user."""
    q = await db.execute(select(User).where(User.is_active == True).order_by(User.username))
    return [UserAssignable.model_validate(u) for u in q.scalars()]


@router.get("", response_model=list[UserOut], summary="List users")
async def list_users(_: User = Depends(require_admin),
                     db: AsyncSession = Depends(get_db)) -> list[UserOut]:
    """List all user accounts ordered by username, including inactive ones. Admin only."""
    q = await db.execute(select(User).order_by(User.username))
    return [UserOut.model_validate(u) for u in q.scalars()]


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED,
             summary="Create a user")
async def create_user(req: UserCreate, request: Request,
                      admin: User = Depends(require_admin),
                      db: AsyncSession = Depends(get_db)) -> UserOut:
    """Create a new user account from username, email, password, role and optional
    qualifications. The account is flagged to force a password change (and TOTP
    enrolment if globally required). Returns 409 if the username or email already
    exists. Admin only. Returns the created user."""
    existing = await db.execute(
        select(User).where((func.lower(User.username) == req.username.lower()) |
                           (func.lower(User.email)    == req.email.lower()))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "Username or email already exists")
    user = User(
        id=uuid.uuid4(),
        username=req.username,
        email=req.email,
        full_name=req.full_name,
        hashed_password=await ahash_password(req.password),
        role=req.role,
        is_active=True,
        force_password_change=True,
        force_totp_enrol=settings.totp_required,
        qualifications=req.qualifications,
    )
    db.add(user)
    await db.flush()
    await write_audit(
        db, "user_create",
        user_id=admin.id, username=admin.username,
        resource_type="user", resource_id=str(user.id),
        details={"new_user": user.username, "role": user.role},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return UserOut.model_validate(user)


@router.get("/{user_id}", response_model=UserOut, summary="Get a user")
async def get_user(user_id: uuid.UUID, _: User = Depends(require_admin),
                   db: AsyncSession = Depends(get_db)) -> UserOut:
    """Fetch a single user account by id. Returns 404 if not found. Admin only."""
    u = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not u:
        raise HTTPException(404, "User not found")
    return UserOut.model_validate(u)


@router.patch("/{user_id}", response_model=UserOut, summary="Update a user")
async def update_user(user_id: uuid.UUID, req: UserUpdate, request: Request,
                      admin: User = Depends(require_admin),
                      db: AsyncSession = Depends(get_db)) -> UserOut:
    """Partially update a user's full name, qualifications, role, active flag, or
    TOTP/password-change flags. Guards prevent self-demotion, self-deactivation, and
    removing the last active admin. Returns 404 if not found. Admin only. Returns the
    updated user."""
    u = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not u:
        raise HTTPException(404, "User not found")

    changed: dict[str, object] = {}
    if req.full_name is not None and req.full_name != u.full_name:
        u.full_name = req.full_name; changed["full_name"] = req.full_name
    if req.qualifications is not None and req.qualifications != u.qualifications:
        u.qualifications = req.qualifications; changed["qualifications"] = True
    if req.role is not None and req.role != u.role:
        if u.id == admin.id and req.role != "admin":
            raise HTTPException(400, "You cannot demote yourself")
        if req.role != "admin":
            await _assert_not_last_admin(db, u, "demote")
        u.role = req.role; changed["role"] = req.role
    if req.is_active is not None and req.is_active != u.is_active:
        if u.id == admin.id and not req.is_active:
            raise HTTPException(400, "You cannot deactivate yourself")
        if not req.is_active:
            await _assert_not_last_admin(db, u, "deactivate")
        u.is_active = req.is_active; changed["is_active"] = req.is_active
    if req.disable_totp:
        u.totp_enabled = False; u.totp_secret_enc = None
        changed["totp_disabled"] = True
    if req.force_totp_enrol is not None and req.force_totp_enrol != u.force_totp_enrol:
        u.force_totp_enrol = req.force_totp_enrol
        changed["force_totp_enrol"] = req.force_totp_enrol
    if req.force_password_change is not None and req.force_password_change != u.force_password_change:
        u.force_password_change = req.force_password_change
        changed["force_password_change"] = req.force_password_change

    if changed:
        await write_audit(
            db, "user_update",
            user_id=admin.id, username=admin.username,
            resource_type="user", resource_id=str(u.id),
            details={"target_username": u.username, "changes": changed},
            ip_address=request.client.host if request.client else None,
        )
    await db.commit()
    return UserOut.model_validate(u)


@router.delete("/{user_id}", summary="Delete a user")
async def delete_user(user_id: uuid.UUID, request: Request,
                      admin: User = Depends(require_admin),
                      db: AsyncSession = Depends(get_db)) -> dict:
    """Permanently delete a user account. Refuses to delete yourself or the last
    active admin, and returns 409 if the user has associated records (disable the
    account instead). Returns 404 if not found. Admin only."""
    u = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not u:
        raise HTTPException(404, "User not found")
    if u.id == admin.id:
        raise HTTPException(400, "You cannot delete yourself")
    await _assert_not_last_admin(db, u, "delete")
    await write_audit(
        db, "user_delete",
        user_id=admin.id, username=admin.username,
        resource_type="user", resource_id=str(u.id),
        details={"deleted_username": u.username},
        ip_address=request.client.host if request.client else None,
    )
    try:
        await db.delete(u)
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "User has associated records and cannot be deleted. Disable the account instead.",
        )
    return {"status": "ok"}


@router.post("/{user_id}/reset-password", summary="Reset a user's password")
async def reset_password(user_id: uuid.UUID, req: ResetPasswordRequest, request: Request,
                         admin: User = Depends(require_admin),
                         db: AsyncSession = Depends(get_db)) -> dict:
    """Set a new password for a user and optionally force a change on next login.
    Returns 404 if not found. Admin only."""
    u = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not u:
        raise HTTPException(404, "User not found")
    u.hashed_password = await ahash_password(req.new_password)
    u.force_password_change = req.force_change_on_login
    await write_audit(
        db, "password_reset",
        user_id=admin.id, username=admin.username,
        resource_type="user", resource_id=str(u.id),
        details={"target_username": u.username, "force_change": req.force_change_on_login},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return {"status": "ok"}


@router.get("/{user_id}/sessions", response_model=list[SessionOut],
            summary="List a user's sessions")
async def get_user_sessions(user_id: uuid.UUID, _: User = Depends(require_admin),
                             db: AsyncSession = Depends(get_db)) -> list[SessionOut]:
    """List a user's active (non-revoked) login sessions, most recently seen first.
    Returns 404 if the user is not found. Admin only."""
    u = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not u:
        raise HTTPException(404, "User not found")
    q = await db.execute(
        select(UserSession)
        .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
        .order_by(UserSession.last_seen_at.desc())
    )
    return [SessionOut.model_validate(s) for s in q.scalars()]


@router.delete("/{user_id}/sessions/{session_id}", summary="Revoke a user's session")
async def revoke_user_session(user_id: uuid.UUID, session_id: uuid.UUID, request: Request,
                              admin: User = Depends(require_admin),
                              db: AsyncSession = Depends(get_db)) -> dict:
    """Revoke a single login session for a user and evict it from the Redis session
    cache. Returns 404 if the user or session is not found, or already_revoked if it
    was already revoked. Admin only."""
    u = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not u:
        raise HTTPException(404, "User not found")
    s = (await db.execute(
        select(UserSession).where(UserSession.id == session_id, UserSession.user_id == user_id)
    )).scalar_one_or_none()
    if not s:
        raise HTTPException(404, "Session not found")
    if s.revoked_at is not None:
        return {"status": "already_revoked"}
    s.revoked_at = datetime.now(timezone.utc)
    s.revoke_reason = "admin"
    r = get_redis()
    await r.delete(f"session:{s.token_hash}")
    await write_audit(
        db, "session_revoke",
        user_id=admin.id, username=admin.username,
        resource_type="session", resource_id=str(s.id),
        details={"target_username": u.username, "admin_action": True},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return {"status": "ok"}


@router.post("/{user_id}/sessions/revoke-all", summary="Revoke all of a user's sessions")
async def revoke_user_all_sessions(user_id: uuid.UUID, request: Request,
                                   admin: User = Depends(require_admin),
                                   db: AsyncSession = Depends(get_db)) -> dict:
    """Revoke every active login session for a user and evict them from the Redis
    session cache. Returns 404 if the user is not found, otherwise the count of
    revoked sessions. Admin only."""
    u = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not u:
        raise HTTPException(404, "User not found")
    q = await db.execute(
        select(UserSession)
        .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
    )
    r = get_redis()
    now = datetime.now(timezone.utc)
    n = 0
    for s in q.scalars():
        s.revoked_at = now
        s.revoke_reason = "admin"
        await r.delete(f"session:{s.token_hash}")
        n += 1
    if n > 0:
        await write_audit(
            db, "session_revoke_all",
            user_id=admin.id, username=admin.username,
            resource_type="user", resource_id=str(u.id),
            details={"target_username": u.username, "revoked_count": n},
            ip_address=request.client.host if request.client else None,
        )
    await db.commit()
    return {"revoked": n}


@router.post("/{user_id}/unlock", summary="Unlock a user")
async def unlock_user(user_id: uuid.UUID, request: Request,
                      admin: User = Depends(require_admin),
                      db: AsyncSession = Depends(get_db)) -> dict:
    """Clear a user's accumulated login and TOTP failure counters, lifting any
    lockout. Returns 404 if not found. Admin only."""
    u = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not u:
        raise HTTPException(404, "User not found")
    await clear_login_failures(u.username)
    await clear_totp_failures(u.id)
    await write_audit(
        db, "user_unlock",
        user_id=admin.id, username=admin.username,
        resource_type="user", resource_id=str(u.id),
        details={"target_username": u.username},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return {"status": "ok"}


@router.get("/{user_id}/activity", response_model=list[AuditLogEntryOut],
            summary="List a user's audit activity")
async def get_user_activity(user_id: uuid.UUID, _: User = Depends(require_admin),
                             db: AsyncSession = Depends(get_db)) -> list[AuditLogEntryOut]:
    """Return up to the 100 most recent audit log entries either performed by the
    user or targeting the user, newest first. Returns 404 if not found. Admin only."""
    u = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not u:
        raise HTTPException(404, "User not found")
    q = await db.execute(
        select(AuditLog)
        .where(
            or_(
                AuditLog.user_id == user_id,
                and_(AuditLog.resource_type == "user", AuditLog.resource_id == str(user_id)),
            )
        )
        .order_by(AuditLog.timestamp.desc())
        .limit(100)
    )
    return [AuditLogEntryOut.model_validate(e) for e in q.scalars()]


@router.get("/{user_id}/teams", response_model=list[TeamOut],
            summary="List a user's teams")
async def get_user_teams(user_id: uuid.UUID, _: User = Depends(require_admin),
                          db: AsyncSession = Depends(get_db)) -> list[TeamOut]:
    """List the teams a user belongs to, ordered by team name. Returns 404 if the
    user is not found. Admin only."""
    u = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not u:
        raise HTTPException(404, "User not found")
    q = await db.execute(
        select(Team)
        .join(user_team, Team.id == user_team.c.team_id)
        .where(user_team.c.user_id == user_id)
        .order_by(Team.name)
    )
    return [TeamOut.model_validate(t) for t in q.scalars().unique()]
