"""Session management — per-user (router) + admin-global (global_router)."""
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_session, require_admin
from auth.service import revoke_other_sessions, revoke_session
from core.database import get_db
from models import User, UserSession
from schemas import AdminSessionOut, SessionLabelUpdate, SessionOut

router        = APIRouter()   # per-user, mounted at /api/sessions
global_router = APIRouter()   # admin,    mounted at /api/admin


@router.get("", response_model=list[SessionOut], summary="List my active sessions")
async def list_my_sessions(session=Depends(current_session),
                           db: AsyncSession = Depends(get_db)) -> list[SessionOut]:
    """List the calling user's own non-revoked sessions, newest last-seen first.
    Authenticated user. Each item flags whether it is the current session."""
    user, current = session
    q = await db.execute(
        select(UserSession)
        .where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
        .order_by(UserSession.last_seen_at.desc())
    )
    out = []
    for s in q.scalars():
        item = SessionOut.model_validate(s)
        item.is_current = (s.id == current.id)
        out.append(item)
    return out


@router.delete("/{session_id}", summary="Revoke one of my sessions")
async def revoke_one(session_id: uuid.UUID, request: Request,
                     session=Depends(current_session),
                     db: AsyncSession = Depends(get_db)) -> dict:
    """Revoke one of the calling user's own sessions by id. Authenticated user.
    Returns 404 if the session is not found or not owned by the caller, and
    {"status": "already_revoked"} if it was already revoked."""
    user, current = session
    q = await db.execute(select(UserSession).where(UserSession.id == session_id))
    s = q.scalar_one_or_none()
    if not s or s.user_id != user.id:
        raise HTTPException(404, "Session not found")
    if s.revoked_at is not None:
        return {"status": "already_revoked"}
    await revoke_session(db, s, reason="user")
    await write_audit(
        db, "session_revoke",
        user_id=user.id, username=user.username,
        resource_type="session", resource_id=str(s.id),
        details={"self_revoked": True, "was_current": s.id == current.id},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return {"status": "ok"}


@router.post("/revoke-others", summary="Revoke my other sessions")
async def revoke_others(request: Request,
                        session=Depends(current_session),
                        db: AsyncSession = Depends(get_db)) -> dict:
    """Revoke all of the calling user's sessions except the current one.
    Authenticated user. Returns {"revoked": <count>} of sessions ended."""
    user, current = session
    n = await revoke_other_sessions(db, user.id, keep_session_id=current.id)
    if n > 0:
        await write_audit(
            db, "session_revoke_others",
            user_id=user.id, username=user.username,
            details={"revoked_count": n},
            ip_address=request.client.host if request.client else None,
        )
    await db.commit()
    return {"revoked": n}


@router.patch("/{session_id}/label", response_model=SessionOut, summary="Rename one of my sessions")
async def label_session(session_id: uuid.UUID, req: SessionLabelUpdate,
                        session=Depends(current_session),
                        db: AsyncSession = Depends(get_db)) -> SessionOut:
    """Update the human-readable label on one of the calling user's own sessions.
    Authenticated user. Returns 404 if not found or not owned by the caller, and
    the updated session with its is_current flag on success."""
    user, current = session
    q = await db.execute(select(UserSession).where(UserSession.id == session_id))
    s = q.scalar_one_or_none()
    if not s or s.user_id != user.id:
        raise HTTPException(404, "Session not found")
    s.label = req.label
    await db.commit()
    out = SessionOut.model_validate(s)
    out.is_current = (s.id == current.id)
    return out


# ─── Admin endpoints ──────────────────────────────────────────────────────────

@global_router.get("/sessions", response_model=list[AdminSessionOut], summary="List all active sessions (admin)")
async def admin_list_sessions(
    admin=Depends(require_admin),
    session=Depends(current_session),
    db: AsyncSession = Depends(get_db),
) -> list[AdminSessionOut]:
    """List every non-revoked session across all users, newest last-seen first,
    with each session's owning username. Admin only. Each item flags whether it
    is the caller's current session."""
    _, current = session
    rows = (await db.execute(
        select(UserSession, User.username)
        .join(User, User.id == UserSession.user_id)
        .where(UserSession.revoked_at.is_(None))
        .order_by(UserSession.last_seen_at.desc())
    )).all()

    out = []
    for s, username in rows:
        item = AdminSessionOut.model_validate(s)
        item.username   = username
        item.is_current = (s.id == current.id)
        out.append(item)
    return out


@global_router.delete("/sessions/{session_id}", summary="Revoke any user's session (admin)")
async def admin_revoke_session(
    session_id: uuid.UUID,
    request: Request,
    admin=Depends(require_admin),
    session=Depends(current_session),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Revoke any user's session by id. Admin only. Returns 404 if not found or
    already revoked, and 400 if it is the admin's own current session (use logout
    instead). Returns {"status": "ok"} on success."""
    admin_user, current = session
    s = (await db.execute(
        select(UserSession).where(UserSession.id == session_id)
    )).scalar_one_or_none()
    if not s or s.revoked_at is not None:
        raise HTTPException(404, "Session not found or already revoked")
    if s.id == current.id:
        raise HTTPException(400, "Use sign-out to end your own current session")

    await revoke_session(db, s, reason="admin")
    await write_audit(
        db, "admin_session_revoke",
        user_id=admin_user.id, username=admin_user.username,
        resource_type="session", resource_id=str(s.id),
        details={"target_user_id": str(s.user_id), "admin_revoked": True},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return {"status": "ok"}
