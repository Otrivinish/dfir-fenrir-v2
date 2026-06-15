"""Per-incident comms routes: comments, OOB passphrase, dark operation toggle,
OOB log.

Mounted at prefix="/api/incidents".

Passphrase format: ADJECTIVE-ANIMAL-NNNN  (e.g. CHARLIE-FALCON-3849)
  ~21.9 bits entropy, cryptographically secure via `secrets`.
  Stored in cleartext on the Incident row — it is a short-lived human
  verification aid, not a long-term secret. Regeneration is audited.
"""
import base64
import json
import secrets
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from incidents.access import get_accessible_incident
from models import Comment, Incident, OOBLog, User
from notifications.service import notify_comment
from schemas import (
    CommentCreate,
    CommentList,
    CommentOut,
    CommentUpdate,
    DarkOperationUpdate,
    OOBLogCreate,
    OOBLogList,
    OOBLogOut,
    PassphraseOut,
)

router = APIRouter()

# ── Passphrase word pools (NATO phonetic alphabet + operational codename words) ─

_ADJECTIVES = [
    "ALPHA", "BRAVO", "CHARLIE", "DELTA", "ECHO", "FOXTROT", "GOLF", "HOTEL",
    "INDIA", "JULIET", "KILO", "LIMA", "MIKE", "NOVEMBER", "OSCAR", "PAPA",
    "QUEBEC", "ROMEO", "SIERRA", "TANGO", "UNIFORM", "VICTOR", "WHISKEY", "YANKEE",
]
_ANIMALS = [
    "WOLF", "EAGLE", "FALCON", "RAVEN", "BEAR", "LYNX", "COBRA", "TIGER",
    "HAWK", "VIPER", "SHARK", "GHOST", "PHANTOM", "SHADOW", "STORM", "FROST",
]


def _generate_passphrase() -> str:
    return f"{secrets.choice(_ADJECTIVES)}-{secrets.choice(_ANIMALS)}-{secrets.randbelow(10000):04d}"


# ── Helpers ────────────────────────────────────────────────────────────────

def _encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"o": offset}).encode()).decode().rstrip("=")


def _decode_cursor(cursor: Optional[str]) -> int:
    if not cursor:
        return 0
    try:
        pad = "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(cursor + pad).decode())
        return max(0, int(data.get("o", 0)))
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid cursor")


async def _load_usernames(db: AsyncSession, ids: set) -> dict:
    if not ids:
        return {}
    rows = (await db.execute(
        select(User.id, User.username).where(User.id.in_(ids))
    )).all()
    return {r.id: r.username for r in rows}


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


# ═══════════════════════════════════════════════════════════════════════════
# Comments
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/{incident_id}/comments", response_model=CommentList, summary="List comments")
async def list_comments(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
    limit:  int           = Query(default=100, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
) -> CommentList:
    """List comments on an incident, oldest first, with cursor-based pagination.

    Requires access to the incident. Supports `limit` (1-200) and an opaque
    `cursor`. Returns a page of comments (each enriched with the author's
    username) plus a `next_cursor` when more results remain.
    """
    await _get_incident(db, incident_id, user)
    offset = _decode_cursor(cursor)
    stmt = (
        select(Comment)
        .where(Comment.incident_id == incident_id)
        .order_by(Comment.created_at.asc(), Comment.id)
        .offset(offset)
        .limit(limit + 1)
    )
    rows     = (await db.execute(stmt)).scalars().all()
    has_more = len(rows) > limit
    page     = rows[:limit]
    names    = await _load_usernames(db, {r.author_id for r in page if r.author_id})
    items    = [
        CommentOut.model_validate(r).model_copy(update={"author_username": names.get(r.author_id)})
        for r in page
    ]
    next_cursor = _encode_cursor(offset + limit) if has_more else None
    return CommentList(items=items, next_cursor=next_cursor)


@router.post("/{incident_id}/comments",
             response_model=CommentOut,
             status_code=status.HTTP_201_CREATED,
             summary="Add a comment")
async def create_comment(
    incident_id: uuid.UUID,
    req: CommentCreate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> CommentOut:
    """Add a comment to an incident. Requires the analyst role.

    Rejected if the incident is closed. Records an audit entry and notifies
    other participants. Returns the created comment with the author's username.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    c = Comment(
        id=uuid.uuid4(),
        incident_id=incident_id,
        body=req.body.strip(),
        author_id=user.id,
    )
    db.add(c)
    await db.flush()
    await write_audit(
        db, "comment_create",
        user_id=user.id, username=user.username,
        resource_type="comment", resource_id=str(c.id),
        details={"incident_id": str(incident_id)},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    await notify_comment(
        db, user.id, incident_id,
        inc.ref or str(incident_id), user.username, c.body,
    )
    return CommentOut.model_validate(c).model_copy(update={"author_username": user.username})


@router.patch("/{incident_id}/comments/{comment_id}", response_model=CommentOut,
              summary="Edit a comment")
async def update_comment(
    incident_id: uuid.UUID,
    comment_id:  uuid.UUID,
    req: CommentUpdate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> CommentOut:
    """Edit a comment's body. Requires the analyst role; only the original
    author or an admin may edit.

    Rejected if the incident is closed. The first edit stamps `edited_at` and
    the change is audited. Returns the updated comment.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    c = (await db.execute(
        select(Comment).where(Comment.id == comment_id, Comment.incident_id == incident_id)
    )).scalar_one_or_none()
    if not c:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Comment not found")
    # Only author or admin may edit.
    if c.author_id != user.id and user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not your comment")

    body = req.body.strip()
    if body != c.body:
        if c.edited_at is None:
            c.edited_at = datetime.now(timezone.utc)
        c.body = body
        await write_audit(
            db, "comment_update",
            user_id=user.id, username=user.username,
            resource_type="comment", resource_id=str(c.id),
            details={"incident_id": str(incident_id)},
            ip_address=request.client.host if request.client else None,
        )
    await db.commit()
    return CommentOut.model_validate(c)


@router.delete("/{incident_id}/comments/{comment_id}", summary="Delete a comment")
async def delete_comment(
    incident_id: uuid.UUID,
    comment_id:  uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Delete a comment. Requires the analyst role; only the original author or
    an admin may delete.

    Rejected if the incident is closed. The deletion is audited. Returns
    `{"status": "ok"}`.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    c = (await db.execute(
        select(Comment).where(Comment.id == comment_id, Comment.incident_id == incident_id)
    )).scalar_one_or_none()
    if not c:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Comment not found")
    if c.author_id != user.id and user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not your comment")

    await write_audit(
        db, "comment_delete",
        user_id=user.id, username=user.username,
        resource_type="comment", resource_id=str(c.id),
        details={"incident_id": str(incident_id)},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(c)
    await db.commit()
    return {"status": "ok"}


# ═══════════════════════════════════════════════════════════════════════════
# OOB — passphrase + dark operation toggle
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/{incident_id}/oob/passphrase", response_model=PassphraseOut,
            summary="Get the OOB verification passphrase")
async def get_passphrase(
    incident_id: uuid.UUID,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> PassphraseOut:
    """Return the incident's out-of-band verification passphrase, generating
    one (format ADJECTIVE-ANIMAL-NNNN) on first access. Requires the analyst
    role.
    """
    inc = await _get_incident(db, incident_id, user)
    if not inc.oob_passphrase:
        inc.oob_passphrase = _generate_passphrase()
        await db.commit()
    return PassphraseOut(passphrase=inc.oob_passphrase)


@router.post("/{incident_id}/oob/passphrase/regenerate", response_model=PassphraseOut,
             summary="Regenerate the OOB verification passphrase")
async def regenerate_passphrase(
    incident_id: uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> PassphraseOut:
    """Generate a fresh out-of-band verification passphrase for the incident,
    replacing the existing one. Requires the analyst role. The regeneration is
    audited. Returns the new passphrase.
    """
    inc = await _get_incident(db, incident_id, user)
    inc.oob_passphrase = _generate_passphrase()
    await write_audit(
        db, "oob_passphrase_regenerate",
        user_id=user.id, username=user.username,
        resource_type="incident", resource_id=str(incident_id),
        details={"incident_id": str(incident_id)},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return PassphraseOut(passphrase=inc.oob_passphrase)


@router.patch("/{incident_id}/oob/dark-operation", summary="Toggle dark operation mode")
async def toggle_dark_operation(
    incident_id: uuid.UUID,
    req: DarkOperationUpdate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Enable or disable dark-operation mode on the incident via `enabled`.
    Requires the analyst role. State changes are audited. Returns the current
    `{"dark_operation": bool}`.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.dark_operation != req.enabled:
        inc.dark_operation = req.enabled
        await write_audit(
            db, "dark_operation_enabled" if req.enabled else "dark_operation_disabled",
            user_id=user.id, username=user.username,
            resource_type="incident", resource_id=str(incident_id),
            details={"incident_id": str(incident_id), "enabled": req.enabled},
            ip_address=request.client.host if request.client else None,
        )
        await db.commit()
    return {"dark_operation": inc.dark_operation}


# ═══════════════════════════════════════════════════════════════════════════
# OOB communications log
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/{incident_id}/oob/log", response_model=OOBLogList,
            summary="List out-of-band communications")
async def list_oob_log(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> OOBLogList:
    """List the incident's out-of-band communication log entries, newest first.
    Requires access to the incident. Each entry is enriched with the recording
    user's username.
    """
    await _get_incident(db, incident_id, user)
    rows = (await db.execute(
        select(OOBLog)
        .where(OOBLog.incident_id == incident_id)
        .order_by(OOBLog.created_at.desc())
    )).scalars().all()
    names = await _load_usernames(db, {r.created_by_id for r in rows if r.created_by_id})
    items = [
        OOBLogOut.model_validate(r).model_copy(update={"created_by_username": names.get(r.created_by_id)})
        for r in rows
    ]
    return OOBLogList(items=items)


@router.post("/{incident_id}/oob/log",
             response_model=OOBLogOut,
             status_code=status.HTTP_201_CREATED,
             summary="Log an out-of-band communication")
async def create_oob_log(
    incident_id: uuid.UUID,
    req: OOBLogCreate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> OOBLogOut:
    """Record an out-of-band communication (channel, direction, stakeholder,
    summary, and verification details) on the incident. Requires the analyst
    role. The entry is audited and returned with the recording user's username.
    """
    await _get_incident(db, incident_id, user)

    entry = OOBLog(
        id=uuid.uuid4(),
        incident_id=incident_id,
        stakeholder_name=req.stakeholder_name.strip(),
        channel=req.channel,
        direction=req.direction,
        summary=req.summary.strip(),
        verified=req.verified,
        verification_method=req.verification_method,
        created_by_id=user.id,
    )
    db.add(entry)
    await db.flush()
    await write_audit(
        db, "oob_log_create",
        user_id=user.id, username=user.username,
        resource_type="oob_log", resource_id=str(entry.id),
        details={
            "incident_id":      str(incident_id),
            "channel":          entry.channel,
            "direction":        entry.direction,
            "stakeholder_name": entry.stakeholder_name,
            "verified":         entry.verified,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return OOBLogOut.model_validate(entry).model_copy(update={"created_by_username": user.username})


@router.delete("/{incident_id}/oob/log/{log_id}",
               summary="Delete an out-of-band log entry")
async def delete_oob_log(
    incident_id: uuid.UUID,
    log_id:      uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Delete an out-of-band communication log entry from the incident.
    Requires the analyst role. The deletion is audited. Returns
    `{"status": "ok"}`.
    """
    await _get_incident(db, incident_id, user)

    entry = (await db.execute(
        select(OOBLog).where(OOBLog.id == log_id, OOBLog.incident_id == incident_id)
    )).scalar_one_or_none()
    if not entry:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Log entry not found")

    await write_audit(
        db, "oob_log_delete",
        user_id=user.id, username=user.username,
        resource_type="oob_log", resource_id=str(entry.id),
        details={"incident_id": str(incident_id), "channel": entry.channel},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(entry)
    await db.commit()
    return {"status": "ok"}
