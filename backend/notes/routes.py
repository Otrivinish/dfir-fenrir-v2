"""Per-incident analyst notes: one evolving markdown scratchpad per analyst
per incident (GitHub-README style), separate from the Comments thread.

Mounted at prefix="/api/incidents".

A note marked private (`is_private=True`, the default) is visible only to
its author -- never to other analysts, and never to admins either. The list
query enforces this for every caller, with no admin bypass. Saving is an
upsert: `POST .../notes` creates the caller's note on first save and
updates it on every save after that -- there is at most one row per
(incident, author), enforced by a DB unique constraint. Because of that, an
admin's delete authority (mirroring Comments' author-or-admin rule) only
ever reaches a *non-private* note: a private note owned by someone else is
a 404 for everyone but its author, same as an inaccessible incident, so its
existence isn't leaked. There is no admin edit of someone else's note --
editing another analyst's personal scratchpad for them doesn't fit this
model; moderation is delete-only.

Every save that actually changes something snapshots a NoteVersion, so
history/diff work. Each version carries the note's is_private *at the time
it was saved*, and a non-author viewing another analyst's shared note only
ever sees versions that were themselves non-private when written -- a note
made private after being shared doesn't retroactively hide already-shared
history, but a version that was private when authored stays private even
if the note is shared later.
"""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from incidents.access import get_accessible_incident
from models import Incident, Note, NoteVersion, User
from schemas import NoteCreate, NoteList, NoteOut, NoteVersionList, NoteVersionOut

router = APIRouter()


async def _load_usernames(db: AsyncSession, ids: set) -> dict:
    if not ids:
        return {}
    rows = (await db.execute(
        select(User.id, User.username).where(User.id.in_(ids))
    )).all()
    return {r.id: r.username for r in rows}


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


async def _get_visible_note(db: AsyncSession, incident_id: uuid.UUID, note_id: uuid.UUID, user: User) -> Note:
    """Fetch a note by id, 404ing if it doesn't exist or is a private note
    owned by someone else (existence not leaked, same as an inaccessible
    incident)."""
    n = (await db.execute(
        select(Note).where(Note.id == note_id, Note.incident_id == incident_id)
    )).scalar_one_or_none()
    if not n or (n.is_private and n.author_id != user.id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Note not found")
    return n


@router.get("/{incident_id}/notes", response_model=NoteList, summary="List notes")
async def list_notes(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> NoteList:
    """List notes on an incident -- at most one per analyst. Requires access
    to the incident. Private notes are only included for their own author --
    enforced here, not left to the frontend to hide.
    """
    await _get_incident(db, incident_id, user)
    stmt = (
        select(Note)
        .where(Note.incident_id == incident_id)
        .where(or_(Note.is_private.is_(False), Note.author_id == user.id))
        .order_by(Note.updated_at.desc())
    )
    rows  = (await db.execute(stmt)).scalars().all()
    names = await _load_usernames(db, {r.author_id for r in rows if r.author_id})
    items = [
        NoteOut.model_validate(r).model_copy(update={"author_username": names.get(r.author_id)})
        for r in rows
    ]
    return NoteList(items=items)


@router.post("/{incident_id}/notes", response_model=NoteOut, summary="Save your note")
async def save_note(
    incident_id: uuid.UUID,
    req: NoteCreate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> NoteOut:
    """Create or update the caller's own note on this incident (upsert --
    one per analyst per incident). Requires the analyst role. Rejected if
    the incident is closed. Every actual change snapshots a new
    NoteVersion and records an audit entry (metadata only, never the note
    body).
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    body = req.body.strip()
    n = (await db.execute(
        select(Note).where(Note.incident_id == incident_id, Note.author_id == user.id)
    )).scalar_one_or_none()

    if n is None:
        n = Note(
            id=uuid.uuid4(), incident_id=incident_id, author_id=user.id,
            body=body, is_private=req.is_private, version=1,
        )
        db.add(n)
        await db.flush()
        db.add(NoteVersion(
            id=uuid.uuid4(), note_id=n.id, version_number=1,
            body=n.body, is_private=n.is_private,
        ))
        await write_audit(
            db, "note_create",
            user_id=user.id, username=user.username,
            resource_type="note", resource_id=str(n.id),
            details={"incident_id": str(incident_id), "is_private": n.is_private, "version": n.version},
            ip_address=request.client.host if request.client else None,
        )
    elif body != n.body or req.is_private != n.is_private:
        if n.edited_at is None:
            n.edited_at = datetime.now(timezone.utc)
        n.body = body
        n.is_private = req.is_private
        n.version += 1
        await db.flush()
        db.add(NoteVersion(
            id=uuid.uuid4(), note_id=n.id, version_number=n.version,
            body=n.body, is_private=n.is_private,
        ))
        await write_audit(
            db, "note_update",
            user_id=user.id, username=user.username,
            resource_type="note", resource_id=str(n.id),
            details={"incident_id": str(incident_id), "is_private": n.is_private, "version": n.version},
            ip_address=request.client.host if request.client else None,
        )

    await db.commit()
    return NoteOut.model_validate(n).model_copy(update={"author_username": user.username})


@router.get("/{incident_id}/notes/{note_id}/versions", response_model=NoteVersionList,
            summary="List a note's version history")
async def list_note_versions(
    incident_id: uuid.UUID,
    note_id:     uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> NoteVersionList:
    """List a note's version history, newest first, for diffing in the UI.
    Requires access to the incident and to the note itself (same private-note
    404 as everything else here). A non-author additionally only sees
    versions that were themselves non-private when saved -- a version
    written while the note was private stays private even if the note is
    shared later.
    """
    await _get_incident(db, incident_id, user)
    n = await _get_visible_note(db, incident_id, note_id, user)

    stmt = select(NoteVersion).where(NoteVersion.note_id == note_id)
    if n.author_id != user.id:
        stmt = stmt.where(NoteVersion.is_private.is_(False))
    stmt = stmt.order_by(NoteVersion.version_number.desc())
    rows = (await db.execute(stmt)).scalars().all()
    return NoteVersionList(items=[NoteVersionOut.model_validate(r) for r in rows])


@router.delete("/{incident_id}/notes/{note_id}", summary="Delete a note")
async def delete_note(
    incident_id: uuid.UUID,
    note_id:     uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Delete a note (and its version history). Requires the analyst role;
    only the original author or an admin may delete (a private note not
    owned by the caller 404s, same as everywhere else here). Rejected if
    the incident is closed. The deletion is audited. Returns
    `{"status": "ok"}`.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    n = await _get_visible_note(db, incident_id, note_id, user)
    if n.author_id != user.id and user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not your note")

    await write_audit(
        db, "note_delete",
        user_id=user.id, username=user.username,
        resource_type="note", resource_id=str(n.id),
        details={"incident_id": str(incident_id), "is_private": n.is_private},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(n)
    await db.commit()
    return {"status": "ok"}
