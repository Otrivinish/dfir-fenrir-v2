"""Per-incident analyst notes: one evolving markdown scratchpad per analyst
per incident (GitHub-README style), separate from the Comments thread.

Mounted at prefix="/api/incidents".

LEGACY, READ-ONLY since H2 (owner decision 2026-10-03): shared, append-only case
notes (case_notes/routes.py) replace the scratchpad. Saving returns 410
use_case_notes and deleting returns 410 scratchpad_read_only, so existing text can
no longer be changed or destroyed. Nothing is published automatically: a private
scratchpad stays visible to its author only, who can post it as a case note
(`POST .../case-notes` with `source_scratchpad_id`). Reads and version history
below are unchanged. The rest of this docstring describes the rules as built.

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

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import current_user, require_analyst
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from incidents.access import get_accessible_incident
from models import Incident, Note, NoteVersion, User
from schemas import NoteList, NoteOut, NoteVersionList, NoteVersionOut

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


@router.post("/{incident_id}/notes", status_code=status.HTTP_410_GONE, deprecated=True,
             summary="Save your note (retired: use case notes)",
             responses={410: {"model": ApiErrorBody, "description": "use_case_notes"}})
async def save_note(
    incident_id: uuid.UUID,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Retired by H2: always 410 use_case_notes (after the access check). Add a shared,
    append-only entry with `POST /api/incidents/{id}/case-notes` instead; post your existing
    scratchpad there with `source_scratchpad_id`."""
    await _get_incident(db, incident_id, user)
    raise ApiError(status.HTTP_410_GONE, "use_case_notes",
                   "The private scratchpad is read-only. Add a case note instead "
                   "(POST /api/incidents/{id}/case-notes).")


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


@router.delete("/{incident_id}/notes/{note_id}", status_code=status.HTTP_410_GONE, deprecated=True,
               summary="Delete a note (retired)",
               responses={410: {"model": ApiErrorBody, "description": "scratchpad_read_only"}})
async def delete_note(
    incident_id: uuid.UUID,
    note_id:     uuid.UUID,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Retired by H2: legacy scratchpads can no longer be destroyed. 404 when the note isn't
    visible to the caller, else always 410 scratchpad_read_only."""
    await _get_incident(db, incident_id, user)
    await _get_visible_note(db, incident_id, note_id, user)
    raise ApiError(status.HTTP_410_GONE, "scratchpad_read_only",
                   "Scratchpads are read-only legacy records and can't be deleted.")
