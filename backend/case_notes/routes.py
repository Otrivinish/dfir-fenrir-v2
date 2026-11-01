"""Case notes (H2, R05): shared, append-only contemporaneous notes per incident.

Mounted at prefix="/api/incidents".

Everyone who can see the incident reads every entry; analysts and admins add entries. A stored
entry is never changed or deleted -- the DB refuses it (trigger, core/database.py). Editing a note
(CN-2) adds a new entry with `corrects_id` = the note's current revision: a note is the chain of its
revisions (case_notes/chain.py), and only its author (of revision 1) or an admin may edit it. Each
CN-2 entry is signed at save time (`signed_name`, `signed_as`, hashed: `hash_v` 2).
`created_at` is server time. Each entry's `content_sha256` (canonical form below) is stored on
the row and in its `case_note_create` audit row, which the hash chain protects. On a closed
incident new entries are refused (409 incident_closed), as comments are (R73).

These replace the private scratchpad (notes/routes.py, now read-only legacy): its author can
post a scratchpad's text as a case note (`source_scratchpad_id`); nothing is published for them.
"""
import base64
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import select, tuple_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from audit.service import write_audit
from case_notes.chain import chain_cte, revision_meta
from case_notes.hashing import content_sha256
from auth.deps import current_user, require_analyst
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from incidents.access import get_accessible_incident, held_role_keys
from models import IOC, CaseNote, Entity, Evidence, Note, TimelineEvent, User
from schemas import CaseNoteCreate, CaseNoteList, CaseNoteOut

router = APIRouter()

# (request/row field, model, label) -- every link must be a row of the same incident.
_LINKS = (
    ("evidence_ids", Evidence, "exhibit"),
    ("entity_ids", Entity, "entity"),
    ("ioc_ids", IOC, "IOC"),
    ("timeline_event_ids", TimelineEvent, "timeline event"),
)


def _encode_cursor(**key) -> str:
    raw = json.dumps(key).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(cursor: str, mode: str) -> dict:
    """The cursor's key; it must come from a list of the same kind (`mode`). A pre-CN-2 cursor has no
    mode and is an "all" one."""
    try:
        d = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode())
        if d.pop("m", "all") != mode:
            raise ValueError(mode)
        return d
    except Exception:
        raise ApiError(status.HTTP_400_BAD_REQUEST, "invalid_cursor", "Invalid cursor")


async def _out(db: AsyncSession, incident_id: uuid.UUID, rows: list[CaseNote]) -> list[CaseNoteOut]:
    """Rows with author usernames, `corrected_by_id`, `root_id`, `revision` and the note's author filled in."""
    if not rows:
        return []
    ids = [r.id for r in rows]
    fixes = dict((await db.execute(
        select(CaseNote.corrects_id, CaseNote.id).where(CaseNote.corrects_id.in_(ids))
    )).all())
    meta = await revision_meta(db, incident_id, ids)
    names = dict((await db.execute(
        select(User.id, User.username).where(User.id.in_({r.author_id for r in rows} | {m[2] for m in meta.values()}))
    )).all())
    return [CaseNoteOut.model_validate(r).model_copy(
        update={"author_username": names.get(r.author_id), "corrected_by_id": fixes.get(r.id),
                "root_id": meta[r.id][0], "revision": meta[r.id][1],
                "root_author_id": meta[r.id][2], "root_author_username": names.get(meta[r.id][2])}) for r in rows]


_ERRORS = {
    400: {"model": ApiErrorBody, "description": "invalid_cursor"},
}
_WRITE_ERRORS = {
    403: {"model": ApiErrorBody, "description": "not_author: only the note's author (of revision 1) or an "
                                                "admin may edit it; only its author may post a scratchpad"},
    404: {"model": ApiErrorBody, "description": "scratchpad_not_found"},
    409: {"model": ApiErrorBody, "description": "incident_closed, or already_corrected (with corrected_by_id): "
                                                "corrects_id is no longer the note's current revision"},
    422: {"model": ApiErrorBody, "description": "invalid_link (with field, ids), or invalid_correction"},
}


@router.get("/{incident_id}/case-notes", response_model=CaseNoteList, summary="List case notes",
            responses=_ERRORS)
async def list_case_notes(
    incident_id: uuid.UUID,
    author_id: Optional[uuid.UUID] = Query(default=None, description="Only entries by this user"),
    evidence_id: Optional[uuid.UUID] = Query(default=None, description="Only entries linked to this exhibit"),
    entity_id: Optional[uuid.UUID] = Query(default=None, description="Only entries linked to this entity"),
    ioc_id: Optional[uuid.UUID] = Query(default=None, description="Only entries linked to this IOC"),
    timeline_event_id: Optional[uuid.UUID] = Query(default=None, description="Only entries linked to this event"),
    current: bool = Query(default=False, description="Only each note's current revision, in the order the notes "
                                                     "were first written"),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> CaseNoteList:
    """List an incident's case notes (keyset-paged: pass `next_cursor` as `cursor`). Default: every
    entry (every revision), oldest first. `current=true`: one item per note -- its current revision --
    ordered by when the note was first written, so an edited note keeps its place. Any role with
    access to the incident (404 otherwise). Filters combine with AND and match the listed entry itself
    (with current=true: the current revision's signer and links). Each item carries `root_id`, `revision`, `corrected_by_id` (the next revision,
    if any), its signature (`signed_name`, `signed_as`) and `content_sha256`."""
    await get_accessible_incident(db, incident_id, user)
    stmt = select(CaseNote).where(CaseNote.incident_id == incident_id)
    if author_id:
        stmt = stmt.where(CaseNote.author_id == author_id)
    for value, col in ((evidence_id, CaseNote.evidence_ids), (entity_id, CaseNote.entity_ids),
                       (ioc_id, CaseNote.ioc_ids), (timeline_event_id, CaseNote.timeline_event_ids)):
        if value:
            stmt = stmt.where(col.contains([value]))
    if current:
        chain, root, succ = chain_cte(incident_id), aliased(CaseNote), aliased(CaseNote)
        stmt = (stmt.join(chain, chain.c.id == CaseNote.id).join(root, root.id == chain.c.root_id)
                .where(~select(succ.id).where(succ.corrects_id == CaseNote.id).exists()))
        key = (root.created_at, root.id)
    else:
        key = (CaseNote.created_at, CaseNote.id)
    mode = "current" if current else "all"
    if cursor:
        k = _decode_cursor(cursor, mode)
        try:
            t, i = datetime.fromisoformat(k["t"]), uuid.UUID(k["i"])
        except Exception:
            raise ApiError(status.HTTP_400_BAD_REQUEST, "invalid_cursor", "Invalid cursor")
        stmt = stmt.where(tuple_(*key) > tuple_(t, i))
    found = (await db.execute(stmt.add_columns(*key).order_by(*key).limit(limit + 1))).all()
    more = len(found) > limit
    found = found[:limit]
    nxt = _encode_cursor(m=mode, t=found[-1][1].isoformat(), i=str(found[-1][2])) if more else None
    return CaseNoteList(items=await _out(db, incident_id, [r for r, _, _ in found]), next_cursor=nxt)


@router.get("/{incident_id}/case-notes/{note_id}", response_model=CaseNoteOut, summary="Get a case note",
            responses={404: {"model": ApiErrorBody, "description": "case_note_not_found"}})
async def get_case_note(
    incident_id: uuid.UUID,
    note_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> CaseNoteOut:
    """One case-note entry (one revision). Any role with access to the incident."""
    await get_accessible_incident(db, incident_id, user)
    n = (await db.execute(
        select(CaseNote).where(CaseNote.id == note_id, CaseNote.incident_id == incident_id)
    )).scalar_one_or_none()
    if n is None:
        raise ApiError(status.HTTP_404_NOT_FOUND, "case_note_not_found", "Case note not found")
    return (await _out(db, incident_id, [n]))[0]


@router.get("/{incident_id}/case-notes/{note_id}/revisions", response_model=CaseNoteList,
            summary="List a case note's revisions",
            responses={**_ERRORS, 404: {"model": ApiErrorBody, "description": "case_note_not_found"}})
async def list_case_note_revisions(
    incident_id: uuid.UUID,
    note_id: uuid.UUID,
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> CaseNoteList:
    """Every revision of the note that entry `note_id` belongs to (any revision's id works), revision 1
    first (keyset-paged). Each is signed by whoever saved it. Any role with access to the incident."""
    await get_accessible_incident(db, incident_id, user)
    meta = await revision_meta(db, incident_id, [note_id])
    if note_id not in meta:
        raise ApiError(status.HTTP_404_NOT_FOUND, "case_note_not_found", "Case note not found")
    chain = chain_cte(incident_id)
    stmt = (select(CaseNote, chain.c.revision).join(chain, chain.c.id == CaseNote.id)
            .where(chain.c.root_id == meta[note_id][0]))
    if cursor:
        try:
            after = int(_decode_cursor(cursor, "revisions")["r"])
        except (KeyError, TypeError, ValueError):
            raise ApiError(status.HTTP_400_BAD_REQUEST, "invalid_cursor", "Invalid cursor")
        stmt = stmt.where(chain.c.revision > after)
    found = (await db.execute(stmt.order_by(chain.c.revision).limit(limit + 1))).all()
    more = len(found) > limit
    found = found[:limit]
    return CaseNoteList(items=await _out(db, incident_id, [r for r, _ in found]),
                        next_cursor=_encode_cursor(m="revisions", r=found[-1][1]) if more else None)


@router.post("/{incident_id}/case-notes", response_model=CaseNoteOut, status_code=status.HTTP_201_CREATED,
             summary="Add a case note", responses=_WRITE_ERRORS)
async def create_case_note(
    incident_id: uuid.UUID,
    req: CaseNoteCreate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> CaseNoteOut:
    """Add a note, or edit one (analyst or admin; 409 incident_closed on a closed incident). Links must
    be rows of this incident (422 invalid_link). To edit, set `corrects_id` to the note's current
    revision (an entry of this incident, else 422 invalid_correction) and send the full new body and
    links: the entry becomes the next revision. Only the note's author (of revision 1) or an admin may
    edit it (403 not_author); a revision that is no longer current gives 409 already_corrected with
    the newer `corrected_by_id` (someone saved first). `source_scratchpad_id`: your own legacy
    scratchpad, whose text becomes the body (404 scratchpad_not_found, 403 not_author). The entry is
    signed (`signed_name`, `signed_as`, in its hash) and its hash is audited (`case_note_create`,
    never the body)."""
    inc = await get_accessible_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")

    links: dict[str, list[uuid.UUID]] = {}
    for field, model, label in _LINKS:
        ids = sorted(set(getattr(req, field)), key=str)
        if ids:
            found = set((await db.execute(
                select(model.id).where(model.id.in_(ids), model.incident_id == incident_id)
            )).scalars().all())
            missing = [str(i) for i in ids if i not in found]
            if missing:
                raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_link",
                               f"{len(missing)} linked {label}(s) not found in this incident.",
                               extra={"field": field, "ids": missing})
        links[field] = ids

    if req.corrects_id:
        orig = (await db.execute(
            select(CaseNote).where(CaseNote.id == req.corrects_id, CaseNote.incident_id == incident_id)
        )).scalar_one_or_none()
        if orig is None:
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_correction",
                           "corrects_id is not a case note of this incident.")
        owner = (await revision_meta(db, incident_id, [orig.id]))[orig.id][2]
        if owner != user.id and user.role != "admin":
            raise ApiError(status.HTTP_403_FORBIDDEN, "not_author",
                           "Only the note's author (or an admin) can edit it.")
        fixed_by = (await db.execute(
            select(CaseNote.id).where(CaseNote.corrects_id == orig.id)
        )).scalar_one_or_none()
        if fixed_by:
            raise ApiError(status.HTTP_409_CONFLICT, "already_corrected",
                           "This is no longer the note's current revision; edit the current one instead.",
                           extra={"corrected_by_id": str(fixed_by)})

    body = req.body.strip() if req.body is not None else None
    if req.source_scratchpad_id:
        sp = (await db.execute(
            select(Note).where(Note.id == req.source_scratchpad_id, Note.incident_id == incident_id)
        )).scalar_one_or_none()
        if sp is None or (sp.is_private and sp.author_id != user.id):
            raise ApiError(status.HTTP_404_NOT_FOUND, "scratchpad_not_found", "Scratchpad not found")
        if sp.author_id != user.id:
            raise ApiError(status.HTTP_403_FORBIDDEN, "not_author",
                           "Only its author can post a scratchpad as a case note.")
        body = sp.body

    n = CaseNote(id=uuid.uuid4(), incident_id=incident_id, author_id=user.id,
                 created_at=datetime.now(timezone.utc), body=body, corrects_id=req.corrects_id,
                 source_scratchpad_id=req.source_scratchpad_id, **links,
                 signed_name=(user.full_name or "").strip() or user.username,
                 signed_as=",".join(await held_role_keys(db, user, inc)) or user.role, hash_v=2)
    n.content_sha256 = content_sha256(n)
    db.add(n)
    try:
        await db.flush()
    except IntegrityError:   # a concurrent edit of the same revision won (uq_case_notes_corrects_id)
        await db.rollback()
        raise ApiError(status.HTTP_409_CONFLICT, "already_corrected",
                       "This is no longer the note's current revision; edit the current one instead.")
    out = (await _out(db, incident_id, [n]))[0]
    await write_audit(
        db, "case_note_create",
        user_id=user.id, username=user.username,
        resource_type="case_note", resource_id=str(n.id),
        details={"incident_id": str(incident_id), "content_sha256": n.content_sha256, "hash_v": n.hash_v,
                 "root_id": str(out.root_id), "revision": out.revision, "signed_as": n.signed_as,
                 "corrects_id": str(n.corrects_id) if n.corrects_id else None,
                 "source_scratchpad_id": str(n.source_scratchpad_id) if n.source_scratchpad_id else None,
                 "body_chars": len(n.body),
                 "links": {f: [str(x) for x in links[f]] for f in links if links[f]}},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return out
