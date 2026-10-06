"""Per-incident entity endpoints + entity relation (graph edge) endpoints."""
import base64
import json
import re
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.config import settings
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from evidence.crypto import EvidenceCryptoError, awrite_encrypted
from evidence.streaming import decrypted_download, require_free_space
from incidents.access import get_accessible_incident
from models import Entity, EntityEvent, EntityFile, EntityRelation, Incident, RecoveryRecord, RespondAction, User, utcnow
from files.routes import decorated_files, delete_file_row, file_references, locked_file, referenced_error, required_reason
from respond.containment import containment_map
from schemas import (Criticality, EntityCreate, EntityEventCreate,
                     EntityEventList, EntityEventOut, EntityFileList, EntityFileOut, FileDelete,
                     EntityList, EntityOut,
                     EntityRelationCreate, EntityRelationList,
                     EntityRelationOut, EntityType, EntityUpdate)

_ENTITY_FILE_MAX_BYTES = 50 * 1024 * 1024  # 50 MB


# Suffixes the stores reserve for their own files (rotation journals, staging, v0 sidecars): a name ending
# with one is neutralised, so a stored file can never be taken for one (G-fix R3-1). Same list in files.
_RESERVED_SUFFIXES = (".keyslot", ".rewrite", ".tmp", ".partial", ".nonce")


def _safe_name(name: str) -> str:
    """Strip path separators and whitespace from filename; a reserved suffix gets a trailing "_"."""
    safe = re.sub(r'[^\w.\-]', '_', Path(name).name)[:200] or "file"
    return safe + "_" if safe.lower().endswith(_RESERVED_SUFFIXES) else safe


def _entity_file_path(entity_id: uuid.UUID, file_id: uuid.UUID, original_name: str) -> str:
    # New names end with a fixed ".enc" (R3-1); rows written before keep their path (readers use the row's).
    return f"entity-files/{entity_id}/{file_id}_{_safe_name(original_name)}.enc"

router = APIRouter()


async def _add_system_event(
    db: AsyncSession,
    entity: Entity,
    title: str,
    actor_id=None,
) -> None:
    """Insert a system event into the entity asset log (same transaction as caller)."""
    ev = EntityEvent(
        id=uuid.uuid4(),
        entity_id=entity.id,
        incident_id=entity.incident_id,
        event_type="system",
        title=title,
        actor_id=actor_id,
    )
    db.add(ev)


# Cursor helpers mirror incidents.routes / iocs.routes — opaque offset-encoded.
# L11, accepted: a row deleted between two page reads makes an offset cursor skip one row; the war room pages by keyset.
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


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


# ─── List ────────────────────────────────────────────────────────────────────

@router.get("/{incident_id}/entities", response_model=EntityList, summary="List entities for an incident")
async def list_entities(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
    type:        Optional[EntityType]  = Query(default=None),
    criticality: Optional[Criticality] = Query(default=None),
    compromised: Optional[bool]        = Query(default=None,
                                               description="true = only compromised entities (the incident's "
                                                           "affected systems); false = only the others"),
    limit:       int                   = Query(default=50, ge=1, le=200),
    cursor:      Optional[str]         = Query(default=None),
) -> EntityList:
    """List entities (hosts, accounts, etc.) for an incident, newest first.

    Supports optional filtering by `type`, `criticality` and `compromised`, plus
    cursor-based pagination via `limit` and `cursor`. Each item includes a `file_count` of
    attached files and its `containment` state from the Respond board (isolated /
    disabled / blocked / pending, or null). Requires an authenticated user with
    access to the incident. Returns a paginated `EntityList` with `items` and
    `next_cursor`.
    """
    await _get_incident(db, incident_id, user)
    offset = _decode_cursor(cursor)

    stmt = (
        select(Entity)
        .where(Entity.incident_id == incident_id)
        .order_by(Entity.added_at.desc(), Entity.id)
    )
    if type:        stmt = stmt.where(Entity.type        == type)
    if criticality: stmt = stmt.where(Entity.criticality == criticality)
    if compromised is not None: stmt = stmt.where(Entity.compromised == compromised)

    stmt = stmt.offset(offset).limit(limit + 1)
    rows = (await db.execute(stmt)).scalars().all()

    has_more = len(rows) > limit
    page     = rows[:limit]

    # Count files per entity in one query.
    entity_ids = [e.id for e in page]
    count_rows = (await db.execute(
        select(EntityFile.entity_id, func.count(EntityFile.id).label("cnt"))
        .where(EntityFile.entity_id.in_(entity_ids))
        .group_by(EntityFile.entity_id)
    )).all() if entity_ids else []
    count_map = {str(r.entity_id): r.cnt for r in count_rows}
    containment = await containment_map(db, RespondAction.entity_id, entity_ids)

    items = [
        EntityOut.model_validate(e).model_copy(update={"file_count": count_map.get(str(e.id), 0),
                                                       "containment": containment.get(e.id)})
        for e in page
    ]
    next_cursor = _encode_cursor(offset + limit) if has_more else None
    return EntityList(items=items, next_cursor=next_cursor)


# ─── Create ──────────────────────────────────────────────────────────────────

@router.post("/{incident_id}/entities",
             response_model=EntityOut,
             status_code=status.HTTP_201_CREATED,
             summary="Create an entity")
async def create_entity(
    incident_id: uuid.UUID,
    req: EntityCreate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> EntityOut:
    """Create a new entity on an incident and record a system event in its asset
    log. `compromised: true` adds it straight to the incident's affected systems.
    Returns 409 if the incident is closed or if an identical entity already
    exists on it. Requires the analyst role and access to the incident. Returns
    the created `EntityOut`.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")

    ent = Entity(
        id=uuid.uuid4(),
        incident_id=incident_id,
        type=req.type,
        value=req.value.strip(),
        name=req.name,
        description=req.description,
        criticality=req.criticality,
        attributes=req.attributes or {},
        compromised=req.compromised,
        added_by_id=user.id,
    )
    db.add(ent)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "This entity already exists on this incident")

    await _add_system_event(db, ent, "Entity added", actor_id=user.id)
    if ent.compromised:
        await _add_system_event(db, ent, "Marked as compromised", actor_id=user.id)
    await write_audit(
        db, "entity_create",
        user_id=user.id, username=user.username,
        resource_type="entity", resource_id=str(ent.id),
        details={"incident_id": str(incident_id), "type": ent.type, "value": ent.value,
                 "compromised": ent.compromised},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return EntityOut.model_validate(ent)


# ─── Update ──────────────────────────────────────────────────────────────────

@router.patch("/{incident_id}/entities/{entity_id}", response_model=EntityOut,
              summary="Update an entity")
async def update_entity(
    incident_id: uuid.UUID,
    entity_id: uuid.UUID,
    req: EntityUpdate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> EntityOut:
    """Partially update an entity's name, description, criticality, compromised
    flag, or attributes. Toggling the compromised flag records a system event in
    the asset log. Returns 409 if the incident is closed and 404 if the entity is
    not found. Requires the analyst role and access to the incident. Returns the
    updated `EntityOut`.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")

    ent = (await db.execute(
        select(Entity).where(Entity.id == entity_id, Entity.incident_id == incident_id)
    )).scalar_one_or_none()
    if not ent:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Entity not found")

    changed: dict[str, object] = {}
    if req.name is not None and req.name != (ent.name or ""):
        ent.name = req.name; changed["name"] = req.name
    if req.description is not None and req.description != (ent.description or ""):
        ent.description = req.description; changed["description"] = req.description
    if req.criticality is not None and req.criticality != ent.criticality:
        ent.criticality = req.criticality; changed["criticality"] = req.criticality
    compromised_changed = req.compromised is not None and req.compromised != ent.compromised
    if compromised_changed:
        ent.compromised = req.compromised; changed["compromised"] = req.compromised
    if req.attributes is not None and req.attributes != (ent.attributes or {}):
        ent.attributes = req.attributes; changed["attributes"] = req.attributes

    if compromised_changed:
        label = "Marked as compromised" if ent.compromised else "Compromised flag cleared"
        await _add_system_event(db, ent, label, actor_id=user.id)

    if changed:
        await write_audit(
            db, "entity_update",
            user_id=user.id, username=user.username,
            resource_type="entity", resource_id=str(ent.id),
            details={"incident_id": str(incident_id), "changes": changed},
            ip_address=request.client.host if request.client else None,
        )
    await db.commit()
    return EntityOut.model_validate(ent)


# ─── Delete ──────────────────────────────────────────────────────────────────

@router.delete("/{incident_id}/entities/{entity_id}", summary="Delete an entity")
async def delete_entity(
    incident_id: uuid.UUID,
    entity_id: uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Delete an entity from an incident. Returns 409 if the incident is closed
    (or 409 recovery_record_exists when the system has a recovery record, I1)
    and 404 if the entity is not found. Requires the analyst role and access to
    the incident. Returns `{"status": "ok"}` on success.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")

    ent = (await db.execute(
        select(Entity).where(Entity.id == entity_id, Entity.incident_id == incident_id)
    )).scalar_one_or_none()
    if not ent:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Entity not found")
    # I1: a recovery record (who restored / validated the system) is never deleted with its entity.
    if (await db.execute(select(RecoveryRecord.id).where(RecoveryRecord.entity_id == ent.id))).first():
        raise ApiError(status.HTTP_409_CONFLICT, "recovery_record_exists",
                       "This system has a recovery record; clear its compromised flag instead of deleting it.")

    await write_audit(
        db, "entity_delete",
        user_id=user.id, username=user.username,
        resource_type="entity", resource_id=str(ent.id),
        details={"incident_id": str(incident_id), "type": ent.type, "value": ent.value},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(ent)
    await db.commit()
    return {"status": "ok"}


# ─── Entity asset log ────────────────────────────────────────────────────────
# Sub-resource: /incidents/{incident_id}/entities/{entity_id}/asset-log
# NOTE: These literal sub-paths register before the parametric entity routes
# so FastAPI resolves them correctly.

@router.get("/{incident_id}/entities/{entity_id}/asset-log",
            response_model=EntityEventList,
            summary="List an entity's asset-log events")
async def list_entity_events(
    incident_id: uuid.UUID,
    entity_id:   uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> EntityEventList:
    """List the asset-log events (notes and system events) for an entity, ordered
    by occurrence time descending. Returns 404 if the entity is not found on the
    incident. Requires an authenticated user with access to the incident. Returns
    an `EntityEventList`.
    """
    await _get_incident(db, incident_id, user)
    ent = (await db.execute(
        select(Entity).where(Entity.id == entity_id, Entity.incident_id == incident_id)
    )).scalar_one_or_none()
    if not ent:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Entity not found")

    rows = (await db.execute(
        select(EntityEvent)
        .where(EntityEvent.entity_id == entity_id)
        .order_by(EntityEvent.occurred_at.desc(), EntityEvent.created_at.desc())
    )).scalars().all()
    return EntityEventList(items=[EntityEventOut.model_validate(r) for r in rows])


@router.post("/{incident_id}/entities/{entity_id}/asset-log",
             response_model=EntityEventOut,
             status_code=status.HTTP_201_CREATED,
             summary="Add a note to an entity's asset log")
async def create_entity_event(
    incident_id: uuid.UUID,
    entity_id:   uuid.UUID,
    req:         EntityEventCreate,
    request:     Request,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> EntityEventOut:
    """Add a note event to an entity's asset log, defaulting `occurred_at` to now
    when not supplied. Returns 409 if the incident is closed and 404 if the
    entity is not found. Requires the analyst role and access to the incident.
    Returns the created `EntityEventOut`.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")

    ent = (await db.execute(
        select(Entity).where(Entity.id == entity_id, Entity.incident_id == incident_id)
    )).scalar_one_or_none()
    if not ent:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Entity not found")

    ev = EntityEvent(
        id=uuid.uuid4(),
        entity_id=entity_id,
        incident_id=incident_id,
        event_type="note",
        title=req.title.strip(),
        body=req.body,
        actor_id=user.id,
        occurred_at=req.occurred_at or utcnow(),
    )
    db.add(ev)
    await db.flush()

    await write_audit(
        db, "entity_event_create",
        user_id=user.id, username=user.username,
        resource_type="entity_event", resource_id=str(ev.id),
        details={"entity_id": str(entity_id), "incident_id": str(incident_id), "title": ev.title},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return EntityEventOut.model_validate(ev)


@router.delete("/{incident_id}/entities/{entity_id}/asset-log/{event_id}",
               summary="Delete an entity asset-log event")
async def delete_entity_event(
    incident_id: uuid.UUID,
    entity_id:   uuid.UUID,
    event_id:    uuid.UUID,
    request:     Request,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> dict:
    """Delete a note event from an entity's asset log. Returns 409 if the
    incident is closed, 404 if the event is not found, and 403 if the event is a
    system event (those cannot be deleted). Requires the analyst role and access
    to the incident. Returns `{"status": "ok"}` on success.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")

    ev = (await db.execute(
        select(EntityEvent).where(
            EntityEvent.id == event_id,
            EntityEvent.entity_id == entity_id,
        )
    )).scalar_one_or_none()
    if not ev:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Event not found")
    if ev.event_type == "system":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "System events cannot be deleted")

    await write_audit(
        db, "entity_event_delete",
        user_id=user.id, username=user.username,
        resource_type="entity_event", resource_id=str(ev.id),
        details={"entity_id": str(entity_id), "incident_id": str(incident_id)},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(ev)
    await db.commit()
    return {"status": "ok"}


# ─── Entity files ────────────────────────────────────────────────────────────

@router.get("/{incident_id}/entities/{entity_id}/files",
            response_model=EntityFileList,
            summary="List an entity's files")
async def list_entity_files(
    incident_id: uuid.UUID,
    entity_id:   uuid.UUID,
    user: User = Depends(current_user),
    db:   AsyncSession = Depends(get_db),
) -> EntityFileList:
    """List the files attached to an entity, oldest upload first. Returns 404 if
    the entity is not found on the incident. Requires an authenticated user with
    access to the incident. Returns an `EntityFileList`.
    """
    await _get_incident(db, incident_id, user)
    ent = (await db.execute(
        select(Entity).where(Entity.id == entity_id, Entity.incident_id == incident_id)
    )).scalar_one_or_none()
    if not ent:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Entity not found")

    rows = (await db.execute(
        select(EntityFile)
        .where(EntityFile.entity_id == entity_id)
        .order_by(EntityFile.uploaded_at.asc())
    )).scalars().all()
    return EntityFileList(items=await decorated_files(db, rows))


@router.post("/{incident_id}/entities/{entity_id}/files",
             response_model=EntityFileOut,
             status_code=status.HTTP_201_CREATED,
             summary="Upload a file to an entity",
             responses={507: {"model": ApiErrorBody, "description": "insufficient_storage (the file store, with its 1 GiB reserve, or the upload scratch space is full; nothing stored)"}})
async def upload_entity_file(
    incident_id: uuid.UUID,
    entity_id:   uuid.UUID,
    request:     Request,
    file:        UploadFile = File(...),
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> EntityFileOut:
    """Upload a file attachment for an entity; the bytes are encrypted at rest and
    hashed by the server in the same pass (SHA-256 / SHA-1 / MD5). Returns 409 if the incident is closed, 404 if the entity is not found, and
    413 if the file exceeds the 50 MB limit. Requires the analyst role and access
    to the incident. Returns the created `EntityFileOut`.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")

    ent = (await db.execute(
        select(Entity).where(Entity.id == entity_id, Entity.incident_id == incident_id)
    )).scalar_one_or_none()
    if not ent:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Entity not found")

    cl = request.headers.get("content-length")
    if cl and int(cl) > _ENTITY_FILE_MAX_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "File exceeds 50 MB limit")

    raw = await file.read()
    if len(raw) > _ENTITY_FILE_MAX_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "File exceeds 50 MB limit")

    file_id       = uuid.uuid4()
    original_name = file.filename or "file"
    rel_path      = _entity_file_path(entity_id, file_id, original_name)

    require_free_space(len(raw), "this file", root=settings.logs_path)       # L2: 507, nothing stored
    stored = await awrite_encrypted(raw, rel_path, root=settings.logs_path)   # FENRGCM v2, staged write

    ef = EntityFile(
        id=file_id,
        entity_id=entity_id,
        incident_id=incident_id,
        original_name=original_name,
        file_size=len(raw),
        content_type=file.content_type,
        file_path=rel_path,
        nonce_hex=stored.nonce_hex,
        sha256=stored.sha256, sha1=stored.sha1, md5=stored.md5,
        uploaded_by_id=user.id,
    )
    db.add(ef)
    await write_audit(
        db, "entity_file_upload",
        user_id=user.id, username=user.username,
        resource_type="entity_file", resource_id=str(file_id),
        details={"entity_id": str(entity_id), "incident_id": str(incident_id),
                 "filename": original_name, "size": len(raw), "sha256": stored.sha256},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return EntityFileOut.model_validate(ef)


@router.get("/{incident_id}/entities/{entity_id}/files/{file_id}/download",
            summary="Download an entity file",
            responses={200: {"description": "The file's bytes, with Content-Length. Over 16 MiB the body is "
                                            "streamed as it is decrypted: if a later part fails its integrity "
                                            "check the server closes the connection before Content-Length bytes "
                                            "are sent; treat a short body as a failed download, never as the file."}})
async def download_entity_file(
    incident_id: uuid.UUID,
    entity_id:   uuid.UUID,
    file_id:     uuid.UUID,
    user: User = Depends(current_user),
    db:   AsyncSession = Depends(get_db),
) -> Response:
    """Download a file attached to an entity, decrypting it on the fly. Returns
    404 if the file record is not found or its data is missing on disk. Requires
    an authenticated user with access to the incident. Returns the decrypted file
    as an attachment Response.

    G2: a file up to 16 MiB is fully decrypted and authenticated before the response starts.
    A larger one streams with bounded memory and Content-Length set; a failure found
    mid-stream aborts the connection (the body is shorter than Content-Length).
    """
    await _get_incident(db, incident_id, user)
    ef = (await db.execute(
        select(EntityFile).where(
            EntityFile.id == file_id,
            EntityFile.entity_id == entity_id,
            EntityFile.incident_id == incident_id,       # H4: only a file of the incident checked above
        )
    )).scalar_one_or_none()
    if not ef:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")

    media_type = ef.content_type or "application/octet-stream"
    safe = _safe_name(ef.original_name)
    try:
        return await decrypted_download(ef.file_path, ef.nonce_hex, ef.file_size, root=settings.logs_path,
                                        media_type=media_type,
                                        headers={"Content-Disposition": f'attachment; filename="{safe}"'})
    except EvidenceCryptoError as e:
        if e.reason == "file_missing":
            raise HTTPException(status.HTTP_404_NOT_FOUND, "File data missing on disk")
        raise


@router.delete("/{incident_id}/entities/{entity_id}/files/{file_id}",
               summary="Delete an entity file",
               responses={409: {"model": ApiErrorBody, "description": "incident_closed, or file_referenced (a record "
                                "relies on the file; `references` lists them)"},
                          422: {"model": ApiErrorBody, "description": "reason_required"}})
async def delete_entity_file(
    incident_id: uuid.UUID,
    entity_id:   uuid.UUID,
    file_id:     uuid.UUID,
    request:     Request,
    body:        Optional[FileDelete] = None,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> dict:
    """Delete a file attached to an entity, removing both its record and its
    on-disk data. Returns 409 if the incident is closed and 404 if the file is
    not found. Requires the analyst role and access to the incident. Returns
    `{"status": "ok"}` on success.

    H4: a reason is required — JSON body `{"reason": "…"}` (10–2000 characters, else 422 code
    reason_required). Refused with 409 code file_referenced while another record relies on the file
    (report figure, saved report, case note, exhibit — as for incident Files; this entity's own
    attachment is what is being removed, so it doesn't count). The audit keeps the reason and hashes.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")

    ef = await locked_file(db, file_id, entity_id=entity_id, incident_id=incident_id)
    if not ef:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")
    why = required_reason(body.reason if body else None, "delete a file")
    refs = await file_references(db, ef, via_entity=True)
    if refs:
        raise referenced_error(refs)
    await delete_file_row(db, ef, why=why, user=user, request=request, action="entity_file_delete",
                          resource_type="entity_file",
                          details={"entity_id": str(entity_id), "incident_id": str(incident_id)})
    return {"status": "ok"}


# ─── Entity relations (graph edges) ──────────────────────────────────────────

@router.get("/{incident_id}/entity-relations", response_model=EntityRelationList,
            summary="List entity relations")
async def list_entity_relations(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> EntityRelationList:
    """List the entity relations (graph edges) for an incident, ordered by
    creation time. Requires an authenticated user with access to the incident.
    Returns an `EntityRelationList`.
    """
    await _get_incident(db, incident_id, user)
    rows = (await db.execute(
        select(EntityRelation)
        .where(EntityRelation.incident_id == incident_id)
        .order_by(EntityRelation.created_at)
    )).scalars().all()
    return EntityRelationList(items=[EntityRelationOut.model_validate(r) for r in rows])


@router.post("/{incident_id}/entity-relations",
             response_model=EntityRelationOut,
             status_code=status.HTTP_201_CREATED,
             summary="Create an entity relation")
async def create_entity_relation(
    incident_id: uuid.UUID,
    req: EntityRelationCreate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> EntityRelationOut:
    """Create a directed relation (graph edge) between two entities on an
    incident. Returns 409 if the incident is closed or the relation already
    exists, 422 if an entity relates to itself, and 404 if either entity is not
    on the incident. Requires the analyst role and access to the incident.
    Returns the created `EntityRelationOut`.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")
    if req.from_entity_id == req.to_entity_id:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "An entity cannot relate to itself")

    # Verify both entities belong to this incident.
    for eid in (req.from_entity_id, req.to_entity_id):
        exists = (await db.execute(
            select(Entity.id).where(Entity.id == eid, Entity.incident_id == incident_id)
        )).scalar_one_or_none()
        if not exists:
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                f"Entity {eid} not found on this incident")

    rel = EntityRelation(
        id=uuid.uuid4(),
        incident_id=incident_id,
        from_entity_id=req.from_entity_id,
        to_entity_id=req.to_entity_id,
        relationship_type=req.relationship_type.strip(),
        notes=req.notes,
        created_by_id=user.id,
    )
    db.add(rel)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "This relationship already exists")

    await write_audit(
        db, "entity_relation_create",
        user_id=user.id, username=user.username,
        resource_type="entity_relation", resource_id=str(rel.id),
        details={
            "incident_id": str(incident_id),
            "from": str(req.from_entity_id),
            "to": str(req.to_entity_id),
            "type": rel.relationship_type,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return EntityRelationOut.model_validate(rel)


@router.delete("/{incident_id}/entity-relations/{relation_id}",
               summary="Delete an entity relation")
async def delete_entity_relation(
    incident_id: uuid.UUID,
    relation_id: uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Delete an entity relation (graph edge) from an incident. Returns 409 if
    the incident is closed and 404 if the relation is not found. Requires the
    analyst role and access to the incident. Returns `{"status": "ok"}` on
    success.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")

    rel = (await db.execute(
        select(EntityRelation).where(
            EntityRelation.id == relation_id,
            EntityRelation.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not rel:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Relation not found")

    await write_audit(
        db, "entity_relation_delete",
        user_id=user.id, username=user.username,
        resource_type="entity_relation", resource_id=str(rel.id),
        details={
            "incident_id": str(incident_id),
            "from": str(rel.from_entity_id),
            "to": str(rel.to_entity_id),
            "type": rel.relationship_type,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(rel)
    await db.commit()
    return {"status": "ok"}
