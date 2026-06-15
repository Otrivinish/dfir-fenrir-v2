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
from evidence.crypto import adecrypt_file_bytes, aencrypt_file_bytes
from incidents.access import get_accessible_incident
from models import Entity, EntityEvent, EntityFile, EntityRelation, Incident, User, utcnow
from schemas import (Criticality, EntityCreate, EntityEventCreate,
                     EntityEventList, EntityEventOut, EntityFileList, EntityFileOut,
                     EntityList, EntityOut,
                     EntityRelationCreate, EntityRelationList,
                     EntityRelationOut, EntityType, EntityUpdate)

_ENTITY_FILE_MAX_BYTES = 50 * 1024 * 1024  # 50 MB


def _safe_name(name: str) -> str:
    """Strip path separators and whitespace from filename."""
    return re.sub(r'[^\w.\-]', '_', Path(name).name)[:200] or "file"


def _entity_file_path(entity_id: uuid.UUID, file_id: uuid.UUID, original_name: str) -> str:
    return f"entity-files/{entity_id}/{file_id}_{_safe_name(original_name)}"

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
    limit:       int                   = Query(default=50, ge=1, le=200),
    cursor:      Optional[str]         = Query(default=None),
) -> EntityList:
    """List entities (hosts, accounts, etc.) for an incident, newest first.

    Supports optional filtering by `type` and `criticality`, plus cursor-based
    pagination via `limit` and `cursor`. Each item includes a `file_count` of
    attached files. Requires an authenticated user with access to the incident.
    Returns a paginated `EntityList` with `items` and `next_cursor`.
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

    items = [
        EntityOut.model_validate(e).model_copy(update={"file_count": count_map.get(str(e.id), 0)})
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
    log. Returns 409 if the incident is closed or if an identical entity already
    exists on it. Requires the analyst role and access to the incident. Returns
    the created `EntityOut`.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    ent = Entity(
        id=uuid.uuid4(),
        incident_id=incident_id,
        type=req.type,
        value=req.value.strip(),
        name=req.name,
        description=req.description,
        criticality=req.criticality,
        attributes=req.attributes or {},
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
    await write_audit(
        db, "entity_create",
        user_id=user.id, username=user.username,
        resource_type="entity", resource_id=str(ent.id),
        details={"incident_id": str(incident_id), "type": ent.type, "value": ent.value},
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
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

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
    and 404 if the entity is not found. Requires the analyst role and access to
    the incident. Returns `{"status": "ok"}` on success.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    ent = (await db.execute(
        select(Entity).where(Entity.id == entity_id, Entity.incident_id == incident_id)
    )).scalar_one_or_none()
    if not ent:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Entity not found")

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
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

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
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

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
    return EntityFileList(items=[EntityFileOut.model_validate(r) for r in rows])


@router.post("/{incident_id}/entities/{entity_id}/files",
             response_model=EntityFileOut,
             status_code=status.HTTP_201_CREATED,
             summary="Upload a file to an entity")
async def upload_entity_file(
    incident_id: uuid.UUID,
    entity_id:   uuid.UUID,
    request:     Request,
    file:        UploadFile = File(...),
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> EntityFileOut:
    """Upload a file attachment for an entity; the bytes are encrypted at rest.
    Returns 409 if the incident is closed, 404 if the entity is not found, and
    413 if the file exceeds the 50 MB limit. Requires the analyst role and access
    to the incident. Returns the created `EntityFileOut`.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

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

    ct, nonce_hex = await aencrypt_file_bytes(raw)
    dest = Path(settings.logs_path) / rel_path
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(ct)

    ef = EntityFile(
        id=file_id,
        entity_id=entity_id,
        incident_id=incident_id,
        original_name=original_name,
        file_size=len(raw),
        content_type=file.content_type,
        file_path=rel_path,
        nonce_hex=nonce_hex,
        uploaded_by_id=user.id,
    )
    db.add(ef)
    await write_audit(
        db, "entity_file_upload",
        user_id=user.id, username=user.username,
        resource_type="entity_file", resource_id=str(file_id),
        details={"entity_id": str(entity_id), "incident_id": str(incident_id),
                 "filename": original_name, "size": len(raw)},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return EntityFileOut.model_validate(ef)


@router.get("/{incident_id}/entities/{entity_id}/files/{file_id}/download",
            summary="Download an entity file")
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
    """
    await _get_incident(db, incident_id, user)
    ef = (await db.execute(
        select(EntityFile).where(
            EntityFile.id == file_id,
            EntityFile.entity_id == entity_id,
        )
    )).scalar_one_or_none()
    if not ef:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")

    path = Path(settings.logs_path) / ef.file_path
    if not path.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File data missing on disk")

    plaintext = await adecrypt_file_bytes(path.read_bytes(), ef.nonce_hex)
    media_type = ef.content_type or "application/octet-stream"
    safe = _safe_name(ef.original_name)
    return Response(
        content=plaintext,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{safe}"'},
    )


@router.delete("/{incident_id}/entities/{entity_id}/files/{file_id}",
               summary="Delete an entity file")
async def delete_entity_file(
    incident_id: uuid.UUID,
    entity_id:   uuid.UUID,
    file_id:     uuid.UUID,
    request:     Request,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> dict:
    """Delete a file attached to an entity, removing both its record and its
    on-disk data. Returns 409 if the incident is closed and 404 if the file is
    not found. Requires the analyst role and access to the incident. Returns
    `{"status": "ok"}` on success.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    ef = (await db.execute(
        select(EntityFile).where(
            EntityFile.id == file_id,
            EntityFile.entity_id == entity_id,
        )
    )).scalar_one_or_none()
    if not ef:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")

    path = Path(settings.logs_path) / ef.file_path
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass

    await write_audit(
        db, "entity_file_delete",
        user_id=user.id, username=user.username,
        resource_type="entity_file", resource_id=str(file_id),
        details={"entity_id": str(entity_id), "incident_id": str(incident_id),
                 "filename": ef.original_name},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(ef)
    await db.commit()
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
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
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
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

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
