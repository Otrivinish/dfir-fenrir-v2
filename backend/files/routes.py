"""Incident-level file store ("Files").

A lightweight working-file area for NON-malicious supporting material —
screenshots, raw logs, exported notes. Distinct from Evidence (chain of custody)
and Artifacts (quarantined malicious files): no CoC, no AV/sandbox.

Physically this is the same store as entity files (the `entity_files` table +
the AES-256-GCM-encrypted `/asset_logs` directory). A file may be incident-level
(no entity) or linked to an entity; the entity drawer shows the per-entity
subset, this router shows the whole incident.

Mounted at prefix="/api/incidents".
"""
import re
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.config import settings
from core.database import get_db
from evidence.crypto import adecrypt_file_bytes, aencrypt_file_bytes
from incidents.access import get_accessible_incident
from models import Entity, EntityFile, Incident, User
from schemas import EntityFileList, EntityFileOut, IncidentFileUpdate

router = APIRouter()

_FILE_MAX_BYTES = 50 * 1024 * 1024  # 50 MB — mirrors the entity-file limit


def _safe_name(name: str) -> str:
    """Strip path separators and unsafe chars from a filename."""
    return re.sub(r'[^\w.\-]', '_', Path(name).name)[:200] or "file"


def _incident_file_path(incident_id: uuid.UUID, file_id: uuid.UUID, original_name: str) -> Path:
    return Path("files") / str(incident_id) / f"{file_id}_{_safe_name(original_name)}"


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


async def _username_map(db: AsyncSession, user_ids) -> dict[uuid.UUID, str]:
    ids = {i for i in user_ids if i}
    if not ids:
        return {}
    rows = (await db.execute(select(User.id, User.username).where(User.id.in_(ids)))).all()
    return {uid: uname for uid, uname in rows}


async def _entity_name_map(db: AsyncSession, entity_ids) -> dict[uuid.UUID, str]:
    ids = {i for i in entity_ids if i}
    if not ids:
        return {}
    rows = (await db.execute(
        select(Entity.id, Entity.name, Entity.value).where(Entity.id.in_(ids))
    )).all()
    return {eid: (name or value) for eid, name, value in rows}


def _decorate(out: EntityFileOut, umap: dict, emap: dict) -> EntityFileOut:
    out.uploaded_by_username = umap.get(out.uploaded_by_id)
    out.entity_name = emap.get(out.entity_id) if out.entity_id else None
    return out


# ─── List ──────────────────────────────────────────────────────────────────────

@router.get("/{incident_id}/files", response_model=EntityFileList,
            summary="List all files stored for an incident")
async def list_incident_files(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db:   AsyncSession = Depends(get_db),
) -> EntityFileList:
    """List every file in the incident's store (entity-linked or not), newest first.

    Each item carries the uploader's username and the linked entity's name for
    display. Requires an authenticated user with access to the incident.
    """
    await _get_incident(db, incident_id, user)
    rows = (await db.execute(
        select(EntityFile)
        .where(EntityFile.incident_id == incident_id)
        .order_by(EntityFile.uploaded_at.desc())
    )).scalars().all()

    umap = await _username_map(db, [r.uploaded_by_id for r in rows])
    emap = await _entity_name_map(db, [r.entity_id for r in rows])
    items = [_decorate(EntityFileOut.model_validate(r), umap, emap) for r in rows]
    return EntityFileList(items=items)


# ─── Upload ──────────────────────────────────────────────────────────────────

@router.post("/{incident_id}/files", response_model=EntityFileOut,
             status_code=status.HTTP_201_CREATED,
             summary="Upload a file to the incident store")
async def upload_incident_file(
    incident_id: uuid.UUID,
    request:     Request,
    file:        UploadFile = File(...),
    entity_id:   Optional[uuid.UUID] = Form(default=None),
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> EntityFileOut:
    """Upload a non-malicious supporting file; bytes are encrypted at rest.

    Optionally link it to an entity via `entity_id` (must belong to the incident).
    Returns 409 if the incident is closed, 404 if the entity is unknown, and 413
    over the 50 MB limit. Requires the analyst role and access to the incident.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    if entity_id is not None:
        ent = (await db.execute(
            select(Entity).where(Entity.id == entity_id, Entity.incident_id == incident_id)
        )).scalar_one_or_none()
        if not ent:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Entity not found")

    cl = request.headers.get("content-length")
    if cl and int(cl) > _FILE_MAX_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "File exceeds 50 MB limit")

    raw = await file.read()
    if len(raw) > _FILE_MAX_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "File exceeds 50 MB limit")

    file_id       = uuid.uuid4()
    original_name = file.filename or "file"
    rel_path      = _incident_file_path(incident_id, file_id, original_name)

    ct, nonce_hex = await aencrypt_file_bytes(raw)
    # Defense-in-depth: confine the write to the store root (path traversal guard).
    base_dir = Path(settings.logs_path).resolve()
    dest = (base_dir / rel_path).resolve()
    try:
        safe_rel_path = dest.relative_to(base_dir).as_posix()
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid file path")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(ct)

    ef = EntityFile(
        id=file_id,
        entity_id=entity_id,
        incident_id=incident_id,
        original_name=original_name,
        file_size=len(raw),
        content_type=file.content_type,
        file_path=safe_rel_path,
        nonce_hex=nonce_hex,
        uploaded_by_id=user.id,
    )
    db.add(ef)
    await write_audit(
        db, "file_upload",
        user_id=user.id, username=user.username,
        resource_type="incident_file", resource_id=str(file_id),
        details={"incident_id": str(incident_id), "entity_id": str(entity_id) if entity_id else None,
                 "filename": original_name, "size": len(raw)},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    out = EntityFileOut.model_validate(ef)
    out.uploaded_by_username = user.username
    if entity_id:
        emap = await _entity_name_map(db, [entity_id])
        out.entity_name = emap.get(entity_id)
    return out


# ─── Download ──────────────────────────────────────────────────────────────────

@router.get("/{incident_id}/files/{file_id}/download", summary="Download a stored file")
async def download_incident_file(
    incident_id: uuid.UUID,
    file_id:     uuid.UUID,
    user: User = Depends(current_user),
    db:   AsyncSession = Depends(get_db),
) -> Response:
    """Download a stored file, decrypting it on the fly. Returns 404 if the record
    is missing or its data is absent on disk. Requires access to the incident."""
    await _get_incident(db, incident_id, user)
    ef = (await db.execute(
        select(EntityFile).where(EntityFile.id == file_id, EntityFile.incident_id == incident_id)
    )).scalar_one_or_none()
    if not ef:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")

    base_dir = Path(settings.logs_path).resolve()
    path = (base_dir / ef.file_path).resolve()
    try:
        path.relative_to(base_dir)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid file path")
    if not path.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File data missing on disk")

    plaintext = await adecrypt_file_bytes(path.read_bytes(), ef.nonce_hex)
    return Response(
        content=plaintext,
        media_type=ef.content_type or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{_safe_name(ef.original_name)}"'},
    )


# ─── Update (rename / link-unlink entity) ──────────────────────────────────────

@router.patch("/{incident_id}/files/{file_id}", response_model=EntityFileOut,
              summary="Rename a file or (un)link it to an entity")
async def update_incident_file(
    incident_id: uuid.UUID,
    file_id:     uuid.UUID,
    req:         IncidentFileUpdate,
    request:     Request,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> EntityFileOut:
    """Rename a stored file and/or (un)link it to an entity. `entity_id` is
    tri-state — an explicit null unlinks. Returns 409 if the incident is closed,
    404 if the file or target entity is unknown. Requires the analyst role."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    ef = (await db.execute(
        select(EntityFile).where(EntityFile.id == file_id, EntityFile.incident_id == incident_id)
    )).scalar_one_or_none()
    if not ef:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")

    changed: dict[str, object] = {}
    if req.original_name is not None and req.original_name.strip() and req.original_name != ef.original_name:
        ef.original_name = req.original_name.strip()
        changed["original_name"] = ef.original_name
    if "entity_id" in req.model_fields_set and req.entity_id != ef.entity_id:
        if req.entity_id is not None:
            ent = (await db.execute(
                select(Entity).where(Entity.id == req.entity_id, Entity.incident_id == incident_id)
            )).scalar_one_or_none()
            if not ent:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Entity not found")
        ef.entity_id = req.entity_id
        changed["entity_id"] = str(req.entity_id) if req.entity_id else None

    if changed:
        await write_audit(
            db, "file_update",
            user_id=user.id, username=user.username,
            resource_type="incident_file", resource_id=str(file_id),
            details={"incident_id": str(incident_id), "changes": changed},
            ip_address=request.client.host if request.client else None,
        )
    await db.commit()

    out = EntityFileOut.model_validate(ef)
    umap = await _username_map(db, [ef.uploaded_by_id])
    emap = await _entity_name_map(db, [ef.entity_id])
    return _decorate(out, umap, emap)


# ─── Delete ──────────────────────────────────────────────────────────────────

@router.delete("/{incident_id}/files/{file_id}", summary="Delete a stored file")
async def delete_incident_file(
    incident_id: uuid.UUID,
    file_id:     uuid.UUID,
    request:     Request,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> dict:
    """Delete a stored file (record + on-disk data). 409 if the incident is
    closed, 404 if not found. Requires the analyst role and access."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    ef = (await db.execute(
        select(EntityFile).where(EntityFile.id == file_id, EntityFile.incident_id == incident_id)
    )).scalar_one_or_none()
    if not ef:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")

    base_dir = Path(settings.logs_path).resolve()
    path = (base_dir / ef.file_path).resolve()
    try:
        path.relative_to(base_dir)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid file path")
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        # Best-effort filesystem cleanup: keep API idempotency, but record the failure.
        await write_audit(
            db, "file_delete_unlink_failed",
            user_id=user.id, username=user.username,
            resource_type="incident_file", resource_id=str(file_id),
            details={"incident_id": str(incident_id), "filename": ef.original_name,
                     "path": str(path), "error": str(exc)},
            ip_address=request.client.host if request.client else None,
        )

    await write_audit(
        db, "file_delete",
        user_id=user.id, username=user.username,
        resource_type="incident_file", resource_id=str(file_id),
        details={"incident_id": str(incident_id), "filename": ef.original_name},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(ef)
    await db.commit()
    return {"status": "ok"}
