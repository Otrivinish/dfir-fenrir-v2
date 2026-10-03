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
import asyncio
import hashlib
import re
import struct
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
from core.errors import ApiError, ApiErrorBody
from evidence.crypto import EvidenceCryptoError, adecrypt_file_bytes, aencrypt_file_bytes, decrypt_file_bytes
from incidents.access import get_accessible_incident
from models import Entity, EntityFile, Incident, User
from schemas import EntityFileList, EntityFileOut, IncidentFileUpdate

router = APIRouter()

_FILE_MAX_BYTES = 50 * 1024 * 1024  # 50 MB — mirrors the entity-file limit


def sniff_report_image(head: bytes) -> Optional[str]:
    """MIME type of a raster image a report may embed, from its magic bytes; None
    for anything else. SVG (it can carry script) and every other format are refused."""
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    return None


# A report figure may be at most this big (E-fix L3): the browser decodes it to embed it, so a
# small file that declares huge dimensions (a decompression bomb) is refused when it is picked.
MAX_REPORT_IMAGE_SIDE = 16384
MAX_REPORT_IMAGE_PIXELS = 50_000_000
_JPEG_SOF = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}


def _gif_size(b: bytes) -> tuple[int, int]:
    """Logical screen size, grown to cover every frame (browsers enlarge the canvas to an oversized
    frame). Walks the block structure and skips each frame's data sub-blocks; nothing is decoded."""
    w, h = struct.unpack("<HH", b[6:10])
    pos = 13 + (3 << ((b[10] & 7) + 1) if b[10] & 0x80 else 0)

    def skip_sub_blocks(p: int) -> int:
        while p < len(b) and b[p]:
            p += 1 + b[p]
        return p + 1

    while pos < len(b):
        if b[pos] == 0x21:                                   # extension: label + sub-blocks
            pos = skip_sub_blocks(pos + 2)
        elif b[pos] == 0x2C:                                 # image descriptor
            left, top, fw, fh = struct.unpack("<HHHH", b[pos + 1:pos + 9])
            w, h = max(w, left + fw), max(h, top + fh)
            flags = b[pos + 9]
            pos += 10 + (3 << ((flags & 7) + 1) if flags & 0x80 else 0)
            pos = skip_sub_blocks(pos + 1)                   # + LZW minimum code size
        else:                                                # trailer (0x3B) or junk
            break
    return w, h


def report_image_size(b: bytes, mime: str) -> Optional[tuple[int, int]]:
    """(width, height) of a PNG/JPEG/GIF/WebP read from its header bytes only (never a pixel
    decode); None when the header can't be read or declares a zero dimension."""
    try:
        if mime == "image/png":
            if b[12:16] != b"IHDR":
                return None
            w, h = struct.unpack(">II", b[16:24])
        elif mime == "image/gif":
            w, h = _gif_size(b)
        elif mime == "image/webp":
            kind = b[12:16]
            if kind == b"VP8X":                              # extended: 24-bit canvas size - 1
                w = 1 + int.from_bytes(b[24:27], "little")
                h = 1 + int.from_bytes(b[27:30], "little")
            elif kind == b"VP8 " and b[23:26] == b"\x9d\x01\x2a":   # lossy key frame
                w, h = (v & 0x3FFF for v in struct.unpack("<HH", b[26:30]))
            elif kind == b"VP8L" and b[20] == 0x2F:          # lossless: 14-bit width/height - 1
                bits = int.from_bytes(b[21:25], "little")
                w, h = 1 + (bits & 0x3FFF), 1 + ((bits >> 14) & 0x3FFF)
            else:
                return None
        elif mime == "image/jpeg":                           # walk the markers to the first SOFn
            pos, w, h = 2, 0, 0
            while pos + 4 <= len(b):
                if b[pos] != 0xFF:
                    return None
                marker = b[pos + 1]
                if marker == 0xFF:                           # fill byte
                    pos += 1
                    continue
                if marker in _JPEG_SOF:
                    h, w = struct.unpack(">HH", b[pos + 5:pos + 9])
                    break
                if marker in (0xD9, 0xDA):                   # end of image / start of scan before a frame
                    return None
                if 0xD0 <= marker <= 0xD7 or marker == 0x01:  # standalone markers
                    pos += 2
                    continue
                pos += 2 + struct.unpack(">H", b[pos + 2:pos + 4])[0]
        else:
            return None
    except (IndexError, struct.error, ValueError):
        return None
    return (w, h) if w > 0 and h > 0 else None


def read_report_image(file_path: str, nonce_hex: str) -> tuple[str, Optional[str], Optional[tuple[int, int]]]:
    """(SHA-256 hex, sniffed image MIME, header dimensions) of a stored file's decrypted bytes.
    Raises ValueError/OSError when its data is outside the store or missing on disk, and
    EvidenceCryptoError (EvidenceIntegrityError included) when it fails decryption or AES-GCM
    authentication (tampered or corrupt). Blocking (disk read + AES-GCM + hash): call it via
    asyncio.to_thread."""
    base_dir = Path(settings.logs_path).resolve()
    path = (base_dir / file_path).resolve()
    path.relative_to(base_dir)
    plaintext = decrypt_file_bytes(path.read_bytes(), nonce_hex)
    mime = sniff_report_image(plaintext[:12])
    return (hashlib.sha256(plaintext).hexdigest(), mime,
            report_image_size(plaintext, mime) if mime else None)


def report_image_digest(file_path: str, nonce_hex: str) -> tuple[Optional[str], Optional[str]]:
    """(SHA-256 hex, sniffed image MIME) of a stored file's decrypted bytes, or (None, None) when
    its data is missing on disk or fails decryption/authentication. Never raises for those, so one
    bad figure can't fail a whole report. Blocking: call it via asyncio.to_thread."""
    try:
        sha, mime, _ = read_report_image(file_path, nonce_hex)
    except (ValueError, OSError, EvidenceCryptoError):
        return None, None
    return sha, mime


def report_file_present(file_path: str, plain_size: int) -> bool:
    """Cheap check (one stat, no decryption): the stored ciphertext is inside the store and has the
    size AES-GCM gives the original (plaintext + 16-byte tag). Blocking: call it via asyncio.to_thread."""
    base_dir = Path(settings.logs_path).resolve()
    path = (base_dir / file_path).resolve()
    try:
        path.relative_to(base_dir)
        return path.stat().st_size == plain_size + 16
    except (ValueError, OSError):
        return False


def _integrity_failed() -> ApiError:
    return ApiError(status.HTTP_409_CONFLICT, "file_integrity_failed",
                    "The stored file failed its integrity check (it can't be decrypted or authenticated: "
                    "tampered or corrupt).")


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
    await asyncio.to_thread(lambda: (dest.parent.mkdir(parents=True, exist_ok=True), dest.write_bytes(ct)))

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

@router.get("/{incident_id}/files/{file_id}/download", summary="Download a stored file",
            responses={409: {"model": ApiErrorBody,
                             "description": "file_integrity_failed (the stored bytes fail decryption / "
                                           "AES-GCM authentication: tampered or corrupt)"}})
async def download_incident_file(
    incident_id: uuid.UUID,
    file_id:     uuid.UUID,
    user: User = Depends(current_user),
    db:   AsyncSession = Depends(get_db),
) -> Response:
    """Download a stored file, decrypting it on the fly. Returns 404 if the record
    is missing or its data is absent on disk, and 409 code file_integrity_failed if
    the stored bytes fail decryption or authentication (tampered or corrupt; nothing
    is returned). Requires access to the incident."""
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

    raw_ct = await asyncio.to_thread(path.read_bytes)
    try:
        plaintext = await adecrypt_file_bytes(raw_ct, ef.nonce_hex)
    except EvidenceCryptoError:
        raise _integrity_failed()
    return Response(
        content=plaintext,
        media_type=ef.content_type or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{_safe_name(ef.original_name)}"'},
    )


# ─── Update (rename / link-unlink entity) ──────────────────────────────────────

@router.patch("/{incident_id}/files/{file_id}", response_model=EntityFileOut,
              responses={422: {"model": ApiErrorBody,
                               "description": "unsupported_report_image (include_in_report on a file "
                                             "that is not a PNG, JPEG, GIF or WebP image, or whose "
                                             "dimensions can't be read from its header) or "
                                             "image_too_large (over 16384 px per side or 50 megapixels)"},
                         409: {"model": ApiErrorBody,
                               "description": "incident closed, or file_integrity_failed (include_in_report "
                                             "on a file whose stored bytes fail decryption / authentication)"}},
              summary="Rename a file, (un)link it to an entity, or pick it as a report figure")
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
    404 if the file or target entity is unknown. Requires the analyst role.

    `include_in_report=true` makes the file a numbered figure in generated reports.
    Only a PNG, JPEG, GIF or WebP image qualifies, checked on the decrypted bytes,
    not the stored content type: anything else, SVG included, is 422 code
    unsupported_report_image, and so is an image whose width and height can't be read
    from its header. The dimensions come from the header only (the image is never
    decoded here): over 16384 px per side or 50 megapixels is 422 code image_too_large.
    A file whose stored bytes fail decryption or authentication (tampered or corrupt)
    is 409 code file_integrity_failed. On success the file's SHA-256 and image type are
    stored for report data; un-including clears them, a caption-only edit keeps them,
    and sending include_in_report=true again for a figure that has none stored
    (picked before they were stored) computes them. `report_caption` (max 512
    characters) is printed under the figure; null or "" clears it. The audit row
    records the caption's length, not its text."""
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
    if req.include_in_report and (not ef.include_in_report or ef.report_sha256 is None):
        # Picked as a figure (or picked before the hash was stored): validate by content, read the
        # dimensions from the header and store the SHA-256 + type, all in a thread (L3 / L5).
        try:
            sha, mime, size = await asyncio.to_thread(read_report_image, ef.file_path, ef.nonce_hex)
        except (ValueError, OSError):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "File data missing on disk")
        except EvidenceCryptoError:
            raise _integrity_failed()
        if mime is None:
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "unsupported_report_image",
                           "Only a PNG, JPEG, GIF or WebP image can be included in a report "
                           "(checked by content; SVG is not allowed).")
        if size is None:
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "unsupported_report_image",
                           "The image's width and height can't be read from its header, so it can't be "
                           "included in a report.")
        w, h = size
        if w > MAX_REPORT_IMAGE_SIDE or h > MAX_REPORT_IMAGE_SIDE or w * h > MAX_REPORT_IMAGE_PIXELS:
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "image_too_large",
                           f"The image is {w}×{h} px; a report figure may be at most "
                           f"{MAX_REPORT_IMAGE_SIDE} px per side and 50 megapixels.")
        ef.report_sha256, ef.report_mime = sha, mime
    if req.include_in_report is not None and req.include_in_report != ef.include_in_report:
        if not req.include_in_report:
            ef.report_sha256 = ef.report_mime = None
        ef.include_in_report = req.include_in_report
        changed["include_in_report"] = req.include_in_report
    if "report_caption" in req.model_fields_set:
        caption = (req.report_caption or "").strip() or None
        if caption != ef.report_caption:
            ef.report_caption = caption
            changed["report_caption_length"] = len(caption or "")

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
