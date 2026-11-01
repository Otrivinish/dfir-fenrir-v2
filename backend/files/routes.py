"""Incident-level file store ("Files").

A lightweight working-file area for NON-malicious supporting material —
screenshots, raw logs, exported notes. Distinct from Evidence (chain of custody)
and Artifacts (quarantined malicious files): no CoC, no AV/sandbox.

Physically this is the same store as entity files (the `entity_files` table +
the AES-256-GCM-encrypted `/asset_logs` directory). A file may be incident-level
(no entity) or linked to an entity; the entity drawer shows the per-entity
subset, this router shows the whole incident.

H4 (R10): the server hashes every upload (SHA-256 / SHA-1 / MD5, from the writer's single pass; rows from
before H4: `python -m files.backfill_hashes`). Rename and delete need a reason (422 reason_required) and are
audited (old/new name; the hashes); delete is refused while a record relies on the file (409 file_referenced,
`file_references`). POST …/files/{id}/register-exhibit copies a file into the evidence store as an unsealed
draft exhibit (G3 semantics); the file stays a supporting document and records the exhibit.

S5 (EG-6, EG-7): an upload (here and on the entity attachment route) may carry a capture record (files/capture.py);
a capture_sha256 is compared with the bytes before anything is stored. A file can be linked to an exhibit, timeline
event or IOC it corroborates (supporting_file_links: POST / DELETE …/files/{id}/links; the list filters on
?linked_type=&linked_id=); a link blocks delete. Register as exhibit pre-fills the new draft from the capture record
(GET …/files/{id}/exhibit-prefill shows what it would fill).

Mounted at prefix="/api/incidents".
"""
import asyncio
import hashlib
import re
import struct
import uuid
from datetime import timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import Response
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.config import settings
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from evidence import codec
from evidence.crypto import (EvidenceCryptoError, EvidenceIntegrityError, StoredFile, adelete_encrypted,
                             asha256_decrypted, awrite_encrypted, read_decrypted, read_decrypted_stream, stored_size,
                             write_encrypted_stream)
from evidence.streaming import SMALL_FILE_BYTES, decrypted_download, require_free_space
from files import capture
from incidents.access import get_accessible_incident, require_incident_person
from models import (CaseNote, Entity, EntityFile, Evidence, GeneratedReport, IOC, Incident, SupportingFileLink,
                    TimelineEvent, User)
from schemas import (CAPTURE_BY_NAME_MAX, CAPTURE_CONTEXT_MAX, CAPTURE_DOC, CAPTURE_SOURCE_MAX, CAPTURE_TOOL_MAX,
                     CAPTURE_TOOL_VERSION_MAX, CAPTURE_URL_MAX, CaptureMethod, EntityFileList, EntityFileOut,
                     FileDelete, FileExhibitPrefillOut, FileReference, FileRegisterExhibitOut, IncidentFileUpdate,
                     LinkTargetType, SupportingFileLinkCreate, SupportingFileLinkOut)

router = APIRouter()

_FILE_MAX_BYTES = 50 * 1024 * 1024  # 50 MB — mirrors the entity-file limit
REASON_MIN, REASON_MAX = 10, 2000   # H4: rename / delete reason (as H1's artifact delete)


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


def read_report_image(file_path: str, nonce_hex: str,
                      size: Optional[int]) -> tuple[str, Optional[str], Optional[tuple[int, int]]]:
    """(SHA-256 hex, sniffed image MIME, header dimensions) of a stored file's decrypted bytes
    (either stored format; `size` = the row's file_size). Raises EvidenceIntegrityError when it
    fails authentication or its row's checks (tampered or corrupt), and EvidenceCryptoError when
    it cannot be read (`reason` file_missing / invalid_path / io_error / wrong_kek / ...).
    Blocking (disk read + AES-GCM + hash): call it via asyncio.to_thread."""
    plaintext = read_decrypted(file_path, nonce_hex, size, root=settings.logs_path)
    mime = sniff_report_image(plaintext[:12])
    return (hashlib.sha256(plaintext).hexdigest(), mime,
            report_image_size(plaintext, mime) if mime else None)


def report_image_digest(file_path: str, nonce_hex: str, size: Optional[int]) -> tuple[Optional[str], Optional[str]]:
    """(SHA-256 hex, sniffed image MIME) of a stored file's decrypted bytes, or (None, None) when
    its data is missing on disk or fails decryption/authentication. Never raises for those, so one
    bad figure can't fail a whole report. Blocking: call it via asyncio.to_thread."""
    try:
        sha, mime, _ = read_report_image(file_path, nonce_hex, size)
    except (ValueError, OSError, EvidenceCryptoError):
        return None, None
    return sha, mime


def report_file_present(file_path: str, plain_size: int, nonce_hex: str) -> bool:
    """Cheap check (one stat, no decryption): the stored ciphertext is inside the store and has the
    size its format gives the original (v0: plaintext + 16-byte tag; v2: the FENRGCM container
    size). Blocking: call it via asyncio.to_thread."""
    base_dir = Path(settings.logs_path).resolve()
    path = (base_dir / file_path).resolve()
    try:
        path.relative_to(base_dir)
        return path.stat().st_size == stored_size(nonce_hex, plain_size)
    except (ValueError, OSError):
        return False


def _integrity_failed() -> ApiError:
    return ApiError(status.HTTP_409_CONFLICT, "file_integrity_failed",
                    "The stored file failed its integrity check (it can't be decrypted or authenticated: "
                    "tampered or corrupt).")


def _read_failed() -> ApiError:
    return ApiError(status.HTTP_503_SERVICE_UNAVAILABLE, "file_read_error",
                    "The stored file could not be read (storage error or wrong EVIDENCE_KEK). The attempt "
                    "was audited and admins were notified.")


# Suffixes the stores reserve for their own files (rotation journals, staging, v0 sidecars): a name ending
# with one is neutralised, so a stored file can never be taken for one (G-fix R3-1). Same list in entities.
_RESERVED_SUFFIXES = (".keyslot", ".rewrite", ".tmp", ".partial", ".nonce")


def _safe_name(name: str) -> str:
    """Strip path separators and unsafe chars from a filename; a reserved suffix gets a trailing "_"."""
    safe = re.sub(r'[^\w.\-]', '_', Path(name).name)[:200] or "file"
    return safe + "_" if safe.lower().endswith(_RESERVED_SUFFIXES) else safe


def _incident_file_path(incident_id: uuid.UUID, file_id: uuid.UUID) -> Path:
    # Server ids only, never the uploaded name (CodeQL py/path-injection); the name lives in the row. New names end with
    # a fixed ".enc" (R3-1); rows written before keep their `<id>_<name>.enc` path (readers use the row's).
    return Path("files") / str(incident_id) / f"{file_id}.enc"


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


async def _exhibit_map(db: AsyncSession, evidence_ids) -> dict[uuid.UUID, tuple[str, bool]]:
    ids = {i for i in evidence_ids if i}
    if not ids:
        return {}
    rows = (await db.execute(select(Evidence.id, Evidence.identifier, Evidence.coc_sealed)
                             .where(Evidence.id.in_(ids)))).all()
    return {r[0]: (r[1], bool(r[2])) for r in rows}


def _decorate(out: EntityFileOut, umap: dict, emap: dict, xmap: Optional[dict] = None,
              lmap: Optional[dict] = None) -> EntityFileOut:
    out.uploaded_by_username = umap.get(out.uploaded_by_id)
    out.captured_by_username = umap.get(out.captured_by_id) if out.captured_by_id else None
    out.entity_name = emap.get(out.entity_id) if out.entity_id else None
    if out.evidence_id and xmap and out.evidence_id in xmap:
        out.evidence_identifier, out.evidence_sealed = xmap[out.evidence_id]
    out.links = (lmap or {}).get(out.id, [])
    return out


async def decorated_files(db: AsyncSession, rows) -> list[EntityFileOut]:
    """Rows as EntityFileOut with the uploader's and capturer's usernames, the entity's name, the exhibit's
    identifier and seal state (H4) and the file's links (S5) filled in. Shared with the entity drawer's list
    (entities/routes.py)."""
    umap = await _username_map(db, [r.uploaded_by_id for r in rows] + [r.captured_by_id for r in rows])
    emap = await _entity_name_map(db, [r.entity_id for r in rows])
    xmap = await _exhibit_map(db, [r.evidence_id for r in rows])
    lmap: dict[uuid.UUID, list[SupportingFileLinkOut]] = {}
    if rows:
        links = (await db.execute(select(SupportingFileLink)
                                  .where(SupportingFileLink.file_id.in_([r.id for r in rows]))
                                  .order_by(SupportingFileLink.linked_at, SupportingFileLink.id))).scalars().all()
        for out in await link_outs(db, links):
            lmap.setdefault(out.file_id, []).append(out)
    return [_decorate(EntityFileOut.model_validate(r), umap, emap, xmap, lmap) for r in rows]


# ─── S5: capture record (EG-6) and links (EG-7) ───────────────────────────────

def capture_form(
    captured_at:          Optional[str] = Form(default=None, description=CAPTURE_DOC["captured_at"]),
    captured_by_id:       Optional[uuid.UUID] = Form(default=None, description=CAPTURE_DOC["captured_by_id"]),
    captured_by_name:     Optional[str] = Form(default=None, max_length=CAPTURE_BY_NAME_MAX,
                                               description=CAPTURE_DOC["captured_by_name"]),
    capture_tool:         Optional[str] = Form(default=None, max_length=CAPTURE_TOOL_MAX,
                                               description=CAPTURE_DOC["capture_tool"]),
    capture_tool_version: Optional[str] = Form(default=None, max_length=CAPTURE_TOOL_VERSION_MAX,
                                               description=CAPTURE_DOC["capture_tool_version"]),
    capture_method:       Optional[CaptureMethod] = Form(default=None, description=CAPTURE_DOC["capture_method"]),
    capture_source:       Optional[str] = Form(default=None, max_length=CAPTURE_SOURCE_MAX,
                                               description=CAPTURE_DOC["capture_source"]),
    capture_url:          Optional[str] = Form(default=None, max_length=CAPTURE_URL_MAX,
                                               description=CAPTURE_DOC["capture_url"]),
    capture_context:      Optional[str] = Form(default=None, max_length=CAPTURE_CONTEXT_MAX,
                                               description=CAPTURE_DOC["capture_context"]),
    capture_sha256:       Optional[str] = Form(default=None, description=CAPTURE_DOC["capture_sha256"]),
) -> dict:
    """The capture-record form fields of a supporting-document upload (both upload routes), those sent."""
    sent = dict(captured_at=captured_at, captured_by_id=captured_by_id, captured_by_name=captured_by_name,
                capture_tool=capture_tool, capture_tool_version=capture_tool_version, capture_method=capture_method,
                capture_source=capture_source, capture_url=capture_url, capture_context=capture_context,
                capture_sha256=capture_sha256)
    return {k: v for k, v in sent.items() if v is not None}


async def capture_record(db: AsyncSession, incident_id: uuid.UUID, user: User, sent: dict) -> dict:
    """The upload's capture columns, checked (capture.capture_columns), with a captured_by_id other than the caller
    checked against the incident (404 user_not_found, 422 assignee_no_access). Before anything is read or stored."""
    cols = capture.capture_columns(sent)
    if cols.get("captured_by_id") and cols["captured_by_id"] != user.id:
        await require_incident_person(db, incident_id, cols["captured_by_id"], "the capturer")
    return cols


async def check_capture_sha256(db: AsyncSession, request: Request, user: User, raw: bytes, cols: dict, *,
                               action: str, resource_type: str, details: dict) -> None:
    """C3-style intake check: the SHA-256 taken at capture vs the server's SHA-256 of the uploaded bytes, BEFORE the
    encrypted write. A mismatch writes `<action>_rejected` (no file content), commits it and raises 422
    capture_hash_mismatch: nothing is stored."""
    expected = cols.get("capture_sha256")
    if not expected:
        return
    computed = await asyncio.to_thread(lambda: hashlib.sha256(raw).hexdigest())
    if computed == expected:
        return
    await write_audit(db, f"{action}_rejected", user_id=user.id, username=user.username,
                      resource_type=resource_type, outcome="failure",
                      details={**details, "size": len(raw), "reason": "capture_hash_mismatch",
                               "capture_sha256": expected, "computed_sha256": computed},
                      ip_address=request.client.host if request.client else None)
    await db.commit()
    raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "capture_hash_mismatch",
                   f"The SHA-256 taken at capture ({expected}) does not match the uploaded file, whose SHA-256 is "
                   f"{computed}. Nothing was stored; the attempt was audited.")


_LINK_COLUMN = {"exhibit": "evidence_id", "timeline_event": "timeline_event_id", "ioc": "ioc_id"}


def _link_target(link: SupportingFileLink) -> tuple[str, uuid.UUID]:
    return next((t, getattr(link, c)) for t, c in _LINK_COLUMN.items() if getattr(link, c) is not None)


async def link_outs(db: AsyncSession, links) -> list[SupportingFileLinkOut]:
    """Links as SupportingFileLinkOut, with each target's label and the linker's username (one query per kind)."""
    ids: dict[str, set] = {t: set() for t in _LINK_COLUMN}
    for ln in links:
        t, tid = _link_target(ln)
        ids[t].add(tid)
    labels: dict[uuid.UUID, str] = {}
    if ids["exhibit"]:
        labels.update((i, f"{ident} · {name}") for i, ident, name in (await db.execute(
            select(Evidence.id, Evidence.identifier, Evidence.name).where(Evidence.id.in_(ids["exhibit"])))).all())
    if ids["timeline_event"]:
        labels.update((i, f"{_z(at)} · {(desc or '')[:80]}") for i, at, desc in (await db.execute(
            select(TimelineEvent.id, TimelineEvent.event_time, TimelineEvent.description)
            .where(TimelineEvent.id.in_(ids["timeline_event"])))).all())
    if ids["ioc"]:
        labels.update((i, f"{typ} {val[:120]}") for i, typ, val in (await db.execute(
            select(IOC.id, IOC.type, IOC.value).where(IOC.id.in_(ids["ioc"])))).all())
    umap = await _username_map(db, [ln.linked_by_id for ln in links])
    outs = []
    for ln in links:
        t, tid = _link_target(ln)
        outs.append(SupportingFileLinkOut(id=ln.id, file_id=ln.file_id, target_type=t, target_id=tid,
                                          target_label=labels.get(tid), note=ln.note, linked_by_id=ln.linked_by_id,
                                          linked_by_username=umap.get(ln.linked_by_id), linked_at=ln.linked_at))
    return outs


async def _require_link_target(db: AsyncSession, incident_id: uuid.UUID, target_type: str,
                               target_id: uuid.UUID) -> None:
    """404 evidence_not_found / timeline_event_not_found / ioc_not_found unless the target is of this incident."""
    model, code, what = {"exhibit": (Evidence, "evidence_not_found", "Exhibit"),
                         "timeline_event": (TimelineEvent, "timeline_event_not_found", "Timeline event"),
                         "ioc": (IOC, "ioc_not_found", "IOC")}[target_type]
    found = (await db.execute(select(model.id).where(model.id == target_id,
                                                     model.incident_id == incident_id))).first()
    if not found:
        raise ApiError(status.HTTP_404_NOT_FOUND, code, f"{what} not found in this incident")


# ─── H4: reason, references, hash for the audit ───────────────────────────────

def required_reason(reason: Optional[str], what: str) -> str:
    """The trimmed reason, or 422 reason_required (REASON_MIN–REASON_MAX characters)."""
    why = (reason or "").strip()
    if not (REASON_MIN <= len(why) <= REASON_MAX):
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "reason_required",
                       f"A reason of {REASON_MIN}–{REASON_MAX} characters is required to {what}.")
    return why


def _z(dt) -> Optional[str]:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


async def file_references(db: AsyncSession, ef: EntityFile, *, via_entity: bool = False) -> list[dict]:
    """H4 delete guard: the records that rely on this supporting document ({type, id, label}).

      report_figure     it is picked as a report figure (Include in report)
      generated_report  a saved report of the incident prints its SHA-256 (it was a figure when generated)
      case_note         a case note of the incident cites its id or SHA-256 (case notes are append-only)
      exhibit           it was registered as an exhibit (evidence_id)
      link              S5: it corroborates an exhibit, timeline event or IOC (supporting_file_links; id = the link)
      entity            it is attached to an entity — not counted when deleting through that entity's own
                        attachment route (`via_entity`), which is the act of removing the attachment."""
    refs: list[dict] = []
    if ef.include_in_report:
        refs.append({"type": "report_figure", "id": str(ef.id), "label": "picked as a report figure"})
    hashes = sorted({h.lower() for h in (ef.sha256, ef.report_sha256) if h})
    if hashes:
        for rid, kind, at in (await db.execute(
            select(GeneratedReport.id, GeneratedReport.report_type, GeneratedReport.generated_at)
            .where(GeneratedReport.incident_id == ef.incident_id,
                   or_(*[func.strpos(GeneratedReport.html_content, h) > 0 for h in hashes]))
            .order_by(GeneratedReport.generated_at)
        )).all():
            refs.append({"type": "generated_report", "id": str(rid), "label": f"{kind} report generated {_z(at)}"})
    needles = [str(ef.id), *hashes]
    for nid, at in (await db.execute(
        select(CaseNote.id, CaseNote.created_at)
        .where(CaseNote.incident_id == ef.incident_id,
               or_(*[func.strpos(func.lower(CaseNote.body), n) > 0 for n in needles]))
        .order_by(CaseNote.created_at)
    )).all():
        refs.append({"type": "case_note", "id": str(nid), "label": f"case note of {_z(at)}"})
    if ef.evidence_id is not None:
        ident = (await db.execute(select(Evidence.identifier).where(Evidence.id == ef.evidence_id))).scalar()
        refs.append({"type": "exhibit", "id": str(ef.evidence_id), "label": f"registered as exhibit {ident}"})
    links = (await db.execute(select(SupportingFileLink).where(SupportingFileLink.file_id == ef.id)
                              .order_by(SupportingFileLink.linked_at, SupportingFileLink.id))).scalars().all()
    for ln in await link_outs(db, links):
        refs.append({"type": "link", "id": str(ln.id),
                     "label": f"corroborates {ln.target_type.replace('_', ' ')} {ln.target_label or ln.target_id}"})
    if ef.entity_id is not None and not via_entity:
        name = (await _entity_name_map(db, [ef.entity_id])).get(ef.entity_id)
        refs.append({"type": "entity", "id": str(ef.entity_id), "label": f"attached to entity {name}"})
    return refs


def referenced_error(refs: list[dict]) -> ApiError:
    return ApiError(status.HTTP_409_CONFLICT, "file_referenced",
                    f"{len(refs)} record(s) rely on this file (report figure, saved report, case note, exhibit, "
                    "link or entity); it can't be deleted while they do.",
                    extra={"references": [FileReference(**r).model_dump() for r in refs]})


async def delete_hashes(ef: EntityFile) -> dict:
    """The hashes a delete audit keeps: the recorded ones, or (a row not yet hashed) a SHA-256 computed now,
    streaming; an unreadable file records why instead of failing the delete."""
    if ef.sha256:
        return {"sha256": ef.sha256, "sha1": ef.sha1, "md5": ef.md5, "sha256_source": "recorded"}
    try:
        sha = await asha256_decrypted(ef.file_path, ef.nonce_hex, ef.file_size, root=settings.logs_path)
        return {"sha256": sha, "sha256_source": "computed_at_delete"}
    except EvidenceCryptoError as e:        # EvidenceIntegrityError included
        return {"sha256": ef.report_sha256, "sha256_source": f"unreadable ({e.reason or type(e).__name__})"}


async def locked_file(db: AsyncSession, file_id: uuid.UUID, **where) -> Optional[EntityFile]:
    """The file row (of `where`: incident_id or entity_id) under a row lock until commit."""
    q = select(EntityFile).where(EntityFile.id == file_id, *[getattr(EntityFile, k) == v for k, v in where.items()])
    return (await db.execute(q.with_for_update().execution_options(populate_existing=True))).scalar_one_or_none()


# ─── List ──────────────────────────────────────────────────────────────────────

@router.get("/{incident_id}/files", response_model=EntityFileList,
            summary="List all files stored for an incident",
            responses={422: {"model": ApiErrorBody, "description": "invalid_link_filter (linked_type without "
                                                                   "linked_id, or the other way round)"}})
async def list_incident_files(
    incident_id: uuid.UUID,
    linked_type: Optional[LinkTargetType] = Query(default=None, description="S5: only files linked to this kind of "
                                                                            "target (with linked_id)"),
    linked_id:   Optional[uuid.UUID] = Query(default=None, description="S5: the exhibit, timeline event or IOC id"),
    user: User = Depends(current_user),
    db:   AsyncSession = Depends(get_db),
) -> EntityFileList:
    """List every file in the incident's store (entity-linked or not), newest first.

    Each item carries the uploader's username and the linked entity's name for
    display, its capture record and its links (S5). `linked_type` + `linked_id`
    (both, else 422 invalid_link_filter) list only the files linked to that exhibit,
    timeline event or IOC. Requires an authenticated user with access to the incident.
    """
    await _get_incident(db, incident_id, user)
    if (linked_type is None) != (linked_id is None):
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_link_filter",
                       "linked_type and linked_id go together: send both, or neither")
    q = select(EntityFile).where(EntityFile.incident_id == incident_id)
    if linked_type is not None:
        target = getattr(SupportingFileLink, _LINK_COLUMN[linked_type])
        q = q.where(EntityFile.id.in_(select(SupportingFileLink.file_id).where(target == linked_id)))
    rows = (await db.execute(q.order_by(EntityFile.uploaded_at.desc()))).scalars().all()
    return EntityFileList(items=await decorated_files(db, rows))


# ─── Upload ──────────────────────────────────────────────────────────────────

@router.post("/{incident_id}/files", response_model=EntityFileOut,
             status_code=status.HTTP_201_CREATED,
             summary="Upload a file to the incident store",
             responses={404: {"model": ApiErrorBody, "description": "the entity, or user_not_found (captured_by_id)"},
                        422: {"model": ApiErrorBody, "description": "capture_hash_mismatch (audited), "
                                                                    "invalid_captured_at, invalid_capture_text, "
                                                                    "invalid_hash_format, captured_by_conflict or "
                                                                    "assignee_no_access (the capturer); nothing stored"},
                        507: {"model": ApiErrorBody, "description": "insufficient_storage (the file store, with its 1 GiB reserve, or the upload scratch space is full; nothing stored)"}})
async def upload_incident_file(
    incident_id: uuid.UUID,
    request:     Request,
    file:        UploadFile = File(...),
    entity_id:   Optional[uuid.UUID] = Form(default=None),
    capture_sent: dict = Depends(capture_form),
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> EntityFileOut:
    """Upload a non-malicious supporting file; bytes are encrypted at rest and hashed by the
    server in the same pass (SHA-256 / SHA-1 / MD5, returned and audited).

    Optionally link it to an entity via `entity_id` (must belong to the incident).
    Returns 409 if the incident is closed, 404 if the entity is unknown, and 413
    over the 50 MB limit. Requires the analyst role and access to the incident.

    S5: optional capture-record form fields (ISO/IEC 27037 §7.1.1.1): `captured_at`, `captured_by_id` or
    `captured_by_name` (neither = not recorded; the uploader is never assumed), `capture_tool`,
    `capture_tool_version`, `capture_method`, `capture_source`, `capture_url`, `capture_context`,
    `capture_sha256`. A `capture_sha256` is compared with the server's SHA-256 of the bytes before
    anything is stored: a mismatch is 422 capture_hash_mismatch, audited `file_upload_rejected`.
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
    cap = await capture_record(db, incident_id, user, capture_sent)     # S5: checked before anything is read

    cl = request.headers.get("content-length")
    if cl and int(cl) > _FILE_MAX_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "File exceeds 50 MB limit")

    raw = await file.read()
    if len(raw) > _FILE_MAX_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "File exceeds 50 MB limit")
    await check_capture_sha256(db, request, user, raw, cap, action="file_upload", resource_type="incident_file",
                               details={"incident_id": str(incident_id),
                                        "entity_id": str(entity_id) if entity_id else None,
                                        "filename": file.filename or "file"})

    file_id       = uuid.uuid4()
    original_name = file.filename or "file"
    rel_path      = _incident_file_path(inc.id, file_id)        # the row's id, not the URL's

    # Defense-in-depth: confine the write to the store root (path traversal guard).
    base_dir = Path(settings.logs_path).resolve()
    dest = (base_dir / rel_path).resolve()
    try:
        safe_rel_path = dest.relative_to(base_dir).as_posix()
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid file path")
    require_free_space(len(raw), "this file", root=settings.logs_path)            # L2: 507, nothing stored
    stored = await awrite_encrypted(raw, safe_rel_path, root=settings.logs_path)   # FENRGCM v2, staged write

    ef = EntityFile(
        id=file_id,
        entity_id=entity_id,
        incident_id=incident_id,
        original_name=original_name,
        file_size=len(raw),
        content_type=file.content_type,
        file_path=safe_rel_path,
        nonce_hex=stored.nonce_hex,
        sha256=stored.sha256, sha1=stored.sha1, md5=stored.md5,
        uploaded_by_id=user.id,
        **cap,
    )
    db.add(ef)
    await write_audit(
        db, "file_upload",
        user_id=user.id, username=user.username,
        resource_type="incident_file", resource_id=str(file_id),
        details={"incident_id": str(incident_id), "entity_id": str(entity_id) if entity_id else None,
                 "filename": original_name, "size": len(raw), "sha256": stored.sha256,
                 **capture.audit_values(ef)},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return (await decorated_files(db, [ef]))[0]


# ─── Download ──────────────────────────────────────────────────────────────────

@router.get("/{incident_id}/files/{file_id}/download", summary="Download a stored file",
            responses={200: {"description": "The file's bytes, with Content-Length. Over "
                                            f"{SMALL_FILE_BYTES // (1024 * 1024)} MiB the body is streamed as it is "
                                            "decrypted: if a later part fails its integrity check the server closes "
                                            "the connection before Content-Length bytes are sent; treat a short "
                                            "body as a failed download, never as the file."},
                       409: {"model": ApiErrorBody,
                             "description": "file_integrity_failed (the stored bytes fail decryption / "
                                           "AES-GCM authentication: tampered or corrupt)"},
                       503: {"model": ApiErrorBody,
                             "description": "file_read_error (the stored file could not be read: storage "
                                           "error or wrong EVIDENCE_KEK; audited, admins notified)"}})
async def download_incident_file(
    incident_id: uuid.UUID,
    file_id:     uuid.UUID,
    user: User = Depends(current_user),
    db:   AsyncSession = Depends(get_db),
) -> Response:
    """Download a stored file, decrypting it on the fly. Returns 404 if the record
    is missing or its data is absent on disk, and 409 code file_integrity_failed if
    the stored bytes fail decryption or authentication (tampered or corrupt; nothing
    is returned). A file that cannot be read for another reason (storage error, wrong
    EVIDENCE_KEK) is 503 code file_read_error. Requires access to the incident.

    G2: a file up to 16 MiB is fully decrypted and authenticated before the response starts.
    A larger one streams with bounded memory and Content-Length set; a failure found
    mid-stream aborts the connection (the body is shorter than Content-Length), so a client
    must treat a short body as a failed download."""
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
    try:
        return await decrypted_download(
            ef.file_path, ef.nonce_hex, ef.file_size, root=settings.logs_path,
            media_type=ef.content_type or "application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{_safe_name(ef.original_name)}"'})
    except EvidenceIntegrityError:
        raise _integrity_failed()
    except EvidenceCryptoError as e:
        if e.reason == "file_missing":
            raise HTTPException(status.HTTP_404_NOT_FOUND, "File data missing on disk")
        raise _read_failed() from e


# ─── Update (rename / link-unlink entity) ──────────────────────────────────────

@router.patch("/{incident_id}/files/{file_id}", response_model=EntityFileOut,
              responses={422: {"model": ApiErrorBody,
                               "description": "unsupported_report_image (include_in_report on a file "
                                             "that is not a PNG, JPEG, GIF or WebP image, or whose "
                                             "dimensions can't be read from its header) or "
                                             "image_too_large (over 16384 px per side or 50 megapixels), "
                                             "reason_required (a rename without a 10–2000 character reason), or a "
                                             "capture-record code: capture_sha256_read_only, invalid_captured_at, "
                                             "invalid_capture_text, captured_by_conflict, assignee_no_access"},
                         404: {"model": ApiErrorBody, "description": "the file or entity, or user_not_found "
                                                                    "(captured_by_id)"},
                         409: {"model": ApiErrorBody,
                               "description": "incident closed, or file_integrity_failed (include_in_report "
                                             "on a file whose stored bytes fail decryption / authentication)"},
                         503: {"model": ApiErrorBody,
                               "description": "file_read_error (include_in_report on a file that could not be "
                                             "read: storage error or wrong EVIDENCE_KEK)"}},
              summary="Rename a file, (un)link it to an entity, pick it as a report figure, or edit its capture record")
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

    H4: a rename (an `original_name` that changes the name) needs `reason` (10–2000 characters after
    trimming, else 422 code reason_required, nothing changed); the `file_update` audit row records
    `changes.original_name` = {from, to} and the reason. The stored bytes and their hashes don't change.

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
    records the caption's length, not its text.

    S5: the capture record's fields (all but `capture_sha256`, which was checked against the bytes at
    upload: sending it is 422 capture_sha256_read_only) can be changed; only those sent change, null or
    "" clears one, and each change is audited in `file_update` as {from, to}. No reason is needed (as for
    the entity link and the report figure)."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    ef = (await db.execute(
        select(EntityFile).where(EntityFile.id == file_id, EntityFile.incident_id == incident_id)
    )).scalar_one_or_none()
    if not ef:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")

    # S5: the capture record, checked before anything changes.
    if "capture_sha256" in req.model_fields_set:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "capture_sha256_read_only",
                       "capture_sha256 was checked against the file's bytes at upload and can't be changed. "
                       "Nothing was changed.")
    cap = capture.capture_columns({k: getattr(req, k) for k in capture.EDITABLE if k in req.model_fields_set})
    if cap.get("captured_by_id") and cap["captured_by_id"] not in (ef.captured_by_id, user.id):
        await require_incident_person(db, incident_id, cap["captured_by_id"], "the capturer")

    changed: dict[str, object] = {}
    for k, v in cap.items():
        if v != getattr(ef, k):
            changed[k] = {"from": capture.jsonable(getattr(ef, k)), "to": capture.jsonable(v)}
            setattr(ef, k, v)
    reason: Optional[str] = None
    new_name = (req.original_name or "").strip()
    if new_name and new_name != ef.original_name:
        reason = required_reason(req.reason, "rename a file")          # H4: before anything changes
        changed["original_name"] = {"from": ef.original_name, "to": new_name}
        ef.original_name = new_name
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
            sha, mime, size = await asyncio.to_thread(read_report_image, ef.file_path, ef.nonce_hex, ef.file_size)
        except EvidenceIntegrityError:
            raise _integrity_failed()
        except EvidenceCryptoError as e:
            if e.reason in ("file_missing", "invalid_path"):
                raise HTTPException(status.HTTP_404_NOT_FOUND, "File data missing on disk")
            raise _read_failed() from e
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
            details={"incident_id": str(incident_id), "changes": changed,
                     **({"reason": reason} if reason else {})},
            ip_address=request.client.host if request.client else None,
        )
    await db.commit()
    return (await decorated_files(db, [ef]))[0]


# ─── Delete ──────────────────────────────────────────────────────────────────

_DELETE_RESPONSES = {
    409: {"model": ApiErrorBody, "description": "incident closed, or file_referenced (a record relies on the file; "
                                                "`references` lists them as {type, id, label})"},
    422: {"model": ApiErrorBody, "description": "reason_required"},
}


async def delete_file_row(db: AsyncSession, ef: EntityFile, *, why: str, user: User, request: Request,
                          action: str, resource_type: str, details: dict) -> None:
    """H4: audit (reason + hashes), delete the row, commit, THEN remove the stored file (a failure there
    leaves an unreferenced file, never a dangling row; it is audited). The caller checked access, state,
    reason and references under the row lock."""
    ip = request.client.host if request.client else None
    hashes = await delete_hashes(ef)
    rel, fid = ef.file_path, str(ef.id)
    await write_audit(db, action, user_id=user.id, username=user.username,
                      resource_type=resource_type, resource_id=fid,
                      details={**details, "filename": ef.original_name, "size": ef.file_size, "reason": why,
                               **{k: v for k, v in hashes.items() if v}},
                      ip_address=ip)
    await db.delete(ef)
    await db.commit()
    base_dir = Path(settings.logs_path).resolve()
    path = (base_dir / rel).resolve()
    try:
        path.relative_to(base_dir)
        await asyncio.to_thread(path.unlink, missing_ok=True)
    except (ValueError, OSError) as exc:
        await write_audit(db, f"{action}_unlink_failed", user_id=user.id, username=user.username,
                          resource_type=resource_type, resource_id=fid,
                          details={**details, "path": rel, "error": str(exc)[:300]}, ip_address=ip)
        await db.commit()


@router.delete("/{incident_id}/files/{file_id}", summary="Delete a stored file", responses=_DELETE_RESPONSES)
async def delete_incident_file(
    incident_id: uuid.UUID,
    file_id:     uuid.UUID,
    request:     Request,
    body:        Optional[FileDelete] = None,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> dict:
    """Delete a stored file (record + on-disk data). 409 if the incident is
    closed, 404 if not found. Requires the analyst role and access.

    H4: a reason is required — JSON body `{"reason": "…"}` (10–2000 characters, else 422 code
    reason_required). Refused with 409 code file_referenced while a record relies on the file: it is
    picked as a report figure, a saved report prints its SHA-256, a case note cites its id or SHA-256,
    it was registered as an exhibit, or it is attached to an entity; `references` lists them
    ({type, id, label}). The `file_delete` audit row keeps the reason and the hashes."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    ef = await locked_file(db, file_id, incident_id=incident_id)
    if not ef:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")
    why = required_reason(body.reason if body else None, "delete a file")
    refs = await file_references(db, ef)
    if refs:
        raise referenced_error(refs)
    await delete_file_row(db, ef, why=why, user=user, request=request, action="file_delete",
                          resource_type="incident_file",
                          details={"incident_id": str(incident_id),
                                   "entity_id": str(ef.entity_id) if ef.entity_id else None})
    return {"status": "ok"}


# ─── S5 (EG-7): what a supporting document corroborates ───────────────────────

@router.post("/{incident_id}/files/{file_id}/links", response_model=SupportingFileLinkOut,
             status_code=status.HTTP_201_CREATED,
             summary="Link a supporting document to the exhibit, timeline event or IOC it corroborates",
             responses={404: {"model": ApiErrorBody, "description": "the file, or evidence_not_found / "
                                                                    "timeline_event_not_found / ioc_not_found (not "
                                                                    "in this incident)"},
                        409: {"model": ApiErrorBody, "description": "incident_closed or already_linked"}})
async def link_incident_file(
    incident_id: uuid.UUID,
    file_id:     uuid.UUID,
    req:         SupportingFileLinkCreate,
    request:     Request,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> SupportingFileLinkOut:
    """Record that this supporting document corroborates an exhibit, a timeline event or an IOC of the same
    incident (`target_type` exhibit | timeline_event | ioc, `target_id`, optional `note`). Distinct from
    Register as exhibit (`evidence_id`, "registered as"): the file stays a supporting document, with no chain of
    custody, and never goes into a disclosure package. A linked file can't be deleted (409 file_referenced) until
    it is unlinked; deleting the timeline event or IOC removes its links. Audited `file_link`. 409 already_linked
    for the same target twice, 409 incident_closed. Analyst role and incident access."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")
    ef = await locked_file(db, file_id, incident_id=incident_id)       # serialises with delete and other links
    if not ef:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")
    await _require_link_target(db, incident_id, req.target_type, req.target_id)
    column = _LINK_COLUMN[req.target_type]
    if (await db.execute(select(SupportingFileLink.id).where(
            SupportingFileLink.file_id == ef.id, getattr(SupportingFileLink, column) == req.target_id))).first():
        raise ApiError(status.HTTP_409_CONFLICT, "already_linked",
                       f"This file is already linked to that {req.target_type.replace('_', ' ')}")
    link = SupportingFileLink(id=uuid.uuid4(), file_id=ef.id, note=req.note or None, linked_by_id=user.id,
                              **{column: req.target_id})
    db.add(link)
    await db.flush()
    out = (await link_outs(db, [link]))[0]
    await write_audit(db, "file_link", user_id=user.id, username=user.username,
                      resource_type="incident_file", resource_id=str(ef.id),
                      details={"incident_id": str(incident_id), "link_id": str(link.id),
                               "target_type": req.target_type, "target_id": str(req.target_id),
                               "target_label": out.target_label, "note": link.note},
                      ip_address=request.client.host if request.client else None)
    await db.commit()
    return out


@router.delete("/{incident_id}/files/{file_id}/links/{link_id}",
               summary="Unlink a supporting document from what it corroborates",
               responses={404: {"model": ApiErrorBody, "description": "the file, or link_not_found"},
                          409: {"model": ApiErrorBody, "description": "incident_closed"}})
async def unlink_incident_file(
    incident_id: uuid.UUID,
    file_id:     uuid.UUID,
    link_id:     uuid.UUID,
    request:     Request,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> dict:
    """Remove one of the file's links (ids in the file's `links`). Audited `file_unlink` with the target and the
    note. Analyst role, incident access, open incident (409 incident_closed)."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")
    ef = await locked_file(db, file_id, incident_id=incident_id)
    if not ef:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")
    link = (await db.execute(select(SupportingFileLink).where(
        SupportingFileLink.id == link_id, SupportingFileLink.file_id == ef.id))).scalar_one_or_none()
    if not link:
        raise ApiError(status.HTTP_404_NOT_FOUND, "link_not_found", "Link not found")
    out = (await link_outs(db, [link]))[0]
    await db.delete(link)
    await write_audit(db, "file_unlink", user_id=user.id, username=user.username,
                      resource_type="incident_file", resource_id=str(ef.id),
                      details={"incident_id": str(incident_id), "link_id": str(link_id),
                               "target_type": out.target_type, "target_id": str(out.target_id),
                               "target_label": out.target_label, "note": out.note},
                      ip_address=request.client.host if request.client else None)
    await db.commit()
    return {"status": "ok"}


# ─── H4: Register as exhibit ─────────────────────────────────────────────────

class _HashMismatch(Exception):
    def __init__(self, computed: str):
        self.computed = computed


def _hash_mismatch() -> ApiError:
    return ApiError(status.HTTP_409_CONFLICT, "file_hash_mismatch",
                    "The stored file no longer matches the SHA-256 recorded at upload. Nothing was registered; "
                    "the attempt was audited.")


def _prefill_out(cols: dict, left_empty: list[dict]) -> FileExhibitPrefillOut:
    return FileExhibitPrefillOut(**{k: v for k, v in cols.items() if k in FileExhibitPrefillOut.model_fields},
                                 left_empty=left_empty)


@router.get("/{incident_id}/files/{file_id}/exhibit-prefill", response_model=FileExhibitPrefillOut,
            summary="What Register as exhibit would pre-fill from the file's capture record")
async def file_exhibit_prefill(
    incident_id: uuid.UUID,
    file_id:     uuid.UUID,
    user: User = Depends(current_user),
    db:   AsyncSession = Depends(get_db),
) -> FileExhibitPrefillOut:
    """S5: the acquisition and source fields a NEW draft exhibit gets from this file's capture record when it is
    registered (POST …/register-exhibit): acquired_at ← captured_at, acquisition_tool / _version ← capture_tool /
    _version, source_system ← capture_source, source_path ← capture_url (style cloud_uri when it passes that rule,
    else other), screen_state ← capture_context. Null = no capture value: nothing is invented. `left_empty` = a
    source field the exhibit's source check would refuse, left empty rather than refusing the registration. When
    the incident already holds an exhibit with the same SHA-256, registering links that one and pre-fills
    nothing. Read-only; incident access."""
    await _get_incident(db, incident_id, user)
    ef = (await db.execute(select(EntityFile).where(EntityFile.id == file_id,
                                                    EntityFile.incident_id == incident_id))).scalar_one_or_none()
    if not ef:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")
    return _prefill_out(*capture.exhibit_prefill(ef))


@router.post("/{incident_id}/files/{file_id}/register-exhibit", response_model=FileRegisterExhibitOut,
             summary="Register a supporting document as an exhibit",
             responses={409: {"model": ApiErrorBody,
                              "description": "incident_closed, file_hash_unrecorded (no SHA-256 recorded yet: run "
                                             "`python -m files.backfill_hashes --apply`), file_hash_mismatch (the "
                                             "stored bytes no longer hash to the recorded SHA-256; nothing "
                                             "registered, audited) or file_integrity_failed (tampered / corrupt)"},
                        503: {"model": ApiErrorBody,
                              "description": "file_read_error (storage error or wrong EVIDENCE_KEK)"},
                        507: {"model": ApiErrorBody, "description": "insufficient_storage (evidence volume)"}})
async def register_file_as_exhibit(
    incident_id: uuid.UUID,
    file_id:     uuid.UUID,
    request:     Request,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> FileRegisterExhibitOut:
    """Register a supporting document as an exhibit with full chain of custody. The file stays a
    supporting document and records the exhibit (`evidence_id`).

    The stored file is decrypted as a stream, re-encrypted into the evidence store with a new key
    (FENRGCM v2) and its SHA-256 checked against the one recorded at upload before anything is kept.
    Same rules as an analyser upload (G3): when the SHA-256 equals an active digital exhibit of the
    incident (the oldest, if several), that exhibit is linked (`exhibit_link` sha256_match, no second
    copy; the file is re-hashed first); otherwise a new UNSEALED DRAFT exhibit is created (its identifier
    from the naming convention, collected by and in the custody of the caller), audited `evidence_collect`
    (method and source `supporting_document`, `file_id`) — complete its acquisition record and seal it
    on the Evidence page as for any draft. Idempotent: a file already registered returns its exhibit
    (`already_registered`). Analyst role, incident access, open incident (409 incident_closed).

    S5: the new draft is pre-filled from the file's capture record (see GET …/exhibit-prefill; `prefill`
    in the response); with no capture record acquired_at stays unknown. A source field the source check
    refuses is left empty, never a refused registration; the audit rows say so (`prefill_left_empty`)."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")
    ef = await locked_file(db, file_id, incident_id=incident_id)       # serialises calls for this file
    if not ef:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")
    ip = request.client.host if request.client else None

    async def out(ev: Evidence, link: str, prefill: Optional[FileExhibitPrefillOut] = None) -> FileRegisterExhibitOut:
        return FileRegisterExhibitOut(evidence_id=ev.id, evidence_identifier=ev.identifier,
                                      evidence_sealed=bool(ev.coc_sealed), exhibit_link=link,
                                      file=(await decorated_files(db, [ef]))[0], prefill=prefill)

    if ef.evidence_id is not None:
        ev = await db.get(Evidence, ef.evidence_id)
        if ev is not None:
            return await out(ev, "already_registered")
    if not ef.sha256:
        raise ApiError(status.HTTP_409_CONFLICT, "file_hash_unrecorded",
                       "This file has no SHA-256 recorded yet (uploaded before hashing was added). An admin runs "
                       "`python -m files.backfill_hashes --apply` first.")
    from evidence.register import draft_storage_path, lock_upload_sha256, register_draft, unique_sha256_match

    async def audit(link: str, ev: Optional[Evidence], outcome: str = "success", **extra) -> None:
        await write_audit(db, "file_register_exhibit", user_id=user.id, username=user.username,
                          resource_type="incident_file", resource_id=str(ef.id), outcome=outcome,
                          details={"incident_id": str(incident_id), "filename": ef.original_name,
                                   "sha256": ef.sha256, "exhibit_link": link,
                                   **({"evidence_id": str(ev.id), "evidence_identifier": ev.identifier} if ev else {}),
                                   **extra},
                          ip_address=ip)

    async def mismatch(computed: Optional[str]) -> ApiError:
        await audit("none", None, outcome="failure", result="hash_mismatch", sha256_recomputed=computed)
        await db.commit()
        return _hash_mismatch()

    def read_error(e: EvidenceCryptoError) -> HTTPException:
        if isinstance(e, EvidenceIntegrityError):
            return _integrity_failed()
        if e.reason in ("file_missing", "invalid_path"):
            return HTTPException(status.HTTP_404_NOT_FOUND, "File data missing on disk")
        return _read_failed()

    await lock_upload_sha256(db, incident_id, ef.sha256)          # M8: one exhibit per bytes, until commit
    match = await unique_sha256_match(db, incident_id, ef.sha256, oldest=True)
    if match is not None:
        try:
            computed = await asha256_decrypted(ef.file_path, ef.nonce_hex, ef.file_size, root=settings.logs_path)
        except EvidenceCryptoError as e:
            raise read_error(e) from None
        if computed != ef.sha256:
            raise await mismatch(computed)
        ef.evidence_id = match.id
        await audit("sha256_match", match)
        await db.commit()
        return await out(match, "sha256_match")

    require_free_space(codec.container_size(ef.file_size), "this exhibit")   # evidence volume; 507, nothing stored
    prefill, left_empty = capture.exhibit_prefill(ef)              # S5: the new draft's fields from the capture record
    prefilled = {k: capture.jsonable(v) for k, v in prefill.items()}
    noted = {**({"prefilled_from_capture": prefilled} if prefilled else {}),
             **({"prefill_left_empty": left_empty} if left_empty else {})}
    ev_id = uuid.uuid4()
    filename, rel = draft_storage_path(incident_id, ev_id, ef.original_name)

    def accept(stored: StoredFile) -> None:                       # before the copy is moved into place
        if stored.sha256 != ef.sha256 or stored.size != ef.file_size:
            raise _HashMismatch(stored.sha256)

    try:
        stored = await write_encrypted_stream(
            read_decrypted_stream(ef.file_path, ef.nonce_hex, ef.file_size, root=settings.logs_path),
            rel, accept=accept)                                   # F-12: complete only if the stream ended cleanly
    except _HashMismatch as m:
        raise await mismatch(m.computed) from None
    except EvidenceCryptoError as e:
        raise read_error(e) from None
    try:
        ev = await register_draft(
            db, incident_id=incident_id, user=user, ev_id=ev_id, filename=filename, stored=stored,
            mime_type=ef.content_type, name=f"Supporting document: {ef.original_name}",
            method="supporting_document", analyser_label="Supporting documents", ip=ip,
            acquired_at=prefill.get("acquired_at"), upload_hash_check=prefill.get("upload_hash_check", "not_checked"),
            extra={"source": "supporting_document", "file_id": str(ef.id), **noted})
        for k, v in prefill.items():
            setattr(ev, k, v)
        ev.description = (f"Draft exhibit registered from the supporting document {ef.original_name} "
                          f"(file {ef.id}, uploaded {_z(ef.uploaded_at)}). Complete the acquisition record and seal it.")
        ef.evidence_id = ev.id
        await audit("registered", ev, **noted)
        await db.commit()
    except BaseException:
        await adelete_encrypted(rel)                              # no row, so no copy left behind
        raise
    return await out(ev, "registered", _prefill_out(prefill, left_empty))
