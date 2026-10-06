"""G1 stage 3b (R80) — chunked, resumable uploads, encrypted as they arrive.

    POST   /api/incidents/{id}/uploads                              open a session (201)
    GET    /api/incidents/{id}/uploads                              your open sessions (M7, G-fix B)
    GET    /api/incidents/{id}/uploads/{upload_id}                  its progress
    PUT    /api/incidents/{id}/uploads/{upload_id}/chunks/{index}   one chunk, raw octet-stream
    POST   /api/incidents/{id}/uploads/{upload_id}/complete         check, store, register (201 / 200)
    DELETE /api/incidents/{id}/uploads/{upload_id}                  abort (204)

Why (before G-fix R80, multipart spools moved to the RAM-only tmpfs): Starlette spools a multipart
body over 1 MiB to the backend's /tmp (the backend-scratch
volume) in plaintext before a route sees it (R80). Here every chunk is read from the request
stream into memory (≤ 8 MiB), hashed (SHA-256 / SHA-1 / MD5) and AES-256-GCM encrypted (FENRGCM
v2) into <evidence_path>/.staging/<random>.partial (crypto.EncryptedStagingWriter): the plaintext
never reaches a disk. `complete` runs the checks on the streamed hashes (the client's
expected_hash, then the purpose's own check) and only then moves the file into place and writes the
row, exactly as the multipart route for that purpose does: evidence = collect_digital's helpers
(C3 target hash, evidence_collect / evidence_collect_rejected); email / pcap / webhistory = G3's
unique_sha256_match + register_draft (a new unsealed draft exhibit, or the one active exhibit with
the same SHA-256 — then the upload's own copy is deleted). The analysis is then run through the
analyser's …/from-evidence/{evidence_id} route. Nothing is stored before `complete` succeeds.

Protocol:
  * every chunk is exactly CHUNK_SIZE (8 MiB, under Caddy's 10 MiB non-multipart limit) except the
    last (the remainder); chunks go strictly in order — the only accepted index is next_index.
    Anything else is refused and changes nothing (409 upload_out_of_order, with next_index): a
    client that lost a response re-reads GET …/{upload_id} and continues from next_index, so a
    chunk is never applied twice (no idempotent re-send: the server keeps no copy to compare with).
  * one request at a time per session (409 upload_busy);
  * a session belongs to the user who opened it, for that incident: anyone else gets 404; access to
    the incident (and, for writes, that it is not closed) is re-checked on every call;
  * at most MAX_OPEN_PER_USER open sessions per user (409 upload_limit_reached, whose `open_uploads` lists
    them so the client can resume or cancel one; GET …/uploads lists the ones on an incident — M7);
  * `metadata` at create (optional, L12) is validated with the purpose's `complete` schema before any byte
    is sent, and not stored; `complete` validates its own body again;
  * G2: the evidence volume must have room (statvfs): at create for the whole file plus what the other
    open sessions still have to send, at complete for nothing more, each plus a 1 GiB reserve; else 507
    insufficient_storage (nothing changes: at complete the session stays open).

Sessions live in this process: the hash and cipher state cannot be serialised, so a backend restart
ends every open session — the client gets 404 upload_not_found and starts again; the startup sweep
(crypto.sweep_staging) deletes the orphaned partial files. A session that receives no chunk for
IDLE_TTL is aborted and its partial deleted, lazily on the next call or by the reaper (every
REAP_EVERY_SECONDS, which also runs the staging sweep). Audited: upload_session_create /
_complete / _abort (sizes and hashes, never content), plus the purpose's normal rows.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import PurePosixPath
from typing import Optional

import anyio
from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response, status
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from sqlalchemy import select
from starlette.requests import ClientDisconnect
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import require_analyst
from core.config import settings
from core.database import SessionLocal, get_db
from core.errors import ApiError, ApiErrorBody
from email_analyzer.parser import is_msg
from email_analyzer.routes import MAX_EMAIL_BYTES
from evidence import codec, crypto, exports
from evidence.crypto import EncryptedStagingWriter, EvidenceCryptoError, StoredFile
from evidence.hashing import hash_algorithm
from evidence.register import draft_storage_path, lock_upload_sha256, register_draft, unique_sha256_match
from evidence.routes import (_ALGORITHM_LABEL, _UploadRefused, _check_acquired_at, _normalise_hash,
                             _resolve_entity, _storage_path_for, _to_out, audit_collect_rejected,
                             create_digital_evidence, digital_intake)
from evidence.streaming import require_free_space
from incidents.access import get_accessible_incident, require_incident_person
from models import Evidence, Incident, User, utcnow
from pcap.routes import _MAX_PCAP_BYTES, _is_capture
from schemas import (UploadComplete, UploadCompleteEmail, UploadCompleteEvidence, UploadCompleteOut,
                     UploadCompletePcap, UploadCompleteWebHistory, UploadSessionCreate, UploadSessionList,
                     UploadSessionOut)
from webhistory.parser import SQLITE_MAGIC
from webhistory.routes import MAX_UPLOAD_BYTES as MAX_WEBHISTORY_BYTES

log = logging.getLogger("fenrir.evidence.uploads")
router = APIRouter()

CHUNK_SIZE = 8 * 1024 * 1024          # a multiple of the codec's 1 MiB chunk
IDLE_TTL = timedelta(minutes=30)
MAX_OPEN_PER_USER = 3
REAP_EVERY_SECONDS = 60
_HEAD_LEN = 64                        # first plaintext bytes kept in memory for the content checks

_MIB = 1024 * 1024
# G3 analysers: identifier prefix, the audit method and the label register_or_link_upload uses.
_G3 = {
    "email":      ("EMAIL", "email_upload", "Email analyser"),
    "pcap":       ("PCAP", "pcap_upload", "PCAP analyser"),
    "webhistory": ("WEBHIST", "webhistory_upload", "Browser history"),
}


# L12: the `complete` body schema of each purpose (also used to check the optional metadata preview at create).
_COMPLETE_MODEL = {"evidence": UploadCompleteEvidence, "email": UploadCompleteEmail, "pcap": UploadCompletePcap,
                   "webhistory": UploadCompleteWebHistory}


def _cap(purpose: str) -> int:
    return {"evidence": settings.evidence_max_upload_bytes, "email": MAX_EMAIL_BYTES,
            "pcap": _MAX_PCAP_BYTES, "webhistory": MAX_WEBHISTORY_BYTES}[purpose]


@dataclass(eq=False)
class _Session:
    id:            uuid.UUID
    incident_id:   uuid.UUID
    user_id:       uuid.UUID
    username:      str
    purpose:       str
    filename:      str
    size:          int
    mime_type:     Optional[str]
    expected_hash: Optional[str]
    writer:        EncryptedStagingWriter
    created_at:    datetime
    expires_at:    datetime
    received:      int = 0
    next_index:    int = 0
    head:          bytes = b""
    state:         str = "open"            # open → completing → ended (or open → ended)
    lock:          asyncio.Lock = field(default_factory=asyncio.Lock)

    @property
    def chunk_count(self) -> int:
        return -(-self.size // CHUNK_SIZE)

    def chunk_len(self, index: int) -> int:
        return min(CHUNK_SIZE, self.size - index * CHUNK_SIZE)


_SESSIONS: dict[uuid.UUID, _Session] = {}
_create_lock = asyncio.Lock()


# ─── helpers ──────────────────────────────────────────────────────────────────────────────────

def _ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


def _out(s: _Session) -> UploadSessionOut:
    return UploadSessionOut(upload_id=s.id, incident_id=s.incident_id, purpose=s.purpose, filename=s.filename,
                            size=s.size, chunk_size=CHUNK_SIZE, chunk_count=s.chunk_count,
                            next_index=s.next_index, received_bytes=s.received, created_at=s.created_at,
                            expires_at=s.expires_at)


def _mine(user_id: uuid.UUID) -> list[_Session]:
    """The user's sessions (open or completing), oldest first."""
    return sorted((x for x in _SESSIONS.values() if x.user_id == user_id), key=lambda x: x.created_at)


def _check_metadata_preview(purpose: str, metadata: Optional[dict]) -> None:
    """L12: validate the optional `metadata` preview with the purpose's `complete` schema (nothing is stored).
    A schema error is the standard 422 request-validation body, located under body.metadata."""
    if metadata is None:
        return
    if "purpose" in metadata and metadata["purpose"] != purpose:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "purpose_mismatch",
                       f"metadata.purpose is {metadata['purpose']!r} but the upload is opened for purpose={purpose}; "
                       "leave purpose out of metadata.")
    try:
        _COMPLETE_MODEL[purpose].model_validate({**metadata, "purpose": purpose})
    except ValidationError as e:
        raise RequestValidationError([{**err, "loc": ("body", "metadata", *err["loc"])}
                                      for err in e.errors(include_url=False)]) from None


def _progress(s: _Session) -> dict:
    return {"next_index": s.next_index, "chunk_count": s.chunk_count, "received_bytes": s.received}


def _still_to_write() -> int:
    """Stored bytes the open sessions have not written yet (they already hold what has arrived)."""
    return sum(max(0, codec.container_size(x.size) - x.received) for x in _SESSIONS.values() if x.state == "open")


def _not_found() -> ApiError:
    return ApiError(status.HTTP_404_NOT_FOUND, "upload_not_found",
                    "No such upload session. It may have expired, been cancelled or completed, or the server "
                    "restarted: nothing was stored from it. Start the upload again.")


def _busy(s: _Session) -> ApiError:
    return ApiError(status.HTTP_409_CONFLICT, "upload_busy",
                    "Another request for this upload is still running: wait for it, then read the upload's "
                    "status (GET) and continue from next_index.", extra=_progress(s))


async def _incident(db: AsyncSession, incident_id: uuid.UUID, user: User, *, writable: bool) -> Incident:
    try:
        inc = await get_accessible_incident(db, incident_id, user)
    except HTTPException as e:
        if e.status_code == status.HTTP_404_NOT_FOUND:
            raise ApiError(status.HTTP_404_NOT_FOUND, "incident_not_found", "Incident not found") from None
        raise
    if writable and inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")
    return inc


async def _audit(db: AsyncSession, action: str, s: _Session, *, ip: Optional[str], outcome: str = "success",
                 **details) -> None:
    await write_audit(
        db, action, user_id=s.user_id, username=s.username, outcome=outcome,
        resource_type="upload_session", resource_id=str(s.id),
        details={"incident_id": str(s.incident_id), "purpose": s.purpose, "filename": s.filename,
                 "size": s.size, **details},
        ip_address=ip)


async def _end(s: _Session) -> None:
    """Forget the session and delete its partial file (a no-op once committed or aborted)."""
    s.state = "ended"
    _SESSIONS.pop(s.id, None)
    await s.writer.aabort()


async def _expire(db: AsyncSession, s: _Session, *, ip: Optional[str] = None) -> None:
    await _end(s)
    await _audit(db, "upload_session_abort", s, ip=ip, outcome="failure", reason="expired",
                 received_bytes=s.received, idle_ttl_minutes=int(IDLE_TTL.total_seconds() // 60))


def _expired(s: _Session) -> bool:
    return s.state == "open" and s.expires_at <= utcnow() and not s.lock.locked()


async def reap_expired(db: AsyncSession, *, user_id: Optional[uuid.UUID] = None) -> int:
    """Abort every idle session (of `user_id`, or all): partial deleted, audited. Commits."""
    n = 0
    for s in list(_SESSIONS.values()):
        if (user_id is None or s.user_id == user_id) and _expired(s):
            await _expire(db, s)
            n += 1
    if n:
        await db.commit()
    return n


async def _session_for(db: AsyncSession, incident_id: uuid.UUID, upload_id: uuid.UUID, user: User, *,
                       writable: bool) -> _Session:
    await _incident(db, incident_id, user, writable=writable)
    s = _SESSIONS.get(upload_id)
    if s is None or s.user_id != user.id or s.incident_id != incident_id:
        raise _not_found()
    if _expired(s):                       # lazy expiry (the reaper may not have run yet)
        await _expire(db, s)
        await db.commit()
        raise _not_found()
    return s


def _safe_filename(name: str) -> str:
    base = PurePosixPath(name.replace("\\", "/")).name
    if not base or base in (".", "..") or any(ord(c) < 32 or ord(c) == 127 for c in base):
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_filename",
                       "filename must be a file name (no path, no control characters)")
    return base


async def _drain(request: Request) -> None:
    """Read and drop up to one chunk of a body we refuse, so the refusal reaches the client through
    the proxy as a normal response."""
    n = 0
    try:
        async for piece in request.stream():
            n += len(piece)
            if n > CHUNK_SIZE:
                break
    except Exception:
        pass


# ─── routes ───────────────────────────────────────────────────────────────────────────────────

_E = lambda d: {"model": ApiErrorBody, "description": d}          # noqa: E731
_NOT_FOUND = {404: _E("incident_not_found, upload_not_found (unknown, someone else's, expired, cancelled, "
                      "completed, or lost by a server restart: start again)")}


@router.post(
    "/{incident_id}/uploads", response_model=UploadSessionOut, status_code=status.HTTP_201_CREATED,
    summary="Open a chunked upload session (encrypted on arrival)",
    responses={404: _E("incident_not_found"),
               409: _E("incident_closed or upload_limit_reached (`open_uploads` in the body: your open sessions "
                       "{upload_id, incident_id, purpose, filename, size, received_bytes, next_index, expires_at, …} "
                       "— resume one, or cancel it with DELETE …/incidents/{incident_id}/uploads/{upload_id})"),
               413: _E("upload_too_large (size over the purpose's cap)"),
               422: _E("invalid_filename, invalid_hash_format (expected_hash), empty_file, purpose_mismatch "
                       "(metadata.purpose differs), or a request-validation error — also for `metadata` (the "
                       "standard validation body, loc body.metadata.…; nothing was opened)"),
               503: _E("upload_storage_error (no staging file could be created)"),
               507: _E("insufficient_storage (the evidence volume has no room for the file, the other open "
                       "uploads and a 1 GiB reserve; nothing was opened)")},
)
async def create_upload_session(
    incident_id: uuid.UUID,
    body: UploadSessionCreate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> UploadSessionOut:
    """Open an upload session for one file of exactly `size` bytes, then send it with PUT
    …/uploads/{upload_id}/chunks/{index} (raw `application/octet-stream`, `chunk_size` bytes each
    except the last, index 0, 1, … in order) and finish with POST …/complete. Every chunk is hashed
    (SHA-256 / SHA-1 / MD5) and AES-256-GCM encrypted as it arrives into a staging file: the
    plaintext never reaches the server's disk, and nothing is stored until `complete` succeeds.

    Caps by purpose: evidence 10 GiB by default (the server's EVIDENCE_MAX_UPLOAD_BYTES), email
    25 MiB, pcap 500 MiB, webhistory 500 MiB (413 upload_too_large); an email / pcap / webhistory
    file cannot be empty (422 empty_file). The evidence volume must have room for the file, for
    what the other open uploads still have to send, and a 1 GiB reserve (507 insufficient_storage).
    `expected_hash` (optional, MD5 / SHA-1 / SHA-256 hex) is compared at `complete` with the hash
    of the bytes received. `metadata` (optional) previews the `complete` body: it is validated now with
    the same schema (enum values in its description) and not stored, so a bad field fails before the
    upload (422). At most 3 open sessions per user (409 upload_limit_reached, listing them in
    `open_uploads`; GET …/uploads lists yours on an incident). The session
    lives in this server process: it ends after 30 minutes without a chunk, and a server restart
    ends it (then 404 upload_not_found: start again). Requires the analyst role and an open
    incident (409 incident_closed); only the user who opened a session can use it. Audited
    `upload_session_create`. Returns the session (201)."""
    await _incident(db, incident_id, user, writable=True)
    filename = _safe_filename(body.filename)
    cap = _cap(body.purpose)
    if body.size > cap:
        raise ApiError(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "upload_too_large",
                       f"The file is larger than the {cap // _MIB} MiB limit for {body.purpose} uploads")
    if body.size == 0 and body.purpose != "evidence":
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "empty_file", "The file is empty")
    expected = _normalise_hash(body.expected_hash, "expected_hash")
    _check_metadata_preview(body.purpose, body.metadata)
    await reap_expired(db, user_id=user.id)
    async with _create_lock:
        mine = _mine(user.id)
        if len(mine) >= MAX_OPEN_PER_USER:
            raise ApiError(status.HTTP_409_CONFLICT, "upload_limit_reached",
                           f"You already have {MAX_OPEN_PER_USER} uploads open: finish or cancel one first "
                           "(open_uploads lists them).",
                           extra={"open_uploads": [_out(x).model_dump(mode="json") for x in mine]})
        require_free_space(codec.container_size(body.size) + _still_to_write(), "this upload")
        try:
            writer = await EncryptedStagingWriter.aopen()
        except OSError as e:
            log.error("upload: could not create a staging file: %s", e)
            raise ApiError(status.HTTP_503_SERVICE_UNAVAILABLE, "upload_storage_error",
                           "The server could not create a staging file for the upload. Try again later or "
                           "ask an admin to check the evidence storage.") from None
        now = utcnow()
        s = _Session(id=uuid.uuid4(), incident_id=incident_id, user_id=user.id, username=user.username,
                     purpose=body.purpose, filename=filename, size=body.size,
                     mime_type=body.mime_type if body.purpose == "evidence" else None,
                     expected_hash=expected, writer=writer, created_at=now, expires_at=now + IDLE_TTL)
        _SESSIONS[s.id] = s
    try:
        await _audit(db, "upload_session_create", s, ip=_ip(request), chunk_size=CHUNK_SIZE,
                     chunk_count=s.chunk_count, expected_hash=expected)
        await db.commit()
    except BaseException:
        await _end(s)
        raise
    return _out(s)


@router.get(
    "/{incident_id}/uploads", response_model=UploadSessionList,
    summary="List your open upload sessions on an incident", responses={404: _E("incident_not_found")},
)
async def list_upload_sessions(
    incident_id: uuid.UUID,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> UploadSessionList:
    """M7: your own open upload sessions on this incident (oldest first): `upload_id`, `purpose`,
    `filename`, `size`, `received_bytes`, `next_index`, `expires_at`, … — resume one (PUT the chunk at
    `next_index`) or cancel it (DELETE …/uploads/{upload_id}) to get under the limit of 3 open
    sessions per user. Other users' sessions are never listed (a session belongs to the user who
    opened it). Idle sessions are expired first. Sessions live in the server process: after a restart
    the list is empty. Requires the analyst role and access to the incident (allowed when closed, so a
    session can still be found and cancelled). A single page: `next_cursor` is always null."""
    await _incident(db, incident_id, user, writable=False)
    await reap_expired(db, user_id=user.id)
    return UploadSessionList(items=[_out(x) for x in _mine(user.id) if x.incident_id == incident_id])


@router.get(
    "/{incident_id}/uploads/{upload_id}", response_model=UploadSessionOut,
    summary="Read an upload session's progress", responses=_NOT_FOUND,
)
async def get_upload_session(
    incident_id: uuid.UUID,
    upload_id: uuid.UUID,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> UploadSessionOut:
    """The session's progress: `next_index` (the only chunk index the next PUT accepts),
    `received_bytes`, `expires_at`. Use it to resume after a failed or unanswered chunk. Only the
    user who opened the session (404 otherwise)."""
    return _out(await _session_for(db, incident_id, upload_id, user, writable=False))


@router.put(
    "/{incident_id}/uploads/{upload_id}/chunks/{index}", response_model=UploadSessionOut,
    summary="Send one chunk (raw application/octet-stream body)",
    openapi_extra={"requestBody": {"required": True, "content": {
        "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}}},
    responses={**_NOT_FOUND,
               400: _E("client_disconnected (the connection closed before the whole chunk arrived: nothing "
                       "changed; GET the session and continue from next_index)"),
               409: _E("incident_closed, upload_out_of_order (next_index in the body: nothing changed) or "
                       "upload_busy (another request for this upload is running)"),
               413: _E("chunk_too_large (over chunk_size) or upload_too_large (past the declared size)"),
               415: _E("unsupported_media_type (Content-Type must be application/octet-stream)"),
               422: _E("chunk_length_mismatch (a chunk other than the last must be exactly chunk_size, the "
                       "last exactly the remainder; nothing changed)"),
               503: _E("upload_storage_error (the staging write failed: the upload is cancelled, start again)")},
)
async def put_upload_chunk(
    incident_id: uuid.UUID,
    upload_id: uuid.UUID,
    request: Request,
    index: int = Path(ge=0),
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> UploadSessionOut:
    """Append chunk `index` (must equal the session's `next_index`) as the raw request body, read
    from the request stream (never multipart, never spooled) and encrypted into the session's
    staging file. A refused chunk changes nothing: on any failure or lost response, GET the session
    and continue from `next_index`. Each accepted chunk extends `expires_at`. Returns the session."""
    try:
        if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/octet-stream":
            raise ApiError(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type",
                           "Send the chunk as the raw body with Content-Type: application/octet-stream")
        s = await _session_for(db, incident_id, upload_id, user, writable=True)
        await db.commit()                     # release the DB connection while the body streams in
        if s.lock.locked():
            raise _busy(s)
    except ApiError:
        await _drain(request)
        raise
    async with s.lock:
        if s.state != "open":
            await _drain(request)
            raise _not_found()
        if index != s.next_index or s.next_index >= s.chunk_count:
            await _drain(request)
            raise ApiError(status.HTTP_409_CONFLICT, "upload_out_of_order",
                           (f"Expected chunk {s.next_index}, got {index}: nothing changed. Continue from "
                            f"next_index." if s.next_index < s.chunk_count else
                            "Every chunk has arrived: complete the upload."), extra=_progress(s))
        want = s.chunk_len(index)
        buf = bytearray()
        try:
            async for piece in request.stream():
                buf += piece
                if len(buf) > want:
                    break
        except ClientDisconnect:              # the client went away mid-chunk (e.g. cancelled): nothing changed
            raise ApiError(status.HTTP_400_BAD_REQUEST, "client_disconnected",
                           "The connection closed before the chunk arrived; nothing changed.") from None
        if len(buf) > CHUNK_SIZE:
            raise ApiError(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "chunk_too_large",
                           f"A chunk is at most {CHUNK_SIZE} bytes: nothing changed.", extra=_progress(s))
        if len(buf) > want:
            raise ApiError(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "upload_too_large",
                           f"Chunk {index} would go past the declared size ({s.size} bytes): it must be "
                           f"{want} bytes. Nothing changed.", extra=_progress(s))
        if len(buf) < want:
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "chunk_length_mismatch",
                           f"Chunk {index} must be exactly {want} bytes, got {len(buf)}. Nothing changed.",
                           extra=_progress(s))
        if s.state != "open":                 # cancelled while the body was arriving
            raise _not_found()
        if s.writer.size != s.received:       # R3-4: the staged file must hold exactly what was accepted
            await _storage_failed(db, s, request, f"staged {s.writer.size} bytes, accepted {s.received}")
        try:
            await s.writer.awrite(buf)
        except asyncio.CancelledError:
            # R3-4: cancelled while the chunk was being written: whether it reached the staged file is
            # unknown, so the session can't continue. End it (its partial is deleted), then let the
            # cancellation through.
            with anyio.CancelScope(shield=True):
                await _end(s)
            raise
        except EvidenceCryptoError:          # aborted meanwhile (cancel / expiry)
            raise _not_found() from None
        except OSError as e:
            log.error("upload %s: staging write failed: %s", s.id, e)
            await _end(s)
            await _audit(db, "upload_session_abort", s, ip=_ip(request), outcome="failure",
                         reason="storage_error", received_bytes=s.received)
            await db.commit()
            raise ApiError(status.HTTP_503_SERVICE_UNAVAILABLE, "upload_storage_error",
                           "The server could not write the upload to its staging area; the upload was "
                           "cancelled and nothing was stored. Try again later or ask an admin to check the "
                           "evidence storage.") from None
        if index == 0:
            s.head = bytes(buf[:_HEAD_LEN])
        s.received += want
        s.next_index += 1
        s.expires_at = utcnow() + IDLE_TTL
        return _out(s)


@router.post(
    "/{incident_id}/uploads/{upload_id}/complete", response_model=UploadCompleteOut,
    status_code=status.HTTP_201_CREATED,
    summary="Complete an upload: check it, store it and register the exhibit",
    responses={200: {"model": UploadCompleteOut,
                     "description": "sha256_match: the one active exhibit with the same SHA-256 (G3 purposes); "
                                    "the upload's own copy was deleted"},
               404: _E("incident_not_found, upload_not_found (unknown, someone else's, expired, cancelled, completed, "
                       "or lost by a server restart: start again), user_not_found (witness_user_id), evidence_not_found "
                       "(webhistory companion_of), or the entity_id is not in the incident; the last three leave the "
                       "session open"),
               409: _E("incident_closed, upload_incomplete (not every byte has arrived: next_index in the "
                       "body), upload_busy, identifier_exists (evidence; nothing stored — the session stays "
                       "open: complete again with another identifier) or upload_completing"),
               413: _E("upload_too_large (purpose evidence: the server's cap was lowered below the file's size "
                       "after the session opened; nothing stored)"),
               422: _E("purpose_mismatch, upload_hash_mismatch (expected_hash; nothing stored), hash_mismatch "
                       "(C3 target hash; nothing stored), not_a_capture (pcap; nothing stored), not_sqlite "
                       "(webhistory; nothing stored), form_history_not_firefox, invalid_hash_format, "
                       "acquired_in_future, assignee_no_access, or a request-body validation error. The ones "
                       "marked 'nothing stored' end the session; the others leave it open."),
               503: _E("upload_storage_error (the staged file could not be finalised; nothing stored)"),
               507: _E("insufficient_storage (the evidence volume is below its 1 GiB reserve: nothing stored, "
                       "the session stays open; free space, then complete again or cancel)")},
)
async def complete_upload_session(
    incident_id: uuid.UUID,
    upload_id: uuid.UUID,
    body: UploadComplete,
    request: Request,
    response: Response,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> UploadCompleteOut:
    """Finish the upload once every byte has arrived. The body repeats the session's `purpose`
    (discriminator) with the same metadata the multipart route for that purpose takes:

    - **evidence** — the POST …/evidence/digital fields as JSON (name, identifier, acquisition
      record, C3 `acquisition_hash_target` + `target_hash_scope`). Creates the exhibit exactly as
      that route does (`evidence_collect`; a refused target hash → 422 hash_mismatch, audited
      `evidence_collect_rejected`, nothing stored). 201, exhibit_link `collected`.
    - **email** / **pcap** / **webhistory** — `acquired_at` (+ `browser`, and `companion_of` for a
      Firefox formhistory.sqlite). Registers the file as an unsealed draft exhibit exactly as the
      analyser's G3 upload does (201, `registered`), or links the one active exhibit with the same
      SHA-256 and deletes the upload's copy (200, `sha256_match`). Then analyse it with
      POST …/email|pcap|webhistory/from-evidence/{evidence_id}.

    Before anything is stored: `expected_hash` (if given at create) must match the bytes received
    (422 upload_hash_mismatch), a pcap must be pcap / pcapng (422 not_a_capture) and a browser
    history SQLite (422 not_sqlite) — each of these deletes the staged file and ends the session.
    Input errors (bad witness, entity, hash format, time, identifier taken) leave the session open
    to complete again, and so does 507 insufficient_storage (the evidence volume is below its 1 GiB
    reserve). Requires the analyst role, an open incident, and the session's owner.
    Audited `upload_session_complete` (hashes, size, the exhibit). Returns the exhibit."""
    s = await _session_for(db, incident_id, upload_id, user, writable=True)
    if s.lock.locked():
        raise _busy(s)
    async with s.lock:
        if s.state != "open":
            raise _not_found()
        if body.purpose != s.purpose:
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "purpose_mismatch",
                           f"This upload was opened for purpose={s.purpose}; complete it with that purpose.")
        if s.received != s.size:
            raise ApiError(status.HTTP_409_CONFLICT, "upload_incomplete",
                           f"{s.received} of {s.size} bytes have arrived: send the remaining chunks first.",
                           extra=_progress(s))
        require_free_space(0, "a new exhibit")          # the file is already staged; keep the reserve
        ip = _ip(request)
        if isinstance(body, UploadCompleteEvidence):
            final = await _prepare_evidence(db, s, body)
        else:
            final = await _prepare_g3(db, s, body)
        s.state = "completing"
        try:
            ev, link = await final(db, request, user, ip)
        except BaseException:
            await _end(s)
            raise
        await _end(s)
    if link == "sha256_match":
        response.status_code = status.HTTP_200_OK
    return UploadCompleteOut(upload_id=s.id, purpose=s.purpose, exhibit_link=link, evidence_id=ev.id,
                             evidence=_to_out(ev))


@router.delete(
    "/{incident_id}/uploads/{upload_id}", status_code=status.HTTP_204_NO_CONTENT,
    summary="Cancel an upload session (its staged file is deleted)",
    responses={**_NOT_FOUND, 409: _E("upload_completing (it is being completed)")},
)
async def abort_upload_session(
    incident_id: uuid.UUID,
    upload_id: uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Cancel the upload: the staged (encrypted) partial file is deleted and nothing is stored.
    Allowed on a closed incident. Only the user who opened it. Audited `upload_session_abort`
    (reason cancelled). 204."""
    s = await _session_for(db, incident_id, upload_id, user, writable=False)
    if s.state == "completing":
        raise ApiError(status.HTTP_409_CONFLICT, "upload_completing",
                       "The upload is being completed and can't be cancelled now.")
    await _end(s)
    await _audit(db, "upload_session_abort", s, ip=_ip(request), reason="cancelled", received_bytes=s.received)
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ─── complete: per purpose ────────────────────────────────────────────────────────────────────
# _prepare_* checks the metadata while the session is still open (an error leaves it open) and
# returns the final step, which ends the session whatever happens.

async def _storage_failed(db: AsyncSession, s: _Session, request: Request, why: str) -> None:
    """R3-4: the staged file and the session disagree: end the session (nothing stored) → 503."""
    log.error("upload %s: %s; the upload is cancelled", s.id, why)
    await _end(s)
    await _audit(db, "upload_session_abort", s, ip=_ip(request), outcome="failure", reason="storage_error",
                 received_bytes=s.received, detail=why)
    await db.commit()
    raise ApiError(status.HTTP_503_SERVICE_UNAVAILABLE, "upload_storage_error",
                   "The server's staged copy of the upload does not match what it accepted; the upload was "
                   "cancelled and nothing was stored. Start again.")


async def _finish(db: AsyncSession, s: _Session, ip: Optional[str]) -> StoredFile:
    """Finalise the staged file; check the client's expected_hash (422 upload_hash_mismatch)."""
    try:
        stored = await s.writer.afinish()
    except EvidenceCryptoError:
        raise _not_found() from None
    except OSError as e:
        log.error("upload %s: finalising the staged file failed: %s", s.id, e)
        await _audit(db, "upload_session_abort", s, ip=ip, outcome="failure", reason="storage_error",
                     received_bytes=s.received)
        await db.commit()
        raise ApiError(status.HTTP_503_SERVICE_UNAVAILABLE, "upload_storage_error",
                       "The server could not finalise the uploaded file; nothing was stored. Start again.") from None
    if stored.size != s.size:                 # R3-4 / L1: the stored file holds exactly the declared size
        log.error("upload %s: staged %d bytes, declared %d; nothing stored", s.id, stored.size, s.size)
        await _audit(db, "upload_session_abort", s, ip=ip, outcome="failure", reason="size_mismatch",
                     received_bytes=s.received, staged_bytes=stored.size)
        await db.commit()
        raise ApiError(status.HTTP_503_SERVICE_UNAVAILABLE, "upload_storage_error",
                       "The server's staged copy of the upload is not the declared size; nothing was stored. "
                       "Start again.")
    if s.expected_hash:
        algo = hash_algorithm(s.expected_hash)
        got = getattr(stored, algo)
        if got != s.expected_hash:
            await _audit(db, "upload_session_abort", s, ip=ip, outcome="failure", reason="upload_hash_mismatch",
                         algorithm=algo, expected_hash=s.expected_hash, computed_hash=got,
                         received_bytes=s.received)
            await db.commit()
            label = _ALGORITHM_LABEL[algo]
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "upload_hash_mismatch",
                           f"The {label} of the bytes received is {got}, not the expected_hash given when the "
                           "upload was opened. Nothing was stored: upload the file again.")
    return stored


async def _refuse_content(db: AsyncSession, s: _Session, ip: Optional[str], code: str, detail: str) -> ApiError:
    await _audit(db, "upload_session_abort", s, ip=ip, outcome="failure", reason=code, received_bytes=s.received)
    await db.commit()
    return ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, code, detail)


async def _completed_audit(db: AsyncSession, s: _Session, ip: Optional[str], stored: StoredFile, ev: Evidence,
                           link: str) -> None:
    await _audit(db, "upload_session_complete", s, ip=ip, exhibit_link=link, evidence_id=str(ev.id),
                 evidence_identifier=ev.identifier, sha256=stored.sha256, sha1=stored.sha1, md5=stored.md5,
                 file_size_bytes=stored.size)


async def _prepare_evidence(db: AsyncSession, s: _Session, body: UploadCompleteEvidence):
    """collect_digital's checks, in its order (witness, entity, time + hashes), and the identifier."""
    witness_uid = None
    if body.witness_user_id:
        await require_incident_person(db, s.incident_id, body.witness_user_id, "the witness")
        witness_uid = body.witness_user_id
    entity_id = await _resolve_entity(db, s.incident_id, str(body.entity_id)) if body.entity_id else None
    intake = digital_intake(body.acquired_at, body.acquisition_hash_source, body.acquisition_hash_target,
                            body.target_hash_scope)
    if (await db.execute(select(Evidence.id).where(Evidence.incident_id == s.incident_id,
                                                   Evidence.identifier == body.identifier))).first():
        raise ApiError(status.HTTP_409_CONFLICT, "identifier_exists",
                       "Evidence identifier already exists on this incident: the upload is kept, complete it "
                       "again with another identifier.")
    fields = body.model_dump(exclude={"purpose", "entity_id", "witness_user_id", "acquisition_hash_source",
                                      "acquisition_hash_target", "target_hash_scope", "acquired_at"})
    fields.update(entity_id=entity_id, witness_user_id=witness_uid, device_types=body.device_types or None,
                  acquisition_tool_sha256=(body.acquisition_tool_sha256.lower()
                                           if body.acquisition_tool_sha256 else None))

    async def final(db: AsyncSession, request: Request, user: User, ip: Optional[str]):
        await _finish(db, s, ip)
        evidence_id = uuid.uuid4()
        rel = _storage_path_for(s.incident_id, evidence_id, s.filename)
        try:
            stored = await s.writer.acommit(rel, accept=intake.check)     # C3 on the streamed hash
        except _UploadRefused as refused:
            if refused.why == "too_large":            # the cap was lowered after the upload opened
                raise ApiError(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "upload_too_large",
                               f"Upload exceeds max {settings.evidence_max_upload_bytes} bytes") from None
            err = await audit_collect_rejected(db, request, user, s.incident_id, identifier=body.identifier,
                                               name=body.name, original_filename=s.filename, intake=intake,
                                               refused=refused, extra={"upload_id": str(s.id)})
            await _audit(db, "upload_session_abort", s, ip=ip, outcome="failure", reason="hash_mismatch",
                         received_bytes=s.received)
            await db.commit()
            raise err from None
        try:
            ev = await create_digital_evidence(db, request, user, s.incident_id, evidence_id=evidence_id,
                                               stored=stored, original_filename=s.filename, mime_type=s.mime_type,
                                               intake=intake, fields=fields, audit_extra={"upload_id": str(s.id)})
            await _completed_audit(db, s, ip, stored, ev, "collected")
            await db.commit()
        except BaseException:
            await crypto.adelete_encrypted(rel)       # no row: never leave the stored file behind
            raise
        return ev, "collected"
    return final


async def _prepare_g3(db: AsyncSession, s: _Session, body):
    """The G3 upload's checks and names (email_analyzer / pcap / webhistory upload routes)."""
    acquired_at = _check_acquired_at(body.acquired_at)
    prefix, method, label = _G3[s.purpose]
    extra: dict = {}
    if s.purpose == "email":
        src = PurePosixPath(s.filename).name or "message.eml"
        name, mime = f"Email message: {src}", ("application/vnd.ms-outlook" if is_msg(s.head) else "message/rfc822")
        bad = None
    elif s.purpose == "pcap":
        src = PurePosixPath(s.filename).name or "capture.pcap"
        name, mime = f"Network capture: {src}", "application/vnd.tcpdump.pcap"
        bad = None if _is_capture(s.head) else ("not_a_capture", "Not a valid PCAP or PCAPNG file; nothing was stored")
    else:
        assert isinstance(body, UploadCompleteWebHistory)
        mime = "application/vnd.sqlite3"
        extra = {"browser": body.browser}
        if body.companion_of is not None:
            if body.browser != "firefox":
                raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "form_history_not_firefox",
                               "companion_of (formhistory.sqlite) is only supported for browser=firefox")
            found = (await db.execute(select(Evidence.id).where(Evidence.id == body.companion_of,
                                                                Evidence.incident_id == s.incident_id))).first()
            if not found:
                raise ApiError(status.HTTP_404_NOT_FOUND, "evidence_not_found",
                               "companion_of: no such exhibit in this incident")
            src = PurePosixPath(s.filename).name or "formhistory.sqlite"
            name = f"Browser form history (firefox): {src}"
            extra["companion_of"] = str(body.companion_of)
        else:
            src = PurePosixPath(s.filename).name or "History"
            name = f"Browser history ({body.browser}): {src}"
        bad = (None if s.head[:16] == SQLITE_MAGIC else
               ("not_sqlite", "Not a SQLite database; nothing was stored"))

    async def final(db: AsyncSession, request: Request, user: User, ip: Optional[str]):
        if bad:
            raise await _refuse_content(db, s, ip, *bad)
        stored = await _finish(db, s, ip)
        await lock_upload_sha256(db, s.incident_id, stored.sha256)    # M8: one exhibit per bytes, until commit
        match = await unique_sha256_match(db, s.incident_id, stored.sha256, oldest=True)
        if match is not None:                          # G3: link it, keep no second copy
            await s.writer.aabort()
            await _completed_audit(db, s, ip, stored, match, "sha256_match")
            await db.commit()
            return match, "sha256_match"
        ev_id = uuid.uuid4()
        filename, rel = draft_storage_path(s.incident_id, ev_id, src)
        stored = await s.writer.acommit(rel)
        try:
            ev = await register_draft(db, incident_id=s.incident_id, user=user, ev_id=ev_id, filename=filename,
                                      stored=stored, mime_type=mime, prefix=prefix, name=name, method=method,
                                      analyser_label=label, acquired_at=acquired_at, ip=ip,
                                      extra={**extra, "upload_id": str(s.id)})
            await _completed_audit(db, s, ip, stored, ev, "registered")
            await db.commit()
        except BaseException:
            await crypto.adelete_encrypted(rel)
            raise
        return ev, "registered"
    return final


# ─── reaper (lifespan) ────────────────────────────────────────────────────────────────────────

_reaper: Optional[asyncio.Task] = None


async def _reap_loop() -> None:
    while True:
        await asyncio.sleep(REAP_EVERY_SECONDS)
        try:
            async with SessionLocal() as db:
                n = await reap_expired(db)
                if n:
                    log.info("upload reaper: aborted %d idle upload session(s)", n)
                stale = {root: await asyncio.to_thread(crypto.sweep_staging, root)
                         for root in (settings.evidence_path, settings.logs_path, settings.quarantine_path)}
                if any(stale.values()):
                    log.warning("upload reaper: removed stale staging files (idle > %d min): %s",
                                crypto.STALE_PARTIAL_MINUTES, stale)
                    await write_audit(db, "storage_staging_cleanup", outcome="success",
                                      details={"removed": stale, "older_than_minutes": crypto.STALE_PARTIAL_MINUTES,
                                               "by": "upload_reaper"})
                    await db.commit()
                # R105: custody exports left `pending` by a build that died with an earlier process.
                swept = await exports.sweep_stale_pending(db, by="upload_reaper")
                if swept:
                    log.warning("upload reaper: revoked %d abandoned pending export(s)", swept)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("upload reaper failed; retrying in %d s", REAP_EVERY_SECONDS)


def start_reaper() -> None:
    global _reaper
    _reaper = asyncio.create_task(_reap_loop(), name="upload-session-reaper")


async def stop_reaper() -> None:
    """Shutdown: stop the reaper and delete every open session's partial file (sessions cannot
    outlive the process)."""
    if _reaper is not None:
        _reaper.cancel()
        try:
            await _reaper
        except asyncio.CancelledError:
            pass
    open_sessions = list(_SESSIONS.values())
    for s in open_sessions:
        await _end(s)
    if open_sessions:
        log.warning("shutdown: cancelled %d open upload session(s); their staged files were deleted",
                    len(open_sessions))
