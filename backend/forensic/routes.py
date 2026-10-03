"""Forensic artifact parse endpoint + persisted import store.

Mounted at prefix="/api/incidents".

Flows:
  • /parse                              — stateless preview parse (kept for back-compat).
  • /imports                            — persist + list + reload + dispose.
    POST   /imports                      upload, parse, persist, return events
    GET    /imports                      list past imports for the incident
    GET    /imports/{import_id}          re-fetch parsed events
    POST   /imports/{import_id}/promote  copy events (by index) onto the timeline (C5)
    DELETE /imports/{import_id}          dispose (hard delete, audit-logged)
  • /from-evidence/{evidence_id}        — parse a registered exhibit, hash re-verified (C5)
  • /from-artifact/{artifact_id}        — parse an ingested Velociraptor collection

C5 honest timestamps: zone-less times are read in the operator-chosen `source_tz` (IANA) and every
parsed event carries a `time_basis` (forensic/parser.py). The timeline copy is made server-side
from the stored parse, so the browser never supplies an imported event's time; an event without a
time is never promoted.
"""
import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.config import settings
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from evidence.crypto import EvidenceIntegrityError, read_decrypted
from evidence.hashing import sha256_chunked
from incidents.access import get_accessible_incident
from models import Artifact, Evidence, ForensicImport, TimelineEvent, User, utcnow
from schemas import (ForensicImportDetail, ForensicImportFromEvidence, ForensicImportList,
                     ForensicImportPromote, ForensicImportPromoteResult,
                     ForensicImportSummary, ForensicParseResponse,
                     ParsedEventOut)

from .parser import PARSER_VERSION, parse_artifact, parse_velociraptor_collection, resolve_tz

router = APIRouter()

# Raised from 100 MB after a real Microsoft Entra ID Audit Log export for a
# single day (not even a month, unlike the sign-in log exports) came in at
# 178 MB for one tenant -- matches the cap already used for other large
# forensic uploads (Web Browser History).
_MAX_UPLOAD_BYTES = 500 * 1024 * 1024  # 500 MB

# from-evidence `parser` override -> the extension parse_artifact's detection keys on.
_PARSER_EXT = {"evtx": ".evtx", "xml": ".xml", "sqlite": ".db", "csv": ".csv", "tsv": ".tsv",
               "syslog": ".log", "json": ".json"}
_PROMOTE_CHUNK = 1000          # rows per INSERT (23 binds/row; asyncpg caps a statement at 32767)
_TIME_BASES_STORED = {"explicit", "assumed_tz", "inferred_year"}


def _events_from_raw(raw_events: list[dict]) -> list[ParsedEventOut]:
    return [
        ParsedEventOut(
            idx=i,
            event_time=ev.get("event_time"),
            hostname=ev.get("hostname"),
            source=ev.get("source"),
            event_type=ev.get("event_type"),
            description=ev.get("description", ""),
            raw_log=ev.get("raw_log"),
            mitre_tactic_id=ev.get("mitre_tactic_id"),
            mitre_tactic_name=ev.get("mitre_tactic_name"),
            mitre_technique_id=ev.get("mitre_technique_id"),
            mitre_technique_name=ev.get("mitre_technique_name"),
            suspicious=ev.get("suspicious", False),
            suspicious_reasons=ev.get("suspicious_reasons", []),
            time_basis=ev.get("time_basis"),
        )
        for i, ev in enumerate(raw_events)
    ]


def _parse_to_events(filename: str, content: bytes, source_tz: str, year_ref: Optional[datetime]
                     ) -> tuple[str, list[ParsedEventOut], list[dict], bool, int]:
    """Parse + build the API events + their stored form, plus the parser's truncation record
    (truncated, total_seen). CPU-bound: call via asyncio.to_thread."""
    detected_format, raw_events, truncated, total_seen = parse_artifact(
        filename, content, source_tz=source_tz, year_ref=year_ref)
    events = _events_from_raw(raw_events)
    return detected_format, events, [e.model_dump() for e in events], truncated, total_seen


def _validate_upload(content: bytes) -> None:
    if len(content) > _MAX_UPLOAD_BYTES:
        raise ApiError(
            status.HTTP_413_CONTENT_TOO_LARGE, "file_too_large",
            f"File exceeds the {_MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit "
            f"({len(content) // (1024 * 1024)} MB received)",
        )
    if not content:
        raise ApiError(status.HTTP_400_BAD_REQUEST, "file_empty", "Uploaded file is empty")


def _parse_failed(exc: Exception) -> ApiError:
    return ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "parse_failed", f"Failed to parse artifact: {exc}")


def _check_tz(source_tz: str) -> str:
    try:
        resolve_tz(source_tz)
    except ValueError as exc:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_source_tz", str(exc)) from exc
    return source_tz


def _year_reference(ev: Optional[Evidence]) -> Optional[datetime]:
    """What a year-less BSD-syslog line is dated against: the exhibit's acquisition time, else
    when it was registered (the upload time); None (= now, the import time) without an exhibit."""
    if ev is None:
        return None
    return ev.acquired_at or ev.collected_at


async def _evidence_identifiers(db: AsyncSession, ids) -> dict:
    ids = {i for i in ids if i}
    if not ids:
        return {}
    return dict((await db.execute(select(Evidence.id, Evidence.identifier).where(Evidence.id.in_(ids)))).all())


def _detail(row: ForensicImport, events: list[ParsedEventOut], identifier: Optional[str]) -> ForensicImportDetail:
    return ForensicImportDetail(
        id=row.id, filename=row.filename, file_size=row.file_size,
        mime_type=row.mime_type, sha256_hash=row.sha256_hash,
        detected_format=row.detected_format,
        event_count=row.event_count, suspicious_count=row.suspicious_count,
        uploaded_by=row.uploaded_by, uploaded_at=row.uploaded_at,
        evidence_id=row.evidence_id, evidence_identifier=identifier,
        parser_version=row.parser_version, source_tz=row.source_tz,
        truncated=row.truncated, total_seen=row.total_seen,
        events=events,
    )


async def _get_import(db: AsyncSession, incident_id: uuid.UUID, import_id: uuid.UUID, *, with_events: bool) -> ForensicImport:
    stmt = select(ForensicImport).where(ForensicImport.id == import_id, ForensicImport.incident_id == incident_id)
    if not with_events:
        stmt = stmt.options(defer(ForensicImport.parsed_events))
    row = (await db.execute(stmt)).scalar_one_or_none()
    if not row:
        raise ApiError(status.HTTP_404_NOT_FOUND, "forensic_import_not_found", "Forensic import not found")
    return row


# ─── Stateless preview (back-compat) ────────────────────────────────────────

@router.post(
    "/{incident_id}/forensic/timeline-import/parse",
    response_model=ForensicParseResponse,
    status_code=status.HTTP_200_OK,
    summary="Parse a forensic artifact and return candidate timeline events (stateless preview)",
    responses={400: {"model": ApiErrorBody, "description": "file_empty"},
               413: {"model": ApiErrorBody, "description": "file_too_large"},
               422: {"model": ApiErrorBody, "description": "invalid_source_tz or parse_failed"}},
)
async def parse_forensic_artifact(
    incident_id: uuid.UUID,
    file: UploadFile = File(...),
    source_tz: str = Form(default="UTC", max_length=64),
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> ForensicParseResponse:
    """Parse an uploaded forensic artifact and return candidate timeline events without persisting.

    Auto-detects the artifact format, extracts events, and flags suspicious ones; uploads
    are capped at 500 MB. `source_tz` (IANA, default UTC) is the zone of times that don't state
    one; each event's `time_basis` says how its time was worked out. `truncated` / `total_seen`
    say whether a parser cap cut the output and how many source records were read. Requires
    access to the incident. Returns the detected format, counts, and the parsed event list for
    preview.
    """
    await get_accessible_incident(db, incident_id, user)
    _check_tz(source_tz)
    content = await file.read()
    _validate_upload(content)
    filename = file.filename or "unknown"

    try:
        detected_format, events, _, truncated, total_seen = await asyncio.to_thread(
            _parse_to_events, filename, content, source_tz, None)
    except Exception as exc:
        raise _parse_failed(exc) from exc

    return ForensicParseResponse(
        source_file=filename,
        detected_format=detected_format,
        count=len(events),
        suspicious_count=sum(1 for e in events if e.suspicious),
        truncated=truncated,
        total_seen=total_seen,
        events=events,
    )


# ─── Import from an ingested collection artifact (U1.3) ──────────────────────

@router.post(
    "/{incident_id}/forensic/timeline-import/from-artifact/{artifact_id}",
    response_model=ForensicImportDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Parse an ingested Velociraptor collection artifact into a persisted import",
    responses={422: {"model": ApiErrorBody, "description": "parse_failed"}},
)
async def import_from_artifact(
    incident_id: uuid.UUID,
    artifact_id: uuid.UUID,
    request:     Request,
    user:        User       = Depends(require_analyst),
    db:          AsyncSession = Depends(get_db),
) -> ForensicImportDetail:
    """Target of the Collections tab "Review in Timeline Import" deep-link.

    Reads the collection ZIP straight from quarantine (no re-upload, no 100 MB
    cap) and parses the per-artifact JSONL into candidate timeline events. Times
    without a zone are read as UTC (recorded as source_tz UTC, time_basis assumed_tz).
    """
    await get_accessible_incident(db, incident_id, user)
    artifact = (await db.execute(
        select(Artifact).where(
            Artifact.id == artifact_id,
            Artifact.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not artifact:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Artifact not found")

    # Resolve + path-traversal guard, mirroring the artifacts module.
    path = (Path(settings.quarantine_path) / str(incident_id) / artifact.stored_filename).resolve()
    root = Path(settings.quarantine_path).resolve()
    if not str(path).startswith(str(root)) or not path.is_file():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Artifact file is no longer available")

    def _parse() -> tuple[list[ParsedEventOut], list[dict], bool, int]:
        raw, truncated, total_seen = parse_velociraptor_collection(str(path), source_tz="UTC")
        evs = _events_from_raw(raw)
        return evs, [e.model_dump() for e in evs], truncated, total_seen

    try:
        events, stored, truncated, total_seen = await asyncio.to_thread(_parse)
    except Exception as exc:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "parse_failed",
                       f"Failed to parse collection: {exc}") from exc

    suspicious = sum(1 for e in events if e.suspicious)

    row = ForensicImport(
        id               = uuid.uuid4(),
        incident_id      = incident_id,
        filename         = (artifact.original_filename or "collection.zip")[:512],
        file_size        = artifact.file_size,
        mime_type        = artifact.mime_type,
        sha256_hash      = artifact.sha256_hash,
        parser_version   = PARSER_VERSION,
        source_tz        = "UTC",
        detected_format  = "velociraptor",
        event_count      = len(events),
        suspicious_count = suspicious,
        truncated        = truncated,
        total_seen       = total_seen,
        parsed_events    = stored,
        uploaded_by_id   = user.id,
        uploaded_by      = user.username,
    )
    db.add(row)
    await write_audit(
        db, "forensic_import_create",
        user_id=user.id, username=user.username,
        resource_type="forensic_import", resource_id=str(row.id),
        details={
            "incident_id":     str(incident_id),
            "source_artifact": str(artifact_id),
            "detected_format": "velociraptor",
            "parser_version":  PARSER_VERSION,
            "source_tz":       "UTC",
            "event_count":     row.event_count,
            "suspicious_count": row.suspicious_count,
            "truncated":       truncated,
            "total_seen":      total_seen,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    await db.refresh(row)
    return _detail(row, events, None)


# ─── Import from a registered exhibit (C5) ───────────────────────────────────

def _read_exhibit(storage_path: str, nonce_hex: str) -> tuple[bytes, str]:
    """Decrypt the exhibit's master copy into memory and hash it. Blocking I/O + CPU: call via
    asyncio.to_thread. EvidenceIntegrityError = the ciphertext failed authentication (not the
    collected bytes); any other exception = it could not be read."""
    data = read_decrypted(storage_path, nonce_hex)
    return data, sha256_chunked(data)


def _exhibit_state_error(ev: Evidence) -> Optional[ApiError]:
    """Why this exhibit can't be examined now (409), else None. Checked before the read and again,
    under a row lock, before anything is written."""
    if ev.status != "active":
        return ApiError(status.HTTP_409_CONFLICT, "evidence_not_active",
                        f"Cannot examine evidence in status '{ev.status}'")
    if ev.current_custodian_id is None:
        return ApiError(status.HTTP_409_CONFLICT, "evidence_not_in_internal_custody",
                        "The exhibit is not held by an internal custodian; transfer it back first")
    if ev.pending_custodian_id is not None:
        return ApiError(status.HTTP_409_CONFLICT, "transfer_pending",
                        "A custody transfer is awaiting the recipient's acceptance; examine it after "
                        "it is accepted or declined")
    return None


async def _lock_exhibit(db: AsyncSession, incident_id: uuid.UUID, evidence_id: uuid.UUID) -> Evidence:
    """Re-read the exhibit under SELECT … FOR UPDATE (held until commit): a transfer, dispose or
    verify that ran during the decrypt/parse is seen, and can't interleave with the write."""
    return (await db.execute(
        select(Evidence).where(Evidence.id == evidence_id, Evidence.incident_id == incident_id)
        .with_for_update(of=Evidence).execution_options(populate_existing=True)
    )).scalar_one()


# Recorded in the custody log: the parse never touches the stored master. It is decrypted into
# memory, hash-verified against the collection SHA-256, and that copy is parsed (EVTX / SQLite
# libraries read it from the RAM-only parser tmpfs; the file is deleted after the parse).
_EXAMINED_ON = "hash-verified in-memory copy of the master"


@router.post(
    "/{incident_id}/forensic/timeline-import/from-evidence/{evidence_id}",
    response_model=ForensicImportDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Parse a registered exhibit (hash re-verified) into a persisted import",
    responses={
        404: {"model": ApiErrorBody, "description": "evidence_not_found"},
        409: {"model": ApiErrorBody, "description": "incident_closed, evidence_not_active, "
              "evidence_not_in_internal_custody, transfer_pending, evidence_storage_missing or "
              "evidence_hash_mismatch (the item is frozen: verify_failed)"},
        422: {"model": ApiErrorBody, "description": "evidence_not_digital, evidence_too_large, "
              "invalid_source_tz or parse_failed"},
        503: {"model": ApiErrorBody, "description": "evidence_read_error (stored copy unreadable; "
              "not frozen)"},
    },
)
async def import_from_evidence(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    req:         ForensicImportFromEvidence,
    request:     Request,
    user:        User         = Depends(require_analyst),
    db:          AsyncSession = Depends(get_db),
) -> ForensicImportDetail:
    """Parse an exhibit already registered in Evidence instead of re-uploading the file.

    The exhibit must be a digital file of this incident that is `active`, held by an internal
    custodian and not awaiting a custody transfer (409 otherwise; checked again under a row lock
    after the parse, so a transfer or dispose that happened meanwhile wins and nothing is stored).
    Its encrypted master copy is decrypted into memory and hashed off the event loop; the master
    itself is never modified. The SHA-256 must equal the one recorded at collection: a mismatch
    (or ciphertext that fails AES-GCM authentication) freezes an item that is still active
    (`verify_failed`, audited `evidence_verify_failed`) and returns 409 `evidence_hash_mismatch`.
    A stored copy that can't be read at all (missing file, storage error) is not evidence of
    tampering: 503 `evidence_read_error`, the item is not frozen, the failed attempt is audited.
    Zone-less times are read in `source_tz`; year-less BSD-syslog lines are dated against the
    exhibit's `acquired_at` (else its registration time). The examination is recorded in the
    exhibit's custody log as `evidence_examine` (tool = the FENRIR timeline parser + version,
    `examined_on` = the hash-verified in-memory copy, truncation). Requires the analyst role.
    Returns the stored import (201) with `evidence_id`, `parser_version`, `source_tz`,
    `truncated` / `total_seen` and each event's `time_basis`.
    """
    inc = await get_accessible_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")
    _check_tz(req.source_tz)
    ev = (await db.execute(
        select(Evidence).where(Evidence.id == evidence_id, Evidence.incident_id == incident_id)
    )).scalar_one_or_none()
    if ev is None:
        raise ApiError(status.HTTP_404_NOT_FOUND, "evidence_not_found", "Evidence not found in this incident")
    if ev.kind != "digital_file":
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "evidence_not_digital",
                       "Only a digital-file exhibit can be parsed")
    if (err := _exhibit_state_error(ev)) is not None:
        raise err
    if not ev.storage_path or not ev.nonce_hex or not ev.sha256:
        raise ApiError(status.HTTP_409_CONFLICT, "evidence_storage_missing",
                       "The exhibit has no stored file or recorded hash to verify against")
    if (ev.file_size_bytes or 0) > _MAX_UPLOAD_BYTES:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "evidence_too_large",
                       "The exhibit is larger than the 500 MB Timeline Import limit")

    ip = request.client.host if request.client else None
    recorded = ev.sha256
    stem = Path(ev.original_filename or "exhibit").name
    filename = stem if req.parser == "auto" else Path(stem).stem + _PARSER_EXT[req.parser]
    year_ref = _year_reference(ev)
    examine = {
        "incident_id":  str(incident_id),
        "tool":         "FENRIR timeline parser",
        "version":      PARSER_VERSION,
        "params":       {"source_tz": req.source_tz, "parser": req.parser,
                         "bsd_year_reference": year_ref.isoformat() if year_ref else None},
    }

    async def _examine_failed(result: str, error: str) -> None:
        await write_audit(
            db, "evidence_examine",
            user_id=user.id, username=user.username,
            resource_type="evidence", resource_id=str(evidence_id), outcome="failure",
            details={**examine, "result": result, "error": error[:500]},
            ip_address=ip,
        )
        await db.commit()

    try:
        content, computed = await asyncio.to_thread(_read_exhibit, ev.storage_path, ev.nonce_hex)
    except EvidenceIntegrityError:          # AES-GCM tag failed: the stored ciphertext was altered
        content, computed = None, None
    except Exception as exc:                # missing file / storage I/O: unreadable, not tampered
        await _examine_failed("read_error", f"{type(exc).__name__}: {exc}")
        raise ApiError(status.HTTP_503_SERVICE_UNAVAILABLE, "evidence_read_error",
                       "The exhibit's stored copy could not be read (storage error). Nothing was "
                       "parsed and the item was not frozen; try again or ask an admin to check "
                       "the evidence storage.") from exc
    if computed != recorded:
        ev = await _lock_exhibit(db, incident_id, evidence_id)
        status_before = ev.status
        frozen = status_before == "active"      # never overwrite a status changed meanwhile
        if frozen:
            ev.status = "verify_failed"
        await write_audit(
            db, "evidence_verify_failed",
            user_id=user.id, username=user.username,
            resource_type="evidence", resource_id=str(ev.id), outcome="failure",
            details={"incident_id": str(incident_id), "phase": "timeline_import",
                     "sha256_recorded": recorded, "sha256_recomputed": computed,
                     "status_before": status_before, "frozen": frozen},
            ip_address=ip,
        )
        await db.commit()
        raise ApiError(status.HTTP_409_CONFLICT, "evidence_hash_mismatch",
                       "The stored exhibit no longer matches the SHA-256 recorded at collection; "
                       + ("it has been frozen (verify_failed) pending admin review."
                          if frozen else f"its status ('{status_before}') was left as it is.")
                       + " Nothing was parsed.")

    examine["sha256_verified"] = computed
    examine["examined_on"] = _EXAMINED_ON
    try:
        detected_format, events, stored, truncated, total_seen = await asyncio.to_thread(
            _parse_to_events, filename, content, req.source_tz, year_ref)
    except Exception as exc:
        await _examine_failed("parse_failed", str(exc))
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "parse_failed",
                       f"Failed to parse the exhibit: {exc}") from exc
    del content

    # The decrypt + parse took a while: re-check the exhibit under a row lock before writing.
    ev = await _lock_exhibit(db, incident_id, evidence_id)
    if (err := _exhibit_state_error(ev)) is not None:
        await _examine_failed("discarded_state_changed", err.detail)
        raise err

    row = ForensicImport(
        id               = uuid.uuid4(),
        incident_id      = incident_id,
        filename         = stem[:512],
        file_size        = ev.file_size_bytes or 0,
        mime_type        = ev.mime_type,
        sha256_hash      = computed,
        evidence_id      = ev.id,
        parser_version   = PARSER_VERSION,
        source_tz        = req.source_tz,
        detected_format  = detected_format,
        event_count      = len(events),
        suspicious_count = sum(1 for e in events if e.suspicious),
        truncated        = truncated,
        total_seen       = total_seen,
        parsed_events    = stored,
        uploaded_by_id   = user.id,
        uploaded_by      = user.username,
    )
    db.add(row)
    await db.flush()
    await write_audit(
        db, "evidence_examine",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id), outcome="success",
        details={**examine, "result": "timeline_import", "forensic_import_id": str(row.id),
                 "detected_format": detected_format, "event_count": row.event_count,
                 "untimestamped": sum(1 for e in events if e.time_basis == "missing"),
                 "truncated": truncated, "total_seen": total_seen},
        ip_address=ip,
    )
    await write_audit(
        db, "forensic_import_create",
        user_id=user.id, username=user.username,
        resource_type="forensic_import", resource_id=str(row.id),
        details={"incident_id": str(incident_id), "evidence_id": str(ev.id), "filename": row.filename,
                 "sha256": computed, "detected_format": detected_format, "parser_version": PARSER_VERSION,
                 "source_tz": req.source_tz, "event_count": row.event_count,
                 "suspicious_count": row.suspicious_count,
                 "truncated": truncated, "total_seen": total_seen},
        ip_address=ip,
    )
    await db.commit()
    await db.refresh(row)
    return _detail(row, events, ev.identifier)


# ─── Persisted imports ──────────────────────────────────────────────────────

@router.post(
    "/{incident_id}/forensic/timeline-import/imports",
    response_model=ForensicImportDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Upload, parse and persist a forensic artifact for later re-load",
    responses={400: {"model": ApiErrorBody, "description": "file_empty"},
               413: {"model": ApiErrorBody, "description": "file_too_large"},
               422: {"model": ApiErrorBody, "description": "invalid_source_tz or parse_failed"}},
)
async def create_forensic_import(
    incident_id: uuid.UUID,
    request:     Request,
    file:        UploadFile = File(...),
    source_tz:   str        = Form(default="UTC", max_length=64),
    user:        User       = Depends(require_analyst),
    db:          AsyncSession = Depends(get_db),
) -> ForensicImportDetail:
    """Upload, parse, and persist a forensic artifact so its events can be re-loaded later.

    Auto-detects the format and stores the parsed events plus file metadata (size, SHA-256).
    `source_tz` (IANA, default UTC) is the zone of times that don't state one; each event's
    `time_basis` says how its time was worked out. When the file's SHA-256 equals exactly one
    `active` exhibit of this incident the import is linked to it (`evidence_id`), the
    examination is written to that exhibit's custody log (`evidence_examine`, method
    `upload_sha256_match`) and year-less syslog lines are dated against its acquisition time.
    `truncated` / `total_seen` say whether a parser cap cut the output. Hashing and parsing run
    off the event loop. Uploads are capped at 500 MB. Requires the analyst role and access to
    the incident; audit-logged. Returns the persisted import including its parsed events.
    """
    await get_accessible_incident(db, incident_id, user)
    _check_tz(source_tz)
    content = await file.read()
    _validate_upload(content)
    filename = file.filename or "unknown"

    sha256 = await asyncio.to_thread(sha256_chunked, content)
    matches = (await db.execute(
        select(Evidence).where(Evidence.incident_id == incident_id, Evidence.sha256 == sha256,
                               Evidence.status == "active").limit(2)
    )).scalars().all()
    exhibit = matches[0] if len(matches) == 1 else None
    year_ref = _year_reference(exhibit)

    try:
        detected_format, events, stored, truncated, total_seen = await asyncio.to_thread(
            _parse_to_events, filename, content, source_tz, year_ref)
    except Exception as exc:
        raise _parse_failed(exc) from exc

    row = ForensicImport(
        id               = uuid.uuid4(),
        incident_id      = incident_id,
        filename         = filename[:512],
        file_size        = len(content),
        mime_type        = (file.content_type or None),
        sha256_hash      = sha256,
        evidence_id      = exhibit.id if exhibit else None,
        parser_version   = PARSER_VERSION,
        source_tz        = source_tz,
        detected_format  = detected_format,
        event_count      = len(events),
        suspicious_count = sum(1 for e in events if e.suspicious),
        truncated        = truncated,
        total_seen       = total_seen,
        parsed_events    = stored,
        uploaded_by_id   = user.id,
        uploaded_by      = user.username,
    )
    db.add(row)
    ip = request.client.host if request.client else None

    if exhibit is not None:
        # The uploaded bytes ARE this exhibit (same SHA-256): record the examination in its
        # custody log, as from-evidence does.
        await write_audit(
            db, "evidence_examine",
            user_id=user.id, username=user.username,
            resource_type="evidence", resource_id=str(exhibit.id), outcome="success",
            details={
                "incident_id": str(incident_id),
                "tool":        "FENRIR timeline parser",
                "version":     PARSER_VERSION,
                "params":      {"source_tz": source_tz, "parser": "auto",
                                "bsd_year_reference": year_ref.isoformat() if year_ref else None},
                "method":      "upload_sha256_match",
                "examined_on": "uploaded copy whose SHA-256 equals the exhibit's",
                "sha256_verified": sha256,
                "result":      "timeline_import",
                "forensic_import_id": str(row.id),
                "detected_format": detected_format,
                "event_count": row.event_count,
                "untimestamped": sum(1 for e in events if e.time_basis == "missing"),
                "truncated":   truncated,
                "total_seen":  total_seen,
            },
            ip_address=ip,
        )
    await write_audit(
        db, "forensic_import_create",
        user_id=user.id, username=user.username,
        resource_type="forensic_import", resource_id=str(row.id),
        details={
            "incident_id":      str(incident_id),
            "filename":         row.filename,
            "file_size":        row.file_size,
            "sha256":           row.sha256_hash,
            "evidence_id":      str(exhibit.id) if exhibit else None,
            "evidence_link":    "sha256_match" if exhibit else None,
            "detected_format":  detected_format,
            "parser_version":   PARSER_VERSION,
            "source_tz":        source_tz,
            "event_count":      row.event_count,
            "suspicious_count": row.suspicious_count,
            "truncated":        truncated,
            "total_seen":       total_seen,
        },
        ip_address=ip,
    )
    await db.commit()
    await db.refresh(row)
    return _detail(row, events, exhibit.identifier if exhibit else None)


@router.get(
    "/{incident_id}/forensic/timeline-import/imports",
    response_model=ForensicImportList,
    summary="List persisted forensic imports for an incident",
)
async def list_forensic_imports(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db:   AsyncSession = Depends(get_db),
) -> ForensicImportList:
    """List the persisted forensic imports for an incident, newest first.

    Requires access to the incident. Returns summary metadata per import (filename,
    format, event and suspicious counts, uploader, timestamp, linked exhibit, parser version,
    source timezone) without the parsed events.
    """
    await get_accessible_incident(db, incident_id, user)
    rows = (await db.execute(
        select(ForensicImport)
        .options(defer(ForensicImport.parsed_events))
        .where(ForensicImport.incident_id == incident_id)
        .order_by(ForensicImport.uploaded_at.desc())
    )).scalars().all()
    idents = await _evidence_identifiers(db, [r.evidence_id for r in rows])
    items = []
    for r in rows:
        s = ForensicImportSummary.model_validate(r)
        s.evidence_identifier = idents.get(r.evidence_id)
        items.append(s)
    return ForensicImportList(items=items)


@router.get(
    "/{incident_id}/forensic/timeline-import/imports/{import_id}",
    response_model=ForensicImportDetail,
    summary="Re-fetch parsed events for a persisted import",
)
async def get_forensic_import(
    incident_id: uuid.UUID,
    import_id:   uuid.UUID,
    user: User = Depends(current_user),
    db:   AsyncSession = Depends(get_db),
) -> ForensicImportDetail:
    """Re-fetch a persisted forensic import including its full parsed event list.

    Requires access to the incident. Returns 404 if the import does not exist for that
    incident, otherwise the import metadata plus all stored events.
    """
    await get_accessible_incident(db, incident_id, user)
    row = await _get_import(db, incident_id, import_id, with_events=True)
    events = [ParsedEventOut(**ev) for ev in (row.parsed_events or [])]
    idents = await _evidence_identifiers(db, [row.evidence_id])
    return _detail(row, events, idents.get(row.evidence_id))


def _promotion_rows(stored: list[tuple[int, str]], *, incident_id: uuid.UUID, imp: ForensicImport,
                    ir_phase: Optional[str], user_id: uuid.UUID) -> tuple[list[dict], list[int]]:
    """Stored parsed events -> timeline_events rows; events without a time are left out (and
    listed). Decodes JSON for up to 10 000 events: call via asyncio.to_thread."""
    now = utcnow()
    rows: list[dict] = []
    untimed: list[int] = []
    for idx, elem in stored:
        ev = json.loads(elem) if isinstance(elem, str) else elem
        ts = ev.get("event_time")
        if not ts or ev.get("time_basis") == "missing":
            untimed.append(idx)
            continue
        event_time = datetime.fromisoformat(ts)
        if event_time.tzinfo is None:          # parser output is always aware; be defensive
            event_time = event_time.replace(tzinfo=timezone.utc)
        basis = ev.get("time_basis")
        rows.append({
            "id":                   uuid.uuid4(),
            "incident_id":          incident_id,
            "event_time":           event_time,
            "hostname":             (ev.get("hostname") or None) and ev["hostname"][:256],
            "source":               (ev.get("source") or None) and ev["source"][:128],
            "event_type":           (ev.get("event_type") or None) and ev["event_type"][:128],
            # stripped, as PATCH compares it (sending the stored text back must not count as a change)
            "description":          (ev.get("description") or "").strip(),
            "raw_log":              (ev.get("raw_log") or None) and ev["raw_log"][:4000],
            "ir_phase":             ir_phase,
            "mitre_tactic_id":      (ev.get("mitre_tactic_id") or None) and ev["mitre_tactic_id"][:16],
            "mitre_tactic_name":    (ev.get("mitre_tactic_name") or None) and ev["mitre_tactic_name"][:64],
            "mitre_technique_id":   (ev.get("mitre_technique_id") or None) and ev["mitre_technique_id"][:16],
            "mitre_technique_name": (ev.get("mitre_technique_name") or None) and ev["mitre_technique_name"][:128],
            "origin":               "forensic_import",
            "is_system":            False,
            "external_safe":        True,
            "created_by_id":        user_id,
            "evidence_id":          imp.evidence_id,
            "forensic_import_id":   imp.id,
            "import_event_index":   idx,
            # legacy imports (parsed before C5) carry no basis: stays NULL, like other legacy events
            "time_basis":           basis if basis in _TIME_BASES_STORED else None,
            "created_at":           now,
            "updated_at":           now,
        })
    return rows, untimed


@router.post(
    "/{incident_id}/forensic/timeline-import/imports/{import_id}/promote",
    response_model=ForensicImportPromoteResult,
    summary="Promote events of a stored import to the timeline (server-side copy)",
    responses={
        404: {"model": ApiErrorBody, "description": "forensic_import_not_found"},
        409: {"model": ApiErrorBody, "description": "incident_closed or reparse_required (an import "
              "parsed before parser versioning)"},
        422: {"model": ApiErrorBody, "description": "index_out_of_range (or a validation error)"},
    },
)
async def promote_forensic_import(
    incident_id: uuid.UUID,
    import_id:   uuid.UUID,
    req:         ForensicImportPromote,
    request:     Request,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> ForensicImportPromoteResult:
    """Copy events of a stored import onto the incident timeline, picked by their `idx`.

    The server copies each event from the stored parse — time, host, source, type, description,
    raw log, ATT&CK and `time_basis` — and links it to the import, its index and the import's
    exhibit; the caller sends only indices (and an optional `ir_phase` for all). Events without a
    time are never placed on the timeline: they are skipped and listed in
    `skipped_untimestamped`. An index already promoted from this import is skipped
    (`already_promoted`), so re-promoting is a no-op. Promoted events keep their facts immutable
    (timeline edits of those fields return 409 imported_fact_immutable). 409 on a closed incident.
    409 `reparse_required` for an import parsed before parser versioning (`parser_version` null):
    its events carry no time basis, so import the file or exhibit again and promote from that.
    Requires the analyst role; audit-logged as `forensic_import_promote`.
    """
    inc = await get_accessible_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")
    imp = await _get_import(db, incident_id, import_id, with_events=False)
    if imp.parser_version is None:
        raise ApiError(status.HTTP_409_CONFLICT, "reparse_required",
                       "This import was parsed before parser versioning, so its event times carry no "
                       "time basis. Import the file or exhibit again and promote from the new import.")
    wanted = sorted(set(req.indices))
    bad = [i for i in wanted if i < 0 or i >= imp.event_count]
    if bad:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "index_out_of_range",
                       f"{len(bad)} index(es) are not events of this import (0..{imp.event_count - 1})",
                       extra={"indices": bad[:50]})

    already = set((await db.execute(
        select(TimelineEvent.import_event_index).where(
            TimelineEvent.forensic_import_id == imp.id,
            TimelineEvent.import_event_index.in_(wanted),
        )
    )).scalars().all())
    todo = [i for i in wanted if i not in already]
    stored: list[tuple[int, str]] = []
    if todo:
        # Only the requested elements leave Postgres; the (possibly large) parse stays there.
        stored = [(r.idx, r.elem) for r in (await db.execute(text(
            "SELECT (t.ord - 1)::int AS idx, t.elem::text AS elem "
            "FROM forensic_imports f "
            "CROSS JOIN LATERAL json_array_elements(f.parsed_events) WITH ORDINALITY AS t(elem, ord) "
            "WHERE f.id = :id AND (t.ord - 1) = ANY(:idx) ORDER BY t.ord"
        ), {"id": imp.id, "idx": todo})).all()]
    rows, untimed = await asyncio.to_thread(
        _promotion_rows, stored, incident_id=incident_id, imp=imp, ir_phase=req.ir_phase, user_id=user.id)

    created: list[int] = []
    for start in range(0, len(rows), _PROMOTE_CHUNK):
        res = await db.execute(
            pg_insert(TimelineEvent).values(rows[start:start + _PROMOTE_CHUNK])
            .on_conflict_do_nothing(index_elements=[TimelineEvent.forensic_import_id, TimelineEvent.import_event_index],
                                    index_where=TimelineEvent.forensic_import_id.isnot(None))
            .returning(TimelineEvent.import_event_index)
        )
        created.extend(res.scalars().all())
    created.sort()
    # A concurrent promote of the same index loses the ON CONFLICT race: count it as already there.
    raced = sorted(set(r["import_event_index"] for r in rows) - set(created))
    already_promoted = sorted(already | set(raced))

    await write_audit(
        db, "forensic_import_promote",
        user_id=user.id, username=user.username,
        resource_type="forensic_import", resource_id=str(imp.id),
        details={
            "incident_id":           str(incident_id),
            "evidence_id":           str(imp.evidence_id) if imp.evidence_id else None,
            "parser_version":        imp.parser_version,
            "requested":             len(wanted),
            "created":               len(created),
            "skipped_untimestamped": len(untimed),
            "already_promoted":      len(already_promoted),
            "ir_phase":              req.ir_phase,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return ForensicImportPromoteResult(created=len(created), created_indices=created,
                                       skipped_untimestamped=untimed, already_promoted=already_promoted)


@router.delete(
    "/{incident_id}/forensic/timeline-import/imports/{import_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Dispose a persisted forensic import (hard delete, audited)",
    responses={404: {"model": ApiErrorBody, "description": "forensic_import_not_found"},
               409: {"model": ApiErrorBody, "description": "import_has_promoted_events"}},
)
async def delete_forensic_import(
    incident_id: uuid.UUID,
    import_id:   uuid.UUID,
    request:     Request,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
):
    """Permanently delete a persisted forensic import (hard delete, audit-logged).

    Refused with 409 `import_has_promoted_events` while timeline events promoted from it exist
    (the import is their provenance record). Requires the analyst role and access to the
    incident. Returns 404 if the import does not exist for that incident, otherwise 204.
    """
    await get_accessible_incident(db, incident_id, user)
    row = await _get_import(db, incident_id, import_id, with_events=False)
    promoted = (await db.execute(
        select(func.count()).select_from(TimelineEvent).where(TimelineEvent.forensic_import_id == row.id)
    )).scalar_one()
    if promoted:
        raise ApiError(status.HTTP_409_CONFLICT, "import_has_promoted_events",
                       f"{promoted} timeline event(s) were promoted from this import; it is their "
                       "provenance record and can't be disposed while they exist")

    await write_audit(
        db, "forensic_import_dispose",
        user_id=user.id, username=user.username,
        resource_type="forensic_import", resource_id=str(import_id),
        details={
            "incident_id":      str(incident_id),
            "filename":         row.filename,
            "sha256":           row.sha256_hash,
            "event_count":      row.event_count,
            "suspicious_count": row.suspicious_count,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(row)
    await db.commit()
