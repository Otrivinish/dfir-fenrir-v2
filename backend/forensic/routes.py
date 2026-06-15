"""Forensic artifact parse endpoint + persisted import store.

Mounted at prefix="/api/incidents".

Two flows:
  • /parse                              — stateless preview parse (kept for back-compat).
  • /imports                            — persist + list + reload + dispose.
    POST   /imports                      upload, parse, persist, return events
    GET    /imports                      list past imports for the incident
    GET    /imports/{import_id}          re-fetch parsed events
    DELETE /imports/{import_id}          dispose (hard delete, audit-logged)
"""
import hashlib
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.config import settings
from core.database import get_db
from incidents.access import get_accessible_incident
from models import Artifact, ForensicImport, User
from schemas import (ForensicImportDetail, ForensicImportList,
                     ForensicImportSummary, ForensicParseResponse,
                     ParsedEventOut)

from .parser import parse_artifact, parse_velociraptor_collection

router = APIRouter()

_MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MB


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
        )
        for i, ev in enumerate(raw_events)
    ]


def _validate_upload(content: bytes) -> None:
    if len(content) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"File exceeds 100 MB limit ({len(content) // (1024*1024)} MB received)",
        )
    if not content:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Uploaded file is empty")


# ─── Stateless preview (back-compat) ────────────────────────────────────────

@router.post(
    "/{incident_id}/forensic/timeline-import/parse",
    response_model=ForensicParseResponse,
    status_code=status.HTTP_200_OK,
    summary="Parse a forensic artifact and return candidate timeline events (stateless preview)",
)
async def parse_forensic_artifact(
    incident_id: uuid.UUID,
    file: UploadFile = File(...),
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> ForensicParseResponse:
    """Parse an uploaded forensic artifact and return candidate timeline events without persisting.

    Auto-detects the artifact format, extracts events, and flags suspicious ones; uploads
    are capped at 100 MB. Requires access to the incident. Returns the detected format,
    counts, and the parsed event list for preview.
    """
    await get_accessible_incident(db, incident_id, user)
    content = await file.read()
    _validate_upload(content)
    filename = file.filename or "unknown"

    try:
        detected_format, raw_events = parse_artifact(filename, content)
    except Exception as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Failed to parse artifact: {exc}",
        ) from exc

    events = _events_from_raw(raw_events)
    return ForensicParseResponse(
        source_file=filename,
        detected_format=detected_format,
        count=len(events),
        suspicious_count=sum(1 for e in events if e.suspicious),
        events=events,
    )


# ─── Import from an ingested collection artifact (U1.3) ──────────────────────

@router.post(
    "/{incident_id}/forensic/timeline-import/from-artifact/{artifact_id}",
    response_model=ForensicImportDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Parse an ingested Velociraptor collection artifact into a persisted import",
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
    cap) and parses the per-artifact JSONL into candidate timeline events.
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

    try:
        raw_events = parse_velociraptor_collection(str(path))
    except Exception as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Failed to parse collection: {exc}",
        ) from exc

    events = _events_from_raw(raw_events)
    suspicious = sum(1 for e in events if e.suspicious)

    row = ForensicImport(
        id               = uuid.uuid4(),
        incident_id      = incident_id,
        filename         = (artifact.original_filename or "collection.zip")[:512],
        file_size        = artifact.file_size,
        mime_type        = artifact.mime_type,
        sha256_hash      = artifact.sha256_hash,
        detected_format  = "velociraptor",
        event_count      = len(events),
        suspicious_count = suspicious,
        parsed_events    = [e.model_dump() for e in events],
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
            "event_count":     row.event_count,
            "suspicious_count": row.suspicious_count,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    await db.refresh(row)

    return ForensicImportDetail(
        id=row.id, filename=row.filename, file_size=row.file_size,
        mime_type=row.mime_type, sha256_hash=row.sha256_hash,
        detected_format=row.detected_format,
        event_count=row.event_count, suspicious_count=row.suspicious_count,
        uploaded_by=row.uploaded_by, uploaded_at=row.uploaded_at,
        events=events,
    )


# ─── Persisted imports ──────────────────────────────────────────────────────

@router.post(
    "/{incident_id}/forensic/timeline-import/imports",
    response_model=ForensicImportDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Upload, parse and persist a forensic artifact for later re-load",
)
async def create_forensic_import(
    incident_id: uuid.UUID,
    request:     Request,
    file:        UploadFile = File(...),
    user:        User       = Depends(require_analyst),
    db:          AsyncSession = Depends(get_db),
) -> ForensicImportDetail:
    """Upload, parse, and persist a forensic artifact so its events can be re-loaded later.

    Auto-detects the format, stores the parsed events plus file metadata (size, SHA-256),
    and writes an audit record. Uploads are capped at 100 MB. Requires the analyst role and
    access to the incident. Returns the persisted import including its parsed events.
    """
    await get_accessible_incident(db, incident_id, user)
    content = await file.read()
    _validate_upload(content)
    filename = file.filename or "unknown"

    try:
        detected_format, raw_events = parse_artifact(filename, content)
    except Exception as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Failed to parse artifact: {exc}",
        ) from exc

    events = _events_from_raw(raw_events)
    suspicious = sum(1 for e in events if e.suspicious)

    row = ForensicImport(
        id               = uuid.uuid4(),
        incident_id      = incident_id,
        filename         = filename[:512],
        file_size        = len(content),
        mime_type        = (file.content_type or None),
        sha256_hash      = hashlib.sha256(content).hexdigest(),
        detected_format  = detected_format,
        event_count      = len(events),
        suspicious_count = suspicious,
        parsed_events    = [e.model_dump() for e in events],
        uploaded_by_id   = user.id,
        uploaded_by      = user.username,
    )
    db.add(row)

    await write_audit(
        db, "forensic_import_create",
        user_id=user.id, username=user.username,
        resource_type="forensic_import", resource_id=str(row.id),
        details={
            "incident_id":      str(incident_id),
            "filename":         row.filename,
            "file_size":        row.file_size,
            "sha256":           row.sha256_hash,
            "detected_format":  detected_format,
            "event_count":      row.event_count,
            "suspicious_count": row.suspicious_count,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    await db.refresh(row)

    return ForensicImportDetail(
        id=row.id, filename=row.filename, file_size=row.file_size,
        mime_type=row.mime_type, sha256_hash=row.sha256_hash,
        detected_format=row.detected_format,
        event_count=row.event_count, suspicious_count=row.suspicious_count,
        uploaded_by=row.uploaded_by, uploaded_at=row.uploaded_at,
        events=events,
    )


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
    format, event and suspicious counts, uploader, timestamp) without the parsed events.
    """
    await get_accessible_incident(db, incident_id, user)
    rows = (await db.execute(
        select(ForensicImport)
        .where(ForensicImport.incident_id == incident_id)
        .order_by(ForensicImport.uploaded_at.desc())
    )).scalars().all()
    return ForensicImportList(items=[ForensicImportSummary.model_validate(r) for r in rows])


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
    row = (await db.execute(
        select(ForensicImport).where(
            ForensicImport.id == import_id,
            ForensicImport.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Forensic import not found")
    events = [ParsedEventOut(**ev) for ev in (row.parsed_events or [])]
    return ForensicImportDetail(
        id=row.id, filename=row.filename, file_size=row.file_size,
        mime_type=row.mime_type, sha256_hash=row.sha256_hash,
        detected_format=row.detected_format,
        event_count=row.event_count, suspicious_count=row.suspicious_count,
        uploaded_by=row.uploaded_by, uploaded_at=row.uploaded_at,
        events=events,
    )


@router.delete(
    "/{incident_id}/forensic/timeline-import/imports/{import_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Dispose a persisted forensic import (hard delete, audited)",
)
async def delete_forensic_import(
    incident_id: uuid.UUID,
    import_id:   uuid.UUID,
    request:     Request,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
):
    """Permanently delete a persisted forensic import (hard delete, audit-logged).

    Requires the analyst role and access to the incident. Returns 404 if the import does
    not exist for that incident, otherwise 204 with no body.
    """
    await get_accessible_incident(db, incident_id, user)
    row = (await db.execute(
        select(ForensicImport).where(
            ForensicImport.id == import_id,
            ForensicImport.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Forensic import not found")

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
