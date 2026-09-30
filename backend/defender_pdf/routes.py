"""Microsoft Defender incident PDF import.

Mounted at prefix="/api/incidents". Two flows:
  - /parse            stateless preview (kept for back-compat / a quick look
                       without saving anything).
  - /imports          upload, parse, quarantine the raw PDF as an Artifact,
                       and persist the parsed candidates so the page survives
                       a refresh -- same "parse returns candidates, the
                       frontend drives promotion via existing CRUD" pattern as
                       ForensicImport, plus quarantine like every other
                       file-upload analyzer in this codebase.

Committing an accepted candidate as an IOC/Entity/Timeline event still goes
through the existing `/iocs`, `/iocs/batch`, `/entities`, `/timeline/batch`
endpoints from the frontend -- nothing here writes to those tables.
"""
import asyncio
import hashlib
import re
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
from models import Artifact, DefenderPdfImport, User
from schemas import (DefenderPdfImportDetail, DefenderPdfImportList,
                     DefenderPdfImportSummary, DefenderPdfParseResponse)

from .parser import parse_defender_incident_pdf

router = APIRouter()

_MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MB — generous for a report PDF
_PDF_MAGIC = b"%PDF"


# ─── Quarantine helpers (same hardened pattern as webhistory/routes.py) ─────

def _safe_filename(name: str) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]", "_", (name or "file").strip()) or "file"
    return base[:200]


def _resolve_in_quarantine(incident_id: uuid.UUID, stored_filename: str) -> Path:
    """Resolve a stored filename to an absolute path and verify it is
    actually contained within this incident's quarantine directory --
    belt-and-suspenders against path traversal, not reliant on
    `_safe_filename`'s regex alone. `incident_id` is re-validated as a
    canonical UUID rather than trusted from its type hint (a caller could
    pass a raw string), and containment is checked with `relative_to`
    rather than a `.parents` scan -- CodeQL's path-injection query
    recognizes `relative_to` as a real sanitizer boundary, not just the
    parents-membership check this used before."""
    root = Path(settings.quarantine_path).resolve()
    incident_dir = str(uuid.UUID(str(incident_id)))
    p = (root / incident_dir / stored_filename).resolve()
    try:
        p.relative_to(root)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid path")
    return p


def _store_quarantine(incident_id: uuid.UUID, filename: str, data: bytes) -> tuple[uuid.UUID, str]:
    aid = uuid.uuid4()
    stored = f"{aid}_{_safe_filename(filename)}"
    target = _resolve_in_quarantine(incident_id, stored)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return aid, stored


def _validate_pdf_upload(content: bytes) -> None:
    if not content:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Uploaded file is empty")
    if len(content) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                             f"File exceeds {_MAX_UPLOAD_BYTES // (1024*1024)} MB limit")
    if content[:4] != _PDF_MAGIC:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Not a PDF file")


def _to_import_detail(row: DefenderPdfImport) -> DefenderPdfImportDetail:
    # Explicit, not DefenderPdfImportDetail.model_validate(row) -- the ORM
    # column is `incident_meta` (avoids shadowing the existing `incident_id`
    # FK) but the schema field the frontend already consumes is `incident`.
    return DefenderPdfImportDetail(
        id=row.id, filename=row.filename, file_size=row.file_size,
        sha256_hash=row.sha256_hash, candidate_count=row.candidate_count,
        low_confidence_count=row.low_confidence_count,
        uploaded_by=row.uploaded_by, uploaded_at=row.uploaded_at,
        incident=row.incident_meta, candidates=row.candidates,
    )


async def _get_import(db, incident_id, import_id) -> DefenderPdfImport:
    row = (await db.execute(
        select(DefenderPdfImport).where(
            DefenderPdfImport.id == import_id,
            DefenderPdfImport.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Defender PDF import not found")
    return row


# ─── Stateless preview (back-compat) ────────────────────────────────────────

@router.post(
    "/{incident_id}/forensic/defender-pdf/parse",
    response_model=DefenderPdfParseResponse,
    status_code=status.HTTP_200_OK,
    summary="Parse a Microsoft Defender incident PDF into candidate IOCs/Entities/Timeline events (stateless preview)",
)
async def parse_defender_pdf(
    incident_id: uuid.UUID,
    file: UploadFile = File(...),
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> DefenderPdfParseResponse:
    await get_accessible_incident(db, incident_id, user)
    content = await file.read()
    _validate_pdf_upload(content)

    try:
        result = await asyncio.to_thread(parse_defender_incident_pdf, content)
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))

    return DefenderPdfParseResponse(**result)


# ─── Persisted imports ──────────────────────────────────────────────────────

@router.post(
    "/{incident_id}/forensic/defender-pdf/imports",
    response_model=DefenderPdfImportDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Upload, parse, quarantine, and persist a Defender incident PDF",
)
async def create_defender_pdf_import(
    incident_id: uuid.UUID,
    request: Request,
    file: UploadFile = File(...),
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> DefenderPdfImportDetail:
    await get_accessible_incident(db, incident_id, user)
    content = await file.read()
    _validate_pdf_upload(content)
    filename = file.filename or "incident.pdf"

    try:
        parsed = await asyncio.to_thread(parse_defender_incident_pdf, content)
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))

    candidates = parsed["candidates"]
    low_confidence = sum(1 for c in candidates if c.get("low_confidence"))
    sha256 = hashlib.sha256(content).hexdigest()
    art_id, stored = _store_quarantine(incident_id, filename, content)

    db.add(Artifact(
        id=art_id, incident_id=incident_id,
        original_filename=filename, stored_filename=stored,
        file_size=len(content), mime_type="application/pdf",
        md5_hash=hashlib.md5(content).hexdigest(), sha256_hash=sha256,
        sha512_hash=hashlib.sha512(content).hexdigest(),
        description="Microsoft Defender incident PDF",
        uploaded_by_id=user.id, uploaded_by=user.username,
    ))

    row = DefenderPdfImport(
        id=uuid.uuid4(), incident_id=incident_id,
        filename=filename[:512], file_size=len(content), sha256_hash=sha256,
        source_artifact_id=art_id,
        candidate_count=len(candidates), low_confidence_count=low_confidence,
        incident_meta=parsed["incident"], candidates=candidates,
        uploaded_by_id=user.id, uploaded_by=user.username,
    )
    db.add(row)

    await write_audit(
        db, "defender_pdf_import_create",
        user_id=user.id, username=user.username,
        resource_type="defender_pdf_import", resource_id=str(row.id),
        details={
            "incident_id": str(incident_id), "filename": row.filename,
            "sha256": sha256, "candidate_count": row.candidate_count,
            "low_confidence_count": row.low_confidence_count,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    await db.refresh(row)

    return _to_import_detail(row)


@router.get(
    "/{incident_id}/forensic/defender-pdf/imports",
    response_model=DefenderPdfImportList,
    summary="List persisted Defender PDF imports for an incident",
)
async def list_defender_pdf_imports(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> DefenderPdfImportList:
    await get_accessible_incident(db, incident_id, user)
    rows = (await db.execute(
        select(DefenderPdfImport)
        .where(DefenderPdfImport.incident_id == incident_id)
        .order_by(DefenderPdfImport.uploaded_at.desc())
    )).scalars().all()
    return DefenderPdfImportList(items=[DefenderPdfImportSummary.model_validate(r) for r in rows])


@router.get(
    "/{incident_id}/forensic/defender-pdf/imports/{import_id}",
    response_model=DefenderPdfImportDetail,
    summary="Re-fetch a persisted Defender PDF import's candidates",
)
async def get_defender_pdf_import(
    incident_id: uuid.UUID,
    import_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> DefenderPdfImportDetail:
    await get_accessible_incident(db, incident_id, user)
    row = await _get_import(db, incident_id, import_id)
    return _to_import_detail(row)


@router.delete(
    "/{incident_id}/forensic/defender-pdf/imports/{import_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Dispose a persisted Defender PDF import (hard delete, audited)",
)
async def delete_defender_pdf_import(
    incident_id: uuid.UUID,
    import_id: uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    await get_accessible_incident(db, incident_id, user)
    row = await _get_import(db, incident_id, import_id)

    await write_audit(
        db, "defender_pdf_import_delete",
        user_id=user.id, username=user.username,
        resource_type="defender_pdf_import", resource_id=str(row.id),
        details={"incident_id": str(incident_id), "filename": row.filename},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(row)
    await db.commit()
