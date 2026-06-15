"""Per-incident quarantine artifact management.

Mounted at prefix="/api/incidents".

Upload pipeline:
  - MD5 + SHA256 + SHA512 computed in one streaming pass
  - MIME type detected via python-magic
  - File stored at {quarantine_path}/{incident_id}/{uuid}_{safe_filename}
  - Path-traversal guard on every file access
  - Two IOC records auto-created (SHA256 + MD5) for immediate enrichment
  - Audit logged

Download:
  - AES-256 password-protected ZIP, password "infected"
  - Standard malware-analyst convention — prevents AV auto-execution

Analysis:
  - Proxy to air-gapped analysis worker (http://analysis-worker:8001)
  - Tool selection: file-type | hashes | entropy | strings | ioc-extract
                    pe | office | pdf | exif | hexdump
  - Results persisted in artifact.analysis_results keyed by tool name
"""
import hashlib
import io
import re
import uuid
from pathlib import Path
from typing import Optional

import httpx
import magic
import pyzipper
from fastapi import (APIRouter, Depends, File, Form, HTTPException,
                     Query, Request, Response, UploadFile, status)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.config import settings
from core.database import get_db
from incidents.access import get_accessible_incident
from models import Artifact, Incident, IOC, User

router = APIRouter()

WORKER_URL   = "http://analysis-worker:8001"
CHUNK_SIZE   = 64 * 1024   # 64 KiB
ZIP_PASSWORD = b"infected"

_VALID_TOOLS = frozenset({
    "file-type", "hashes", "entropy", "strings",
    "ioc-extract", "pe", "office", "pdf", "exif", "hexdump",
    "yara",
})


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _quarantine_dir(incident_id: uuid.UUID) -> Path:
    return Path(settings.quarantine_path) / str(incident_id)


def _quarantine_path(incident_id: uuid.UUID, stored_filename: str) -> Path:
    p = (_quarantine_dir(incident_id) / stored_filename).resolve()
    root = Path(settings.quarantine_path).resolve()
    if not str(p).startswith(str(root)):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid file path")
    return p


def _safe_filename(name: str) -> str:
    """Strip special chars; keep extension; cap at 200 chars."""
    stem = Path(name).stem
    ext  = Path(name).suffix
    safe = re.sub(r"[^\w\-.]", "_", stem)[:200 - len(ext)]
    return (safe or "artifact") + ext


async def _multi_hash(stream) -> tuple[bytes, str, str, str, int]:
    h256 = hashlib.sha256()
    h512 = hashlib.sha512()
    hmd5 = hashlib.md5()
    size = 0
    chunks: list[bytes] = []
    while True:
        chunk = stream.read(CHUNK_SIZE)
        if not chunk:
            break
        h256.update(chunk); h512.update(chunk); hmd5.update(chunk)
        size += len(chunk)
        chunks.append(chunk)
    raw = b"".join(chunks)
    return raw, h256.hexdigest(), h512.hexdigest(), hmd5.hexdigest(), size


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


async def _get_artifact(
    db: AsyncSession, incident_id: uuid.UUID, artifact_id: uuid.UUID
) -> Artifact:
    row = (await db.execute(
        select(Artifact).where(
            Artifact.id == artifact_id,
            Artifact.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Artifact not found")
    return row


# ─── List ────────────────────────────────────────────────────────────────────

@router.get("/{incident_id}/artifacts", summary="List artifacts")
async def list_artifacts(
    incident_id: uuid.UUID,
    db:   AsyncSession = Depends(get_db),
    user: User         = Depends(current_user),
):
    """List all quarantined artifacts for the incident, newest upload first.
    Requires access to the incident. Returns `{items: [...]}` of artifact
    metadata (filename, size, MIME, hashes, analysis status)."""
    await _get_incident(db, incident_id, user)
    rows = (await db.execute(
        select(Artifact)
        .where(Artifact.incident_id == incident_id)
        .order_by(Artifact.uploaded_at.desc())
    )).scalars().all()
    return {"items": [_artifact_out(r) for r in rows]}


# ─── Upload ──────────────────────────────────────────────────────────────────

@router.post("/{incident_id}/artifacts", status_code=status.HTTP_201_CREATED,
             summary="Upload an artifact")
async def upload_artifact(
    incident_id: uuid.UUID,
    request:     Request,
    description: Optional[str] = Form(default=None),
    file:        UploadFile     = File(...),
    user:        User           = Depends(require_analyst),
    db:          AsyncSession   = Depends(get_db),
):
    """Upload a file into the incident's quarantine: computes MD5/SHA256/SHA512,
    detects MIME via magic, stores it, and auto-creates SHA256 + MD5 IOC records.
    Requires the analyst role and an open incident; rejects oversize uploads.
    Returns the created artifact metadata."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    cl = request.headers.get("content-length")
    if cl and int(cl) > settings.artifact_max_upload_bytes:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"Upload exceeds {settings.artifact_max_upload_bytes} bytes",
        )

    raw, sha256, sha512, md5, size = await _multi_hash(file.file)
    if size > settings.artifact_max_upload_bytes:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"Upload exceeds {settings.artifact_max_upload_bytes} bytes",
        )

    # Detect MIME from first 2 KiB (magic-based, not extension trust).
    mime_type = magic.from_buffer(raw[:2048], mime=True)

    original_filename = file.filename or "unnamed.bin"
    safe_name         = _safe_filename(original_filename)
    artifact_id       = uuid.uuid4()
    stored_filename   = f"{artifact_id}_{safe_name}"

    out_dir = _quarantine_dir(incident_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / stored_filename
    out_path.write_bytes(raw)

    artifact = Artifact(
        id=artifact_id,
        incident_id=incident_id,
        original_filename=original_filename,
        stored_filename=stored_filename,
        file_size=size,
        mime_type=mime_type,
        md5_hash=md5,
        sha256_hash=sha256,
        sha512_hash=sha512,
        description=description,
        analysis_status="pending",
        analysis_results={},
        uploaded_by_id=user.id,
        uploaded_by=user.username,
    )
    db.add(artifact)
    await db.flush()

    # Auto-create IOC records for SHA256 and MD5 — skip if already present (dedup).
    # Use the schema's canonical IocType literals so IOCOut serialisation accepts
    # these rows (the literal set is ip|domain|url|hash_md5|hash_sha1|hash_sha256
    # |email|registry_key|file_path|other — plain "hash" is rejected).
    for ioc_value, ioc_type in [(sha256, "hash_sha256"), (md5, "hash_md5")]:
        exists = (await db.execute(
            select(IOC).where(
                IOC.incident_id == incident_id,
                IOC.type == ioc_type,
                IOC.value == ioc_value,
            )
        )).scalar_one_or_none()
        if not exists:
            db.add(IOC(
                incident_id=incident_id,
                type=ioc_type,
                value=ioc_value,
                notes=f"Auto-extracted from artifact: {original_filename}",
                source="artifact-upload",
                tags=["artifact"],
                added_by_id=user.id,
            ))

    await write_audit(db, user_id=user.id, action="artifact_upload", details={
        "artifact_id": str(artifact_id),
        "filename": original_filename,
        "size": size,
        "sha256": sha256,
        "md5": md5,
        "mime_type": mime_type,
        "incident_id": str(incident_id),
    })
    await db.commit()
    return _artifact_out(artifact)


# ─── Get ─────────────────────────────────────────────────────────────────────

@router.get("/{incident_id}/artifacts/{artifact_id}", summary="Get an artifact")
async def get_artifact(
    incident_id: uuid.UUID,
    artifact_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User       = Depends(current_user),
):
    """Fetch metadata for a single artifact by id within the incident, including
    hashes and persisted analysis results. Requires access to the incident.
    Returns the artifact record; 404 if not found."""
    await _get_incident(db, incident_id, user)
    return _artifact_out(await _get_artifact(db, incident_id, artifact_id))


# ─── Update description ───────────────────────────────────────────────────────

@router.patch("/{incident_id}/artifacts/{artifact_id}", summary="Update an artifact description")
async def update_artifact(
    incident_id: uuid.UUID,
    artifact_id: uuid.UUID,
    description: Optional[str] = Form(default=None),
    user: User         = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
):
    """Update the free-text description of an artifact. Requires the analyst role
    and an open incident. Returns the updated artifact record; 404 if not
    found."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    artifact = await _get_artifact(db, incident_id, artifact_id)
    artifact.description = description
    await write_audit(db, user_id=user.id, action="artifact_update", details={
        "artifact_id": str(artifact_id),
        "incident_id": str(incident_id),
    })
    await db.commit()
    return _artifact_out(artifact)


# ─── Delete ──────────────────────────────────────────────────────────────────

@router.delete("/{incident_id}/artifacts/{artifact_id}", status_code=status.HTTP_204_NO_CONTENT,
               summary="Delete an artifact")
async def delete_artifact(
    incident_id: uuid.UUID,
    artifact_id: uuid.UUID,
    user: User         = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
):
    """Delete an artifact: removes the file from the quarantine volume and the
    database record. Requires the analyst role and an open incident. Returns
    204; 404 if not found."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    artifact = await _get_artifact(db, incident_id, artifact_id)

    # Remove file from quarantine volume.
    try:
        fpath = _quarantine_path(incident_id, artifact.stored_filename)
        fpath.unlink(missing_ok=True)
    except Exception:
        pass  # Continue — DB record deletion is the authoritative action.

    await write_audit(db, user_id=user.id, action="artifact_delete", details={
        "artifact_id": str(artifact_id),
        "filename": artifact.original_filename,
        "sha256": artifact.sha256_hash,
        "incident_id": str(incident_id),
    })
    await db.delete(artifact)
    await db.commit()


# ─── Download (AES-256 password-protected ZIP) ───────────────────────────────

@router.get("/{incident_id}/artifacts/{artifact_id}/download",
            summary="Download an artifact")
async def download_artifact(
    incident_id: uuid.UUID,
    artifact_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User       = Depends(current_user),
):
    """Download an artifact wrapped in an AES-256 password-protected ZIP
    (password "infected", per malware-analyst convention to prevent AV
    auto-execution). Requires access to the incident. Returns the ZIP bytes;
    404 if the file is missing on disk."""
    await _get_incident(db, incident_id, user)
    artifact = await _get_artifact(db, incident_id, artifact_id)

    fpath = _quarantine_path(incident_id, artifact.stored_filename)
    if not fpath.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found on disk")

    raw = fpath.read_bytes()
    buf = io.BytesIO()
    with pyzipper.AESZipFile(
        buf, "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as zf:
        zf.setpassword(ZIP_PASSWORD)
        zf.writestr(artifact.original_filename, raw)

    zip_bytes = buf.getvalue()
    safe_zip_name = re.sub(r"[^\w\-.]", "_", artifact.original_filename) + ".zip"
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_zip_name}"',
            "X-Zip-Password": "infected",
        },
    )


# ─── Analysis proxy ───────────────────────────────────────────────────────────

@router.post("/{incident_id}/artifacts/{artifact_id}/analyze/{tool}",
             summary="Analyze an artifact")
async def analyze_artifact(
    incident_id: uuid.UUID,
    artifact_id: uuid.UUID,
    tool:        str,
    offset:      int = Query(0, ge=0),
    length:      int = Query(512, ge=1, le=65536),
    db:          AsyncSession = Depends(get_db),
    user:        User         = Depends(require_analyst),
):
    """Run one analysis tool against the artifact via the air-gapped analysis
    worker and persist the result under that tool name. `tool` must be one of
    file-type, hashes, entropy, strings, ioc-extract, pe, office, pdf, exif,
    hexdump, yara; hexdump honours the `offset`/`length` query params. Requires
    the analyst role. Returns the worker's result JSON."""
    if tool not in _VALID_TOOLS:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Unknown tool '{tool}'. Valid: {sorted(_VALID_TOOLS)}",
        )
    await _get_incident(db, incident_id, user)
    artifact = await _get_artifact(db, incident_id, artifact_id)

    fpath = _quarantine_path(incident_id, artifact.stored_filename)
    if not fpath.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found on disk")

    # Pass the quarantine-relative path so the analysis worker can read it.
    # The worker has /quarantine mounted read-only.
    file_path = str(fpath)
    params: dict = {"path": file_path}
    if tool == "hexdump":
        params["offset"] = offset
        params["length"] = length

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{WORKER_URL}/analyze/{tool}",
                json=params,
            )
            resp.raise_for_status()
            result = resp.json()
    except httpx.ConnectError:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Analysis worker unreachable",
        )
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            f"Analysis worker error: {e.response.text[:256]}",
        )

    # Persist results keyed by tool name.
    artifact.analysis_results = {**artifact.analysis_results, tool: result}
    artifact.analysis_status  = "completed"
    await db.commit()
    return result


# ─── Serialiser ──────────────────────────────────────────────────────────────

def _artifact_out(a: Artifact) -> dict:
    return {
        "id":                str(a.id),
        "incident_id":       str(a.incident_id),
        "original_filename": a.original_filename,
        "file_size":         a.file_size,
        "mime_type":         a.mime_type,
        "md5_hash":          a.md5_hash,
        "sha256_hash":       a.sha256_hash,
        "sha512_hash":       a.sha512_hash,
        "description":       a.description,
        "analysis_status":   a.analysis_status,
        "analysis_results":  a.analysis_results,
        "uploaded_by":       a.uploaded_by,
        "uploaded_at":       a.uploaded_at.isoformat() if a.uploaded_at else None,
    }
