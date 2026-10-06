"""Per-incident quarantine artifact management.

Mounted at prefix="/api/incidents".

Upload pipeline:
  - H1 (R06): encrypted at rest (FENRGCM v2, artifacts/store.py) in one streaming pass that also
    computes MD5 + SHA-256 (+ SHA-512) and keeps the first 2 KiB for MIME detection (python-magic);
    the plaintext never reaches a disk
  - File stored at {quarantine_path}/{incident_id}/{uuid}_{safe_filename}.enc
  - Path-traversal guard on every file access
  - Hash IOCs only on request (`create_hash_iocs`, default false) or later through
    POST …/artifacts/{id}/hash-iocs: a ransom note or a screenshot is not an indicator
  - Audit logged

Delete (H1): a reason is required (422 reason_required); refused while another record names the
artifact (409 artifact_referenced, with the references); audited with the reason.

Download:
  - AES-256 password-protected ZIP, password "infected", built on the RAM tmpfs from the
    authenticated stream
  - Standard malware-analyst convention — prevents AV auto-execution

Analysis:
  - The backend decrypts the artifact to a private file on the RAM tmpfs and sends its bytes (TLS)
    to the air-gapped analysis worker (https://analysis-worker:8001/analyze/upload/{tool})
  - Tool selection: file-type | hashes | entropy | strings | ioc-extract
                    pe | office | pdf | exif | hexdump | yara
  - Results persisted in artifact.analysis_results keyed by tool name
"""
import asyncio
import re
import uuid
from typing import Optional

import anyio
import httpx
import magic
from fastapi import (APIRouter, Depends, File, Form, HTTPException,
                     Query, Request, UploadFile, status)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from artifacts import store
from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.worker_client import WORKER_URL, worker_client, worker_headers
from core.config import settings
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from evidence.crypto import EvidenceCryptoError
from evidence.streaming import require_free_space
from incidents.access import get_accessible_incident
from models import (Artifact, BrowserHistoryUpload, CollectionPackage, DefenderPdfImport, EmailAnalysis,
                    ForensicImport, Incident, IOC, User, YaraMatch)

router = APIRouter()

REASON_MIN, REASON_MAX = 10, 2000

_VALID_TOOLS = frozenset({
    "file-type", "hashes", "entropy", "strings",
    "ioc-extract", "pe", "office", "pdf", "exif", "hexdump",
    "yara",
})


# ─── Helpers ─────────────────────────────────────────────────────────────────

async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


def _ensure_open(inc: Incident) -> None:
    """409 incident_closed: a closed incident's record is frozen (re-open it first)."""
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")


_CLOSED_409 = {409: {"model": ApiErrorBody, "description": "incident_closed"}}
_READ_ERRORS = {409: {"model": ApiErrorBody, "description": "incident_closed (writes), or artifact_integrity_failed "
                      "(the stored file failed its integrity check)"},
                503: {"model": ApiErrorBody, "description": "artifact_read_error (the stored file cannot be read; "
                      "admins notified)"}}


async def _add_hash_iocs(db: AsyncSession, a: Artifact, user: User, note: str) -> tuple[list[dict], list[dict]]:
    """SHA-256 + MD5 IOCs for the artifact, skipping ones the incident already has. Returns (created, existing)."""
    created, existing = [], []
    for value, ioc_type in [(a.sha256_hash, "hash_sha256"), (a.md5_hash, "hash_md5")]:
        if not value:
            continue
        row = (await db.execute(select(IOC).where(
            IOC.incident_id == a.incident_id, IOC.type == ioc_type, IOC.value == value))).scalars().first()
        if row is not None:
            existing.append({"id": str(row.id), "type": ioc_type, "value": value})
            continue
        ioc = IOC(id=uuid.uuid4(), incident_id=a.incident_id, type=ioc_type, value=value,
                  notes=f"{note}: {a.original_filename}", source="artifact-upload", tags=["artifact"],
                  added_by_id=user.id)
        db.add(ioc)
        created.append({"id": str(ioc.id), "type": ioc_type, "value": value})
    return created, existing


async def artifact_references(db: AsyncSession, a: Artifact) -> list[dict]:
    """Records that name this artifact (H1 delete guard): the source of an email analysis or one of its
    extracted attachments, a browser-history upload, a collection package's ingest result, a Defender
    import, a timeline import parsed from it. YARA matches are its own results and are deleted with it."""
    aid = a.id
    queries = [
        ("email_analysis", select(EmailAnalysis.id).where(or_(
            EmailAnalysis.source_artifact_id == aid,
            EmailAnalysis.attachments.cast(JSONB).contains([{"artifact_id": str(aid)}])))),
        ("browser_history_upload", select(BrowserHistoryUpload.id).where(or_(
            BrowserHistoryUpload.source_artifact_id == aid, BrowserHistoryUpload.form_history_artifact_id == aid))),
        ("collection_package", select(CollectionPackage.id).where(CollectionPackage.result_artifact_id == aid)),
        ("defender_pdf_import", select(DefenderPdfImport.id).where(DefenderPdfImport.source_artifact_id == aid)),
        ("timeline_import", select(ForensicImport.id).where(ForensicImport.source_artifact_id == aid)),
    ]
    out = []
    for kind, q in queries:
        out += [{"type": kind, "id": str(rid)} for rid in (await db.execute(q.limit(20))).scalars().all()]
    return out


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
             summary="Upload an artifact",
             responses={**_CLOSED_409,
                        507: {"model": ApiErrorBody, "description": "insufficient_storage (the quarantine volume, "
                              "with its 1 GiB reserve, or the upload scratch space is full; nothing stored)"}})
async def upload_artifact(
    incident_id: uuid.UUID,
    request:     Request,
    description: Optional[str] = Form(default=None),
    create_hash_iocs: bool     = Form(default=False, description="Also create SHA-256 + MD5 IOCs for this file "
                                      "(only for a malicious sample; default false — see POST …/hash-iocs)"),
    file:        UploadFile     = File(...),
    user:        User           = Depends(require_analyst),
    db:          AsyncSession   = Depends(get_db),
):
    """Upload a file into the incident's quarantine: encrypted at rest (AES-256-GCM, FENRGCM v2) in one
    streaming pass that computes MD5/SHA-256/SHA-512 and detects MIME via magic. Hash IOCs are created
    only with `create_hash_iocs=true` (form field; default false), deduplicated against the incident's
    IOCs. Requires the analyst role and an open incident (409 incident_closed); rejects oversize uploads
    (413) and a full quarantine volume (507). Returns the created artifact metadata."""
    _ensure_open(await _get_incident(db, incident_id, user))

    cap = settings.artifact_max_upload_bytes
    cl = request.headers.get("content-length")
    if (cl and cl.isdigit() and int(cl) > cap) or (file.size or 0) > cap:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, f"Upload exceeds {cap} bytes")
    require_free_space(file.size or 0, "this artifact", root=settings.quarantine_path)

    original_filename = file.filename or "unnamed.bin"
    artifact_id       = uuid.uuid4()
    stored_filename   = store.stored_name(artifact_id, original_filename)
    stored, tap = await store.awrite(file.file, incident_id, stored_filename, cap=cap)
    mime_type = magic.from_buffer(tap.head, mime=True)   # magic-based, not extension trust

    artifact = Artifact(
        id=artifact_id,
        incident_id=incident_id,
        original_filename=original_filename,
        stored_filename=stored_filename,
        file_size=stored.size,
        mime_type=mime_type,
        nonce_hex=stored.nonce_hex,
        md5_hash=stored.md5,
        sha256_hash=stored.sha256,
        sha512_hash=tap.sha512.hexdigest(),
        description=description,
        analysis_status="pending",
        analysis_results={},
        uploaded_by_id=user.id,
        uploaded_by=user.username,
    )
    db.add(artifact)
    await db.flush()
    created: list[dict] = []
    if create_hash_iocs:
        created, _existing = await _add_hash_iocs(db, artifact, user, "Auto-extracted from artifact")

    await write_audit(db, user_id=user.id, action="artifact_upload", details={
        "artifact_id": str(artifact_id),
        "filename": original_filename,
        "size": stored.size,
        "sha256": stored.sha256,
        "md5": stored.md5,
        "mime_type": mime_type,
        "incident_id": str(incident_id),
        "encrypted_at_rest": True,
        "create_hash_iocs": create_hash_iocs,
        "iocs_created": [c["id"] for c in created],
    })
    try:
        await db.commit()
    except BaseException:
        await asyncio.to_thread(store.unlink, incident_id, stored_filename)   # no row: no file left behind
        raise
    return _artifact_out(artifact)


@router.post("/{incident_id}/artifacts/{artifact_id}/hash-iocs", summary="Promote an artifact's hashes to IOCs",
             responses=_CLOSED_409)
async def promote_hash_iocs(
    incident_id: uuid.UUID,
    artifact_id: uuid.UUID,
    user: User         = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
):
    """Create SHA-256 + MD5 IOCs (source `artifact-upload`) for an artifact the analyst judged malicious;
    ones the incident already has are reported, not duplicated. Requires the analyst role and an open
    incident (409 incident_closed). Audited `artifact_hash_iocs_promoted`. Returns
    `{created: [{id, type, value}], existing: [...]}`."""
    _ensure_open(await _get_incident(db, incident_id, user))
    artifact = await _get_artifact(db, incident_id, artifact_id)
    created, existing = await _add_hash_iocs(db, artifact, user, "Promoted from artifact")
    await write_audit(db, "artifact_hash_iocs_promoted", user_id=user.id, username=user.username,
                      resource_type="artifact", resource_id=str(artifact_id), outcome="success",
                      details={"incident_id": str(incident_id), "artifact_id": str(artifact_id),
                               "created": created, "existing": [e["id"] for e in existing]})
    await db.commit()
    return {"created": created, "existing": existing}


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

@router.patch("/{incident_id}/artifacts/{artifact_id}", summary="Update an artifact description",
              responses=_CLOSED_409)
async def update_artifact(
    incident_id: uuid.UUID,
    artifact_id: uuid.UUID,
    description: Optional[str] = Form(default=None),
    user: User         = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
):
    """Update the free-text description of an artifact. Requires the analyst role
    and an open incident (409 incident_closed). Returns the updated artifact record;
    404 if not found."""
    _ensure_open(await _get_incident(db, incident_id, user))
    artifact = await _get_artifact(db, incident_id, artifact_id)
    artifact.description = description
    await write_audit(db, user_id=user.id, action="artifact_update", details={
        "artifact_id": str(artifact_id),
        "incident_id": str(incident_id),
    })
    await db.commit()
    return _artifact_out(artifact)


# ─── Delete ──────────────────────────────────────────────────────────────────

class ArtifactDelete(BaseModel):
    reason: Optional[str] = Field(default=None, description="Why the artifact is deleted (10–2000 characters).")


@router.delete("/{incident_id}/artifacts/{artifact_id}", status_code=status.HTTP_204_NO_CONTENT,
               summary="Delete an artifact",
               responses={409: {"model": ApiErrorBody, "description": "incident_closed, or artifact_referenced "
                                "(another record names it; `references` lists them)"},
                          422: {"model": ApiErrorBody, "description": "reason_required"}})
async def delete_artifact(
    incident_id: uuid.UUID,
    artifact_id: uuid.UUID,
    body: Optional[ArtifactDelete] = None,
    user: User         = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
):
    """Delete an artifact: its database record, its YARA matches, then its file on the quarantine volume.
    A reason is required: JSON body `{"reason": "…"}` (10–2000 characters, else 422 code reason_required).
    Refused with 409 code artifact_referenced while another record names the artifact — an email analysis
    (source message or an extracted attachment), a browser-history upload, a collection package's ingest
    result, a Defender import or a timeline import; the body's `references` lists them ({type, id}).
    The audit record keeps the reason, the hashes and the number of YARA matches removed. Requires the
    analyst role and an open incident (409 incident_closed). Returns 204; 404 if not found."""
    inc = await _get_incident(db, incident_id, user)
    artifact = (await db.execute(
        select(Artifact).where(Artifact.id == artifact_id, Artifact.incident_id == incident_id)
        .with_for_update().execution_options(populate_existing=True))).scalar_one_or_none()
    if not artifact:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Artifact not found")
    _ensure_open(inc)
    why = (body.reason or "").strip() if body is not None else ""
    if not (REASON_MIN <= len(why) <= REASON_MAX):
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "reason_required",
                       f"A reason of {REASON_MIN}–{REASON_MAX} characters is required to delete an artifact.")
    refs = await artifact_references(db, artifact)
    if refs:
        raise ApiError(status.HTTP_409_CONFLICT, "artifact_referenced",
                       f"{len(refs)} record(s) name this artifact (email analysis, browser history, collection, "
                       "Defender or timeline import); it can't be deleted while they do.", extra={"references": refs})
    yara_n = (await db.execute(select(func.count()).select_from(YaraMatch)
                               .where(YaraMatch.artifact_id == artifact_id))).scalar_one()
    stored = (artifact.incident_id, artifact.stored_filename)
    await write_audit(db, "artifact_delete", user_id=user.id, username=user.username,
                      resource_type="artifact", resource_id=str(artifact_id), outcome="success", details={
                          "artifact_id": str(artifact_id),
                          "filename": artifact.original_filename,
                          "sha256": artifact.sha256_hash,
                          "md5": artifact.md5_hash,
                          "size": artifact.file_size,
                          "incident_id": str(incident_id),
                          "reason": why,
                          "yara_matches_deleted": yara_n,
                          "encrypted_at_rest": store.is_encrypted(artifact),
                      })
    await db.delete(artifact)
    await db.commit()
    # The record is gone: now the file (a failure here leaves an unreferenced file, never a dangling row).
    await asyncio.to_thread(store.unlink, *stored)


# ─── Download (AES-256 password-protected ZIP) ───────────────────────────────

@router.get("/{incident_id}/artifacts/{artifact_id}/download",
            summary="Download an artifact", responses=_READ_ERRORS)
async def download_artifact(
    incident_id: uuid.UUID,
    artifact_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User       = Depends(current_user),
):
    """Download an artifact wrapped in an AES-256 password-protected ZIP
    (password "infected", per malware-analyst convention to prevent AV
    auto-execution). The stored file is decrypted and authenticated in full before the
    first byte is sent. Requires access to the incident. 404 if the file is missing on disk,
    409 artifact_integrity_failed if it fails its integrity check, 503 artifact_read_error."""
    await _get_incident(db, incident_id, user)
    artifact = await _get_artifact(db, incident_id, artifact_id)
    try:
        f, size = await asyncio.to_thread(store.zip_infected, artifact)
    except EvidenceCryptoError as e:
        raise store.read_error(e) from None

    async def body():
        try:
            while True:
                block = await anyio.to_thread.run_sync(f.read, store.CHUNK)
                if not block:
                    return
                yield block
        finally:
            await anyio.to_thread.run_sync(f.close)

    safe_zip_name = re.sub(r"[^\w\-.]", "_", artifact.original_filename) + ".zip"
    return StreamingResponse(body(), media_type="application/zip", headers={
        "Content-Disposition": f'attachment; filename="{safe_zip_name}"',
        "Content-Length": str(size),
        "X-Zip-Password": "infected",
    })


# ─── Analysis proxy ───────────────────────────────────────────────────────────

async def worker_upload(artifact: Artifact, tool: str, *, timeout: float, form: Optional[dict] = None,
                        rules: Optional[bytes] = None) -> httpx.Response:
    """H1: decrypt the artifact to a private file on the RAM tmpfs, send its bytes (TLS) to the worker's
    /analyze/upload/{tool}, delete the copy. Raises EvidenceCryptoError on a read failure and the httpx
    errors as they come; the caller maps both."""
    path, _sha = await store.amaterialise(artifact)
    try:
        with open(path, "rb") as fh:
            files = {"file": (artifact.original_filename or "artifact.bin", fh, "application/octet-stream")}
            if rules is not None:
                files["rules"] = ("rules.json", rules, "application/json")
            async with worker_client(timeout=timeout) as client:
                resp = await client.post(f"{WORKER_URL}/analyze/upload/{tool}", headers=worker_headers(),
                                         data=form or {}, files=files)
        resp.raise_for_status()
        return resp
    finally:
        await store.adiscard(path)


@router.post("/{incident_id}/artifacts/{artifact_id}/analyze/{tool}",
             summary="Analyze an artifact", responses=_READ_ERRORS)
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
    hexdump, yara; hexdump honours the `offset`/`length` query params. The stored file is
    decrypted to a private RAM-only copy that is sent (TLS) to the worker and deleted after.
    Requires the analyst role and an open incident (the result is stored on the artifact:
    409 incident_closed otherwise). 404 if the file is missing on disk, 409
    artifact_integrity_failed, 503 artifact_read_error. Returns the worker's result JSON."""
    if tool not in _VALID_TOOLS:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Unknown tool '{tool}'. Valid: {sorted(_VALID_TOOLS)}",
        )
    _ensure_open(await _get_incident(db, incident_id, user))
    artifact = await _get_artifact(db, incident_id, artifact_id)
    form = {"offset": str(offset), "length": str(length)} if tool == "hexdump" else None
    try:
        resp = await worker_upload(artifact, tool, timeout=120.0, form=form)
        result = resp.json()
    except EvidenceCryptoError as e:
        raise store.read_error(e) from None
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
        # H1: false only for a legacy plaintext file not yet migrated (artifacts.encrypt_quarantine)
        "encrypted_at_rest": a.nonce_hex is not None,
        "uploaded_at":       a.uploaded_at.isoformat() if a.uploaded_at else None,
    }
