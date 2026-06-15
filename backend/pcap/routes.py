"""Per-incident PCAP analysis endpoints.

Mounted at prefix="/api/incidents". Proxies file uploads to the air-gapped
analysis worker, persists results per-incident, and supports IOC extraction
directly into the incident's IOC list.

Route ordering: literal sub-paths (import-iocs) come before parametric ones.
"""
import uuid
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from incidents.access import get_accessible_incident
from models import IOC, Incident, PCAPAnalysis, User
from pcap.dns_recon import DnsReconResponse, build_recon

router = APIRouter()

WORKER_URL = "http://analysis-worker:8001"

# Cap PCAP uploads. Unlike artifacts/evidence this endpoint had no limit, so a
# single large upload (or Content-Length-spoofed chunked body) was an easy OOM.
_MAX_PCAP_BYTES = 500 * 1024 * 1024  # 500 MiB


async def _read_capped(file: UploadFile, cap: int) -> bytes:
    """Read the upload, aborting as soon as it exceeds `cap` — never trusts
    Content-Length and never buffers more than the limit."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > cap:
            raise HTTPException(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                f"PCAP exceeds the {cap // (1024 * 1024)} MiB limit",
            )
        chunks.append(chunk)
    return b"".join(chunks)

# IOC types this endpoint can produce — subset of IocType literal in schemas.py
_ALLOWED_IOC_TYPES = {"ip", "domain", "url"}


class _IocItem(BaseModel):
    type:  str
    value: str
    notes: Optional[str] = None


class _IocImportBody(BaseModel):
    iocs: list[_IocItem]
    # Auto-source tag stamped on every imported IOC. Defaults to ["pcap"]
    # for the standard PCAP "Import IOCs" flow; the DNS Recon view passes
    # ["dns-recon"] so DNS-derived indicators are filterable separately.
    tags_override: Optional[list[str]] = None


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


# ─── List ────────────────────────────────────────────────────────────────────

@router.get("/{incident_id}/pcap", summary="List PCAP analyses")
async def list_pcap(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
):
    """List the incident's saved PCAP analyses (up to 50, newest first).
    Requires access to the incident. Returns a list of summaries (id, filename,
    size, uploader, created_at)."""
    await _get_incident(db, incident_id, user)
    rows = (
        await db.execute(
            select(PCAPAnalysis)
            .where(PCAPAnalysis.incident_id == incident_id)
            .order_by(PCAPAnalysis.created_at.desc())
            .limit(50)
        )
    ).scalars().all()
    return [
        {
            "id":          str(r.id),
            "filename":    r.filename,
            "file_size":   r.file_size,
            "uploaded_by": r.uploaded_by,
            "created_at":  r.created_at.isoformat(),
        }
        for r in rows
    ]


# ─── Upload + Analyze ────────────────────────────────────────────────────────

@router.post("/{incident_id}/pcap", status_code=201, summary="Analyze a PCAP")
async def upload_pcap(
    incident_id: uuid.UUID,
    file: UploadFile = File(...),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Upload a packet capture (max 500 MiB) and analyze it via the air-gapped
    analysis worker, persisting the result for the incident. Requires the
    analyst role and an open incident. Returns the analysis result JSON with the
    saved `result_id`."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    content = await _read_capped(file, _MAX_PCAP_BYTES)

    try:
        async with httpx.AsyncClient(timeout=300) as client:
            resp = await client.post(
                f"{WORKER_URL}/analyze/pcap",
                files={
                    "file": (
                        file.filename or "capture.pcap",
                        content,
                        "application/octet-stream",
                    )
                },
            )
        if not resp.is_success:
            try:
                err = resp.json().get("detail", "Analysis failed")
            except Exception:
                err = f"Analysis worker error ({resp.status_code})"
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, err)
        data = resp.json()
        if data.get("error"):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, data["error"])
    except httpx.ConnectError:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Analysis worker unavailable — check fenrir-analysis container",
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, f"Analysis failed: {e}")

    record = PCAPAnalysis(
        id=uuid.uuid4(),
        incident_id=incident_id,
        filename=file.filename or "capture.pcap",
        file_size=len(content),
        uploaded_by_id=user.id,
        uploaded_by=user.username,
        result_json=data,
    )
    db.add(record)
    await db.flush()

    await write_audit(
        db,
        "pcap_upload",
        user_id=user.id,
        username=user.username,
        resource_type="pcap_analysis",
        resource_id=str(record.id),
        details={
            "incident_id": str(incident_id),
            "filename": record.filename,
            "file_size": len(content),
        },
        ip_address=request.client.host if request and request.client else None,
    )
    await db.commit()

    data["result_id"] = str(record.id)
    return data


# ─── Import IOCs (literal before parametric) ─────────────────────────────────

@router.post("/{incident_id}/pcap/{result_id}/import-iocs", status_code=201,
             summary="Import IOCs from a PCAP analysis")
async def import_pcap_iocs(
    incident_id: uuid.UUID,
    result_id: uuid.UUID,
    body: _IocImportBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Import selected indicators (ip, domain, url only) from a saved PCAP
    analysis into the incident's IOC list, deduplicating against existing
    values and tagging them (`pcap` by default, or `tags_override`). Requires
    the analyst role and an open incident. Returns `{imported, skipped_duplicates}`."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    r = (
        await db.execute(
            select(PCAPAnalysis).where(
                PCAPAnalysis.id == result_id,
                PCAPAnalysis.incident_id == incident_id,
            )
        )
    ).scalar_one_or_none()
    if not r:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Result not found")

    if not body.iocs:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No IOCs to import")

    # Pre-load existing values for fast dedup
    existing = set(
        row[0]
        for row in (
            await db.execute(select(IOC.value).where(IOC.incident_id == incident_id))
        ).fetchall()
    )

    imported = 0
    skipped  = 0
    auto_tags = body.tags_override if body.tags_override else ["pcap"]
    audit_source = "pcap-analysis" if auto_tags == ["pcap"] else f"pcap-analysis:{auto_tags[0]}"
    for item in body.iocs:
        ioc_type = (item.type or "").strip()
        value    = (item.value or "").strip()
        notes    = (item.notes or "").strip() or None

        if not value or ioc_type not in _ALLOWED_IOC_TYPES or value in existing:
            skipped += 1
            continue

        ioc = IOC(
            id=uuid.uuid4(),
            incident_id=incident_id,
            type=ioc_type,
            value=value,
            notes=notes,
            source=audit_source,
            tags=auto_tags,
            added_by_id=user.id,
        )
        db.add(ioc)
        try:
            await db.flush()
            existing.add(value)
            imported += 1
        except IntegrityError:
            await db.rollback()
            skipped += 1

    await write_audit(
        db,
        "pcap_import_iocs",
        user_id=user.id,
        username=user.username,
        resource_type="pcap_analysis",
        resource_id=str(result_id),
        details={
            "incident_id": str(incident_id),
            "imported": imported,
            "skipped": skipped,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return {"imported": imported, "skipped_duplicates": skipped}


# ─── DNS recon (literal sub-path before parametric /{result_id}) ────────────

@router.get(
    "/{incident_id}/pcap/{result_id}/dns-recon",
    response_model=DnsReconResponse,
    summary="Get DNS recon for a PCAP analysis",
)
async def get_pcap_dns_recon(
    incident_id: uuid.UUID,
    result_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
):
    """Aggregate the saved PCAP's raw DNS queries into a per-domain analyst
    view (query chains, suspicious flags, DGA candidates, top resolvers).
    Pure derivation — no worker round-trip, no extra storage."""
    await _get_incident(db, incident_id, user)
    r = (
        await db.execute(
            select(PCAPAnalysis).where(
                PCAPAnalysis.id == result_id,
                PCAPAnalysis.incident_id == incident_id,
            )
        )
    ).scalar_one_or_none()
    if not r:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Result not found")
    queries = (r.result_json or {}).get("dns_queries", []) or []
    return build_recon(str(r.id), queries)


# ─── Get one ─────────────────────────────────────────────────────────────────

@router.get("/{incident_id}/pcap/{result_id}", summary="Get a PCAP analysis")
async def get_pcap(
    incident_id: uuid.UUID,
    result_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
):
    """Fetch a single saved PCAP analysis by id within the incident, returning
    the full stored result JSON plus `result_id`, `filename`, and `saved_at`.
    Requires access to the incident. 404 if not found."""
    await _get_incident(db, incident_id, user)
    r = (
        await db.execute(
            select(PCAPAnalysis).where(
                PCAPAnalysis.id == result_id,
                PCAPAnalysis.incident_id == incident_id,
            )
        )
    ).scalar_one_or_none()
    if not r:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Result not found")
    data = dict(r.result_json or {})
    data["result_id"] = str(r.id)
    data["filename"]  = r.filename
    data["saved_at"]  = r.created_at.isoformat()
    return data


# ─── Delete ──────────────────────────────────────────────────────────────────

@router.delete("/{incident_id}/pcap/{result_id}", summary="Delete a PCAP analysis")
async def delete_pcap(
    incident_id: uuid.UUID,
    result_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Delete a saved PCAP analysis by id from the incident. Requires the
    analyst role and an open incident. Returns `{status: "ok"}`; 404 if not
    found."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    r = (
        await db.execute(
            select(PCAPAnalysis).where(
                PCAPAnalysis.id == result_id,
                PCAPAnalysis.incident_id == incident_id,
            )
        )
    ).scalar_one_or_none()
    if not r:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Result not found")

    await write_audit(
        db,
        "pcap_delete",
        user_id=user.id,
        username=user.username,
        resource_type="pcap_analysis",
        resource_id=str(r.id),
        details={"incident_id": str(incident_id), "filename": r.filename},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(r)
    await db.commit()
    return {"status": "ok"}
