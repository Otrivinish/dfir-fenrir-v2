"""Browser history analyzer routes.

Upload a Chrome/Edge/Brave `History` file or Firefox `places.sqlite`
(mounted under /api/incidents). The raw file is quarantined as an Artifact
(same convention as email_analyzer) with an optional later "mint as
Evidence"; the parsed visits/search-terms are persisted so the page
survives a refresh -- not held in request-scoped memory.
"""
import asyncio
import base64
import hashlib
import json as _json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from sqlalchemy import insert, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.config import settings
from core.database import get_db
from evidence.crypto import awrite_encrypted
from incidents.access import get_accessible_incident
from models import (Artifact, BrowserHistoryDownload, BrowserHistorySearchTerm,
                    BrowserHistoryUpload, BrowserHistoryVisit, Evidence, User, utcnow)
from schemas import (BrowserHistoryDownloadList, BrowserHistoryDownloadOut,
                     BrowserHistorySearchTermList, BrowserHistorySearchTermOut,
                     BrowserHistoryUploadList, BrowserHistoryUploadOut,
                     BrowserHistoryVisitList, BrowserHistoryVisitOut)
from webhistory.parser import SQLITE_MAGIC, parse_history_db

router = APIRouter()

MAX_UPLOAD_BYTES = 500 * 1024 * 1024
_INSERT_BATCH = 5000
_VALID_BROWSERS = {"chrome", "edge", "brave", "firefox"}


# ─── Quarantine helpers (same convention as email_analyzer/routes.py) ───────

def _quarantine_dir(incident_id: uuid.UUID) -> Path:
    return Path(settings.quarantine_path) / str(incident_id)


def _safe_filename(name: str) -> str:
    import re
    base = re.sub(r"[^A-Za-z0-9._-]", "_", (name or "file").strip()) or "file"
    return base[:200]


def _store_quarantine(incident_id: uuid.UUID, filename: str, data: bytes) -> tuple[uuid.UUID, str]:
    aid = uuid.uuid4()
    stored = f"{aid}_{_safe_filename(filename)}"
    out_dir = _quarantine_dir(incident_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / stored).write_bytes(data)
    return aid, stored


def _read_quarantine(incident_id: uuid.UUID, stored_filename: str) -> bytes:
    p = (_quarantine_dir(incident_id) / stored_filename).resolve()
    root = Path(settings.quarantine_path).resolve()
    if root not in p.parents:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid path")
    if not p.exists():
        raise HTTPException(status.HTTP_410_GONE, "Source file no longer in quarantine")
    return p.read_bytes()


# ─── Cursor helpers (same convention as correlations/routes.py) ────────────

def _enc(offset: int) -> str:
    return base64.urlsafe_b64encode(_json.dumps({"o": offset}).encode()).decode().rstrip("=")


def _dec(cursor: Optional[str]) -> int:
    if not cursor:
        return 0
    try:
        pad = "=" * (-len(cursor) % 4)
        data = _json.loads(base64.urlsafe_b64decode(cursor + pad).decode())
        return max(0, int(data.get("o", 0)))
    except Exception:
        return 0


async def _incident(db, incident_id, user, *, writable=True):
    inc = await get_accessible_incident(db, incident_id, user)
    if writable and inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    return inc


async def _get_upload(db, incident_id, upload_id) -> BrowserHistoryUpload:
    u = (await db.execute(
        select(BrowserHistoryUpload).where(
            BrowserHistoryUpload.id == upload_id,
            BrowserHistoryUpload.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not u:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Upload not found")
    return u


# ─── Upload + parse ──────────────────────────────────────────────────────────

@router.post("/{incident_id}/webhistory", response_model=BrowserHistoryUploadOut,
             status_code=status.HTTP_201_CREATED, summary="Upload and parse a browser history database")
async def upload_history(
    incident_id: uuid.UUID,
    request: Request,
    file: UploadFile = File(...),
    browser: str = Form(...),
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> BrowserHistoryUploadOut:
    """Parse a Chrome/Edge/Brave `History` or Firefox `places.sqlite` file
    (capped at 500 MB). Quarantines the raw file as an Artifact, persists
    every visit and (Chromium only) typed search term, and returns the
    upload summary. Requires the analyst role and an open incident.
    """
    inc = await _incident(db, incident_id, user)

    if browser not in _VALID_BROWSERS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"browser must be one of {sorted(_VALID_BROWSERS)}")

    data = await file.read()
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty file")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, f"File exceeds {MAX_UPLOAD_BYTES} bytes")
    if data[:16] != SQLITE_MAGIC:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Not a SQLite database")

    try:
        parsed = await asyncio.to_thread(parse_history_db, data)
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))

    src_name = file.filename or "History"
    art_id, stored = _store_quarantine(incident_id, src_name, data)
    sha256 = hashlib.sha256(data).hexdigest()

    artifact = Artifact(
        id=art_id, incident_id=incident_id,
        original_filename=src_name, stored_filename=stored,
        file_size=len(data), mime_type="application/vnd.sqlite3",
        md5_hash=hashlib.md5(data).hexdigest(), sha256_hash=sha256,
        sha512_hash=hashlib.sha512(data).hexdigest(),
        description=f"Browser history ({browser})",
        uploaded_by_id=user.id, uploaded_by=user.username,
    )
    db.add(artifact)

    upload = BrowserHistoryUpload(
        id=uuid.uuid4(), incident_id=incident_id,
        browser=browser, schema_family=parsed["schema_family"],
        source_artifact_id=art_id,
        original_filename=src_name, file_size=len(data), sha256_hash=sha256,
        record_count=len(parsed["visits"]), search_term_count=len(parsed["search_terms"]),
        download_count=len(parsed["downloads"]),
        truncated=parsed["truncated"],
        uploaded_by_id=user.id, uploaded_by=user.username,
    )
    db.add(upload)
    await db.flush()

    visit_rows = [{
        "id": uuid.uuid4(), "upload_id": upload.id, "incident_id": incident_id,
        "url": v["url"][:8192], "host": (v["host"] or None) and v["host"][:512],
        "title": v["title"], "visit_time": v["visit_time"],
        "visit_count": v["visit_count"], "transition": v["transition"],
    } for v in parsed["visits"]]
    for i in range(0, len(visit_rows), _INSERT_BATCH):
        await db.execute(insert(BrowserHistoryVisit), visit_rows[i:i + _INSERT_BATCH])

    term_rows = [{
        "id": uuid.uuid4(), "upload_id": upload.id, "incident_id": incident_id,
        "term": t["term"], "url": t["url"], "visit_time": t["visit_time"],
    } for t in parsed["search_terms"]]
    for i in range(0, len(term_rows), _INSERT_BATCH):
        await db.execute(insert(BrowserHistorySearchTerm), term_rows[i:i + _INSERT_BATCH])

    download_rows = [{
        "id": uuid.uuid4(), "upload_id": upload.id, "incident_id": incident_id,
        "url": (d["url"] or None) and d["url"][:8192],
        "target_path": (d["target_path"] or None) and d["target_path"][:2048],
        "start_time": d["start_time"], "end_time": d["end_time"],
        "received_bytes": d["received_bytes"], "total_bytes": d["total_bytes"],
        "state": d["state"], "danger": d["danger"], "mime_type": d["mime_type"],
    } for d in parsed["downloads"]]
    for i in range(0, len(download_rows), _INSERT_BATCH):
        await db.execute(insert(BrowserHistoryDownload), download_rows[i:i + _INSERT_BATCH])

    await write_audit(
        db, "webhistory_upload",
        user_id=user.id, username=user.username,
        resource_type="browser_history_upload", resource_id=str(upload.id),
        details={
            "incident_id": str(incident_id), "browser": browser,
            "schema_family": parsed["schema_family"],
            "record_count": len(visit_rows), "search_term_count": len(term_rows),
            "download_count": len(download_rows),
            "sha256": sha256,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return BrowserHistoryUploadOut.model_validate(upload)


@router.get("/{incident_id}/webhistory", response_model=BrowserHistoryUploadList,
            summary="List browser history uploads")
async def list_uploads(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> BrowserHistoryUploadList:
    await _incident(db, incident_id, user, writable=False)
    rows = (await db.execute(
        select(BrowserHistoryUpload)
        .where(BrowserHistoryUpload.incident_id == incident_id)
        .order_by(BrowserHistoryUpload.uploaded_at.desc())
    )).scalars().all()
    return BrowserHistoryUploadList(items=[BrowserHistoryUploadOut.model_validate(r) for r in rows])


@router.delete("/{incident_id}/webhistory/{upload_id}", summary="Delete a browser history upload")
async def delete_upload(
    incident_id: uuid.UUID,
    upload_id: uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Delete an upload and its visits/search terms (cascade). Does not
    delete the quarantined Artifact or any minted Evidence -- those are
    managed from their own pages. Requires the analyst role and an open
    incident."""
    await _incident(db, incident_id, user)
    upload = await _get_upload(db, incident_id, upload_id)

    await write_audit(
        db, "webhistory_delete",
        user_id=user.id, username=user.username,
        resource_type="browser_history_upload", resource_id=str(upload.id),
        details={"incident_id": str(incident_id)},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(upload)
    await db.commit()
    return {"status": "ok"}


# ─── Mint quarantined file as Evidence (mirrors email_analyzer) ────────────

@router.post("/{incident_id}/webhistory/{upload_id}/mint-evidence",
             response_model=BrowserHistoryUploadOut, summary="Mint the raw history file as Evidence")
async def mint_evidence(
    incident_id: uuid.UUID,
    upload_id: uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> BrowserHistoryUploadOut:
    inc = await _incident(db, incident_id, user)
    upload = await _get_upload(db, incident_id, upload_id)
    if upload.evidence_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Already minted as Evidence")
    if not upload.source_artifact_id:
        raise HTTPException(status.HTTP_410_GONE, "Source artifact missing")

    src = (await db.execute(select(Artifact).where(Artifact.id == upload.source_artifact_id))).scalar_one_or_none()
    if not src:
        raise HTTPException(status.HTTP_410_GONE, "Source artifact missing")
    raw = _read_quarantine(incident_id, src.stored_filename)

    ev_id = uuid.uuid4()
    rel = f"webhistory/{ev_id}.db.enc"
    await awrite_encrypted(raw, rel)
    nonce = (Path(settings.evidence_path) / (rel + ".nonce")).read_text().strip()
    short = str(upload_id)[:8]
    ev = Evidence(
        id=ev_id, incident_id=incident_id, kind="digital_file", status="active",
        name=f"Browser history ({upload.browser}): {upload.original_filename}",
        identifier=f"WEBHIST-{short}",
        original_filename=upload.original_filename, storage_path=rel, nonce_hex=nonce,
        file_size_bytes=len(raw), mime_type="application/vnd.sqlite3",
        sha256=hashlib.sha256(raw).hexdigest(), sha1=hashlib.sha1(raw).hexdigest(),
        md5=hashlib.md5(raw).hexdigest(),
        current_custodian_id=user.id, collected_by_id=user.id, collected_at=utcnow(),
    )
    db.add(ev)
    await db.flush()
    upload.evidence_id = ev_id
    await write_audit(
        db, "webhistory_mint_evidence",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev_id), outcome="success",
        details={"incident_id": str(incident_id), "upload_id": str(upload_id), "sha256": ev.sha256},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return BrowserHistoryUploadOut.model_validate(upload)


# ─── Visits (paginated + filterable) ────────────────────────────────────────

@router.get("/{incident_id}/webhistory/visits", response_model=BrowserHistoryVisitList,
            summary="List/search browser history visits")
async def list_visits(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
    search:     Optional[str] = Query(default=None, description="Substring match on URL/title/host"),
    upload_id:  Optional[uuid.UUID] = Query(default=None),
    browser:    Optional[str] = Query(default=None),
    date_from:  Optional[datetime] = Query(default=None),
    date_to:    Optional[datetime] = Query(default=None),
    limit:      int = Query(default=100, ge=1, le=500),
    cursor:     Optional[str] = Query(default=None),
) -> BrowserHistoryVisitList:
    await _incident(db, incident_id, user, writable=False)
    offset = _dec(cursor)

    stmt = (
        select(BrowserHistoryVisit, BrowserHistoryUpload.browser)
        .join(BrowserHistoryUpload, BrowserHistoryUpload.id == BrowserHistoryVisit.upload_id)
        .where(BrowserHistoryVisit.incident_id == incident_id)
    )
    if upload_id:
        stmt = stmt.where(BrowserHistoryVisit.upload_id == upload_id)
    if browser:
        stmt = stmt.where(BrowserHistoryUpload.browser == browser)
    if search:
        like = f"%{search}%"
        stmt = stmt.where(or_(
            BrowserHistoryVisit.url.ilike(like),
            BrowserHistoryVisit.title.ilike(like),
            BrowserHistoryVisit.host.ilike(like),
        ))
    if date_from:
        stmt = stmt.where(BrowserHistoryVisit.visit_time >= date_from)
    if date_to:
        stmt = stmt.where(BrowserHistoryVisit.visit_time <= date_to)

    stmt = stmt.order_by(BrowserHistoryVisit.visit_time.desc()).offset(offset).limit(limit + 1)
    rows = (await db.execute(stmt)).all()

    has_more = len(rows) > limit
    rows = rows[:limit]
    items = []
    for visit, browser_label in rows:
        out = BrowserHistoryVisitOut.model_validate(visit)
        out.browser = browser_label
        items.append(out)

    return BrowserHistoryVisitList(items=items, next_cursor=_enc(offset + limit) if has_more else None)


# ─── Search terms (Chromium only) ───────────────────────────────────────────

@router.get("/{incident_id}/webhistory/search-terms", response_model=BrowserHistorySearchTermList,
            summary="List browser search terms (Chromium)")
async def list_search_terms(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
    search:    Optional[str] = Query(default=None),
    upload_id: Optional[uuid.UUID] = Query(default=None),
    limit:     int = Query(default=100, ge=1, le=500),
    cursor:    Optional[str] = Query(default=None),
) -> BrowserHistorySearchTermList:
    await _incident(db, incident_id, user, writable=False)
    offset = _dec(cursor)

    stmt = (
        select(BrowserHistorySearchTerm, BrowserHistoryUpload.browser)
        .join(BrowserHistoryUpload, BrowserHistoryUpload.id == BrowserHistorySearchTerm.upload_id)
        .where(BrowserHistorySearchTerm.incident_id == incident_id)
    )
    if upload_id:
        stmt = stmt.where(BrowserHistorySearchTerm.upload_id == upload_id)
    if search:
        stmt = stmt.where(BrowserHistorySearchTerm.term.ilike(f"%{search}%"))

    stmt = stmt.order_by(BrowserHistorySearchTerm.visit_time.desc()).offset(offset).limit(limit + 1)
    rows = (await db.execute(stmt)).all()

    has_more = len(rows) > limit
    rows = rows[:limit]
    items = []
    for term, browser_label in rows:
        out = BrowserHistorySearchTermOut.model_validate(term)
        out.browser = browser_label
        items.append(out)

    return BrowserHistorySearchTermList(items=items, next_cursor=_enc(offset + limit) if has_more else None)


# ─── Downloads (paginated + filterable) ─────────────────────────────────────

@router.get("/{incident_id}/webhistory/downloads", response_model=BrowserHistoryDownloadList,
            summary="List/search browser downloads")
async def list_downloads(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
    search:    Optional[str] = Query(default=None, description="Substring match on URL/target path"),
    upload_id: Optional[uuid.UUID] = Query(default=None),
    browser:   Optional[str] = Query(default=None),
    date_from: Optional[datetime] = Query(default=None),
    date_to:   Optional[datetime] = Query(default=None),
    limit:     int = Query(default=100, ge=1, le=500),
    cursor:    Optional[str] = Query(default=None),
) -> BrowserHistoryDownloadList:
    await _incident(db, incident_id, user, writable=False)
    offset = _dec(cursor)

    stmt = (
        select(BrowserHistoryDownload, BrowserHistoryUpload.browser)
        .join(BrowserHistoryUpload, BrowserHistoryUpload.id == BrowserHistoryDownload.upload_id)
        .where(BrowserHistoryDownload.incident_id == incident_id)
    )
    if upload_id:
        stmt = stmt.where(BrowserHistoryDownload.upload_id == upload_id)
    if browser:
        stmt = stmt.where(BrowserHistoryUpload.browser == browser)
    if search:
        like = f"%{search}%"
        stmt = stmt.where(or_(
            BrowserHistoryDownload.url.ilike(like),
            BrowserHistoryDownload.target_path.ilike(like),
        ))
    if date_from:
        stmt = stmt.where(BrowserHistoryDownload.start_time >= date_from)
    if date_to:
        stmt = stmt.where(BrowserHistoryDownload.start_time <= date_to)

    stmt = stmt.order_by(BrowserHistoryDownload.start_time.desc()).offset(offset).limit(limit + 1)
    rows = (await db.execute(stmt)).all()

    has_more = len(rows) > limit
    rows = rows[:limit]
    items = []
    for dl, browser_label in rows:
        out = BrowserHistoryDownloadOut.model_validate(dl)
        out.browser = browser_label
        items.append(out)

    return BrowserHistoryDownloadList(items=items, next_cursor=_enc(offset + limit) if has_more else None)
