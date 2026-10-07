"""Browser history analyzer routes.

Upload a Chrome/Edge/Brave `History` file or Firefox `places.sqlite`
(mounted under /api/incidents). The parsed visits/search-terms are persisted
so the page survives a refresh -- not held in request-scoped memory.

G3 (R02) register-first: the history file IS an exhibit. An upload is registered
as an unsealed draft exhibit first (or linked to the one active exhibit with the
same SHA-256) and that exhibit is parsed; `from-evidence/{evidence_id}` parses a
registered exhibit (hash re-verified). No quarantine copy is made. Each upload
carries its run record (exhibit, input SHA-256, parser + version, the exhibit's
clock offset) and the parse is in the exhibit's custody log. `promote` puts
visits / downloads on the Timeline (server-side copy, offset applied, immutable
facts). Uploads made before G3 keep their quarantine copy and the legacy
"Register as exhibit" (mint-evidence).
"""
import asyncio
import base64
import hashlib
import json as _json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from sqlalchemy import func, insert, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.config import settings
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from artifacts import store as artifact_store
from evidence.crypto import EvidenceCryptoError, awrite_encrypted
from evidence.hashing import ahashes_of
from evidence.streaming import require_free_space
from evidence.register import (EXAMINED_MASTER, EXAMINED_MATCH, EXAMINED_UPLOAD, UPLOAD_ID_DOC, ExhibitInput,
                               examine_audit, exhibit_brief, link_error_extra, read_exhibit_for_analysis,
                               recheck_exhibit, register_or_link_upload, upload_link_for)
from evidence.routes import _check_acquired_at
from forensic.routes import clock_offset_fields, exhibit_info, scratch_full
from incidents.access import get_accessible_incident
from models import (Artifact, BrowserHistoryDownload, BrowserHistorySearchTerm,
                    BrowserHistoryUpload, BrowserHistoryVisit, Evidence, TimelineEvent, User, utcnow)
from schemas import (BrowserHistoryDownloadList, BrowserHistoryDownloadOut, BrowserHistoryFromEvidence,
                     BrowserHistoryPromote, BrowserHistoryPromoteResult,
                     BrowserHistorySearchTermList, BrowserHistorySearchTermOut,
                     BrowserHistoryUploadList, BrowserHistoryUploadOut,
                     BrowserHistoryVisitList, BrowserHistoryVisitOut)
from webhistory.parser import (PARSER_NAME, PARSER_VERSION, SQLITE_MAGIC, parse_form_history_db,
                               parse_history_db)

router = APIRouter()

MAX_UPLOAD_BYTES = 500 * 1024 * 1024
_MULTIPART_TOTAL_MAX = 512 * 1024 * 1024     # the deprecated multipart route: both files together (R80)
_INSERT_BATCH = 5000
_PROMOTE_CHUNK = 900            # timeline rows per INSERT (≈33 binds/row; asyncpg caps a statement at 32767)


def _json_default(o):
    """raw_log JSON: datetimes as UTC ISO 8601 `…Z`, anything else as text."""
    if isinstance(o, datetime):
        return o.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(o)
_VALID_BROWSERS = {"chrome", "edge", "brave", "firefox"}


# ─── Quarantine helpers (same convention as email_analyzer/routes.py) ───────

def _safe_filename(name: str) -> str:
    import re
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


def _read_quarantine(src: Artifact) -> bytes:
    """A pre-G3 upload's quarantined history DB (H1: either row format, ≤ the upload cap). 410 when the
    file is gone, 409 artifact_integrity_failed / 503 artifact_read_error (artifacts/store.py)."""
    try:
        return artifact_store.read_all(src, MAX_UPLOAD_BYTES)
    except EvidenceCryptoError as e:
        raise artifact_store.read_error(e, missing_status=status.HTTP_410_GONE,
                                        missing_detail="Source file no longer in quarantine") from None


# ─── Cursor helpers (same convention as correlations/routes.py) ────────────

# L11, accepted: a row deleted between two page reads makes an offset cursor skip one row; the war room pages by keyset.
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
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")
    return inc


_CLOSED_409 = {409: {"model": ApiErrorBody, "description": "incident_closed"}}


async def _read_capped(file: UploadFile, cap: int, what: str = "File") -> bytes:
    """Read an upload, aborting as soon as it exceeds `cap` (never trusts Content-Length)."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > cap:
            raise ApiError(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "file_too_large",
                           f"{what} is larger than {cap // (1024 * 1024)} MiB ({cap} bytes): nothing was stored.")
        chunks.append(chunk)
    return b"".join(chunks)


async def _upload_out(db, rows: list) -> list[BrowserHistoryUploadOut]:
    """G3 — uploads with their run record resolved: exhibit identifiers + draft state, and the clock
    offset applied vs the exhibit's offset now (G4 ClockOffsetStatus)."""
    brief = await exhibit_brief(db, [i for r in rows for i in (r.evidence_id, r.form_history_evidence_id)])
    info = await exhibit_info(db, [r.evidence_id for r in rows if r.parser_version])
    out = []
    for r in rows:
        o = BrowserHistoryUploadOut.model_validate(r)
        if r.evidence_id in brief:
            o.evidence_identifier, o.evidence_sealed = brief[r.evidence_id]
        if r.form_history_evidence_id in brief:
            o.form_history_evidence_identifier = brief[r.form_history_evidence_id][0]
        if r.parser_version:             # offset status only for run-record uploads
            for k, v in clock_offset_fields(r.evidence_id, r.clock_offset_seconds, info).items():
                setattr(o, k, v)
        out.append(o)
    return out


async def _timeline_events_of(db, record_ids: list) -> dict:
    """G3 — {visit/download id: the Timeline event promoted from it} for one page of records."""
    if not record_ids:
        return {}
    rows = (await db.execute(
        select(TimelineEvent.source_record_id, TimelineEvent.id).where(
            TimelineEvent.browser_history_upload_id.isnot(None),
            TimelineEvent.source_record_id.in_(record_ids))
    )).all()
    return {r[0]: r[1] for r in rows}


async def _get_upload(db, incident_id, upload_id, *, for_update: bool = False) -> BrowserHistoryUpload:
    stmt = select(BrowserHistoryUpload).where(
        BrowserHistoryUpload.id == upload_id,
        BrowserHistoryUpload.incident_id == incident_id,
    )
    if for_update:          # L28: delete serialises with promote (row lock) instead of a foreign-key 500
        stmt = stmt.with_for_update(of=BrowserHistoryUpload).execution_options(populate_existing=True)
    u = (await db.execute(stmt)).scalar_one_or_none()
    if not u:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Upload not found")
    return u


# ─── Upload + parse ──────────────────────────────────────────────────────────

_UPLOAD_RESPONSES = {
    **_CLOSED_409,
    413: {"model": ApiErrorBody, "description": "file_too_large (a file is larger than 500 MiB)"},
    422: {"model": ApiErrorBody,
          "description": "not a SQLite database (nothing stored), acquired_in_future, or parse_failed (the "
                         "file stays registered as a draft exhibit: `evidence_id` in the body)"},
    507: {"model": ApiErrorBody, "description": "insufficient_storage (the evidence volume or the upload scratch space is full; nothing stored)"},
}


async def _parse_and_store(db, inc, x: ExhibitInput, fx: Optional[ExhibitInput], browser: str, src_name: str,
                           user: User, ip: Optional[str], chunked: tuple = (None, None)) -> BrowserHistoryUpload:
    """Parse the history exhibit (and Firefox's formhistory exhibit), store the upload with its run
    record and every visit / search term / download, and write the examination to the exhibits'
    custody logs. Parsing runs off the event loop. `chunked` = (upload_id, its link) of the chunked
    upload the history exhibit came from (R93; from-evidence only)."""
    upload_id, upload_link = chunked
    incident_id = inc.id
    offset = x.evidence.system_time_offset_seconds
    base = {"incident_id": str(incident_id), "tool": PARSER_NAME, "version": PARSER_VERSION,
            "params": {"browser": browser, "clock_offset_seconds": offset,
                       "form_history_evidence_id": str(fx.evidence.id) if fx else None}}

    async def _fail(which: ExhibitInput, exc: Exception):
        full = scratch_full(exc)                  # R80: the shared memory-only tmpfs is full → 507
        await examine_audit(db, user=user, ip=ip, evidence_id=which.evidence.id, outcome="failure",
                            details={**base, "result": "scratch_full" if full else "parse_failed",
                                     "error": str(exc)[:500]})
        await db.commit()
        if full:
            raise full from exc
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "parse_failed",
                       f"{exc}. The file is registered as exhibit {which.evidence.identifier}; nothing was parsed.",
                       extra=link_error_extra(which)) from exc

    try:
        parsed = await asyncio.to_thread(parse_history_db, x.data)
    except ValueError as e:
        await _fail(x, e)
    if fx is not None:
        try:
            form_terms = await asyncio.to_thread(parse_form_history_db, fx.data)
        except ValueError as e:
            await _fail(fx, e)
        parsed["search_terms"] = [*parsed["search_terms"], *form_terms]
    if x.link == "from_evidence":        # the decrypt + parse took a while: re-check under a row lock
        await recheck_exhibit(db, incident_id=incident_id, evidence_id=x.evidence.id, user=user, ip=ip, base=base)
        if fx is not None:
            await recheck_exhibit(db, incident_id=incident_id, evidence_id=fx.evidence.id, user=user, ip=ip, base=base)

    upload = BrowserHistoryUpload(
        id=uuid.uuid4(), incident_id=incident_id,
        browser=browser, schema_family=parsed["schema_family"],
        source_artifact_id=None, form_history_artifact_id=None,
        evidence_id=x.evidence.id, form_history_evidence_id=fx.evidence.id if fx else None,
        parser_name=PARSER_NAME, parser_version=PARSER_VERSION, exhibit_link=upload_link or x.link,
        clock_offset_seconds=offset,
        original_filename=src_name[:512], file_size=len(x.data), sha256_hash=x.sha256,
        record_count=len(parsed["visits"]), search_term_count=len(parsed["search_terms"]),
        download_count=len(parsed["downloads"]),
        truncated=parsed["truncated"],
        uploaded_by_id=user.id, uploaded_by=user.username,
    )
    db.add(upload)
    await db.flush()
    await _insert_rows(db, upload, parsed)

    for which, result in ((x, "browser_history_parse"), (fx, "browser_form_history_parse")):
        if which is None:
            continue
        await examine_audit(db, user=user, ip=ip, evidence_id=which.evidence.id, details={
            **base, "result": result, "browser_history_upload_id": str(upload.id),
            "method": {"registered": "upload_registered", "sha256_match": "upload_sha256_match"}.get(which.link, "from_evidence"),
            "examined_on": {"registered": EXAMINED_UPLOAD, "sha256_match": EXAMINED_MATCH}.get(which.link, EXAMINED_MASTER),
            "sha256_verified": which.sha256, "schema_family": parsed["schema_family"],
            "record_count": upload.record_count, "search_term_count": upload.search_term_count,
            "download_count": upload.download_count, "truncated": parsed["truncated"]})
    await write_audit(
        db, "webhistory_upload",
        user_id=user.id, username=user.username,
        resource_type="browser_history_upload", resource_id=str(upload.id),
        details={
            "incident_id": str(incident_id), "browser": browser,
            "schema_family": parsed["schema_family"],
            "record_count": upload.record_count, "search_term_count": upload.search_term_count,
            "download_count": upload.download_count,
            "sha256": x.sha256,
            "form_history_provided": fx is not None,
            "evidence_id": str(x.evidence.id), "evidence_identifier": x.evidence.identifier,
            "form_history_evidence_id": str(fx.evidence.id) if fx else None,
            "exhibit_link": upload.exhibit_link, "parser": PARSER_NAME, "parser_version": PARSER_VERSION,
            "clock_offset_seconds": offset,
            **({"upload_id": str(upload_id)} if upload_id else {}),
        },
        ip_address=ip,
    )
    await db.commit()
    return upload


async def _insert_rows(db, upload: BrowserHistoryUpload, parsed: dict) -> None:
    incident_id = upload.incident_id
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


@router.post("/{incident_id}/webhistory", response_model=BrowserHistoryUploadOut,
             status_code=status.HTTP_201_CREATED, responses=_UPLOAD_RESPONSES, deprecated=True,
             summary="Register a browser history database as a draft exhibit and parse it (multipart; "
                     "deprecated: use the upload session API)")
async def upload_history(
    incident_id: uuid.UUID,
    request: Request,
    file: UploadFile = File(...),
    browser: str = Form(...),
    form_history_file: Optional[UploadFile] = File(default=None),
    acquired_at: Optional[datetime] = Form(default=None, description="When the file was acquired (UTC; "
                                           "optional, unknown if omitted). Not in the future."),
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> BrowserHistoryUploadOut:
    """Deprecated (G1 stage 3b, R80): the whole multipart body is held by the server in its memory-only
    scratch space (tmpfs, 1 GiB shared by every upload and parse; 507 insufficient_storage when full)
    before this route sees it; the two files together are capped at 512 MiB (413). Use the upload
    session API instead — POST
    …/uploads (purpose=webhistory; formhistory.sqlite as its own upload with companion_of), PUT the
    chunks, POST …/uploads/{upload_id}/complete, then POST …/webhistory/from-evidence/{evidence_id}
    {browser, form_history_evidence_id}. Kept for API compatibility.

    Register-first (G3): a Chrome/Edge/Brave `History` or Firefox `places.sqlite` file (capped at
    500 MB, must be SQLite — else 422 and nothing is stored) is FIRST registered as an exhibit — a
    new unsealed draft (identifier `WEBHIST-…`, the caller as collector and custodian, `acquired_at`
    as supplied or unknown, lawful basis pending; hashed, encrypted at rest, audited
    `evidence_collect`) or the one active exhibit with the same SHA-256 — and then that exhibit is
    parsed: every visit, download and (Chromium) typed search term is persisted. No quarantine copy
    is made. Firefox only: an optional second file, `formhistory.sqlite`, becomes its own exhibit;
    its search-bar queries are merged into this upload's search terms. The run record (exhibit,
    `sha256_hash`, `parser_name` / `parser_version`, `exhibit_link`, the exhibit's clock offset) is
    on the upload and the parse is in the exhibit's custody log (`evidence_examine`). A file that
    can't be parsed stays registered: 422 parse_failed with `evidence_id`. Requires the analyst role
    and an open incident (409 incident_closed)."""
    inc = await _incident(db, incident_id, user)
    acquired_at = _check_acquired_at(acquired_at)

    if browser not in _VALID_BROWSERS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"browser must be one of {sorted(_VALID_BROWSERS)}")
    if form_history_file is not None and browser != "firefox":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "form_history_file is only supported for browser=firefox")

    data = await _read_capped(file, MAX_UPLOAD_BYTES)
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty file")
    if data[:16] != SQLITE_MAGIC:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Not a SQLite database")
    form_history_data = None
    if form_history_file is not None:
        # R80 (G-fix): both parts of this multipart body sit in the 1 GiB memory-only tmpfs together.
        form_history_data = await _read_capped(form_history_file,
                                               min(MAX_UPLOAD_BYTES, _MULTIPART_TOTAL_MAX - len(data)),
                                               "form_history_file (with the history file, 512 MiB together)")
        if not form_history_data:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty form_history_file")
        if form_history_data[:16] != SQLITE_MAGIC:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "form_history_file is not a SQLite database")

    ip = request.client.host if request.client else None
    src_name = Path(file.filename or "History").name or "History"
    x = await register_or_link_upload(
        db, incident_id=incident_id, user=user, data=data, filename=src_name,
        mime_type="application/vnd.sqlite3", prefix="WEBHIST",
        name=f"Browser history ({browser}): {src_name}", method="webhistory_upload",
        analyser_label="Browser history", acquired_at=acquired_at, ip=ip, extra={"browser": browser})
    fx = None
    if form_history_data is not None:
        await db.commit()       # review H1: never hold the audit-chain lock while the next file is encrypted
        fh_name = Path(form_history_file.filename or "formhistory.sqlite").name or "formhistory.sqlite"
        fx = await register_or_link_upload(
            db, incident_id=incident_id, user=user, data=form_history_data, filename=fh_name,
            mime_type="application/vnd.sqlite3", prefix="WEBHIST",
            name=f"Browser form history (firefox): {fh_name}", method="webhistory_upload",
            analyser_label="Browser history", acquired_at=acquired_at, ip=ip,
            extra={"browser": browser, "companion_of": str(x.evidence.id)})
    await db.commit()                     # registered first: the exhibits stand even if the parse fails
    upload = await _parse_and_store(db, inc, x, fx, browser, src_name, user, ip)
    return (await _upload_out(db, [upload]))[0]


@router.post("/{incident_id}/webhistory/from-evidence/{evidence_id}", response_model=BrowserHistoryUploadOut,
             status_code=status.HTTP_201_CREATED,
             summary="Parse a registered exhibit (hash re-verified) as browser history",
             responses={
                 404: {"model": ApiErrorBody, "description": "evidence_not_found"},
                 409: {"model": ApiErrorBody, "description": "incident_closed, evidence_not_active, "
                       "evidence_not_in_internal_custody, transfer_pending, evidence_storage_missing or "
                       "evidence_hash_mismatch (the item is frozen: verify_failed)"},
                 413: {"model": ApiErrorBody, "description": "exhibit_too_large_for_analyser (over the 500 MB "
                       "browser-history limit; checked before anything is decrypted)"},
                 422: {"model": ApiErrorBody, "description": "evidence_not_digital, not_sqlite, "
                       "form_history_not_firefox, same_exhibit, parse_failed or upload_link_not_found (upload_id)"},
                 503: {"model": ApiErrorBody, "description": "evidence_read_error (stored copy unreadable; not frozen)"},
             })
async def upload_history_from_evidence(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    req: BrowserHistoryFromEvidence,
    request: Request,
    upload_id: Optional[uuid.UUID] = Query(default=None, description=UPLOAD_ID_DOC),
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> BrowserHistoryUploadOut:
    """Parse an exhibit already registered in Evidence (a browser history SQLite, up to 500 MB) instead
    of re-uploading it — the C5/G4 rules: active, in internal custody, no pending transfer (409
    otherwise; re-checked under a row lock before anything is stored); decrypted and re-hashed off the
    event loop — a mismatch freezes the exhibit (409 evidence_hash_mismatch), an unreadable copy is 503
    evidence_read_error. Firefox: `form_history_evidence_id` names a second exhibit
    (formhistory.sqlite), verified the same way. The parse is recorded in each exhibit's custody log
    (`evidence_examine`). The exhibit's clock offset is recorded on the upload and applied when visits
    or downloads are promoted to the Timeline. After a chunked upload, pass the history file's
    `upload_id` so the run record keeps the upload's exhibit link (R93). The read transaction ends
    before the parse (L24). Requires the analyst role and an open incident."""
    inc = await _incident(db, incident_id, user)
    if req.form_history_evidence_id is not None and req.browser != "firefox":
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "form_history_not_firefox",
                       "form_history_evidence_id is only supported for browser=firefox")
    if req.form_history_evidence_id == evidence_id:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "same_exhibit",
                       "The form-history exhibit must be a different exhibit")
    upload_link = await upload_link_for(db, upload_id=upload_id, incident_id=incident_id, evidence_id=evidence_id,
                                        purpose="webhistory", user=user)
    ip = request.client.host if request.client else None
    base = {"incident_id": str(incident_id), "tool": PARSER_NAME, "version": PARSER_VERSION,
            "params": {"browser": req.browser}}
    xs = []
    for eid in (evidence_id, req.form_history_evidence_id):
        if eid is None:
            continue
        x = await read_exhibit_for_analysis(db, incident_id=incident_id, evidence_id=eid, user=user, ip=ip,
                                            max_bytes=MAX_UPLOAD_BYTES, limit_label="500 MB browser history",
                                            phase="browser_history", base=base)
        if x.data[:16] != SQLITE_MAGIC:
            await examine_audit(db, user=user, ip=ip, evidence_id=eid, outcome="failure",
                                details={**base, "result": "not_sqlite", "error": "not a SQLite database"})
            await db.commit()
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "not_sqlite",
                           f"Exhibit {x.evidence.identifier} is not a SQLite database; nothing was parsed")
        xs.append(x)
    x, fx = xs[0], (xs[1] if len(xs) > 1 else None)
    src_name = Path(x.evidence.original_filename or "History").name or "History"
    await db.commit()                     # L24: end the read transaction before the (long) parse
    upload = await _parse_and_store(db, inc, x, fx, req.browser, src_name, user, ip,
                                    chunked=(upload_id, upload_link))
    return (await _upload_out(db, [upload]))[0]


def _promote_row(up: BrowserHistoryUpload, rec_id, when: datetime, *, event_type: str, description: str,
                 raw: dict, ir_phase, user_id, now) -> dict:
    """One timeline_events row copied from a stored visit / download. Browser times are UTC epochs
    (explicit); the upload's clock-offset snapshot corrects them and the recorded time is kept."""
    off = up.clock_offset_seconds
    return {
        "id": uuid.uuid4(), "incident_id": up.incident_id,
        "event_time": when - timedelta(seconds=off) if off is not None else when,
        "hostname": None, "entity_id": None,
        "source": f"Browser history ({up.browser})"[:128],
        "event_type": event_type[:128], "description": description,
        "raw_log": _json.dumps(raw, default=_json_default)[:4000],
        "ir_phase": ir_phase,
        "mitre_tactic_id": None, "mitre_tactic_name": None,
        "mitre_technique_id": None, "mitre_technique_name": None,
        "origin": "forensic_import", "is_system": False, "system_source": None,
        # Browsing history is personal data: internal-only until the analyst marks it external-safe.
        "external_safe": False, "created_by_id": user_id,
        "evidence_id": up.evidence_id, "forensic_import_id": None, "defender_import_id": None,
        "pcap_analysis_id": None, "browser_history_upload_id": up.id, "source_record_id": rec_id,
        "import_event_index": None, "time_basis": "explicit",
        "recorded_event_time": when if off is not None else None,
        "clock_offset_seconds": off,
        "created_at": now, "updated_at": now,
    }


@router.post("/{incident_id}/webhistory/promote", response_model=BrowserHistoryPromoteResult,
             summary="Put browser-history visits / downloads on the Timeline (server-side copy)",
             responses={**_CLOSED_409, 422: {"model": ApiErrorBody, "description": "validation error"}})
async def promote_history(
    incident_id: uuid.UUID,
    req: BrowserHistoryPromote,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> BrowserHistoryPromoteResult:
    """Put visits and downloads of this incident's browser-history uploads on the Timeline. The
    caller sends only ids; the server copies each record from its stored upload, so every event
    carries the upload's exhibit (`evidence_id`), the upload (`browser_history_upload_id`) and the
    record (`source_record_id`), `time_basis` explicit (browser times are UTC epochs) and — when the
    exhibit records a clock offset — the recorded time and the offset (event_time = recorded −
    offset). Promoted facts are immutable (timeline edits → 409 imported_fact_immutable). Events are
    internal-only (`external_safe` false: browsing history is personal data). A record of an upload
    made before run records → `reparse_required` (upload it again or parse its exhibit); a download
    without a start time → `skipped_untimestamped`; already promoted → `already_promoted` (re-promoting
    is a no-op); not a record of this incident → `not_found`. Requires the analyst role and an open
    incident; audited `webhistory_promote`."""
    await _incident(db, incident_id, user)
    visit_ids, download_ids = set(req.visit_ids), set(req.download_ids)
    visits = (await db.execute(
        select(BrowserHistoryVisit, BrowserHistoryUpload)
        .join(BrowserHistoryUpload, BrowserHistoryUpload.id == BrowserHistoryVisit.upload_id)
        .where(BrowserHistoryVisit.incident_id == incident_id, BrowserHistoryVisit.id.in_(visit_ids))
        .with_for_update(of=BrowserHistoryUpload)                  # L28: the parent upload, until commit
    )).all() if visit_ids else []
    downloads = (await db.execute(
        select(BrowserHistoryDownload, BrowserHistoryUpload)
        .join(BrowserHistoryUpload, BrowserHistoryUpload.id == BrowserHistoryDownload.upload_id)
        .where(BrowserHistoryDownload.incident_id == incident_id, BrowserHistoryDownload.id.in_(download_ids))
        .with_for_update(of=BrowserHistoryUpload)                  # L28
    )).all() if download_ids else []
    found = {v.id for v, _ in visits} | {d.id for d, _ in downloads}
    not_found = sorted((visit_ids | download_ids) - found, key=str)
    already = set((await db.execute(
        select(TimelineEvent.source_record_id).where(
            TimelineEvent.browser_history_upload_id.isnot(None), TimelineEvent.source_record_id.in_(found))
    )).scalars().all()) if found else set()

    now = utcnow()
    rows, reparse, untimed, again = [], [], [], []
    for v, up in visits:
        if up.parser_version is None or up.evidence_id is None:
            reparse.append(v.id); continue
        if v.id in already:
            again.append(v.id); continue
        desc = f"Visited {v.url[:2000]}" + (f" — {v.title[:300]}" if v.title else "")
        rows.append(_promote_row(up, v.id, v.visit_time,
                                 event_type="Web visit" + (f" ({v.transition})" if v.transition else ""),
                                 description=desc,
                                 raw={"record": "visit", "url": v.url, "title": v.title, "host": v.host,
                                      "visit_time": v.visit_time, "visit_count": v.visit_count,
                                      "transition": v.transition},
                                 ir_phase=req.ir_phase, user_id=user.id, now=now))
    for d, up in downloads:
        if up.parser_version is None or up.evidence_id is None:
            reparse.append(d.id); continue
        if d.id in already:
            again.append(d.id); continue
        if d.start_time is None:
            untimed.append(d.id); continue
        desc = (f"Downloaded {(d.target_path or '?')[:1000]} from {(d.url or '?')[:2000]}"
                + (f" ({d.state})" if d.state else "")
                + (f" — danger: {d.danger}" if d.danger and d.danger != "not_dangerous" else ""))
        rows.append(_promote_row(up, d.id, d.start_time, event_type="File download", description=desc,
                                 raw={"record": "download", "url": d.url, "target_path": d.target_path,
                                      "start_time": d.start_time, "end_time": d.end_time,
                                      "received_bytes": d.received_bytes, "total_bytes": d.total_bytes,
                                      "state": d.state, "danger": d.danger, "mime_type": d.mime_type},
                                 ir_phase=req.ir_phase, user_id=user.id, now=now))
    made: list = []
    for start in range(0, len(rows), _PROMOTE_CHUNK):
        res = await db.execute(
            pg_insert(TimelineEvent).values(rows[start:start + _PROMOTE_CHUNK])
            .on_conflict_do_nothing(index_elements=[TimelineEvent.browser_history_upload_id, TimelineEvent.source_record_id],
                                    index_where=TimelineEvent.browser_history_upload_id.isnot(None))
            .returning(TimelineEvent.source_record_id))
        made.extend(res.scalars().all())
    # A concurrent promote of the same record loses the ON CONFLICT race: count it as already there.
    again = sorted(set(again) | ({r["source_record_id"] for r in rows} - set(made)), key=str)
    uploads = {up.id: up for _, up in [*visits, *downloads]}
    await write_audit(
        db, "webhistory_promote",
        user_id=user.id, username=user.username,
        resource_type="incident", resource_id=str(incident_id),
        details={"incident_id": str(incident_id),
                 "uploads": sorted(str(u) for u in uploads),
                 "evidence_ids": sorted({str(u.evidence_id) for u in uploads.values() if u.evidence_id}),
                 "requested": len(visit_ids) + len(download_ids), "created_events": len(made),
                 "already_promoted": len(again), "skipped_untimestamped": len(untimed),
                 "reparse_required": len(reparse), "not_found": len(not_found), "ir_phase": req.ir_phase},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return BrowserHistoryPromoteResult(created=len(made), created_ids=sorted(made, key=str),
                                       skipped_untimestamped=sorted(untimed, key=str), already_promoted=again,
                                       not_found=not_found, reparse_required=sorted(reparse, key=str))


@router.get("/{incident_id}/webhistory", response_model=BrowserHistoryUploadList,
            summary="List browser history uploads")
async def list_uploads(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> BrowserHistoryUploadList:
    """List the incident's browser-history uploads, newest first, each with its run record (G3:
    exhibit + identifier + draft state, input SHA-256, parser + version, clock offset and its status)."""
    await _incident(db, incident_id, user, writable=False)
    rows = (await db.execute(
        select(BrowserHistoryUpload)
        .where(BrowserHistoryUpload.incident_id == incident_id)
        .order_by(BrowserHistoryUpload.uploaded_at.desc())
    )).scalars().all()
    return BrowserHistoryUploadList(items=await _upload_out(db, rows))


@router.delete("/{incident_id}/webhistory/{upload_id}", summary="Delete a browser history upload",
               responses={409: {"model": ApiErrorBody, "description": "incident_closed or import_has_promoted_events"}})
async def delete_upload(
    incident_id: uuid.UUID,
    upload_id: uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Delete an upload and its visits/search terms (cascade). Does not
    delete the exhibit, the quarantined Artifact of a pre-G3 upload or any
    minted Evidence -- those are managed from their own pages. 409
    `import_has_promoted_events` while timeline events promoted from it exist
    (the upload is their provenance record). Requires the analyst role and an
    open incident."""
    await _incident(db, incident_id, user)
    upload = await _get_upload(db, incident_id, upload_id, for_update=True)
    promoted = (await db.execute(select(func.count()).select_from(TimelineEvent)
                                 .where(TimelineEvent.browser_history_upload_id == upload.id))).scalar_one()
    if promoted:
        raise ApiError(status.HTTP_409_CONFLICT, "import_has_promoted_events",
                       f"{promoted} timeline event(s) were promoted from this upload; it is their "
                       "provenance record and can't be deleted while they exist")

    await write_audit(
        db, "webhistory_delete",
        user_id=user.id, username=user.username,
        resource_type="browser_history_upload", resource_id=str(upload.id),
        details={"incident_id": str(incident_id),
                 "evidence_id": str(upload.evidence_id) if upload.evidence_id else None,
                 "sha256": upload.sha256_hash, "parser_version": upload.parser_version},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(upload)
    await db.commit()
    return {"status": "ok"}


# ─── Mint quarantined file as Evidence (mirrors email_analyzer) ────────────

@router.post("/{incident_id}/webhistory/{upload_id}/mint-evidence",
             response_model=BrowserHistoryUploadOut,
             summary="Register a pre-G3 upload's history file as an exhibit (legacy)",
             operation_id="mint_webhistory_evidence",
             responses={409: {"model": ApiErrorBody, "description": "already_minted, artifact_hash_mismatch, or incident_closed"},
                        507: {"model": ApiErrorBody, "description": "insufficient_storage (the evidence volume is full; nothing stored)"}})
async def mint_evidence(
    incident_id: uuid.UUID,
    upload_id: uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> BrowserHistoryUploadOut:
    """Register the uploaded raw history database as an encrypted chain-of-custody exhibit — for an
    upload made BEFORE G3 only (it was parsed from a quarantine copy first); a G3 upload already is of
    an exhibit (`evidence_id` set: 400, as before).

    Re-hashes the quarantined file first: if its SHA-256 no longer matches the hash recorded
    at upload, nothing is minted (409 `artifact_hash_mismatch`, audited as
    `evidence_collect_rejected`). Otherwise stores it AES-encrypted with `acquired_at` = the
    upload time and audits `evidence_collect` (details.method = webhistory_mint). 409
    already_minted if already minted, 410 if the source file is gone. Requires the analyst role.
    """
    await _incident(db, incident_id, user)
    upload = await _get_upload(db, incident_id, upload_id)
    if upload.evidence_id:
        raise ApiError(status.HTTP_409_CONFLICT, "already_minted", "Already minted as Evidence")
    if not upload.source_artifact_id:
        raise HTTPException(status.HTTP_410_GONE, "Source artifact missing")

    src = (await db.execute(select(Artifact).where(Artifact.id == upload.source_artifact_id))).scalar_one_or_none()
    if not src:
        raise HTTPException(status.HTTP_410_GONE, "Source artifact missing")
    raw = await asyncio.to_thread(_read_quarantine, src)
    sha256, sha1, md5 = await ahashes_of(raw)
    # C3 — the quarantined copy must still be the bytes hashed at upload.
    if sha256 != (src.sha256_hash or "").lower():
        await write_audit(
            db, "evidence_collect_rejected",
            user_id=user.id, username=user.username,
            resource_type="evidence", outcome="failure",
            details={"incident_id": str(incident_id), "method": "webhistory_mint",
                     "upload_id": str(upload_id), "artifact_id": str(src.id),
                     "reason": "artifact_hash_mismatch",
                     "recorded_sha256": src.sha256_hash, "computed_sha256": sha256},
            ip_address=request.client.host if request.client else None,
        )
        await db.commit()
        raise ApiError(status.HTTP_409_CONFLICT, "artifact_hash_mismatch",
                       "The stored history file no longer matches the SHA-256 recorded when it "
                       "was uploaded; it was not minted as evidence.")

    require_free_space(len(raw), "this exhibit")                           # L2
    ev_id = uuid.uuid4()
    rel = f"webhistory/{ev_id}.db.enc"
    stored = await awrite_encrypted(raw, rel)
    short = str(upload_id)[:8]
    ev = Evidence(
        id=ev_id, incident_id=incident_id, kind="digital_file", status="active",
        name=f"Browser history ({upload.browser}): {upload.original_filename}",
        identifier=f"WEBHIST-{short}",
        original_filename=upload.original_filename, storage_path=rel, nonce_hex=stored.nonce_hex,
        file_size_bytes=len(raw), mime_type="application/vnd.sqlite3",
        sha256=sha256, sha1=sha1, md5=md5,
        current_custodian_id=user.id, collected_by_id=user.id, collected_at=utcnow(),
        acquired_at=src.uploaded_at, upload_hash_check="not_checked",
    )
    db.add(ev)
    await db.flush()
    upload.evidence_id = ev_id
    await write_audit(
        db, "evidence_collect",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev_id), outcome="success",
        details={"incident_id": str(incident_id), "method": "webhistory_mint",
                 "upload_id": str(upload_id), "artifact_id": str(src.id),
                 "kind": "digital_file", "identifier": ev.identifier, "name": ev.name,
                 "sha256": ev.sha256, "file_size_bytes": ev.file_size_bytes,
                 "acquired_at": ev.acquired_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                                 if ev.acquired_at else None,
                 "artifact_hash_verified": True},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return (await _upload_out(db, [upload]))[0]


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

    stmt = stmt.order_by(BrowserHistoryVisit.visit_time.desc(), BrowserHistoryVisit.id).offset(offset).limit(limit + 1)
    rows = (await db.execute(stmt)).all()

    has_more = len(rows) > limit
    rows = rows[:limit]
    items = []
    on_timeline = await _timeline_events_of(db, [v.id for v, _ in rows])
    for visit, browser_label in rows:
        out = BrowserHistoryVisitOut.model_validate(visit)
        out.browser = browser_label
        out.timeline_event_id = on_timeline.get(visit.id)
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

    stmt = stmt.order_by(BrowserHistorySearchTerm.visit_time.desc(), BrowserHistorySearchTerm.id).offset(offset).limit(limit + 1)
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

    stmt = stmt.order_by(BrowserHistoryDownload.start_time.desc(), BrowserHistoryDownload.id).offset(offset).limit(limit + 1)
    rows = (await db.execute(stmt)).all()

    has_more = len(rows) > limit
    rows = rows[:limit]
    items = []
    on_timeline = await _timeline_events_of(db, [d.id for d, _ in rows])
    for dl, browser_label in rows:
        out = BrowserHistoryDownloadOut.model_validate(dl)
        out.browser = browser_label
        out.timeline_event_id = on_timeline.get(dl.id)
        items.append(out)

    return BrowserHistoryDownloadList(items=items, next_cursor=_enc(offset + limit) if has_more else None)
