"""Microsoft Defender incident PDF import.

Mounted at prefix="/api/incidents". Flows:
  - /parse            stateless preview (kept for back-compat / a quick look
                       without saving anything).
  - /imports          upload, parse, quarantine the raw PDF as an Artifact,
                       and persist the parsed candidates so the page survives
                       a refresh, plus quarantine like every other
                       file-upload analyzer in this codebase.
  - /from-evidence/{evidence_id}
                      (G4) parse a registered exhibit instead: hash
                       re-verified, recorded in its custody log; nothing is
                       re-uploaded or quarantined.
  - /imports/{id}/promote
                      (G4) commit candidates as IOCs / entities / timeline
                       events. The server copies them from the stored parse
                       (the browser sends only idx + destination), so each
                       fact carries the run's exhibit and, for timeline
                       events, the import and candidate index.

Run record (G4, R03): every import stores the exhibit it is (if any), the SHA-256
of the parsed PDF, the parser name + version, the clock offset applied, and
who / when (uploaded_by / uploaded_at).
"""
import asyncio
import hashlib
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, status
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.config import settings
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from artifacts import store as artifact_store
from evidence.crypto import EvidenceIntegrityError
from evidence.streaming import require_free_space
from forensic.parser import apply_clock_offset
from forensic.routes import (_exhibit_state_error, _lock_exhibit, _read_exhibit, clock_offset_fields,
                             exhibit_info, exhibit_too_large, upload_match)
from incidents.access import get_accessible_incident
from models import (IOC, Artifact, DefenderPdfImport, Entity, EntityEvent, Evidence, TimelineEvent,
                    User, utcnow)
from schemas import (DefenderPdfImportDetail, DefenderPdfImportList,
                     DefenderPdfImportSummary, DefenderPdfParseResponse,
                     DefenderPdfPromote, DefenderPdfPromoteResult)

from .parser import PARSER_NAME, PARSER_VERSION, parse_defender_incident_pdf
# After .parser: it keeps pypdfium2 (the native renderer) out of this process before pdfplumber loads.
from pdfminer.psparser import PSException  # noqa: E402
from pdfplumber.utils.exceptions import MalformedPDFException, PdfminerException  # noqa: E402

router = APIRouter()

_MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MB — generous for a report PDF
_PDF_MAGIC = b"%PDF"
_DEFAULT_SOURCE = "Microsoft Defender PDF import"
_TIME_BASES_STORED = {"explicit", "assumed_tz", "inferred_year"}
_PROMOTE_CHUNK = 500            # rows per INSERT (≤ 29 binds/row; asyncpg caps a statement at 32767)


# ─── Upload helpers ─────────────────────────────────────────────────────────

def _hashes(data: bytes) -> tuple[str, str, str]:
    """(md5, sha256, sha512) of the upload. CPU-bound over up to 25 MB: call via asyncio.to_thread."""
    return (hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest(),
            hashlib.sha512(data).hexdigest())


def _validate_pdf_upload(content: bytes) -> None:
    if not content:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Uploaded file is empty")
    if len(content) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                             f"File exceeds {_MAX_UPLOAD_BYTES // (1024*1024)} MB limit")
    if content[:4] != _PDF_MAGIC:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Not a PDF file")


async def _parse(content: bytes) -> dict:
    """Parse off the event loop. 422 when it isn't a Defender incident export (ValueError), and
    422 code parse_failed when the PDF itself can't be read (R64: a corrupt or truncated `%PDF`
    was a 500). pdfplumber wraps pdfminer's errors in PdfminerException; PSException is pdfminer's
    own base, for anything raised outside those wrappers."""
    try:
        return await asyncio.to_thread(parse_defender_incident_pdf, content)
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))
    except (PdfminerException, MalformedPDFException, PSException):
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "parse_failed",
                       "The PDF could not be read (corrupt, truncated or not a valid PDF): nothing was stored.")


_PARSE_422 = {422: {"model": ApiErrorBody, "description": "parse_failed (unreadable PDF), or not a PDF / "
                                                           "not a Defender incident export"}}


# R78 (G-fix): Defender times come from Microsoft's cloud, not from the device clock, so the exhibit's clock
# offset is not applied (parser 1.1.0 on). Imports parsed before kept the offset they were parsed with.
_OFFSET_NOT_APPLIED = "not_applicable (Defender incident times are Microsoft cloud times, not the device clock)"


def _offset_fields(row: DefenderPdfImport, info: dict) -> dict:
    fields = clock_offset_fields(row.evidence_id, row.clock_offset_seconds, info)
    if row.evidence_id is not None and row.parser_version not in (None, "1.0.0"):
        fields["clock_offset_status"] = "not_applicable"
    return fields


def _to_import_detail(row: DefenderPdfImport, info: dict) -> DefenderPdfImportDetail:
    # Explicit, not DefenderPdfImportDetail.model_validate(row) -- the ORM
    # column is `incident_meta` (avoids shadowing the existing `incident_id`
    # FK) but the schema field the frontend already consumes is `incident`.
    return DefenderPdfImportDetail(
        id=row.id, filename=row.filename, file_size=row.file_size,
        sha256_hash=row.sha256_hash, candidate_count=row.candidate_count,
        low_confidence_count=row.low_confidence_count,
        uploaded_by=row.uploaded_by, uploaded_at=row.uploaded_at,
        evidence_id=row.evidence_id,
        evidence_identifier=info[row.evidence_id][0] if row.evidence_id in info else None,
        source_artifact_id=row.source_artifact_id,
        parser_name=row.parser_name, parser_version=row.parser_version,
        **_offset_fields(row, info),
        incident=row.incident_meta,
        candidates=[{**c, "idx": i} for i, c in enumerate(row.candidates or [])],
    )


def _ensure_open(inc) -> None:
    """409 incident_closed: a closed incident's record is frozen (re-open it first)."""
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")


_CLOSED_409 = {409: {"model": ApiErrorBody, "description": "incident_closed"}}


async def _get_import(db, incident_id, import_id, *, for_update: bool = False) -> DefenderPdfImport:
    """for_update (L28): promote and delete lock the import row, so they serialise instead of racing
    into a foreign-key 500."""
    stmt = select(DefenderPdfImport).where(
        DefenderPdfImport.id == import_id,
        DefenderPdfImport.incident_id == incident_id,
    )
    if for_update:
        stmt = stmt.with_for_update(of=DefenderPdfImport).execution_options(populate_existing=True)
    row = (await db.execute(stmt)).scalar_one_or_none()
    if not row:
        raise ApiError(status.HTTP_404_NOT_FOUND, "defender_import_not_found", "Defender PDF import not found")
    return row


def _new_import(incident_id, *, filename, size, sha256, artifact_id, exhibit, clock_offset, parsed, user
                ) -> DefenderPdfImport:
    candidates = parsed["candidates"]
    return DefenderPdfImport(
        id=uuid.uuid4(), incident_id=incident_id,
        filename=filename[:512], file_size=size, sha256_hash=sha256,
        source_artifact_id=artifact_id,
        evidence_id=exhibit.id if exhibit is not None else None,
        parser_name=PARSER_NAME, parser_version=PARSER_VERSION,
        clock_offset_seconds=clock_offset,
        candidate_count=len(candidates),
        low_confidence_count=sum(1 for c in candidates if c.get("low_confidence")),
        incident_meta=parsed["incident"], candidates=candidates,
        uploaded_by_id=user.id, uploaded_by=user.username,
    )


def _examine_details(incident_id, row: DefenderPdfImport, clock_offset, **extra) -> dict:
    """The custody-log record (evidence_examine) of a Defender parse of an exhibit."""
    return {
        "incident_id": str(incident_id),
        "tool":        PARSER_NAME,
        "version":     PARSER_VERSION,
        "params":      {"clock_offset_seconds": clock_offset, "clock_offset": _OFFSET_NOT_APPLIED},
        **extra,
        "result":      "defender_pdf_import",
        "defender_import_id": str(row.id),
        "candidate_count": row.candidate_count,
        "untimestamped": sum(1 for c in row.candidates if c.get("time_basis") == "missing"),
    }


def _create_audit_details(incident_id, row: DefenderPdfImport, **extra) -> dict:
    return {
        "incident_id": str(incident_id), "filename": row.filename,
        "sha256": row.sha256_hash, "candidate_count": row.candidate_count,
        "low_confidence_count": row.low_confidence_count,
        "evidence_id": str(row.evidence_id) if row.evidence_id else None,
        "parser": row.parser_name, "parser_version": row.parser_version,
        "clock_offset_seconds": row.clock_offset_seconds, "clock_offset_status": "not_applicable",
        **extra,
    }


# ─── Stateless preview (back-compat) ────────────────────────────────────────

@router.post(
    "/{incident_id}/forensic/defender-pdf/parse",
    response_model=DefenderPdfParseResponse,
    status_code=status.HTTP_200_OK,
    summary="Parse a Microsoft Defender incident PDF into candidate IOCs/Entities/Timeline events (stateless preview)",
    responses=_PARSE_422,
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
    return DefenderPdfParseResponse(**(await _parse(content)))


# ─── Persisted imports ──────────────────────────────────────────────────────

@router.post(
    "/{incident_id}/forensic/defender-pdf/imports",
    response_model=DefenderPdfImportDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Upload, parse, quarantine, and persist a Defender incident PDF",
    responses={**_CLOSED_409, **_PARSE_422,
               507: {"model": ApiErrorBody, "description": "insufficient_storage (the quarantine volume, with its 1 GiB reserve, or the upload scratch space is full; nothing stored)"}},
)
async def create_defender_pdf_import(
    incident_id: uuid.UUID,
    request: Request,
    file: UploadFile = File(...),
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> DefenderPdfImportDetail:
    """Upload a Defender incident PDF: parse it, quarantine the raw PDF as an artifact and
    persist the candidates. Requires the analyst role; 409 incident_closed on a closed incident
    (checked before anything is stored). An unreadable PDF is 422 code parse_failed and stores
    nothing. Hashing and parsing run off the event loop. When the PDF's SHA-256 equals exactly one
    `active` digital exhibit of this incident with a stored file, the import is linked to it
    (`evidence_id`) and the parse is written to that exhibit's custody log (`evidence_examine`,
    method `upload_sha256_match`) — unless the exhibit is in external custody or awaiting a
    transfer: then nothing is linked (`evidence_link_skipped` in the audit row). R78: the exhibit's
    clock offset is not applied — Defender's times are Microsoft cloud times, not the device's
    (`clock_offset_status` not_applicable). The run record — input SHA-256, `parser_name` /
    `parser_version`, the exhibit, who and when — is on the import. Audited."""
    _ensure_open(await get_accessible_incident(db, incident_id, user))
    content = await file.read()
    _validate_pdf_upload(content)
    filename = file.filename or "incident.pdf"
    md5, sha256, sha512 = await asyncio.to_thread(_hashes, content)
    exhibit, link_skipped = await upload_match(db, incident_id, sha256)
    clock_offset = None             # R78: Defender times are Microsoft's cloud times, not the device clock

    parsed = await _parse(content)
    apply_clock_offset(parsed["candidates"], clock_offset)
    art_id = None
    if exhibit is None:
        # L27 (H1): a PDF that IS an exhibit (same SHA-256) is already stored, encrypted, with its custody
        # log: no second (quarantine) copy. Otherwise the raw PDF is quarantined, encrypted at rest.
        require_free_space(len(content), "this report", root=settings.quarantine_path)   # L2: 507, nothing stored
        art_id = uuid.uuid4()
        stored = artifact_store.stored_name(art_id, filename)
        sf, _tap = await artifact_store.awrite(content, incident_id, stored)
        db.add(Artifact(
            id=art_id, incident_id=incident_id,
            original_filename=filename, stored_filename=stored,
            file_size=sf.size, mime_type="application/pdf", nonce_hex=sf.nonce_hex,
            md5_hash=md5, sha256_hash=sha256, sha512_hash=sha512,
            description="Microsoft Defender incident PDF",
            uploaded_by_id=user.id, uploaded_by=user.username,
        ))

    row = _new_import(incident_id, filename=filename, size=len(content), sha256=sha256, artifact_id=art_id,
                      exhibit=exhibit, clock_offset=clock_offset, parsed=parsed, user=user)
    db.add(row)
    ip = request.client.host if request.client else None
    if exhibit is not None:
        # The uploaded bytes ARE this exhibit (same SHA-256): record the parse in its custody log.
        await write_audit(
            db, "evidence_examine",
            user_id=user.id, username=user.username,
            resource_type="evidence", resource_id=str(exhibit.id), outcome="success",
            details=_examine_details(incident_id, row, clock_offset, method="upload_sha256_match",
                                     examined_on="uploaded copy whose SHA-256 equals the exhibit's",
                                     sha256_verified=sha256),
            ip_address=ip,
        )
    await write_audit(
        db, "defender_pdf_import_create",
        user_id=user.id, username=user.username,
        resource_type="defender_pdf_import", resource_id=str(row.id),
        details=_create_audit_details(incident_id, row,
                                      evidence_link="sha256_match" if exhibit is not None else None,
                                      evidence_link_skipped=link_skipped),
        ip_address=ip,
    )
    await db.commit()
    await db.refresh(row)

    return _to_import_detail(row, await exhibit_info(db, [row.evidence_id]))


@router.post(
    "/{incident_id}/forensic/defender-pdf/from-evidence/{evidence_id}",
    response_model=DefenderPdfImportDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Parse a registered exhibit (hash re-verified) as a Defender incident PDF",
    responses={
        404: {"model": ApiErrorBody, "description": "evidence_not_found"},
        409: {"model": ApiErrorBody, "description": "incident_closed, evidence_not_active, "
              "evidence_not_in_internal_custody, transfer_pending, evidence_storage_missing or "
              "evidence_hash_mismatch (the item is frozen: verify_failed)"},
        413: {"model": ApiErrorBody, "description": "exhibit_too_large_for_analyser (over the 25 MB Defender "
              "PDF limit; checked before anything is decrypted)"},
        422: {"model": ApiErrorBody, "description": "evidence_not_digital, not_a_pdf, not_a_defender_pdf or "
              "parse_failed"},
        503: {"model": ApiErrorBody, "description": "evidence_read_error (stored copy unreadable; not frozen)"},
    },
)
async def import_defender_pdf_from_evidence(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> DefenderPdfImportDetail:
    """Parse an exhibit already registered in Evidence as a Defender incident PDF, instead of
    re-uploading it (same rules as the Logs & triage from-evidence).

    The exhibit must be a digital file of this incident (up to 25 MB) that is `active`, held by an
    internal custodian and not awaiting a custody transfer (409 otherwise; checked again under a
    row lock after the parse, so a transfer or dispose that happened meanwhile wins and nothing is
    stored). Its encrypted master copy is decrypted into memory and hashed off the event loop; the
    master is never modified and nothing is quarantined. The SHA-256 must equal the one recorded at
    collection: a mismatch (or ciphertext that fails AES-GCM authentication) freezes an item that is
    still active (`verify_failed`, audited `evidence_verify_failed`) and returns 409
    `evidence_hash_mismatch`. An unreadable stored copy is 503 `evidence_read_error` (not frozen).
    R78: the exhibit's clock offset (`system_time_offset_seconds`) is not applied — Defender's times
    are Microsoft cloud times, not the device's (`clock_offset_status` not_applicable). The run is
    recorded in the exhibit's custody log as `evidence_examine` (tool = the parser name + version).
    Requires the analyst role. Returns the stored import (201) with its run record.
    """
    _ensure_open(await get_accessible_incident(db, incident_id, user))
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
        raise exhibit_too_large("25 MB Defender PDF")

    ip = request.client.host if request.client else None
    recorded = ev.sha256
    clock_offset = None             # R78: Defender times are Microsoft's cloud times, not the device clock
    base = {"incident_id": str(incident_id), "tool": PARSER_NAME, "version": PARSER_VERSION,
            "params": {"clock_offset_seconds": clock_offset, "clock_offset": _OFFSET_NOT_APPLIED}}

    async def _examine_failed(result: str, error: str) -> None:
        await write_audit(
            db, "evidence_examine",
            user_id=user.id, username=user.username,
            resource_type="evidence", resource_id=str(evidence_id), outcome="failure",
            details={**base, "result": result, "error": error[:500]},
            ip_address=ip,
        )
        await db.commit()

    try:
        content, computed = await asyncio.to_thread(_read_exhibit, ev.storage_path, ev.nonce_hex, ev.file_size_bytes)
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
            details={"incident_id": str(incident_id), "phase": "defender_pdf_import",
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

    if content[:4] != _PDF_MAGIC:
        await _examine_failed("not_a_pdf", "the exhibit does not start with %PDF")
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "not_a_pdf",
                       "The exhibit is not a PDF file; nothing was stored")
    try:
        parsed = await _parse(content)
    except ApiError as exc:
        await _examine_failed("parse_failed", exc.detail)
        raise
    except HTTPException as exc:            # ValueError: a PDF, but not a Defender incident export
        await _examine_failed("not_a_defender_pdf", str(exc.detail))
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "not_a_defender_pdf", str(exc.detail)) from exc
    size = len(content)
    del content
    apply_clock_offset(parsed["candidates"], clock_offset)

    # The decrypt + parse took a while: re-check the exhibit under a row lock before writing.
    ev = await _lock_exhibit(db, incident_id, evidence_id)
    if (err := _exhibit_state_error(ev)) is not None:
        await _examine_failed("discarded_state_changed", err.detail)
        raise err

    row = _new_import(incident_id, filename=Path(ev.original_filename or "exhibit.pdf").name, size=size,
                      sha256=computed, artifact_id=None, exhibit=ev, clock_offset=clock_offset,
                      parsed=parsed, user=user)
    db.add(row)
    await db.flush()
    await write_audit(
        db, "evidence_examine",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id), outcome="success",
        details=_examine_details(incident_id, row, clock_offset, sha256_verified=computed,
                                 examined_on="hash-verified in-memory copy of the master"),
        ip_address=ip,
    )
    await write_audit(
        db, "defender_pdf_import_create",
        user_id=user.id, username=user.username,
        resource_type="defender_pdf_import", resource_id=str(row.id),
        details=_create_audit_details(incident_id, row, evidence_link="from_evidence"),
        ip_address=ip,
    )
    await db.commit()
    await db.refresh(row)
    return _to_import_detail(row, await exhibit_info(db, [ev.id]))


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
    """List the incident's Defender PDF imports, newest first, each with its run record (input
    SHA-256, exhibit, parser name + version, clock offset applied and its status)."""
    await get_accessible_incident(db, incident_id, user)
    rows = (await db.execute(
        select(DefenderPdfImport)
        .where(DefenderPdfImport.incident_id == incident_id)
        .order_by(DefenderPdfImport.uploaded_at.desc())
    )).scalars().all()
    info = await exhibit_info(db, [r.evidence_id for r in rows])
    items = []
    for r in rows:
        s = DefenderPdfImportSummary.model_validate(r)
        s.evidence_identifier = info[r.evidence_id][0] if r.evidence_id in info else None
        for k, v in _offset_fields(r, info).items():
            setattr(s, k, v)
        items.append(s)
    return DefenderPdfImportList(items=items)


@router.get(
    "/{incident_id}/forensic/defender-pdf/imports/{import_id}",
    response_model=DefenderPdfImportDetail,
    summary="Re-fetch a persisted Defender PDF import's candidates",
    responses={404: {"model": ApiErrorBody, "description": "defender_import_not_found"}},
)
async def get_defender_pdf_import(
    incident_id: uuid.UUID,
    import_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> DefenderPdfImportDetail:
    await get_accessible_incident(db, incident_id, user)
    row = await _get_import(db, incident_id, import_id)
    return _to_import_detail(row, await exhibit_info(db, [row.evidence_id]))


def _promote_rows(imp: DefenderPdfImport, items, incident_id: uuid.UUID, ir_phase, user_id, already: set
                  ) -> tuple[list[dict], list[dict], list[dict], list[int], list[int]]:
    """Stored candidates -> rows for iocs / entities / timeline_events (the server copies the facts;
    the caller only picked idx + destination). Returns (iocs, entities, events, untimed, already)."""
    now = utcnow()
    cands = imp.candidates or []
    iocs, ents, evs, untimed, again = [], [], [], [], []
    for it in items:
        c = cands[it.idx]
        value = (c.get("value") or c.get("description") or "").strip()
        if it.destination == "ioc":
            iocs.append({
                "id": uuid.uuid4(), "incident_id": incident_id,
                "type": c.get("ioc_type") or "other", "value": value[:2048],
                "notes": c.get("raw_log") or None,
                "source": (c.get("source") or _DEFAULT_SOURCE)[:256],
                "malicious": None, "confidence": 50, "tags": [],
                "entity_id": None, "evidence_id": imp.evidence_id,
                "added_by_id": user_id, "added_at": now, "updated_at": now, "_idx": it.idx,
            })
        elif it.destination == "entity":
            ents.append({
                "id": uuid.uuid4(), "incident_id": incident_id,
                "type": c.get("entity_type_hint") or "other", "value": value[:2048],
                "name": (c.get("value") or None) and c["value"][:256],
                "description": c.get("description"),
                "criticality": c.get("criticality") or "medium",
                "attributes": {}, "compromised": False,
                "added_by_id": user_id, "added_at": now, "updated_at": now, "_idx": it.idx,
            })
        else:
            if it.idx in already:
                again.append(it.idx)
                continue
            if not c.get("event_time") or c.get("time_basis") == "missing":
                untimed.append(it.idx)
                continue
            basis = c.get("time_basis")
            evs.append({
                "id": uuid.uuid4(), "incident_id": incident_id,
                "event_time": datetime.fromisoformat(c["event_time"]),
                "hostname": (c.get("hostname") or None) and c["hostname"][:256],
                "entity_id": None,
                "source": (c.get("source") or _DEFAULT_SOURCE)[:128],
                "event_type": (c.get("event_type") or None) and c["event_type"][:128],
                "description": (c.get("description") or "").strip(),
                "raw_log": (c.get("raw_log") or None) and c["raw_log"][:4000],
                "ir_phase": ir_phase,
                "mitre_tactic_id": None, "mitre_tactic_name": None,
                "mitre_technique_id": None, "mitre_technique_name": None,
                "origin": "forensic_import", "is_system": False, "system_source": None,
                "external_safe": True, "created_by_id": user_id,
                "evidence_id": imp.evidence_id, "forensic_import_id": None,
                "defender_import_id": imp.id, "import_event_index": it.idx,
                "time_basis": basis if basis in _TIME_BASES_STORED else None,
                "recorded_event_time": datetime.fromisoformat(c["recorded_time"]) if c.get("recorded_time") else None,
                "clock_offset_seconds": imp.clock_offset_seconds if c.get("recorded_time") else None,
                "created_at": now, "updated_at": now,
            })
    return iocs, ents, evs, untimed, again


@router.post(
    "/{incident_id}/forensic/defender-pdf/imports/{import_id}/promote",
    response_model=DefenderPdfPromoteResult,
    summary="Commit candidates of a stored Defender import as IOCs, entities or timeline events",
    responses={
        404: {"model": ApiErrorBody, "description": "defender_import_not_found"},
        409: {"model": ApiErrorBody, "description": "incident_closed or reparse_required (an import made "
              "before parser versioning)"},
        422: {"model": ApiErrorBody, "description": "index_out_of_range (or a validation error)"},
    },
)
async def promote_defender_pdf_import(
    incident_id: uuid.UUID,
    import_id: uuid.UUID,
    req: DefenderPdfPromote,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> DefenderPdfPromoteResult:
    """Commit candidates of a stored Defender import, picked by `idx`, each to a `destination`
    (ioc | entity | timeline_event; the candidate's suggestion or the analyst's override).

    The server copies the facts from the stored parse; the caller sends only idx + destination
    (and an optional `ir_phase` for the timeline events). IOCs carry the import's exhibit
    (`evidence_id`); timeline events carry the exhibit, the import (`defender_import_id`), the
    candidate index, the `time_basis` and — when the exhibit's clock offset corrected the time —
    the recorded time and the offset; their facts are then immutable (timeline edits of them return
    409 imported_fact_immutable). A candidate without a time never becomes a timeline event
    (`skipped_untimestamped`); one already promoted to the timeline from this import is skipped
    (`already_promoted`), and an IOC / entity of the same type + value already on the incident is
    left as it is (`already_exists`). A repeated idx counts once (the first destination wins).
    409 `reparse_required` for an import made before parser versioning (its candidates carry no
    time basis): import the PDF again. 409 on a closed incident. Requires the analyst role;
    audit-logged as `defender_pdf_import_promote`.
    """
    _ensure_open(await get_accessible_incident(db, incident_id, user))
    imp = await _get_import(db, incident_id, import_id, for_update=True)
    if imp.parser_version is None:
        raise ApiError(status.HTTP_409_CONFLICT, "reparse_required",
                       "This import was made before parser versioning, so its candidates carry no time "
                       "basis. Import the PDF or exhibit again and commit from the new import.")
    n = len(imp.candidates or [])
    bad = sorted({it.idx for it in req.items if it.idx >= n})
    if bad:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "index_out_of_range",
                       f"{len(bad)} index(es) are not candidates of this import (0..{n - 1})",
                       extra={"indices": bad[:50]})
    seen: set[int] = set()
    items = []
    for it in req.items:
        if it.idx not in seen:
            seen.add(it.idx)
            items.append(it)
    tl_idx = [it.idx for it in items if it.destination == "timeline_event"]
    already = set((await db.execute(
        select(TimelineEvent.import_event_index).where(
            TimelineEvent.defender_import_id == imp.id, TimelineEvent.import_event_index.in_(tl_idx))
    )).scalars().all()) if tl_idx else set()
    iocs, ents, evs, untimed, again = _promote_rows(imp, items, incident_id, req.ir_phase, user.id, already)

    created_idx: list[int] = []
    exists: list[int] = []

    async def _insert_keyed(model, rows: list[dict]) -> int:
        """IOCs / entities: ON CONFLICT (incident, type, value) DO NOTHING. An idx whose row wasn't
        inserted (already on the incident, or a duplicate within this request) is `already_exists`."""
        if not rows:
            return 0
        made: set[tuple[str, str]] = set()
        for start in range(0, len(rows), _PROMOTE_CHUNK):
            chunk = [{k: v for k, v in r.items() if k != "_idx"} for r in rows[start:start + _PROMOTE_CHUNK]]
            res = await db.execute(
                pg_insert(model).values(chunk)
                .on_conflict_do_nothing(index_elements=[model.incident_id, model.type, model.value])
                .returning(model.id, model.type, model.value))
            made |= {(t, v) for _, t, v in res.all()}
        n_made = 0
        for r in rows:
            if (r["type"], r["value"]) in made:
                made.discard((r["type"], r["value"]))
                created_idx.append(r["_idx"])
                n_made += 1
                if model is Entity:
                    db.add(EntityEvent(id=uuid.uuid4(), entity_id=r["id"], incident_id=incident_id,
                                       event_type="system", title="Entity added (Defender import)",
                                       actor_id=user.id))
            else:
                exists.append(r["_idx"])
        return n_made

    n_iocs = await _insert_keyed(IOC, iocs)
    n_ents = await _insert_keyed(Entity, ents)
    made_ev: list[int] = []
    for start in range(0, len(evs), _PROMOTE_CHUNK):
        res = await db.execute(
            pg_insert(TimelineEvent).values(evs[start:start + _PROMOTE_CHUNK])
            .on_conflict_do_nothing(index_elements=[TimelineEvent.defender_import_id, TimelineEvent.import_event_index],
                                    index_where=TimelineEvent.defender_import_id.isnot(None))
            .returning(TimelineEvent.import_event_index))
        made_ev.extend(res.scalars().all())
    # A concurrent promote of the same idx loses the ON CONFLICT race: count it as already there.
    again = sorted(set(again) | ({e["import_event_index"] for e in evs} - set(made_ev)))
    created_idx = sorted(created_idx + made_ev)

    await write_audit(
        db, "defender_pdf_import_promote",
        user_id=user.id, username=user.username,
        resource_type="defender_pdf_import", resource_id=str(imp.id),
        details={
            "incident_id": str(incident_id),
            "evidence_id": str(imp.evidence_id) if imp.evidence_id else None,
            "parser_version": imp.parser_version,
            "clock_offset_seconds": imp.clock_offset_seconds,
            "requested": len(items),
            "created_iocs": n_iocs, "created_entities": n_ents, "created_events": len(made_ev),
            "skipped_untimestamped": len(untimed), "already_promoted": len(again),
            "already_exists": len(exists), "ir_phase": req.ir_phase,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return DefenderPdfPromoteResult(
        created=n_iocs + n_ents + len(made_ev), created_iocs=n_iocs, created_entities=n_ents,
        created_events=len(made_ev), created_indices=created_idx,
        skipped_untimestamped=sorted(untimed), already_promoted=again, already_exists=sorted(exists),
    )


@router.delete(
    "/{incident_id}/forensic/defender-pdf/imports/{import_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Dispose a persisted Defender PDF import (hard delete, audited)",
    responses={404: {"model": ApiErrorBody, "description": "defender_import_not_found"},
               409: {"model": ApiErrorBody, "description": "incident_closed or import_has_promoted_events"}},
)
async def delete_defender_pdf_import(
    incident_id: uuid.UUID,
    import_id: uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Delete a persisted Defender PDF import. Requires the analyst role; 409 incident_closed
    on a closed incident; 409 `import_has_promoted_events` while timeline events promoted from it
    exist (the import is their provenance record); 404 if not found. Audited."""
    _ensure_open(await get_accessible_incident(db, incident_id, user))
    row = await _get_import(db, incident_id, import_id, for_update=True)
    promoted = (await db.execute(
        select(func.count()).select_from(TimelineEvent).where(TimelineEvent.defender_import_id == row.id)
    )).scalar_one()
    if promoted:
        raise ApiError(status.HTTP_409_CONFLICT, "import_has_promoted_events",
                       f"{promoted} timeline event(s) were promoted from this import; it is their "
                       "provenance record and can't be disposed while they exist")

    await write_audit(
        db, "defender_pdf_import_delete",
        user_id=user.id, username=user.username,
        resource_type="defender_pdf_import", resource_id=str(row.id),
        details={"incident_id": str(incident_id), "filename": row.filename,
                 "sha256": row.sha256_hash,
                 "evidence_id": str(row.evidence_id) if row.evidence_id else None,
                 "parser_version": row.parser_version},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(row)
    await db.commit()
