"""Per-incident evidence endpoints (chain of custody).

Mounted at `/api/incidents` alongside incidents/iocs/entities routers.

Vocabulary follows 800-61 R3 / ISO 27037 ("evidence", "chain of custody").
Custody events land in the existing hash-chained audit log; this router's
Evidence row holds *current state* only (custodian, status, hashes). The
authoritative history is the audit chain.

Phase 1 endpoints (this slice):
- POST   /{id}/evidence/digital        — multipart upload, AES-256-GCM at rest
- POST   /{id}/evidence/physical       — physical item registration
- GET    /{id}/evidence                — list, cursor pagination
- GET    /{id}/evidence/{eid}          — detail
- PATCH  /{id}/evidence/{eid}          — descriptive fields only
- POST   /{id}/evidence/{eid}/transfer — change custodian
- POST   /{id}/evidence/{eid}/examine  — record analysis action
- POST   /{id}/evidence/{eid}/verify   — recompute hash, compare to recorded
- POST   /{id}/evidence/{eid}/dispose  — destroy / return / archive
- GET    /{id}/evidence/{eid}/custody  — per-item custody timeline (filtered audit chain)

Phase 2 (next slice): /exports, /download/{token}
Phase 3 (polish): PDF CoC generator, chain verifier endpoint.
"""
import base64
import io
import json
import uuid
from typing import Optional

from fastapi import (APIRouter, Depends, File, Form, HTTPException, Query,
                     Request, Response, UploadFile, status)
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_admin, require_analyst
from core.config import settings
from core.database import get_db
from incidents.access import get_accessible_incident
from models import AuditLog, CustodyExport, Entity, Evidence, EvidenceCopy, Incident, User, utcnow
from audit.service import verify_row_hash
from schemas import (ChainVerifyResult, CustodyEventOut, DisposeRequest,
                     EvidenceCopyList, EvidenceCopyOut, EvidenceList,
                     EvidenceOut, EvidenceSealRequest,
                     EvidenceUpdate, ExamineRequest, ExportCreate,
                     ExportCreateResponse, ExportList, ExportOut,
                     PhysicalEvidenceCreate, ProvenanceScore, Tlp,
                     TransferRequest, VerifyResult, WorkingCopyCreate)
from evidence.provenance import score_evidence

from evidence.crypto import (adelete_encrypted, aread_decrypted,
                             awrite_encrypted)
from evidence.exports import build_bundle, effective_status
from evidence.hashing import amulti_hash, sha256_of
from evidence.timestamping import timestamp_sha256

router = APIRouter()


# Cursor helpers — mirror incidents/iocs/entities patterns.
def _encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"o": offset}).encode()).decode().rstrip("=")


def _decode_cursor(cursor: Optional[str]) -> int:
    if not cursor:
        return 0
    try:
        pad = "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(cursor + pad).decode())
        return max(0, int(data.get("o", 0)))
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid cursor")


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


async def _get_evidence(db: AsyncSession, incident_id: uuid.UUID, evidence_id: uuid.UUID) -> Evidence:
    ev = (await db.execute(
        select(Evidence).where(Evidence.id == evidence_id, Evidence.incident_id == incident_id)
    )).scalar_one_or_none()
    if not ev:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Evidence not found")
    return ev


async def _resolve_entity(
    db: AsyncSession,
    incident_id: uuid.UUID,
    entity_id_str: Optional[str],
) -> Optional[uuid.UUID]:
    if not entity_id_str:
        return None
    try:
        eid = uuid.UUID(entity_id_str)
    except ValueError:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid entity_id format")
    exists = (await db.execute(
        select(Entity.id).where(Entity.id == eid, Entity.incident_id == incident_id)
    )).scalar_one_or_none()
    if not exists:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Entity not found in this incident")
    return eid


def _storage_path_for(incident_id: uuid.UUID, evidence_id: uuid.UUID, filename: str) -> str:
    # Sanitise filename — only keep basename, no path traversal.
    safe = filename.replace("/", "_").replace("\\", "_")
    return f"{incident_id}/{evidence_id}__{safe}.enc"


def _to_out(ev: Evidence) -> EvidenceOut:
    return EvidenceOut.model_validate(ev)


def _json_object(raw: Optional[str], field: str) -> Optional[dict]:
    """Parse an optional JSON-object form field (multipart can't carry nested
    objects natively). Returns None when empty; 422s on malformed input."""
    if not raw:
        return None
    try:
        val = json.loads(raw)
    except (ValueError, TypeError):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"{field} must be valid JSON")
    if not isinstance(val, dict):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"{field} must be a JSON object")
    return val


def _json_list(raw: Optional[str], field: str) -> Optional[list]:
    """Parse an optional JSON-array form field. Multipart list binding varies by
    framework version, so we carry lists (e.g. device_types) as a JSON string and
    parse here. Returns None when empty; 422s on malformed input."""
    if not raw:
        return None
    try:
        val = json.loads(raw)
    except (ValueError, TypeError):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"{field} must be valid JSON")
    if not isinstance(val, list):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"{field} must be a JSON array")
    return val or None


async def _verified_copy_ids(db: AsyncSession, evidence_ids: list) -> set:
    """Evidence ids that have ≥1 non-discarded, master-verified working copy
    (ISO/IEC 27037 §7.1.3.1.1). Grouped query — avoids an async lazy-load of a
    copies relationship on freshly-created Evidence objects (Slice D)."""
    if not evidence_ids:
        return set()
    rows = (await db.execute(
        select(EvidenceCopy.evidence_id).where(
            EvidenceCopy.evidence_id.in_(evidence_ids),
            EvidenceCopy.verified_against_master.is_(True),
            EvidenceCopy.discarded_at.is_(None),
        )
    )).scalars().all()
    return set(rows)


async def _examination_flags(db: AsyncSession, evidence_ids: list) -> dict:
    """Per-evidence ISO/IEC 27042 documentation flags from the examine audit rows
    (GS-3): {str(evidence_id): {examined, findings, scope}}. Grouped query — keeps the
    async scorer off a relationship."""
    if not evidence_ids:
        return {}
    rows = (await db.execute(
        select(AuditLog.resource_id, AuditLog.details).where(
            AuditLog.resource_type == "evidence",
            AuditLog.action == "evidence_examine",
            AuditLog.resource_id.in_([str(i) for i in evidence_ids]),
        )
    )).all()
    flags: dict = {}
    for rid, details in rows:
        d = details or {}
        f = flags.setdefault(rid, {"examined": False, "findings": False, "scope": False})
        f["examined"] = True
        if (d.get("findings") or "").strip():          f["findings"] = True
        if (d.get("scope_limitations") or "").strip(): f["scope"] = True
    return flags


def _apply_exam_flags(ev: Evidence, flags: dict) -> None:
    f = flags.get(str(ev.id))
    if f:
        ev.has_examination          = f["examined"]
        ev.has_examination_findings = f["findings"]
        ev.has_examination_scope    = f["scope"]


# ─── List ────────────────────────────────────────────────────────────────────

@router.get(
    "/{incident_id}/evidence",
    response_model=EvidenceList,
    summary="List evidence for an incident",
)
async def list_evidence(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
    kind:   Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    limit:  int           = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
) -> EvidenceList:
    """List evidence items registered against an incident, newest collection
    first. Optional `kind` (digital_file | physical_item) and `status` filters
    narrow the result; pagination is cursor-based via `limit`/`cursor`. Requires
    access to the incident. Each item carries derived flags (verified working
    copy present, examination documentation completeness)."""
    await _get_incident(db, incident_id, user)
    offset = _decode_cursor(cursor)

    stmt = (
        select(Evidence)
        .where(Evidence.incident_id == incident_id)
        .order_by(Evidence.collected_at.desc(), Evidence.id)
    )
    if kind:          stmt = stmt.where(Evidence.kind   == kind)
    if status_filter: stmt = stmt.where(Evidence.status == status_filter)

    stmt = stmt.offset(offset).limit(limit + 1)
    rows = (await db.execute(stmt)).scalars().all()

    has_more    = len(rows) > limit
    page        = rows[:limit]
    ids         = [r.id for r in page]
    verified    = await _verified_copy_ids(db, ids)
    exam_flags  = await _examination_flags(db, ids)
    for r in page:
        r.has_verified_working_copy = r.id in verified
        _apply_exam_flags(r, exam_flags)
    items       = [_to_out(r) for r in page]
    next_cursor = _encode_cursor(offset + limit) if has_more else None
    return EvidenceList(items=items, next_cursor=next_cursor)


# ─── Global custody log + chain verify (literal paths — must register BEFORE
#     the detail route so they don't bind {evidence_id}="custody-log") ──────

def _audit_to_custody_event(row: AuditLog) -> CustodyEventOut:
    return CustodyEventOut(
        id=row.id,
        event_type=row.action,
        user_id=row.user_id,
        username=row.username,
        resource_type=row.resource_type,
        resource_id=row.resource_id,
        outcome=row.outcome,
        details=row.details or {},
        ip_address=row.ip_address,
        created_at=row.timestamp,
        hash=row.row_hash,
        prev_hash=row.prev_hash,
    )


async def _incident_evidence_events(db: AsyncSession, incident_id: uuid.UUID) -> list[AuditLog]:
    """All evidence_* audit rows for this incident, oldest first."""
    q = await db.execute(
        select(AuditLog)
        .where(
            AuditLog.action.like("evidence_%"),
            AuditLog.details["incident_id"].as_string() == str(incident_id),
        )
        .order_by(AuditLog.timestamp.asc(), AuditLog.id.asc())
    )
    return q.scalars().all()


@router.get(
    "/{incident_id}/evidence/custody-log",
    response_model=list[CustodyEventOut],
    summary="Get the incident-wide custody log",
)
async def incident_custody_log(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> list[CustodyEventOut]:
    """Global custody timeline — every evidence_* event for this incident,
    oldest first. Drawn from the hash-chained audit log (the authoritative
    custody history), so each event carries its `hash`/`prev_hash`. Requires
    access to the incident."""
    await _get_incident(db, incident_id, user)
    rows = await _incident_evidence_events(db, incident_id)
    return [_audit_to_custody_event(r) for r in rows]


@router.post(
    "/{incident_id}/evidence/custody-log/verify",
    response_model=ChainVerifyResult,
    summary="Verify the incident custody chain",
)
async def incident_custody_chain_verify(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> ChainVerifyResult:
    """Recompute each evidence audit row's hash and compare to the stored value.

    NB: cross-row linkage (`prev_hash` traces back to the previous row in the
    full audit chain) is NOT checked here — that requires walking the whole
    audit log. This endpoint only verifies that each individual row hasn't been
    tampered with after the fact.
    """
    await _get_incident(db, incident_id, user)
    rows = await _incident_evidence_events(db, incident_id)

    for row in rows:
        if not verify_row_hash(row):
            return ChainVerifyResult(
                ok=False,
                checked=len(rows),
                broken_at_id=row.id,
                broken_reason=(
                    f"row_hash mismatch on event '{row.action}' "
                    f"at {row.timestamp.isoformat()}"
                ),
                message="Integrity check FAILED — at least one event has been tampered with.",
            )

    return ChainVerifyResult(
        ok=True,
        checked=len(rows),
        message=f"All {len(rows)} evidence events verify cleanly.",
    )


# ─── Exports (must be registered before /{evidence_id} to avoid route shadowing) ─

@router.get(
    "/{incident_id}/evidence/exports",
    response_model=ExportList,
    summary="List custody export bundles",
)
async def list_exports(
    incident_id: uuid.UUID,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    limit:  int           = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
) -> ExportList:
    """List the custody export bundles created for an incident, newest first
    (cursor-paginated). Admin only. Each item's status reflects expiry/consumed
    overlay; secrets (download token, AES key) are never returned here."""
    await _get_incident(db, incident_id, user)
    offset = _decode_cursor(cursor)

    stmt = (
        select(CustodyExport)
        .where(CustodyExport.incident_id == incident_id)
        .order_by(CustodyExport.created_at.desc(), CustodyExport.id)
        .offset(offset)
        .limit(limit + 1)
    )
    rows = (await db.execute(stmt)).scalars().all()
    has_more    = len(rows) > limit
    items       = [_to_export_out(r) for r in rows[:limit]]
    next_cursor = _encode_cursor(offset + limit) if has_more else None
    return ExportList(items=items, next_cursor=next_cursor)


@router.get(
    "/{incident_id}/evidence/exports/{export_id}",
    response_model=ExportOut,
    summary="Get a custody export bundle",
)
async def get_export(
    incident_id: uuid.UUID,
    export_id:   uuid.UUID,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ExportOut:
    """Get one custody export bundle's metadata by id, scoped to the incident.
    Admin only. Returns the export record with an expiry-aware status; does not
    expose the one-time download token or encryption key."""
    await _get_incident(db, incident_id, user)
    exp = (await db.execute(
        select(CustodyExport).where(
            CustodyExport.id == export_id,
            CustodyExport.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not exp:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Export not found")
    return _to_export_out(exp)


# ─── Detail ──────────────────────────────────────────────────────────────────

@router.get(
    "/{incident_id}/evidence/{evidence_id}",
    response_model=EvidenceOut,
    summary="Get an evidence item",
)
async def get_evidence(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> EvidenceOut:
    """Get the current state of a single evidence item (custodian, status,
    hashes, acquisition metadata) by id within an incident. Requires access to
    the incident. Returns 404 if the item is not part of this incident."""
    await _get_incident(db, incident_id, user)
    ev = await _get_evidence(db, incident_id, evidence_id)
    return _to_out(ev)


# ─── Collect (digital_file) — multipart upload ───────────────────────────────

@router.post(
    "/{incident_id}/evidence/digital",
    response_model=EvidenceOut,
    status_code=status.HTTP_201_CREATED,
    summary="Collect digital file evidence",
)
async def collect_digital(
    incident_id:        uuid.UUID,
    request:            Request,
    name:               str           = Form(..., min_length=1, max_length=256),
    identifier:         str           = Form(..., min_length=1, max_length=128),
    description:        Optional[str] = Form(default=None),
    tlp:                Tlp           = Form(default="amber"),
    collected_location: Optional[str] = Form(default=None, max_length=256),
    collected_as_role:  Optional[str] = Form(default=None),   # GS-12 — defr | des
    entity_id:          Optional[str] = Form(default=None),
    file:               UploadFile    = File(...),
    # ── Wizard A — optional acquisition metadata (additive) ───────────────
    lawful_basis:              Optional[str]  = Form(default=None),
    lawful_basis_note:         Optional[str]  = Form(default=None),
    acquisition_tool:          Optional[str]  = Form(default=None),
    acquisition_tool_version:  Optional[str]  = Form(default=None),
    acquisition_tool_sha256:   Optional[str]  = Form(default=None),
    acquisition_params:        Optional[str]  = Form(default=None),
    acquisition_hash_source:   Optional[str]  = Form(default=None),
    acquisition_hash_target:   Optional[str]  = Form(default=None),
    write_blocker_used:        Optional[bool] = Form(default=None),
    write_blocker_serial:      Optional[str]  = Form(default=None),
    system_state:              Optional[str]  = Form(default=None),
    live_justification:        Optional[str]  = Form(default=None),
    network_isolated:          Optional[bool] = Form(default=None),
    witness_user_id:           Optional[str]  = Form(default=None),
    witness_name:              Optional[str]  = Form(default=None),
    # ── Collection wizard — ISO/IEC 27037 §7 (additive) ───────────────────
    device_types:              Optional[str]  = Form(default=None),  # JSON array
    handling_mode:             Optional[str]  = Form(default=None),
    decision_factors:          Optional[str]  = Form(default=None),  # JSON object
    acquisition_scope:         Optional[str]  = Form(default=None),
    logical_acquisition_rationale: Optional[str] = Form(default=None),
    system_time_offset:        Optional[str]  = Form(default=None),
    screen_state:              Optional[str]  = Form(default=None),
    changes_made:              Optional[str]  = Form(default=None),
    device_details:            Optional[str]  = Form(default=None),  # JSON object
    # ── ISO/IEC 27041 — method/tool validation (Slice B) ──────────────────
    acquisition_tool_validated:       Optional[bool] = Form(default=None),
    acquisition_tool_validation_ref:  Optional[str]  = Form(default=None),
    acquisition_tool_validation_date: Optional[str]  = Form(default=None),
    user:               User          = Depends(require_analyst),
    db:                 AsyncSession  = Depends(get_db),
) -> EvidenceOut:
    """Collect a digital file as evidence via multipart upload. The file is
    streamed once to compute SHA-256/SHA-1/MD5 and is stored encrypted at rest
    with AES-256-GCM; the plaintext is never persisted. Accepts extensive
    optional ISO/IEC 27037/27041 acquisition metadata (tool, write-blocker,
    lawful basis, witness, device details) as form fields. Requires analyst
    role and an open incident; the caller becomes collector and custodian.
    Returns the created evidence record (201)."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    resolved_entity_id = await _resolve_entity(db, incident_id, entity_id)
    device_types_list    = _json_list(device_types, "device_types")
    decision_factors_obj = _json_object(decision_factors, "decision_factors")
    device_details_obj   = _json_object(device_details, "device_details")

    # Early reject on Content-Length if available — saves bandwidth.
    cl = request.headers.get("content-length")
    if cl and int(cl) > settings.evidence_max_upload_bytes:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"Upload exceeds max {settings.evidence_max_upload_bytes} bytes",
        )

    # Stream the file, computing all three hashes in one pass.
    raw, sha256, sha1, md5, size = await amulti_hash(file.file)
    if size > settings.evidence_max_upload_bytes:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"Upload exceeds max {settings.evidence_max_upload_bytes} bytes",
        )

    evidence_id   = uuid.uuid4()
    relative_path = _storage_path_for(incident_id, evidence_id, file.filename or "unnamed.bin")

    # Encrypt-at-rest with AES-256-GCM. write_encrypted returns the path.
    await awrite_encrypted(raw, relative_path)
    # Read back the nonce we just wrote.
    from pathlib import Path
    nonce_hex = (Path(settings.evidence_path) / (relative_path + ".nonce")).read_text().strip()

    # Optional witness user lookup (must be an active platform user).
    witness_uid = None
    if witness_user_id:
        try:
            witness_uid = uuid.UUID(witness_user_id)
            exists = (await db.execute(
                select(User.id).where(User.id == witness_uid)
            )).scalar_one_or_none()
            if not exists:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Witness user not found")
        except ValueError:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid witness_user_id format")

    ev = Evidence(
        id=evidence_id,
        incident_id=incident_id,
        kind="digital_file",
        name=name,
        identifier=identifier,
        description=description,
        tlp=tlp,
        status="active",
        entity_id=resolved_entity_id,
        original_filename=file.filename,
        storage_path=relative_path,
        file_size_bytes=size,
        mime_type=file.content_type,
        sha256=sha256, sha1=sha1, md5=md5,
        nonce_hex=nonce_hex,
        current_custodian_id=user.id,
        collected_by_id=user.id,
        collected_as_role=(collected_as_role if collected_as_role in ("defr", "des") else None),
        collected_at=utcnow(),
        collected_location=collected_location,
        # Wizard A — only persisted if the caller supplied them
        lawful_basis=lawful_basis,
        lawful_basis_note=lawful_basis_note,
        acquisition_tool=acquisition_tool,
        acquisition_tool_version=acquisition_tool_version,
        acquisition_tool_sha256=(acquisition_tool_sha256.lower() if acquisition_tool_sha256 else None),
        acquisition_params=acquisition_params,
        acquisition_hash_source=(acquisition_hash_source.lower() if acquisition_hash_source else None),
        acquisition_hash_target=(acquisition_hash_target.lower() if acquisition_hash_target else None),
        write_blocker_used=write_blocker_used,
        write_blocker_serial=write_blocker_serial,
        system_state=system_state,
        live_justification=live_justification,
        network_isolated=network_isolated,
        witness_user_id=witness_uid,
        witness_name=witness_name,
        # Collection wizard (ISO/IEC 27037 §7)
        device_types=device_types_list,
        handling_mode=handling_mode,
        decision_factors=decision_factors_obj,
        acquisition_scope=acquisition_scope,
        logical_acquisition_rationale=logical_acquisition_rationale,
        system_time_offset=system_time_offset,
        screen_state=screen_state,
        changes_made=changes_made,
        device_details=device_details_obj,
        # ISO/IEC 27041 — method/tool validation + collector competence (Slice B)
        acquisition_tool_validated=acquisition_tool_validated,
        acquisition_tool_validation_ref=acquisition_tool_validation_ref,
        acquisition_tool_validation_date=acquisition_tool_validation_date,
        collected_by_qualifications=user.qualifications,
    )
    db.add(ev)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        await adelete_encrypted(relative_path)
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Evidence identifier already exists on this incident",
        )

    await write_audit(
        db, "evidence_collect",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id),
        details={
            "incident_id": str(incident_id),
            "kind": "digital_file",
            "identifier": identifier,
            "name": name,
            "sha256": sha256,
            "file_size_bytes": size,
            "tlp": tlp,
            "collected_location": collected_location,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return _to_out(ev)


# ─── Collect (physical_item) — JSON ──────────────────────────────────────────

@router.post(
    "/{incident_id}/evidence/physical",
    response_model=EvidenceOut,
    status_code=status.HTTP_201_CREATED,
    summary="Collect physical item evidence",
)
async def collect_physical(
    incident_id: uuid.UUID,
    req:         PhysicalEvidenceCreate,
    request:     Request,
    user:        User = Depends(require_analyst),
    db:          AsyncSession = Depends(get_db),
) -> EvidenceOut:
    """Register a physical item (device, media, document) as evidence from a
    JSON body, capturing make/model/serial, location, condition, photos and
    optional ISO/IEC 27037 acquisition metadata. Requires analyst role and an
    open incident; the caller becomes collector and custodian. Returns the
    created evidence record (201)."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    resolved_entity_id = await _resolve_entity(db, incident_id, str(req.entity_id) if req.entity_id else None)

    # Wizard A — validate witness user if provided.
    witness_uid = req.witness_user_id
    if witness_uid:
        exists = (await db.execute(
            select(User.id).where(User.id == witness_uid)
        )).scalar_one_or_none()
        if not exists:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Witness user not found")

    ev = Evidence(
        id=uuid.uuid4(),
        incident_id=incident_id,
        kind="physical_item",
        name=req.name,
        identifier=req.identifier,
        description=req.description,
        tlp=req.tlp,
        status="active",
        entity_id=resolved_entity_id,
        make=req.make, model=req.model, serial=req.serial,
        physical_location=req.physical_location,
        condition=req.condition,
        photos=[p.model_dump(mode="json") for p in req.photos],
        current_custodian_id=user.id,
        collected_by_id=user.id,
        collected_as_role=req.collected_as_role,
        collected_at=utcnow(),
        collected_location=req.collected_location,
        # Wizard A passthrough (subset relevant to physical items)
        lawful_basis=req.lawful_basis,
        lawful_basis_note=req.lawful_basis_note,
        acquisition_tool=req.acquisition_tool,
        acquisition_tool_version=req.acquisition_tool_version,
        acquisition_tool_sha256=(req.acquisition_tool_sha256.lower() if req.acquisition_tool_sha256 else None),
        acquisition_params=req.acquisition_params,
        witness_user_id=witness_uid,
        witness_name=req.witness_name,
        # Collection wizard (ISO/IEC 27037 §7)
        device_types=(req.device_types or None),
        handling_mode=req.handling_mode,
        decision_factors=req.decision_factors,
        acquisition_scope=req.acquisition_scope,
        logical_acquisition_rationale=req.logical_acquisition_rationale,
        system_time_offset=req.system_time_offset,
        screen_state=req.screen_state,
        changes_made=req.changes_made,
        device_details=req.device_details,
        # ISO/IEC 27041 — method/tool validation + collector competence (Slice B)
        acquisition_tool_validated=req.acquisition_tool_validated,
        acquisition_tool_validation_ref=req.acquisition_tool_validation_ref,
        acquisition_tool_validation_date=req.acquisition_tool_validation_date,
        collected_by_qualifications=user.qualifications,
    )
    db.add(ev)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Evidence identifier already exists on this incident",
        )

    await write_audit(
        db, "evidence_collect",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id),
        details={
            "incident_id": str(incident_id),
            "kind": "physical_item",
            "identifier": req.identifier,
            "name": req.name,
            "make": req.make, "model": req.model, "serial": req.serial,
            "tlp": req.tlp,
            "collected_location": req.collected_location,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return _to_out(ev)


# ─── Update (descriptive fields) ─────────────────────────────────────────────

@router.patch(
    "/{incident_id}/evidence/{evidence_id}",
    response_model=EvidenceOut,
    summary="Update evidence descriptive fields",
)
async def update_evidence(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    req:     EvidenceUpdate,
    request: Request,
    user:    User = Depends(require_analyst),
    db:      AsyncSession = Depends(get_db),
) -> EvidenceOut:
    """Edit descriptive fields only (name, description, TLP, physical location,
    condition, photos, collected-as role) — hashes, custodian and acquisition
    facts are immutable here. Requires analyst role and an open incident; the
    item must be active or verify_failed (disposed items reject). Only changed
    fields are audited. Returns the updated record."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    ev = await _get_evidence(db, incident_id, evidence_id)
    if ev.status not in ("active", "verify_failed"):
        raise HTTPException(status.HTTP_409_CONFLICT, "Disposed evidence cannot be edited")

    changed: dict[str, object] = {}
    if req.name is not None and req.name != ev.name:
        ev.name = req.name; changed["name"] = req.name
    if req.description is not None and req.description != (ev.description or ""):
        ev.description = req.description; changed["description"] = req.description
    if req.tlp is not None and req.tlp != ev.tlp:
        ev.tlp = req.tlp; changed["tlp"] = req.tlp
    if req.physical_location is not None and req.physical_location != (ev.physical_location or ""):
        ev.physical_location = req.physical_location; changed["physical_location"] = req.physical_location
    if req.condition is not None and req.condition != (ev.condition or ""):
        ev.condition = req.condition; changed["condition"] = req.condition
    if req.photos is not None:
        ev.photos = [p.model_dump(mode="json") for p in req.photos]
        changed["photos_count"] = len(ev.photos)
    if req.collected_as_role is not None and req.collected_as_role != ev.collected_as_role:
        ev.collected_as_role = req.collected_as_role; changed["collected_as_role"] = req.collected_as_role

    if changed:
        await write_audit(
            db, "evidence_update",
            user_id=user.id, username=user.username,
            resource_type="evidence", resource_id=str(ev.id),
            details={"incident_id": str(incident_id), "changes": changed},
            ip_address=request.client.host if request.client else None,
        )
    await db.commit()
    return _to_out(ev)


# ─── Transfer custody ────────────────────────────────────────────────────────

def _is_external_custody(ev: Evidence) -> bool:
    """True when the row's accountable party is a real-world external person
    without a platform account (Wizard-level chain extension)."""
    return ev.current_custodian_id is None and bool(ev.current_custodian_external_name)


def _block_if_external(ev: Evidence, action: str) -> None:
    """Raise 409 if the action needs an internal actor. Used to gate
    examine/verify/seal/exam-session while the row is in external custody."""
    if _is_external_custody(ev):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Cannot {action}: evidence is in external custody "
            f"({ev.current_custodian_external_name}"
            + (f", {ev.current_custodian_external_org}" if ev.current_custodian_external_org else "")
            + "). Transfer back to an internal custodian first.",
        )


@router.post(
    "/{incident_id}/evidence/{evidence_id}/transfer",
    response_model=EvidenceOut,
    summary="Transfer custody of evidence",
)
async def transfer_evidence(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    req:     TransferRequest,
    request: Request,
    user:    User = Depends(require_analyst),
    db:      AsyncSession = Depends(get_db),
) -> EvidenceOut:
    """Hand custody of an active evidence item to a new custodian — either an
    internal platform user (`to_user_id`) or an external party (`to_external`),
    capturing reason, transport method, seal id and courier reference. Requires
    analyst role and an open incident; rejects no-op transfers to the current
    custodian. Records an evidence_transfer custody event and returns the
    updated record."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    ev = await _get_evidence(db, incident_id, evidence_id)
    if ev.status != "active":
        raise HTTPException(status.HTTP_409_CONFLICT, f"Cannot transfer evidence in status '{ev.status}'")

    from_user_id     = ev.current_custodian_id
    from_external    = ev.current_custodian_external_name
    from_external_org = ev.current_custodian_external_org

    if req.to_user_id is not None:
        # ── Internal transfer ──────────────────────────────────────────────
        to_user = (await db.execute(
            select(User).where(User.id == req.to_user_id)
        )).scalar_one_or_none()
        if not to_user:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Target user not found")
        if not to_user.is_active:
            raise HTTPException(status.HTTP_409_CONFLICT, "Target user is not active")
        if to_user.id == ev.current_custodian_id:
            raise HTTPException(status.HTTP_409_CONFLICT, "Target user is already the custodian")
        ev.current_custodian_id                  = to_user.id
        ev.current_custodian_external_name       = None
        ev.current_custodian_external_org        = None
        ev.current_custodian_external_contact    = None
        audit_details = {
            "incident_id":  str(incident_id),
            "kind":         "internal",
            "from_user_id": str(from_user_id) if from_user_id else None,
            "from_external_name": from_external,
            "from_external_org":  from_external_org,
            "to_user_id":   str(to_user.id),
            "to_username":  to_user.username,
            "reason":       req.reason,
            "transport_method": req.transport_method,
            "seal_id":          req.seal_id,
            "courier_ref":      req.courier_ref,
        }
    else:
        # ── External transfer ─────────────────────────────────────────────
        ext = req.to_external
        same_as_now = (
            ev.current_custodian_id is None and
            (ev.current_custodian_external_name or "").strip().lower() == ext.name.strip().lower() and
            (ev.current_custodian_external_org or "").strip().lower() == (ext.organisation or "").strip().lower()
        )
        if same_as_now:
            raise HTTPException(status.HTTP_409_CONFLICT, "Target external party is already the custodian")
        ev.current_custodian_id                  = None
        ev.current_custodian_external_name       = ext.name.strip()
        ev.current_custodian_external_org        = (ext.organisation or "").strip() or None
        ev.current_custodian_external_contact    = (ext.contact or "").strip() or None
        audit_details = {
            "incident_id":  str(incident_id),
            "kind":         "external",
            "from_user_id": str(from_user_id) if from_user_id else None,
            "from_external_name": from_external,
            "from_external_org":  from_external_org,
            "to_external_name":   ev.current_custodian_external_name,
            "to_external_org":    ev.current_custodian_external_org,
            "to_external_contact": ev.current_custodian_external_contact,
            "reason":       req.reason,
            "transport_method": req.transport_method,
            "seal_id":          req.seal_id,
            "courier_ref":      req.courier_ref,
        }

    await write_audit(
        db, "evidence_transfer",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id),
        details=audit_details,
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return _to_out(ev)


# ─── Examine ─────────────────────────────────────────────────────────────────

@router.post(
    "/{incident_id}/evidence/{evidence_id}/examine",
    response_model=EvidenceOut,
    summary="Record an examination action",
)
async def examine_evidence(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    req:     ExamineRequest,
    request: Request,
    user:    User = Depends(require_analyst),
    db:      AsyncSession = Depends(get_db),
) -> EvidenceOut:
    """Record a standalone analysis/examination action (tool used, notes) as a
    custody event. Requires analyst role and an open incident; the item must be
    active and held by an internal custodian (external custody is rejected).
    For integrity-bracketed analysis use the examination-session endpoint
    instead. Returns the evidence record."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    ev = await _get_evidence(db, incident_id, evidence_id)
    if ev.status != "active":
        raise HTTPException(status.HTTP_409_CONFLICT, f"Cannot examine evidence in status '{ev.status}'")
    _block_if_external(ev, "examine")

    await write_audit(
        db, "evidence_examine",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id),
        details={
            "incident_id": str(incident_id),
            "tool":  req.tool,
            "notes": req.notes,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return _to_out(ev)


# ─── Verify integrity ────────────────────────────────────────────────────────

@router.post(
    "/{incident_id}/evidence/{evidence_id}/verify",
    response_model=VerifyResult,
    summary="Verify evidence integrity",
)
async def verify_evidence(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    request: Request,
    user:    User = Depends(require_analyst),
    db:      AsyncSession = Depends(get_db),
) -> VerifyResult:
    """Decrypt the stored digital_file blob, recompute its SHA-256 and compare
    against the hash recorded at collection. Requires analyst role; digital-file
    only and internal custody only. On mismatch the item is frozen
    (status → verify_failed) and a failure custody event is written. Returns the
    recorded vs recomputed hashes and an ok flag."""
    inc = await _get_incident(db, incident_id, user)
    ev  = await _get_evidence(db, incident_id, evidence_id)

    if ev.kind != "digital_file":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Verify only applies to digital_file evidence",
        )
    _block_if_external(ev, "verify")
    if not ev.storage_path or not ev.nonce_hex or not ev.sha256:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Evidence is missing storage metadata required for verification",
        )

    try:
        plaintext = await aread_decrypted(ev.storage_path, ev.nonce_hex)
        computed  = sha256_of(plaintext)
        ok        = (computed == ev.sha256)
    except Exception as e:
        ok = False
        computed = None
        err_msg  = str(e)

    if ok:
        await write_audit(
            db, "evidence_verify",
            user_id=user.id, username=user.username,
            resource_type="evidence", resource_id=str(ev.id),
            outcome="success",
            details={
                "incident_id": str(incident_id),
                "sha256": ev.sha256,
            },
            ip_address=request.client.host if request.client else None,
        )
        await db.commit()
        return VerifyResult(
            ok=True,
            sha256_recorded=ev.sha256,
            sha256_recomputed=computed,
            message="Integrity verified.",
        )

    # Failure path: freeze the evidence + audit + return.
    if ev.status == "active":
        ev.status = "verify_failed"
    await write_audit(
        db, "evidence_verify_failed",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id),
        outcome="failure",
        details={
            "incident_id": str(incident_id),
            "sha256_recorded":   ev.sha256,
            "sha256_recomputed": computed,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return VerifyResult(
        ok=False,
        sha256_recorded=ev.sha256,
        sha256_recomputed=computed,
        message="Integrity check FAILED — evidence frozen pending admin review.",
    )


# ─── Dispose (destroy / return / archive) ────────────────────────────────────

@router.post(
    "/{incident_id}/evidence/{evidence_id}/dispose",
    response_model=EvidenceOut,
    summary="Dispose of evidence",
)
async def dispose_evidence(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    req:     DisposeRequest,
    request: Request,
    user:    User = Depends(require_admin),
    db:      AsyncSession = Depends(get_db),
) -> EvidenceOut:
    """Dispose of an evidence item — destroy, return, or archive (`req.kind`).
    Admin only. On destroy the encrypted blob and any encrypted photos are
    permanently deleted while the final SHA-256 and custody chain are retained.
    Legal-hold items require a distinct active second approver (`witness_id`) for
    two-person integrity. Returns the updated record with disposition status and
    timestamp."""
    inc = await _get_incident(db, incident_id, user)
    ev  = await _get_evidence(db, incident_id, evidence_id)
    if ev.status in ("destroyed", "returned", "archived"):
        raise HTTPException(status.HTTP_409_CONFLICT, "Evidence is already disposed")

    # GS-10 — two-person integrity for legal-hold disposal (SWGDE/ACPO). A held
    # item may only be disposed with a second approver who is a distinct active user.
    if ev.legal_hold:
        if not req.witness_id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                "Legal-hold evidence requires a second approver (witness_id) to dispose")
        if req.witness_id == user.id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                "The disposal witness must be a different user (two-person integrity)")
        witness = (await db.execute(
            select(User).where(User.id == req.witness_id, User.is_active.is_(True))
        )).scalar_one_or_none()
        if not witness:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "witness_id is not an active user")
        ev.dispose_witness_id = req.witness_id

    # Record final hash before removing the file (digital_file only).
    final_hash = ev.sha256
    if req.kind == "destroy" and ev.kind == "digital_file" and ev.storage_path:
        # File is permanently removed; chain entry + hash persist.
        await adelete_encrypted(ev.storage_path)
        ev.storage_path = None
        ev.nonce_hex    = None
    if req.kind == "destroy":
        # GS-11 — also remove encrypted photo files (digital or physical).
        for p in (ev.photos or []):
            if isinstance(p, dict) and p.get("storage_path"):
                await adelete_encrypted(p["storage_path"])

    status_by_kind = {"destroy": "destroyed", "return": "returned", "archive": "archived"}
    ev.status                    = status_by_kind[req.kind]
    ev.disposed_at               = utcnow()
    ev.final_hash_at_disposition = final_hash

    await write_audit(
        db, f"evidence_{req.kind}",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id),
        outcome="success",
        details={
            "incident_id": str(incident_id),
            "reason":      req.reason,
            "final_sha256": final_hash,
            "file_removed": req.kind == "destroy" and ev.kind == "digital_file",
            "legal_hold":   ev.legal_hold,
            "dispose_witness_id": str(req.witness_id) if ev.legal_hold else None,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return _to_out(ev)


# ─── GS-11 — Photo attachments (ISO/IEC 27037 §9.1.4; encrypted at rest) ────
# Real image bytes are stored AES-256-GCM under photos/{eid}/ and only served
# back through the auth-gated GET route below. Legacy free-text-URL photos (no
# storage_path) are untouched — the frontend renders them via their url directly.

@router.post(
    "/{incident_id}/evidence/{evidence_id}/photos",
    response_model=EvidenceOut,
    summary="Attach a photo to evidence",
)
async def add_evidence_photo(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    request:  Request,
    file:     UploadFile = File(...),
    caption:  Optional[str] = Form(default=None),
    taken_at: Optional[str] = Form(default=None),   # ISO 8601 (optional)
    user:     User = Depends(require_analyst),
    db:       AsyncSession = Depends(get_db),
) -> EvidenceOut:
    """Upload an image (multipart) and attach it to an evidence item, with an
    optional caption and ISO 8601 `taken_at`. The image is stored encrypted at
    rest with AES-256-GCM and its SHA-256 recorded; it is served back only via
    the auth-gated photo GET route. Requires analyst role and an open incident;
    the item must be active or verify_failed. Returns the updated record."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    ev = await _get_evidence(db, incident_id, evidence_id)
    if ev.status not in ("active", "verify_failed"):
        raise HTTPException(status.HTTP_409_CONFLICT, "Disposed evidence cannot be edited")
    if not (file.content_type or "").lower().startswith("image/"):
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Photo must be an image/* file")

    raw = await file.read()
    if not raw:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty file")
    if len(raw) > settings.evidence_max_upload_bytes:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            f"Photo exceeds max {settings.evidence_max_upload_bytes} bytes")

    photo_id = uuid.uuid4().hex
    rel = f"photos/{evidence_id}/{photo_id}.enc"
    await awrite_encrypted(raw, rel)
    from pathlib import Path
    nonce_hex = (Path(settings.evidence_path) / (rel + ".nonce")).read_text().strip()

    entry = {
        "id":           photo_id,
        "url":          f"/api/incidents/{incident_id}/evidence/{evidence_id}/photos/{photo_id}",
        "caption":      (caption or None),
        "taken_at":     (taken_at or None),
        "storage_path": rel,
        "nonce_hex":    nonce_hex,
        "mime_type":    file.content_type,
        "sha256":       sha256_of(raw),
        "size":         len(raw),
    }
    ev.photos = (list(ev.photos) if ev.photos else []) + [entry]
    await write_audit(
        db, "evidence_photo_add",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id), outcome="success",
        details={"incident_id": str(incident_id), "photo_id": photo_id,
                 "mime_type": file.content_type, "sha256": entry["sha256"], "size": len(raw)},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return _to_out(ev)


@router.get(
    "/{incident_id}/evidence/{evidence_id}/photos/{photo_id}",
    summary="Download an evidence photo",
)
async def get_evidence_photo(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    photo_id:    str,
    user: User = Depends(current_user),
    db:   AsyncSession = Depends(get_db),
) -> Response:
    """Stream back a previously attached evidence photo by id. Requires access
    to the incident (zero-trust gate). Decrypts the AES-256-GCM-stored image on
    the fly and returns the raw bytes with the original media type."""
    await _get_incident(db, incident_id, user)   # incident-access gate (zero-trust)
    ev = await _get_evidence(db, incident_id, evidence_id)
    entry = next((p for p in (ev.photos or [])
                  if isinstance(p, dict) and p.get("id") == photo_id), None)
    if not entry or not entry.get("storage_path"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Photo not found")
    raw = await aread_decrypted(entry["storage_path"], entry.get("nonce_hex") or "")
    return Response(content=raw, media_type=entry.get("mime_type") or "application/octet-stream")


# ─── Wizard A — Seal acquisition (ISO/IEC 27037 §9.2.4) ────────────────────
# Validates that the minimum reproducibility + lawful-basis fields are present,
# then sets coc_sealed. After sealing, subsequent PATCH updates write an
# `evidence_amend_after_seal` audit row so reviewers can see post-seal changes.

@router.post(
    "/{incident_id}/evidence/{evidence_id}/seal",
    response_model=EvidenceOut,
    summary="Seal the chain of custody",
)
async def seal_evidence(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    req:     EvidenceSealRequest,
    request: Request,
    user:    User = Depends(require_analyst),
    db:      AsyncSession = Depends(get_db),
) -> EvidenceOut:
    """Seal an item's chain of custody (ISO/IEC 27037 §9.2.4) after enforcing
    the minimum reproducibility and lawful-basis fields are present (e.g. lawful
    basis, device types, and for digital files the hash plus acquisition tool +
    version). Best-effort applies a trusted timestamp to the sealed hash.
    Requires `confirm=true`, analyst role, an open incident, internal custody,
    and active status; rejects an already-sealed item. After sealing, later
    edits are audited as post-seal amendments. Returns the sealed record."""
    if not req.confirm:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "confirm must be true to seal")
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    ev = await _get_evidence(db, incident_id, evidence_id)
    if ev.coc_sealed:
        raise HTTPException(status.HTTP_409_CONFLICT, "Evidence is already sealed")
    if ev.status != "active":
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"Cannot seal evidence in status '{ev.status}'")
    _block_if_external(ev, "seal")

    # Gate sealing on the wizard-A minimum (ISO §9.2.4 + GDPR Art. 5.1(c)).
    missing: list[str] = []
    if not ev.lawful_basis:
        missing.append("lawful_basis")
    if not ev.collected_by_id:
        missing.append("collected_by_id")
    # Collection wizard (ISO/IEC 27037 §7) — at least one device type tagged.
    if not ev.device_types:
        missing.append("device_types")
    if ev.kind == "digital_file":
        if not ev.sha256:
            missing.append("sha256")
        if not ev.acquisition_tool:
            missing.append("acquisition_tool")
        if not ev.acquisition_tool_version:
            missing.append("acquisition_tool_version")
        if ev.acquisition_hash_source and ev.acquisition_hash_target:
            if ev.acquisition_hash_source.lower() != ev.acquisition_hash_target.lower():
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    "Acquisition source and target hashes do not match — cannot seal",
                )
        # Live justification covers both 'live' and 'live_critical' (§7.1.3.1.1).
        if (ev.system_state or "").lower() in ("live", "live_critical") and not (ev.live_justification or "").strip():
            missing.append("live_justification")
        # Logical acquisition must carry a rationale (§7.1.3.1.1).
        if (ev.acquisition_scope or "").lower() == "logical" and not (ev.logical_acquisition_rationale or "").strip():
            missing.append("logical_acquisition_rationale")
    if ev.kind == "physical_item":
        if not (ev.photos and len(ev.photos) > 0):
            missing.append("photos")

    if missing:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Cannot seal — required fields missing: {', '.join(missing)}",
        )

    ev.coc_sealed       = True
    ev.coc_sealed_at    = utcnow()
    ev.coc_sealed_by_id = user.id

    # GS-4 — trusted timestamp on the sealed hash (best-effort; only the hash egresses).
    tst = await timestamp_sha256(ev.sha256)
    if tst:
        ev.seal_tst      = tst["tst_b64"]
        ev.seal_tst_time = tst["time"]
        ev.seal_tsa      = tst["tsa"]

    await write_audit(
        db, "evidence_seal",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id),
        outcome="success",
        details={
            "incident_id":     str(incident_id),
            "lawful_basis":    ev.lawful_basis,
            "acquisition_tool":         ev.acquisition_tool,
            "acquisition_tool_version": ev.acquisition_tool_version,
            "sha256":          ev.sha256,
            "witness_user_id": str(ev.witness_user_id) if ev.witness_user_id else None,
            "trusted_timestamp": bool(tst),
            "tsa_time":        tst["time"] if tst else None,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return _to_out(ev)


# ─── Wizard B — Examination session (pre-verify + examine + post-verify) ──
# A transactional grouping that prevents recording analysis without integrity
# verification on both sides (ISO/IEC 27037 §9.4.2). All three audit rows
# share an examination_session uuid in their details so the custody log can
# group them.

class ExamSessionRequest(BaseModel):
    tool:    str = Field(min_length=1, max_length=256)
    version: Optional[str] = Field(default=None, max_length=64)
    params:  Optional[str] = Field(default=None, max_length=4096)
    notes:   Optional[str] = Field(default=None, max_length=4096)
    # ISO/IEC 27041 — analysis tool/method validation (Slice B)
    tool_validated:      Optional[bool] = None
    tool_validation_ref: Optional[str]  = Field(default=None, max_length=256)
    # ISO/IEC 27042 — analysis & interpretation records (Slice E; checklist items 8 + 12)
    findings:          Optional[str] = Field(default=None, max_length=8192)   # what was found
    interpretation:    Optional[str] = Field(default=None, max_length=8192)   # what it means
    confidence:        Optional[str] = Field(default=None, max_length=32)     # low | moderate | high
    scope_limitations: Optional[str] = Field(default=None, max_length=4096)   # what was NOT examined / caveats (item 12)
    # GS-2 — which working copy the analysis was performed on (ISO/IEC 27037 §7.1.3.1.1)
    working_copy_id:   Optional[uuid.UUID] = None


class ExamSessionResult(BaseModel):
    ok:                 bool
    session_id:         uuid.UUID
    pre_verify_sha256:  Optional[str] = None
    post_verify_sha256: Optional[str] = None
    message:            str


async def _verify_once(ev: Evidence) -> tuple[bool, Optional[str]]:
    if not ev.storage_path or not ev.nonce_hex or not ev.sha256:
        return False, None
    try:
        plaintext = await aread_decrypted(ev.storage_path, ev.nonce_hex)
        computed  = sha256_of(plaintext)
        return (computed == ev.sha256), computed
    except Exception:
        return False, None


@router.post(
    "/{incident_id}/evidence/{evidence_id}/examination-session",
    response_model=ExamSessionResult,
    summary="Run an examination session",
)
async def examination_session(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    req:     ExamSessionRequest,
    request: Request,
    user:    User = Depends(require_analyst),
    db:      AsyncSession = Depends(get_db),
) -> ExamSessionResult:
    """Run an integrity-bracketed examination (ISO/IEC 27037 §9.4.2): pre-verify
    the hash, record the examine action (tool, findings, interpretation, scope
    limitations, optional working-copy id), then post-verify — all sharing one
    session id in the custody log. Requires analyst role, an open incident,
    active digital-file evidence held internally. A failed pre- or post-verify
    freezes the item (verify_failed). Returns pre/post hashes and an ok flag."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    ev = await _get_evidence(db, incident_id, evidence_id)
    if ev.status != "active":
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"Cannot examine evidence in status '{ev.status}'")
    if ev.kind != "digital_file":
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Examination session is digital-file only (uses hash verify)")
    _block_if_external(ev, "run examination session on")

    # GS-2 — if a working copy is named, it must belong to this evidence (ISO 27042:
    # analysis runs on a verified copy, not the master).
    if req.working_copy_id is not None:
        wc = (await db.execute(
            select(EvidenceCopy.id).where(
                EvidenceCopy.id == req.working_copy_id,
                EvidenceCopy.evidence_id == ev.id,
            )
        )).scalar_one_or_none()
        if wc is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                "working_copy_id does not belong to this evidence item")

    session_id = uuid.uuid4()
    ip = request.client.host if request.client else None

    # ── Pre-verify ──────────────────────────────────────────────────────
    pre_ok, pre_hash = await _verify_once(ev)
    await write_audit(
        db, "evidence_verify" if pre_ok else "evidence_verify_failed",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id),
        outcome="success" if pre_ok else "failure",
        details={
            "incident_id":        str(incident_id),
            "examination_session": str(session_id),
            "phase":              "pre",
            "sha256_recorded":    ev.sha256,
            "sha256_recomputed":  pre_hash,
        },
        ip_address=ip,
    )
    if not pre_ok:
        if ev.status == "active":
            ev.status = "verify_failed"
        await db.commit()
        return ExamSessionResult(
            ok=False, session_id=session_id, pre_verify_sha256=pre_hash,
            message="Pre-examination integrity check FAILED — evidence frozen; examination aborted.",
        )

    # ── Examine ─────────────────────────────────────────────────────────
    await write_audit(
        db, "evidence_examine",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id),
        outcome="success",
        details={
            "incident_id":         str(incident_id),
            "examination_session": str(session_id),
            "phase":               "examine",
            "tool":    req.tool,
            "version": req.version,
            "params":  req.params,
            "notes":   req.notes,
            # ISO/IEC 27041 — analysis-tool validation + examiner competence (Slice B)
            "tool_validated":        req.tool_validated,
            "tool_validation_ref":   req.tool_validation_ref,
            "examiner_qualifications": user.qualifications,
            # ISO/IEC 27042 — analysis & interpretation records (Slice E)
            "findings":          req.findings,
            "interpretation":    req.interpretation,
            "confidence":        req.confidence,
            "scope_limitations": req.scope_limitations,
            "working_copy_id":   str(req.working_copy_id) if req.working_copy_id else None,
        },
        ip_address=ip,
    )

    # ── Post-verify ─────────────────────────────────────────────────────
    post_ok, post_hash = await _verify_once(ev)
    await write_audit(
        db, "evidence_verify" if post_ok else "evidence_verify_failed",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id),
        outcome="success" if post_ok else "failure",
        details={
            "incident_id":         str(incident_id),
            "examination_session": str(session_id),
            "phase":               "post",
            "sha256_recorded":     ev.sha256,
            "sha256_recomputed":   post_hash,
        },
        ip_address=ip,
    )
    if not post_ok:
        if ev.status == "active":
            ev.status = "verify_failed"
        await db.commit()
        return ExamSessionResult(
            ok=False, session_id=session_id,
            pre_verify_sha256=pre_hash, post_verify_sha256=post_hash,
            message="Post-examination integrity check FAILED — evidence frozen; the examination is recorded but the tool may have modified the artefact.",
        )

    await db.commit()
    return ExamSessionResult(
        ok=True, session_id=session_id,
        pre_verify_sha256=pre_hash, post_verify_sha256=post_hash,
        message="Examination session complete — integrity verified before and after.",
    )


# ─── Provenance score (mirrors SOP autoCheck server-side) ────────────────
@router.get(
    "/{incident_id}/evidence/{evidence_id}/provenance",
    response_model=ProvenanceScore,
    summary="Score evidence provenance",
)
async def evidence_provenance(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    user: User = Depends(current_user),
    db:   AsyncSession = Depends(get_db),
) -> ProvenanceScore:
    """Compute a server-side provenance/defensibility score for an evidence item
    from its acquisition metadata, verified-working-copy presence and
    examination documentation flags. Requires access to the incident. Returns
    the provenance score breakdown."""
    await _get_incident(db, incident_id, user)
    ev = await _get_evidence(db, incident_id, evidence_id)
    ev.has_verified_working_copy = bool(await _verified_copy_ids(db, [ev.id]))
    _apply_exam_flags(ev, await _examination_flags(db, [ev.id]))
    return ProvenanceScore(**score_evidence(ev))


# ─── Working copies (ISO/IEC 27037 §7.1.3.1.1 ledger, Slice C) ───────────────
@router.get(
    "/{incident_id}/evidence/{evidence_id}/working-copies",
    response_model=EvidenceCopyList,
    summary="List working copies of evidence",
)
async def list_working_copies(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    user: User = Depends(current_user),
    db:   AsyncSession = Depends(get_db),
) -> EvidenceCopyList:
    """List the working-copy ledger entries (ISO/IEC 27037 §7.1.3.1.1) for an
    evidence item, newest first — each records the copy's hash, whether it was
    verified against the master, who made it, and its purpose. Requires access
    to the incident."""
    await _get_incident(db, incident_id, user)
    await _get_evidence(db, incident_id, evidence_id)
    rows = (await db.execute(
        select(EvidenceCopy)
        .where(EvidenceCopy.evidence_id == evidence_id)
        .order_by(EvidenceCopy.created_at.desc())
    )).scalars().all()
    return EvidenceCopyList(items=[EvidenceCopyOut.model_validate(r) for r in rows])


@router.post(
    "/{incident_id}/evidence/{evidence_id}/working-copy",
    response_model=EvidenceCopyOut,
    status_code=status.HTTP_201_CREATED,
    summary="Mint a working copy of evidence",
)
async def mint_working_copy(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    req:     WorkingCopyCreate,
    request: Request,
    user:    User = Depends(require_analyst),
    db:      AsyncSession = Depends(get_db),
) -> EvidenceCopyOut:
    """Record an out-of-band working copy in the ledger. Re-hashes the master to
    verify integrity at mint time (digital-file only); the master is never
    modified or handed out as the master. Requires analyst role, an open
    incident, and internal custody. Returns the created working-copy record (201)."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    ev = await _get_evidence(db, incident_id, evidence_id)
    if ev.kind != "digital_file":
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Working copies apply to digital evidence (the hashable master blob)")
    _block_if_external(ev, "mint a working copy of")

    ok, computed = await _verify_once(ev)
    copy = EvidenceCopy(
        id=uuid.uuid4(), evidence_id=ev.id, role="working",
        sha256=(computed or ev.sha256), verified_against_master=ok,
        created_by_id=user.id, created_by_qualifications=user.qualifications,
        purpose=req.purpose,
    )
    db.add(copy)
    await db.flush()
    await write_audit(
        db, "evidence_copy_mint",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id),
        outcome="success" if ok else "failure",
        details={
            "incident_id": str(incident_id),
            "copy_id":     str(copy.id),
            "sha256":      copy.sha256,
            "verified_against_master": ok,
            "purpose":     req.purpose,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return EvidenceCopyOut.model_validate(copy)


# ─── Exports (Phase 2 legal handoff) ─────────────────────────────────────────

def _to_export_out(exp: CustodyExport) -> ExportOut:
    out = ExportOut.model_validate(exp)
    # Apply expiry overlay so the UI always sees a fresh status.
    out.status = effective_status(exp)
    return out


@router.post(
    "/{incident_id}/evidence/exports",
    response_model=ExportCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a custody export bundle",
)
async def create_export(
    incident_id: uuid.UUID,
    req:     ExportCreate,
    request: Request,
    user:    User = Depends(require_admin),
    db:      AsyncSession = Depends(get_db),
) -> ExportCreateResponse:
    """Build an AES-256-GCM-encrypted custody export bundle for the chosen
    evidence items (`item_ids`), addressed to a recipient with a stated purpose
    and acknowledgments. Admin only; all items must belong to the incident. Each
    exported item also mints a verified working-copy ledger row. Returns the
    export record together with the one-time download URL/token, the AES key
    (shown once, delivered out-of-band) and the bundle SHA-256."""
    inc = await _get_incident(db, incident_id, user)

    # Resolve items, scoped to this incident.
    if not req.item_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Pick at least one item")
    q = await db.execute(
        select(Evidence)
        .where(Evidence.incident_id == incident_id,
               Evidence.id.in_(req.item_ids))
    )
    items = q.scalars().all()
    missing = set(map(str, req.item_ids)) - {str(i.id) for i in items}
    if missing:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"Evidence not found in this incident: {sorted(missing)}",
        )

    export, key_hex, download_url = await build_bundle(
        db, inc, items, user,
        recipient=req.recipient,
        purpose=req.purpose,
        acknowledgments=req.acknowledgments,
    )

    # Audit one event per included item plus an overall export event.
    # Each exported item also mints a tracked working-copy ledger row (Slice C):
    # the bytes in the bundle are the master plaintext, so verified_against_master.
    for ev in items:
        await write_audit(
            db, "evidence_export",
            user_id=user.id, username=user.username,
            resource_type="evidence", resource_id=str(ev.id),
            outcome="success",
            details={
                "incident_id":   str(incident_id),
                "export_id":     str(export.id),
                "recipient":     req.recipient,
                "bundle_sha256": export.bundle_sha256,
                "key_hint":      export.key_hint,
            },
            ip_address=request.client.host if request.client else None,
        )
        copy = EvidenceCopy(
            id=uuid.uuid4(), evidence_id=ev.id, role="working",
            sha256=ev.sha256, verified_against_master=True,
            created_by_id=user.id, created_by_qualifications=user.qualifications,
            purpose=f"Export to {req.recipient}: {req.purpose}",
            export_id=export.id,
        )
        db.add(copy)
        await write_audit(
            db, "evidence_copy_mint",
            user_id=user.id, username=user.username,
            resource_type="evidence", resource_id=str(ev.id),
            outcome="success",
            details={
                "incident_id": str(incident_id),
                "export_id":   str(export.id),
                "sha256":      ev.sha256,
                "verified_against_master": True,
                "purpose":     f"Export to {req.recipient}",
            },
            ip_address=request.client.host if request.client else None,
        )
    await write_audit(
        db, "evidence_export_create",
        user_id=user.id, username=user.username,
        resource_type="custody_export", resource_id=str(export.id),
        outcome="success",
        details={
            "incident_id":   str(incident_id),
            "recipient":     req.recipient,
            "purpose":       req.purpose,
            "item_count":    len(items),
            "bundle_sha256": export.bundle_sha256,
            "expires_at":    export.expires_at.isoformat(),
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    return ExportCreateResponse(
        export=_to_export_out(export),
        key=key_hex,
        download_url=download_url,
        bundle_sha256=export.bundle_sha256,
    )


# ─── Custody log (filtered audit chain for one item) ─────────────────────────

@router.get(
    "/{incident_id}/evidence/{evidence_id}/custody",
    response_model=list[CustodyEventOut],
    summary="Get an item's custody timeline",
)
async def custody_log(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> list[CustodyEventOut]:
    """Get the per-item custody timeline — all audit events for one evidence
    item, oldest first, drawn from the hash-chained audit log with each event's
    `hash`/`prev_hash`. Requires access to the incident."""
    await _get_incident(db, incident_id, user)
    await _get_evidence(db, incident_id, evidence_id)

    q = await db.execute(
        select(AuditLog)
        .where(
            AuditLog.resource_type == "evidence",
            AuditLog.resource_id   == str(evidence_id),
        )
        .order_by(AuditLog.timestamp.asc(), AuditLog.id.asc())
    )
    rows = q.scalars().all()
    return [_audit_to_custody_event(row) for row in rows]
