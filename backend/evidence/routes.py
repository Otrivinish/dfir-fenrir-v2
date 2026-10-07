"""Per-incident evidence endpoints (chain of custody).

Mounted at `/api/incidents` alongside incidents/iocs/entities routers.

Vocabulary follows 800-61 R3 / ISO 27037 ("evidence", "chain of custody").
Custody events land in the existing hash-chained audit log; this router's
Evidence row holds *current state* only (custodian, status, hashes). The
authoritative history is the audit chain.

Phase 1 endpoints (this slice):
- POST   /{id}/evidence/digital        — multipart upload, AES-256-GCM at rest (deprecated, R80: the
                                         chunked upload sessions in evidence/uploads.py replace it)
- POST   /{id}/evidence/physical       — physical item registration
- GET    /{id}/evidence                — list, cursor pagination
- GET    /{id}/evidence/{eid}          — detail
- PATCH  /{id}/evidence/{eid}          — descriptive fields only
- POST   /{id}/evidence/{eid}/transfer — request a custody transfer (internal, C4) or
                                         hand over to an external party
- POST   /{id}/evidence/{eid}/transfer/accept  — recipient accepts (custody changes) (C4)
- POST   /{id}/evidence/{eid}/transfer/decline — recipient declines / requester or admin cancels (C4)
- POST   /{id}/evidence/{eid}/examine  — record analysis action
- POST   /{id}/evidence/{eid}/verify   — recompute hash, compare to recorded
- POST   /{id}/evidence/{eid}/dispose  — destroy / return / archive
- GET    /{id}/evidence/{eid}/custody  — per-item custody timeline (filtered audit chain)
- GET    /{id}/evidence/{eid}/working-copies            — working copies (G5: own hashes, status)
- POST   /{id}/evidence/{eid}/working-copies            — issue a working copy to download (G5)
- GET    /{id}/evidence/{eid}/working-copies/{cid}/download?token= — its one-time download (G5)
- POST   /{id}/evidence/{eid}/working-copy              — record a lab copy with its own hash (G5)
- PUT    /{id}/evidence/{eid}/legal-hold                — set / release a legal hold (G5)

Phase 2 (next slice): /exports, /download/{token}
Phase 3 (polish): PDF CoC generator, chain verifier endpoint.
"""
import asyncio
import base64
import io
import json
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Optional

from fastapi import (APIRouter, Depends, File, Form, HTTPException, Query,
                     Request, Response, UploadFile, status)
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_admin, require_analyst
from core.config import settings
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from incidents.access import (LeadAccess, accessible_filter, get_accessible_incident, is_incident_lead,
                              not_incident_lead, require_incident_lead, require_incident_person)
from models import (AuditLog, BrowserHistoryUpload, CustodyExport, DefenderPdfImport, Entity, Evidence,
                    EvidenceCopy, ForensicImport, Incident, PCAPAnalysis, User, utcnow)
from audit.service import verify_row_hash
from schemas import (ChainVerifyResult, CustodyEventOut, DisposeRequest, EvidenceAcquisitionRecord,
                     EvidenceCopyList, EvidenceCopyOut, EvidenceList,
                     EvidenceOut, EvidenceSealRequest,
                     EvidenceUpdate, ExamineRequest, ExportCreate,
                     ExportCreateResponse, ExportList, ExportOut, LegalHoldChange,
                     PhysicalEvidenceCreate, ProvenanceScore, TIME_OFFSET_DESCRIPTION,
                     TIME_OFFSET_MAX_SECONDS, Tlp,
                     TransferAcceptRequest, TransferDeclineRequest,
                     TransferRequest, VerifyResult, WorkingCopyCreate, WorkingCopyIssue,
                     WorkingCopyIssued)
from evidence import codec
from evidence import working_copies as wcs
from evidence.provenance import score_evidence
from notifications.service import notify_custody_transfer, notify_custody_transfer_outcome, notify_disclosure_built

from evidence.crypto import (EvidenceCryptoError, EvidenceIntegrityError, StoredFile, adelete_encrypted,
                             asha256_decrypted, awrite_encrypted, write_encrypted_stream)
from evidence.exports import BUILDING as export_building
from evidence.exports import (EXPORT_MAX_PLAINTEXT_BYTES, ExhibitIntegrityError, _build_staged, effective_status,
                              is_unsealed_draft, plan_bundle)
from evidence.streaming import decrypted_download, require_free_space
from evidence.hashing import hash_algorithm
from evidence.timestamping import timestamp_sha256

router = APIRouter()

# G2 / G-fix (R80): the deprecated multipart routes (POST …/evidence/digital and …/photos) are capped at
# 512 MiB even when evidence_max_upload_bytes is higher. Starlette spools a multipart body to the backend's
# memory-only tmpfs (/run/fenrir-parse, 1 GiB, shared with every other multipart upload and parse; main.py),
# and the photo route reads the whole file into memory; only the chunked upload sessions
# (evidence/uploads.py) take files up to evidence_max_upload_bytes.
LEGACY_MULTIPART_MAX_BYTES = 512 * 1024 * 1024


def multipart_max_bytes() -> int:
    return min(settings.evidence_max_upload_bytes, LEGACY_MULTIPART_MAX_BYTES)


# Cursor helpers — mirror incidents/iocs/entities patterns.
# L11, accepted: a row deleted between two page reads makes an offset cursor skip one row; the war room pages by keyset.
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


async def _get_evidence(db: AsyncSession, incident_id: uuid.UUID, evidence_id: uuid.UUID,
                        *, for_update: bool = False) -> Evidence:
    """for_update=True locks the row (SELECT … FOR UPDATE) until the transaction ends — C4
    check-then-write paths on the pending transfer (transfer, accept, decline, dispose, seal)."""
    stmt = select(Evidence).where(Evidence.id == evidence_id, Evidence.incident_id == incident_id)
    if for_update:
        stmt = stmt.with_for_update(of=Evidence).execution_options(populate_existing=True)
    ev = (await db.execute(stmt)).scalar_one_or_none()
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


# ─── C3 intake integrity helpers ─────────────────────────────────────────────
# acquired_at may be at most this far ahead of the server clock (client skew).
ACQUIRED_AT_SKEW = timedelta(minutes=2)
_ALGORITHM_LABEL = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}


class _UploadRefused(Exception):
    """Raised by the intake check on a staged upload (G1 stage 3a); the staging file is then
    deleted, so nothing is stored. `why` = too_large | hash_mismatch."""

    def __init__(self, why: str, stored: StoredFile):
        super().__init__(why)
        self.why, self.stored = why, stored


def _check_acquired_at(acquired_at: Optional[datetime]) -> Optional[datetime]:
    """Naive = UTC; returned in UTC. 422 code acquired_in_future when later than
    now + ACQUIRED_AT_SKEW."""
    if acquired_at is None:
        return None
    if acquired_at.tzinfo is None:
        acquired_at = acquired_at.replace(tzinfo=timezone.utc)
    acquired_at = acquired_at.astimezone(timezone.utc)
    if acquired_at > utcnow() + ACQUIRED_AT_SKEW:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "acquired_in_future",
                       "acquired_at cannot be in the future")
    return acquired_at


def _normalise_hash(value: Optional[str], field: str) -> Optional[str]:
    """Lower-cased hex, or None when blank. 422 code invalid_hash_format unless it is
    32 (MD5), 40 (SHA-1) or 64 (SHA-256) hex characters."""
    value = (value or "").strip().lower()
    if not value:
        return None
    if hash_algorithm(value) is None:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_hash_format",
                       f"{field} must be 32 (MD5), 40 (SHA-1) or 64 (SHA-256) hex characters")
    return value


def _comparable_hashes(source: Optional[str], target: Optional[str]) -> bool:
    """Source and target can be compared only when both use the same algorithm."""
    return bool(source and target) and hash_algorithm(source) == hash_algorithm(target)


# ─── Digital intake, shared by the multipart route and the chunked upload (G1 stage 3b) ──────

@dataclass(frozen=True)
class DigitalIntake:
    """collect_digital's C3 inputs, checked: acquired_at (UTC), the normalised source / target
    hashes and whether the target is compared with the uploaded bytes."""
    acquired_at:       Optional[datetime]
    hash_source:       Optional[str]
    hash_target:       Optional[str]
    target_hash_scope: str

    @property
    def target_algo(self) -> Optional[str]:
        return hash_algorithm(self.hash_target)

    @property
    def compare_target(self) -> bool:
        return bool(self.hash_target) and self.target_hash_scope != "container_media"

    @property
    def upload_hash_check(self) -> str:
        if not self.hash_target:
            return "not_checked"
        return "container_media" if self.target_hash_scope == "container_media" else "match"

    def check(self, stored: StoredFile, cap: Optional[int] = None) -> None:
        """The intake check on the complete staged file, before it is moved into place. `cap` defaults
        to evidence_max_upload_bytes (the upload sessions); the multipart route passes its own."""
        if stored.size > (settings.evidence_max_upload_bytes if cap is None else cap):
            raise _UploadRefused("too_large", stored)
        if self.compare_target and getattr(stored, self.target_algo) != self.hash_target:
            raise _UploadRefused("hash_mismatch", stored)


def digital_intake(acquired_at: Optional[datetime], acquisition_hash_source: Optional[str],
                   acquisition_hash_target: Optional[str], target_hash_scope: str) -> DigitalIntake:
    """422 acquired_in_future / invalid_hash_format, before anything is stored."""
    acquired_at = _check_acquired_at(acquired_at)
    hash_source = _normalise_hash(acquisition_hash_source, "acquisition_hash_source")
    hash_target = _normalise_hash(acquisition_hash_target, "acquisition_hash_target")
    return DigitalIntake(acquired_at, hash_source, hash_target, target_hash_scope)


async def audit_collect_rejected(db: AsyncSession, request: Request, user: User, incident_id: uuid.UUID, *,
                                 identifier: str, name: str, original_filename: Optional[str],
                                 intake: DigitalIntake, refused: "_UploadRefused",
                                 extra: Optional[dict] = None) -> ApiError:
    """C3: audit a refused target hash (`evidence_collect_rejected`, no file content); returns the
    422 hash_mismatch to raise. The caller commits."""
    target_algo = intake.target_algo
    computed = getattr(refused.stored, target_algo)
    label = _ALGORITHM_LABEL[target_algo]
    await write_audit(
        db, "evidence_collect_rejected",
        user_id=user.id, username=user.username,
        resource_type="evidence", outcome="failure",
        details={
            "incident_id": str(incident_id),
            "kind": "digital_file",
            "identifier": identifier,
            "name": name,
            "original_filename": original_filename,
            "file_size_bytes": refused.stored.size,
            "reason": "hash_mismatch",
            "algorithm": target_algo,
            "acquisition_hash_target": intake.hash_target,
            "computed_hash": computed,
            **(extra or {}),
        },
        ip_address=request.client.host if request.client else None,
    )
    return ApiError(
        status.HTTP_422_UNPROCESSABLE_CONTENT, "hash_mismatch",
        f"The target hash ({label}) does not match the uploaded file, whose {label} is "
        f"{computed}. Nothing was stored. If the hash covers an E01/AFF4 container's "
        f"media rather than this file, set target_hash_scope=container_media.",
    )


async def create_digital_evidence(
    db: AsyncSession, request: Request, user: User, incident_id: uuid.UUID, *, evidence_id: uuid.UUID,
    stored: StoredFile, original_filename: Optional[str], mime_type: Optional[str], intake: DigitalIntake,
    fields: dict, audit_extra: Optional[dict] = None,
) -> Evidence:
    """The digital exhibit row + its `evidence_collect` audit for a file already stored at
    `stored.relative_path`. `fields` = the descriptive / acquisition columns (name, identifier, …;
    witness_user_id and entity_id already resolved). An identifier that already exists → the stored
    file is deleted and 409 identifier_exists. Flushes and audits; the caller commits."""
    ev = Evidence(
        id=evidence_id,
        incident_id=incident_id,
        kind="digital_file",
        status="active",
        original_filename=original_filename,
        storage_path=stored.relative_path,
        file_size_bytes=stored.size,
        mime_type=mime_type,
        sha256=stored.sha256, sha1=stored.sha1, md5=stored.md5,
        nonce_hex=stored.nonce_hex,
        current_custodian_id=user.id,
        collected_by_id=user.id,
        collected_at=utcnow(),
        acquisition_hash_source=intake.hash_source,
        acquisition_hash_target=intake.hash_target,
        acquired_at=intake.acquired_at,
        upload_hash_check=intake.upload_hash_check,
        collected_by_qualifications=user.qualifications,
        **fields,
    )
    db.add(ev)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        await adelete_encrypted(stored.relative_path)
        raise ApiError(status.HTTP_409_CONFLICT, "identifier_exists",
                       "Evidence identifier already exists on this incident")

    await write_audit(
        db, "evidence_collect",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id),
        details={
            "incident_id": str(incident_id),
            "kind": "digital_file",
            "identifier": ev.identifier,
            "name": ev.name,
            "sha256": stored.sha256,
            "file_size_bytes": stored.size,
            "tlp": ev.tlp,
            "collected_location": ev.collected_location,
            "acquired_at": _utc_z(intake.acquired_at),
            "upload_hash_check": intake.upload_hash_check,
            "target_hash_algorithm": intake.target_algo,
            "system_time_offset_seconds": ev.system_time_offset_seconds,
            **(audit_extra or {}),
        },
        ip_address=request.client.host if request.client else None,
    )
    return ev


async def _verified_copy_ids(db: AsyncSession, evidence_ids: list, exclude_copy_ids: set = frozenset()) -> set:
    """Evidence ids that have ≥1 non-discarded, master-verified working copy
    (ISO/IEC 27037 §7.1.3.1.1). Grouped query — avoids an async lazy-load of a
    copies relationship on freshly-created Evidence objects (Slice D). `exclude_copy_ids`:
    copies a correction note says not to count (L10). G5 (R08): the copy's own hash must have
    matched — a complete download, a verified lab copy or an export copy; a pre-G5 "Record copy"
    row (its hash a re-hash of the master) or a copy an examination found altered never counts."""
    if not evidence_ids:
        return set()
    stmt = select(EvidenceCopy.evidence_id).where(
        EvidenceCopy.evidence_id.in_(evidence_ids),
        EvidenceCopy.verified_against_master.is_(True),
        EvidenceCopy.discarded_at.is_(None),
        EvidenceCopy.altered_at.is_(None),
        or_(EvidenceCopy.export_id.is_not(None),
            (EvidenceCopy.kind == "download") & (EvidenceCopy.status == "complete"),
            (EvidenceCopy.kind == "lab_copy") & (EvidenceCopy.status == "verified")),
    )
    if exclude_copy_ids:
        stmt = stmt.where(EvidenceCopy.id.notin_([uuid.UUID(c) for c in exclude_copy_ids]))
    rows = (await db.execute(stmt)).scalars().all()
    return set(rows)


async def _corrected_copy_ids(db: AsyncSession, evidence_id: uuid.UUID) -> set:
    """L10: ids of this item's working copies that an append-only `evidence_copy_correction`
    audit row marks as wrongly recorded verified_against_master (an export minted them although
    the item's bytes were not in the bundle). The copy rows themselves are never rewritten."""
    rows = (await db.execute(
        select(AuditLog.details).where(
            AuditLog.resource_type == "evidence",
            AuditLog.action == "evidence_copy_correction",
            AuditLog.resource_id == str(evidence_id),
        )
    )).scalars().all()
    return {str(d["copy_id"]) for d in rows if isinstance(d, dict) and d.get("copy_id")}


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


async def _transfer_ack_counts(db: AsyncSession, evidence_ids: list) -> dict:
    """C4 — per-evidence internal custody changes from the evidence_transfer audit rows:
    {str(evidence_id): [acknowledged, legacy]}. Since C4 every internal custody change is
    written by the recipient (accept, or a return from external custody) with
    `acknowledged: true`; rows without the key predate recipient acceptance. Transfers to an
    external party are not counted. Grouped query, like _examination_flags."""
    if not evidence_ids:
        return {}
    rows = (await db.execute(
        select(AuditLog.resource_id, AuditLog.details).where(
            AuditLog.resource_type == "evidence",
            AuditLog.action == "evidence_transfer",
            AuditLog.resource_id.in_([str(i) for i in evidence_ids]),
        )
    )).all()
    counts: dict = {}
    for rid, details in rows:
        d = details or {}
        if not d.get("to_user_id"):
            continue
        c = counts.setdefault(rid, [0, 0])
        if "acknowledged" not in d:
            c[1] += 1
        elif d["acknowledged"] is True:
            c[0] += 1
    return counts


def _apply_transfer_counts(ev: Evidence, counts: dict) -> None:
    c = counts.get(str(ev.id))
    if c:
        ev.internal_transfers_acknowledged, ev.internal_transfers_legacy = c


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
    transfers   = await _transfer_ack_counts(db, ids)
    for r in page:
        r.has_verified_working_copy = r.id in verified
        _apply_exam_flags(r, exam_flags)
        _apply_transfer_counts(r, transfers)
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
        user_agent=row.user_agent,
        created_at=row.timestamp,
        hash=row.row_hash,
        prev_hash=row.prev_hash,
    )


# Email / browser-history mints audited under their own action before C3 (now evidence_collect).
_LEGACY_MINT_ACTIONS = ("email_mint_evidence", "webhistory_mint_evidence")


async def _incident_evidence_events(db: AsyncSession, incident_id: uuid.UUID) -> list[AuditLog]:
    """All evidence_* audit rows for this incident (plus legacy mint rows), oldest first."""
    q = await db.execute(
        select(AuditLog)
        .where(
            or_(AuditLog.action.like("evidence_%"), AuditLog.action.in_(_LEGACY_MINT_ACTIONS)),
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
    """Global custody timeline — every evidence_* event for this incident
    (plus legacy `email_mint_evidence` / `webhistory_mint_evidence` rows),
    oldest first. Drawn from the hash-chained audit log (the authoritative
    custody history), so each event carries its `hash`/`prev_hash`. An event about an exhibit
    (resource_type evidence) also carries `exhibit_identifier` and `exhibit_name` (K1). Requires
    access to the incident."""
    await _get_incident(db, incident_id, user)
    rows = await _incident_evidence_events(db, incident_id)
    # K1 (R37): name each event's exhibit by its identifier (and name), not by a truncated id.
    exhibits = {str(i): (ident, name) for i, ident, name in (await db.execute(
        select(Evidence.id, Evidence.identifier, Evidence.name).where(Evidence.incident_id == incident_id))).all()}
    out = []
    for r in rows:
        ev = _audit_to_custody_event(r)
        if r.resource_type == "evidence" and r.resource_id in exhibits:
            ev.exhibit_identifier, ev.exhibit_name = exhibits[r.resource_id]
        out.append(ev)
    return out


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
    summary="List custody export bundles (deprecated: GET …/disclosures)",
    deprecated=True,
    responses={403: {"model": ApiErrorBody, "description": "not_incident_lead"}},
)
async def list_exports(
    incident_id: uuid.UUID,
    lead: LeadAccess = Depends(require_incident_lead),
    db: AsyncSession = Depends(get_db),
    limit:  int           = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
) -> ExportList:
    """List the custody export bundles created for an incident, newest first
    (cursor-paginated). K1: incident lead or admin (403 not_incident_lead), as disclosure packages; every
    disclosure package's download row is listed here too. Each item's status reflects expiry/consumed
    overlay; secrets (download token, AES key) are never returned here. **Deprecated (K1):** use GET
    …/disclosures."""
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
    summary="Get a custody export bundle (deprecated: GET …/disclosures/{id})",
    deprecated=True,
    responses={403: {"model": ApiErrorBody, "description": "not_incident_lead"}},
)
async def get_export(
    incident_id: uuid.UUID,
    export_id:   uuid.UUID,
    lead: LeadAccess = Depends(require_incident_lead),
    db: AsyncSession = Depends(get_db),
) -> ExportOut:
    """Get one custody export bundle's metadata by id, scoped to the incident.
    K1: incident lead or admin (403 not_incident_lead). Returns the export record with an expiry-aware status;
    does not expose the one-time download token or encryption key. **Deprecated (K1).**"""
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
    hashes, acquisition metadata) by id within an incident, with the same derived
    flags as the list (verified working copy, examination documentation, internal
    transfers acknowledged / legacy). Requires access to the incident. Returns 404
    if the item is not part of this incident."""
    await _get_incident(db, incident_id, user)
    ev = await _get_evidence(db, incident_id, evidence_id)
    # K5 (R49): the list's derived flags, so GET agrees with the list.
    ev.has_verified_working_copy = bool(await _verified_copy_ids(db, [ev.id]))
    _apply_exam_flags(ev, await _examination_flags(db, [ev.id]))
    _apply_transfer_counts(ev, await _transfer_ack_counts(db, [ev.id]))
    return _to_out(ev)


# ─── Collect (digital_file) — multipart upload ───────────────────────────────

@router.post(
    "/{incident_id}/evidence/digital",
    response_model=EvidenceOut,
    status_code=status.HTTP_201_CREATED,
    summary="Collect digital file evidence (multipart; deprecated: use the upload session API)",
    deprecated=True,
    responses={404: {"model": ApiErrorBody, "description": "user_not_found (unknown witness_user_id)"},
               409: {"model": ApiErrorBody, "description": "identifier_exists (nothing stored)"},
               422: {"model": ApiErrorBody,
                     "description": "hash_mismatch (nothing stored), invalid_hash_format, acquired_in_future or "
                                    "assignee_no_access (witness deactivated or can't see the incident)"},
               507: {"model": ApiErrorBody, "description": "insufficient_storage (the evidence volume, with its 1 GiB reserve, or the upload scratch space is full; nothing stored)"}},
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
    system_time_offset_seconds: Optional[int] = Form(default=None, ge=-TIME_OFFSET_MAX_SECONDS,
                                                     le=TIME_OFFSET_MAX_SECONDS,
                                                     description=TIME_OFFSET_DESCRIPTION),
    screen_state:              Optional[str]  = Form(default=None),
    changes_made:              Optional[str]  = Form(default=None),
    device_details:            Optional[str]  = Form(default=None),  # JSON object
    # ── ISO/IEC 27041 — method/tool validation (Slice B) ──────────────────
    acquisition_tool_validated:       Optional[bool] = Form(default=None),
    acquisition_tool_validation_ref:  Optional[str]  = Form(default=None),
    acquisition_tool_validation_date: Optional[str]  = Form(default=None),
    # ── C3 — intake integrity ─────────────────────────────────────────────
    acquired_at:       Optional[datetime] = Form(default=None),
    target_hash_scope: Literal["uploaded_file", "container_media"] = Form(default="uploaded_file"),
    user:               User          = Depends(require_analyst),
    db:                 AsyncSession  = Depends(get_db),
) -> EvidenceOut:
    """Deprecated (G1 stage 3b, R80): the whole multipart body is held by the server in its
    memory-only scratch space (tmpfs, 1 GiB shared by every upload and parse; 507
    insufficient_storage when full) before this route sees it. Use the upload session API
    instead — POST …/uploads (purpose=evidence), PUT the chunks, then POST
    …/uploads/{upload_id}/complete with these same fields as JSON — which encrypts every
    chunk as it arrives. Kept for API compatibility, and capped at 512 MiB (413) whatever
    EVIDENCE_MAX_UPLOAD_BYTES says: larger files only through the upload sessions (G2).

    Collect a digital file as evidence via multipart upload. The file is
    streamed once to compute SHA-256/SHA-1/MD5 and is stored encrypted at rest
    with AES-256-GCM. Accepts extensive
    optional ISO/IEC 27037/27041 acquisition metadata (tool, write-blocker,
    lawful basis, witness, device details) as form fields.

    Intake integrity: `acquisition_hash_source` / `acquisition_hash_target` are MD5,
    SHA-1 or SHA-256 hex (algorithm inferred from length 32/40/64, else 422
    `invalid_hash_format`). With `target_hash_scope=uploaded_file` (default) the
    target hash is compared with the server's hash of the uploaded bytes (same
    algorithm) BEFORE anything is stored: a mismatch returns 422 `hash_mismatch`,
    writes an `evidence_collect_rejected` audit row and stores nothing. Use
    `container_media` when the hash covers an E01/AFF4 container's media rather
    than the file itself; it is recorded as advisory, not compared. The result
    is `upload_hash_check`. `acquired_at` = when the image was taken (UTC, not in
    the future, else 422 `acquired_in_future`); `collected_at` stays the
    registration time. A `witness_user_id` must be an active user who can see the
    incident (404 `user_not_found`, 422 `assignee_no_access`), checked before the
    upload is read. Requires analyst role and an open incident; the caller
    becomes collector and custodian. Returns the created evidence record (201)."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    # Optional witness (F2: an active user who can see the incident), checked before anything is stored.
    witness_uid = None
    if witness_user_id:
        try:
            witness_uid = uuid.UUID(witness_user_id)
        except ValueError:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid witness_user_id format")
        await require_incident_person(db, incident_id, witness_uid, "the witness")
    resolved_entity_id = await _resolve_entity(db, incident_id, entity_id)
    device_types_list    = _json_list(device_types, "device_types")
    decision_factors_obj = _json_object(decision_factors, "decision_factors")
    device_details_obj   = _json_object(device_details, "device_details")
    intake = digital_intake(acquired_at, acquisition_hash_source, acquisition_hash_target, target_hash_scope)

    # Early reject on Content-Length if available — saves bandwidth.
    cap = multipart_max_bytes()
    cl = request.headers.get("content-length")
    if cl and int(cl) > cap:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"Upload exceeds max {cap} bytes",
        )

    if (file.size or 0) > cap:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"Upload exceeds max {cap} bytes",
        )

    require_free_space(codec.container_size(file.size or 0), "this exhibit")   # L2: 507 before anything is written
    evidence_id   = uuid.uuid4()
    relative_path = _storage_path_for(incident_id, evidence_id, file.filename or "unnamed.bin")

    # One pass (G1 stage 3a, spec §4.4): SHA-256/SHA-1/MD5 and AES-256-GCM (FENRGCM v2) into a
    # staging file. C3 compares the typed target hash with the uploaded bytes BEFORE the file is
    # moved into place; on a mismatch the staging file is deleted (nothing is stored), and the
    # refusal is audited (no file content).
    try:
        stored = await write_encrypted_stream(file.file, relative_path,
                                              accept=lambda st: intake.check(st, cap=cap))
    except _UploadRefused as refused:
        if refused.why == "too_large":
            raise HTTPException(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                f"Upload exceeds max {cap} bytes",
            )
        err = await audit_collect_rejected(db, request, user, incident_id, identifier=identifier, name=name,
                                           original_filename=file.filename, intake=intake, refused=refused)
        await db.commit()
        raise err

    ev = await create_digital_evidence(
        db, request, user, incident_id, evidence_id=evidence_id, stored=stored,
        original_filename=file.filename, mime_type=file.content_type, intake=intake,
        fields=dict(
            name=name,
            identifier=identifier,
            description=description,
            tlp=tlp,
            entity_id=resolved_entity_id,
            collected_as_role=(collected_as_role if collected_as_role in ("defr", "des") else None),
            collected_location=collected_location,
            # Wizard A — only persisted if the caller supplied them
            lawful_basis=lawful_basis,
            lawful_basis_note=lawful_basis_note,
            acquisition_tool=acquisition_tool,
            acquisition_tool_version=acquisition_tool_version,
            acquisition_tool_sha256=(acquisition_tool_sha256.lower() if acquisition_tool_sha256 else None),
            acquisition_params=acquisition_params,
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
            system_time_offset_seconds=system_time_offset_seconds,
            screen_state=screen_state,
            changes_made=changes_made,
            device_details=device_details_obj,
            # ISO/IEC 27041 — method/tool validation + collector competence (Slice B)
            acquisition_tool_validated=acquisition_tool_validated,
            acquisition_tool_validation_ref=acquisition_tool_validation_ref,
            acquisition_tool_validation_date=acquisition_tool_validation_date,
        ),
    )
    await db.commit()
    return _to_out(ev)


# ─── Collect (physical_item) — JSON ──────────────────────────────────────────

@router.post(
    "/{incident_id}/evidence/physical",
    response_model=EvidenceOut,
    status_code=status.HTTP_201_CREATED,
    summary="Collect physical item evidence",
    responses={404: {"model": ApiErrorBody, "description": "user_not_found (unknown witness_user_id)"},
               422: {"model": ApiErrorBody, "description": "acquired_in_future, or assignee_no_access (witness "
                                                           "deactivated or can't see the incident)"}},
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
    optional ISO/IEC 27037 acquisition metadata. `acquired_at` = when the item
    was seized (UTC, not in the future, else 422 `acquired_in_future`). A
    `witness_user_id` must be an active user who can see the incident (404
    `user_not_found`, 422 `assignee_no_access`). Requires analyst role and an open
    incident; the caller becomes collector and custodian. Returns the created
    evidence record (201)."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    acquired_at = _check_acquired_at(req.acquired_at)
    resolved_entity_id = await _resolve_entity(db, incident_id, str(req.entity_id) if req.entity_id else None)

    # Wizard A — the witness, if given, must be an active user who can see the incident (F2).
    witness_uid = req.witness_user_id
    if witness_uid:
        await require_incident_person(db, incident_id, witness_uid, "the witness")

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
        acquired_at=acquired_at,
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
        system_time_offset_seconds=req.system_time_offset_seconds,
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
            "acquired_at": _utc_z(acquired_at),
            "system_time_offset_seconds": req.system_time_offset_seconds,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return _to_out(ev)


# ─── Update (descriptive fields) ─────────────────────────────────────────────

# R76 — after the seal these stay as recorded at collection: the photo list (a PATCH replaces it, so it
# could drop the in-situ photos the seal required; adding one with POST …/photos is still allowed) and
# the collector's DEFR / DES role (a fact of the collection, like the rest of the acquisition record,
# which PATCH …/acquisition-record refuses on a sealed item). The other fields here are descriptive or
# change over time; on a sealed item each change also writes evidence_amend_after_seal {field, from, to}.
SEALED_IMMUTABLE_FIELDS = ("photos", "collected_as_role")

# What a PATCH may change on an uploaded (encrypted-at-rest) photo (R101). Everything else on it is held by
# the server: storage_path, nonce_hex, sha256, size, mime_type, url, id.
_PHOTO_EDITABLE = ("caption", "taken_at")


def _merge_photos(current: list, sent: list) -> list:
    """R101 / FE-H1: the photo list a PATCH asks for, merged with the stored one by photo `id` — never rebuilt
    from what the client sent, so no server-held field (storage_path, nonce_hex, sha256, size, mime type) can
    be dropped. An uploaded photo (it has an id) keeps every stored field; only caption / taken_at change. A
    photo without an id is a reference-only entry (a URL or a caption, no stored file): those are replaced by
    the ones sent, as before. 422 unknown_photo_id for an id the item doesn't have; 422
    photo_remove_not_supported when an uploaded photo is left out (there is no audited photo-delete route;
    destroying the item removes its photos)."""
    stored = {str(p["id"]): p for p in current if isinstance(p, dict) and p.get("id")}
    seen: set[str] = set()
    out = []
    for ref in sent:
        if ref.id is None:
            out.append(ref.model_dump(mode="json", exclude={"id", "mime_type"}))
            continue
        pid = str(ref.id)
        if pid not in stored:
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "unknown_photo_id",
                           f"The item has no photo with id {pid!r}: nothing was changed. Add a photo with POST "
                           "…/photos.")
        if pid in seen:
            continue
        seen.add(pid)
        sent_fields = ref.model_dump(mode="json", include=set(_PHOTO_EDITABLE))
        out.append({**stored[pid], **sent_fields})
    missing = sorted(set(stored) - seen)
    if missing:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "photo_remove_not_supported",
                       f"An uploaded photo can't be removed with PATCH (left out: {', '.join(missing)}): send every "
                       "photo with its id. Nothing was changed.")
    return out


async def _check_offset_authority(db: AsyncSession, ev: Evidence, user: User, inc: Incident) -> None:
    """M10 / L6: the one rule set for recording an exhibit's clock offset or its acquisition record — its
    collector, its current custodian, the incident lead or an admin (403 not_collector_or_custodian); the
    item in internal custody (409 evidence_not_in_internal_custody) with no transfer pending (409
    transfer_pending)."""
    if ev.current_custodian_id is None:
        raise ApiError(status.HTTP_409_CONFLICT, "evidence_not_in_internal_custody",
                       "The item is not held by an internal custodian; transfer it back first")
    _block_if_transfer_pending(ev)
    if user.id not in (ev.collected_by_id, ev.current_custodian_id) and not await is_incident_lead(db, user, inc):
        raise ApiError(status.HTTP_403_FORBIDDEN, "not_collector_or_custodian",
                       "Only the item's collector, its current custodian, the incident lead or an admin can "
                       "record its acquisition facts (including the clock offset)")


@router.patch(
    "/{incident_id}/evidence/{evidence_id}",
    response_model=EvidenceOut,
    summary="Update evidence descriptive fields",
    responses={403: {"model": ApiErrorBody, "description": "not_collector_or_custodian (changing "
                                                           "system_time_offset_seconds: collector, custodian, "
                                                           "incident lead or admin only)"},
               409: {"model": ApiErrorBody, "description": "sealed_field_immutable (photos or collected_as_role "
                                                           "on a sealed item; nothing changed); changing "
                                                           "system_time_offset_seconds: evidence_not_in_internal_"
                                                           "custody or transfer_pending"},
               422: {"model": ApiErrorBody, "description": "use_legal_hold_endpoint (legal_hold sent; nothing "
                                                           "changed), unknown_photo_id or "
                                                           "photo_remove_not_supported (photos)"}},
)
async def update_evidence(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    req:     EvidenceUpdate,
    request: Request,
    user:    User = Depends(require_analyst),
    db:      AsyncSession = Depends(get_db),
) -> EvidenceOut:
    """Edit descriptive fields (name, description, TLP, physical location,
    condition, photos, collected-as role) — hashes, custodian and acquisition
    facts are immutable here, with one exception: `system_time_offset_seconds`
    (G4), the device clock offset as a number, can be set, corrected or cleared
    (explicit null). Its change is audited `{from, to}` with the number of imports
    of this exhibit that keep the offset they were parsed with. Imports and promoted timeline
    events are never rewritten: re-import from the exhibit to apply a new value.

    G5: `legal_hold` is not settable here (422 code use_legal_hold_endpoint; use PUT
    …/legal-hold). On a SEALED item (R76) `photos` and `collected_as_role` can't change (409 code
    sealed_field_immutable, nothing changed), and every other changed field also writes an
    `evidence_amend_after_seal` row `{field, from, to}` to the custody log.
    `photos` (R101) is merged with the stored list by photo `id`: an uploaded photo keeps its stored
    file and hashes, and only its caption / taken_at change; an entry without an id is a reference-only
    photo (URL / caption), and those are replaced by the ones sent. An unknown id is 422 unknown_photo_id;
    leaving an uploaded photo out is 422 photo_remove_not_supported (nothing changed).
    Changing `system_time_offset_seconds` follows the acquisition-record rules (M10): only the item's
    collector, its current custodian, the incident lead or an admin (403 not_collector_or_custodian), with
    the item in internal custody and no transfer pending (409).
    Requires analyst role and an open incident; the item must be active or
    verify_failed (disposed items reject). Only changed fields are audited.
    Returns the updated record."""
    if "legal_hold" in req.model_fields_set:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "use_legal_hold_endpoint",
                       "legal_hold can't be changed with PATCH …/evidence/{id}: use PUT "
                       "…/evidence/{id}/legal-hold with {\"legal_hold\": true|false, \"reason\": …}.")
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    ev = await _get_evidence(db, incident_id, evidence_id, for_update=True)
    if ev.status not in ("active", "verify_failed"):
        raise HTTPException(status.HTTP_409_CONFLICT, "Disposed evidence cannot be edited")
    if ev.coc_sealed:
        sent = [f for f in SEALED_IMMUTABLE_FIELDS
                if f in req.model_fields_set and getattr(req, f) is not None]
        if sent:
            raise ApiError(status.HTTP_409_CONFLICT, "sealed_field_immutable",
                           f"The item is sealed: {', '.join(sent)} can't change after the seal. Nothing was "
                           "changed. (Add a photo with POST …/photos.)")

    changed: dict[str, object] = {}
    amended: dict[str, dict] = {}       # R76: field → {from, to}

    def _set(field: str, value, before) -> None:
        amended[field] = {"from": before, "to": value}
        setattr(ev, field, value)
        changed[field] = value

    if req.name is not None and req.name != ev.name:
        _set("name", req.name, ev.name)
    if req.description is not None and req.description != (ev.description or ""):
        _set("description", req.description, ev.description)
    if req.tlp is not None and req.tlp != ev.tlp:
        _set("tlp", req.tlp, ev.tlp)
    if req.physical_location is not None and req.physical_location != (ev.physical_location or ""):
        _set("physical_location", req.physical_location, ev.physical_location)
    if req.condition is not None and req.condition != (ev.condition or ""):
        _set("condition", req.condition, ev.condition)
    if req.photos is not None:
        ev.photos = _merge_photos(list(ev.photos or []), req.photos)
        changed["photos_count"] = len(ev.photos)
    if req.collected_as_role is not None and req.collected_as_role != ev.collected_as_role:
        _set("collected_as_role", req.collected_as_role, ev.collected_as_role)
    offset_change = None
    if ("system_time_offset_seconds" in req.model_fields_set
            and req.system_time_offset_seconds != ev.system_time_offset_seconds):
        await _check_offset_authority(db, ev, user, inc)
        offset_change = {"from": ev.system_time_offset_seconds, "to": req.system_time_offset_seconds}
        amended["system_time_offset_seconds"] = offset_change
        ev.system_time_offset_seconds = req.system_time_offset_seconds
        changed["system_time_offset_seconds"] = offset_change

    if changed:
        details = {"incident_id": str(incident_id), "changes": changed}
        if offset_change is not None:
            # G4 — imports already made from this exhibit keep the offset they were parsed with.
            details["imports_keep_previous_offset"] = await _runs_with_offset(db, ev.id)
        await write_audit(
            db, "evidence_update",
            user_id=user.id, username=user.username,
            resource_type="evidence", resource_id=str(ev.id),
            details=details,
            ip_address=request.client.host if request.client else None,
        )
        if ev.coc_sealed:
            # R76 (G4 wrote this for the offset only): one row per changed field, with both values.
            for field, change in amended.items():
                await write_audit(
                    db, "evidence_amend_after_seal",
                    user_id=user.id, username=user.username,
                    resource_type="evidence", resource_id=str(ev.id),
                    details={"incident_id": str(incident_id), "field": field, **change},
                    ip_address=request.client.host if request.client else None,
                )
    await db.commit()
    return _to_out(ev)


async def _runs_with_offset(db: AsyncSession, evidence_id: uuid.UUID) -> int:
    """G4 / L21 (G-fix B): the runs of this exhibit that applied (or recorded) its clock offset when they ran —
    Timeline Imports, Defender imports, PCAP analyses and browser-history uploads. They keep that offset when
    it changes (re-import / re-analyse to apply the new one). Email analyses apply none (relay times)."""
    n = 0
    for model in (ForensicImport, DefenderPdfImport, PCAPAnalysis, BrowserHistoryUpload):
        n += (await db.execute(select(func.count()).select_from(model)
                               .where(model.evidence_id == evidence_id))).scalar_one()
    return n


# ─── G3: complete an unsealed item's acquisition record ──────────────────────
# A draft exhibit (registered by an Email / PCAP / Browser history upload) or a Quick add has no
# acquisition record, so it could never be sealed (seal needs lawful basis, device type, tool +
# version). This fills it in — only while the item is unsealed — so the existing seal works.

_ACQ_JSON_FIELDS = ("device_types", "decision_factors", "device_details")


def _acq_audit_value(v):
    if isinstance(v, datetime):
        return _utc_z(v)
    if isinstance(v, uuid.UUID):
        return str(v)
    return v


@router.patch(
    "/{incident_id}/evidence/{evidence_id}/acquisition-record",
    response_model=EvidenceOut,
    summary="Complete the acquisition record of an unsealed item (then seal it)",
    responses={
        403: {"model": ApiErrorBody, "description": "not_collector_or_custodian"},
        404: {"model": ApiErrorBody, "description": "the item, or user_not_found (unknown witness_user_id)"},
        409: {"model": ApiErrorBody, "description": "incident_closed, evidence_sealed, evidence_not_active, "
              "evidence_not_in_internal_custody or transfer_pending"},
        422: {"model": ApiErrorBody, "description": "invalid_hash_format, hash_mismatch (target hash vs the "
              "stored file; nothing changed), acquisition_hashes_differ, acquired_in_future or "
              "assignee_no_access"},
    },
)
async def update_acquisition_record(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    req:     EvidenceAcquisitionRecord,
    request: Request,
    user:    User = Depends(require_analyst),
    db:      AsyncSession = Depends(get_db),
) -> EvidenceOut:
    """Fill in (or correct) the acquisition record of an UNSEALED item — lawful basis, device type,
    acquisition tool + version, imaging hashes, acquisition time, write-blocker, system state,
    witness, ISO/IEC 27037 §7 and 27041 fields — so it can then be sealed with POST …/seal. Typical
    use: a draft exhibit registered by an Email / PCAP / Browser history upload (G3), or a Quick add.

    Only the fields sent change (`null` clears one); the stored file and its hashes never change. The
    same checks as the collect routes: MD5 / SHA-1 / SHA-256 hex hashes (422 invalid_hash_format); a
    target hash with `target_hash_scope=uploaded_file` is compared with the stored file's hash of the
    same algorithm — a mismatch changes nothing (422 hash_mismatch, audited
    `evidence_acquisition_record_rejected`); source and target of the same algorithm must match (422
    acquisition_hashes_differ); `acquired_at` not in the future; a witness must be an active user who
    can see the incident. The item must be active, unsealed (a sealed item is amended, not
    re-recorded: 409 evidence_sealed), in internal custody and not awaiting a transfer. Only its
    collector, its current custodian, the incident lead or an admin may record it (403
    not_collector_or_custodian; the same rules as changing the clock offset with PATCH, M10).
    Audited `evidence_acquisition_record` with each field's before / after (custody log). Requires the
    analyst role and an open incident. Returns the item."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")
    ev = await _get_evidence(db, incident_id, evidence_id, for_update=True)
    if ev.coc_sealed:
        raise ApiError(status.HTTP_409_CONFLICT, "evidence_sealed",
                       "The item is sealed: its acquisition record is locked (changes are post-seal amendments)")
    if ev.status != "active":
        raise ApiError(status.HTTP_409_CONFLICT, "evidence_not_active",
                       f"Cannot record the acquisition of evidence in status '{ev.status}'")
    await _check_offset_authority(db, ev, user, inc)            # M10: one rule set with PATCH's offset

    fs = req.model_fields_set - {"target_hash_scope"}
    values = {k: getattr(req, k) for k in fs}
    if "acquired_at" in values:
        values["acquired_at"] = _check_acquired_at(values["acquired_at"])
    for h in ("acquisition_hash_source", "acquisition_hash_target"):
        if h in values:
            values[h] = _normalise_hash(values[h], h)
    if "acquisition_tool_sha256" in values and values["acquisition_tool_sha256"]:
        v = _normalise_hash(values["acquisition_tool_sha256"], "acquisition_tool_sha256")
        if hash_algorithm(v) != "sha256":
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_hash_format",
                           "acquisition_tool_sha256 must be 64 (SHA-256) hex characters")
        values["acquisition_tool_sha256"] = v
    if values.get("witness_user_id"):
        await require_incident_person(db, incident_id, values["witness_user_id"], "the witness")
    if "device_types" in values and values["device_types"] is not None:
        values["device_types"] = list(values["device_types"]) or None

    source = values.get("acquisition_hash_source", ev.acquisition_hash_source)
    target = values.get("acquisition_hash_target", ev.acquisition_hash_target)
    if _comparable_hashes(source, target) and source.lower() != target.lower():
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "acquisition_hashes_differ",
                       "The source and target hashes (same algorithm) do not match: the acquisition "
                       "integrity is broken. Re-acquire, or correct the hash you typed.")

    upload_hash_check = None
    if "acquisition_hash_target" in values or "target_hash_scope" in req.model_fields_set:
        algo = hash_algorithm(target)
        if not target:
            upload_hash_check = "not_checked"
        elif req.target_hash_scope == "container_media":
            upload_hash_check = "container_media"
        elif ev.kind == "digital_file" and ev.sha256:
            computed = {"md5": ev.md5, "sha1": ev.sha1, "sha256": ev.sha256}[algo]
            if (computed or "").lower() != target:
                label = _ALGORITHM_LABEL[algo]
                await write_audit(
                    db, "evidence_acquisition_record_rejected",
                    user_id=user.id, username=user.username,
                    resource_type="evidence", resource_id=str(ev.id), outcome="failure",
                    details={"incident_id": str(incident_id), "reason": "hash_mismatch", "algorithm": algo,
                             "acquisition_hash_target": target, "stored_hash": computed},
                    ip_address=request.client.host if request.client else None,
                )
                await db.commit()
                raise ApiError(
                    status.HTTP_422_UNPROCESSABLE_CONTENT, "hash_mismatch",
                    f"The target hash ({label}) does not match the stored file, whose {label} is {computed}. "
                    "Nothing was changed. If the hash covers an E01/AFF4 container's media rather than this "
                    "file, set target_hash_scope=container_media.")
            upload_hash_check = "match"
        else:
            upload_hash_check = "not_checked"

    changes: dict[str, object] = {}
    for k, v in values.items():
        before = getattr(ev, k)
        if before == v:
            continue
        setattr(ev, k, v)
        changes[k] = ({"to": v} if k in _ACQ_JSON_FIELDS
                      else {"from": _acq_audit_value(before), "to": _acq_audit_value(v)})
    if upload_hash_check is not None and upload_hash_check != ev.upload_hash_check:
        changes["upload_hash_check"] = {"from": ev.upload_hash_check, "to": upload_hash_check}
        ev.upload_hash_check = upload_hash_check
    if changes:
        details = {"incident_id": str(incident_id), "identifier": ev.identifier, "changes": changes}
        if "system_time_offset_seconds" in changes:          # L21: as PATCH's offset change
            details["imports_keep_previous_offset"] = await _runs_with_offset(db, ev.id)
        await write_audit(
            db, "evidence_acquisition_record",
            user_id=user.id, username=user.username,
            resource_type="evidence", resource_id=str(ev.id), outcome="success",
            details=details,
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


def _block_if_transfer_pending(ev: Evidence) -> None:
    """C4 — 409 transfer_pending while an internal transfer awaits the recipient: another
    transfer, dispose and seal wait until it is accepted or declined."""
    if ev.pending_custodian_id is not None:
        raise ApiError(
            status.HTTP_409_CONFLICT, "transfer_pending",
            "A custody transfer is awaiting the recipient's acceptance. The recipient accepts "
            "or declines it, or the requester or an admin cancels it, first.",
        )


async def _check_transfer_recipient(db: AsyncSession, incident_id: uuid.UUID, to_user: User) -> None:
    """C4 — the recipient must be able to accept: active, not read-only (viewer), and with
    access to this incident (same rules as incidents.access). 422 otherwise."""
    if not to_user.is_active:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "recipient_inactive",
                       "The recipient's account is disabled")
    if to_user.role not in ("admin", "analyst"):
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "recipient_read_only",
                       "The recipient has a read-only role and could not accept custody")
    can_see = (await db.execute(
        select(Incident.id).where(Incident.id == incident_id, accessible_filter(to_user))
    )).scalar_one_or_none()
    if can_see is None:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "recipient_no_access",
                       "The recipient has no access to this incident")


def _utc_z(dt: Optional[datetime]) -> Optional[str]:
    """UTC ISO 8601 with a Z suffix, sub-second precision kept (audit details)."""
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if dt else None


async def _handed_out_by(db: AsyncSession, evidence_id: uuid.UUID) -> Optional[uuid.UUID]:
    """M5 — the internal custodian who handed the item to the external party now holding it: the
    `from_user_id` of the latest external `evidence_transfer` that left internal custody (an
    external → external hand-over has none). The audit log is the authoritative record."""
    rows = (await db.execute(
        select(AuditLog.details).where(
            AuditLog.resource_type == "evidence", AuditLog.resource_id == str(evidence_id),
            AuditLog.action == "evidence_transfer",
        ).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
    )).scalars().all()
    for d in rows:
        d = d or {}
        if d.get("kind") == "external" and d.get("from_user_id"):
            try:
                return uuid.UUID(d["from_user_id"])
            except ValueError:
                return None
    return None


def _clear_pending_transfer(ev: Evidence) -> None:
    ev.pending_custodian_id          = None
    ev.pending_transfer_by_id        = None
    ev.pending_transfer_requested_at = None


@router.post(
    "/{incident_id}/evidence/{evidence_id}/transfer",
    response_model=EvidenceOut,
    summary="Request a custody transfer",
    responses={403: {"model": ApiErrorBody,
                     "description": "not_custodian / return_requires_recipient / not_authorised_take_back"},
               409: {"model": ApiErrorBody, "description": "transfer_pending"},
               422: {"model": ApiErrorBody,
                     "description": "recipient_inactive / recipient_read_only / recipient_no_access / "
                                    "recipient_is_requester / condition_required"}},
)
async def transfer_evidence(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    req:     TransferRequest,
    request: Request,
    user:    User = Depends(require_analyst),
    db:      AsyncSession = Depends(get_db),
) -> EvidenceOut:
    """Hand over an active evidence item. Only the current custodian or an admin may
    (403 not_custodian); an admin who is not the custodian is audited `override: true`.
    Requires an open incident; 409 transfer_pending while another transfer awaits acceptance.

    - **Internal** (`to_user_id`) is a REQUEST: custody does not change. The recipient must be
      active, analyst or admin, have access to the incident, and not be you (422
      recipient_is_requester: two-person control, also for an admin). Sets the item's
      `pending_*` fields, audits `evidence_transfer_request` and notifies the recipient, who
      then accepts (`…/transfer/accept`) or declines.
    - **External** (`to_external`): one step — custody passes at once (`evidence_transfer`).
    - **Return from external custody**: `to_user_id` must be yourself (403
      return_requires_recipient) — you record receipt in one step with `condition_on_receipt`
      and `seals_intact` (422 condition_required). Only the user who handed the item out (the
      internal custodian before the external transfer) or an admin may (403
      not_authorised_take_back); an admin who isn't that user is audited `override: true`.

    Captures reason, transport method, seal id and courier reference. Returns the item."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    ev = await _get_evidence(db, incident_id, evidence_id, for_update=True)
    if ev.status != "active":
        raise HTTPException(status.HTTP_409_CONFLICT, f"Cannot transfer evidence in status '{ev.status}'")
    _block_if_transfer_pending(ev)

    from_user_id     = ev.current_custodian_id
    from_external    = ev.current_custodian_external_name
    from_external_org = ev.current_custodian_external_org
    ip = request.client.host if request.client else None
    transport = {"reason": req.reason, "transport_method": req.transport_method,
                 "seal_id": req.seal_id, "courier_ref": req.courier_ref}

    # ── Return from external custody: the receiving user records receipt ──────
    if req.to_user_id is not None and _is_external_custody(ev):
        if req.to_user_id != user.id:
            raise ApiError(status.HTTP_403_FORBIDDEN, "return_requires_recipient",
                           "Only the receiving user can take an item back from external custody — "
                           "set yourself as the recipient")
        handed_out_by = await _handed_out_by(db, ev.id)
        take_back_override = handed_out_by != user.id
        if take_back_override and user.role != "admin":
            raise ApiError(status.HTTP_403_FORBIDDEN, "not_authorised_take_back",
                           "Only the user who handed this item to the external party, or an admin, "
                           "can take it back")
        condition = (req.condition_on_receipt or "").strip()
        if not condition or req.seals_intact is None:
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "condition_required",
                           "Taking an item back from external custody needs condition_on_receipt "
                           "and seals_intact")
        ev.current_custodian_id                  = user.id
        ev.current_custodian_external_name       = None
        ev.current_custodian_external_org        = None
        ev.current_custodian_external_contact    = None
        await write_audit(
            db, "evidence_transfer",
            user_id=user.id, username=user.username,
            resource_type="evidence", resource_id=str(ev.id),
            details={
                "incident_id": str(incident_id), "kind": "internal",
                "return_from_external": True, "acknowledged": True,
                "from_user_id": None,
                "from_external_name": from_external, "from_external_org": from_external_org,
                "to_user_id": str(user.id), "to_username": user.username,
                **transport,
                "condition_on_receipt": condition, "seals_intact": req.seals_intact,
                "handed_out_by_id": str(handed_out_by) if handed_out_by else None,
                "override": take_back_override,
            },
            ip_address=ip,
        )
        await db.commit()
        return _to_out(ev)

    is_custodian = from_user_id is not None and from_user_id == user.id
    if not is_custodian and user.role != "admin":
        raise ApiError(status.HTTP_403_FORBIDDEN, "not_custodian",
                       "Only the current custodian or an admin can hand this item over")
    override = not is_custodian

    if req.to_user_id is not None:
        # ── Internal: a request; custody changes when the recipient accepts ──
        to_user = (await db.execute(
            select(User).where(User.id == req.to_user_id)
        )).scalar_one_or_none()
        if not to_user:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Target user not found")
        if to_user.id == from_user_id:
            raise HTTPException(status.HTTP_409_CONFLICT, "Target user is already the custodian")
        if to_user.id == user.id:
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "recipient_is_requester",
                           "You can't request a transfer to yourself: another person must accept "
                           "custody (two-person control)")
        await _check_transfer_recipient(db, incident_id, to_user)
        ev.pending_custodian_id          = to_user.id
        ev.pending_transfer_by_id        = user.id
        ev.pending_transfer_requested_at = utcnow()
        await write_audit(
            db, "evidence_transfer_request",
            user_id=user.id, username=user.username,
            resource_type="evidence", resource_id=str(ev.id),
            details={
                "incident_id": str(incident_id), "kind": "internal",
                "from_user_id": str(from_user_id) if from_user_id else None,
                "to_user_id": str(to_user.id), "to_username": to_user.username,
                **transport,
                "override": override,
            },
            ip_address=ip,
        )
        await notify_custody_transfer(      # commits, then pushes
            db, recipient_id=to_user.id, incident_id=incident_id,
            incident_ref=inc.ref or str(incident_id), requester_username=user.username,
        )
        return _to_out(ev)

    # ── External transfer: one step ────────────────────────────────────────
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
    await write_audit(
        db, "evidence_transfer",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id),
        details={
            "incident_id":  str(incident_id),
            "kind":         "external",
            "from_user_id": str(from_user_id) if from_user_id else None,
            "from_external_name": from_external,
            "from_external_org":  from_external_org,
            "to_external_name":   ev.current_custodian_external_name,
            "to_external_org":    ev.current_custodian_external_org,
            "to_external_contact": ev.current_custodian_external_contact,
            **transport,
            "override": override,
        },
        ip_address=ip,
    )
    await db.commit()
    return _to_out(ev)


@router.post(
    "/{incident_id}/evidence/{evidence_id}/transfer/accept",
    response_model=EvidenceOut,
    summary="Accept a pending custody transfer",
    responses={403: {"model": ApiErrorBody, "description": "not_transfer_recipient"},
               409: {"model": ApiErrorBody, "description": "no_transfer_pending"},
               422: {"model": ApiErrorBody, "description": "condition_required"}},
)
async def accept_transfer(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    req:     TransferAcceptRequest,
    request: Request,
    user:    User = Depends(require_analyst),
    db:      AsyncSession = Depends(get_db),
) -> EvidenceOut:
    """The recipient of a pending internal transfer confirms receipt after inspecting the
    item: `condition_on_receipt` (what you found) and `seals_intact`. Only the recipient —
    never an admin on their behalf (403 not_transfer_recipient); 409 no_transfer_pending when
    nothing is pending. Custody passes to you and the request is cleared; audited as
    `evidence_transfer` (custody changed hands) with the condition, seals, requester and
    request time. Works on a closed incident so a request left at closure can be settled.
    The requester is notified in-app (L3). Returns the item."""
    inc = await _get_incident(db, incident_id, user)
    ev = await _get_evidence(db, incident_id, evidence_id, for_update=True)
    if ev.pending_custodian_id is None:
        raise ApiError(status.HTTP_409_CONFLICT, "no_transfer_pending", "No custody transfer is pending")
    if ev.pending_custodian_id != user.id:
        raise ApiError(status.HTTP_403_FORBIDDEN, "not_transfer_recipient",
                       "Only the recipient can accept this transfer — nobody can accept on their behalf")
    condition = req.condition_on_receipt.strip()
    if not condition:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "condition_required",
                       "Record the condition of the item on receipt")

    # The request's reason / transport live in its audit row (the authoritative record).
    request_row = (await db.execute(
        select(AuditLog).where(
            AuditLog.resource_type == "evidence", AuditLog.resource_id == str(ev.id),
            AuditLog.action == "evidence_transfer_request",
        ).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).limit(1)
    )).scalar_one_or_none()
    rd = (request_row.details or {}) if request_row else {}

    from_user_id      = ev.current_custodian_id
    from_external     = ev.current_custodian_external_name
    from_external_org = ev.current_custodian_external_org
    requested_by_id   = ev.pending_transfer_by_id
    requested_at      = ev.pending_transfer_requested_at
    ev.current_custodian_id                  = user.id
    ev.current_custodian_external_name       = None
    ev.current_custodian_external_org        = None
    ev.current_custodian_external_contact    = None
    _clear_pending_transfer(ev)

    await write_audit(
        db, "evidence_transfer",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id),
        details={
            "incident_id":  str(incident_id),
            "kind":         "internal",
            "acknowledged": True,
            "from_user_id": str(from_user_id) if from_user_id else None,
            "from_external_name": from_external,
            "from_external_org":  from_external_org,
            "to_user_id":   str(user.id),
            "to_username":  user.username,
            "requested_by_id":       str(requested_by_id) if requested_by_id else None,
            "requested_by_username": request_row.username if request_row else None,
            "requested_at": _utc_z(requested_at),
            "request_audit_id": str(request_row.id) if request_row else None,
            "override":         rd.get("override"),
            "reason":           rd.get("reason"),
            "transport_method": rd.get("transport_method"),
            "seal_id":          rd.get("seal_id"),
            "courier_ref":      rd.get("courier_ref"),
            "condition_on_receipt": condition,
            "seals_intact":         req.seals_intact,
        },
        ip_address=request.client.host if request.client else None,
    )
    if requested_by_id and requested_by_id != user.id:
        await notify_custody_transfer_outcome(      # commits, then pushes
            db, requester_id=requested_by_id, incident_id=incident_id,
            incident_ref=inc.ref or str(incident_id), actor_username=user.username, outcome="accepted")
    else:
        await db.commit()
    return _to_out(ev)


@router.post(
    "/{incident_id}/evidence/{evidence_id}/transfer/decline",
    response_model=EvidenceOut,
    summary="Decline or cancel a pending custody transfer",
    responses={403: {"model": ApiErrorBody, "description": "not_transfer_party"},
               409: {"model": ApiErrorBody, "description": "no_transfer_pending"}},
)
async def decline_transfer(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    req:     TransferDeclineRequest,
    request: Request,
    user:    User = Depends(require_analyst),
    db:      AsyncSession = Depends(get_db),
) -> EvidenceOut:
    """Decline (as the recipient) or cancel (as the requester or an admin) a pending
    internal transfer, with a reason. Anyone else gets 403 not_transfer_party; 409
    no_transfer_pending when nothing is pending. Custody stays where it was; the request is
    cleared and audited as `evidence_transfer_declined` (`declined_as`: recipient |
    requester | admin). Works on a closed incident. The requester is notified in-app unless they
    cancelled it themselves (L3). Returns the item."""
    inc = await _get_incident(db, incident_id, user)
    ev = await _get_evidence(db, incident_id, evidence_id, for_update=True)
    if ev.pending_custodian_id is None:
        raise ApiError(status.HTTP_409_CONFLICT, "no_transfer_pending", "No custody transfer is pending")
    if user.id == ev.pending_custodian_id:
        declined_as = "recipient"
    elif user.id == ev.pending_transfer_by_id:
        declined_as = "requester"
    elif user.role == "admin":
        declined_as = "admin"
    else:
        raise ApiError(status.HTTP_403_FORBIDDEN, "not_transfer_party",
                       "Only the recipient, the requester or an admin can decline this transfer")

    details = {
        "incident_id":     str(incident_id),
        "declined_as":     declined_as,
        "reason":          req.reason,
        "to_user_id":      str(ev.pending_custodian_id),
        "requested_by_id": str(ev.pending_transfer_by_id),
        "requested_at":    _utc_z(ev.pending_transfer_requested_at),
        "custodian_id":    str(ev.current_custodian_id) if ev.current_custodian_id else None,
    }
    requested_by_id = ev.pending_transfer_by_id
    _clear_pending_transfer(ev)
    await write_audit(
        db, "evidence_transfer_declined",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id),
        details=details,
        ip_address=request.client.host if request.client else None,
    )
    if requested_by_id and requested_by_id != user.id:
        await notify_custody_transfer_outcome(      # commits, then pushes
            db, requester_id=requested_by_id, incident_id=incident_id,
            incident_ref=inc.ref or str(incident_id), actor_username=user.username,
            outcome="declined" if declined_as == "recipient" else "cancelled")
    else:
        await db.commit()
    return _to_out(ev)


# ─── Examine ─────────────────────────────────────────────────────────────────

_EXAM_TARGET_RESPONSES = {
    404: {"model": ApiErrorBody, "description": "working_copy_not_found (not a copy of this item)"},
    409: {"model": ApiErrorBody, "description": "working_copy_not_verified (the copy's hash did not match the "
                                                "master, it is not complete, is a pre-G5 record or was found "
                                                "altered)"},
    422: {"model": ApiErrorBody, "description": "working_copy_required, working_copy_or_in_place, "
                                                "in_place_reason_required, working_copy_not_applicable "
                                                "(physical item)"},
}


async def _exam_target(db: AsyncSession, ev: Evidence, working_copy_id: Optional[uuid.UUID],
                       examined_in_place: bool, in_place_reason: Optional[str]) -> Optional[EvidenceCopy]:
    """G5 (R08): what an examination of `ev` ran on. A digital exhibit needs a verified working copy
    (ISO/IEC 27037 §7.1.3.1.1) or an explicit, reasoned "examined in place"; a physical item is exempt.
    Returns the copy (None = in place / physical)."""
    if ev.kind != "digital_file":
        if working_copy_id is not None:
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "working_copy_not_applicable",
                           "A physical item has no working copies; leave working_copy_id out")
        return None
    if working_copy_id is not None and examined_in_place:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "working_copy_or_in_place",
                       "Give either working_copy_id or examined_in_place, not both")
    if examined_in_place:
        if not (in_place_reason or "").strip():
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "in_place_reason_required",
                           "Examining a digital exhibit in place (without a working copy) needs a reason")
        return None
    if working_copy_id is None:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "working_copy_required",
                       "Name the working copy you examined (working_copy_id), or set examined_in_place with "
                       "a reason. Download a working copy, or record your lab copy with its hash, first.")
    wc = (await db.execute(
        select(EvidenceCopy).where(EvidenceCopy.id == working_copy_id, EvidenceCopy.evidence_id == ev.id)
    )).scalar_one_or_none()
    if wc is None:
        raise ApiError(status.HTTP_404_NOT_FOUND, "working_copy_not_found",
                       "working_copy_id is not a working copy of this evidence item")
    corrected = frozenset(await _corrected_copy_ids(db, ev.id)) if wc.export_id else frozenset()
    if not wcs.usable_for_examination(wc, corrected):
        raise ApiError(status.HTTP_409_CONFLICT, "working_copy_not_verified",
                       f"Working copy {wc.copy_identifier or wc.id} can't be examined: its status is "
                       f"'{wcs.effective_status(wc)}'" + (" and it was found altered" if wc.altered_at else "")
                       + ". Only a copy whose own hash matches the master can be.")
    return wc


def _exam_target_details(wc: Optional[EvidenceCopy], examined_in_place: bool,
                         in_place_reason: Optional[str]) -> dict:
    return {
        "working_copy_id":   str(wc.id) if wc else None,
        "copy_identifier":   wc.copy_identifier if wc else None,
        "examined_in_place": bool(examined_in_place) and wc is None,
        "in_place_reason":   (in_place_reason or "").strip() or None if examined_in_place else None,
    }


@router.post(
    "/{incident_id}/evidence/{evidence_id}/examine",
    response_model=EvidenceOut,
    summary="Record an examination action",
    responses=_EXAM_TARGET_RESPONSES,
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
    G5: a digital exhibit names the verified working copy examined (`working_copy_id`) or is
    examined in place with a reason (`examined_in_place`, `in_place_reason`); both are recorded
    in the custody row. A physical item is exempt.
    For integrity-bracketed analysis use the examination-session endpoint
    instead. Returns the evidence record."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    ev = await _get_evidence(db, incident_id, evidence_id)
    if ev.status != "active":
        raise HTTPException(status.HTTP_409_CONFLICT, f"Cannot examine evidence in status '{ev.status}'")
    _block_if_external(ev, "examine")
    wc = await _exam_target(db, ev, req.working_copy_id, req.examined_in_place, req.in_place_reason)

    await write_audit(
        db, "evidence_examine",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id),
        details={
            "incident_id": str(incident_id),
            "tool":  req.tool,
            "notes": req.notes,
            **(_exam_target_details(wc, req.examined_in_place, req.in_place_reason)
               if ev.kind == "digital_file" else {}),
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return _to_out(ev)


# ─── Verify integrity ────────────────────────────────────────────────────────

_READ_ERROR_DOC = {503: {"model": ApiErrorBody, "description": "evidence_read_error (the stored copy could not be "
                                                               "read: missing file, storage error or wrong "
                                                               "EVIDENCE_KEK; not frozen, audited, admins notified)"}}


def _read_error() -> ApiError:
    return ApiError(status.HTTP_503_SERVICE_UNAVAILABLE, "evidence_read_error",
                    "The exhibit's stored copy could not be read (missing file, storage error or wrong "
                    "EVIDENCE_KEK). It was not frozen; the attempt was audited and admins were notified.")


@router.post(
    "/{incident_id}/evidence/{evidence_id}/verify",
    response_model=VerifyResult,
    summary="Verify evidence integrity",
    responses=_READ_ERROR_DOC,
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
    recorded vs recomputed hashes and an ok flag. The stored file is hashed as it is
    decrypted; an integrity failure of the stored file (failed authentication, wrong
    size, header or nonce) also freezes it. A file that cannot be read at all (missing,
    storage error, wrong EVIDENCE_KEK) is 503 evidence_read_error and is NOT frozen; that
    read is audited (evidence_read_failed) and admins are notified."""
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
        computed = await asha256_decrypted(ev.storage_path, ev.nonce_hex, ev.file_size_bytes)
        ok       = (computed == ev.sha256)
        reason   = None if ok else "hash_mismatch"
    except EvidenceIntegrityError as e:
        ok, computed, reason = False, None, e.reason
    except EvidenceCryptoError as e:
        raise _read_error() from e

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

    # Failure path: freeze the evidence + audit + return. M2: the status is re-read under a row lock
    # (freeze_for_integrity), so a dispose that landed during the hash is never overwritten.
    await wcs.freeze_for_integrity(db, ev.id, user=user, ip=request.client.host if request.client else None,
                                   incident_id=incident_id, reason=reason, recomputed=computed, phase="verify")
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
    responses={409: {"model": ApiErrorBody, "description": "transfer_pending, or legal_hold_active (destroy while "
                                                           "the item is on legal hold)"},
               404: {"model": ApiErrorBody, "description": "user_not_found (unknown witness_id), or the item"},
               422: {"model": ApiErrorBody, "description": "assignee_no_access (witness deactivated or can't "
                                                           "see the incident)"}},
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
    Legal-hold items require a distinct second approver (`witness_id`) for
    two-person integrity: an active user who can see the incident (404
    `user_not_found`, 422 `assignee_no_access`). 409 transfer_pending while a
    custody transfer awaits acceptance. G5 (R09): a legal-hold item can't be destroyed at all
    (409 legal_hold_active: release the hold first, PUT …/legal-hold); returning or archiving it
    (the file is kept) needs the second approver above. Returns the updated record with
    disposition status and timestamp."""
    inc = await _get_incident(db, incident_id, user)
    ev  = await _get_evidence(db, incident_id, evidence_id, for_update=True)
    if ev.status in ("destroyed", "returned", "archived"):
        raise HTTPException(status.HTTP_409_CONFLICT, "Evidence is already disposed")
    _block_if_transfer_pending(ev)
    if ev.legal_hold and req.kind == "destroy":
        raise ApiError(status.HTTP_409_CONFLICT, "legal_hold_active",
                       "The item is on legal hold and can't be destroyed. The incident lead or an admin "
                       "releases the hold first (with a reason); then it can be disposed of.")

    # GS-10 — two-person integrity for legal-hold disposal (SWGDE/ACPO). A held
    # item may only be disposed with a second approver who is a distinct active user.
    if ev.legal_hold:
        if not req.witness_id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                "Legal-hold evidence requires a second approver (witness_id) to dispose")
        if req.witness_id == user.id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                "The disposal witness must be a different user (two-person integrity)")
        await require_incident_person(db, incident_id, req.witness_id, "the disposal witness")
        ev.dispose_witness_id = req.witness_id

    # Record final hash before removing the file (digital_file only).
    final_hash = ev.sha256
    if req.kind == "destroy" and ev.kind == "digital_file" and ev.storage_path:
        # File is permanently removed; chain entry + hash persist.
        await adelete_encrypted(ev.storage_path)
        ev.storage_path = None
        ev.nonce_hex    = None
    photos_removed = 0
    if req.kind == "destroy":
        # GS-11 — also remove encrypted photo files (digital or physical). ROT-H2: once a file is gone its
        # row entry no longer names it (storage_path / nonce_hex cleared; sha256 kept, destroyed_at set), so
        # nothing (the KEK rotation tool, the photo GET) takes it for a stored file any more.
        destroyed_at = _utc_z(utcnow())
        kept = []
        for p in (ev.photos or []):
            if isinstance(p, dict) and p.get("storage_path"):
                await adelete_encrypted(p["storage_path"])
                p = {k: v for k, v in p.items() if k not in ("storage_path", "nonce_hex")}
                p["destroyed_at"] = destroyed_at
                photos_removed += 1
            kept.append(p)
        if photos_removed:
            ev.photos = kept

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
            "photo_files_removed": photos_removed,
            "legal_hold":   ev.legal_hold,
            "dispose_witness_id": str(req.witness_id) if ev.legal_hold else None,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return _to_out(ev)


# ─── GS-11 — Photo attachments (ISO/IEC 27037 §6.2.1; encrypted at rest) ────
# Real image bytes are stored AES-256-GCM under photos/{eid}/ and only served
# back through the auth-gated GET route below. Legacy free-text-URL photos (no
# storage_path) are untouched — the frontend renders them via their url directly.

@router.post(
    "/{incident_id}/evidence/{evidence_id}/photos",
    response_model=EvidenceOut,
    summary="Attach a photo to evidence",
    responses={507: {"model": ApiErrorBody, "description": "insufficient_storage (the evidence volume, with its 1 GiB reserve, or the upload scratch space is full; nothing stored)"}},
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
    if len(raw) > multipart_max_bytes():
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            f"Photo exceeds max {multipart_max_bytes()} bytes")

    require_free_space(codec.container_size(len(raw)), "this photo")          # L2
    photo_id = uuid.uuid4().hex
    rel = f"photos/{evidence_id}/{photo_id}.enc"
    stored = await awrite_encrypted(raw, rel)

    entry = {
        "id":           photo_id,
        "url":          f"/api/incidents/{incident_id}/evidence/{evidence_id}/photos/{photo_id}",
        "caption":      (caption or None),
        "taken_at":     (taken_at or None),
        "storage_path": rel,
        "nonce_hex":    stored.nonce_hex,
        "mime_type":    file.content_type,
        "sha256":       stored.sha256,
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
    responses={200: {"description": "The image bytes, with Content-Length. Over 16 MiB the body is streamed "
                                    "as it is decrypted: if a later part fails its integrity check the server "
                                    "closes the connection before Content-Length bytes are sent; treat a short "
                                    "body as a failed download."}},
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
    the fly and returns the raw bytes with the original media type. G2: up to 16 MiB
    it is authenticated whole before sending; a larger one streams (bounded memory) and a
    failure found mid-stream aborts the connection short of Content-Length."""
    await _get_incident(db, incident_id, user)   # incident-access gate (zero-trust)
    ev = await _get_evidence(db, incident_id, evidence_id)
    entry = next((p for p in (ev.photos or [])
                  if isinstance(p, dict) and p.get("id") == photo_id), None)
    if not entry or not entry.get("storage_path"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Photo not found")
    return await decrypted_download(entry["storage_path"], entry.get("nonce_hex") or "", entry.get("size"),
                                    media_type=entry.get("mime_type") or "application/octet-stream")


# ─── Wizard A — Seal acquisition (ISO/IEC 27037 §5.4.4, §6.1) ──────────────
# Validates that the minimum reproducibility + lawful-basis fields are present,
# then sets coc_sealed. After sealing, subsequent PATCH updates write an
# `evidence_amend_after_seal` audit row so reviewers can see post-seal changes.

@router.post(
    "/{incident_id}/evidence/{evidence_id}/seal",
    response_model=EvidenceOut,
    summary="Seal the chain of custody",
    responses={400: {"model": ApiErrorBody, "description": "confirm_required"},
               409: {"model": ApiErrorBody, "description": "transfer_pending, incident_closed, already_sealed or "
                                                           "evidence_not_active"},
               422: {"model": ApiErrorBody, "description": "hash_mismatch (acquisition source vs target hash), or "
                                                           "seal_fields_missing (body has `missing`: the field names)"}},
)
async def seal_evidence(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    req:     EvidenceSealRequest,
    request: Request,
    user:    User = Depends(require_analyst),
    db:      AsyncSession = Depends(get_db),
) -> EvidenceOut:
    """Seal an item's chain of custody (ISO/IEC 27037 §5.4.4, §6.1) after enforcing
    the minimum reproducibility and lawful-basis fields are present (e.g. lawful
    basis, device types, and for digital files the hash plus acquisition tool +
    version). Best-effort applies a trusted timestamp to the sealed hash.
    Requires `confirm=true`, analyst role, an open incident, internal custody,
    and active status; rejects an already-sealed item, and 409 transfer_pending
    while a custody transfer awaits acceptance. After sealing, later
    edits are audited as post-seal amendments. Returns the sealed record."""
    if not req.confirm:
        raise ApiError(status.HTTP_400_BAD_REQUEST, "confirm_required", "confirm must be true to seal")
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")
    ev = await _get_evidence(db, incident_id, evidence_id, for_update=True)
    if ev.coc_sealed:
        raise ApiError(status.HTTP_409_CONFLICT, "already_sealed", "Evidence is already sealed")
    if ev.status != "active":
        raise ApiError(status.HTTP_409_CONFLICT, "evidence_not_active",
                       f"Cannot seal evidence in status '{ev.status}'")
    _block_if_external(ev, "seal")
    _block_if_transfer_pending(ev)

    # Gate sealing on the wizard-A minimum (ISO/IEC 27037 §5.4.4 + GDPR Art. 5.1(c)).
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
        # C3 — compared only when both use the same algorithm (MD5 / SHA-1 / SHA-256);
        # different algorithms are advisory in the provenance score, never a block.
        if _comparable_hashes(ev.acquisition_hash_source, ev.acquisition_hash_target):
            if ev.acquisition_hash_source.lower() != ev.acquisition_hash_target.lower():
                raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "hash_mismatch",
                               "Acquisition source and target hashes do not match — cannot seal")
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
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "seal_fields_missing",
                       f"Cannot seal — required fields missing: {', '.join(missing)}", extra={"missing": missing})

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


# ─── Wizard B — Examination session (copy hash before + examine + copy hash after) ──
# Analysis is recorded together with integrity checks of what was examined (ISO/IEC 27037 §5.4.5;
# ISO/IEC 27042). G5 (R08): a digital exhibit is examined on a verified working copy, so the bracket
# compares the hashes the examiner took of THAT copy (before: optional; after: required) with the
# hash recorded for the copy. The master is not re-hashed here: POST …/verify does that. All rows
# share an examination_session uuid in their details so the custody log can group them.

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
    # GS-2 / G5 — what the analysis was performed on (ISO/IEC 27037 §7.1.3.1.1): a verified working copy,
    # or explicitly in place with a reason. Required for a digital exhibit (see the endpoint).
    working_copy_id:   Optional[uuid.UUID] = None
    examined_in_place: bool = False
    in_place_reason:   Optional[str] = Field(default=None, max_length=2048)
    # G5 — the examiner's hashes of the working copy (MD5 / SHA-1 / SHA-256 hex): after the examination
    # (required with a copy) and, optionally, before it. Compared with the copy's recorded hash.
    pre_exam_copy_hash:  Optional[str] = Field(default=None, max_length=64)
    post_exam_copy_hash: Optional[str] = Field(default=None, max_length=64)


class ExamSessionResult(BaseModel):
    ok:                 bool
    session_id:         uuid.UUID
    # M3 (G-fix): an examination IN PLACE is bracketed by a streamed verify of the master: its SHA-256
    # before and after. Null with a working copy (its own hashes are below) or without a stored file.
    pre_verify_sha256:  Optional[str] = None
    post_verify_sha256: Optional[str] = None
    # G5 — the copy bracket (null when examined in place)
    working_copy_id:     Optional[uuid.UUID] = None
    copy_identifier:     Optional[str] = None
    examined_in_place:   bool = False
    hash_algorithm:      Optional[Literal["md5", "sha1", "sha256"]] = None
    copy_hash_recorded:  Optional[str] = None
    pre_exam_copy_hash:  Optional[str] = None
    pre_exam_match:      Optional[bool] = None
    post_exam_copy_hash: Optional[str] = None
    post_exam_match:     Optional[bool] = None
    message:            str


def _copy_hash_check(wc: EvidenceCopy, value: Optional[str], field: str) -> Optional[tuple[str, str, bool]]:
    """(algorithm, the copy's recorded hash, equal?) for an examiner-entered hash of the copy, or None
    when none was given. 422 invalid_hash_format / hash_not_comparable (the copy has no recorded hash
    of that algorithm)."""
    value = _normalise_hash(value, field)
    if value is None:
        return None
    algo = hash_algorithm(value)
    recorded = wcs.recorded_hash(wc, algo)
    if not recorded:
        have = [a for a in ("sha256", "sha1", "md5") if wcs.recorded_hash(wc, a)]
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "hash_not_comparable",
                       f"{field} is {_ALGORITHM_LABEL[algo]}, but working copy {wc.copy_identifier or wc.id} has "
                       f"no recorded {_ALGORITHM_LABEL[algo]} hash; use "
                       + (" or ".join(_ALGORITHM_LABEL[a] for a in have) or "another copy") + ".")
    return algo, recorded, recorded.lower() == value


@router.post(
    "/{incident_id}/evidence/{evidence_id}/examination-session",
    response_model=ExamSessionResult,
    summary="Run an examination session",
    responses={**_EXAM_TARGET_RESPONSES, **_READ_ERROR_DOC,
               422: {"model": ApiErrorBody,
                     "description": "working_copy_required, working_copy_or_in_place, in_place_reason_required, "
                                    "post_exam_hash_required, invalid_hash_format or hash_not_comparable"}},
)
async def examination_session(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    req:     ExamSessionRequest,
    request: Request,
    user:    User = Depends(require_analyst),
    db:      AsyncSession = Depends(get_db),
) -> ExamSessionResult:
    """Record an examination (ISO/IEC 27042: tool, version, findings, interpretation, scope limitations)
    bracketed by integrity checks of what was examined (ISO/IEC 27037 §5.4.5), all sharing one session id
    in the custody log. Requires analyst role, an open incident, active digital-file evidence held
    internally.

    G5 (R08): name the verified working copy you examined (`working_copy_id`; see GET …/working-copies,
    `usable_for_examination`) and give `post_exam_copy_hash`, the hash you took of that copy after the
    examination (MD5 / SHA-1 / SHA-256; optionally `pre_exam_copy_hash` too). Each is compared with the
    hash recorded for the copy (the bytes FENRIR sent for a download, the tool-reported hash for a lab
    copy): a pre-exam mismatch aborts (nothing examined is recorded, `evidence_working_copy_verify_failed`);
    a post-exam mismatch records the examination and flags the copy altered (it can't be examined again).
    The master is unaffected and NOT re-hashed here — run POST …/verify for that. Or examine in place:
    `examined_in_place: true` + `in_place_reason` (audited). M3: an in-place examination is bracketed by
    the master itself — its SHA-256, hashed as it is decrypted (bounded memory), before and after the
    record (`pre_verify_sha256` / `post_verify_sha256`, audited evidence_verify phase pre / post). A
    mismatch or a failed integrity check freezes the exhibit (verify_failed): before, nothing is recorded;
    after, the examination is recorded. A stored copy that can't be read is 503 evidence_read_error (not
    frozen). Returns the checks and an ok flag."""
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
    wc = await _exam_target(db, ev, req.working_copy_id, req.examined_in_place, req.in_place_reason)
    pre = post = None
    if wc is not None:
        if not (req.post_exam_copy_hash or "").strip():
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "post_exam_hash_required",
                           "Give post_exam_copy_hash: the hash of the working copy after your examination")
        pre = _copy_hash_check(wc, req.pre_exam_copy_hash, "pre_exam_copy_hash")
        post = _copy_hash_check(wc, req.post_exam_copy_hash, "post_exam_copy_hash")

    session_id = uuid.uuid4()
    ip = request.client.host if request.client else None
    target = _exam_target_details(wc, req.examined_in_place, req.in_place_reason)
    result = ExamSessionResult(
        ok=True, session_id=session_id, message="",
        working_copy_id=wc.id if wc else None, copy_identifier=wc.copy_identifier if wc else None,
        examined_in_place=wc is None,
        hash_algorithm=post[0] if post else None, copy_hash_recorded=post[1] if post else None,
        pre_exam_copy_hash=_normalise_hash(req.pre_exam_copy_hash, "pre_exam_copy_hash") if pre else None,
        pre_exam_match=pre[2] if pre else None,
        post_exam_copy_hash=_normalise_hash(req.post_exam_copy_hash, "post_exam_copy_hash") if post else None,
        post_exam_match=post[2] if post else None,
    )

    async def _copy_verify(phase: str, check: tuple[str, str, bool], entered: str) -> None:
        algo, recorded, ok = check
        await write_audit(
            db, "evidence_working_copy_verify" if ok else "evidence_working_copy_verify_failed",
            user_id=user.id, username=user.username,
            resource_type="evidence", resource_id=str(ev.id),
            outcome="success" if ok else "failure",
            details={"incident_id": str(incident_id), "examination_session": str(session_id), "phase": phase,
                     "working_copy_id": str(wc.id), "copy_identifier": wc.copy_identifier,
                     "algorithm": algo, "copy_hash_recorded": recorded, "copy_hash_entered": entered},
            ip_address=ip,
        )

    async def _master_verify(phase: str) -> Optional[tuple[bool, Optional[str]]]:
        """M3: an in-place examination's bracket — the master's SHA-256, streamed. None without a stored
        file. A mismatch / integrity failure freezes (locked re-read). EvidenceCryptoError propagates."""
        if not ev.storage_path or not ev.nonce_hex or not ev.sha256:
            return None
        try:
            computed = await asha256_decrypted(ev.storage_path, ev.nonce_hex, ev.file_size_bytes)
            reason = None if computed == ev.sha256 else "hash_mismatch"
        except EvidenceIntegrityError as e:
            computed, reason = None, e.reason or "integrity"
        if reason is None:
            await write_audit(
                db, "evidence_verify", user_id=user.id, username=user.username,
                resource_type="evidence", resource_id=str(ev.id), outcome="success",
                details={"incident_id": str(incident_id), "examination_session": str(session_id), "phase": phase,
                         "examined_in_place": True, "sha256_recorded": ev.sha256, "sha256_recomputed": computed},
                ip_address=ip)
            return True, computed
        await wcs.freeze_for_integrity(db, ev.id, user=user, ip=ip, incident_id=incident_id, reason=reason,
                                       recomputed=computed, phase=f"examination_session_{phase}",
                                       extra={"examination_session": str(session_id), "examined_in_place": True})
        return False, computed

    if wc is None:
        try:
            pre_master = await _master_verify("pre")
        except EvidenceCryptoError as e:
            raise _read_error() from e
        if pre_master is not None:
            result.pre_verify_sha256 = pre_master[1]
            if not pre_master[0]:
                await db.commit()
                result.ok = False
                result.message = ("Pre-examination integrity check of the master FAILED: the exhibit is frozen "
                                  "(verify_failed) and nothing was recorded.")
                return result

    # ── Before: the examiner's hash of the copy, if given ──────────────
    if pre is not None:
        await _copy_verify("pre", pre, result.pre_exam_copy_hash)
        if not pre[2]:
            wc.altered_at = utcnow()
            await db.commit()
            result.ok = False
            result.message = (f"The working copy {wc.copy_identifier or wc.id} does not match its recorded hash: "
                              "examination aborted and the copy flagged altered. The master is unaffected; use "
                              "another verified copy.")
            return result

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
            **target,
        },
        ip_address=ip,
    )

    if wc is None:
        try:
            post_master = await _master_verify("post")
        except EvidenceCryptoError as e:
            await db.commit()               # keep the pre-verify + examination records
            raise _read_error() from e
        await db.commit()
        if post_master is None:
            result.message = ("Examination recorded as examined in place. The exhibit has no stored file, so "
                              "there was no hash check.")
        elif not post_master[0]:
            result.post_verify_sha256 = post_master[1]
            result.ok = False
            result.message = ("Examination recorded as examined in place, but the master FAILED its integrity check "
                              "afterwards: the exhibit is frozen (verify_failed).")
        else:
            result.post_verify_sha256 = post_master[1]
            result.message = ("Examination recorded as examined in place: the master matched its recorded SHA-256 "
                              "before and after.")
        return result

    # ── After: the examiner's hash of the copy ──────────────────────────
    await _copy_verify("post", post, result.post_exam_copy_hash)
    if not post[2]:
        wc.altered_at = utcnow()
        await db.commit()
        result.ok = False
        result.message = (f"The working copy {wc.copy_identifier or wc.id} changed during the examination (its "
                          "hash no longer matches): the examination is recorded, the copy is flagged altered and "
                          "can't be examined again. The master is unaffected.")
        return result

    await db.commit()
    result.message = (f"Examination recorded — working copy {wc.copy_identifier or wc.id} matched its recorded "
                      "hash" + (" before and after." if pre else " after the examination."))
    return result


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
    corrected = await _corrected_copy_ids(db, ev.id)
    ev.copy_corrections = len(corrected)
    ev.has_verified_working_copy = bool(await _verified_copy_ids(db, [ev.id], corrected))
    _apply_exam_flags(ev, await _examination_flags(db, [ev.id]))
    _apply_transfer_counts(ev, await _transfer_ack_counts(db, [ev.id]))
    return ProvenanceScore(**score_evidence(ev))


# ─── Working copies (ISO/IEC 27037 §7.1.3.1.1 ledger, Slice C; G5) ───────────
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
    """List the working copies (ISO/IEC 27037 §7.1.3.1.1) of an evidence item, newest first: each with its
    kind (download | lab_copy | export | legacy_record), identifier, status, its own hashes and whether
    they equal the master's (`verified_against_master`), who made it, its purpose, and whether an
    examination may name it (`usable_for_examination`). A download shows its issuer, transfer times and
    bytes sent; the link token is never returned. Requires access to the incident."""
    await _get_incident(db, incident_id, user)
    await _get_evidence(db, incident_id, evidence_id)
    rows = (await db.execute(
        select(EvidenceCopy)
        .where(EvidenceCopy.evidence_id == evidence_id)
        .order_by(EvidenceCopy.created_at.desc(), EvidenceCopy.id)
    )).scalars().all()
    corrected = frozenset(await _corrected_copy_ids(db, evidence_id))
    return EvidenceCopyList(items=[wcs.copy_out(r, corrected) for r in rows])


def _working_copy_state_error(ev: Evidence) -> Optional[ApiError]:
    """G5: why no working copy can be made of `ev` now (the from-evidence rules), else None."""
    if ev.kind != "digital_file":
        return ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "evidence_not_digital",
                        "Working copies apply to digital evidence (a physical item has no stored bytes)")
    if ev.status != "active":
        return ApiError(status.HTTP_409_CONFLICT, "evidence_not_active",
                        f"No working copy of evidence in status '{ev.status}'"
                        + (" (frozen pending admin review)" if ev.status == "verify_failed" else ""))
    if ev.current_custodian_id is None:
        return ApiError(status.HTTP_409_CONFLICT, "evidence_not_in_internal_custody",
                        "The exhibit is not held by an internal custodian; take it back first")
    if ev.pending_custodian_id is not None:
        return ApiError(status.HTTP_409_CONFLICT, "transfer_pending",
                        "A custody transfer is awaiting the recipient's acceptance; make the copy after it "
                        "is accepted or declined")
    return None


_WC_STATE_DOC = ("evidence_not_active (incl. frozen verify_failed), evidence_not_in_internal_custody, "
                 "transfer_pending")


@router.post(
    "/{incident_id}/evidence/{evidence_id}/working-copy",
    response_model=EvidenceCopyOut,
    status_code=status.HTTP_201_CREATED,
    operation_id="record_lab_working_copy",       # L16: was mint_working_copy (path unchanged)
    summary="Record a lab copy made outside FENRIR, with its own hash",
    responses={409: {"model": ApiErrorBody, "description": _WC_STATE_DOC},
               422: {"model": ApiErrorBody, "description": "copy_hash_required, invalid_hash_format, "
                                                           "evidence_not_digital, master_hash_missing"}},
)
async def mint_working_copy(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    req:     WorkingCopyCreate,
    request: Request,
    user:    User = Depends(require_analyst),
    db:      AsyncSession = Depends(get_db),
) -> EvidenceCopyOut:
    """Record a working copy made outside FENRIR (e.g. imaged to a lab workstation from the original
    media) with the hash(es) the copying tool reported for THAT copy — G5 (R08): before G5 this route
    re-hashed the master and stored the master's hash as the copy's, which proved nothing about the copy.

    At least one of copy_sha256 / copy_sha1 / copy_md5 (422 copy_hash_required). Each given hash is
    compared with the master's recorded hash of the same algorithm: all equal → `verified` (it counts as
    a verified working copy and can be examined); any differs → `mismatch` (flagged, audited with
    outcome failure, never counted as verified). The master is not read. Gets the next
    "<exhibit>-WC-n" identifier; audited `evidence_working_copy_recorded` in the custody log.

    Requires the analyst role and access to the incident; the item must be an active digital file (not
    frozen) held by an internal custodian with no transfer pending (409). Allowed on a closed incident
    (a custody record). Returns the copy (201)."""
    await _get_incident(db, incident_id, user)
    entered = {"sha256": _normalise_hash(req.copy_sha256, "copy_sha256"),
               "sha1":   _normalise_hash(req.copy_sha1, "copy_sha1"),
               "md5":    _normalise_hash(req.copy_md5, "copy_md5")}
    for algo, value in entered.items():
        if value is not None and hash_algorithm(value) != algo:
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_hash_format",
                           f"copy_{algo} must be {_ALGORITHM_LABEL[algo]} hex "
                           f"({ {'md5': 32, 'sha1': 40, 'sha256': 64}[algo] } characters)")
    entered = {a: v for a, v in entered.items() if v}
    if not entered:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "copy_hash_required",
                       "Give the hash your copying tool reported for the copy (copy_sha256, copy_sha1 or "
                       "copy_md5): FENRIR compares it with the master's recorded hash.")
    ev = await _get_evidence(db, incident_id, evidence_id, for_update=True)
    if (err := _working_copy_state_error(ev)) is not None:
        raise err
    master = {"sha256": ev.sha256, "sha1": ev.sha1, "md5": ev.md5}
    missing = [a for a in entered if not master[a]]
    if missing:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "master_hash_missing",
                       "The master has no recorded " + ", ".join(_ALGORITHM_LABEL[a] for a in missing)
                       + " hash to compare with; give another algorithm")
    differs = sorted(a for a, v in entered.items() if master[a].lower() != v)
    verified = not differs

    seq = await wcs.next_copy_seq(db, ev.id)
    copy = EvidenceCopy(
        id=uuid.uuid4(), evidence_id=ev.id, role="working", kind="lab_copy",
        copy_seq=seq, copy_identifier=f"{ev.identifier}-WC-{seq}",
        status="verified" if verified else "mismatch",
        sha256=entered.get("sha256"), sha1=entered.get("sha1"), md5=entered.get("md5"),
        verified_against_master=verified,
        created_by_id=user.id, created_by_qualifications=user.qualifications,
        purpose=req.purpose, destination_note=req.destination_note, copy_tool=req.copy_tool,
    )
    db.add(copy)
    await db.flush()
    await write_audit(
        db, "evidence_working_copy_recorded",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id),
        outcome="success" if verified else "failure",
        details={
            "incident_id": str(incident_id),
            "working_copy_id": str(copy.id),
            "copy_identifier": copy.copy_identifier,
            "kind": "lab_copy",
            "result": copy.status,
            "copy_hashes": entered,
            "master_hashes": {a: master[a] for a in entered},
            "mismatched": differs,
            "copy_tool": req.copy_tool,
            "destination_note": req.destination_note,
            "purpose": req.purpose,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return wcs.copy_out(copy)


@router.post(
    "/{incident_id}/evidence/{evidence_id}/working-copies",
    response_model=WorkingCopyIssued,
    status_code=status.HTTP_201_CREATED,
    operation_id="issue_working_copy_download",   # L16: was issue_working_copy (path unchanged)
    summary="Issue a working copy to download (one-time link, you only)",
    responses={409: {"model": ApiErrorBody, "description": _WC_STATE_DOC + ", evidence_storage_missing"},
               422: {"model": ApiErrorBody, "description": "evidence_not_digital"}},
)
async def issue_working_copy(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    req:     WorkingCopyIssue,
    request: Request,
    user:    User = Depends(require_analyst),
    db:      AsyncSession = Depends(get_db),
) -> WorkingCopyIssued:
    """Issue a working copy of a digital exhibit to download — G5 (R08). Masters are never downloadable:
    every download is a registered working copy ("<exhibit>-WC-n", status `issued`), audited
    `evidence_working_copy_issued` in the custody log.

    Returns a one-time `download_url` (GET; also send your session cookie or API token — it works for
    you only) valid until `token_expires_at` (10 minutes, to start the transfer). FENRIR streams the
    exhibit's plaintext (bounded memory, any size), hashes exactly the bytes it sends (SHA-256, SHA-1,
    MD5) and records them on the copy when the transfer ends: `complete` (verified_against_master = the
    copy's SHA-256 equals the master's), `aborted` (stopped early: client_disconnected or read_error) or
    `failed_integrity` (the stored master failed its check: the exhibit is frozen, as Verify does).
    Compare your own hash of the file with the one recorded (GET …/working-copies).

    Requires the analyst role and access to the incident (any analyst who can see it); the item must be
    an active digital file (not frozen) with its file stored, held by an internal custodian, no transfer
    pending (409). Allowed on a closed incident (a custody action, like accepting a transfer)."""
    await _get_incident(db, incident_id, user)
    ev = await _get_evidence(db, incident_id, evidence_id, for_update=True)
    if (err := _working_copy_state_error(ev)) is not None:
        raise err
    if not ev.storage_path or not ev.nonce_hex or not ev.sha256:
        raise ApiError(status.HTTP_409_CONFLICT, "evidence_storage_missing",
                       "The exhibit has no stored file or recorded hash to copy")

    token, token_hash = wcs.new_token()
    expires = utcnow() + wcs.TOKEN_TTL
    seq = await wcs.next_copy_seq(db, ev.id)
    copy = EvidenceCopy(
        id=uuid.uuid4(), evidence_id=ev.id, role="working", kind="download",
        copy_seq=seq, copy_identifier=f"{ev.identifier}-WC-{seq}", status="issued",
        verified_against_master=False,
        created_by_id=user.id, created_by_qualifications=user.qualifications,
        purpose=req.purpose, destination_note=req.destination_note,
        token_hash=token_hash, token_expires_at=expires,
    )
    db.add(copy)
    await db.flush()
    await write_audit(
        db, "evidence_working_copy_issued",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id), outcome="success",
        details={
            "incident_id": str(incident_id),
            "working_copy_id": str(copy.id),
            "copy_identifier": copy.copy_identifier,
            "kind": "download",
            "issued_to_id": str(user.id),
            "purpose": req.purpose,
            "destination_note": req.destination_note,
            "master_sha256": ev.sha256,
            "file_size_bytes": ev.file_size_bytes,
            "link_expires_at": _utc_z(expires),
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return WorkingCopyIssued(
        copy=wcs.copy_out(copy),
        download_url=(f"/api/incidents/{incident_id}/evidence/{ev.id}/working-copies/{copy.id}/download"
                      f"?token={token}"),
        token_expires_at=expires,
    )


def _download_name(copy_identifier: str, original: Optional[str]) -> str:
    name = f"{copy_identifier}__{Path(original or 'exhibit.bin').name}"
    return re.sub(r"[^\w.\-]", "_", name)[:200]


@router.get(
    "/{incident_id}/evidence/{evidence_id}/working-copies/{copy_id}/download",
    summary="Download an issued working copy (one-time link)",
    responses={
        200: {"description": "The copy's bytes (application/octet-stream) with Content-Length. Above 16 MiB "
                             "the body streams as it is decrypted: if the stored master fails its integrity "
                             "check part-way, the server closes the connection short of Content-Length (treat "
                             "a short body as a failed download; the copy is recorded failed_integrity).",
              "content": {"application/octet-stream": {}}},
        404: {"model": ApiErrorBody, "description": "working_copy_not_found (unknown, not yours, or a wrong token)"},
        409: {"model": ApiErrorBody, "description": _WC_STATE_DOC + ", evidence_storage_missing, or "
                                                    "evidence_integrity_failed (the stored master failed its "
                                                    "check before the first byte: frozen)"},
        410: {"model": ApiErrorBody, "description": "download_link_used / download_link_expired"},
        **_READ_ERROR_DOC,
    },
)
async def download_working_copy(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    copy_id:     uuid.UUID,
    request:     Request,
    token:       str = Query(min_length=16, max_length=128, description="The one-time token from the issue response"),
    user:        User = Depends(require_analyst),
    db:          AsyncSession = Depends(get_db),
) -> Response:
    """The one-time link of an issued working copy (POST …/working-copies). Works once, for the user who
    issued it, until it expires; the claim is atomic (a second use → 410 download_link_used). Streams the
    exhibit's plaintext and records on the copy, when the response ends, the SHA-256 / SHA-1 / MD5 of
    exactly the bytes sent, the byte count and the outcome (complete, aborted or failed_integrity; custody
    log `evidence_working_copy_complete` / `_aborted` / `_failed`). An integrity failure of the stored
    master freezes the exhibit. The exhibit must still be active, internally held, with no transfer
    pending (409; the link stays usable until it expires). Headers: `X-Working-Copy-Id`,
    `X-Working-Copy-Identifier`, `X-Master-SHA256` (the hash a complete copy must have)."""
    await _get_incident(db, incident_id, user)
    # L4: the exhibit's state is checked and the link claimed under its row lock (released by the claim's
    # commit), so a transfer, dispose or freeze can't land between the check and the claim.
    ev = await _get_evidence(db, incident_id, evidence_id, for_update=True)
    copy = (await db.execute(
        select(EvidenceCopy).where(EvidenceCopy.id == copy_id, EvidenceCopy.evidence_id == ev.id)
    )).scalar_one_or_none()
    not_found = ApiError(status.HTTP_404_NOT_FOUND, "working_copy_not_found",
                         "No working copy of this item was issued to you with this link")
    if copy is None or copy.kind != "download" or copy.created_by_id != user.id:
        raise not_found
    if copy.status != "issued":
        raise ApiError(status.HTTP_410_GONE, "download_link_used",
                       f"This link was already used ({copy.copy_identifier} is "
                       f"{wcs.effective_status(copy)}). Issue a new working copy.")
    if not wcs.token_matches(copy.token_hash, token):
        raise not_found
    now = utcnow()
    if copy.token_expires_at is None or copy.token_expires_at <= now:
        raise ApiError(status.HTTP_410_GONE, "download_link_expired",
                       f"This link expired at {_utc_z(copy.token_expires_at)}. Issue a new working copy.")
    if (err := _working_copy_state_error(ev)) is not None:
        raise err
    if not ev.storage_path or not ev.nonce_hex or not ev.sha256:
        raise ApiError(status.HTTP_409_CONFLICT, "evidence_storage_missing",
                       "The exhibit has no stored file or recorded hash to copy")

    claimed = await db.execute(
        update(EvidenceCopy)
        .where(EvidenceCopy.id == copy.id, EvidenceCopy.status == "issued",
               EvidenceCopy.token_hash == copy.token_hash, EvidenceCopy.token_expires_at > now)
        .values(status="downloading", download_started_at=now, token_hash=None)
    )
    await db.commit()
    if claimed.rowcount != 1:
        raise ApiError(status.HTTP_410_GONE, "download_link_used", "This link was already used")

    ip = request.client.host if request.client else None
    end = dict(copy_id=copy.id, ev_id=ev.id, master_sha256=ev.sha256, incident_id=incident_id, user=user, ip=ip)
    try:
        resp = await decrypted_download(ev.storage_path, ev.nonce_hex, ev.file_size_bytes,
                                        media_type="application/octet-stream")
    except EvidenceIntegrityError as e:
        tally = wcs._Tally()
        tally.failure, tally.failure_reason = "integrity", e.reason
        await wcs.record_download_end(db, tally=tally, **end)
        raise ApiError(status.HTTP_409_CONFLICT, "evidence_integrity_failed",
                       "The stored exhibit failed its integrity check; nothing was sent. The item has been "
                       "frozen (verify_failed) pending admin review.") from e
    except EvidenceCryptoError as e:
        tally = wcs._Tally()
        tally.failure, tally.failure_reason = "read_error", e.reason
        await wcs.record_download_end(db, tally=tally, **end)
        raise _read_error() from e
    if not isinstance(resp, StreamingResponse) and len(resp.body) != ev.file_size_bytes:
        # R3-5: a body authenticated whole (≤ 16 MiB, or any v0 file, whose format has no size check of its
        # own) must be exactly the row's size: otherwise the stored record is wrong — integrity, frozen.
        tally = wcs._Tally()
        tally.failure, tally.failure_reason = "integrity", "size_mismatch"
        await wcs.record_download_end(db, tally=tally, **end)
        raise ApiError(status.HTTP_409_CONFLICT, "evidence_integrity_failed",
                       f"The stored exhibit holds {len(resp.body)} bytes, not the {ev.file_size_bytes} recorded; nothing "
                       "was sent. The item has been frozen (verify_failed) pending admin review.")

    async def on_end(tally) -> None:
        await wcs.record_download_end(db, tally=tally, **end)

    name = _download_name(copy.copy_identifier, ev.original_filename)
    return wcs.tracked(resp, ev.file_size_bytes, on_end=on_end, media_type="application/octet-stream", headers={
        "Content-Disposition": f'attachment; filename="{name}"',
        "Cache-Control": "no-store",
        "X-Working-Copy-Id": str(copy.id),
        "X-Working-Copy-Identifier": copy.copy_identifier,
        "X-Master-SHA256": ev.sha256,
    })


# ─── G5 (R09/R75): legal hold ────────────────────────────────────────────────

@router.put(
    "/{incident_id}/evidence/{evidence_id}/legal-hold",
    response_model=EvidenceOut,
    summary="Set or release a legal hold",
    responses={403: {"model": ApiErrorBody, "description": "not_incident_lead (release: only the incident lead or "
                                                           "an admin)"},
               409: {"model": ApiErrorBody, "description": "legal_hold_unchanged (already in that state), "
                                                           "evidence_destroyed (set on a destroyed item)"}},
)
async def set_legal_hold(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    req:     LegalHoldChange,
    request: Request,
    user:    User = Depends(require_analyst),
    db:      AsyncSession = Depends(get_db),
) -> EvidenceOut:
    """Put an item on legal hold (`legal_hold: true`) or release it (`false`), with a reason. Setting a
    hold preserves, so any analyst who can see the incident may; releasing one is for the incident lead
    (Incident Commander / Deputy) or an admin (403 not_incident_lead). Audited
    `evidence_legal_hold_set` / `evidence_legal_hold_released` in the custody log; the item shows
    `legal_hold_since`, `legal_hold_by_id` and `legal_hold_reason` while held. A held item can't be
    destroyed (409 legal_hold_active on dispose); returning or archiving it needs a second approver.
    Allowed on a closed incident (preservation outlives closure). 409 legal_hold_unchanged when the item
    is already in that state; a destroyed item can't be put on hold. Returns the item."""
    inc = await _get_incident(db, incident_id, user)
    ev = await _get_evidence(db, incident_id, evidence_id, for_update=True)
    reason = req.reason.strip()
    if not reason:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "reason_required", "A reason is required")
    if req.legal_hold == bool(ev.legal_hold):
        raise ApiError(status.HTTP_409_CONFLICT, "legal_hold_unchanged",
                       "The item is already on legal hold" if ev.legal_hold else "The item is not on legal hold")
    if req.legal_hold:
        if ev.status == "destroyed":
            raise ApiError(status.HTTP_409_CONFLICT, "evidence_destroyed",
                           "A destroyed item can't be put on legal hold: its file is gone")
        ev.legal_hold, ev.legal_hold_since, ev.legal_hold_by_id, ev.legal_hold_reason = True, utcnow(), user.id, reason
        action, details = "evidence_legal_hold_set", {"reason": reason}
    else:
        lead = await is_incident_lead(db, user, inc)
        if not lead:
            raise not_incident_lead("release a legal hold")
        details = {"reason": reason,
                   "held_since": _utc_z(ev.legal_hold_since),
                   "held_by_id": str(ev.legal_hold_by_id) if ev.legal_hold_by_id else None,
                   "hold_reason": ev.legal_hold_reason,
                   "released_as": "admin" if user.role == "admin" else "incident_lead"}
        ev.legal_hold, ev.legal_hold_since, ev.legal_hold_by_id, ev.legal_hold_reason = False, None, None, None
        action = "evidence_legal_hold_released"
    await write_audit(
        db, action,
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id), outcome="success",
        details={"incident_id": str(incident_id), "identifier": ev.identifier, "status": ev.status,
                 "incident_closed": inc.status == "closed", **details},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return _to_out(ev)


# ─── Exports (Phase 2 legal handoff) ─────────────────────────────────────────

def _to_export_out(exp: CustodyExport) -> ExportOut:
    out = ExportOut.model_validate(exp)
    # Apply expiry overlay so the UI always sees a fresh status.
    out.status = effective_status(exp)
    return out


_NOT_EXPORTABLE = ("destroyed", "verify_failed")


@router.post(
    "/{incident_id}/evidence/exports",
    response_model=ExportCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a custody export bundle (deprecated: POST …/disclosures)",
    deprecated=True,
    responses={status.HTTP_403_FORBIDDEN: {"model": ApiErrorBody, "description": "not_incident_lead"},
               status.HTTP_409_CONFLICT: {
        "model": ApiErrorBody,
        "description": "evidence_not_exportable (an item is destroyed or verify_failed, also when that happened "
                       "while the bundle was built), or evidence_integrity_failed (an item's stored file failed "
                       "its integrity check, or its SHA-256, while it was being bundled: nothing was exported "
                       "and the item was frozen)"},
               status.HTTP_413_CONTENT_TOO_LARGE: {
        "model": ApiErrorBody,
        "description": "export_too_large (the stored files of the selection exceed the 60 GiB one bundle can "
                       "hold: export them in several bundles)"},
               status.HTTP_503_SERVICE_UNAVAILABLE: {
        "model": ApiErrorBody,
        "description": "evidence_read_error (an item's stored file could not be read: nothing was exported; "
                       "audited, admins notified)"},
               507: {"model": ApiErrorBody,
                     "description": "insufficient_storage (the evidence volume has no room for the bundle)"}},
)
async def create_export(
    incident_id: uuid.UUID,
    req:     ExportCreate,
    request: Request,
    lead:    LeadAccess = Depends(require_incident_lead),
    db:      AsyncSession = Depends(get_db),
) -> ExportCreateResponse:
    """**Deprecated (K1):** use `POST /api/incidents/{id}/disclosures` (a signed Disclosure package; purpose
    internal for this use). This route still works, with the disclosure rights and notification.

    Build an AES-256-GCM-encrypted custody export bundle for the chosen
    evidence items (`item_ids`), addressed to a recipient with a stated purpose
    and acknowledgments. K1: incident lead or admin (403 not_incident_lead; was admin only), and every other
    active admin is notified in-app; all items must belong to the incident, and
    destroyed or verify_failed items are refused with 409 before anything is
    written. Only a digital item whose file is stored in FENRIR has its bytes in the
    bundle, and only such an item mints a working-copy ledger row; a
    physical item or a file-less digital item is exported as records only (its manifest
    entry says "not included") and mints no copy. Returns the export record together
    with the one-time download URL/token, the AES key (shown once, delivered
    out-of-band) and the bundle SHA-256.

    M11: an item whose chain of custody is not sealed (an unsealed draft) is left out by default:
    the manifest lists it as "excluded: unsealed draft" with no records or bytes. Set
    `include_unsealed_drafts` to include such items (audited). Every manifest item carries
    `coc_sealed`, `coc_sealed_at` and `lawful_basis`.

    G2: the bundle is streamed (bounded memory whatever the item sizes) into a staging file
    and published only when complete. R3-3: every embedded file is hashed as it is bundled and
    compared with its recorded SHA-256; a mismatch, or a stored file that fails its integrity
    check part-way, discards the whole bundle and freezes the item (verify_failed, audited
    evidence_verify_failed, phase export): 409 evidence_integrity_failed. A file that can't be
    read is 503 evidence_read_error. Nothing is exported in either case. The selection's stored
    files may total at most 60 GiB (413 export_too_large), and the evidence volume must have room
    for them plus a 1 GiB reserve (507 insufficient_storage); both are checked before anything
    is written. M1: the items are locked only while they are checked and again when the export is
    recorded, never during the build (a `pending` export row exists meanwhile); an item disposed or
    frozen during the build makes the export fail with 409 evidence_not_exportable. A multi-GiB
    bundle takes minutes: keep the request open (the key is only in this response). R105: a
    `pending` row whose build died with the server (older than 2 h, not building) is revoked by a
    sweep at startup and every minute (audited, reason abandoned_pending)."""
    building: list[uuid.UUID] = []          # R105: this request's export id while its build runs
    user = lead.user
    try:
        return await _create_export(incident_id, req, request, user, db, building)
    finally:
        export_building.difference_update(building)


async def _create_export(incident_id: uuid.UUID, req: ExportCreate, request: Request, user: User,
                         db: AsyncSession, building: list) -> ExportCreateResponse:
    inc = await _get_incident(db, incident_id, user)
    ip = request.client.host if request.client else None

    # Resolve items, scoped to this incident.
    if not req.item_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Pick at least one item")

    async def _lock_items() -> list[Evidence]:
        # L6: lock the items (and re-read them) so a concurrent dispose can't land between the exportable
        # check and the rows written right after it. M1: held only for that, never across the build.
        q = await db.execute(
            select(Evidence)
            .where(Evidence.incident_id == incident_id,
                   Evidence.id.in_(req.item_ids))
            .order_by(Evidence.id)
            .with_for_update(of=Evidence)
            .execution_options(populate_existing=True)
        )
        return q.scalars().all()

    def _blocked(rows) -> list[str]:
        return sorted(f"{i.identifier} ({i.status})" for i in rows if i.status in _NOT_EXPORTABLE)

    items = await _lock_items()
    missing = set(map(str, req.item_ids)) - {str(i.id) for i in items}
    if missing:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"Evidence not found in this incident: {sorted(missing)}",
        )
    # A destroyed item has no master left and a verify_failed one no longer
    # matches its recorded hash; exporting either would mint a false
    # "verified" working-copy row. Refuse before any bundle or row is written.
    blocked = _blocked(items)
    if blocked:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"detail": "Destroyed or verify-failed evidence cannot be exported: "
                               + ", ".join(blocked),
                     "code": "evidence_not_exportable"},
        )

    included = [i for i in items if req.include_unsealed_drafts or not is_unsealed_draft(i)]
    stored_bytes = sum(i.file_size_bytes or 0 for i in included
                       if i.kind == "digital_file" and i.storage_path and i.nonce_hex)
    if stored_bytes > EXPORT_MAX_PLAINTEXT_BYTES:
        raise ApiError(status.HTTP_413_CONTENT_TOO_LARGE, "export_too_large",
                       f"The selected items' stored files total {stored_bytes / 1024 ** 3:.2f} GiB; one bundle "
                       f"holds at most {EXPORT_MAX_PLAINTEXT_BYTES // 1024 ** 3} GiB. Export them in several bundles.")
    require_free_space(stored_bytes, "this export bundle")

    # M1: a pending export row stands for the build; the row locks go with this commit.
    export = CustodyExport(
        id=uuid.uuid4(), incident_id=inc.id, exported_by_id=user.id,
        recipient=req.recipient, purpose=req.purpose, acknowledgments=req.acknowledgments,
        token=secrets.token_urlsafe(32), status="pending", file_path=None,
        item_ids=[str(ev.id) for ev in included], created_at=utcnow(), expires_at=utcnow() + timedelta(hours=24),
    )
    db.add(export)
    await db.commit()
    building.append(export.id)
    export_building.add(export.id)
    snapshot = {ev.id: (ev.storage_path, ev.nonce_hex) for ev in included}

    async def _fail(code: str, http: int, detail: str, **details) -> ApiError:
        export.status = "revoked"
        await write_audit(
            db, "evidence_export_create",
            user_id=user.id, username=user.username,
            resource_type="custody_export", resource_id=str(export.id), outcome="failure",
            details={"incident_id": str(incident_id), "recipient": req.recipient, "reason": code,
                     "include_unsealed_drafts": req.include_unsealed_drafts, **details},
            ip_address=ip,
        )
        await db.commit()
        return ApiError(http, code, detail)

    try:
        parts, embedded, excluded = await plan_bundle(
            db, inc, items, user, recipient=req.recipient, purpose=req.purpose,
            acknowledgments=req.acknowledgments, export_id=export.id,
            include_unsealed_drafts=req.include_unsealed_drafts)
        await db.commit()                   # no transaction is held open across the build
        staged, key_hex, bundle_size, bundle_sha256, verified = await asyncio.to_thread(_build_staged, parts)
    except ExhibitIntegrityError as e:
        # R3-3 / R95: the stored file failed while it was bundled: freeze it, as Verify and working copies do.
        frozen = await wcs.freeze_for_integrity(db, e.evidence_id, user=user, ip=ip, incident_id=incident_id,
                                                reason=e.reason, recomputed=e.sha256_recomputed, phase="export",
                                                extra={"export_id": str(export.id)})
        raise await _fail("evidence_integrity_failed", status.HTTP_409_CONFLICT,
                          "An item's stored file failed its integrity check while it was being bundled "
                          f"({e.reason or 'integrity'}). Nothing was exported; the item "
                          + ("has been frozen (verify_failed) pending admin review." if frozen
                             else "was not active, so its status was left as it is."),
                          evidence_id=str(e.evidence_id), integrity_reason=e.reason) from e
    except EvidenceIntegrityError as e:
        raise await _fail("evidence_integrity_failed", status.HTTP_409_CONFLICT,
                          "An item's stored file failed its integrity check while it was being bundled "
                          f"({e.reason or 'integrity'}). Nothing was exported. Run Verify on the items to find "
                          "and freeze it.", integrity_reason=e.reason) from e
    except EvidenceCryptoError as e:
        raise await _fail("evidence_read_error", status.HTTP_503_SERVICE_UNAVAILABLE,
                          "An item's stored file could not be read (missing file, storage error or wrong "
                          "EVIDENCE_KEK). Nothing was exported; the attempt was audited and admins were "
                          "notified.", read_reason=e.reason) from e
    except BaseException:
        try:
            export.status = "revoked"
            await db.commit()
        except Exception:
            pass
        raise

    # M1: re-check the items under the lock before anything is recorded or published.
    try:
        items = await _lock_items()
        rechecked = [i for i in items if i.id in snapshot]
        changed = sorted(f"{i.identifier} ({i.status})" for i in rechecked
                         if i.status in _NOT_EXPORTABLE or snapshot[i.id] != (i.storage_path, i.nonce_hex))
        if changed or len(rechecked) != len(snapshot):
            await asyncio.to_thread(staged.discard)
            raise await _fail("evidence_not_exportable", status.HTTP_409_CONFLICT,
                              "An item was disposed, frozen or changed while the bundle was built: nothing was "
                              "exported. " + ", ".join(changed), changed=changed)
        rel_path = f"exports/{export.id}.enc"
        await asyncio.to_thread(staged.commit, rel_path)
    except BaseException:
        await asyncio.to_thread(staged.discard)
        raise

    export.status = "ready"
    export.expires_at = utcnow() + timedelta(hours=24)       # the link's 24 h start when it is offered
    export.file_path = rel_path
    export.file_size = bundle_size
    export.bundle_sha256 = bundle_sha256
    export.key_hint = f"{key_hex[:8]}…{key_hex[-8:]}"
    excluded_ids = {ev.id for ev in excluded}

    # Audit one event per included item plus an overall export event.
    # An item whose bytes are in the bundle also mints a tracked working-copy ledger row
    # (Slice C): those bytes are the master plaintext. R3-3: verified_against_master only when the
    # bytes bundled were hashed and matched the recorded SHA-256. A physical item or a file-less digital
    # item has no bytes in the bundle, so no copy is minted for it (F4 / R07); its export row says
    # bytes_included=false. An excluded unsealed draft gets no row: it was not exported (M11).
    for ev in items:
        if ev.id in excluded_ids:
            continue
        in_bundle = ev.id in embedded
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
                "bytes_included": in_bundle,
                "sha256_verified_at_export": ev.id in verified if in_bundle else None,
            },
            ip_address=ip,
        )
        if not in_bundle:
            continue
        checked = ev.id in verified
        copy = EvidenceCopy(
            id=uuid.uuid4(), evidence_id=ev.id, role="working",
            sha256=ev.sha256, verified_against_master=checked,
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
                "verified_against_master": checked,
                "purpose":     f"Export to {req.recipient}",
            },
            ip_address=ip,
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
            "item_count":    len(items) - len(excluded_ids),
            "bytes_included_count": len(embedded),
            "include_unsealed_drafts": req.include_unsealed_drafts,
            "excluded_unsealed_drafts": sorted(str(i) for i in excluded_ids),
            "bundle_sha256": export.bundle_sha256,
            "expires_at":    _utc_z(export.expires_at),
        },
        ip_address=ip,
    )
    # K1: as for a disclosure package, every other active admin hears about it (commits).
    await notify_disclosure_built(db, incident_id=inc.id, incident_ref=inc.ref or str(inc.id), builder=user,
                                  purpose="evidence_export")

    return ExportCreateResponse(
        export=_to_export_out(export),
        key=key_hex,
        download_url=f"/api/exports/{export.token}",
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
