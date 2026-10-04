"""G3 (R02) — register-first analysers: Email, Browser history and PCAP.

An analyser's input is an exhibit. Two ways in, one store per file:

  * register_or_link_upload() — the direct upload. Before anything is analysed the bytes are hashed
    (SHA-256 / SHA-1 / MD5, off the event loop) and become an exhibit: a new UNSEALED DRAFT (Quick-add
    semantics: auto identifier, collected_by = custodian = the uploader, acquired_at unknown unless
    supplied, lawful basis pending), written AES-256-GCM through the shared evidence writer
    (`evidence.crypto.awrite_encrypted`, the one the evidence upload route uses) and audited
    `evidence_collect` — or, when the SHA-256 equals exactly one active digital exhibit of the
    incident, that exhibit (no second copy). The draft is completed and sealed later through
    PATCH …/evidence/{id}/acquisition-record + …/seal. The chunked upload (evidence/uploads.py,
    G1 stage 3b) registers the same draft through unique_sha256_match + register_draft, from a file
    encrypted as it arrived (its partial file is discarded when an exhibit matches).
  * read_exhibit_for_analysis() — from a registered exhibit: the C5/G4 rules (active, internal
    custody, no pending transfer; decrypt + re-hash in a thread; a mismatch or a failed AES-GCM tag
    freezes the item → 409 evidence_hash_mismatch; an unreadable copy → 503 evidence_read_error).

Every analysis of an exhibit is written to its custody log as `evidence_examine` (tool = analyser +
version, examined_on) by the caller.

R93 (G-fix B): after a chunked upload the client analyses the exhibit through …/from-evidence/{id}; passing
`upload_id` there makes the run record keep how the upload got the exhibit (registered | sha256_match), read
from the caller's own `upload_session_complete` audit row (upload_link_for); the custody log still records the
from-evidence examination of the re-verified master.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import status
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from core.errors import ApiError
from evidence.crypto import EvidenceIntegrityError, StoredFile, adelete_encrypted, awrite_encrypted
from evidence import codec
from evidence.hashing import ahashes_of
from evidence.streaming import require_free_space
from forensic.routes import _exhibit_state_error, _lock_exhibit, _read_exhibit, exhibit_too_large
from models import AuditLog, Evidence, User, utcnow

log = logging.getLogger("fenrir.evidence.register")

# Recorded in the custody log (evidence_examine.examined_on).
EXAMINED_UPLOAD = "the uploaded bytes registered as this exhibit (same SHA-256), analysed in memory"
EXAMINED_MATCH = "an uploaded copy whose SHA-256 equals the exhibit's, analysed in memory"
EXAMINED_MASTER = "hash-verified in-memory copy of the master"


@dataclass
class ExhibitInput:
    evidence: Evidence
    data: bytes
    sha256: str
    link: str          # registered | sha256_match | from_evidence


def utc_z(dt: Optional[datetime]) -> Optional[str]:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if dt else None


def _storage_path(incident_id: uuid.UUID, evidence_id: uuid.UUID, filename: str) -> str:
    # Same layout as evidence/routes.py `_storage_path_for` (basename only, no traversal).
    safe = (filename or "upload.bin").replace("/", "_").replace("\\", "_")
    return f"{incident_id}/{evidence_id}__{safe}.enc"


async def unique_sha256_match(db: AsyncSession, incident_id: uuid.UUID, sha256: str, *,
                              oldest: bool = False) -> Optional[Evidence]:
    """The one active digital exhibit of the incident with this SHA-256 (a stored file), or None
    when there is none or more than one. `oldest` (register-first, M8): with several, the oldest
    (registered first), so an upload never registers yet another copy of bytes already held."""
    matches = (await db.execute(
        select(Evidence).where(Evidence.incident_id == incident_id, Evidence.sha256 == sha256,
                               Evidence.status == "active", Evidence.kind == "digital_file",
                               Evidence.storage_path.isnot(None))
        .order_by(Evidence.collected_at.asc(), Evidence.id.asc()).limit(2)
    )).scalars().all()
    if oldest:
        return matches[0] if matches else None
    return matches[0] if len(matches) == 1 else None


async def lock_upload_sha256(db: AsyncSession, incident_id: uuid.UUID, sha256: str) -> None:
    """M8: serialise "match, else register" for the same bytes in the same incident until the caller's
    transaction ends, so two concurrent uploads of one file register one exhibit, never two. A
    transaction-level advisory lock in its own key space (the two-key form: never the audit chain's)."""
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext('fenrir.register_first'), hashtext(:k))"),
                     {"k": f"{incident_id}|{sha256}"})


def custody_state_error(ev: Evidence) -> Optional[str]:
    """L22: why an upload that matches this exhibit by SHA-256 must not write an examination to its
    custody log (it is not in internal custody, or a transfer is pending), else None."""
    if ev.current_custodian_id is None:
        return "evidence_not_in_internal_custody"
    if ev.pending_custodian_id is not None:
        return "transfer_pending"
    return None


def draft_storage_path(incident_id: uuid.UUID, ev_id: uuid.UUID, filename: str) -> tuple[str, str]:
    """(the safe original filename, the draft exhibit's storage path)."""
    filename = Path(filename or "upload.bin").name[:255] or "upload.bin"
    return filename, _storage_path(incident_id, ev_id, filename)


async def register_or_link_upload(
    db: AsyncSession, *, incident_id: uuid.UUID, user: User, data: bytes, filename: str,
    mime_type: Optional[str], prefix: str, name: str, method: str, analyser_label: str,
    acquired_at: Optional[datetime] = None, ip: Optional[str] = None, extra: Optional[dict] = None,
) -> ExhibitInput:
    """Register `data` as an unsealed draft exhibit (or link the one active exhibit with the same
    SHA-256). Flushes and audits; the caller commits. `prefix` = identifier prefix (EMAIL / PCAP /
    WEBHIST), `method` = the audit `method` (email_upload / pcap_upload / webhistory_upload)."""
    sha256, sha1, md5 = await ahashes_of(data)
    await lock_upload_sha256(db, incident_id, sha256)          # M8: held until the caller commits
    match = await unique_sha256_match(db, incident_id, sha256, oldest=True)
    if match is not None:
        return ExhibitInput(match, data, sha256, "sha256_match")

    require_free_space(codec.container_size(len(data)), "this exhibit")   # L2: 507, nothing stored
    ev_id = uuid.uuid4()
    filename, rel = draft_storage_path(incident_id, ev_id, filename)
    stored = await awrite_encrypted(data, rel)                # the shared evidence writer (encrypt at rest)
    try:
        ev = await register_draft(db, incident_id=incident_id, user=user, ev_id=ev_id, filename=filename,
                                  stored=stored, mime_type=mime_type, prefix=prefix, name=name, method=method,
                                  analyser_label=analyser_label, acquired_at=acquired_at, ip=ip, extra=extra)
    except BaseException:
        await adelete_encrypted(rel)                          # L23: no row, so no file left behind
        raise
    return ExhibitInput(ev, data, sha256, "registered")


async def register_draft(
    db: AsyncSession, *, incident_id: uuid.UUID, user: User, ev_id: uuid.UUID, filename: str,
    stored: StoredFile, mime_type: Optional[str], prefix: str, name: str, method: str, analyser_label: str,
    acquired_at: Optional[datetime] = None, ip: Optional[str] = None, extra: Optional[dict] = None,
) -> Evidence:
    """The unsealed draft exhibit row + its `evidence_collect` audit for a file already stored (as
    draft_storage_path(...)[1]) — shared by register_or_link_upload and the G1 stage 3b chunked upload
    (evidence/uploads.py). Flushes and audits; the caller commits."""
    sha256, sha1, md5 = stored.sha256, stored.sha1, stored.md5
    identifier = f"{prefix}-{ev_id.hex[:10].upper()}"
    for _ in range(3):                       # an identifier clash is practically impossible; never 500
        taken = (await db.execute(select(Evidence.id).where(
            Evidence.incident_id == incident_id, Evidence.identifier == identifier))).first()
        if not taken:
            break
        identifier = f"{prefix}-{uuid.uuid4().hex[:10].upper()}"
    rel = stored.relative_path
    ev = Evidence(
        id=ev_id, incident_id=incident_id, kind="digital_file", status="active",
        name=name[:256], identifier=identifier,
        description=(f"Draft exhibit registered by the {analyser_label} upload ({filename}). "
                     "Complete the acquisition record and seal it."),
        tlp="amber", original_filename=filename, storage_path=rel, nonce_hex=stored.nonce_hex,
        file_size_bytes=stored.size, mime_type=mime_type,
        sha256=sha256, sha1=sha1, md5=md5,
        current_custodian_id=user.id, collected_by_id=user.id, collected_at=utcnow(),
        acquired_at=acquired_at, upload_hash_check="not_checked",
        collected_by_qualifications=user.qualifications,
    )
    db.add(ev)
    await db.flush()
    await write_audit(
        db, "evidence_collect",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id), outcome="success",
        details={
            "incident_id": str(incident_id), "kind": "digital_file",
            "identifier": identifier, "name": ev.name, "sha256": sha256,
            "file_size_bytes": stored.size, "tlp": "amber",
            "original_filename": filename, "mime_type": mime_type,
            "acquired_at": utc_z(acquired_at), "upload_hash_check": "not_checked",
            "method": method, "draft": True, "sealed": False, **(extra or {}),
        },
        ip_address=ip,
    )
    return ev


async def examine_audit(db: AsyncSession, *, user: User, ip: Optional[str], evidence_id, details: dict,
                        outcome: str = "success") -> None:
    """The exhibit's `evidence_examine` custody row. L22: for an upload that only matched the exhibit by
    SHA-256 (method upload_sha256_match) while the exhibit is in external custody or awaiting a transfer,
    no custody row is written — it was not examined in this custody — and the skip is logged; the analysis
    keeps its run record (exhibit_link sha256_match)."""
    if details.get("method") == "upload_sha256_match":
        ev = (await db.execute(select(Evidence).where(Evidence.id == evidence_id))).scalar_one_or_none()
        why = custody_state_error(ev) if ev is not None else None
        if why is not None:
            log.info("evidence_examine for %s not written (upload_sha256_match, %s)", evidence_id, why)
            return
    await write_audit(db, "evidence_examine", user_id=user.id, username=user.username,
                      resource_type="evidence", resource_id=str(evidence_id), outcome=outcome,
                      details=details, ip_address=ip)


async def read_exhibit_for_analysis(
    db: AsyncSession, *, incident_id: uuid.UUID, evidence_id: uuid.UUID, user: User, ip: Optional[str],
    max_bytes: int, limit_label: str, phase: str, base: dict,
) -> ExhibitInput:
    """The C5/G4 from-evidence read: the exhibit must be a digital file of this incident that is
    active, in internal custody and not awaiting a transfer (409 otherwise); no larger than the
    analyser's cap (413 exhibit_too_large_for_analyser, before anything is decrypted); decrypted and
    re-hashed off the event loop, in one pass; a SHA-256 mismatch (or a failed AES-GCM tag) freezes an
    item that is still active (`evidence_verify_failed`) → 409 evidence_hash_mismatch; an unreadable copy → 503
    evidence_read_error (not frozen; the failed attempt is audited `evidence_examine` failure).
    `base` = the evidence_examine details (incident_id, tool, version, params). Commits only on the
    failure paths. The caller re-checks the state under `_lock_exhibit` before it writes."""
    ev = (await db.execute(
        select(Evidence).where(Evidence.id == evidence_id, Evidence.incident_id == incident_id)
    )).scalar_one_or_none()
    if ev is None:
        raise ApiError(status.HTTP_404_NOT_FOUND, "evidence_not_found", "Evidence not found in this incident")
    if ev.kind != "digital_file":
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "evidence_not_digital",
                       "Only a digital-file exhibit can be analysed")
    if (err := _exhibit_state_error(ev)) is not None:
        raise err
    if not ev.storage_path or not ev.nonce_hex or not ev.sha256:
        raise ApiError(status.HTTP_409_CONFLICT, "evidence_storage_missing",
                       "The exhibit has no stored file or recorded hash to verify against")
    if (ev.file_size_bytes or 0) > max_bytes:
        raise exhibit_too_large(limit_label)
    recorded = ev.sha256
    try:
        data, computed = await asyncio.to_thread(_read_exhibit, ev.storage_path, ev.nonce_hex, ev.file_size_bytes)
    except EvidenceIntegrityError:          # AES-GCM tag failed: the stored ciphertext was altered
        data, computed = None, None
    except Exception as exc:                # missing file / storage I/O: unreadable, not tampered
        await examine_audit(db, user=user, ip=ip, evidence_id=evidence_id, outcome="failure",
                            details={**base, "result": "read_error", "error": f"{type(exc).__name__}: {exc}"[:500]})
        await db.commit()
        raise ApiError(status.HTTP_503_SERVICE_UNAVAILABLE, "evidence_read_error",
                       "The exhibit's stored copy could not be read (storage error). Nothing was "
                       "analysed and the item was not frozen; try again or ask an admin to check "
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
            details={"incident_id": str(incident_id), "phase": phase,
                     "sha256_recorded": recorded, "sha256_recomputed": computed,
                     "status_before": status_before, "frozen": frozen},
            ip_address=ip,
        )
        await db.commit()
        raise ApiError(status.HTTP_409_CONFLICT, "evidence_hash_mismatch",
                       "The stored exhibit no longer matches the SHA-256 recorded at collection; "
                       + ("it has been frozen (verify_failed) pending admin review."
                          if frozen else f"its status ('{status_before}') was left as it is.")
                       + " Nothing was analysed.")
    return ExhibitInput(ev, data, computed, "from_evidence")


async def recheck_exhibit(db: AsyncSession, *, incident_id: uuid.UUID, evidence_id, user: User,
                          ip: Optional[str], base: dict) -> Evidence:
    """After a long decrypt/analysis: re-read the exhibit under a row lock; a transfer, dispose or
    freeze that happened meanwhile wins — the attempt is audited and nothing is stored."""
    ev = await _lock_exhibit(db, incident_id, evidence_id)
    if (err := _exhibit_state_error(ev)) is not None:
        await examine_audit(db, user=user, ip=ip, evidence_id=evidence_id, outcome="failure",
                            details={**base, "result": "discarded_state_changed", "error": err.detail})
        await db.commit()
        raise err
    return ev


async def exhibit_brief(db: AsyncSession, ids) -> dict:
    """{evidence_id: (identifier, coc_sealed)} for an analysis's exhibit pill (draft = not sealed)."""
    ids = {i for i in ids if i}
    if not ids:
        return {}
    rows = (await db.execute(select(Evidence.id, Evidence.identifier, Evidence.coc_sealed)
                             .where(Evidence.id.in_(ids)))).all()
    return {r[0]: (r[1], bool(r[2])) for r in rows}


UPLOAD_ID_DOC = ("Optional (R93): the chunked upload (POST …/uploads, purpose of this analyser) that registered or "
                 "matched this exhibit, completed by you on this incident. The run record then keeps the upload's "
                 "link (registered | sha256_match) instead of from_evidence; 422 upload_link_not_found otherwise.")


async def upload_link_for(db: AsyncSession, *, upload_id: Optional[uuid.UUID], incident_id: uuid.UUID,
                          evidence_id: uuid.UUID, purpose: str, user: User) -> Optional[str]:
    """R93: the exhibit link (registered | sha256_match) of the caller's own completed upload session
    `upload_id` of `purpose` on this incident that became `evidence_id` — from its hash-chained
    `upload_session_complete` audit row, never from the client. None without upload_id; 422
    upload_link_not_found when there is no such completed upload."""
    if upload_id is None:
        return None
    rows = (await db.execute(
        select(AuditLog.details).where(AuditLog.action == "upload_session_complete",
                                       AuditLog.resource_type == "upload_session",
                                       AuditLog.resource_id == str(upload_id),
                                       AuditLog.user_id == user.id, AuditLog.outcome == "success")
    )).scalars().all()
    for d in rows:
        d = d or {}
        if (d.get("incident_id") == str(incident_id) and d.get("evidence_id") == str(evidence_id)
                and d.get("purpose") == purpose and d.get("exhibit_link") in ("registered", "sha256_match")):
            return d["exhibit_link"]
    raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "upload_link_not_found",
                   f"upload_id is not a {purpose} upload you completed on this incident into this exhibit; leave "
                   "it out to record the run as from_evidence.")


def link_error_extra(x: ExhibitInput) -> dict:
    """The exhibit an analysis failure refers to (an upload stays registered even if its analysis fails)."""
    return {"evidence_id": str(x.evidence.id), "evidence_identifier": x.evidence.identifier,
            "exhibit_link": x.link}
