"""K1 (R36): Disclosure packages — one court path for Evidence › Export and the LE package.

`create_disclosure` builds the package (le_package.builder, streamed, G2), records it (CustodyExport for the
one-time download + LePackage + the `le_package_generate` audit anchor), custody-logs every exhibit in it
(`evidence_export`, plus a working-copy ledger row and `evidence_copy_mint` for each exhibit whose bytes are in
it, as the export did), freezes an exhibit that failed its integrity check while it was read, and tells every
other active admin in-app. Used by POST …/disclosures and the deprecated POST …/le-package. The caller checks
the rights (incident lead or admin) and the purpose's required fields.
"""
from __future__ import annotations

import asyncio
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import NamedTuple, Optional

from fastapi import status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from core.config import settings
from core.errors import ApiError
from evidence.crypto import EvidenceCryptoError, EvidenceIntegrityError
from evidence.streaming import require_free_space
from evidence.working_copies import freeze_for_integrity
from le_package.builder import BuildResult, build_le_package, estimate_package_bytes
from models import AuditLog, CustodyExport, Evidence, EvidenceCopy, Incident, LePackage, User
from notifications.service import notify_disclosure_built

NOT_DISCLOSABLE = ("destroyed", "verify_failed")
SIGNATURE_KIND = "ed25519+hmac-sha256"
_PURPOSE_LABEL = {"law_enforcement": "LE package", "regulator": "Regulator disclosure",
                  "internal": "Internal disclosure"}


class Disclosure(NamedTuple):
    lp: LePackage
    cust: CustodyExport
    anchor: AuditLog
    build: BuildResult
    ack_token: Optional[str]


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _snapshot(db: AsyncSession, inc_id: uuid.UUID, item_ids, legal_hold_only: bool, *, lock: bool) -> dict:
    """{exhibit id: (status, storage_path, nonce_hex, identifier)} of the exhibits the package covers (M1: under a
    row lock when `lock`, only for the re-check right before anything is recorded)."""
    q = select(Evidence).where(Evidence.incident_id == inc_id)
    if item_ids is not None:
        q = q.where(Evidence.id.in_(item_ids))
    if legal_hold_only:
        q = q.where(Evidence.legal_hold.is_(True))
    if lock:
        q = q.order_by(Evidence.id).with_for_update(of=Evidence)
    rows = (await db.execute(q.execution_options(populate_existing=True))).scalars().all()
    return {e.id: (e.status, e.storage_path, e.nonce_hex, e.identifier) for e in rows}


async def create_disclosure(
    db: AsyncSession, *, inc: Incident, user: User, purpose: str,
    case_reference: str, requesting_authority: str, legal_basis: str, recipient: str,
    retention_until: Optional[datetime], legal_hold_only: bool, include_artifacts: bool,
    include_unsealed_drafts: bool, item_ids: Optional[list[uuid.UUID]], extras: dict,
    enable_acknowledgment: bool,
) -> Disclosure:
    """Build, record, custody-log and announce one Disclosure package. Commits. Raises ApiError: 409
    evidence_integrity_failed / evidence_not_exportable, 503 evidence_read_error, 507 insufficient_storage."""
    size_estimate = await estimate_package_bytes(db, inc.id, legal_hold_only=legal_hold_only,
                                                 include_artifacts=include_artifacts,
                                                 include_unsealed_drafts=include_unsealed_drafts, item_ids=item_ids)
    require_free_space(size_estimate, "this disclosure package")
    before = await _snapshot(db, inc.id, item_ids, legal_hold_only, lock=False)
    await db.commit()                       # no transaction (or row lock) is held open across the build
    try:
        build = await build_le_package(
            db=db, inc=inc, user=user, case_reference=case_reference,
            requesting_authority=requesting_authority, legal_basis=legal_basis,
            retention_until=retention_until, legal_hold_only=legal_hold_only,
            include_artifacts=include_artifacts, quarantine_path=settings.quarantine_path,
            size_estimate=size_estimate, include_unsealed_drafts=include_unsealed_drafts,
            purpose=purpose, item_ids=item_ids,
        )
    except EvidenceIntegrityError as e:
        raise ApiError(status.HTTP_409_CONFLICT, "evidence_integrity_failed",
                       "An exhibit's stored file changed while it was being written into the package: it failed "
                       f"its integrity check ({e.reason or 'integrity'}). Nothing was built. Run Verify on the "
                       "incident's exhibits, then build the package again.") from e
    except EvidenceCryptoError as e:
        raise ApiError(status.HTTP_503_SERVICE_UNAVAILABLE, "evidence_read_error",
                       "An exhibit's stored file stopped being readable while it was being written into the "
                       "package (storage error). Nothing was built; the attempt was audited and admins were "
                       "notified.") from e

    # M1 (as the export): an exhibit disposed, frozen or re-stored by someone else during the build makes the
    # whole package fail; re-checked under the row locks, which this transaction keeps until it commits.
    export_id = uuid.uuid4()
    try:
        own = {f["evidence_id"] for f in build.integrity_failures}      # frozen below, by this request
        after = await _snapshot(db, inc.id, [d["evidence_id"] for d in build.disclosed], False, lock=True)
        changed = sorted(f"{v[3]} ({v[0]})" for k, v in after.items()
                         if k not in own and k in before and before[k][:3] != v[:3])
        if changed:
            raise ApiError(status.HTTP_409_CONFLICT, "evidence_not_exportable",
                           "An exhibit was disposed, frozen or changed while the package was built: nothing was "
                           "disclosed. " + ", ".join(changed))
        rel_path = f"exports/{export_id}.zip"
        await asyncio.to_thread(build.staged.commit, rel_path)      # not on the event loop
    except BaseException:
        await asyncio.to_thread(build.staged.discard)
        raise

    token = secrets.token_urlsafe(32)
    expires_at = _now() + timedelta(hours=24)
    key_hint = f"{build.bundle_password[:4]}…{build.bundle_password[-4:]}"
    disclosed_ids = [d["evidence_id"] for d in build.disclosed]
    label = _PURPOSE_LABEL[purpose]
    cust = CustodyExport(
        id=export_id, incident_id=inc.id, exported_by_id=user.id, recipient=recipient[:256],
        purpose=f"{label} — {case_reference}", acknowledgments=f"legal_basis={legal_basis}",
        token=token, status="ready", file_path=rel_path, file_size=build.bundle_size,
        bundle_sha256=build.bundle_sha256, key_hint=key_hint, item_ids=[str(i) for i in disclosed_ids],
        created_at=_now(), expires_at=expires_at,
    )
    db.add(cust)
    await db.flush()                        # before the copies below reference it (autoflush-ordering trap)

    # The package's proof of record in the hash-chained audit log (README/SOP name this action).
    anchor = await write_audit(
        db, "le_package_generate",
        user_id=user.id, username=user.username, role_at_time=user.role, outcome="success",
        resource_type="le_package", resource_id=str(export_id), resource_label=case_reference,
        details={
            "purpose":              purpose,
            "case_reference":       case_reference,
            "requesting_authority": requesting_authority,
            "legal_basis":          legal_basis,
            "recipient":            recipient,
            "retention_until":      retention_until.isoformat() if retention_until else None,
            "legal_hold_only":      legal_hold_only,
            "include_artifacts":    include_artifacts,
            "item_ids":             None if item_ids is None else sorted(str(i) for i in item_ids),
            "incident_id":          str(inc.id),
            "incident_ref":         inc.ref,
            "bundle_sha256":        build.bundle_sha256,
            "manifest_sha256":      build.manifest_sha256,
            "hmac_sha256":          build.hmac_sha256,
            "manifest_ed25519_sig": build.manifest_signature_b64,
            "file_count":           build.file_count,
            "total_bytes":          build.total_bytes,
            "evidence_count":       build.evidence_count,
            "audit_row_count":      build.audit_row_count,
            "custody_export_id":    str(export_id),
            "expires_at":           expires_at.isoformat(),
            "key_hint":             key_hint,
            "include_unsealed_drafts": include_unsealed_drafts,
            "unsealed_drafts_excluded": len(build.excluded_drafts),
            "unsealed_drafts_excluded_identifiers": build.excluded_drafts,
            "integrity_failures":   [{"evidence_id": str(f["evidence_id"]), "identifier": f["identifier"],
                                      "integrity": f["integrity"]} for f in build.integrity_failures],
        },
    )
    ack_token = secrets.token_urlsafe(32) if enable_acknowledgment else None
    lp = LePackage(
        id=uuid.uuid4(), incident_id=inc.id, custody_export_id=export_id, purpose=purpose,
        case_reference=case_reference, requesting_authority=requesting_authority, legal_basis=legal_basis,
        retention_until=retention_until, legal_hold_only=legal_hold_only, include_artifacts=include_artifacts,
        prepared_by_id=user.id, prepared_at=_now(),
        bundle_sha256=build.bundle_sha256, manifest_sha256=build.manifest_sha256, hmac_sha256=build.hmac_sha256,
        audit_anchor_row_id=anchor.id, file_count=build.file_count, total_bytes=build.total_bytes,
        evidence_count=build.evidence_count, audit_row_count=build.audit_row_count,
        signature_kind=SIGNATURE_KIND, acknowledgment_token=ack_token, **extras,
    )
    db.add(lp)
    await db.flush()

    # Custody: every exhibit in the package gets its own evidence_export row (in the custody log); one whose
    # bytes are in it also gets a working-copy ledger row (verified only when the bytes matched the recorded
    # SHA-256) and evidence_copy_mint, as Evidence › Export did.
    for d in build.disclosed:
        ev_id = d["evidence_id"]
        base = {"incident_id": str(inc.id), "disclosure_id": str(lp.id), "export_id": str(export_id),
                "purpose": purpose, "recipient": recipient}
        await write_audit(
            db, "evidence_export", user_id=user.id, username=user.username, outcome="success",
            resource_type="evidence", resource_id=str(ev_id),
            details={**base, "bundle_sha256": build.bundle_sha256, "key_hint": key_hint,
                     "bytes_included": d["bytes_included"],
                     "sha256_verified_at_export": d["sha256_verified"] if d["bytes_included"] else None},
        )
        if not d["bytes_included"]:
            continue
        sha = (await db.execute(select(Evidence.sha256).where(Evidence.id == ev_id))).scalar_one()
        db.add(EvidenceCopy(
            id=uuid.uuid4(), evidence_id=ev_id, role="working", sha256=sha,
            verified_against_master=bool(d["sha256_verified"]),
            created_by_id=user.id, created_by_qualifications=user.qualifications,
            purpose=f"{label} to {recipient}: {case_reference}", export_id=export_id,
        ))
        await write_audit(
            db, "evidence_copy_mint", user_id=user.id, username=user.username, outcome="success",
            resource_type="evidence", resource_id=str(ev_id),
            details={**base, "sha256": sha, "verified_against_master": bool(d["sha256_verified"])},
        )
    # R3-2 / R95: an exhibit found tampered (or with another SHA-256) while the package was built is frozen.
    for f in build.integrity_failures:
        await freeze_for_integrity(db, f["evidence_id"], user=user, ip=None, incident_id=inc.id,
                                   reason=f["reason"], recomputed=f["sha256_recomputed"], phase="le_package",
                                   extra={"le_package_id": str(lp.id), "custody_export_id": str(export_id),
                                          "integrity": f["integrity"]})
    await notify_disclosure_built(db, incident_id=inc.id, incident_ref=inc.ref or str(inc.id),   # commits
                                  builder=user, purpose=purpose)
    return Disclosure(lp, cust, anchor, build, ack_token)
