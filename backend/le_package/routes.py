"""LE-package routes.

Endpoints:
  POST   /api/incidents/{id}/le-package   — generate. Incident lead only (admin,
                                            or an analyst assigned IC / Deputy IC).
                                            Returns LePackagePrepared with the
                                            bundle KEK shown ONCE + download URL.
  GET    /api/incidents/{id}/le-packages  — list history for the incident.
                                            Incident lead only (LE packages are sensitive).
  GET    /api/incidents/{id}/le-packages/{lp_id} — single row metadata (incident lead).
  POST   /api/incidents/{id}/le-packages/{lp_id}/manual-ack — incident lead.

The encrypted bundle itself is downloaded via the existing single-use
`/api/exports/{token}` endpoint (mounted by `evidence/download.py`). The
LE-package builder reuses that CustodyExport lifecycle — no new download path.
"""
from __future__ import annotations

import asyncio
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from core.config import settings
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from evidence.crypto import EvidenceCryptoError, EvidenceIntegrityError
from evidence.streaming import require_free_space
from evidence.working_copies import freeze_for_integrity
from incidents.access import LeadAccess, require_incident_lead
from le_package.builder import build_le_package, estimate_package_bytes
from models import AuditLog, CustodyExport, Evidence, LePackage
from notifications.service import notify_le_package_built
from schemas import (LePackageAckRequest, LePackageAckResponse,
                     LePackageList, LePackageManualAckRequest,
                     LePackageOut, LePackagePrepare, LePackagePrepared)


router = APIRouter()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _row_to_out(lp: LePackage, cust: CustodyExport,
                anchor_hash: str | None) -> LePackageOut:
    """Compose LePackageOut from joined rows."""
    expired = cust.expires_at is not None and cust.expires_at <= _now_utc()
    status_str = cust.status
    if status_str == "ready" and expired:
        status_str = "expired"
    return LePackageOut(
        id=lp.id,
        incident_id=lp.incident_id,
        case_reference=lp.case_reference,
        requesting_authority=lp.requesting_authority,
        legal_basis=lp.legal_basis,
        retention_until=lp.retention_until,
        legal_hold_only=lp.legal_hold_only,
        include_artifacts=lp.include_artifacts,
        prepared_by_id=lp.prepared_by_id,
        prepared_at=lp.prepared_at,
        bundle_sha256=lp.bundle_sha256,
        manifest_sha256=lp.manifest_sha256,
        hmac_sha256=lp.hmac_sha256,
        file_count=lp.file_count,
        total_bytes=lp.total_bytes,
        evidence_count=lp.evidence_count,
        audit_row_count=lp.audit_row_count,
        audit_anchor_row_id=lp.audit_anchor_row_id,
        audit_anchor_row_hash=anchor_hash,
        custody_export_id=lp.custody_export_id,
        status=status_str,
        expires_at=cust.expires_at,
        consumed_at=cust.consumed_at,
        key_hint=cust.key_hint,
        # Wizard C — cross-border + recipient + receipt fields.
        eio_reference          = lp.eio_reference,
        issuing_state          = lp.issuing_state,
        executing_state        = lp.executing_state,
        mla_reference          = lp.mla_reference,
        recipient_name         = lp.recipient_name,
        recipient_role         = lp.recipient_role,
        recipient_id_ref       = lp.recipient_id_ref,
        recipient_organisation = lp.recipient_organisation,
        recipient_address      = lp.recipient_address,
        delivery_channel       = lp.delivery_channel,
        delivery_notes         = lp.delivery_notes,
        sender_declaration     = lp.sender_declaration,
        signature_kind         = lp.signature_kind,
        acknowledged_at        = lp.acknowledged_at,
        acknowledged_by_name   = lp.acknowledged_by_name,
    )


@router.post("/{incident_id}/le-package", response_model=LePackagePrepared,
             summary="Build a law-enforcement package",
             responses={403: {"model": ApiErrorBody, "description": "not_incident_lead"},
                        409: {"model": ApiErrorBody,
                              "description": "evidence_integrity_failed (an exhibit's stored file verified, then "
                                             "failed its integrity check while it was written into the package: "
                                             "it changed during the build; nothing was built)"},
                        503: {"model": ApiErrorBody,
                              "description": "evidence_read_error (an exhibit's stored file verified, then could "
                                             "not be read while it was written into the package: nothing was "
                                             "built; audited, admins notified)"},
                        507: {"model": ApiErrorBody,
                              "description": "insufficient_storage (the evidence volume has no room for the "
                                             "package)"}})
async def prepare_le_package(
    incident_id: uuid.UUID,
    req:         LePackagePrepare,
    lead:        LeadAccess = Depends(require_incident_lead),
    db:          AsyncSession = Depends(get_db),
) -> LePackagePrepared:
    """Build a court-ready, encrypted law-enforcement handoff bundle for the
    incident and anchor it in the hash-chained audit log. Incident lead only: an
    admin, or an analyst (effective role) assigned as Incident Commander or Deputy
    Incident Commander on this incident (403 code not_incident_lead; not visible:
    404). When a non-admin builds it, every active admin gets an in-app
    notification (incident ref only).

    The bundle KEK is returned exactly once. The download URL is the standard
    one-time `/api/exports/{token}` link (single use, 24-hour expiry). When
    acknowledgment is enabled, a single-use ack URL is also returned.

    M11 (owner, 2026-10-04): exhibits whose chain of custody is not sealed (unsealed drafts) are left
    out by default — listed in Evidence_Inventory.csv as "excluded: unsealed draft", with no custody
    log or file. `include_unsealed_drafts: true` includes them (audited on the anchor row). The
    inventory gains `coc_sealed`, `coc_sealed_at_utc`, `lawful_basis` and `package_inclusion`.

    G2: the package is streamed into a staging file with bounded memory, whatever the
    exhibit sizes, and published only when complete. Each exhibit is decrypted and
    authenticated whole before it is written: one that is missing or unreadable is listed as
    not included, as before. R3-2: one that fails an integrity check (tampered or corrupt) is
    listed as `integrity_failed:<reason>`, and one whose SHA-256 differs from the recorded one
    as `HASH_MISMATCH_AT_EXPORT`; the package is still built, and each such exhibit is frozen
    (verify_failed, audited evidence_verify_failed, phase le_package). One that fails while it is
    being written (it changed during the build) discards the whole package (409
    evidence_integrity_failed / 503 evidence_read_error, nothing recorded). The evidence
    volume must have room for the package's stored files plus a 1 GiB reserve (507
    insufficient_storage, checked first). A multi-GiB package takes minutes: keep the
    request open (the password is only in this response).
    """
    user, inc = lead

    # 1. Build the encrypted bundle, streamed into /evidence/.staging. Does not commit DB writes.
    size_estimate = await estimate_package_bytes(db, inc.id, legal_hold_only=req.legal_hold_only,
                                                 include_artifacts=req.include_artifacts,
                                                 include_unsealed_drafts=req.include_unsealed_drafts)
    require_free_space(size_estimate, "this LE package")
    try:
        build = await build_le_package(
            db=db,
            inc=inc,
            user=user,
            case_reference=req.case_reference,
            requesting_authority=req.requesting_authority,
            legal_basis=req.legal_basis,
            retention_until=req.retention_until,
            legal_hold_only=req.legal_hold_only,
            include_artifacts=req.include_artifacts,
            quarantine_path=settings.quarantine_path,
            size_estimate=size_estimate,
            include_unsealed_drafts=req.include_unsealed_drafts,
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

    # 2. Move the finished password-protected ZIP to /evidence/exports/{id}.zip.
    export_id = uuid.uuid4()
    rel_path  = f"exports/{export_id}.zip"
    try:
        await asyncio.to_thread(build.staged.commit, rel_path)               # not on the event loop
    except BaseException:
        await asyncio.to_thread(build.staged.discard)
        raise

    # 3. Create the CustodyExport row (owns the download token + lifecycle).
    token      = secrets.token_urlsafe(32)
    expires_at = _now_utc() + timedelta(hours=24)
    # First/last 4 chars of the 24-char password — enough for OOB key-handoff
    # confirmation without revealing the full secret.
    key_hint   = f"{build.bundle_password[:4]}…{build.bundle_password[-4:]}"
    recipient  = (req.recipient or req.requesting_authority)[:256]

    cust = CustodyExport(
        id=export_id,
        incident_id=inc.id,
        exported_by_id=user.id,
        recipient=recipient,
        purpose=f"LE package — {req.case_reference}",
        acknowledgments=f"legal_basis={req.legal_basis}",
        token=token,
        status="ready",
        file_path=rel_path,
        file_size=build.bundle_size,
        bundle_sha256=build.bundle_sha256,
        key_hint=key_hint,
        item_ids=[],            # LE package is incident-wide, not evidence-scoped
        created_at=_now_utc(),
        expires_at=expires_at,
    )
    db.add(cust)
    await db.flush()

    # 4. Write the tamper-evident audit anchor row. This is the LE-package's
    #    proof-of-record in the platform's hash-chained audit log. Its
    #    `details` carry the manifest + bundle hashes so a recipient with
    #    authenticated access to the platform's audit log can verify the
    #    bundle they received matches what was produced.
    anchor_row = await write_audit(
        db, "le_package_generate",
        user_id=user.id, username=user.username, role_at_time=user.role,
        outcome="success",
        resource_type="le_package", resource_id=str(export_id),
        resource_label=req.case_reference,
        details={
            "case_reference":       req.case_reference,
            "requesting_authority": req.requesting_authority,
            "legal_basis":          req.legal_basis,
            "retention_until":      req.retention_until.isoformat() if req.retention_until else None,
            "legal_hold_only":      req.legal_hold_only,
            "include_artifacts":    req.include_artifacts,
            "incident_id":          str(inc.id),
            "incident_ref":         inc.ref,
            "bundle_sha256":        build.bundle_sha256,
            "manifest_sha256":      build.manifest_sha256,
            "hmac_sha256":          build.hmac_sha256,
            "file_count":           build.file_count,
            "total_bytes":          build.total_bytes,
            "evidence_count":       build.evidence_count,
            "audit_row_count":      build.audit_row_count,
            "custody_export_id":    str(export_id),
            "expires_at":           expires_at.isoformat(),
            "key_hint":             key_hint,
            "include_unsealed_drafts": req.include_unsealed_drafts,
            "unsealed_drafts_excluded": build.excluded_drafts,
            "integrity_failures":   [{"evidence_id": str(f["evidence_id"]), "identifier": f["identifier"],
                                      "integrity": f["integrity"]} for f in build.integrity_failures],
        },
    )

    # Wizard C — optional one-shot acknowledgment token (recipient closes the
    # chain by hitting /api/le-package-ack/{token}). Single-use, audit-logged.
    ack_token = secrets.token_urlsafe(32) if req.enable_acknowledgment else None

    # 5. Persist the LePackage row.
    lp = LePackage(
        id=uuid.uuid4(),
        incident_id=inc.id,
        custody_export_id=export_id,
        case_reference=req.case_reference,
        requesting_authority=req.requesting_authority,
        legal_basis=req.legal_basis,
        retention_until=req.retention_until,
        legal_hold_only=req.legal_hold_only,
        include_artifacts=req.include_artifacts,
        prepared_by_id=user.id,
        prepared_at=_now_utc(),
        bundle_sha256=build.bundle_sha256,
        manifest_sha256=build.manifest_sha256,
        hmac_sha256=build.hmac_sha256,
        audit_anchor_row_id=anchor_row.id,
        file_count=build.file_count,
        total_bytes=build.total_bytes,
        evidence_count=build.evidence_count,
        audit_row_count=build.audit_row_count,
        # Wizard C
        eio_reference          = req.eio_reference,
        issuing_state          = req.issuing_state,
        executing_state        = req.executing_state,
        mla_reference          = req.mla_reference,
        recipient_name         = req.recipient_name,
        recipient_role         = req.recipient_role,
        recipient_id_ref       = req.recipient_id_ref,
        recipient_organisation = req.recipient_organisation,
        recipient_address      = req.recipient_address,
        delivery_channel       = req.delivery_channel,
        delivery_notes         = req.delivery_notes,
        sender_declaration     = req.sender_declaration,
        # What protects the manifest: INTEGRITY.sig = HMAC-SHA-256 (no public-key signature).
        # Rows created before 2026-10-03 say "ed25519": a wrong label (docs/reports.md §3).
        signature_kind         = "hmac-sha256",
        acknowledgment_token   = ack_token,
    )
    db.add(lp)
    await db.flush()
    # R3-2 / R95: an exhibit found tampered (or with another SHA-256) while the package was built is frozen
    # through the verify-freeze path, like Verify and the export do.
    for f in build.integrity_failures:
        await freeze_for_integrity(db, f["evidence_id"], user=user, ip=None, incident_id=inc.id,
                                   reason=f["reason"], recomputed=f["sha256_recomputed"], phase="le_package",
                                   extra={"le_package_id": str(lp.id), "custody_export_id": str(export_id),
                                          "integrity": f["integrity"]})
    if user.role != "admin":
        # Delegated (IC / Deputy) build: every active admin hears about it.
        await notify_le_package_built(      # commits, then pushes
            db, incident_id=inc.id, incident_ref=inc.ref or str(inc.id), builder_username=user.username)
    else:
        await db.commit()

    base = _row_to_out(lp, cust, anchor_hash=anchor_row.row_hash)
    return LePackagePrepared(
        **base.model_dump(),
        bundle_password=build.bundle_password,
        download_url=f"/api/exports/{token}",
        acknowledgment_url=(f"/api/le-package-ack/{ack_token}" if ack_token else None),
    )


@router.get("/{incident_id}/le-packages", response_model=LePackageList,
            summary="List law-enforcement packages",
            responses={403: {"model": ApiErrorBody, "description": "not_incident_lead"}})
async def list_le_packages(
    incident_id: uuid.UUID,
    _: LeadAccess = Depends(require_incident_lead),
    db: AsyncSession = Depends(get_db),
) -> LePackageList:
    """List all law-enforcement packages prepared for the incident, newest
    first, with their custody-export status and audit anchor hash. Incident lead
    only (LE packages are sensitive): an admin, or an analyst assigned as Incident
    Commander or Deputy here (403 code not_incident_lead). Returns `{items: [...]}`."""
    rows = (await db.execute(
        select(LePackage, CustodyExport, AuditLog.row_hash)
        .join(CustodyExport, CustodyExport.id == LePackage.custody_export_id)
        .outerjoin(AuditLog,  AuditLog.id == LePackage.audit_anchor_row_id)
        .where(LePackage.incident_id == incident_id)
        .order_by(LePackage.prepared_at.desc())
    )).all()
    items = [_row_to_out(lp, cust, anchor_hash=h) for lp, cust, h in rows]
    return LePackageList(items=items)


@router.get("/{incident_id}/le-packages/{lp_id}", response_model=LePackageOut,
            summary="Get a law-enforcement package",
            responses={403: {"model": ApiErrorBody, "description": "not_incident_lead"}})
async def get_le_package(
    incident_id: uuid.UUID,
    lp_id:       uuid.UUID,
    _: LeadAccess = Depends(require_incident_lead),
    db: AsyncSession = Depends(get_db),
) -> LePackageOut:
    """Fetch metadata for a single law-enforcement package by id within the
    incident, including custody-export status and audit anchor hash. Incident lead
    only (admin, or an analyst assigned as Incident Commander or Deputy here; 403
    code not_incident_lead). Returns the package record; 404 if not found."""
    row = (await db.execute(
        select(LePackage, CustodyExport, AuditLog.row_hash)
        .join(CustodyExport, CustodyExport.id == LePackage.custody_export_id)
        .outerjoin(AuditLog,  AuditLog.id == LePackage.audit_anchor_row_id)
        .where(LePackage.id == lp_id, LePackage.incident_id == incident_id)
    )).first()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "LE package not found")
    lp, cust, h = row
    return _row_to_out(lp, cust, anchor_hash=h)


# ── Sender-mediated ("manual") acknowledgment ───────────────────────────────
# For external recipients who cannot reach the URL-based ack page (offline
# LE agencies, paper-only handoffs). Incident lead only (admin or IC / Deputy
# analyst) — they attest receipt on the recipient's behalf. Audit row records `details.method = "manual:..."`
# so a regulator can distinguish from URL-based acks.

@router.post(
    "/{incident_id}/le-packages/{lp_id}/manual-ack",
    response_model=LePackageAckResponse,
    summary="Manually acknowledge a law-enforcement package",
    responses={403: {"model": ApiErrorBody, "description": "not_incident_lead"}},
)
async def manual_ack_le_package(
    incident_id: uuid.UUID,
    lp_id:       uuid.UUID,
    req:         LePackageManualAckRequest,
    request:     Request,
    lead:        LeadAccess = Depends(require_incident_lead),
    db:          AsyncSession = Depends(get_db),
) -> LePackageAckResponse:
    """Record an attested receipt for an LE package on behalf of an external
    recipient who cannot use the URL ack page (offline / paper-only handoffs).
    Incident lead only (admin, or an analyst assigned as Incident Commander or
    Deputy here; 403 code not_incident_lead); optionally links a scanned-receipt
    Evidence id. Burns the URL ack token, audit-logs the attestation as
    `manual:...`, and rejects already-acknowledged packages. Returns the
    acknowledgment summary."""
    user = lead.user

    lp = (await db.execute(
        select(LePackage).where(
            LePackage.id == lp_id,
            LePackage.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not lp:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "LE package not found")
    if lp.acknowledged_at is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "This LE package has already been acknowledged",
        )

    if req.evidence_id is not None:
        ev = (await db.execute(
            select(Evidence).where(
                Evidence.id == req.evidence_id,
                Evidence.incident_id == incident_id,
            )
        )).scalar_one_or_none()
        if ev is None:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "Linked evidence not found in this incident",
            )

    now = _now_utc()
    ip  = request.client.host if request.client else None
    recipient_name = req.recipient_name.strip()

    # Human-readable summary stored on the LePackage row. Structured fields
    # also live in the audit-log row's details for programmatic review.
    notes_lines = [
        f"Manual acknowledgment attested by {user.username} ({user.role}) "
        f"on {now.replace(microsecond=0).isoformat()}.",
        f"Method: {req.method.replace('_', ' ')}.",
    ]
    if req.recipient_title:
        notes_lines.append(f"Title: {req.recipient_title.strip()}.")
    if req.recipient_agency:
        notes_lines.append(f"Agency: {req.recipient_agency.strip()}.")
    notes_lines.append(
        f"Received at: {req.received_at.replace(microsecond=0).isoformat()}."
    )
    notes_lines.append(f"Attestation: {req.attestation_text.strip()}")
    if req.evidence_id is not None:
        notes_lines.append(
            f"Signed receipt scanned and filed as Evidence {req.evidence_id}."
        )

    lp.acknowledged_at      = req.received_at
    lp.acknowledged_by_name = recipient_name[:256]
    lp.acknowledged_ip      = None    # external recipient — no platform IP
    lp.acknowledged_notes   = "\n".join(notes_lines)[:4096]
    # Burn the URL ack token so the URL path can't be used afterwards.
    lp.acknowledgment_token = None

    await write_audit(
        db, "le_package_acknowledge",
        user_id=user.id, username=user.username, role_at_time=user.role,
        outcome="success",
        resource_type="le_package", resource_id=str(lp.id),
        resource_label=lp.case_reference,
        details={
            "case_reference":       lp.case_reference,
            "requesting_authority": lp.requesting_authority,
            "bundle_sha256":        lp.bundle_sha256,
            "manifest_sha256":      lp.manifest_sha256,
            "method":               f"manual:{req.method}",
            "attested_by_id":       str(user.id),
            "recipient_name":       recipient_name,
            "recipient_title":      req.recipient_title,
            "recipient_agency":     req.recipient_agency,
            "received_at":          req.received_at.replace(microsecond=0).isoformat(),
            "attestation_text":     req.attestation_text.strip()[:1024],
            "evidence_id":          str(req.evidence_id) if req.evidence_id else None,
        },
        ip_address=ip,
    )
    await db.commit()
    return LePackageAckResponse(
        case_reference=lp.case_reference,
        requesting_authority=lp.requesting_authority,
        acknowledged_at=lp.acknowledged_at,
        acknowledged_by_name=lp.acknowledged_by_name,
    )


# ─── Public ack loop (single-use token, no auth) ─────────────────────────
# Mounted at the root of the API surface (not under /incidents) so a
# recipient can hit it from a printed handoff form / QR code without an
# account. Token comes from `LePackage.acknowledgment_token` and is
# consumed exactly once.

ack_router = APIRouter()


@ack_router.get("/api/le-package-ack/{token}", response_model=LePackageOut,
                summary="Preview a law-enforcement package by ack token")
async def get_le_package_by_ack_token(
    token: str,
    db:    AsyncSession = Depends(get_db),
) -> LePackageOut:
    """Read-only metadata about the package (so the recipient sees what they're
    acknowledging before submitting). Does not consume the token."""
    row = (await db.execute(
        select(LePackage, CustodyExport, AuditLog.row_hash)
        .join(CustodyExport, CustodyExport.id == LePackage.custody_export_id)
        .outerjoin(AuditLog,  AuditLog.id == LePackage.audit_anchor_row_id)
        .where(LePackage.acknowledgment_token == token)
    )).first()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Invalid or already-consumed acknowledgment token")
    lp, cust, h = row
    if lp.acknowledged_at is not None:
        raise HTTPException(status.HTTP_410_GONE, "Acknowledgment token already consumed")
    return _row_to_out(lp, cust, anchor_hash=h)


@ack_router.post("/api/le-package-ack/{token}", response_model=LePackageAckResponse,
                 summary="Acknowledge a law-enforcement package")
async def acknowledge_le_package(
    token:   str,
    req:     LePackageAckRequest,
    request: Request,
    db:      AsyncSession = Depends(get_db),
) -> LePackageAckResponse:
    """Single-use receipt loop. Closes the chain by recording the recipient's
    declaration in both the LePackage row and the hash-chained audit log."""
    lp = (await db.execute(
        select(LePackage).where(LePackage.acknowledgment_token == token)
    )).scalar_one_or_none()
    if not lp:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Invalid or already-consumed acknowledgment token")
    if lp.acknowledged_at is not None:
        raise HTTPException(status.HTTP_410_GONE, "Acknowledgment token already consumed")

    now = _now_utc()
    ip  = request.client.host if request.client else None
    lp.acknowledged_at      = now
    lp.acknowledged_by_name = req.name.strip()
    lp.acknowledged_ip      = ip
    lp.acknowledged_notes   = (req.notes or "").strip() or None
    # Burn the token — explicit defence in depth on top of the GONE check.
    lp.acknowledgment_token = None

    # Write an audit row anchored to the same case + bundle hash so reviewers
    # can confirm receipt without admin access.
    await write_audit(
        db, "le_package_acknowledge",
        # No user_id — the actor is the external recipient identified by name.
        username=req.name.strip()[:64],
        outcome="success",
        resource_type="le_package", resource_id=str(lp.id),
        resource_label=lp.case_reference,
        details={
            "case_reference":       lp.case_reference,
            "requesting_authority": lp.requesting_authority,
            "bundle_sha256":        lp.bundle_sha256,
            "manifest_sha256":      lp.manifest_sha256,
            "acknowledged_by_name": req.name.strip(),
            "notes":                lp.acknowledged_notes,
        },
        ip_address=ip,
    )
    await db.commit()
    return LePackageAckResponse(
        case_reference=lp.case_reference,
        requesting_authority=lp.requesting_authority,
        acknowledged_at=now,
        acknowledged_by_name=lp.acknowledged_by_name,
    )
