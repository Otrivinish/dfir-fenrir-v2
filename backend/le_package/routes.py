"""LE-package and Disclosure-package routes.

Endpoints:
  POST   /api/incidents/{id}/disclosures  — K1: build a Disclosure package (internal | law_enforcement |
                                            regulator). Incident lead only (admin, or an analyst assigned
                                            IC / Deputy IC). Password shown ONCE + download URL.
  GET    /api/incidents/{id}/disclosures  — list (cursor-paginated, ?purpose=). Incident lead.
  GET    /api/incidents/{id}/disclosures/{id} — one. Incident lead.
  POST   /api/incidents/{id}/le-package   — deprecated (K1): a law_enforcement disclosure over all exhibits.
  GET    /api/incidents/{id}/le-packages  — deprecated (K1): the law_enforcement disclosures.
  GET    /api/incidents/{id}/le-packages/{lp_id} — deprecated (K1).
  POST   /api/incidents/{id}/le-packages/{lp_id}/manual-ack — incident lead (any disclosure id).

The encrypted bundle itself is downloaded via the existing single-use
`/api/exports/{token}` endpoint (mounted by `evidence/download.py`). The
builder reuses that CustodyExport lifecycle — no new download path. Building,
recording and custody-logging live in `le_package/disclosure.py`.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from evidence.routes import _decode_cursor, _encode_cursor
from incidents.access import LeadAccess, require_incident_lead
from le_package.disclosure import NOT_DISCLOSABLE, create_disclosure
from models import AuditLog, CustodyExport, Evidence, LePackage
from schemas import (DisclosureCreate, DisclosureCreated, DisclosureList, DisclosureOut, DisclosurePurpose,
                     LePackageAckRequest, LePackageAckResponse,
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
        purpose=lp.purpose or "law_enforcement",
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


_EXTRA_FIELDS = ("eio_reference", "issuing_state", "executing_state", "mla_reference", "recipient_name",
                 "recipient_role", "recipient_id_ref", "recipient_organisation", "recipient_address",
                 "delivery_channel", "delivery_notes", "sender_declaration")


@router.post("/{incident_id}/le-package", response_model=LePackagePrepared,
             summary="Build a law-enforcement package (deprecated: POST …/disclosures)", deprecated=True,
             responses={403: {"model": ApiErrorBody, "description": "not_incident_lead"},
                        409: {"model": ApiErrorBody,
                              "description": "evidence_integrity_failed (an exhibit's stored file verified, then "
                                             "failed its integrity check while it was written into the package: "
                                             "it changed during the build; nothing was built), or "
                                             "evidence_not_exportable (an exhibit was disposed, frozen or changed "
                                             "while the package was built; nothing was recorded)"},
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
    """**Deprecated (K1):** use `POST /api/incidents/{id}/disclosures` with `purpose: law_enforcement`. This
    route still works and builds the same package: a law_enforcement Disclosure package over every exhibit of the
    incident (or only those on legal hold), with the same rights, audit, custody rows and admin notification.

    Build a court-ready, encrypted law-enforcement handoff bundle for the incident and anchor it in the
    hash-chained audit log (`le_package_generate`). Incident lead only: an admin, or an analyst (effective
    role) assigned as Incident Commander or Deputy Incident Commander on this incident (403 code
    not_incident_lead; not visible: 404). Every other active admin gets an in-app notification (incident ref
    and purpose only). K1: MANIFEST.json is also signed with Ed25519 (MANIFEST.json.sig +
    SIGNING_PUBLIC_KEY.pem), and every exhibit in the package gets an `evidence_export` custody row (plus a
    working-copy ledger row and `evidence_copy_mint` when its bytes are in it).

    The bundle password is returned exactly once. The download URL is the standard one-time
    `/api/exports/{token}` link (single use, 24-hour expiry). When acknowledgment is enabled, a single-use ack
    URL is also returned.

    M11 (owner, 2026-10-04): exhibits whose chain of custody is not sealed (unsealed drafts) are left
    out by default — listed in Evidence_Inventory.csv as "excluded: unsealed draft", with no custody
    log or file. `include_unsealed_drafts: true` includes them (audited on the anchor row).

    G2: the package is streamed into a staging file with bounded memory and published only when complete.
    An exhibit that fails an integrity check while it is read is listed as `integrity_failed:<reason>` (or
    `HASH_MISMATCH_AT_EXPORT`) and frozen; one that fails while it is being written discards the whole package
    (409 evidence_integrity_failed / 503 evidence_read_error). The evidence volume must have room for the
    package's stored files plus a 1 GiB reserve (507 insufficient_storage). A multi-GiB package takes
    minutes: keep the request open (the password is only in this response).
    """
    user, inc = lead
    d = await create_disclosure(
        db, inc=inc, user=user, purpose="law_enforcement", case_reference=req.case_reference,
        requesting_authority=req.requesting_authority, legal_basis=req.legal_basis,
        recipient=(req.recipient or req.requesting_authority), retention_until=req.retention_until,
        legal_hold_only=req.legal_hold_only, include_artifacts=req.include_artifacts,
        include_unsealed_drafts=req.include_unsealed_drafts, item_ids=None,
        extras={k: getattr(req, k) for k in _EXTRA_FIELDS}, enable_acknowledgment=req.enable_acknowledgment,
    )
    base = _row_to_out(d.lp, d.cust, anchor_hash=d.anchor.row_hash)
    return LePackagePrepared(
        **base.model_dump(),
        bundle_password=d.build.bundle_password,
        download_url=f"/api/exports/{d.cust.token}",
        acknowledgment_url=(f"/api/le-package-ack/{d.ack_token}" if d.ack_token else None),
    )


# ── K1 (R36): Disclosure packages ───────────────────────────────────────────

_PURPOSE_NEEDS = ("case_reference", "requesting_authority", "legal_basis")


def _disclosure_out(lp: LePackage, cust: CustodyExport, anchor_hash: str | None) -> DisclosureOut:
    return DisclosureOut(**_row_to_out(lp, cust, anchor_hash).model_dump(), item_ids=cust.item_ids or [])


def _required(what: str) -> ApiError:
    return ApiError(status.HTTP_422_UNPROCESSABLE_ENTITY, "disclosure_field_required", what)


@router.post("/{incident_id}/disclosures", response_model=DisclosureCreated,
             status_code=status.HTTP_201_CREATED, summary="Build a disclosure package",
             responses={403: {"model": ApiErrorBody, "description": "not_incident_lead"},
                        404: {"model": ApiErrorBody, "description": "evidence_not_found (an item_id is not an "
                                                                    "exhibit of this incident)"},
                        409: {"model": ApiErrorBody,
                              "description": "evidence_not_exportable (a chosen exhibit is destroyed or "
                                             "verify_failed, or one was disposed, frozen or changed while the "
                                             "package was built: nothing was disclosed), or "
                                             "evidence_integrity_failed (an exhibit changed while it was "
                                             "written into the package: nothing was built)"},
                        422: {"model": ApiErrorBody,
                              "description": "disclosure_field_required (law_enforcement / regulator need "
                                             "case_reference, requesting_authority and a legal_basis other than "
                                             "internal; eio needs eio_reference + issuing_state + "
                                             "executing_state; mla needs mla_reference)"},
                        503: {"model": ApiErrorBody, "description": "evidence_read_error"},
                        507: {"model": ApiErrorBody, "description": "insufficient_storage"}})
async def create_disclosure_package(
    incident_id: uuid.UUID,
    req:         DisclosureCreate,
    lead:        LeadAccess = Depends(require_incident_lead),
    db:          AsyncSession = Depends(get_db),
) -> DisclosureCreated:
    """K1 (owner, 2026-10-03): the one way exhibits leave FENRIR — Evidence › Export and the LE package merged.
    Incident lead only: an admin, or an analyst assigned as Incident Commander or Deputy here (403
    not_incident_lead; not visible: 404).

    `purpose` picks the records that go with the exhibits (every package has 04_Evidence, 08_Audit and
    09_Legal): law_enforcement = everything (incident, timeline, IOCs, forensic, communications, case notes,
    recovery, notifications, sign-offs); regulator = incident, timeline, IOCs, recovery, notifications,
    sign-offs; internal = incident, timeline, IOCs, forensic, case notes, recovery. Quarantine artifacts only
    with `include_artifacts`.

    Always signed: an Ed25519 signature over MANIFEST.json (MANIFEST.json.sig; SIGNING_PUBLIC_KEY.pem, the key in
    GET /api/version), plus the HMAC-SHA-256 in INTEGRITY.sig and, when a TSA is configured, an RFC 3161 token.
    Always custody-logged: every exhibit in it gets an `evidence_export` row in the custody log, and one whose
    bytes are in it a working-copy ledger row (export) and `evidence_copy_mint`. Audited (`le_package_generate`
    anchor, `details.purpose`); every other active admin is notified in-app.

    `item_ids` omitted = every exhibit that can be disclosed (not destroyed or verify_failed); unsealed drafts
    are left out unless `include_unsealed_drafts` (audited). Returns the record with the one-time
    `bundle_password` (AES-256 ZIP) and `/api/exports/{token}` download URL (single use, 24 h), the drafts
    left out and the exhibits that failed their integrity check (frozen). Built in this one streamed request
    (G2): keep it open for a large package."""
    user, inc = lead
    if req.purpose != "internal":
        missing = [f for f in _PURPOSE_NEEDS if not (getattr(req, f) or "").strip()]
        if missing:
            raise _required(f"A {req.purpose} disclosure needs {', '.join(missing)}.")
        if req.legal_basis == "internal":
            raise _required(f"A {req.purpose} disclosure needs a legal basis other than internal.")
    if req.legal_basis == "eio" and not all((getattr(req, f) or "").strip()
                                            for f in ("eio_reference", "issuing_state", "executing_state")):
        raise _required("Legal basis eio needs eio_reference, issuing_state and executing_state.")
    if req.legal_basis == "mla" and not (req.mla_reference or "").strip():
        raise _required("Legal basis mla needs mla_reference.")

    if req.item_ids is None:
        item_ids = list((await db.execute(
            select(Evidence.id).where(Evidence.incident_id == inc.id, Evidence.status.notin_(NOT_DISCLOSABLE))
        )).scalars())
    else:
        item_ids = list(dict.fromkeys(req.item_ids))
        rows = (await db.execute(select(Evidence).where(Evidence.incident_id == inc.id,
                                                        Evidence.id.in_(item_ids)))).scalars().all()
        missing = sorted(set(map(str, item_ids)) - {str(e.id) for e in rows})
        if missing:
            raise ApiError(status.HTTP_404_NOT_FOUND, "evidence_not_found",
                           f"Not an exhibit of this incident: {', '.join(missing)}")
        blocked = sorted(f"{e.identifier} ({e.status})" for e in rows if e.status in NOT_DISCLOSABLE)
        if blocked:
            raise ApiError(status.HTTP_409_CONFLICT, "evidence_not_exportable",
                           "Destroyed or verify-failed exhibits cannot be disclosed: " + ", ".join(blocked))

    authority = (req.requesting_authority or "").strip() or "Internal"
    org = (req.recipient_organisation or "").strip()
    d = await create_disclosure(
        db, inc=inc, user=user, purpose=req.purpose,
        case_reference=(req.case_reference or "").strip() or (inc.ref or str(inc.id)),
        requesting_authority=authority, legal_basis=req.legal_basis or "internal",
        recipient=f"{req.recipient_name.strip()}, {org}" if org else req.recipient_name.strip(),
        retention_until=req.retention_until, legal_hold_only=False, include_artifacts=req.include_artifacts,
        include_unsealed_drafts=req.include_unsealed_drafts, item_ids=item_ids,
        extras={k: getattr(req, k) for k in _EXTRA_FIELDS}, enable_acknowledgment=req.enable_acknowledgment,
    )
    out = _disclosure_out(d.lp, d.cust, d.anchor.row_hash)
    return DisclosureCreated(
        **out.model_dump(),
        bundle_password=d.build.bundle_password,
        download_url=f"/api/exports/{d.cust.token}",
        acknowledgment_url=(f"/api/le-package-ack/{d.ack_token}" if d.ack_token else None),
        unsealed_drafts_excluded=d.build.excluded_drafts,
        integrity_failures=[{"evidence_id": str(f["evidence_id"]), "identifier": f["identifier"],
                             "integrity": f["integrity"]} for f in d.build.integrity_failures],
    )


def _disclosure_query(incident_id: uuid.UUID):
    return (select(LePackage, CustodyExport, AuditLog.row_hash)
            .join(CustodyExport, CustodyExport.id == LePackage.custody_export_id)
            .outerjoin(AuditLog, AuditLog.id == LePackage.audit_anchor_row_id)
            .where(LePackage.incident_id == incident_id))


@router.get("/{incident_id}/disclosures", response_model=DisclosureList, summary="List disclosure packages",
            responses={403: {"model": ApiErrorBody, "description": "not_incident_lead"}})
async def list_disclosures(
    incident_id: uuid.UUID,
    _: LeadAccess = Depends(require_incident_lead),
    db: AsyncSession = Depends(get_db),
    purpose: Optional[DisclosurePurpose] = Query(default=None),
    limit:  int           = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
) -> DisclosureList:
    """The incident's disclosure packages (LE packages built before K1 included, purpose law_enforcement),
    newest first, cursor-paginated, optionally by `purpose`. Status reflects the one-time download (ready |
    consumed | expired | revoked). Never returns the password or the download token. Incident lead only (403
    not_incident_lead)."""
    offset = _decode_cursor(cursor)
    q = _disclosure_query(incident_id)
    if purpose:
        q = q.where(LePackage.purpose == purpose)
    rows = (await db.execute(q.order_by(LePackage.prepared_at.desc(), LePackage.id)
                             .offset(offset).limit(limit + 1))).all()
    items = [_disclosure_out(lp, cust, h) for lp, cust, h in rows[:limit]]
    return DisclosureList(items=items, next_cursor=_encode_cursor(offset + limit) if len(rows) > limit else None)


@router.get("/{incident_id}/disclosures/{disclosure_id}", response_model=DisclosureOut,
            summary="Get a disclosure package",
            responses={403: {"model": ApiErrorBody, "description": "not_incident_lead"},
                       404: {"model": ApiErrorBody, "description": "disclosure_not_found"}})
async def get_disclosure(
    incident_id: uuid.UUID,
    disclosure_id: uuid.UUID,
    _: LeadAccess = Depends(require_incident_lead),
    db: AsyncSession = Depends(get_db),
) -> DisclosureOut:
    """One disclosure package by id (its record, exhibits, hashes, audit anchor hash and download status).
    Incident lead only (403 not_incident_lead). Record a receipt with POST …/le-packages/{id}/manual-ack (the
    same id)."""
    row = (await db.execute(_disclosure_query(incident_id).where(LePackage.id == disclosure_id))).first()
    if not row:
        raise ApiError(status.HTTP_404_NOT_FOUND, "disclosure_not_found", "Disclosure package not found")
    return _disclosure_out(*row)


@router.get("/{incident_id}/le-packages", response_model=LePackageList,
            summary="List law-enforcement packages (deprecated: GET …/disclosures)", deprecated=True,
            responses={403: {"model": ApiErrorBody, "description": "not_incident_lead"}})
async def list_le_packages(
    incident_id: uuid.UUID,
    _: LeadAccess = Depends(require_incident_lead),
    db: AsyncSession = Depends(get_db),
) -> LePackageList:
    """List all law-enforcement packages prepared for the incident, newest
    first, with their custody-export status and audit anchor hash. Incident lead
    only (LE packages are sensitive): an admin, or an analyst assigned as Incident
    Commander or Deputy here (403 code not_incident_lead). Returns `{items: [...]}`. **Deprecated (K1):** use
    GET …/disclosures; this lists only the law_enforcement ones."""
    rows = (await db.execute(
        _disclosure_query(incident_id).where(LePackage.purpose == "law_enforcement")
        .order_by(LePackage.prepared_at.desc())
    )).all()
    items = [_row_to_out(lp, cust, anchor_hash=h) for lp, cust, h in rows]
    return LePackageList(items=items)


@router.get("/{incident_id}/le-packages/{lp_id}", response_model=LePackageOut,
            summary="Get a law-enforcement package (deprecated: GET …/disclosures/{id})", deprecated=True,
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
    """Record an attested receipt for an LE package — or any disclosure package (K1: the disclosure id) — on
    behalf of an external
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
