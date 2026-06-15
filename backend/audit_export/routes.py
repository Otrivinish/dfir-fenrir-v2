"""Audit-log export endpoints.

Two routers, mounted under different prefixes:

  • `incident_router` at `/api/incidents`
      POST   /{incident_id}/audit-log/exports     — generate (admin)
      GET    /{incident_id}/audit-log/exports     — list for this incident

  • `global_router` at `/api/admin`
      POST   /audit-log/exports                   — generate global (admin)
      GET    /audit-log/exports                   — list all (admin)
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from audit_export.bundle import build_audit_export, effective_status
from auth.deps import require_admin
from core.database import get_db
from models import AuditExport, AuditLog, Incident, User
from schemas import (
    AuditExportFilters,
    AuditExportList,
    AuditExportOut,
    AuditExportPrepare,
    AuditExportPrepared,
)


incident_router = APIRouter()
global_router   = APIRouter()


# ── Helpers ─────────────────────────────────────────────────────────────────

def _row_to_out(row: AuditExport) -> AuditExportOut:
    return AuditExportOut(
        id=row.id,
        incident_id=row.incident_id,
        exported_by_id=row.exported_by_id,
        filters=row.filters or {},
        purpose=row.purpose,
        first_prev_hash=row.first_prev_hash,
        last_row_hash=row.last_row_hash,
        chain_head_hash=row.chain_head_hash,
        row_count=row.row_count or 0,
        jsonl_sha256=row.jsonl_sha256,
        pubkey_fpr=row.pubkey_fpr,
        file_size=row.file_size,
        bundle_sha256=row.bundle_sha256,
        key_hint=row.key_hint,
        status=effective_status(row),
        created_at=row.created_at,
        expires_at=row.expires_at,
        consumed_at=row.consumed_at,
        retention_until=row.retention_until,
    )


async def _select_slice(
    db:           AsyncSession,
    filters:      AuditExportFilters,
    incident_id:  uuid.UUID | None,
) -> list[AuditLog]:
    """Apply filters + incident scope; return rows ordered by chain insertion."""
    conds = []

    if filters.date_from:     conds.append(AuditLog.timestamp >= filters.date_from)
    if filters.date_to:       conds.append(AuditLog.timestamp <= filters.date_to)
    if filters.action:        conds.append(AuditLog.action.ilike(f"%{filters.action}%"))
    if filters.username:      conds.append(AuditLog.username == filters.username)
    if filters.resource_type: conds.append(AuditLog.resource_type == filters.resource_type)
    if filters.outcome:       conds.append(AuditLog.outcome == filters.outcome)

    if incident_id is not None:
        prefix = f"/api/incidents/{incident_id}"
        conds.append(
            or_(
                AuditLog.request_path == prefix,
                AuditLog.request_path.like(f"{prefix}/%"),
                and_(AuditLog.resource_type == "incident",
                     AuditLog.resource_id == str(incident_id)),
            )
        )

    # Hard ceiling so an unbounded global export can't OOM the worker.
    # 50k rows × ~1.5KB JSONL avg = ~75MB inner, well below the in-memory build budget.
    q = (
        select(AuditLog)
        .where(*conds)
        .order_by(AuditLog.timestamp.asc(), AuditLog.id.asc())
        .limit(50_001)
    )
    rows = (await db.execute(q)).scalars().all()
    if len(rows) > 50_000:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            "Slice exceeds 50,000-row ceiling. Tighten the date range or filters.",
        )
    return rows


async def _chain_head(db: AsyncSession) -> AuditLog | None:
    """The most recent audit row at export time — recorded for cross-reference."""
    q = (
        select(AuditLog)
        .order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
        .limit(1)
    )
    return (await db.execute(q)).scalar_one_or_none()


async def _filters_dict(filters: AuditExportFilters) -> dict:
    """Mirror what goes into AuditExport.filters JSON + the manifest."""
    return {
        "date_from":     filters.date_from.isoformat()     if filters.date_from else None,
        "date_to":       filters.date_to.isoformat()       if filters.date_to   else None,
        "action":        filters.action,
        "username":      filters.username,
        "resource_type": filters.resource_type,
        "outcome":       filters.outcome,
    }


# ── Per-incident endpoints ───────────────────────────────────────────────────

@incident_router.post(
    "/{incident_id}/audit-log/exports",
    response_model=AuditExportPrepared,
    status_code=status.HTTP_201_CREATED,
    summary="Create a signed incident audit-log export",
)
async def create_incident_audit_export(
    incident_id: uuid.UUID,
    body:        AuditExportPrepare,
    request:     Request,
    user:        User = Depends(require_admin),
    db:          AsyncSession = Depends(get_db),
) -> AuditExportPrepared:
    """Generate an Ed25519-signed, AES-256-encrypted export of the audit-log
    slice scoped to one incident, applying the supplied filters and stated
    purpose. Admin only; the slice is capped at 50,000 rows. Returns the export
    record plus the one-time bundle password and download URL (both shown only
    on creation)."""
    inc = (await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )).scalar_one_or_none()
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")

    rows  = await _select_slice(db, body.filters, incident_id)
    head  = await _chain_head(db)
    fdict = await _filters_dict(body.filters)

    row, password, url = await build_audit_export(
        db=db, rows=rows, chain_head=head, filters=fdict,
        purpose=body.purpose, exporter=user, incident=inc,
    )

    await write_audit(
        db, "audit_export_create",
        user_id=user.id, username=user.username,
        resource_type="audit_export", resource_id=str(row.id),
        outcome="success",
        details={
            "incident_id":   str(incident_id),
            "scope":         "incident",
            "row_count":     row.row_count,
            "filters":       fdict,
            "bundle_sha256": row.bundle_sha256,
            "jsonl_sha256":  row.jsonl_sha256,
            "pubkey_fpr":    row.pubkey_fpr,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    await db.refresh(row)
    return AuditExportPrepared(
        **_row_to_out(row).model_dump(),
        bundle_password=password,
        download_url=url,
    )


@incident_router.get(
    "/{incident_id}/audit-log/exports",
    response_model=AuditExportList,
    summary="List incident audit-log exports",
)
async def list_incident_audit_exports(
    incident_id: uuid.UUID,
    _user:       User = Depends(require_admin),
    db:          AsyncSession = Depends(get_db),
) -> AuditExportList:
    """List the audit-log export records created for one incident, newest first.
    Admin only. Returns metadata only (hashes, row count, expiry, status) — never
    the download token or bundle password."""
    inc = (await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )).scalar_one_or_none()
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    rows = (await db.execute(
        select(AuditExport)
        .where(AuditExport.incident_id == incident_id)
        .order_by(AuditExport.created_at.desc())
    )).scalars().all()
    return AuditExportList(items=[_row_to_out(r) for r in rows])


# ── Global endpoints ─────────────────────────────────────────────────────────

@global_router.post(
    "/audit-log/exports",
    response_model=AuditExportPrepared,
    status_code=status.HTTP_201_CREATED,
    summary="Create a signed global audit-log export",
)
async def create_global_audit_export(
    body:    AuditExportPrepare,
    request: Request,
    user:    User = Depends(require_admin),
    db:      AsyncSession = Depends(get_db),
) -> AuditExportPrepared:
    """Generate an Ed25519-signed, AES-256-encrypted export of the global
    audit-log slice (all incidents) matching the supplied filters and purpose.
    Admin only; the slice is capped at 50,000 rows. Returns the export record
    plus the one-time bundle password and download URL (shown only on
    creation)."""
    rows  = await _select_slice(db, body.filters, None)
    head  = await _chain_head(db)
    fdict = await _filters_dict(body.filters)

    row, password, url = await build_audit_export(
        db=db, rows=rows, chain_head=head, filters=fdict,
        purpose=body.purpose, exporter=user, incident=None,
    )

    await write_audit(
        db, "audit_export_create",
        user_id=user.id, username=user.username,
        resource_type="audit_export", resource_id=str(row.id),
        outcome="success",
        details={
            "scope":         "global",
            "row_count":     row.row_count,
            "filters":       fdict,
            "bundle_sha256": row.bundle_sha256,
            "jsonl_sha256":  row.jsonl_sha256,
            "pubkey_fpr":    row.pubkey_fpr,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    await db.refresh(row)
    return AuditExportPrepared(
        **_row_to_out(row).model_dump(),
        bundle_password=password,
        download_url=url,
    )


@global_router.get(
    "/audit-log/exports",
    response_model=AuditExportList,
    summary="List all audit-log exports",
)
async def list_global_audit_exports(
    scope:    Optional[str] = None,         # "incident" | "global" | None (all)
    _user:    User = Depends(require_admin),
    db:       AsyncSession = Depends(get_db),
) -> AuditExportList:
    """List audit-log export records across all incidents, newest first. Admin
    only. Optional `scope` filters to "global" (incident-less) or "incident"
    (incident-scoped) exports; omit for all. Returns metadata only, never tokens
    or passwords."""
    q = select(AuditExport).order_by(AuditExport.created_at.desc())
    if scope == "global":
        q = q.where(AuditExport.incident_id.is_(None))
    elif scope == "incident":
        q = q.where(AuditExport.incident_id.is_not(None))
    rows = (await db.execute(q)).scalars().all()
    return AuditExportList(items=[_row_to_out(r) for r in rows])
