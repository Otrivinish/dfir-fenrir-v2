"""Audit log endpoints — per-incident (admin-only) + global (admin-only)."""
import base64
import json
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import require_admin
from core.database import get_db
from models import AuditLog, Incident, User
from schemas import AuditLogEntryOut, AuditLogList

router        = APIRouter()   # per-incident, mounted at /api/incidents
global_router = APIRouter()   # global,       mounted at /api/admin


def _encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"o": offset}).encode()).decode().rstrip("=")


def _decode_cursor(cursor: str | None) -> int:
    if not cursor:
        return 0
    try:
        pad = "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(cursor + pad).decode())
        return max(0, int(data.get("o", 0)))
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid cursor")


@router.get(
    "/{incident_id}/audit-log",
    response_model=AuditLogList,
    summary="Get the incident audit log",
)
async def get_incident_audit_log(
    incident_id: uuid.UUID,
    limit:  int = Query(100, ge=1, le=500),
    cursor: str | None = Query(None),
    _user:  User = Depends(require_admin),
    db:     AsyncSession = Depends(get_db),
) -> AuditLogList:
    """Get the audit-log entries scoped to one incident (by request path or
    incident resource id), newest first, cursor-paginated via `limit`/`cursor`.
    Admin only. Returns the hash-chained audit entries for the incident."""
    inc = (await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )).scalar_one_or_none()
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")

    offset = _decode_cursor(cursor)
    prefix = f"/api/incidents/{incident_id}"

    q = (
        select(AuditLog)
        .where(
            or_(
                AuditLog.request_path == prefix,
                AuditLog.request_path.like(f"{prefix}/%"),
                # Catch programmatic writes that set resource_type/id without a request path.
                and_(AuditLog.resource_type == "incident", AuditLog.resource_id == str(incident_id)),
            )
        )
        .order_by(AuditLog.timestamp.desc())
        .offset(offset)
        .limit(limit + 1)
    )
    rows = (await db.execute(q)).scalars().all()

    has_more = len(rows) > limit
    items = rows[:limit]
    next_cursor = _encode_cursor(offset + limit) if has_more else None

    return AuditLogList(
        items=[AuditLogEntryOut.model_validate(r) for r in items],
        next_cursor=next_cursor,
    )


# ─── Global audit log ────────────────────────────────────────────────────────

@global_router.get(
    "/audit-log",
    response_model=AuditLogList,
    summary="Get the global audit log",
)
async def get_global_audit_log(
    limit:         int            = Query(100, ge=1, le=500),
    cursor:        str | None     = Query(None),
    action:        str | None     = Query(None, description="Substring match on action"),
    username:      str | None     = Query(None, description="Exact username filter"),
    resource_type: str | None     = Query(None),
    date_from:     datetime | None = Query(None),
    date_to:       datetime | None = Query(None),
    _user:         User           = Depends(require_admin),
    db:            AsyncSession   = Depends(get_db),
) -> AuditLogList:
    """Get the global audit log across all incidents, newest first,
    cursor-paginated. Admin only. Optional filters: `action` (substring),
    `username` (exact), `resource_type`, and `date_from`/`date_to`. Returns the
    hash-chained audit entries."""
    offset = _decode_cursor(cursor)

    filters = []
    if action:        filters.append(AuditLog.action.ilike(f"%{action}%"))
    if username:      filters.append(AuditLog.username == username)
    if resource_type: filters.append(AuditLog.resource_type == resource_type)
    if date_from:     filters.append(AuditLog.timestamp >= date_from)
    if date_to:       filters.append(AuditLog.timestamp <= date_to)

    q = (
        select(AuditLog)
        .where(*filters)
        .order_by(AuditLog.timestamp.desc())
        .offset(offset)
        .limit(limit + 1)
    )
    rows = (await db.execute(q)).scalars().all()

    has_more = len(rows) > limit
    items = rows[:limit]
    next_cursor = _encode_cursor(offset + limit) if has_more else None

    return AuditLogList(
        items=[AuditLogEntryOut.model_validate(r) for r in items],
        next_cursor=next_cursor,
    )
