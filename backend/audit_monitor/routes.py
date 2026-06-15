"""GS-8 — audit-chain anchor status (read-only, admin).

Surfaces the periodic anchors so the tamper status is observable from the API/UI/MCP.
The latest row's `verify_ok` is the live tamper verdict; `has_tst` shows whether the head
was independently timestamped. The full TST is not exposed here (it lives in the row).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import require_admin
from core.database import get_db
from models import AuditAnchor, User
from schemas import AuditAnchorList, AuditAnchorOut

router = APIRouter()


@router.get(
    "/audit/anchors",
    response_model=AuditAnchorList,
    summary="List audit-chain anchors",
)
async def list_audit_anchors(
    limit: int = Query(default=50, ge=1, le=500),
    admin: User = Depends(require_admin),
    db:    AsyncSession = Depends(get_db),
) -> AuditAnchorList:
    """List the periodic audit-chain anchors, newest first, for observing tamper
    status. Admin only. The latest row's `verify_ok` is the live tamper verdict
    and `has_tst` shows whether the chain head was independently timestamped; the
    raw timestamp token is not exposed here."""
    rows = (await db.execute(
        select(AuditAnchor)
        .order_by(AuditAnchor.anchored_at.desc(), AuditAnchor.id.desc())
        .limit(limit)
    )).scalars().all()
    return AuditAnchorList(items=[AuditAnchorOut.model_validate(r) for r in rows])
