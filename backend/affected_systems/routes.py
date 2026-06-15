"""Affected systems — per-incident structured list of impacted assets."""
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from incidents.access import get_accessible_incident
from models import AffectedSystem, Entity, User
from schemas import AffectedSystemCreate, AffectedSystemList, AffectedSystemOut, AffectedSystemUpdate

router = APIRouter()

# AffectedSystem.system_type → EntityType. AffectedSystem uses the
# infrastructure-flavoured vocabulary; Entity uses the IR-investigation
# vocabulary. Anything we can't map cleanly lands on "other".
SYSTEM_TYPE_TO_ENTITY_TYPE = {
    "workstation":    "host",
    "server":         "host",
    "network_device": "network_range",
    "cloud_resource": "service",
    "application":    "service",
    "database":       "service",
    "mobile":         "host",
    "other":          "other",
}


@router.get("/{incident_id}/affected-systems", response_model=AffectedSystemList)
async def list_affected_systems(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
):
    await get_accessible_incident(db, incident_id, user)
    result = await db.execute(
        select(AffectedSystem)
        .where(AffectedSystem.incident_id == incident_id)
        .order_by(AffectedSystem.created_at)
    )
    return AffectedSystemList(items=result.scalars().all())


@router.post("/{incident_id}/affected-systems", response_model=AffectedSystemOut, status_code=201)
async def create_affected_system(
    incident_id: UUID,
    body: AffectedSystemCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    await get_accessible_incident(db, incident_id, user)
    sys = AffectedSystem(
        incident_id=incident_id,
        created_by_username=user.username,
        **body.model_dump(),
    )
    db.add(sys)
    await db.commit()
    await db.refresh(sys)
    return sys


@router.patch("/{incident_id}/affected-systems/{sys_id}", response_model=AffectedSystemOut)
async def update_affected_system(
    incident_id: UUID,
    sys_id: UUID,
    body: AffectedSystemUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    await get_accessible_incident(db, incident_id, user)
    sys = await db.get(AffectedSystem, sys_id)
    if not sys or sys.incident_id != incident_id:
        raise HTTPException(404)
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(sys, k, v)
    await db.commit()
    await db.refresh(sys)
    return sys


# ─── Bulk promote to Entities (compromised) ──────────────────────────────────

class PromoteToEntitiesRequest(BaseModel):
    system_ids: Optional[list[UUID]] = None   # None / empty = all systems


class PromoteToEntitiesResult(BaseModel):
    created: int
    skipped: int   # already existed as entities for this incident
    total:   int


@router.post(
    "/{incident_id}/affected-systems/promote-to-entities",
    response_model=PromoteToEntitiesResult,
)
async def promote_to_entities(
    incident_id: UUID,
    body: PromoteToEntitiesRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Create Entity rows from AffectedSystem rows, tagged compromised=True.

    Idempotent — relies on the (incident_id, type, value) unique constraint
    on entities. A previously-promoted system is counted as skipped, not
    created twice.
    """
    inc = await get_accessible_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(409, "Incident is closed")

    stmt = select(AffectedSystem).where(AffectedSystem.incident_id == incident_id)
    if body.system_ids:
        stmt = stmt.where(AffectedSystem.id.in_(body.system_ids))
    systems = (await db.execute(stmt)).scalars().all()

    created = 0
    skipped = 0
    for s in systems:
        entity_type = SYSTEM_TYPE_TO_ENTITY_TYPE.get(s.system_type or "other", "other")
        # Probe for an existing entity with this (type, value) — cheaper than
        # catching IntegrityError per row and rolling the session back.
        existing = (await db.execute(
            select(Entity).where(
                Entity.incident_id == incident_id,
                Entity.type == entity_type,
                Entity.value == s.name,
            )
        )).scalar_one_or_none()
        if existing:
            # Already an entity — make sure it's marked compromised. Safe re-run.
            if not existing.compromised:
                existing.compromised = True
            skipped += 1
            continue
        db.add(Entity(
            incident_id=incident_id,
            type=entity_type,
            value=s.name,
            name=s.name,
            description=s.notes,
            criticality="high",
            compromised=True,
            added_by_id=user.id,
        ))
        created += 1

    if created or skipped:
        await write_audit(
            db, "affected_systems_promote",
            user_id=user.id, username=user.username,
            resource_type="incident", resource_id=str(incident_id),
            details={"created": created, "skipped": skipped, "total": len(systems)},
        )
    await db.commit()
    return PromoteToEntitiesResult(created=created, skipped=skipped, total=len(systems))


@router.delete("/{incident_id}/affected-systems/{sys_id}", status_code=204)
async def delete_affected_system(
    incident_id: UUID,
    sys_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    await get_accessible_incident(db, incident_id, user)
    sys = await db.get(AffectedSystem, sys_id)
    if not sys or sys.incident_id != incident_id:
        raise HTTPException(404)
    await db.delete(sys)
    await db.commit()
