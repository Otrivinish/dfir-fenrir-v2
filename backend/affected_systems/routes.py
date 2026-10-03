"""Affected systems — DEPRECATED compatibility layer over Entities (C2).

Entities is the single scope list; an incident's "affected systems" are its compromised
entities. These routes keep the old /affected-systems shape for API / MCP clients:

- GET    lists the compromised entities (old shape plus `entity_id` / `entity_type`);
- POST   creates the entity (type mapped from `system_type`, compromised) or flags the
         existing one for (incident, type, value): an upsert;
- PATCH  edits that entity (`name` → display name, `notes` → description, `system_type`
         → `attributes.system_type`; the entity type never changes);
- DELETE clears the compromised flag; the entity stays in Entities;
- promote-to-entities is a no-op.

`{sys_id}` is an entity id, or the id of a pre-C2 affected_systems row (resolved through
`affected_systems.migrated_entity_id`). Nothing writes to the legacy table any more.
Writes return 409 `incident_closed` on a closed incident and are audited as entity changes.
"""
import uuid
from typing import Optional, get_args
from uuid import UUID

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from entities.routes import _add_system_event
from incidents.access import get_accessible_incident
from models import AffectedSystem, Entity, Incident, User
from schemas import (AffectedSystemCreate, AffectedSystemList, AffectedSystemOut,
                     AffectedSystemUpdate, SystemType)

router = APIRouter()

# AffectedSystem.system_type → EntityType. AffectedSystem uses the
# infrastructure-flavoured vocabulary; Entity uses the IR-investigation
# vocabulary. Anything we can't map cleanly lands on "other". The C2 migration
# (core/database.py) uses the same map in SQL.
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
_SYSTEM_TYPES = set(get_args(SystemType))

_VIA = "affected-systems (deprecated)"
_ERR_404 = {404: {"model": ApiErrorBody, "description": "affected_system_not_found"}}
_ERR_409 = {409: {"model": ApiErrorBody, "description": "incident_closed or entity_exists"}}


def _as_system(ent: Entity, username: Optional[str]) -> AffectedSystemOut:
    st = (ent.attributes or {}).get("system_type")
    return AffectedSystemOut(
        id=ent.id, entity_id=ent.id, incident_id=ent.incident_id,
        name=ent.name or ent.value, entity_type=ent.type,
        system_type=st if st in _SYSTEM_TYPES else None,
        notes=ent.description, created_at=ent.added_at, created_by_username=username,
    )


async def compromised_systems(db: AsyncSession, incident_id: UUID) -> list[AffectedSystemOut]:
    """The incident's compromised entities in the affected-system shape, oldest first.
    Also the report data's `affected_systems` (reports/routes.py)."""
    rows = (await db.execute(
        select(Entity, User.username)
        .outerjoin(User, User.id == Entity.added_by_id)
        .where(Entity.incident_id == incident_id, Entity.compromised == True)  # noqa: E712
        .order_by(Entity.added_at, Entity.id)
    )).all()
    return [_as_system(e, uname) for e, uname in rows]


async def _out(db: AsyncSession, ent: Entity) -> AffectedSystemOut:
    uname = (await db.execute(select(User.username).where(User.id == ent.added_by_id))).scalar_one_or_none() \
        if ent.added_by_id else None
    return _as_system(ent, uname)


def _ensure_open(inc: Incident) -> None:
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed. Re-open it first.")


async def _resolve(db: AsyncSession, incident_id: UUID, sys_id: UUID) -> Entity:
    """The entity behind `sys_id`: an entity id, or a legacy affected_systems row id."""
    ent = await db.get(Entity, sys_id)
    if ent is None:
        legacy = await db.get(AffectedSystem, sys_id)
        if legacy is not None and legacy.incident_id == incident_id and legacy.migrated_entity_id:
            ent = await db.get(Entity, legacy.migrated_entity_id)
    if ent is None or ent.incident_id != incident_id:
        raise ApiError(status.HTTP_404_NOT_FOUND, "affected_system_not_found", "Affected system not found")
    return ent


async def _audit_update(db: AsyncSession, user: User, ent: Entity, changes: dict) -> None:
    await write_audit(
        db, "entity_update",
        user_id=user.id, username=user.username,
        resource_type="entity", resource_id=str(ent.id),
        details={"incident_id": str(ent.incident_id), "changes": changes, "via": _VIA},
    )


@router.get("/{incident_id}/affected-systems", response_model=AffectedSystemList, deprecated=True,
            summary="List affected systems (deprecated: compromised entities)")
async def list_affected_systems(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
):
    """DEPRECATED — use `GET /api/incidents/{id}/entities?compromised=true`.

    Returns every compromised entity of the incident (oldest first, not paginated) in the
    old affected-system shape; `id` and `entity_id` are the entity's id.
    """
    await get_accessible_incident(db, incident_id, user)
    return AffectedSystemList(items=await compromised_systems(db, incident_id))


@router.post("/{incident_id}/affected-systems", response_model=AffectedSystemOut, status_code=201,
             deprecated=True, responses=_ERR_409,
             summary="Add an affected system (deprecated: upserts a compromised entity)")
async def create_affected_system(
    incident_id: UUID,
    body: AffectedSystemCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """DEPRECATED — use `POST /api/incidents/{id}/entities` with `compromised: true`.

    Upsert: the entity type comes from `system_type` (workstation/server/mobile → host,
    network_device → network_range, cloud_resource/application/database → service, else
    other) and the value is the trimmed `name`. A new entity is created compromised with
    criticality high and `attributes.system_type`; an existing one for (type, value) is
    flagged compromised and only its empty description / system_type are filled in. The
    value matches case-insensitively ("dc01" reuses "DC01"; an exact match wins); without
    a system_type (or with `other`) an entity of any type matches, a host first.
    Always 201. 409 `incident_closed` on a closed incident. Audited as an entity change.
    """
    inc = await get_accessible_incident(db, incident_id, user)
    _ensure_open(inc)
    etype = SYSTEM_TYPE_TO_ENTITY_TYPE.get(body.system_type or "other", "other")
    value = body.name.strip()
    if not value:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "name_required", "name must not be blank")

    # Case-insensitive, so "dc01" reuses an existing "DC01" (an exact match wins). Same type; with
    # system_type omitted / other (→ other) the type is unknown, so any type matches, a host first.
    match = select(Entity).where(Entity.incident_id == incident_id,
                                 func.lower(Entity.value) == value.lower())
    if etype != "other":
        match = match.where(Entity.type == etype)
    ent = (await db.execute(
        match.order_by((Entity.value == value).desc(), (Entity.type == etype).desc(),
                       (Entity.type == "host").desc(), Entity.added_at, Entity.id).limit(1)
    )).scalar_one_or_none()
    if ent is None:
        ent = Entity(
            id=uuid.uuid4(), incident_id=incident_id, type=etype, value=value, name=value,
            description=body.notes, criticality="high",
            attributes={"system_type": body.system_type} if body.system_type else {},
            compromised=True, added_by_id=user.id,
        )
        db.add(ent)
        try:
            await db.flush()
        except IntegrityError:
            await db.rollback()
            raise ApiError(status.HTTP_409_CONFLICT, "entity_exists",
                           "This entity was added at the same moment; retry")
        await _add_system_event(db, ent, "Entity added", actor_id=user.id)
        await _add_system_event(db, ent, "Marked as compromised", actor_id=user.id)
        await write_audit(
            db, "entity_create",
            user_id=user.id, username=user.username,
            resource_type="entity", resource_id=str(ent.id),
            details={"incident_id": str(incident_id), "type": ent.type, "value": ent.value,
                     "compromised": True, "via": _VIA},
        )
    else:
        changes: dict[str, object] = {}
        if not ent.compromised:
            ent.compromised = True; changes["compromised"] = True
        if body.system_type and not (ent.attributes or {}).get("system_type"):
            ent.attributes = {**(ent.attributes or {}), "system_type": body.system_type}
            changes["attributes"] = ent.attributes
        if body.notes and not ent.description:
            ent.description = body.notes; changes["description"] = body.notes
        if "compromised" in changes:
            await _add_system_event(db, ent, "Marked as compromised", actor_id=user.id)
        if changes:
            await _audit_update(db, user, ent, changes)
    await db.commit()
    return await _out(db, ent)


@router.patch("/{incident_id}/affected-systems/{sys_id}", response_model=AffectedSystemOut,
              deprecated=True, responses={**_ERR_404, **_ERR_409},
              summary="Update an affected system (deprecated: edits the entity)")
async def update_affected_system(
    incident_id: UUID,
    sys_id: UUID,
    body: AffectedSystemUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """DEPRECATED — use `PATCH /api/incidents/{id}/entities/{entity_id}`.

    `sys_id` is an entity id or a pre-C2 affected-system id. `name` sets the entity's
    display name (null clears it, so `name` shows the value again), `notes` its
    description, `system_type` its `attributes.system_type`; the entity type and value and
    the compromised flag don't change. 404 `affected_system_not_found`, 409
    `incident_closed`. Audited as an entity change.
    """
    inc = await get_accessible_incident(db, incident_id, user)
    _ensure_open(inc)
    ent = await _resolve(db, incident_id, sys_id)

    data = body.model_dump(exclude_unset=True)
    changes: dict[str, object] = {}
    if "name" in data:
        new = (data["name"] or "").strip() or None
        if new != ent.name:
            ent.name = new; changes["name"] = new
    if "notes" in data and data["notes"] != ent.description:
        ent.description = data["notes"]; changes["description"] = data["notes"]
    attrs = dict(ent.attributes or {})
    if "system_type" in data and data["system_type"] != attrs.get("system_type"):
        if data["system_type"]:
            attrs["system_type"] = data["system_type"]
        else:
            attrs.pop("system_type", None)
        ent.attributes = attrs; changes["attributes"] = attrs
    if changes:
        await _audit_update(db, user, ent, changes)
    await db.commit()
    return await _out(db, ent)


# ─── Promote to Entities: a no-op since C2 ───────────────────────────────────

class PromoteToEntitiesRequest(BaseModel):
    system_ids: Optional[list[UUID]] = None   # ignored since C2


class PromoteToEntitiesResult(BaseModel):
    created: int
    skipped: int   # already existed as entities for this incident
    total:   int
    detail:  str


@router.post(
    "/{incident_id}/affected-systems/promote-to-entities",
    response_model=PromoteToEntitiesResult, deprecated=True,
    summary="Promote affected systems to entities (deprecated no-op)",
)
async def promote_to_entities(
    incident_id: UUID,
    body: PromoteToEntitiesRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """DEPRECATED no-op: affected systems ARE the incident's compromised entities, so there
    is nothing to promote. Returns `created: 0` and every compromised entity as `skipped`.
    Writes nothing.
    """
    await get_accessible_incident(db, incident_id, user)
    n = len(await compromised_systems(db, incident_id))
    return PromoteToEntitiesResult(
        created=0, skipped=n, total=n,
        detail="Nothing to promote: affected systems are this incident's compromised entities.",
    )


@router.delete("/{incident_id}/affected-systems/{sys_id}", status_code=204, deprecated=True,
               responses={**_ERR_404, **_ERR_409},
               summary="Remove an affected system (deprecated: clears the compromised flag)")
async def delete_affected_system(
    incident_id: UUID,
    sys_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """DEPRECATED — use `PATCH /api/incidents/{id}/entities/{entity_id}` with
    `compromised: false`.

    Clears the entity's compromised flag; the entity itself stays in Entities (delete it
    there). Idempotent. `sys_id` is an entity id or a pre-C2 affected-system id. 404
    `affected_system_not_found`, 409 `incident_closed`. Audited as an entity change.
    """
    inc = await get_accessible_incident(db, incident_id, user)
    _ensure_open(inc)
    ent = await _resolve(db, incident_id, sys_id)
    if ent.compromised:
        ent.compromised = False
        await _add_system_event(db, ent, "Compromised flag cleared", actor_id=user.id)
        await _audit_update(db, user, ent, {"compromised": False})
        await db.commit()
