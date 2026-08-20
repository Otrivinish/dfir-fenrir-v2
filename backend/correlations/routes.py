"""Cross-incident correlation endpoints.

incident_router → mounted at /api/incidents (per-incident IOC correlations).
router          → mounted at /api/correlations (global shared-IOC and shared-entity views).

No new models; queries against existing iocs / entities / incidents tables.
"""
import base64
import json as _json
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select, tuple_
from sqlalchemy.orm import aliased
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import current_user
from core.database import get_db
from incidents.access import accessible_filter, get_accessible_incident
from models import Entity, IOC, Incident, User

incident_router = APIRouter()
router = APIRouter()


# ─── Schemas ──────────────────────────────────────────────────────────────────

class IncidentRef(BaseModel):
    id: uuid.UUID
    title: str
    severity: Optional[str] = None
    phase: Optional[str] = None
    model_config = {"from_attributes": True}


class IocCorrelationHit(BaseModel):
    ioc_id: uuid.UUID
    type: str
    value: str
    matched_incidents: list[IncidentRef]


class IocCorrelationResponse(BaseModel):
    items: list[IocCorrelationHit]


class SharedIoc(BaseModel):
    type: str
    value: str
    incident_count: int
    incidents: list[IncidentRef]


class SharedIocList(BaseModel):
    items: list[SharedIoc]
    next_cursor: Optional[str] = None


class SharedEntity(BaseModel):
    type: str
    value: str
    incident_count: int
    incidents: list[IncidentRef]


class SharedEntityList(BaseModel):
    items: list[SharedEntity]
    next_cursor: Optional[str] = None


class LookupItem(BaseModel):
    type:  str
    value: str


class LookupRequest(BaseModel):
    items: list[LookupItem] = Field(max_length=100)


class LookupHit(BaseModel):
    type: str
    value: str
    matched_incidents: list[IncidentRef]


class LookupResponse(BaseModel):
    items: list[LookupHit]


# ─── Cursor helpers ───────────────────────────────────────────────────────────

def _enc(offset: int) -> str:
    return base64.urlsafe_b64encode(_json.dumps({"o": offset}).encode()).decode().rstrip("=")


def _dec(cursor: Optional[str]) -> int:
    if not cursor:
        return 0
    try:
        pad = "=" * (-len(cursor) % 4)
        data = _json.loads(base64.urlsafe_b64decode(cursor + pad).decode())
        return max(0, int(data.get("o", 0)))
    except Exception:
        return 0


# ─── Per-incident: IOC correlations ───────────────────────────────────────────

@incident_router.get("/{incident_id}/iocs/correlations", response_model=IocCorrelationResponse,
                     summary="List IOC correlations for incident")
async def ioc_correlations_for_incident(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> IocCorrelationResponse:
    """
    For each IOC in this incident that also appears in at least one other
    incident the caller can access, return which other incidents share it.
    Single-query join on (type, value) across the iocs table.
    """
    # Gate the source incident, and only correlate against incidents the caller
    # can see — otherwise restricted incident titles/ids leak via the matches.
    await get_accessible_incident(db, incident_id, user)
    acc_ids = select(Incident.id).where(accessible_filter(user))

    OtherIOC = aliased(IOC)

    stmt = (
        select(
            IOC.id.label("ioc_id"),
            IOC.type.label("ioc_type"),
            IOC.value.label("ioc_value"),
            Incident.id.label("other_incident_id"),
            Incident.title.label("other_title"),
            Incident.severity.label("other_severity"),
            Incident.phase.label("other_phase"),
        )
        .join(OtherIOC, and_(
            OtherIOC.type == IOC.type,
            OtherIOC.value == IOC.value,
            OtherIOC.incident_id != incident_id,
        ))
        .join(Incident, Incident.id == OtherIOC.incident_id)
        .where(IOC.incident_id == incident_id, Incident.id.in_(acc_ids))
        .order_by(IOC.id, Incident.created_at.desc())
    )

    rows = (await db.execute(stmt)).all()

    hits: dict[uuid.UUID, IocCorrelationHit] = {}
    for row in rows:
        if row.ioc_id not in hits:
            hits[row.ioc_id] = IocCorrelationHit(
                ioc_id=row.ioc_id,
                type=row.ioc_type,
                value=row.ioc_value,
                matched_incidents=[],
            )
        hits[row.ioc_id].matched_incidents.append(IncidentRef(
            id=row.other_incident_id,
            title=row.other_title,
            severity=row.other_severity,
            phase=row.other_phase,
        ))

    return IocCorrelationResponse(items=list(hits.values()))


# ─── Global: shared IOCs ──────────────────────────────────────────────────────

@router.get("/iocs", response_model=SharedIocList, summary="List globally shared IOCs")
async def global_ioc_correlations(
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
    limit:  int           = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    tag:    Optional[str] = Query(default=None,
                                  description="Filter to (type, value) pairs where ANY underlying row has this tag (canonical lowercase-dashed)"),
) -> SharedIocList:
    """IOC values observed in 2+ incidents the caller can access, by count desc."""
    offset = _dec(cursor)
    # Restrict every count and incident ref to accessible incidents — a non-admin
    # must not learn the ids/titles of restricted incidents that share an IOC.
    acc_ids = select(Incident.id).where(accessible_filter(user))

    pairs_stmt = (
        select(
            IOC.type,
            IOC.value,
            func.count(func.distinct(IOC.incident_id)).label("cnt"),
        )
        .where(IOC.incident_id.in_(acc_ids))
        .group_by(IOC.type, IOC.value)
        .having(func.count(func.distinct(IOC.incident_id)) > 1)
        .order_by(func.count(func.distinct(IOC.incident_id)).desc(), IOC.type, IOC.value)
        .offset(offset).limit(limit + 1)
    )
    if tag:
        from core.tags import normalize_tag
        canonical = normalize_tag(tag)
        if canonical:
            # Cross-incident IOC search by tag — match against the JSON-cast text
            # so any row of this (type, value) carrying the tag pulls it into the
            # correlation set.
            pairs_stmt = pairs_stmt.where(
                func.cast(IOC.tags, type_=None).ilike(f'%"{canonical}"%')
            )
    pairs = (await db.execute(pairs_stmt)).all()

    has_more = len(pairs) > limit
    pairs    = pairs[:limit]

    items = []
    for typ, val, cnt in pairs:
        # IN-subquery instead of JOIN + DISTINCT — DISTINCT on the full Incident
        # row fails because Incident.tags is `json` (no equality operator). The
        # subquery yields unique incident IDs; the outer SELECT is then unique
        # by primary key naturally.
        incs = (await db.execute(
            select(Incident)
            .where(Incident.id.in_(
                select(IOC.incident_id).where(
                    IOC.type == typ, IOC.value == val, IOC.incident_id.in_(acc_ids)
                )
            ))
            .order_by(Incident.created_at.desc())
        )).scalars().all()
        items.append(SharedIoc(
            type=typ,
            value=val,
            incident_count=cnt,
            incidents=[
                IncidentRef(id=i.id, title=i.title, severity=i.severity, phase=i.phase)
                for i in incs
            ],
        ))

    return SharedIocList(
        items=items,
        next_cursor=_enc(offset + limit) if has_more else None,
    )


# ─── Global: correlate arbitrary (type, value) pairs ─────────────────────────

@router.post("/lookup", response_model=LookupResponse,
             summary="Correlate arbitrary indicator values against tracked IOCs")
async def correlate_lookup(
    req: LookupRequest,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> LookupResponse:
    """For each (type, value) pair -- not necessarily an existing IOC -- return
    which accessible incidents already track it as an IOC. Used by the OSINT
    lookup page to hint "already seen elsewhere" before an analyst adds one.
    Capped at 100 items per call; unmatched pairs come back with an empty list.
    """
    if not req.items:
        return LookupResponse(items=[])
    acc_ids = select(Incident.id).where(accessible_filter(user))
    pairs = [(i.type, i.value) for i in req.items]

    rows = (await db.execute(
        select(IOC.type, IOC.value, Incident.id, Incident.title, Incident.severity, Incident.phase)
        .join(Incident, Incident.id == IOC.incident_id)
        .where(tuple_(IOC.type, IOC.value).in_(pairs), Incident.id.in_(acc_ids))
    )).all()

    matches: dict[tuple[str, str], list[IncidentRef]] = {}
    for typ, val, inc_id, title, severity, phase in rows:
        matches.setdefault((typ, val), []).append(
            IncidentRef(id=inc_id, title=title, severity=severity, phase=phase)
        )

    return LookupResponse(items=[
        LookupHit(type=i.type, value=i.value, matched_incidents=matches.get((i.type, i.value), []))
        for i in req.items
    ])


# ─── Global: shared entities ──────────────────────────────────────────────────

@router.get("/entities", response_model=SharedEntityList, summary="List globally shared entities")
async def global_entity_correlations(
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
) -> SharedEntityList:
    """Entity (type, value) pairs in 2+ incidents the caller can access, by count."""
    offset = _dec(cursor)
    acc_ids = select(Incident.id).where(accessible_filter(user))

    pairs_stmt = (
        select(
            Entity.type,
            Entity.value,
            func.count(func.distinct(Entity.incident_id)).label("cnt"),
        )
        .where(Entity.incident_id.in_(acc_ids))
        .group_by(Entity.type, Entity.value)
        .having(func.count(func.distinct(Entity.incident_id)) > 1)
        .order_by(func.count(func.distinct(Entity.incident_id)).desc(), Entity.type, Entity.value)
        .offset(offset).limit(limit + 1)
    )
    pairs = (await db.execute(pairs_stmt)).all()

    has_more = len(pairs) > limit
    pairs    = pairs[:limit]

    items = []
    for typ, val, cnt in pairs:
        # IN-subquery — same json-equality avoidance as the IOC variant above.
        incs = (await db.execute(
            select(Incident)
            .where(Incident.id.in_(
                select(Entity.incident_id).where(
                    Entity.type == typ, Entity.value == val, Entity.incident_id.in_(acc_ids)
                )
            ))
            .order_by(Incident.created_at.desc())
        )).scalars().all()
        items.append(SharedEntity(
            type=typ,
            value=val,
            incident_count=cnt,
            incidents=[
                IncidentRef(id=i.id, title=i.title, severity=i.severity, phase=i.phase)
                for i in incs
            ],
        ))

    return SharedEntityList(
        items=items,
        next_cursor=_enc(offset + limit) if has_more else None,
    )
