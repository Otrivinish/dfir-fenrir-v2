"""IR Roster routes.

Global:
  GET  /api/roster                      — list all analyst+admin users with profile + load
  PATCH /api/roster/{user_id}           — upsert own profile (or any for admin)

Per-incident (mounted at /api/incidents):
  GET  /{incident_id}/roster/coverage   — all CISA roles + who is assigned to each
"""
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import current_user, require_analyst
from core.database import get_db
from incidents.access import get_accessible_incident
from models import (
    IncidentAssignment, Incident, OperationalRole,
    ResponderProfile, User, utcnow,
)
from schemas import (
    CoverageAssignment, CoverageList, CoverageSlot,
    ResponderProfileUpdate, RosterEntry, RosterList,
)

router          = APIRouter()
incident_router = APIRouter()

_AVAILABLE_ROLES = {"admin", "analyst"}


# ─── Helpers ──────────────────────────────────────────────────────────────────

async def _get_or_create_profile(db: AsyncSession, user_id: uuid.UUID) -> ResponderProfile:
    p = (await db.execute(
        select(ResponderProfile).where(ResponderProfile.user_id == user_id)
    )).scalar_one_or_none()
    if p is None:
        p = ResponderProfile(user_id=user_id)
        db.add(p)
        await db.flush()
    return p


# ─── Global roster ────────────────────────────────────────────────────────────

@router.get("", response_model=RosterList, summary="List the responder roster")
async def list_roster(
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
    availability: Optional[str] = None,
    q: Optional[str] = None,
) -> RosterList:
    """List all active analyst and admin users with their responder profile
    (skills, availability, notes) and current active (non-closed) incident
    count. Any authenticated user may read. Optionally filter by `availability`
    and a free-text `q` matched against username and full name.
    """
    # Active incident count per user (incidents not closed).
    load_subq = (
        select(
            IncidentAssignment.user_id,
            func.count(func.distinct(IncidentAssignment.incident_id)).label("cnt"),
        )
        .join(Incident, Incident.id == IncidentAssignment.incident_id)
        .where(Incident.status != "closed", IncidentAssignment.user_id.isnot(None))
        .group_by(IncidentAssignment.user_id)
        .subquery()
    )

    stmt = (
        select(
            User,
            ResponderProfile,
            func.coalesce(load_subq.c.cnt, 0).label("active_incident_count"),
        )
        .outerjoin(ResponderProfile, ResponderProfile.user_id == User.id)
        .outerjoin(load_subq, load_subq.c.user_id == User.id)
        .where(User.role.in_(list(_AVAILABLE_ROLES)), User.is_active.is_(True))
        .order_by(User.username)
    )

    if availability:
        stmt = stmt.where(
            func.coalesce(ResponderProfile.availability, "available") == availability
        )
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(
            func.lower(User.username).like(like) |
            func.lower(func.coalesce(User.full_name, "")).like(like)
        )

    rows = (await db.execute(stmt)).all()
    items = []
    for u, profile, count in rows:
        items.append(RosterEntry(
            user_id=u.id,
            username=u.username,
            full_name=u.full_name,
            role=u.role,
            skills=profile.skills if profile else [],
            availability=profile.availability if profile else "available",
            notes=profile.notes if profile else None,
            active_incident_count=int(count),
        ))
    return RosterList(items=items)


@router.patch("/{user_id}", response_model=RosterEntry,
              summary="Update a responder profile")
async def update_roster_profile(
    user_id: uuid.UUID,
    req: ResponderProfileUpdate,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> RosterEntry:
    """Update a responder profile's skills, availability, and notes (creating
    the profile if absent). Requires the analyst role; you may only update your
    own profile unless you are an admin. Returns the updated roster entry with
    its active incident count.
    """
    if user.id != user_id and user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Can only update your own profile")

    target = (await db.execute(
        select(User).where(User.id == user_id, User.is_active.is_(True))
    )).scalar_one_or_none()
    if not target:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    profile = await _get_or_create_profile(db, user_id)
    if req.skills is not None:
        profile.skills = [s.strip() for s in req.skills if s.strip()]
    if req.availability is not None:
        profile.availability = req.availability
    if req.notes is not None:
        profile.notes = req.notes or None
    profile.updated_at = utcnow()

    await db.commit()

    # Compute active count for response
    count = (await db.execute(
        select(func.count(func.distinct(IncidentAssignment.incident_id)))
        .join(Incident, Incident.id == IncidentAssignment.incident_id)
        .where(
            IncidentAssignment.user_id == user_id,
            Incident.status != "closed",
        )
    )).scalar_one()

    return RosterEntry(
        user_id=target.id,
        username=target.username,
        full_name=target.full_name,
        role=target.role,
        skills=profile.skills,
        availability=profile.availability,
        notes=profile.notes,
        active_incident_count=int(count),
    )


# ─── Per-incident coverage ────────────────────────────────────────────────────

@incident_router.get("/{incident_id}/roster/coverage", response_model=CoverageList,
                     summary="Get role coverage for an incident")
async def get_roster_coverage(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> CoverageList:
    """List every active operational role alongside the responders currently
    assigned to it on this incident (a role may have several or none). Requires
    access to the incident. Returns the roles as coverage slots ordered by sort
    order then label.
    """
    await get_accessible_incident(db, incident_id, user)

    roles = (await db.execute(
        select(OperationalRole)
        .where(OperationalRole.is_active.is_(True))
        .order_by(OperationalRole.sort_order, OperationalRole.label)
    )).scalars().all()

    assignments = (await db.execute(
        select(IncidentAssignment)
        .where(IncidentAssignment.incident_id == incident_id)
    )).scalars().all()

    # Group by role_id (one role can have multiple people assigned).
    by_role: dict[uuid.UUID, list[IncidentAssignment]] = {}
    for a in assignments:
        if a.role_id:
            by_role.setdefault(a.role_id, []).append(a)

    slots = []
    for r in roles:
        slot_assignments = [
            CoverageAssignment(
                assignment_id=a.id,
                user_id=a.user_id,
                username=a.username,
            )
            for a in by_role.get(r.id, [])
        ]
        slots.append(CoverageSlot(
            role_id=r.id,
            role_key=r.key,
            role_label=r.label,
            sort_order=r.sort_order,
            assignments=slot_assignments,
        ))
    return CoverageList(slots=slots)
