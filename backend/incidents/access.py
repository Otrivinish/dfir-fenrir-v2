"""Incident access control helpers.

Access rules:
  - Admins: see and access all incidents.
  - Analysts/viewers: see incidents with no teams assigned (open to all), or
    incidents where they are a member of at least one assigned team.
  An operational-role assignment does NOT grant visibility.

Returning 404 (not 403) for forbidden incidents intentionally avoids leaking
incident existence to users who shouldn't know about it.

Incident lead (E3): an admin, or an analyst (effective role: an API token's role
cap applies) holding an Incident Commander or Deputy Incident Commander
assignment on that incident. Matched on the operational role KEY, evaluated on
every request: removing the assignment ends the rights at once (no standing
privilege). Viewers are never leads, even when assigned.
"""
import uuid
from typing import NamedTuple, Optional

from fastapi import Depends, HTTPException, status
from sqlalchemy import exists, or_, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import current_user
from core.database import get_db
from core.errors import ApiError
from models import (Incident, IncidentAssignment, OnCallEntry, OperationalRole, User,
                    incident_teams, user_team, utc_today)

# Operational role keys (auth/bootstrap.py SEED_ROLES) that make an analyst the incident lead.
LEAD_ROLE_KEYS = ("incident_commander", "deputy_commander")


async def _team_visible(db: AsyncSession, incident_id: uuid.UUID, user_id: uuid.UUID) -> bool:
    """True when the incident has no team, or the user is in one of its teams."""
    has_team = (await db.execute(
        select(incident_teams.c.team_id)
        .where(incident_teams.c.incident_id == incident_id)
        .limit(1)
    )).scalar_one_or_none()
    if has_team is None:
        return True  # No teams assigned — visible to all authenticated users.

    # At least one team is assigned; user must be in one of them.
    member = (await db.execute(
        select(incident_teams.c.team_id)
        .join(user_team, user_team.c.team_id == incident_teams.c.team_id)
        .where(incident_teams.c.incident_id == incident_id)
        .where(user_team.c.user_id == user_id)
        .limit(1)
    )).scalar_one_or_none()
    return member is not None


async def get_accessible_incident(
    db: AsyncSession,
    incident_id: uuid.UUID,
    user: User,
    *,
    for_update: bool = False,
) -> Incident:
    """Fetch incident by id, enforcing team-based access control. for_update=True
    takes a row lock (SELECT … FOR UPDATE) held until the transaction ends, for
    check-then-write paths (phase change, close, re-open)."""
    stmt = select(Incident).where(Incident.id == incident_id)
    if for_update:
        stmt = stmt.with_for_update(of=Incident).execution_options(populate_existing=True)
    inc = (await db.execute(stmt)).scalar_one_or_none()
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    if user.role == "admin":
        return inc
    if not await _team_visible(db, incident_id, user.id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    return inc


async def user_can_see_incident(db: AsyncSession, user: User, incident_id: uuid.UUID) -> bool:
    """Whether another user (e.g. an assignee) can see the incident: active, and an
    admin or allowed by the team rule. Uses the stored role (no token in play)."""
    if not user.is_active:
        return False
    if user.role == "admin":
        return True
    return await _team_visible(db, incident_id, user.id)


def accessible_filter(user: User):
    """SQLAlchemy WHERE expression limiting a query to incidents the user may see.

    Returns a boolean expression suitable for `.where()`. Admins get `True`
    (no restriction). Non-admins see incidents with no teams, or incidents where
    they belong to an assigned team.
    """
    if user.role == "admin":
        return true()

    no_teams = ~exists(
        select(incident_teams.c.team_id)
        .where(incident_teams.c.incident_id == Incident.id)
    )
    user_in_team = exists(
        select(incident_teams.c.team_id)
        .join(user_team, user_team.c.team_id == incident_teams.c.team_id)
        .where(incident_teams.c.incident_id == Incident.id)
        .where(user_team.c.user_id == user.id)
    )
    return or_(no_teams, user_in_team)


# ─── Incident lead (E3) ──────────────────────────────────────────────────────

async def is_lead_role(db: AsyncSession, role_id: Optional[uuid.UUID]) -> bool:
    """Whether an operational role is Incident Commander or Deputy (by key)."""
    if role_id is None:
        return False
    key = (await db.execute(select(OperationalRole.key).where(OperationalRole.id == role_id))).scalar_one_or_none()
    return key in LEAD_ROLE_KEYS


def _lead_assignment(incident_id: uuid.UUID):
    """IC / Deputy assignments on the incident; a deactivated operational role grants nothing."""
    return (select(IncidentAssignment.id)
            .join(OperationalRole, OperationalRole.id == IncidentAssignment.role_id)
            .where(IncidentAssignment.incident_id == incident_id,
                   OperationalRole.key.in_(LEAD_ROLE_KEYS),
                   OperationalRole.is_active.is_(True)))


async def is_incident_lead(db: AsyncSession, user: User, incident: Incident) -> bool:
    """Admin, or an analyst (effective role, so an API token capped at viewer is not)
    holding an IC / Deputy IC assignment on this incident. The caller must already have
    passed the visibility check (get_accessible_incident)."""
    if user.role == "admin":
        return True
    if user.role != "analyst":
        return False
    row = (await db.execute(
        _lead_assignment(incident.id).where(IncidentAssignment.user_id == user.id).limit(1)
    )).scalar_one_or_none()
    return row is not None


async def incident_has_lead(db: AsyncSession, incident_id: uuid.UUID) -> bool:
    """Whether someone can act as lead: an IC / Deputy assignment held by an active
    analyst or admin who can see the incident (admin, or allowed by the team rule).
    An assigned viewer, a deactivated user or a holder the teams lock out doesn't
    count, so the creator / on-call fallback still works."""
    no_teams = ~exists(select(incident_teams.c.team_id)
                       .where(incident_teams.c.incident_id == incident_id))
    holder_in_team = exists(select(incident_teams.c.team_id)
                            .join(user_team, user_team.c.team_id == incident_teams.c.team_id)
                            .where(incident_teams.c.incident_id == incident_id,
                                   user_team.c.user_id == IncidentAssignment.user_id))
    row = (await db.execute(
        _lead_assignment(incident_id)
        .join(User, User.id == IncidentAssignment.user_id)
        .where(User.is_active.is_(True), User.role.in_(("analyst", "admin")),
               or_(User.role == "admin", no_teams, holder_in_team))
        .limit(1)
    )).scalar_one_or_none()
    return row is not None


async def _on_call_today(db: AsyncSession) -> Optional[uuid.UUID]:
    """The user on call today (UTC date), as GET /api/on-call/current picks it."""
    today = utc_today()
    return (await db.execute(
        select(OnCallEntry.user_id)
        .where(OnCallEntry.start_date <= today, OnCallEntry.end_date >= today)
        .order_by(OnCallEntry.start_date.desc())
        .limit(1)
    )).scalar_one_or_none()


async def may_manage_lead_roles(db: AsyncSession, user: User, incident: Incident) -> bool:
    """Who may create or remove an IC / Deputy assignment: an incident lead (admins
    included), or, while the incident has no lead, its creator or today's on-call
    analyst. Caller has passed the visibility check."""
    if await is_incident_lead(db, user, incident):
        return True
    if user.role != "analyst":
        return False
    if await incident_has_lead(db, incident.id):
        return False
    return user.id == incident.created_by_id or user.id == await _on_call_today(db)


def not_incident_lead(what: str) -> ApiError:
    return ApiError(status.HTTP_403_FORBIDDEN, "not_incident_lead",
                    f"Only this incident's lead (an analyst assigned as Incident Commander or Deputy "
                    f"Incident Commander) or an admin can {what}.")


class LeadAccess(NamedTuple):
    user: User
    incident: Incident


async def require_incident_lead(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> LeadAccess:
    """Dependency: the incident is visible to the caller (else 404) and the caller is
    its lead (else 403 not_incident_lead)."""
    inc = await get_accessible_incident(db, incident_id, user)
    if not await is_incident_lead(db, user, inc):
        raise not_incident_lead("do this")
    return LeadAccess(user, inc)


# Capabilities returned by GET /api/incidents/{id}/access (the UI holds no permission rule).
CAPABILITIES = {
    "read_audit_log":        "Read the incident audit log (lead)",
    "manage_le_package":     "Build, list and acknowledge law-enforcement packages (lead)",
    "set_teams":             "Set the incident's teams (lead; only an admin can clear a restricted list)",
    "override_gate":         "Send override_gate=true on a phase change or close (lead)",
    "remove_any_assignment": "Remove anyone's assignment (lead)",
    "assign_lead_roles":     "Create or remove Incident Commander / Deputy assignments (lead, or the "
                             "creator / today's on-call analyst while the incident has no lead)",
    "remove_own_assignment": "Remove your own assignment (analyst or admin)",
}


async def incident_capabilities(db: AsyncSession, user: User, incident: Incident) -> tuple[bool, list[str]]:
    """(is_lead, capabilities) for a caller who has passed the visibility check."""
    lead = await is_incident_lead(db, user, incident)
    caps: list[str] = []
    if lead:
        caps += ["read_audit_log", "manage_le_package", "set_teams", "override_gate", "remove_any_assignment"]
    if await may_manage_lead_roles(db, user, incident):
        caps.append("assign_lead_roles")
    if user.role in ("admin", "analyst"):
        caps.append("remove_own_assignment")
    return lead, caps
