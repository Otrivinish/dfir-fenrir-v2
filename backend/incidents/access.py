"""Incident access control helpers.

Access rules:
  - Admins: see and access all incidents.
  - Analysts/viewers: see incidents with no teams assigned (open to all), or
    incidents where they are a member of at least one assigned team.

Returning 404 (not 403) for forbidden incidents intentionally avoids leaking
incident existence to users who shouldn't know about it.
"""
import uuid

from fastapi import HTTPException, status
from sqlalchemy import exists, or_, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from models import Incident, User, incident_teams, user_team


async def get_accessible_incident(
    db: AsyncSession,
    incident_id: uuid.UUID,
    user: User,
) -> Incident:
    """Fetch incident by id, enforcing team-based access control."""
    inc = (await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )).scalar_one_or_none()
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    if user.role == "admin":
        return inc

    # Check whether any team is assigned to this incident.
    has_team = (await db.execute(
        select(incident_teams.c.team_id)
        .where(incident_teams.c.incident_id == incident_id)
        .limit(1)
    )).scalar_one_or_none()

    if has_team is None:
        return inc  # No teams assigned — visible to all authenticated users.

    # At least one team is assigned; user must be in one of them.
    member = (await db.execute(
        select(incident_teams.c.team_id)
        .join(user_team, user_team.c.team_id == incident_teams.c.team_id)
        .where(incident_teams.c.incident_id == incident_id)
        .where(user_team.c.user_id == user.id)
        .limit(1)
    )).scalar_one_or_none()

    if member is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    return inc


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
