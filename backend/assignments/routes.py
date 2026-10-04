"""Per-incident assignment roster — links users to incidents in operational roles."""
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from incidents.access import (LEAD_ROLE_KEYS, get_accessible_incident, is_incident_lead, is_lead_role,
                              may_manage_lead_roles, not_incident_lead, user_can_see_incident)
from models import Incident, IncidentAssignment, OperationalRole, User
from notifications.service import notify_assignment
from schemas import (
    IncidentAssignmentCreate,
    IncidentAssignmentList,
    IncidentAssignmentOut,
)

router = APIRouter()


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


async def _get_assignment(
    db: AsyncSession, incident_id: uuid.UUID, assignment_id: uuid.UUID
) -> IncidentAssignment:
    row = (await db.execute(
        select(IncidentAssignment).where(
            IncidentAssignment.id == assignment_id,
            IncidentAssignment.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Assignment not found")
    return row


def _to_out(a: IncidentAssignment) -> IncidentAssignmentOut:
    return IncidentAssignmentOut.model_validate(a)


@router.get("/{incident_id}/assignments", response_model=IncidentAssignmentList,
            summary="List assignments")
async def list_assignments(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db:   AsyncSession = Depends(get_db),
) -> IncidentAssignmentList:
    """List the incident's responder assignments, ordered by assignment time.
    Requires access to the incident.
    """
    await _get_incident(db, incident_id, user)
    rows = (await db.execute(
        select(IncidentAssignment)
        .where(IncidentAssignment.incident_id == incident_id)
        .order_by(IncidentAssignment.assigned_at)
    )).scalars().all()
    return IncidentAssignmentList(items=[_to_out(r) for r in rows])


_LEAD_ROLES = "the Incident Commander or Deputy Incident Commander role"


@router.post("/{incident_id}/assignments", response_model=IncidentAssignmentOut,
             status_code=status.HTTP_201_CREATED,
             summary="Assign a responder",
             responses={403: {"model": ApiErrorBody, "description": "not_incident_lead"},
                        404: {"model": ApiErrorBody, "description": "user_not_found, or the role"},
                        422: {"model": ApiErrorBody, "description": "assignee_no_access"}})
async def create_assignment(
    incident_id: uuid.UUID,
    req:  IncidentAssignmentCreate,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> IncidentAssignmentOut:
    """Assign a user to the incident in an operational role. Requires the
    analyst role. The target user and an active operational role must exist; a
    user cannot be assigned the same role twice (409). Rejected if the incident
    is closed. The assignment is audited and returned.

    Incident Commander and Deputy Incident Commander make an analyst the incident
    lead, so assigning them needs: an admin, a current lead of this incident, or,
    while no active analyst or admin holds either role here, the incident's creator
    or today's on-call analyst (403 code not_incident_lead otherwise). The assignee
    must be active and able to see the incident (422 code assignee_no_access); an
    assignment does not grant visibility. The assignee gets an in-app notification
    (incident ref only), unless they assigned themselves.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    # Resolve user
    target_user = (await db.execute(
        select(User).where(User.id == req.user_id)
    )).scalar_one_or_none()
    if not target_user:
        raise ApiError(status.HTTP_404_NOT_FOUND, "user_not_found", "User not found")

    # Resolve operational role
    role = (await db.execute(
        select(OperationalRole).where(
            OperationalRole.id == req.role_id,
            OperationalRole.is_active == True,
        )
    )).scalar_one_or_none()
    if not role:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Operational role not found or inactive")

    if role.key in LEAD_ROLE_KEYS and not await may_manage_lead_roles(db, user, inc):
        raise ApiError(status.HTTP_403_FORBIDDEN, "not_incident_lead",
                       f"Only this incident's lead or an admin can assign {_LEAD_ROLES}; while the "
                       "incident has no lead, its creator or today's on-call analyst can too.")
    if not target_user.is_active:
        # L4: no username — don't disclose who a deactivated account belonged to.
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "assignee_no_access",
                       "The selected account is deactivated: choose an active user.")
    if not await user_can_see_incident(db, target_user, inc.id):
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "assignee_no_access",
                       f"{target_user.username} can't see this incident (not in any of its teams). "
                       "An assignment doesn't grant access: add a team first.")

    row = IncidentAssignment(
        id=uuid.uuid4(),
        incident_id=incident_id,
        user_id=target_user.id,
        username=target_user.username,
        role_id=role.id,
        role_label=role.label,
        notes=req.notes,
        assigned_by_id=user.id,
        assigned_by_username=user.username,
    )
    db.add(row)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{target_user.username} already assigned as {role.label} on this incident",
        )

    await write_audit(
        db, "assignment_create",
        resource_type="assignment", resource_id=str(row.id),
        resource_label=f"{target_user.username} → {role.label}",
        details={"incident_id": str(incident_id)},
    )
    if target_user.id != user.id:
        await notify_assignment(        # commits, then pushes
            db, assignee_id=target_user.id, incident_id=inc.id, incident_ref=inc.ref or str(inc.id),
            role_label=role.label, assigner_username=user.username,
        )
    else:
        await db.commit()
    return _to_out(row)


@router.delete("/{incident_id}/assignments/{assignment_id}",
               status_code=status.HTTP_204_NO_CONTENT,
               summary="Remove an assignment",
               responses={403: {"model": ApiErrorBody, "description": "not_incident_lead"}})
async def delete_assignment(
    incident_id:   uuid.UUID,
    assignment_id: uuid.UUID,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> None:
    """Remove a responder assignment from the incident. Requires the analyst
    role. Analysts may remove their own assignment; the incident lead (an admin,
    or an analyst assigned as Incident Commander or Deputy here) may remove any.
    Removing an Incident Commander or Deputy assignment follows the rule for
    assigning one (lead or admin; while the incident has no lead, its creator or
    today's on-call analyst). Otherwise 403 code not_incident_lead. Rejected if the
    incident is closed. The removal is audited. Returns 204 No Content.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    row = await _get_assignment(db, incident_id, assignment_id)

    # IC / Deputy: as for assigning them. Others: your own, or anyone's as the lead.
    if await is_lead_role(db, row.role_id):
        if not await may_manage_lead_roles(db, user, inc):
            raise ApiError(status.HTTP_403_FORBIDDEN, "not_incident_lead",
                           f"Only this incident's lead or an admin can remove {_LEAD_ROLES}; while the "
                           "incident has no lead, its creator or today's on-call analyst can too.")
    elif row.user_id != user.id and not await is_incident_lead(db, user, inc):
        raise not_incident_lead("remove another user's assignment")

    await write_audit(
        db, "assignment_delete",
        resource_type="assignment", resource_id=str(row.id),
        resource_label=f"{row.username} → {row.role_label}",
        details={"incident_id": str(incident_id)},
    )
    await db.delete(row)
    await db.commit()
