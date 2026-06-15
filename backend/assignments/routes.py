"""Per-incident assignment roster — links users to incidents in operational roles."""
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from incidents.access import get_accessible_incident
from models import Incident, IncidentAssignment, OperationalRole, User
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


@router.post("/{incident_id}/assignments", response_model=IncidentAssignmentOut,
             status_code=status.HTTP_201_CREATED,
             summary="Assign a responder")
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
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    # Resolve user
    target_user = (await db.execute(
        select(User).where(User.id == req.user_id)
    )).scalar_one_or_none()
    if not target_user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    # Resolve operational role
    role = (await db.execute(
        select(OperationalRole).where(
            OperationalRole.id == req.role_id,
            OperationalRole.is_active == True,
        )
    )).scalar_one_or_none()
    if not role:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Operational role not found or inactive")

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
    await db.commit()
    return _to_out(row)


@router.delete("/{incident_id}/assignments/{assignment_id}",
               status_code=status.HTTP_204_NO_CONTENT,
               summary="Remove an assignment")
async def delete_assignment(
    incident_id:   uuid.UUID,
    assignment_id: uuid.UUID,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> None:
    """Remove a responder assignment from the incident. Requires the analyst
    role; analysts may only remove their own assignment, while admins may remove
    any. Rejected if the incident is closed. The removal is audited. Returns 204
    No Content.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    row = await _get_assignment(db, incident_id, assignment_id)

    # Analysts can only remove themselves; admins can remove anyone.
    if user.role != "admin" and row.user_id != user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cannot remove another user's assignment")

    await write_audit(
        db, "assignment_delete",
        resource_type="assignment", resource_id=str(row.id),
        resource_label=f"{row.username} → {row.role_label}",
        details={"incident_id": str(incident_id)},
    )
    await db.delete(row)
    await db.commit()
