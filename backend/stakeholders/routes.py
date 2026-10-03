"""Per-incident stakeholder contact registry.

E2: POST …/stakeholders with `contact_id` copies a Contacts-directory entry (org_contacts) into the
incident. The copy is independent: editing or deleting the directory entry later never changes it.
"""
import copy
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from core.errors import ApiError
from incidents.access import get_accessible_incident
from models import Incident, IncidentStakeholder, OrgContact, User
from schemas import (
    IncidentStakeholderBulkCreate,
    IncidentStakeholderBulkResult,
    IncidentStakeholderCreate,
    IncidentStakeholderList,
    IncidentStakeholderOut,
    IncidentStakeholderUpdate,
)

router = APIRouter()


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


async def _get_stakeholder(
    db: AsyncSession, incident_id: uuid.UUID, stakeholder_id: uuid.UUID
) -> IncidentStakeholder:
    row = (await db.execute(
        select(IncidentStakeholder).where(
            IncidentStakeholder.id == stakeholder_id,
            IncidentStakeholder.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Stakeholder not found")
    return row


def _to_out(s: IncidentStakeholder) -> IncidentStakeholderOut:
    return IncidentStakeholderOut.model_validate(s)


_COPIED = ("name", "title", "organization", "type", "contact_methods", "notes", "available_hours")


async def _stakeholder_values(db: AsyncSession, req: IncidentStakeholderCreate) -> dict:
    """The new row's fields: the request's, or a copy of the directory entry `contact_id` with any
    non-null field the request also sent taking precedence."""
    def sent(f):
        v = getattr(req, f)
        return [m.model_dump() for m in v] if f == "contact_methods" else v
    if req.contact_id is None:
        return {f: sent(f) for f in _COPIED}
    src = (await db.execute(select(OrgContact).where(OrgContact.id == req.contact_id))).scalar_one_or_none()
    if src is None:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "contact_not_found",
                       "No Contacts-directory entry has that contact_id.")
    vals = {f: copy.deepcopy(getattr(src, f)) for f in _COPIED}
    vals["contact_methods"] = vals["contact_methods"] or []
    for f in req.model_fields_set & set(_COPIED):
        if getattr(req, f) is not None:
            vals[f] = sent(f)
    return vals


@router.get("/{incident_id}/stakeholders", response_model=IncidentStakeholderList,
            summary="List stakeholders")
async def list_stakeholders(
    incident_id: uuid.UUID,
    type: str | None = Query(None),
    q:    str | None = Query(None),
    user: User = Depends(current_user),
    db:   AsyncSession = Depends(get_db),
) -> IncidentStakeholderList:
    """List the incident's stakeholder contacts, ordered by name. Requires
    access to the incident. Optionally filter by `type` and a free-text `q`
    matched against name, organization, and title.
    """
    await _get_incident(db, incident_id, user)
    stmt = select(IncidentStakeholder).where(
        IncidentStakeholder.incident_id == incident_id
    ).order_by(IncidentStakeholder.name)
    if type:
        stmt = stmt.where(IncidentStakeholder.type == type)
    rows = (await db.execute(stmt)).scalars().all()
    if q:
        q_lower = q.lower()
        rows = [r for r in rows if q_lower in r.name.lower()
                or (r.organization and q_lower in r.organization.lower())
                or (r.title and q_lower in r.title.lower())]
    return IncidentStakeholderList(items=[_to_out(r) for r in rows])


@router.post("/{incident_id}/stakeholders", response_model=IncidentStakeholderOut,
             status_code=status.HTTP_201_CREATED,
             summary="Add a stakeholder")
async def create_stakeholder(
    incident_id: uuid.UUID,
    req:  IncidentStakeholderCreate,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> IncidentStakeholderOut:
    """Add a stakeholder contact (name, title, organization, type, contact
    methods, notes, availability) to the incident. Requires the analyst role.
    Rejected if the incident is closed. The creation is audited and the new
    stakeholder returned.

    With `contact_id` the stakeholder is a copy of that Contacts-directory entry
    (GET /api/contacts); `name` is then optional and any other non-null field
    you send overrides the copied value. The incident keeps its own copy: later
    directory edits or deletes don't change it. Unknown contact_id: 422
    contact_not_found.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    vals = await _stakeholder_values(db, req)
    row = IncidentStakeholder(
        id=uuid.uuid4(),
        incident_id=incident_id,
        created_by_id=user.id,
        **vals,
    )
    db.add(row)
    await db.flush()
    details = {"incident_id": str(incident_id), "type": row.type}
    if req.contact_id is not None:
        details["contact_id"] = str(req.contact_id)
    await write_audit(
        db, "stakeholder_create",
        resource_type="stakeholder", resource_id=str(row.id),
        resource_label=row.name,
        details=details,
    )
    await db.commit()
    return _to_out(row)


@router.patch("/{incident_id}/stakeholders/{stakeholder_id}",
              response_model=IncidentStakeholderOut,
              summary="Update a stakeholder")
async def update_stakeholder(
    incident_id:    uuid.UUID,
    stakeholder_id: uuid.UUID,
    req:  IncidentStakeholderUpdate,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> IncidentStakeholderOut:
    """Update fields on an incident stakeholder; only the provided fields are
    changed. Requires the analyst role. Rejected if the incident is closed. The
    update is audited and the updated stakeholder returned.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    row = await _get_stakeholder(db, incident_id, stakeholder_id)

    if req.name            is not None: row.name            = req.name
    if req.title           is not None: row.title           = req.title
    if req.organization    is not None: row.organization    = req.organization
    if req.type            is not None: row.type            = req.type
    if req.contact_methods is not None:
        row.contact_methods = [m.model_dump() for m in req.contact_methods]
    if req.notes           is not None: row.notes           = req.notes
    if req.available_hours is not None: row.available_hours = req.available_hours

    await write_audit(
        db, "stakeholder_update",
        resource_type="stakeholder", resource_id=str(row.id),
        resource_label=row.name,
        details={"incident_id": str(incident_id)},
    )
    await db.commit()
    return _to_out(row)


@router.delete("/{incident_id}/stakeholders/{stakeholder_id}",
               status_code=status.HTTP_204_NO_CONTENT,
               summary="Remove a stakeholder")
async def delete_stakeholder(
    incident_id:    uuid.UUID,
    stakeholder_id: uuid.UUID,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> None:
    """Remove a stakeholder contact from the incident. Requires the analyst
    role. The deletion is audited. Returns 204 No Content.
    """
    await _get_incident(db, incident_id, user)
    row = await _get_stakeholder(db, incident_id, stakeholder_id)
    await write_audit(
        db, "stakeholder_delete",
        resource_type="stakeholder", resource_id=str(row.id),
        resource_label=row.name,
        details={"incident_id": str(incident_id)},
    )
    await db.delete(row)
    await db.commit()


@router.post("/{incident_id}/stakeholders/bulk",
             response_model=IncidentStakeholderBulkResult,
             status_code=status.HTTP_200_OK,
             summary="Bulk import stakeholders")
async def bulk_create_stakeholders(
    incident_id: uuid.UUID,
    req:  IncidentStakeholderBulkCreate,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> IncidentStakeholderBulkResult:
    """Import multiple stakeholder contacts onto the incident in one request.
    Requires the analyst role. Rejected if the incident is closed. Rows are
    processed individually; the import is audited. Returns the number created
    and a list of per-row error messages.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    created = 0
    errors: list[str] = []

    for i, row_data in enumerate(req.rows):
        try:
            row = IncidentStakeholder(
                id=uuid.uuid4(),
                incident_id=incident_id,
                name=row_data.name,
                title=row_data.title,
                organization=row_data.organization,
                type=row_data.type,
                contact_methods=[m.model_dump() for m in row_data.contact_methods],
                notes=row_data.notes,
                available_hours=row_data.available_hours,
                created_by_id=user.id,
            )
            db.add(row)
            await db.flush()
            created += 1
        except Exception as e:
            errors.append(f"Row {i + 1} ({row_data.name!r}): {e}")

    await write_audit(
        db, "stakeholder_bulk_import",
        resource_type="incident", resource_id=str(incident_id),
        details={"created": created, "errors": len(errors)},
    )
    await db.commit()
    return IncidentStakeholderBulkResult(created=created, errors=errors)
