"""Operational role catalog (CISA IR roles seeded; admin-extensible)."""
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_admin
from core.database import get_db
from models import OperationalRole, User
from schemas import OperationalRoleCreate, OperationalRoleOut, OperationalRoleUpdate

router = APIRouter()


@router.get("", response_model=list[OperationalRoleOut], summary="List operational roles")
async def list_roles(include_inactive: bool = False,
                     _: User = Depends(current_user),
                     db: AsyncSession = Depends(get_db)) -> list[OperationalRoleOut]:
    """List operational (CISA IR) roles ordered by sort order then label. By default
    only active roles are returned; pass include_inactive=true to include deactivated
    ones. Available to any authenticated user."""
    q = select(OperationalRole).order_by(OperationalRole.sort_order, OperationalRole.label)
    if not include_inactive:
        q = q.where(OperationalRole.is_active.is_(True))
    return [OperationalRoleOut.model_validate(r) for r in (await db.execute(q)).scalars()]


@router.post("", response_model=OperationalRoleOut, status_code=status.HTTP_201_CREATED,
             summary="Create an operational role")
async def create_role(req: OperationalRoleCreate, request: Request,
                      admin: User = Depends(require_admin),
                      db: AsyncSession = Depends(get_db)) -> OperationalRoleOut:
    """Create a custom (non-system) operational role from key, label, description and
    sort order. Returns 409 if the key already exists. Admin only. Returns the
    created role."""
    existing = await db.execute(select(OperationalRole).where(OperationalRole.key == req.key))
    if existing.scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "Role key already exists")
    r = OperationalRole(
        id=uuid.uuid4(),
        key=req.key, label=req.label, description=req.description,
        is_system=False, is_active=True, sort_order=req.sort_order,
    )
    db.add(r)
    await db.flush()
    await write_audit(
        db, "operational_role_create",
        user_id=admin.id, username=admin.username,
        resource_type="operational_role", resource_id=str(r.id),
        details={"key": r.key, "label": r.label},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return OperationalRoleOut.model_validate(r)


@router.patch("/{role_id}", response_model=OperationalRoleOut,
              summary="Update an operational role")
async def update_role(role_id: uuid.UUID, req: OperationalRoleUpdate, request: Request,
                      admin: User = Depends(require_admin),
                      db: AsyncSession = Depends(get_db)) -> OperationalRoleOut:
    """Partially update an operational role's label, description, active flag, or sort
    order. System roles may only change sort order and active flag; renaming or editing
    their description is rejected. Returns 404 if not found. Admin only. Returns the
    updated role."""
    r = (await db.execute(select(OperationalRole).where(OperationalRole.id == role_id))).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Role not found")

    changed: dict[str, object] = {}
    # System roles: only sort_order and is_active editable.
    if r.is_system:
        if req.label is not None:
            raise HTTPException(400, "Cannot rename a system role")
        if req.description is not None:
            raise HTTPException(400, "Cannot edit description of a system role")

    if req.label is not None and req.label != r.label:
        r.label = req.label; changed["label"] = req.label
    if req.description is not None and req.description != r.description:
        r.description = req.description; changed["description"] = req.description
    if req.is_active is not None and req.is_active != r.is_active:
        r.is_active = req.is_active; changed["is_active"] = req.is_active
    if req.sort_order is not None and req.sort_order != r.sort_order:
        r.sort_order = req.sort_order; changed["sort_order"] = req.sort_order

    if changed:
        await write_audit(
            db, "operational_role_update",
            user_id=admin.id, username=admin.username,
            resource_type="operational_role", resource_id=str(r.id),
            details={"key": r.key, "changes": changed},
            ip_address=request.client.host if request.client else None,
        )
    await db.commit()
    return OperationalRoleOut.model_validate(r)


@router.delete("/{role_id}", summary="Delete an operational role")
async def delete_role(role_id: uuid.UUID, request: Request,
                      admin: User = Depends(require_admin),
                      db: AsyncSession = Depends(get_db)) -> dict:
    """Delete a custom operational role. System roles cannot be deleted (deactivate
    them instead) and return 400. Returns 404 if not found. Admin only."""
    r = (await db.execute(select(OperationalRole).where(OperationalRole.id == role_id))).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Role not found")
    if r.is_system:
        raise HTTPException(400, "System roles cannot be deleted (deactivate instead)")
    await write_audit(
        db, "operational_role_delete",
        user_id=admin.id, username=admin.username,
        resource_type="operational_role", resource_id=str(r.id),
        details={"key": r.key, "label": r.label},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(r)
    await db.commit()
    return {"status": "ok"}
