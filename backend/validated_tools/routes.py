"""Validated-tools registry (ISO/IEC 27041, GS-1).

A governed catalog of validated forensic tools/methods. Listing is open to any
authenticated user (the acquisition/examination wizards pick from it); create/update/
delete are admin-only. Each mutation is written to the hash-chained audit log.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_admin
from core.database import get_db
from models import User, ValidatedTool
from schemas import (ValidatedToolCreate, ValidatedToolList, ValidatedToolOut,
                     ValidatedToolUpdate)

router = APIRouter()


@router.get("", response_model=ValidatedToolList, summary="List validated tools")
async def list_validated_tools(
    include_inactive: bool = Query(default=False),
    user: User = Depends(current_user),
    db:   AsyncSession = Depends(get_db),
) -> ValidatedToolList:
    """List validated forensic tools/methods ordered by name then version. By default
    only active entries are returned; pass include_inactive=true to include retired
    ones. Available to any authenticated user."""
    stmt = select(ValidatedTool).order_by(ValidatedTool.name, ValidatedTool.version)
    if not include_inactive:
        stmt = stmt.where(ValidatedTool.is_active.is_(True))
    rows = (await db.execute(stmt)).scalars().all()
    return ValidatedToolList(items=[ValidatedToolOut.model_validate(r) for r in rows])


@router.post("", response_model=ValidatedToolOut, status_code=status.HTTP_201_CREATED,
             summary="Create a validated tool")
async def create_validated_tool(
    req:     ValidatedToolCreate,
    request: Request,
    admin:   User = Depends(require_admin),
    db:      AsyncSession = Depends(get_db),
) -> ValidatedToolOut:
    """Register a validated forensic tool/method (name, version, validation reference,
    scope, validator, validation date, notes). Returns 409 if the name + version pair
    already exists. Admin only. Returns the created entry."""
    tool = ValidatedTool(
        id=uuid.uuid4(), name=req.name.strip(), version=req.version.strip(),
        validation_ref=req.validation_ref, scope=req.scope,
        validated_by=req.validated_by, validated_at=req.validated_at,
        notes=req.notes, is_active=True,
    )
    db.add(tool)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "A validated tool with this name + version already exists")
    await write_audit(
        db, "validated_tool_create",
        user_id=admin.id, username=admin.username,
        resource_type="validated_tool", resource_id=str(tool.id),
        details={"name": tool.name, "version": tool.version, "validation_ref": tool.validation_ref},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return ValidatedToolOut.model_validate(tool)


@router.patch("/{tool_id}", response_model=ValidatedToolOut,
              summary="Update a validated tool")
async def update_validated_tool(
    tool_id: uuid.UUID,
    req:     ValidatedToolUpdate,
    request: Request,
    admin:   User = Depends(require_admin),
    db:      AsyncSession = Depends(get_db),
) -> ValidatedToolOut:
    """Partially update a validated tool's validation reference, scope, validator,
    validation date, notes, or active flag. Returns 404 if not found. Admin only.
    Returns the updated entry."""
    tool = (await db.execute(
        select(ValidatedTool).where(ValidatedTool.id == tool_id)
    )).scalar_one_or_none()
    if not tool:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Validated tool not found")
    changed = {}
    for field in ("validation_ref", "scope", "validated_by", "validated_at", "notes", "is_active"):
        val = getattr(req, field)
        if val is not None and val != getattr(tool, field):
            setattr(tool, field, val)
            changed[field] = val
    await write_audit(
        db, "validated_tool_update",
        user_id=admin.id, username=admin.username,
        resource_type="validated_tool", resource_id=str(tool.id),
        details={"name": tool.name, "version": tool.version, "changed": list(changed.keys())},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return ValidatedToolOut.model_validate(tool)


@router.delete("/{tool_id}", status_code=status.HTTP_204_NO_CONTENT,
               summary="Delete a validated tool")
async def delete_validated_tool(
    tool_id: uuid.UUID,
    request: Request,
    admin:   User = Depends(require_admin),
    db:      AsyncSession = Depends(get_db),
) -> Response:
    """Delete a validated tool entry. Returns 404 if not found and 204 on success.
    Admin only."""
    tool = (await db.execute(
        select(ValidatedTool).where(ValidatedTool.id == tool_id)
    )).scalar_one_or_none()
    if not tool:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Validated tool not found")
    await write_audit(
        db, "validated_tool_delete",
        user_id=admin.id, username=admin.username,
        resource_type="validated_tool", resource_id=str(tool.id),
        details={"name": tool.name, "version": tool.version},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(tool)
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
