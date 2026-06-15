"""Stakeholder Matrix — global notification rules.

Org-wide rules linking incident severity → stakeholder role → notification SLA.
Distinct from `backend/stakeholders/` which is per-incident contact CRUD.

Read access: any authenticated user (the incident Comms banner needs it).
Write access: admin only (org policy).
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_admin
from core.database import get_db
from models import StakeholderMatrixRule, User
from schemas import (
    StakeholderMatrixRuleCreate,
    StakeholderMatrixRuleList,
    StakeholderMatrixRuleOut,
    StakeholderMatrixRuleUpdate,
)

router = APIRouter()


@router.get("", response_model=StakeholderMatrixRuleList,
            operation_id="list_stakeholder_matrix_rules",
            summary="List stakeholder matrix rules")
async def list_rules(
    user: User       = Depends(current_user),
    db:   AsyncSession = Depends(get_db),
) -> StakeholderMatrixRuleList:
    """List all org-wide stakeholder notification rules, ordered by severity
    then role. Any authenticated user may read (the incident Comms banner needs
    it). Returns the full rule set as a list."""
    rows = (await db.execute(
        select(StakeholderMatrixRule)
        .order_by(StakeholderMatrixRule.severity, StakeholderMatrixRule.role)
    )).scalars().all()
    return StakeholderMatrixRuleList(
        items=[StakeholderMatrixRuleOut.model_validate(r) for r in rows]
    )


@router.post("",
             response_model=StakeholderMatrixRuleOut,
             status_code=status.HTTP_201_CREATED,
             operation_id="create_stakeholder_matrix_rule",
             summary="Create a stakeholder matrix rule")
async def create_rule(
    req: StakeholderMatrixRuleCreate,
    request: Request,
    user: User       = Depends(require_admin),
    db:   AsyncSession = Depends(get_db),
) -> StakeholderMatrixRuleOut:
    """Create an org-wide rule mapping incident severity and stakeholder role to
    a notification SLA and category. Admin only. Returns the created rule, or
    409 if a rule for the same severity / role / category already exists."""
    rule = StakeholderMatrixRule(
        id=uuid.uuid4(),
        severity=req.severity,
        role=req.role.strip(),
        notify_within_minutes=req.notify_within_minutes,
        category=req.category,
        required=req.required,
        created_by_id=user.id,
    )
    db.add(rule)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"A rule for {req.severity} / {req.role} / {req.category} already exists",
        )

    await write_audit(
        db, "stakeholder_matrix_create",
        user_id=user.id, username=user.username,
        resource_type="stakeholder_matrix_rule", resource_id=str(rule.id),
        details={
            "severity": rule.severity, "role": rule.role,
            "category": rule.category, "required": rule.required,
            "notify_within_minutes": rule.notify_within_minutes,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return StakeholderMatrixRuleOut.model_validate(rule)


@router.patch("/{rule_id}", response_model=StakeholderMatrixRuleOut,
              operation_id="update_stakeholder_matrix_rule",
              summary="Update a stakeholder matrix rule")
async def update_rule(
    rule_id: uuid.UUID,
    req: StakeholderMatrixRuleUpdate,
    request: Request,
    user: User       = Depends(require_admin),
    db:   AsyncSession = Depends(get_db),
) -> StakeholderMatrixRuleOut:
    """Partially update a stakeholder matrix rule (severity, role, category,
    notify_within_minutes, required); only supplied fields change. Admin only.
    Returns the updated rule, 404 if missing, or 409 if the change collides with
    an existing severity / role / category combination."""
    rule = (await db.execute(
        select(StakeholderMatrixRule).where(StakeholderMatrixRule.id == rule_id)
    )).scalar_one_or_none()
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")

    fields = req.model_fields_set
    changed: dict = {}
    if "severity" in fields and req.severity is not None and req.severity != rule.severity:
        rule.severity = req.severity; changed["severity"] = req.severity
    if "role" in fields and req.role is not None:
        cleaned = req.role.strip()
        if cleaned != rule.role:
            rule.role = cleaned; changed["role"] = cleaned
    if "notify_within_minutes" in fields and req.notify_within_minutes is not None \
            and req.notify_within_minutes != rule.notify_within_minutes:
        rule.notify_within_minutes = req.notify_within_minutes
        changed["notify_within_minutes"] = req.notify_within_minutes
    if "category" in fields and req.category is not None and req.category != rule.category:
        rule.category = req.category; changed["category"] = req.category
    if "required" in fields and req.required is not None and req.required != rule.required:
        rule.required = req.required; changed["required"] = req.required

    if changed:
        try:
            await db.flush()
        except IntegrityError:
            await db.rollback()
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "Another rule with the same severity / role / category already exists",
            )
        await write_audit(
            db, "stakeholder_matrix_update",
            user_id=user.id, username=user.username,
            resource_type="stakeholder_matrix_rule", resource_id=str(rule.id),
            details={"changes": changed},
            ip_address=request.client.host if request.client else None,
        )
    await db.commit()
    return StakeholderMatrixRuleOut.model_validate(rule)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT,
               operation_id="delete_stakeholder_matrix_rule",
               summary="Delete a stakeholder matrix rule")
async def delete_rule(
    rule_id: uuid.UUID,
    request: Request,
    user: User       = Depends(require_admin),
    db:   AsyncSession = Depends(get_db),
) -> Response:
    """Delete an org-wide stakeholder matrix rule. Admin only. Returns 204 No
    Content, or 404 if the rule does not exist."""
    rule = (await db.execute(
        select(StakeholderMatrixRule).where(StakeholderMatrixRule.id == rule_id)
    )).scalar_one_or_none()
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")

    await write_audit(
        db, "stakeholder_matrix_delete",
        user_id=user.id, username=user.username,
        resource_type="stakeholder_matrix_rule", resource_id=str(rule.id),
        details={
            "severity": rule.severity, "role": rule.role,
            "category": rule.category, "required": rule.required,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(rule)
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
