"""Cost tracking + business impact assessment (Post-Incident → Reports)."""
import uuid
from datetime import date
from decimal import Decimal
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from incidents.access import get_accessible_incident
from models import BusinessImpact, IncidentCost, Incident, User, COST_CATEGORIES, IR_PHASES

router = APIRouter()


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


# ── Business Impact ───────────────────────────────────────────────────────────

def _bia_to_out(b: BusinessImpact) -> dict:
    return {
        "id":           str(b.id),
        "incident_id":  str(b.incident_id),
        "financial":    b.financial,
        "operational":  b.operational,
        "data_exposure": b.data_exposure,
        "reputational": b.reputational,
        "regulatory":   b.regulatory,
        "legal":        b.legal,
        "notes":        b.notes,
        "updated_at":   b.updated_at.isoformat() if b.updated_at else None,
    }


async def _get_or_create_bia(db: AsyncSession, incident_id: uuid.UUID) -> BusinessImpact:
    row = (await db.execute(
        select(BusinessImpact).where(BusinessImpact.incident_id == incident_id)
    )).scalar_one_or_none()
    if not row:
        row = BusinessImpact(incident_id=incident_id)
        db.add(row)
        await db.flush()
    return row


@router.get("/{incident_id}/business-impact", summary="Get business impact assessment")
async def get_business_impact(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the business impact assessment (BIA) for an incident, creating an empty one if absent.

    Requires read access to the incident. Returns the BIA fields (financial, operational, data
    exposure, reputational, regulatory, legal, notes).
    """
    await _get_incident(db, incident_id, user)
    bia = await _get_or_create_bia(db, incident_id)
    await db.commit()
    return _bia_to_out(bia)


class BIAUpdate(BaseModel):
    financial:    Optional[str] = None
    operational:  Optional[str] = None
    data_exposure: Optional[str] = None
    reputational: Optional[str] = None
    regulatory:   Optional[str] = None
    legal:        Optional[str] = None
    notes:        Optional[str] = None


@router.patch("/{incident_id}/business-impact", summary="Update business impact assessment")
async def update_business_impact(
    incident_id: uuid.UUID,
    body: BIAUpdate,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Update the business impact assessment for an incident, creating it if absent.

    Only the provided (non-null) fields are written; the change is audit-logged. Requires the
    analyst role and write access. Returns the updated BIA.
    """
    await _get_incident(db, incident_id, user)
    bia = await _get_or_create_bia(db, incident_id)
    for field in ("financial", "operational", "data_exposure", "reputational",
                  "regulatory", "legal", "notes"):
        val = getattr(body, field)
        if val is not None:
            setattr(bia, field, val)
    bia.updated_by_id = user.id
    await write_audit(db, "bia_update", user_id=user.id, details={"incident_id": str(incident_id)})
    await db.commit()
    await db.refresh(bia)
    return _bia_to_out(bia)


# ── Cost Tracking ─────────────────────────────────────────────────────────────

def _cost_to_out(c: IncidentCost) -> dict:
    return {
        "id":           str(c.id),
        "incident_id":  str(c.incident_id),
        "category":     c.category,
        "description":  c.description,
        "amount":       float(c.amount),
        "currency":     c.currency,
        "ir_phase":     c.ir_phase,
        "is_estimated": c.is_estimated,
        "incurred_at":  c.incurred_at.isoformat() if c.incurred_at else None,
        "created_at":   c.created_at.isoformat(),
    }


@router.get("/{incident_id}/costs", summary="List incident cost line items")
async def list_costs(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all recorded cost line items for an incident, ordered by when each was incurred.

    Requires read access to the incident. Returns the cost entries with category, amount,
    currency, IR phase and estimated/realised flag.
    """
    await _get_incident(db, incident_id, user)
    rows = (await db.execute(
        select(IncidentCost)
        .where(IncidentCost.incident_id == incident_id)
        .order_by(IncidentCost.incurred_at.asc().nullslast(), IncidentCost.created_at)
    )).scalars().all()
    return [_cost_to_out(r) for r in rows]


@router.get("/{incident_id}/costs/summary", summary="Summarize incident costs")
async def cost_summary(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    """Aggregate an incident's cost line items into estimated/realised totals.

    Returns grand totals plus breakdowns by cost category and by IR phase. Requires read access to
    the incident.
    """
    await _get_incident(db, incident_id, user)
    rows = (await db.execute(
        select(IncidentCost).where(IncidentCost.incident_id == incident_id)
    )).scalars().all()

    by_category: dict = {}
    by_phase:    dict = {}
    total_estimated = 0.0
    total_realised  = 0.0
    currency = "USD"

    for c in rows:
        if c.currency:
            currency = c.currency
        amt = float(c.amount)
        cat = c.category
        if cat not in by_category:
            by_category[cat] = {"estimated": 0.0, "realised": 0.0}
        if c.is_estimated:
            by_category[cat]["estimated"] += amt
            total_estimated += amt
        else:
            by_category[cat]["realised"] += amt
            total_realised += amt

        if c.ir_phase:
            ph = c.ir_phase
            if ph not in by_phase:
                by_phase[ph] = {"estimated": 0.0, "realised": 0.0}
            if c.is_estimated:
                by_phase[ph]["estimated"] += amt
            else:
                by_phase[ph]["realised"] += amt

    return {
        "total_estimated": round(total_estimated, 2),
        "total_realised":  round(total_realised, 2),
        "total":           round(total_estimated + total_realised, 2),
        "currency":        currency,
        "by_category":     {k: {kk: round(vv, 2) for kk, vv in v.items()} for k, v in by_category.items()},
        "by_phase":        {k: {kk: round(vv, 2) for kk, vv in v.items()} for k, v in by_phase.items()},
    }


class CostCreate(BaseModel):
    category:     str
    description:  str
    amount:       float
    currency:     str = "USD"
    ir_phase:     Optional[str] = None
    is_estimated: bool = False
    incurred_at:  Optional[date] = None


@router.post("/{incident_id}/costs", status_code=status.HTTP_201_CREATED,
             summary="Add a cost line item")
async def create_cost(
    incident_id: uuid.UUID,
    body: CostCreate,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Record a new cost line item against an incident.

    Validates the category against the allowed set, the currency as a 3-letter ISO code, and the
    optional IR phase; invalid values return 422. Requires the analyst role and write access; the
    creation is audit-logged. Returns the created cost entry.
    """
    await _get_incident(db, incident_id, user)
    if body.category not in COST_CATEGORIES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"category must be one of {sorted(COST_CATEGORIES)}")
    if len(body.currency) != 3:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "currency must be a 3-letter ISO code")
    if body.ir_phase and body.ir_phase not in IR_PHASES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"ir_phase must be one of {sorted(IR_PHASES)}")

    c = IncidentCost(
        incident_id=incident_id,
        category=body.category,
        description=body.description.strip(),
        amount=Decimal(str(body.amount)),
        currency=body.currency.upper(),
        ir_phase=body.ir_phase or None,
        is_estimated=body.is_estimated,
        incurred_at=body.incurred_at,
        recorded_by_id=user.id,
    )
    db.add(c)
    await write_audit(db, "cost_create", user_id=user.id,
                      details={"incident_id": str(incident_id), "category": body.category,
                               "amount": body.amount, "is_estimated": body.is_estimated})
    await db.commit()
    await db.refresh(c)
    return _cost_to_out(c)


class CostUpdate(BaseModel):
    category:     Optional[str]   = None
    description:  Optional[str]   = None
    amount:       Optional[float] = None
    currency:     Optional[str]   = None
    ir_phase:     Optional[str]   = None
    is_estimated: Optional[bool]  = None
    incurred_at:  Optional[date]  = None


@router.patch("/{incident_id}/costs/{cost_id}", summary="Update a cost line item")
async def update_cost(
    incident_id: uuid.UUID,
    cost_id:     uuid.UUID,
    body:        CostUpdate,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Partially update a cost line item on an incident.

    Only provided fields are applied; category, currency and IR phase are re-validated and invalid
    values return 422. Returns 404 if the cost entry is not in this incident. Requires the analyst
    role and write access; the change is audit-logged. Returns the updated cost entry.
    """
    await _get_incident(db, incident_id, user)
    c = (await db.execute(
        select(IncidentCost).where(
            IncidentCost.id == cost_id,
            IncidentCost.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not c:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Cost entry not found")

    if body.category is not None:
        if body.category not in COST_CATEGORIES:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid category")
        c.category = body.category
    if body.description is not None:
        c.description = body.description.strip()
    if body.amount is not None:
        c.amount = Decimal(str(body.amount))
    if body.currency is not None:
        if len(body.currency) != 3:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "currency must be 3 letters")
        c.currency = body.currency.upper()
    if body.ir_phase is not None:
        if body.ir_phase and body.ir_phase not in IR_PHASES:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid ir_phase")
        c.ir_phase = body.ir_phase or None
    if body.is_estimated is not None:
        c.is_estimated = body.is_estimated
    if body.incurred_at is not None:
        c.incurred_at = body.incurred_at

    await write_audit(db, "cost_update", user_id=user.id,
                      details={"incident_id": str(incident_id), "cost_id": str(cost_id)})
    await db.commit()
    await db.refresh(c)
    return _cost_to_out(c)


@router.delete("/{incident_id}/costs/{cost_id}", status_code=status.HTTP_204_NO_CONTENT,
               summary="Delete a cost line item")
async def delete_cost(
    incident_id: uuid.UUID,
    cost_id:     uuid.UUID,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Delete a cost line item from an incident.

    Returns 404 if the cost entry is not in this incident. Requires the analyst role and write
    access; the deletion is audit-logged. Returns 204 No Content.
    """
    await _get_incident(db, incident_id, user)
    c = (await db.execute(
        select(IncidentCost).where(
            IncidentCost.id == cost_id,
            IncidentCost.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not c:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Cost entry not found")
    await write_audit(db, "cost_delete", user_id=user.id,
                      details={"incident_id": str(incident_id), "category": c.category,
                               "amount": float(c.amount)})
    await db.delete(c)
    await db.commit()
