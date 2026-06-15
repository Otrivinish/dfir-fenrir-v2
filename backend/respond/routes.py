"""Per-incident Respond sub-section: action trackers + decisions log.

Mounted at prefix="/api/incidents" alongside other per-incident routers.

Action categories map to the 800-61 R3 CER phase:
  containment → Containment
  eradication → Eradication
  recovery    → Recovery

Decisions are records of choices made — distinct from work items (tasks).
"""
import base64
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from incidents.access import get_accessible_incident
from models import Decision, Incident, RespondAction, TimelineEvent, User
from schemas import (
    DecisionCreate,
    DecisionList,
    DecisionOut,
    DecisionUpdate,
    RespondActionCategory,
    RespondActionCreate,
    RespondActionList,
    RespondActionOut,
    RespondActionRevert,
    RespondActionUpdate,
)

router = APIRouter()


def _encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"o": offset}).encode()).decode().rstrip("=")


def _decode_cursor(cursor: Optional[str]) -> int:
    if not cursor:
        return 0
    try:
        pad = "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(cursor + pad).decode())
        return max(0, int(data.get("o", 0)))
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid cursor")


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


# ─── Actions — list ──────────────────────────────────────────────────────────

@router.get("/{incident_id}/respond/actions", response_model=RespondActionList,
            summary="List response actions")
async def list_respond_actions(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
    category: Optional[RespondActionCategory] = Query(default=None),
    limit:    int                              = Query(default=100, ge=1, le=200),
    cursor:   Optional[str]                   = Query(default=None),
) -> RespondActionList:
    """List response actions (containment/eradication/recovery) for an incident.

    Any authenticated user with access to the incident may read. Optionally
    filter by `category`; paginated via `limit` and opaque `cursor`. Returns
    `{items, next_cursor}` ordered by category, then order index, then created
    time.
    """
    await _get_incident(db, incident_id, user)
    offset = _decode_cursor(cursor)

    stmt = (
        select(RespondAction)
        .where(RespondAction.incident_id == incident_id)
        .order_by(RespondAction.category, RespondAction.order_index, RespondAction.created_at)
    )
    if category:
        stmt = stmt.where(RespondAction.category == category)

    stmt = stmt.offset(offset).limit(limit + 1)
    rows = (await db.execute(stmt)).scalars().all()

    has_more    = len(rows) > limit
    items       = [RespondActionOut.model_validate(r) for r in rows[:limit]]
    next_cursor = _encode_cursor(offset + limit) if has_more else None
    return RespondActionList(items=items, next_cursor=next_cursor)


# ─── Actions — create ────────────────────────────────────────────────────────

@router.post("/{incident_id}/respond/actions",
             response_model=RespondActionOut,
             status_code=status.HTTP_201_CREATED,
             summary="Create a response action")
async def create_respond_action(
    incident_id: uuid.UUID,
    req: RespondActionCreate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> RespondActionOut:
    """Create a response action under an incident's Respond section.

    Requires the analyst role. The incident must not be closed (409 otherwise).
    The action is categorised (containment/eradication/recovery), audited, and
    the created action is returned.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    action = RespondAction(
        id=uuid.uuid4(),
        incident_id=incident_id,
        category=req.category,
        title=req.title.strip(),
        description=req.description,
        status=req.status,
        assignee_id=req.assignee_id,
        notes=req.notes,
        details=req.details or {},
        order_index=req.order_index,
        created_by_id=user.id,
        occurred_at=req.occurred_at,
    )
    db.add(action)
    await db.flush()

    await write_audit(
        db, "respond_action_create",
        user_id=user.id, username=user.username,
        resource_type="respond_action", resource_id=str(action.id),
        details={"incident_id": str(incident_id), "category": action.category, "title": action.title},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return RespondActionOut.model_validate(action)


# ─── Actions — update ────────────────────────────────────────────────────────

@router.patch("/{incident_id}/respond/actions/{action_id}", response_model=RespondActionOut,
              summary="Update a response action")
async def update_respond_action(
    incident_id: uuid.UUID,
    action_id:   uuid.UUID,
    req: RespondActionUpdate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> RespondActionOut:
    """Update fields on an existing response action.

    Requires the analyst role; the incident must not be closed (409 otherwise).
    Only provided fields are changed and audited. Marking the action `done`
    stamps completion and emits a system timeline event. Returns the updated
    action.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    action = (await db.execute(
        select(RespondAction).where(
            RespondAction.id == action_id,
            RespondAction.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not action:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Action not found")

    changed: dict[str, object] = {}
    if req.title       is not None and req.title.strip() != action.title:
        action.title = req.title.strip(); changed["title"] = action.title
    if req.description is not None and req.description != (action.description or ""):
        action.description = req.description;  changed["description"] = True
    if req.notes       is not None and req.notes != (action.notes or ""):
        action.notes = req.notes;              changed["notes"] = True
    if req.details     is not None:
        action.details = req.details;          changed["details"] = True
    if req.order_index is not None and req.order_index != action.order_index:
        action.order_index = req.order_index;  changed["order_index"] = req.order_index
    if req.assignee_id is not None and req.assignee_id != action.assignee_id:
        action.assignee_id = req.assignee_id;  changed["assignee_id"] = str(req.assignee_id)

    status_became_done = False
    if req.status is not None and req.status != action.status:
        prev_status = action.status
        action.status = req.status
        if req.status == "done" and action.completed_at is None:
            action.completed_at = datetime.now(timezone.utc)
            status_became_done = True
        elif req.status != "done":
            action.completed_at = None
        changed["status"] = {"from": prev_status, "to": action.status}

    if req.occurred_at is not None and req.occurred_at != action.occurred_at:
        action.occurred_at = req.occurred_at
        changed["occurred_at"] = True

    if changed:
        await write_audit(
            db, "respond_action_update",
            user_id=user.id, username=user.username,
            resource_type="respond_action", resource_id=str(action.id),
            details={"incident_id": str(incident_id), "changes": changed},
            ip_address=request.client.host if request.client else None,
        )

    if status_became_done:
        event_time = action.occurred_at or action.completed_at
        desc_parts = [f"[{action.category.capitalize()}] {action.title}"]
        if action.details.get("target"):
            desc_parts.append(f"Target: {action.details['target']}")
        if action.notes:
            desc_parts.append(action.notes)
        db.add(TimelineEvent(
            id=uuid.uuid4(),
            incident_id=incident_id,
            event_time=event_time,
            source="Respond",
            event_type=action.category.capitalize(),
            description=" — ".join(desc_parts),
            origin="system",
            is_system=True,
            external_safe=False,
            system_source="respond_action",
            created_by_id=user.id,
        ))

    await db.commit()
    return RespondActionOut.model_validate(action)


# ─── Actions — revert ────────────────────────────────────────────────────────

@router.post("/{incident_id}/respond/actions/{action_id}/revert", response_model=RespondActionOut,
             summary="Revert a response action")
async def revert_respond_action(
    incident_id: uuid.UUID,
    action_id:   uuid.UUID,
    req: RespondActionRevert,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> RespondActionOut:
    """Roll back a response action, recording a required reason.

    Requires the analyst role; the incident must not be closed (409) and the
    action must not already be reverted (409). Sets status to `reverted`,
    stamps who/when, audits the change, and emits a system timeline event so
    the rollback is visible. Returns the reverted action.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    action = (await db.execute(
        select(RespondAction).where(
            RespondAction.id == action_id,
            RespondAction.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not action:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Action not found")
    if action.status == "reverted":
        raise HTTPException(status.HTTP_409_CONFLICT, "Action already reverted")

    prev_status = action.status
    now = datetime.now(timezone.utc)
    action.status = "reverted"
    action.reverted_at = now
    action.reverted_by_id = user.id
    action.revert_reason = req.revert_reason.strip()

    await write_audit(
        db, "respond_action_revert",
        user_id=user.id, username=user.username,
        resource_type="respond_action", resource_id=str(action.id),
        details={
            "incident_id": str(incident_id),
            "from_status": prev_status,
            "reason": action.revert_reason[:200],
        },
        ip_address=request.client.host if request.client else None,
    )

    # Auto-log to timeline so the rollback is visible alongside the original action.
    desc_parts = [f"[{action.category.capitalize()}] REVERTED: {action.title}"]
    desc_parts.append(f"Reason: {action.revert_reason}")
    db.add(TimelineEvent(
        id=uuid.uuid4(),
        incident_id=incident_id,
        event_time=now,
        source="Respond",
        event_type=f"{action.category.capitalize()} reverted",
        description=" — ".join(desc_parts),
        origin="system",
        is_system=True,
        external_safe=False,
        system_source="respond_action_revert",
        created_by_id=user.id,
    ))

    await db.commit()
    await db.refresh(action)
    return RespondActionOut.model_validate(action)


# ─── Actions — delete ────────────────────────────────────────────────────────

@router.delete("/{incident_id}/respond/actions/{action_id}",
               summary="Delete a response action")
async def delete_respond_action(
    incident_id: uuid.UUID,
    action_id:   uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Permanently delete a response action from an incident.

    Requires the analyst role; the incident must not be closed (409 otherwise).
    Returns 404 if the action is not found. The deletion is audited and the
    response is `{"status": "ok"}`.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    action = (await db.execute(
        select(RespondAction).where(
            RespondAction.id == action_id,
            RespondAction.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not action:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Action not found")

    await write_audit(
        db, "respond_action_delete",
        user_id=user.id, username=user.username,
        resource_type="respond_action", resource_id=str(action.id),
        details={"incident_id": str(incident_id), "category": action.category, "title": action.title},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(action)
    await db.commit()
    return {"status": "ok"}


# ─── Decisions — list ────────────────────────────────────────────────────────

@router.get("/{incident_id}/respond/decisions", response_model=DecisionList,
            summary="List decisions")
async def list_decisions(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
    limit:  int           = Query(default=100, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
) -> DecisionList:
    """List the decision-log records for an incident, newest first.

    Any authenticated user with access to the incident may read. Paginated via
    `limit` and opaque `cursor`. Returns `{items, next_cursor}`.
    """
    await _get_incident(db, incident_id, user)
    offset = _decode_cursor(cursor)

    stmt = (
        select(Decision)
        .where(Decision.incident_id == incident_id)
        .order_by(Decision.created_at.desc(), Decision.id)
        .offset(offset)
        .limit(limit + 1)
    )
    rows = (await db.execute(stmt)).scalars().all()

    has_more    = len(rows) > limit
    items       = [DecisionOut.model_validate(r) for r in rows[:limit]]
    next_cursor = _encode_cursor(offset + limit) if has_more else None
    return DecisionList(items=items, next_cursor=next_cursor)


# ─── Decisions — create ──────────────────────────────────────────────────────

@router.post("/{incident_id}/respond/decisions",
             response_model=DecisionOut,
             status_code=status.HTTP_201_CREATED,
             summary="Log a decision")
async def create_decision(
    incident_id: uuid.UUID,
    req: DecisionCreate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> DecisionOut:
    """Record a decision made during incident response.

    Requires the analyst role; the incident must not be closed (409 otherwise).
    Captures summary, rationale, outcome, decider and optional tags. The
    decision is audited and a system timeline event is emitted. Returns the
    created decision.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    dec = Decision(
        id=uuid.uuid4(),
        incident_id=incident_id,
        summary=req.summary.strip(),
        rationale=req.rationale,
        outcome=req.outcome,
        decided_by_id=req.decided_by_id,
        decided_at=req.decided_at,
        tags=req.tags or [],
        created_by_id=user.id,
    )
    db.add(dec)
    await db.flush()

    await write_audit(
        db, "decision_create",
        user_id=user.id, username=user.username,
        resource_type="decision", resource_id=str(dec.id),
        details={"incident_id": str(incident_id), "outcome": dec.outcome,
                 "summary": dec.summary[:120]},
        ip_address=request.client.host if request.client else None,
    )

    db.add(TimelineEvent(
        id=uuid.uuid4(),
        incident_id=incident_id,
        event_time=dec.decided_at or dec.created_at,
        source="Decisions",
        event_type="Decision",
        description=f"[Decision] {dec.summary[:200]}",
        origin="system",
        is_system=True,
        external_safe=False,
        system_source="decision",
        created_by_id=user.id,
    ))

    await db.commit()
    return DecisionOut.model_validate(dec)


# ─── Decisions — update ──────────────────────────────────────────────────────

@router.patch("/{incident_id}/respond/decisions/{decision_id}", response_model=DecisionOut,
              summary="Update a decision")
async def update_decision(
    incident_id: uuid.UUID,
    decision_id: uuid.UUID,
    req: DecisionUpdate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> DecisionOut:
    """Update fields on an existing decision-log record.

    Requires the analyst role; the incident must not be closed (409 otherwise).
    Returns 404 if the decision is not found. Only provided fields are changed
    and audited. Returns the updated decision.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    dec = (await db.execute(
        select(Decision).where(
            Decision.id == decision_id,
            Decision.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not dec:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Decision not found")

    changed: dict[str, object] = {}
    if req.summary       is not None and req.summary.strip() != dec.summary:
        dec.summary = req.summary.strip();     changed["summary"] = True
    if req.rationale     is not None and req.rationale != (dec.rationale or ""):
        dec.rationale = req.rationale;         changed["rationale"] = True
    if req.outcome       is not None and req.outcome != dec.outcome:
        dec.outcome = req.outcome;             changed["outcome"] = req.outcome
    if req.decided_by_id is not None and req.decided_by_id != dec.decided_by_id:
        dec.decided_by_id = req.decided_by_id; changed["decided_by_id"] = str(req.decided_by_id)
    if req.decided_at    is not None and req.decided_at != dec.decided_at:
        dec.decided_at = req.decided_at;       changed["decided_at"] = True
    if req.tags          is not None:
        dec.tags = req.tags;                   changed["tags"] = req.tags

    if changed:
        await write_audit(
            db, "decision_update",
            user_id=user.id, username=user.username,
            resource_type="decision", resource_id=str(dec.id),
            details={"incident_id": str(incident_id), "changes": changed},
            ip_address=request.client.host if request.client else None,
        )
    await db.commit()
    return DecisionOut.model_validate(dec)


# ─── Decisions — delete ──────────────────────────────────────────────────────

@router.delete("/{incident_id}/respond/decisions/{decision_id}",
               summary="Delete a decision")
async def delete_decision(
    incident_id: uuid.UUID,
    decision_id: uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Permanently delete a decision-log record from an incident.

    Requires the analyst role; the incident must not be closed (409 otherwise).
    Returns 404 if the decision is not found. The deletion is audited and the
    response is `{"status": "ok"}`.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    dec = (await db.execute(
        select(Decision).where(
            Decision.id == decision_id,
            Decision.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not dec:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Decision not found")

    await write_audit(
        db, "decision_delete",
        user_id=user.id, username=user.username,
        resource_type="decision", resource_id=str(dec.id),
        details={"incident_id": str(incident_id), "summary": dec.summary[:120]},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(dec)
    await db.commit()
    return {"status": "ok"}
