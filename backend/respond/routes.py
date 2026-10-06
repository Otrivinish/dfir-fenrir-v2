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
from core.errors import ApiError, ApiErrorBody
from incidents.access import get_accessible_incident, require_incident_person
from models import IOC, Decision, Entity, Incident, PlaybookTask, RespondAction, TimelineEvent, User
from respond.containment import check_target_type
from schemas import (
    LinkedActionRef,
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

# F2 — person-reference errors (incidents.access.require_incident_person).
_PERSON_ERRORS = {404: {"model": ApiErrorBody, "description": "user_not_found (unknown assignee_id / decided_by_id)"},
                  422: {"model": ApiErrorBody, "description": "assignee_no_access (that user is deactivated or "
                                                              "can't see the incident)"}}


# L11, accepted: a row deleted between two page reads makes an offset cursor skip one row; the war room pages by keyset.
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


async def _linked(db: AsyncSession, incident_id: uuid.UUID, model, obj_id: uuid.UUID, kind: str):
    """Load the entity / IOC an action links to: 404 if unknown, 422 if on another incident."""
    obj = await db.get(model, obj_id)
    label = "Entity" if kind == "entity" else "IOC"
    if obj is None:
        raise ApiError(status.HTTP_404_NOT_FOUND, f"{kind}_not_found", f"{label} not found")
    if obj.incident_id != incident_id:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, f"{kind}_other_incident",
                       f"{label} belongs to another incident; link one from this incident")
    return obj


async def _linked_ref(db: AsyncSession, incident_id: uuid.UUID, model, obj_id: uuid.UUID, kind: str):
    """J5: load the decision / playbook task an action links to: 404 {kind}_not_found, 422
    {kind}_other_incident; an archived task (replaced plan) is 422 task_archived."""
    obj = await db.get(model, obj_id)
    label = "Decision" if kind == "decision" else "Playbook task"
    if obj is None:
        raise ApiError(status.HTTP_404_NOT_FOUND, f"{kind}_not_found", f"{label} not found")
    if obj.incident_id != incident_id:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, f"{kind}_other_incident",
                       f"{label} belongs to another incident; link one from this incident")
    if kind == "task" and obj.archived_at is not None:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "task_archived",
                       "That task is history from a replaced plan; link a task of the current plan.")
    return obj


async def linked_actions_map(db: AsyncSession, column, ids) -> dict[uuid.UUID, list[LinkedActionRef]]:
    """J5: {decision or task id: the actions linked to it}. `column` is RespondAction.decision_id or
    RespondAction.task_id. One query."""
    ids = list(ids)
    if not ids:
        return {}
    rows = (await db.execute(
        select(column.label("owner_id"), RespondAction.id, RespondAction.title, RespondAction.category,
               RespondAction.status)
        .where(column.in_(ids))
        .order_by(RespondAction.category, RespondAction.order_index, RespondAction.created_at, RespondAction.id)
    )).all()
    out: dict[uuid.UUID, list[LinkedActionRef]] = {}
    for r in rows:
        out.setdefault(r.owner_id, []).append(
            LinkedActionRef(id=r.id, title=r.title, category=r.category, status=r.status))
    return out


async def _decision_out(db: AsyncSession, dec: Decision) -> DecisionOut:
    out = DecisionOut.model_validate(dec)
    out.linked_actions = (await linked_actions_map(db, RespondAction.decision_id, [dec.id])).get(dec.id, [])
    return out


async def _set_decision_actions(db: AsyncSession, incident_id: uuid.UUID, dec: Decision,
                                action_ids: list[uuid.UUID]) -> dict:
    """J5: make `action_ids` exactly the actions this decision approves. Returns {linked, unlinked}
    (ids as str) for the audit row; 404 action_not_found / 422 action_other_incident."""
    wanted = list(dict.fromkeys(action_ids))
    for aid in wanted:
        act = await db.get(RespondAction, aid)
        if act is None:
            raise ApiError(status.HTTP_404_NOT_FOUND, "action_not_found", "Response action not found")
        if act.incident_id != incident_id:
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "action_other_incident",
                           "Response action belongs to another incident; link one from this incident")
    current = (await db.execute(select(RespondAction).where(RespondAction.decision_id == dec.id))).scalars().all()
    unlinked = [a for a in current if a.id not in wanted]
    for a in unlinked:
        a.decision_id = None
    linked = []
    for aid in wanted:
        act = await db.get(RespondAction, aid)
        if act.decision_id != dec.id:
            act.decision_id = dec.id
            linked.append(str(aid))
    return {"linked": linked, "unlinked": [str(a.id) for a in unlinked]}


async def _fill_target(db: AsyncSession, action: RespondAction,
                       entity: Optional[Entity] = None, ioc: Optional[IOC] = None) -> None:
    """An empty target text takes the linked entity's (else IOC's) value."""
    if str((action.details or {}).get("target") or "").strip():
        return
    src = entity or ioc
    if src is None and action.entity_id:
        src = await db.get(Entity, action.entity_id)
    if src is None and action.ioc_id:
        src = await db.get(IOC, action.ioc_id)
    if src is not None:
        action.details = {**(action.details or {}), "target": src.value}


def _add_done_timeline_event(db: AsyncSession, action: RespondAction,
                             incident_id: uuid.UUID, user: User) -> None:
    """Stage the system timeline event for an action that has just become `done`.

    Placed at the time the action occurred, else its completion time. The caller commits.
    """
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


# ─── Actions — list ──────────────────────────────────────────────────────────

@router.get("/{incident_id}/respond/actions", response_model=RespondActionList,
            summary="List response actions")
async def list_respond_actions(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
    category: Optional[RespondActionCategory] = Query(default=None),
    entity_id: Optional[uuid.UUID]            = Query(default=None, description="Only actions linked to this entity"),
    ioc_id:    Optional[uuid.UUID]            = Query(default=None, description="Only actions linked to this IOC"),
    limit:    int                              = Query(default=100, ge=1, le=200),
    cursor:   Optional[str]                   = Query(default=None),
) -> RespondActionList:
    """List response actions (containment/eradication/recovery) for an incident.

    Any authenticated user with access to the incident may read. Optionally
    filter by `category`, by linked `entity_id` or by linked `ioc_id`;
    paginated via `limit` and opaque `cursor`. Returns `{items, next_cursor}`
    ordered by category, then order index, then created time (then id, so pages
    never split or repeat rows that tie).
    """
    await _get_incident(db, incident_id, user)
    offset = _decode_cursor(cursor)

    stmt = (
        select(RespondAction)
        .where(RespondAction.incident_id == incident_id)
        .order_by(RespondAction.category, RespondAction.order_index, RespondAction.created_at, RespondAction.id)
    )
    if category:
        stmt = stmt.where(RespondAction.category == category)
    if entity_id:
        stmt = stmt.where(RespondAction.entity_id == entity_id)
    if ioc_id:
        stmt = stmt.where(RespondAction.ioc_id == ioc_id)

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
             summary="Create a response action",
             responses=_PERSON_ERRORS)
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
    the created action is returned. Creating it as `done` stamps completion and
    emits a system timeline event, as marking it done later does.

    `entity_id` / `ioc_id` link the action to its target on this incident
    (404 `entity_not_found` / `ioc_not_found`; 422 `entity_other_incident` /
    `ioc_other_incident`); an empty `details.target` is then filled from the
    entity's or IOC's value. A containment `template_id` (e.g. `isolate_host`,
    `block_ip`) sets the linked entity's / IOC's containment state, and only
    links of a matching type are accepted (422 `target_type_mismatch`, e.g.
    `isolate_host` on a hash IOC); a free-text target is not checked.

    `assignee_id` must be an active user who can see the incident (404
    `user_not_found`, 422 `assignee_no_access`).

    J5: `decision_id` links the decision that approved the action and `task_id` the
    playbook task it carries out (same incident: 404 `decision_not_found` /
    `task_not_found`, 422 `decision_other_incident` / `task_other_incident` /
    `task_archived`). Links only: completing a task never completes an action.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    if req.assignee_id is not None:
        await require_incident_person(db, incident_id, req.assignee_id)

    entity = await _linked(db, incident_id, Entity, req.entity_id, "entity") if req.entity_id else None
    ioc    = await _linked(db, incident_id, IOC, req.ioc_id, "ioc") if req.ioc_id else None
    check_target_type(req.template_id, entity, ioc)
    if req.decision_id:
        await _linked_ref(db, incident_id, Decision, req.decision_id, "decision")
    if req.task_id:
        await _linked_ref(db, incident_id, PlaybookTask, req.task_id, "task")

    action = RespondAction(
        id=uuid.uuid4(),
        incident_id=incident_id,
        category=req.category,
        title=req.title.strip(),
        description=req.description,
        status=req.status,
        assignee_id=req.assignee_id,
        notes=req.notes,
        defer_reason=(req.defer_reason or "").strip() or None,
        details=req.details or {},
        order_index=req.order_index,
        created_by_id=user.id,
        occurred_at=req.occurred_at,
        completed_at=datetime.now(timezone.utc) if req.status == "done" else None,
        entity_id=req.entity_id,
        ioc_id=req.ioc_id,
        template_id=req.template_id,
        decision_id=req.decision_id,
        task_id=req.task_id,
    )
    await _fill_target(db, action, entity, ioc)
    db.add(action)
    await db.flush()

    audit_details = {"incident_id": str(incident_id), "category": action.category, "title": action.title}
    for key in ("entity_id", "ioc_id", "template_id", "decision_id", "task_id"):
        if getattr(action, key):
            audit_details[key] = str(getattr(action, key))
    await write_audit(
        db, "respond_action_create",
        user_id=user.id, username=user.username,
        resource_type="respond_action", resource_id=str(action.id),
        details=audit_details,
        ip_address=request.client.host if request.client else None,
    )
    if action.status == "done":
        _add_done_timeline_event(db, action, incident_id, user)
    await db.commit()
    return RespondActionOut.model_validate(action)


# ─── Actions — update ────────────────────────────────────────────────────────

@router.patch("/{incident_id}/respond/actions/{action_id}", response_model=RespondActionOut,
              summary="Update a response action", responses=_PERSON_ERRORS)
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

    `entity_id`, `ioc_id` and `template_id` change only when sent; an explicit
    null unlinks / clears. Links are checked as on create (404 / 422), and an
    empty `details.target` is filled from the linked entity or IOC. When the
    template or a link changes, the resulting template / target-type pair is
    checked as on create (422 `target_type_mismatch`).

    A new `assignee_id` is checked as on create (404 `user_not_found`, 422
    `assignee_no_access`); an explicit `"assignee_id": null` unassigns.

    `decision_id` / `task_id` (J5) change only when sent and are checked as on
    create; an explicit null unlinks.
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

    sent = req.model_fields_set
    entity = await _linked(db, incident_id, Entity, req.entity_id, "entity") \
        if "entity_id" in sent and req.entity_id else None
    ioc    = await _linked(db, incident_id, IOC, req.ioc_id, "ioc") \
        if "ioc_id" in sent and req.ioc_id else None
    # The template / target pair the action ends up with, checked only when it changes.
    final = {k: getattr(req, k) if k in sent else getattr(action, k) for k in ("template_id", "entity_id", "ioc_id")}
    if any(final[k] != getattr(action, k) for k in final):
        check_target_type(
            final["template_id"],
            entity if "entity_id" in sent else (await db.get(Entity, final["entity_id"]) if final["entity_id"] else None),
            ioc if "ioc_id" in sent else (await db.get(IOC, final["ioc_id"]) if final["ioc_id"] else None),
        )

    for key, model, kind in (("decision_id", Decision, "decision"), ("task_id", PlaybookTask, "task")):
        new = getattr(req, key)
        if key in sent and new and new != getattr(action, key):
            await _linked_ref(db, incident_id, model, new, kind)

    changed: dict[str, object] = {}
    if req.title       is not None and req.title.strip() != action.title:
        action.title = req.title.strip(); changed["title"] = action.title
    if req.description is not None and req.description != (action.description or ""):
        action.description = req.description;  changed["description"] = True
    if req.notes       is not None and req.notes != (action.notes or ""):
        action.notes = req.notes;              changed["notes"] = True
    if req.defer_reason is not None and (req.defer_reason.strip() or None) != action.defer_reason:
        action.defer_reason = req.defer_reason.strip() or None;  changed["defer_reason"] = action.defer_reason
    if req.details     is not None:
        action.details = req.details;          changed["details"] = True
    if req.order_index is not None and req.order_index != action.order_index:
        action.order_index = req.order_index;  changed["order_index"] = req.order_index
    if "assignee_id" in sent and req.assignee_id != action.assignee_id:
        if req.assignee_id is not None:        # clearing needs no check
            await require_incident_person(db, incident_id, req.assignee_id)
        action.assignee_id = req.assignee_id
        changed["assignee_id"] = str(req.assignee_id) if req.assignee_id else None
    for key in ("entity_id", "ioc_id", "template_id", "decision_id", "task_id"):
        new = getattr(req, key)
        if key in sent and new != getattr(action, key):
            setattr(action, key, new)
            changed[key] = str(new) if new else None
    if changed.keys() & {"details", "entity_id", "ioc_id"}:
        await _fill_target(db, action, entity, ioc)

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
        _add_done_timeline_event(db, action, incident_id, user)

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
    links       = await linked_actions_map(db, RespondAction.decision_id, [d.id for d in items])
    for d in items:
        d.linked_actions = links.get(d.id, [])
    next_cursor = _encode_cursor(offset + limit) if has_more else None
    return DecisionList(items=items, next_cursor=next_cursor)


# ─── Decisions — create ──────────────────────────────────────────────────────

@router.post("/{incident_id}/respond/decisions",
             response_model=DecisionOut,
             status_code=status.HTTP_201_CREATED,
             summary="Log a decision",
             responses=_PERSON_ERRORS)
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
    decider (`decided_by_id`) must be an active user who can see the incident (404
    `user_not_found`, 422 `assignee_no_access`). The decision is audited and a
    system timeline event is emitted. Returns the created decision.

    J5: `action_ids` links the actions this decision approves (sets their
    `decision_id`; 404 `action_not_found`, 422 `action_other_incident`); the response
    lists them in `linked_actions`.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    if req.decided_by_id is not None:
        await require_incident_person(db, incident_id, req.decided_by_id, "the decider")

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

    audit_details = {"incident_id": str(incident_id), "outcome": dec.outcome, "summary": dec.summary[:120]}
    if req.action_ids:
        audit_details["action_ids"] = (await _set_decision_actions(db, incident_id, dec, req.action_ids))["linked"]
    await write_audit(
        db, "decision_create",
        user_id=user.id, username=user.username,
        resource_type="decision", resource_id=str(dec.id),
        details=audit_details,
        ip_address=request.client.host if request.client else None,
    )
    add_decision_timeline_event(db, dec, incident_id, user)

    await db.commit()
    return await _decision_out(db, dec)


def add_decision_timeline_event(db: AsyncSession, dec: Decision, incident_id: uuid.UUID, user: User) -> None:
    """Stage the system timeline event for a new decision (also used by J4 promote). The caller commits."""
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


# ─── Decisions — update ──────────────────────────────────────────────────────

@router.patch("/{incident_id}/respond/decisions/{decision_id}", response_model=DecisionOut,
              summary="Update a decision", responses=_PERSON_ERRORS)
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
    and audited. A new `decided_by_id` is checked as on create (404
    `user_not_found`, 422 `assignee_no_access`); an explicit `"decided_by_id": null`
    clears the decider. `action_ids` (J5) replaces the approved actions ([] unlinks
    all; omit to keep). Returns the updated decision.
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
    if "decided_by_id" in req.model_fields_set and req.decided_by_id != dec.decided_by_id:
        if req.decided_by_id is not None:      # clearing needs no check
            await require_incident_person(db, incident_id, req.decided_by_id, "the decider")
        dec.decided_by_id = req.decided_by_id
        changed["decided_by_id"] = str(req.decided_by_id) if req.decided_by_id else None
    if req.decided_at    is not None and req.decided_at != dec.decided_at:
        dec.decided_at = req.decided_at;       changed["decided_at"] = True
    if req.tags          is not None:
        dec.tags = req.tags;                   changed["tags"] = req.tags
    if req.action_ids    is not None:
        links = await _set_decision_actions(db, incident_id, dec, req.action_ids)
        if links["linked"] or links["unlinked"]:
            changed["action_ids"] = links

    if changed:
        await write_audit(
            db, "decision_update",
            user_id=user.id, username=user.username,
            resource_type="decision", resource_id=str(dec.id),
            details={"incident_id": str(incident_id), "changes": changed},
            ip_address=request.client.host if request.client else None,
        )
    await db.commit()
    return await _decision_out(db, dec)


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
