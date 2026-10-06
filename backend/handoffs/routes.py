"""Incident handoffs — shift-change snapshot per incident + global pending queue.

J4 (R32): the snapshot also stores the open Respond actions and the open playbook tasks of the
current phase (GET .../handoffs/prefill returns the same lists for the form); a next step can become
a playbook task for the recipient; the sender (IC / lead / admin) can ask for the Incident Commander
role to move to the recipient on acknowledgement. A viewer can't be a recipient: a viewer can't
acknowledge or act on the handoff (422 recipient_read_only).
"""
import uuid
from typing import get_args

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from incidents.access import (get_accessible_incident, is_incident_lead, not_incident_lead,
                              require_incident_person, user_can_see_incident)
from models import (
    Entity, Incident, IncidentAssignment, IncidentHandoff, IOC, OperationalRole, PlaybookTask,
    RespondAction, TimelineEvent, User, utcnow,
)
from notifications.service import commit_and_push, notify_handoff, queue_ic_transferred
from schemas import (
    HandoffPrefill,
    IncidentHandoffAcknowledge,
    IncidentHandoffCreate,
    IncidentHandoffList,
    IncidentHandoffOut,
    Phase,
)

router = APIRouter()

_OPEN = ("open", "in_progress")
_OPEN_ITEMS_CAP = 50       # per list, in the snapshot and the prefill
_MAX_STEP_TASKS = 50       # next steps turned into tasks per handoff
IC_ROLE_KEY = "incident_commander"


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


async def _open_items(db: AsyncSession, inc: Incident) -> tuple[list[dict], list[dict]]:
    """The open (open / in progress) Respond actions, any category, and the open playbook tasks of
    the incident's current phase (current plan only): [{id, title, owner, status, category | phase}],
    at most _OPEN_ITEMS_CAP each, owner = the assignee's username."""
    actions = (await db.execute(
        select(RespondAction.id, RespondAction.title, RespondAction.status, RespondAction.category,
               User.username)
        .outerjoin(User, User.id == RespondAction.assignee_id)
        .where(RespondAction.incident_id == inc.id, RespondAction.status.in_(_OPEN))
        .order_by(RespondAction.category, RespondAction.order_index, RespondAction.created_at, RespondAction.id)
        .limit(_OPEN_ITEMS_CAP)
    )).all()
    tasks = (await db.execute(
        select(PlaybookTask.id, PlaybookTask.title, PlaybookTask.status, PlaybookTask.phase, User.username)
        .outerjoin(User, User.id == PlaybookTask.assignee_id)
        .where(PlaybookTask.incident_id == inc.id, PlaybookTask.phase == inc.phase,
               PlaybookTask.status.in_(_OPEN), PlaybookTask.archived_at.is_(None))
        .order_by(PlaybookTask.order_index, PlaybookTask.created_at, PlaybookTask.id)
        .limit(_OPEN_ITEMS_CAP)
    )).all()
    return (
        [{"id": str(a.id), "title": a.title, "owner": a.username, "status": a.status, "category": a.category}
         for a in actions],
        [{"id": str(t.id), "title": t.title, "owner": t.username, "status": t.status, "phase": t.phase}
         for t in tasks],
    )


async def _build_snapshot(db: AsyncSession, incident_id: uuid.UUID, inc: Incident) -> dict:
    """Capture incident state counters and the open items at the moment the handoff is created."""
    ioc_count = (await db.execute(
        select(func.count()).select_from(IOC).where(IOC.incident_id == incident_id)
    )).scalar() or 0

    timeline_count = (await db.execute(
        select(func.count()).select_from(TimelineEvent).where(TimelineEvent.incident_id == incident_id)
    )).scalar() or 0

    pb_total = (await db.execute(
        select(func.count()).select_from(PlaybookTask).where(PlaybookTask.incident_id == incident_id,
                                                             PlaybookTask.archived_at.is_(None))   # I3
    )).scalar() or 0
    pb_done = (await db.execute(
        select(func.count()).select_from(PlaybookTask).where(
            PlaybookTask.incident_id == incident_id,
            PlaybookTask.status == "done",
            PlaybookTask.archived_at.is_(None),
        )
    )).scalar() or 0

    entity_count = (await db.execute(
        select(func.count()).select_from(Entity).where(Entity.incident_id == incident_id)
    )).scalar() or 0
    compromised_count = (await db.execute(
        select(func.count()).select_from(Entity).where(
            Entity.incident_id == incident_id,
            Entity.compromised == True,  # noqa: E712
        )
    )).scalar() or 0

    respond_total = (await db.execute(
        select(func.count()).select_from(RespondAction).where(RespondAction.incident_id == incident_id)
    )).scalar() or 0
    respond_done = (await db.execute(
        select(func.count()).select_from(RespondAction).where(
            RespondAction.incident_id == incident_id,
            RespondAction.status == "done",
        )
    )).scalar() or 0

    open_actions, open_tasks = await _open_items(db, inc)
    return {
        "open_actions":     open_actions,
        "open_tasks":       open_tasks,
        "phase":            inc.phase,
        "severity":         inc.severity,
        "ioc_count":        ioc_count,
        "timeline_count":   timeline_count,
        "playbook_done":    pb_done,
        "playbook_total":   pb_total,
        "entity_count":     entity_count,
        "compromised_count": compromised_count,
        "respond_done":     respond_done,
        "respond_total":    respond_total,
    }


def _to_out(h: IncidentHandoff) -> IncidentHandoffOut:
    return IncidentHandoffOut.model_validate(h)


def _step_tasks(next_steps: list) -> list[int]:
    """Indexes of the next-step lines marked create_task (422 if such a line has no usable action)."""
    idx = [i for i, st in enumerate(next_steps) if isinstance(st, dict) and st.get("create_task")]
    for i in idx:
        action = next_steps[i].get("action")
        if not isinstance(action, str) or not action.strip() or len(action.strip()) > 512:
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_next_step",
                           f"Next step {i + 1} is marked create_task but its action is empty or longer "
                           "than 512 characters.")
    if len(idx) > _MAX_STEP_TASKS:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "too_many_tasks",
                       f"At most {_MAX_STEP_TASKS} next steps can become tasks in one handoff.")
    return idx


# ─── Per-incident routes ─────────────────────────────────────────────────────

@router.get("/{incident_id}/handoffs", response_model=IncidentHandoffList,
            summary="List handoffs")
async def list_handoffs(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> IncidentHandoffList:
    """List the incident's shift-change handoffs, newest first. Requires access
    to the incident.
    """
    await _get_incident(db, incident_id, user)
    rows = (await db.execute(
        select(IncidentHandoff)
        .where(IncidentHandoff.incident_id == incident_id)
        .order_by(IncidentHandoff.created_at.desc())
    )).scalars().all()
    return IncidentHandoffList(items=[_to_out(r) for r in rows])


@router.get("/{incident_id}/handoffs/prefill", response_model=HandoffPrefill,
            summary="Open items for a new handoff")
async def handoff_prefill(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> HandoffPrefill:
    """What a new handoff form starts from (J4): the incident's open (open / in progress) Respond
    actions of any category and the open playbook tasks of its current phase, each {id, title, owner,
    status, category | phase}, at most 50 per list. The same lists are stored in the handoff's
    snapshot_data (open_actions, open_tasks) when it is created. Requires access to the incident.
    """
    inc = await _get_incident(db, incident_id, user)
    open_actions, open_tasks = await _open_items(db, inc)
    return HandoffPrefill(phase=inc.phase, open_actions=open_actions, open_tasks=open_tasks)


@router.post("/{incident_id}/handoffs", response_model=IncidentHandoffOut,
             status_code=status.HTTP_201_CREATED,
             summary="Create a shift-change handoff",
             responses={403: {"model": ApiErrorBody,
                              "description": "not_incident_lead (transfer_ic by someone other than the IC, "
                                             "a lead or an admin)"},
                        404: {"model": ApiErrorBody, "description": "user_not_found (unknown incoming_user_id)"},
                        422: {"model": ApiErrorBody,
                              "description": "assignee_no_access (recipient deactivated or can't see the "
                                             "incident); recipient_read_only (a viewer); invalid_next_step / "
                                             "too_many_tasks; handing off to yourself"}})
async def create_handoff(
    incident_id: uuid.UUID,
    req: IncidentHandoffCreate,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> IncidentHandoffOut:
    """Create a shift-change handoff from the current analyst to an incoming
    user. Requires the analyst role; you cannot hand off to yourself (422), and the
    incoming user must exist (404 user_not_found), be active and able to see the
    incident (422 assignee_no_access), and be an analyst or admin: a viewer can't
    acknowledge or act on a handoff (422 recipient_read_only). Rejected if the incident
    is closed. Captures a snapshot of incident state counters plus the open Respond
    actions and open current-phase playbook tasks (snapshot_data.open_actions /
    open_tasks), audits and notifies the recipient, and returns the new handoff in
    `pending` status.

    A `next_steps` line with `create_task: true` becomes a playbook task assigned to
    the recipient in the incident's current phase, linked back by its `handoff_id`; the
    stored line gets the `task_id` (422 invalid_next_step for an empty action, 422
    too_many_tasks above 50). `transfer_ic: true` moves the Incident Commander
    assignment to the recipient when they acknowledge; only the current IC, a lead
    (Deputy IC) or an admin may set it (403 not_incident_lead).
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    if req.incoming_user_id == user.id:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "Cannot hand off to yourself")

    incoming = await require_incident_person(db, incident_id, req.incoming_user_id, "the handoff recipient")
    if incoming.role not in ("analyst", "admin"):
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "recipient_read_only",
                       f"{incoming.username} is a viewer: a viewer can't acknowledge or act on a handoff. "
                       "Choose an analyst or an admin.")
    if req.transfer_ic and not await is_incident_lead(db, user, inc):
        raise not_incident_lead("ask for the Incident Commander role to move on acknowledgement")
    next_steps = list(req.next_steps or [])
    task_lines = _step_tasks(next_steps)

    snapshot = await _build_snapshot(db, incident_id, inc)

    row = IncidentHandoff(
        id=uuid.uuid4(),
        incident_id=incident_id,
        outgoing_user_id=user.id,
        outgoing_username=user.username,
        incoming_user_id=incoming.id,
        incoming_username=incoming.username,
        note=req.note,
        current_hypothesis=req.current_hypothesis,
        hypothesis_confidence=req.hypothesis_confidence,
        key_findings=req.key_findings,
        warnings=req.warnings,
        threads=req.threads or [],
        ruled_out=req.ruled_out or [],
        pending=req.pending or [],
        next_steps=next_steps,
        open_questions=req.open_questions or [],
        snapshot_data=snapshot,
        transfer_ic=req.transfer_ic,
    )
    db.add(row)
    await db.flush()

    task_ids = []
    if task_lines:
        stored = [dict(st) if isinstance(st, dict) else st for st in next_steps]
        for i in task_lines:
            title = stored[i]["action"].strip()
            task = PlaybookTask(
                id=uuid.uuid4(), incident_id=incident_id, title=title,
                description=f"Next step from the handoff {user.username} → {incoming.username}.",
                phase=inc.phase if inc.phase in get_args(Phase) else "detection_and_analysis",
                order_index=0, status="open", assignee_id=incoming.id, created_by_id=user.id,
                handoff_id=row.id,
            )
            db.add(task)
            await db.flush()
            stored[i].pop("create_task", None)
            stored[i]["task_id"] = str(task.id)
            task_ids.append(str(task.id))
            await write_audit(
                db, "playbook_task_create",
                resource_type="playbook_task", resource_id=str(task.id),
                details={"incident_id": str(incident_id), "title": title, "phase": task.phase,
                         "handoff_id": str(row.id)},
            )
        row.next_steps = stored

    audit_details = {"incident_id": str(incident_id)}
    if req.transfer_ic:
        audit_details["transfer_ic"] = True
    if task_ids:
        audit_details["task_ids"] = task_ids
    await write_audit(
        db, "handoff_create",
        resource_type="handoff", resource_id=str(row.id),
        resource_label=f"{user.username} → {incoming.username}",
        details=audit_details,
    )
    await notify_handoff(
        db,
        recipient_id=incoming.id,
        incident_id=incident_id,
        incident_ref=inc.ref or str(incident_id),
        outgoing_username=user.username,
    )
    await db.commit()
    await db.refresh(row)
    return _to_out(row)


async def _transfer_ic(db: AsyncSession, inc: Incident, row: IncidentHandoff, actor: User) -> str:
    """Move the Incident Commander assignment to the handoff recipient (J4). Returns "done" or the
    reason it was skipped; the acknowledgement itself stands either way. Stages the assignment
    changes, their audit rows, a system timeline event and in-app notices to the former IC(s);
    the caller commits."""
    if inc.status == "closed":
        return "skipped_incident_closed"
    new_ic = await db.get(User, row.incoming_user_id) if row.incoming_user_id else None
    if (new_ic is None or new_ic.role not in ("analyst", "admin")
            or not await user_can_see_incident(db, new_ic, inc.id)):
        return "skipped_recipient_ineligible"
    role = (await db.execute(select(OperationalRole).where(
        OperationalRole.key == IC_ROLE_KEY, OperationalRole.is_active.is_(True)))).scalar_one_or_none()
    if role is None:
        return "skipped_no_ic_role"
    current = (await db.execute(select(IncidentAssignment).where(
        IncidentAssignment.incident_id == inc.id, IncidentAssignment.role_id == role.id))).scalars().all()
    old = [a for a in current if a.user_id != new_ic.id]
    for a in old:
        await write_audit(db, "assignment_delete", resource_type="assignment", resource_id=str(a.id),
                          resource_label=f"{a.username} → {a.role_label}",
                          details={"incident_id": str(inc.id), "handoff_id": str(row.id)})
        await db.delete(a)
    if not any(a.user_id == new_ic.id for a in current):
        new = IncidentAssignment(
            id=uuid.uuid4(), incident_id=inc.id, user_id=new_ic.id, username=new_ic.username,
            role_id=role.id, role_label=role.label, notes="Handoff acknowledged (IC transfer)",
            assigned_by_id=actor.id, assigned_by_username=actor.username)
        db.add(new)
        await db.flush()
        await write_audit(db, "assignment_create", resource_type="assignment", resource_id=str(new.id),
                          resource_label=f"{new_ic.username} → {role.label}",
                          details={"incident_id": str(inc.id), "handoff_id": str(row.id)})
    old_names = sorted({a.username for a in old})
    await write_audit(db, "handoff_ic_transfer", resource_type="handoff", resource_id=str(row.id),
                      resource_label=f"{', '.join(old_names) or '(none)'} → {new_ic.username}",
                      details={"incident_id": str(inc.id), "from": old_names, "to": new_ic.username})
    db.add(TimelineEvent(
        id=uuid.uuid4(), incident_id=inc.id, event_time=utcnow(), source="Handoffs",
        event_type="IC transfer",
        description=f"[IC transfer] Incident Commander: {', '.join(old_names) or '(none)'} → "
                    f"{new_ic.username} (handoff acknowledged)",
        origin="system", is_system=True, external_safe=False, system_source="ic_transfer",
        created_by_id=actor.id,
    ))
    for uid in {a.user_id for a in old if a.user_id}:
        await queue_ic_transferred(db, uid, inc.id, inc.ref or str(inc.id), new_ic.username)
    row.ic_transferred_at = utcnow()
    return "done"


@router.patch("/{incident_id}/handoffs/{handoff_id}/acknowledge",
              response_model=IncidentHandoffOut,
              summary="Acknowledge a handoff")
async def acknowledge_handoff(
    incident_id: uuid.UUID,
    handoff_id:  uuid.UUID,
    req: IncidentHandoffAcknowledge,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> IncidentHandoffOut:
    """Acknowledge a pending handoff, optionally with an acknowledgement note.
    Requires the analyst role; only the designated incoming analyst or an admin
    may acknowledge. Stamps `acknowledged_at`, marks the handoff acknowledged
    (no-op if already acknowledged), audits the action, and returns the handoff.

    When the handoff has `transfer_ic`, the Incident Commander assignment moves to
    the recipient in the same transaction: other IC assignments are removed, the
    recipient is assigned if not already, each change is audited (plus
    `handoff_ic_transfer`), a system timeline event (system_source `ic_transfer`) is
    added, the former IC gets an in-app notice and `ic_transferred_at` is set. It is
    skipped (audited as such, the acknowledgement stands) on a closed incident, when
    the recipient can no longer act on the incident, or when the IC operational role is
    inactive.
    """
    inc = await _get_incident(db, incident_id, user)

    row = (await db.execute(
        select(IncidentHandoff).where(
            IncidentHandoff.id == handoff_id,
            IncidentHandoff.incident_id == incident_id,
        ).with_for_update()
    )).scalar_one_or_none()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Handoff not found")

    # Only the designated incoming analyst or an admin may acknowledge.
    if user.role != "admin" and row.incoming_user_id != user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "Only the designated incoming analyst can acknowledge this handoff")

    if row.status == "acknowledged":
        return _to_out(row)

    row.status = "acknowledged"
    row.acknowledged_at = utcnow()
    row.acknowledged_note = req.acknowledged_note

    ack_details = {"incident_id": str(incident_id)}
    if row.transfer_ic:
        ack_details["ic_transfer"] = await _transfer_ic(db, inc, row, user)
    await write_audit(
        db, "handoff_acknowledge",
        resource_type="handoff", resource_id=str(row.id),
        resource_label=f"{row.outgoing_username} → {row.incoming_username}",
        details=ack_details,
    )
    await commit_and_push(db)
    await db.refresh(row)
    return _to_out(row)


# ─── Global pending queue ────────────────────────────────────────────────────

pending_router = APIRouter()


@pending_router.get("/handoffs/pending", response_model=IncidentHandoffList,
                    summary="List my pending handoffs")
async def list_pending_handoffs(
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> IncidentHandoffList:
    """All pending handoffs across incidents where the current user is the
    designated incoming analyst, newest first.
    """
    rows = (await db.execute(
        select(IncidentHandoff)
        .where(
            IncidentHandoff.incoming_user_id == user.id,
            IncidentHandoff.status == "pending",
        )
        .order_by(IncidentHandoff.created_at.desc())
    )).scalars().all()
    return IncidentHandoffList(items=[_to_out(r) for r in rows])
