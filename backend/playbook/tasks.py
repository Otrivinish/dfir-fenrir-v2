"""Per-incident playbook task endpoints.

Mounted at `/api/incidents` alongside the other per-incident routers; literal
sub-paths under `/{incident_id}/playbook/...` avoid collision with the
incident detail / iocs / entities / evidence routes.

Routes:
  GET    /{incident_id}/playbook/tasks          list
  POST   /{incident_id}/playbook/tasks          add custom task
  PATCH  /{incident_id}/playbook/tasks/{tid}    update (status/title/assignee/etc.)
  DELETE /{incident_id}/playbook/tasks/{tid}    delete
  POST   /{incident_id}/playbook/instantiate    apply a template (append, or replace: lead only)

Writes: analyst+ (replace: the incident lead or an admin). Closed-incident writes return 409. Audited.
I3: lists sort by 800-61 R3 phase order, then order_index; a replaced plan's Done/Skipped tasks are
kept as archived, read-only history (409 task_archived on any change).
"""
import uuid
from datetime import datetime, timezone
from typing import get_args

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import case, select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_admin, require_analyst
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from incidents.access import (get_accessible_incident, is_incident_lead, not_incident_lead,
                              require_incident_person)
from models import Incident, PlaybookTask, PlaybookTemplate, User, utcnow
from schemas import (Phase, PlaybookInstantiateRequest, PlaybookTaskCreate,
                     PlaybookTaskOut, PlaybookTaskUpdate)

router = APIRouter()

# 800-61 R3 order (the Phase literal is declared in it); an unknown value sorts last.
_PHASES = get_args(Phase)
_PHASE_RANK = case({p: i for i, p in enumerate(_PHASES)}, value=PlaybookTask.phase, else_=len(_PHASES))
_DONE = ("done", "skipped")


def _ordered(incident_id: uuid.UUID, include_archived: bool = False):
    """The incident's tasks: current plan first, then archived; each by phase order, order_index."""
    stmt = select(PlaybookTask).where(PlaybookTask.incident_id == incident_id)
    if not include_archived:
        stmt = stmt.where(PlaybookTask.archived_at.is_(None))
    return stmt.order_by(PlaybookTask.archived_at.is_not(None), _PHASE_RANK, PlaybookTask.order_index,
                         PlaybookTask.created_at, PlaybookTask.id)


def _blank(v) -> bool:
    return not (isinstance(v, str) and v.strip())

# F2 — person-reference errors on assignee_id (incidents.access.require_incident_person).
_PERSON_ERRORS = {404: {"model": ApiErrorBody, "description": "user_not_found (unknown assignee_id)"},
                  422: {"model": ApiErrorBody, "description": "assignee_no_access (assignee deactivated or "
                                                              "can't see the incident)"}}


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


async def _get_task(db: AsyncSession, incident_id: uuid.UUID, task_id: uuid.UUID) -> PlaybookTask:
    t = (await db.execute(
        select(PlaybookTask).where(
            PlaybookTask.id == task_id,
            PlaybookTask.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not t:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Task not found")
    if t.archived_at is not None:
        raise ApiError(status.HTTP_409_CONFLICT, "task_archived",
                       "This task is history from a replaced plan and can't be changed.")
    return t


@router.get("/{incident_id}/playbook/tasks", response_model=list[PlaybookTaskOut],
            summary="List playbook tasks")
async def list_tasks(
    incident_id: uuid.UUID,
    include_archived: bool = Query(False, description="Also return the archived (read-only) Done/Skipped "
                                                      "tasks of replaced plans, after the current plan."),
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> list[PlaybookTaskOut]:
    """List the incident's current playbook plan, in NIST SP 800-61 R3 phase order (Preparation,
    Detection & Analysis, Containment Eradication & Recovery, Post-Incident), then order_index.

    Any authenticated user with access to the incident may read. Returns the full list (not
    paginated). Each task carries `overdue` (open or in progress and past due_at).
    include_archived=true appends the archived history (archived_at set).
    """
    await _get_incident(db, incident_id, user)
    q = await db.execute(_ordered(incident_id, include_archived))
    return [PlaybookTaskOut.model_validate(t) for t in q.scalars()]


@router.post(
    "/{incident_id}/playbook/tasks",
    response_model=PlaybookTaskOut,
    status_code=status.HTTP_201_CREATED,
    summary="Add a custom playbook task",
    responses=_PERSON_ERRORS,
)
async def create_task(
    incident_id: uuid.UUID,
    req: PlaybookTaskCreate,
    request: Request,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> PlaybookTaskOut:
    """Add a custom playbook task to an incident.

    Requires the analyst role; the incident must not be closed (409 otherwise).
    Captures title, description, 800-61 phase, order index, optional assignee
    and due date; the task starts `open`. The assignee must be an active user who
    can see the incident (404 user_not_found, 422 assignee_no_access). The creation
    is audited and the new task is returned.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    if req.assignee_id is not None:
        await require_incident_person(db, incident_id, req.assignee_id)

    task = PlaybookTask(
        id=uuid.uuid4(),
        incident_id=incident_id,
        title=req.title,
        description=req.description,
        phase=req.phase,
        order_index=req.order_index,
        status="open",
        assignee_id=req.assignee_id,
        due_at=req.due_at,
        created_by_id=user.id,
    )
    db.add(task)
    await db.flush()

    await write_audit(
        db, "playbook_task_create",
        user_id=user.id, username=user.username,
        resource_type="playbook_task", resource_id=str(task.id),
        details={
            "incident_id": str(incident_id),
            "title":       req.title,
            "phase":       req.phase,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return PlaybookTaskOut.model_validate(task)


@router.patch(
    "/{incident_id}/playbook/tasks/{task_id}",
    response_model=PlaybookTaskOut,
    summary="Update a playbook task",
    responses=_PERSON_ERRORS,
)
async def update_task(
    incident_id: uuid.UUID,
    task_id:     uuid.UUID,
    req: PlaybookTaskUpdate,
    request: Request,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> PlaybookTaskOut:
    """Update a playbook task (status, title, phase, assignee, due date, etc.).

    Requires the analyst role; returns 404 if the task is missing and 409 if
    the incident is closed or the task is archived (task_archived). Only provided fields
    are changed and audited. Setting status to `done` stamps completion time and
    completer; any other status clears them. Skipping needs a non-blank skip_reason (sent
    now or already stored): 422 skip_reason_required; leaving Skipped clears it. A new
    `assignee_id` must be an active user who can see the incident (404 user_not_found,
    422 assignee_no_access); an explicit `"assignee_id": null` unassigns, and
    `"due_at": null` clears the due date. Returns the updated task.
    """
    inc  = await _get_incident(db, incident_id, user)
    task = await _get_task(db, incident_id, task_id)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    target = req.status if req.status is not None else task.status
    if target == "skipped" and (req.status == "skipped" or req.skip_reason is not None) \
            and _blank(req.skip_reason if req.skip_reason is not None else task.skip_reason):
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "skip_reason_required",
                       "Say why the task is skipped (skip_reason).")

    changed: dict[str, object] = {}
    if req.title       is not None and req.title       != task.title:
        task.title       = req.title; changed["title"] = req.title
    if req.description is not None and req.description != (task.description or ""):
        task.description = req.description; changed["description"] = req.description
    if req.phase       is not None and req.phase       != task.phase:
        task.phase       = req.phase; changed["phase"] = req.phase
    if req.order_index is not None and req.order_index != task.order_index:
        task.order_index = req.order_index; changed["order_index"] = req.order_index
    if "assignee_id" in req.model_fields_set and req.assignee_id != task.assignee_id:
        if req.assignee_id is not None:      # clearing needs no check
            await require_incident_person(db, incident_id, req.assignee_id)
        task.assignee_id = req.assignee_id
        changed["assignee_id"] = str(req.assignee_id) if req.assignee_id else None
    if "due_at" in req.model_fields_set and req.due_at != task.due_at:
        task.due_at = req.due_at; changed["due_at"] = req.due_at.isoformat() if req.due_at else None
    if req.skip_reason is not None and req.skip_reason != (task.skip_reason or ""):
        task.skip_reason = req.skip_reason; changed["skip_reason"] = req.skip_reason

    if req.status is not None and req.status != task.status:
        if task.status == "skipped" and task.skip_reason is not None:   # the reason described that skip
            task.skip_reason = None; changed["skip_reason"] = None
        task.status = req.status
        changed["status"] = req.status
        if req.status == "done":
            task.completed_at    = datetime.now(timezone.utc)
            task.completed_by_id = user.id
        else:
            task.completed_at    = None
            task.completed_by_id = None

    if changed:
        await write_audit(
            db, "playbook_task_update",
            user_id=user.id, username=user.username,
            resource_type="playbook_task", resource_id=str(task.id),
            details={"incident_id": str(incident_id), "changes": changed},
            ip_address=request.client.host if request.client else None,
        )
    await db.commit()
    return PlaybookTaskOut.model_validate(task)


@router.delete("/{incident_id}/playbook/tasks/{task_id}",
               summary="Delete a playbook task")
async def delete_task(
    incident_id: uuid.UUID,
    task_id:     uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> dict:
    """Permanently delete a playbook task from an incident.

    Requires the analyst role; returns 404 if the task is missing and 409 if
    the incident is closed or the task is archived history (task_archived). The deletion is
    audited and the response is `{"status": "ok"}`.
    """
    inc  = await _get_incident(db, incident_id, user)
    task = await _get_task(db, incident_id, task_id)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    await write_audit(
        db, "playbook_task_delete",
        user_id=user.id, username=user.username,
        resource_type="playbook_task", resource_id=str(task.id),
        details={
            "incident_id": str(incident_id),
            "title":       task.title,
            "phase":       task.phase,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(task)
    await db.commit()
    return {"status": "ok"}


@router.post(
    "/{incident_id}/playbook/instantiate",
    response_model=list[PlaybookTaskOut],
    summary="Apply a playbook template (append, or replace the plan)",
    responses={403: {"model": ApiErrorBody, "description": "not_incident_lead (mode=replace)"},
               409: {"model": ApiErrorBody, "description": "the incident is closed"},
               422: {"model": ApiErrorBody, "description": "reason_required (mode=replace) · mode_conflict"}},
)
async def instantiate_template(
    incident_id: uuid.UUID,
    req: PlaybookInstantiateRequest,
    request: Request,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> list[PlaybookTaskOut]:
    """Apply a playbook template to an incident.

    Requires the analyst role; the incident must not be closed (409) and the template must
    exist (404).
    - mode=append (default): adds the template's tasks to the current plan. A template task
      is skipped when the current plan already has a task from the same template with the
      same title and phase (an exact duplicate); the audit row counts them (skipped_duplicates).
    - mode=replace: only the incident lead (an analyst assigned as IC / Deputy IC) or an admin
      (403 not_incident_lead), with a non-blank `reason` (422 reason_required). Done and Skipped
      tasks of the current plan are archived (kept read-only, with the reason); Open and
      In-progress tasks are deleted; then all the template's tasks are added.
    The deprecated `replace` flag maps to mode (422 mode_conflict if they disagree). Audited as
    playbook_instantiate. Returns the current plan in 800-61 R3 phase order.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    if req.mode is not None and req.replace is not None and (req.mode == "replace") != req.replace:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "mode_conflict",
                       "mode and the deprecated replace flag disagree: send mode only.")
    mode = req.mode or ("replace" if req.replace else "append")
    reason = (req.reason or "").strip()
    if mode == "replace":
        if not await is_incident_lead(db, user, inc):
            raise not_incident_lead("replace the playbook plan (analysts can append a template)")
        if not reason:
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "reason_required",
                           "Say why the plan is replaced (reason).")

    tpl = (await db.execute(
        select(PlaybookTemplate).where(PlaybookTemplate.id == req.template_id)
    )).scalar_one_or_none()
    if not tpl:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Template not found")

    current = (await db.execute(_ordered(incident_id))).scalars().all()
    archived, removed = [], []
    present: set[tuple] = set()
    if mode == "replace":
        now = utcnow()
        for t in current:
            if t.status in _DONE:
                t.archived_at, t.archived_by_id, t.archive_reason = now, user.id, reason
                archived.append(t)
            else:
                removed.append(t.title)
                await db.delete(t)
    else:
        present = {(t.source_template_id, t.title, t.phase) for t in current if t.source_template_id}

    new_tasks: list[PlaybookTask] = []
    skipped = 0
    for idx, spec in enumerate(tpl.tasks or []):
        title, phase = spec.get("title") or "", spec.get("phase") or "preparation"
        if (tpl.id, title, phase) in present:
            skipped += 1
            continue
        new_tasks.append(PlaybookTask(
            id=uuid.uuid4(),
            incident_id=incident_id,
            title=title,
            description=spec.get("description"),
            phase=phase,
            order_index=int(spec.get("order") or 0),
            status="open",
            source_template_id=tpl.id,
            source_task_index=idx,
            created_by_id=user.id,
        ))
    db.add_all(new_tasks)
    await db.flush()

    details = {
        "incident_id":        str(incident_id),
        "template_id":        str(tpl.id),
        "template_key":       tpl.key,
        "mode":               mode,
        "replace":            mode == "replace",
        "task_count":         len(new_tasks),
        "skipped_duplicates": skipped,
    }
    if mode == "replace":
        details.update(reason=reason, archived=len(archived), cleared=len(removed),
                       removed_titles=removed[:50])
    await write_audit(
        db, "playbook_instantiate",
        user_id=user.id, username=user.username,
        resource_type="incident", resource_id=str(incident_id),
        details=details,
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    # The full current plan, so the client picks up pre-existing tasks without a round-trip.
    q = await db.execute(_ordered(incident_id))
    return [PlaybookTaskOut.model_validate(t) for t in q.scalars()]
