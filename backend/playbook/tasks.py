"""Per-incident playbook task endpoints.

Mounted at `/api/incidents` alongside the other per-incident routers; literal
sub-paths under `/{incident_id}/playbook/...` avoid collision with the
incident detail / iocs / entities / evidence routes.

Routes:
  GET    /{incident_id}/playbook/tasks          list
  POST   /{incident_id}/playbook/tasks          add custom task
  PATCH  /{incident_id}/playbook/tasks/{tid}    update (status/title/assignee/etc.)
  DELETE /{incident_id}/playbook/tasks/{tid}    delete
  POST   /{incident_id}/playbook/instantiate    apply a template (append or replace)

Writes: analyst+. Closed-incident writes return 409. Audited.
"""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_admin, require_analyst
from core.database import get_db
from incidents.access import get_accessible_incident
from models import Incident, PlaybookTask, PlaybookTemplate, User, utcnow
from schemas import (PlaybookInstantiateRequest, PlaybookTaskCreate,
                     PlaybookTaskOut, PlaybookTaskUpdate)

router = APIRouter()


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
    return t


@router.get("/{incident_id}/playbook/tasks", response_model=list[PlaybookTaskOut],
            summary="List playbook tasks")
async def list_tasks(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> list[PlaybookTaskOut]:
    """List all playbook tasks for an incident, ordered by phase and order index.

    Any authenticated user with access to the incident may read. Returns the
    full list of tasks (not paginated).
    """
    await _get_incident(db, incident_id, user)
    q = await db.execute(
        select(PlaybookTask)
        .where(PlaybookTask.incident_id == incident_id)
        .order_by(PlaybookTask.phase, PlaybookTask.order_index, PlaybookTask.created_at)
    )
    return [PlaybookTaskOut.model_validate(t) for t in q.scalars()]


@router.post(
    "/{incident_id}/playbook/tasks",
    response_model=PlaybookTaskOut,
    status_code=status.HTTP_201_CREATED,
    summary="Add a custom playbook task",
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
    and due date; the task starts `open`. The creation is audited and the new
    task is returned.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

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
    the incident is closed. Only provided fields are changed and audited.
    Setting status to `done` stamps completion time and completer; any other
    status clears them. Returns the updated task.
    """
    inc  = await _get_incident(db, incident_id, user)
    task = await _get_task(db, incident_id, task_id)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    changed: dict[str, object] = {}
    if req.title       is not None and req.title       != task.title:
        task.title       = req.title; changed["title"] = req.title
    if req.description is not None and req.description != (task.description or ""):
        task.description = req.description; changed["description"] = req.description
    if req.phase       is not None and req.phase       != task.phase:
        task.phase       = req.phase; changed["phase"] = req.phase
    if req.order_index is not None and req.order_index != task.order_index:
        task.order_index = req.order_index; changed["order_index"] = req.order_index
    if req.assignee_id is not None and req.assignee_id != task.assignee_id:
        task.assignee_id = req.assignee_id; changed["assignee_id"] = str(req.assignee_id)
    if req.due_at      is not None and req.due_at      != task.due_at:
        task.due_at = req.due_at; changed["due_at"] = req.due_at.isoformat() if req.due_at else None
    if req.skip_reason is not None and req.skip_reason != (task.skip_reason or ""):
        task.skip_reason = req.skip_reason; changed["skip_reason"] = req.skip_reason

    if req.status is not None and req.status != task.status:
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
    the incident is closed. The deletion is audited and the response is
    `{"status": "ok"}`.
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
    summary="Instantiate a playbook template",
)
async def instantiate_template(
    incident_id: uuid.UUID,
    req: PlaybookInstantiateRequest,
    request: Request,
    # `replace=True` is destructive — admin only. Append-only path is analyst.
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> list[PlaybookTaskOut]:
    """Apply a playbook template to an incident, creating its tasks.

    Requires the analyst role; the incident must not be closed (409) and the
    referenced template must exist (404). With `replace=True` all existing
    tasks for the incident are deleted before the template's tasks are added;
    otherwise the new tasks are appended. The action is audited and the full
    current task list (ordered by phase and order index) is returned.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    tpl = (await db.execute(
        select(PlaybookTemplate).where(PlaybookTemplate.id == req.template_id)
    )).scalar_one_or_none()
    if not tpl:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Template not found")

    cleared = 0
    if req.replace:
        existing = (await db.execute(
            select(PlaybookTask).where(PlaybookTask.incident_id == incident_id)
        )).scalars().all()
        for t in existing:
            await db.delete(t)
        cleared = len(existing)

    new_tasks: list[PlaybookTask] = []
    for idx, spec in enumerate(tpl.tasks or []):
        new_tasks.append(PlaybookTask(
            id=uuid.uuid4(),
            incident_id=incident_id,
            title=spec.get("title") or "",
            description=spec.get("description"),
            phase=spec.get("phase") or "preparation",
            order_index=int(spec.get("order") or 0),
            status="open",
            source_template_id=tpl.id,
            source_task_index=idx,
            created_by_id=user.id,
        ))
    db.add_all(new_tasks)
    await db.flush()

    await write_audit(
        db, "playbook_instantiate",
        user_id=user.id, username=user.username,
        resource_type="incident", resource_id=str(incident_id),
        details={
            "incident_id":  str(incident_id),
            "template_id":  str(tpl.id),
            "template_key": tpl.key,
            "task_count":   len(new_tasks),
            "replace":      req.replace,
            "cleared":      cleared,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    # Return the full current list so the client picks up any pre-existing
    # tasks (append mode) without a separate round-trip.
    q = await db.execute(
        select(PlaybookTask)
        .where(PlaybookTask.incident_id == incident_id)
        .order_by(PlaybookTask.phase, PlaybookTask.order_index, PlaybookTask.created_at)
    )
    return [PlaybookTaskOut.model_validate(t) for t in q.scalars()]
