"""Playbook template endpoints — list, detail, create, update, delete."""
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import current_user, require_admin
from core.database import get_db
from models import PlaybookTask, PlaybookTemplate, User
from schemas import (
    PlaybookTemplateCreate,
    PlaybookTemplateOut,
    PlaybookTemplateSummary,
    PlaybookTemplateUpdate,
)

router = APIRouter()


async def _run_stats(
    db: AsyncSession,
    template_ids: list[uuid.UUID],
) -> dict[uuid.UUID, dict]:
    """Return {template_id: {run_count, last_run_at}} for the given IDs."""
    if not template_ids:
        return {}
    rows = await db.execute(
        select(
            PlaybookTask.source_template_id,
            func.count(func.distinct(PlaybookTask.incident_id)).label("run_count"),
            func.max(PlaybookTask.created_at).label("last_run_at"),
        )
        .where(PlaybookTask.source_template_id.in_(template_ids))
        .group_by(PlaybookTask.source_template_id)
    )
    return {
        row.source_template_id: {
            "run_count": row.run_count,
            "last_run_at": row.last_run_at,
        }
        for row in rows
    }


def _summary(t: PlaybookTemplate, stats: dict) -> PlaybookTemplateSummary:
    s = stats.get(t.id, {})
    out = PlaybookTemplateSummary.model_validate(t)
    out.task_count  = len(t.tasks or [])
    out.run_count   = s.get("run_count", 0)
    out.last_run_at = s.get("last_run_at")
    return out


@router.get("", response_model=list[PlaybookTemplateSummary],
            summary="List playbook templates")
async def list_templates(
    _: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> list[PlaybookTemplateSummary]:
    """List all playbook templates with task counts and run statistics.

    Any authenticated user may read. System templates are ordered first, then
    by name. Each summary includes `task_count`, `run_count` (distinct
    incidents instantiated from it) and `last_run_at`.
    """
    q = await db.execute(
        select(PlaybookTemplate).order_by(
            PlaybookTemplate.is_system.desc(),
            PlaybookTemplate.name,
        )
    )
    templates = list(q.scalars())
    stats = await _run_stats(db, [t.id for t in templates])
    return [_summary(t, stats) for t in templates]


@router.get("/{template_id}", response_model=PlaybookTemplateOut,
            summary="Get a playbook template")
async def get_template(
    template_id: uuid.UUID,
    _: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> PlaybookTemplateOut:
    """Get a single playbook template by ID, including its full task list.

    Any authenticated user may read. Returns 404 if the template does not
    exist.
    """
    t = (await db.execute(
        select(PlaybookTemplate).where(PlaybookTemplate.id == template_id)
    )).scalar_one_or_none()
    if not t:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Template not found")
    return PlaybookTemplateOut.model_validate(t)


@router.post("", response_model=PlaybookTemplateOut, status_code=status.HTTP_201_CREATED,
             summary="Create a playbook template")
async def create_template(
    body: PlaybookTemplateCreate,
    actor: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> PlaybookTemplateOut:
    """Create a new custom (non-system) playbook template.

    Any authenticated user may create. A unique `custom_*` key is generated and
    `is_system` is always False; only admins manage system templates (seeded
    separately). Returns the created template with its task list.
    """
    key = f"custom_{uuid.uuid4().hex[:12]}"
    t = PlaybookTemplate(
        id=uuid.uuid4(),
        key=key,
        name=body.name,
        description=body.description,
        category=body.category or "",
        is_system=False,
        tasks=[step.model_dump() for step in body.tasks],
    )
    db.add(t)
    await db.commit()
    await db.refresh(t)
    return PlaybookTemplateOut.model_validate(t)


@router.patch("/{template_id}", response_model=PlaybookTemplateOut,
              summary="Update a playbook template")
async def update_template(
    template_id: uuid.UUID,
    body: PlaybookTemplateUpdate,
    actor: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> PlaybookTemplateOut:
    """Update a playbook template's name, description, category, or tasks.

    Any authenticated user may edit custom templates; editing a system template
    requires the admin role (403 otherwise). Returns 404 if the template does
    not exist. Only provided fields are changed. Returns the updated template.
    """
    t = (await db.execute(
        select(PlaybookTemplate).where(PlaybookTemplate.id == template_id)
    )).scalar_one_or_none()
    if not t:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Template not found")
    if t.is_system and actor.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "System templates require admin role to edit")

    if body.name        is not None: t.name        = body.name
    if body.description is not None: t.description = body.description
    if body.category    is not None: t.category    = body.category
    if body.tasks       is not None: t.tasks       = [s.model_dump() for s in body.tasks]

    await db.commit()
    await db.refresh(t)
    return PlaybookTemplateOut.model_validate(t)


@router.delete("/{template_id}", status_code=status.HTTP_204_NO_CONTENT,
               summary="Delete a playbook template")
async def delete_template(
    template_id: uuid.UUID,
    actor: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Permanently delete a custom playbook template.

    Requires the admin role. Returns 404 if the template does not exist and 403
    if it is a system template (system templates cannot be deleted). Responds
    204 No Content on success.
    """
    t = (await db.execute(
        select(PlaybookTemplate).where(PlaybookTemplate.id == template_id)
    )).scalar_one_or_none()
    if not t:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Template not found")
    if t.is_system:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "System templates cannot be deleted")
    await db.delete(t)
    await db.commit()
