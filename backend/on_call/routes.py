"""On-call schedule — org-wide rota. Admin CRUD; anyone can read."""
import uuid
from datetime import date, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import current_user, require_admin
from core.database import get_db
from models import OnCallEntry, User
from schemas import OnCallEntryCreate, OnCallEntryList, OnCallEntryOut, OnCallEntryUpdate

router = APIRouter()


def _to_out(e: OnCallEntry) -> OnCallEntryOut:
    return OnCallEntryOut.model_validate(e)


def _today() -> date:
    return date.today()


async def _get_entry(db: AsyncSession, entry_id: uuid.UUID) -> OnCallEntry:
    row = (await db.execute(
        select(OnCallEntry).where(OnCallEntry.id == entry_id)
    )).scalar_one_or_none()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "On-call entry not found")
    return row


@router.get("", response_model=OnCallEntryList, summary="Get the on-call schedule")
async def list_on_call(
    include_past: bool = False,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> OnCallEntryList:
    """List on-call rota entries ordered by start date. Any authenticated user
    may read. By default only entries ending today or later are returned; set
    `include_past=true` to include past entries. Also returns the entry covering
    today as `current`, if any.
    """
    q = select(OnCallEntry)
    if not include_past:
        today = _today()
        q = q.where(OnCallEntry.end_date >= today)
    q = q.order_by(OnCallEntry.start_date)
    rows = (await db.execute(q)).scalars().all()

    today = _today()
    current = next(
        (r for r in rows if r.start_date <= today <= r.end_date), None
    )
    return OnCallEntryList(
        items=[_to_out(r) for r in rows],
        current=_to_out(current) if current else None,
    )


@router.get("/current", response_model=OnCallEntryOut | None,
            summary="Get the current on-call responder")
async def get_current_on_call(
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the on-call entry covering today, or null if none is in effect.
    Any authenticated user may read.
    """
    today = _today()
    row = (await db.execute(
        select(OnCallEntry)
        .where(OnCallEntry.start_date <= today, OnCallEntry.end_date >= today)
        .order_by(OnCallEntry.start_date.desc())
        .limit(1)
    )).scalar_one_or_none()
    return _to_out(row) if row else None


@router.post("", response_model=OnCallEntryOut, status_code=status.HTTP_201_CREATED,
             summary="Add an on-call shift")
async def create_on_call(
    req: OnCallEntryCreate,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> OnCallEntryOut:
    """Create an on-call rota entry assigning a user for a date range. Requires
    the admin role. The target user must exist and `end_date` must be on or
    after `start_date`. Returns the created entry.
    """
    if req.end_date < req.start_date:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "end_date must be >= start_date")

    target = (await db.execute(select(User).where(User.id == req.user_id))).scalar_one_or_none()
    if not target:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    row = OnCallEntry(
        id=uuid.uuid4(),
        user_id=target.id,
        username=target.username,
        display_name=target.full_name,
        start_date=req.start_date,
        end_date=req.end_date,
        notes=req.notes,
        created_by_id=admin.id,
        created_by_username=admin.username,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return _to_out(row)


@router.patch("/{entry_id}", response_model=OnCallEntryOut,
              summary="Update an on-call shift")
async def update_on_call(
    entry_id: uuid.UUID,
    req: OnCallEntryUpdate,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> OnCallEntryOut:
    """Update an on-call rota entry; only the provided fields are changed.
    Requires the admin role. A new `user_id` must reference an existing user,
    and the resulting `end_date` must stay on or after `start_date`. Returns the
    updated entry.
    """
    row = await _get_entry(db, entry_id)

    if req.user_id is not None:
        target = (await db.execute(select(User).where(User.id == req.user_id))).scalar_one_or_none()
        if not target:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
        row.user_id = target.id
        row.username = target.username
        row.display_name = target.full_name

    if req.start_date is not None:
        row.start_date = req.start_date
    if req.end_date is not None:
        row.end_date = req.end_date
    if req.notes is not None:
        row.notes = req.notes

    if row.end_date < row.start_date:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "end_date must be >= start_date")

    await db.commit()
    await db.refresh(row)
    return _to_out(row)


@router.delete("/{entry_id}", status_code=status.HTTP_204_NO_CONTENT,
               summary="Delete an on-call shift")
async def delete_on_call(
    entry_id: uuid.UUID,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete an on-call rota entry. Requires the admin role. Returns 204 No
    Content.
    """
    row = await _get_entry(db, entry_id)
    await db.delete(row)
    await db.commit()
