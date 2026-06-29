"""Team CRUD + membership management (admin only for writes)."""
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_admin
from core.database import get_db
from models import Team, User
from schemas import TeamCreate, TeamOut, TeamUpdate, UserOut

router = APIRouter()


def _to_out(t: Team) -> TeamOut:
    out = TeamOut.model_validate(t)
    try:
        out.member_count = len(t.members)
    except Exception:
        out.member_count = 0
    return out


@router.get("", response_model=list[TeamOut], summary="List teams")
async def list_teams(_: User = Depends(current_user),
                     db: AsyncSession = Depends(get_db)) -> list[TeamOut]:
    """List all teams ordered by name, each with its current member count. Available
    to any authenticated user."""
    q = await db.execute(select(Team).order_by(Team.name))
    return [_to_out(t) for t in q.scalars().unique()]


@router.post("", response_model=TeamOut, status_code=status.HTTP_201_CREATED,
             summary="Create a team")
async def create_team(req: TeamCreate, request: Request,
                      admin: User = Depends(require_admin),
                      db: AsyncSession = Depends(get_db)) -> TeamOut:
    """Create a new team from name, optional description and colour. Returns 409 if
    the team name already exists. Admin only. Returns the created team."""
    existing = await db.execute(select(Team).where(Team.name == req.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "Team name already exists")
    t = Team(id=uuid.uuid4(), name=req.name, description=req.description, color=req.color)
    db.add(t)
    await db.flush()
    await write_audit(
        db, "team_create",
        user_id=admin.id, username=admin.username,
        resource_type="team", resource_id=str(t.id),
        details={"name": req.name},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return _to_out(t)


@router.patch("/{team_id}", response_model=TeamOut, summary="Update a team")
async def update_team(team_id: uuid.UUID, req: TeamUpdate, request: Request,
                      admin: User = Depends(require_admin),
                      db: AsyncSession = Depends(get_db)) -> TeamOut:
    """Partially update a team's name, description, or colour. Returns 404 if not
    found. Admin only. Returns the updated team."""
    t = (await db.execute(select(Team).where(Team.id == team_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(404, "Team not found")
    changed: dict[str, object] = {}
    if req.name is not None and req.name != t.name:
        t.name = req.name; changed["name"] = req.name
    if req.description is not None:
        t.description = req.description; changed["description"] = req.description
    if req.color is not None:
        t.color = req.color; changed["color"] = req.color
    if changed:
        await write_audit(
            db, "team_update",
            user_id=admin.id, username=admin.username,
            resource_type="team", resource_id=str(t.id),
            details=changed,
            ip_address=request.client.host if request.client else None,
        )
    await db.commit()
    return _to_out(t)


@router.delete("/{team_id}", summary="Delete a team")
async def delete_team(team_id: uuid.UUID, request: Request,
                      admin: User = Depends(require_admin),
                      db: AsyncSession = Depends(get_db)) -> dict:
    """Delete a team. Returns 404 if not found. Admin only."""
    t = (await db.execute(select(Team).where(Team.id == team_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(404, "Team not found")
    await write_audit(
        db, "team_delete",
        user_id=admin.id, username=admin.username,
        resource_type="team", resource_id=str(t.id),
        details={"name": t.name},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(t)
    await db.commit()
    return {"status": "ok"}


@router.get("/{team_id}/members", response_model=list[UserOut],
            summary="List team members")
async def list_members(team_id: uuid.UUID,
                       _: User = Depends(current_user),
                       db: AsyncSession = Depends(get_db)) -> list[UserOut]:
    """List the members of a team ordered by username. Returns 404 if the team is not
    found. Available to any authenticated user."""
    t = (await db.execute(
        select(Team).where(Team.id == team_id).options(selectinload(Team.members))
    )).scalar_one_or_none()
    if not t:
        raise HTTPException(404, "Team not found")
    return [UserOut.model_validate(u) for u in sorted(t.members, key=lambda m: m.username)]


@router.post("/{team_id}/members/{user_id}", summary="Add a team member")
async def add_member(team_id: uuid.UUID, user_id: uuid.UUID, request: Request,
                     admin: User = Depends(require_admin),
                     db: AsyncSession = Depends(get_db)) -> dict:
    """Add a user to a team. Returns 404 if either the team or user is not found, or
    already_member if the user is already on the team. Admin only."""
    t = (await db.execute(select(Team).where(Team.id == team_id).options(selectinload(Team.members)))).scalar_one_or_none()
    u = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not t or not u:
        raise HTTPException(404, "Team or user not found")
    if u in t.members:
        return {"status": "already_member"}
    t.members.append(u)
    await write_audit(
        db, "team_member_add",
        user_id=admin.id, username=admin.username,
        resource_type="team", resource_id=str(t.id),
        details={"team": t.name, "added_user": u.username},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return {"status": "ok"}


@router.delete("/{team_id}/members/{user_id}", summary="Remove a team member")
async def remove_member(team_id: uuid.UUID, user_id: uuid.UUID, request: Request,
                        admin: User = Depends(require_admin),
                        db: AsyncSession = Depends(get_db)) -> dict:
    """Remove a user from a team. Returns 404 if either the team or user is not found,
    or not_member if the user is not on the team. Admin only."""
    t = (await db.execute(select(Team).where(Team.id == team_id).options(selectinload(Team.members)))).scalar_one_or_none()
    u = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not t or not u:
        raise HTTPException(404, "Team or user not found")
    if u not in t.members:
        return {"status": "not_member"}
    t.members.remove(u)
    await write_audit(
        db, "team_member_remove",
        user_id=admin.id, username=admin.username,
        resource_type="team", resource_id=str(t.id),
        details={"team": t.name, "removed_user": u.username},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return {"status": "ok"}
