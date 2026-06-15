"""API token endpoints: issue / list / revoke (self), plus admin list / revoke."""
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api_tokens.service import issue_token, revoke_token
from audit.service import write_audit
from auth.deps import current_user, require_admin
from core.database import get_db
from models import ApiToken, User
from schemas import (AdminApiTokenList, AdminApiTokenOut, ApiTokenCreate,
                     ApiTokenIssued, ApiTokenList, ApiTokenOut)


router = APIRouter()
admin_router = APIRouter()


# ─── Self-service (any authenticated user) ──────────────────────────────────

@router.post("", response_model=ApiTokenIssued, summary="Issue an API token for myself")
async def create_token(
    req: ApiTokenCreate,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> ApiTokenIssued:
    """Issue a new API token for the calling user with the requested name, role,
    and optional expiry in days. Authenticated user. The plain token is returned
    once and never again; returns 403 if the requested role is not permitted."""
    try:
        plain, row = await issue_token(
            db, user=user, name=req.name, role=req.role,
            expires_in_days=req.expires_in_days,
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(e))

    await write_audit(
        db, "api_token_issue",
        user_id=user.id, username=user.username, role_at_time=user.role,
        outcome="success",
        resource_type="api_token", resource_id=str(row.id), resource_label=row.name,
        details={"role": row.role, "expires_at": row.expires_at.isoformat() if row.expires_at else None},
    )
    await db.commit()

    base = ApiTokenOut.model_validate(row, from_attributes=True)
    return ApiTokenIssued(**base.model_dump(), token=plain)


@router.get("", response_model=ApiTokenList, summary="List my API tokens")
async def list_my_tokens(
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> ApiTokenList:
    """List the calling user's own API tokens, newest first. Authenticated user.
    Token metadata only; the plain token value is never returned here."""
    q = await db.execute(
        select(ApiToken)
        .where(ApiToken.user_id == user.id)
        .order_by(ApiToken.created_at.desc())
    )
    return ApiTokenList(items=[ApiTokenOut.model_validate(r, from_attributes=True) for r in q.scalars()])


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Revoke one of my API tokens")
async def revoke_my_token(
    token_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Revoke one of the calling user's own API tokens by id. Authenticated user.
    Returns 404 if not found or not owned by the caller, and 204 No Content on
    success (or if the token was already revoked)."""
    q = await db.execute(select(ApiToken).where(ApiToken.id == token_id))
    row = q.scalar_one_or_none()
    if not row or row.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Token not found")
    if row.revoked_at is not None:
        return None
    await revoke_token(db, token_id, reason="user")
    await write_audit(
        db, "api_token_revoke",
        user_id=user.id, username=user.username, role_at_time=user.role,
        outcome="success",
        resource_type="api_token", resource_id=str(row.id), resource_label=row.name,
    )
    await db.commit()
    return None


# ─── Admin ──────────────────────────────────────────────────────────────────

@admin_router.get("/tokens", response_model=AdminApiTokenList, summary="List all API tokens (admin)")
async def admin_list_tokens(
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> AdminApiTokenList:
    """List API tokens across all users, newest first, each with its owning
    username. Admin only. Token metadata only; plain token values are never returned."""
    q = await db.execute(
        select(ApiToken, User.username)
        .join(User, User.id == ApiToken.user_id)
        .order_by(ApiToken.created_at.desc())
    )
    items = []
    for tok, username in q.all():
        item = AdminApiTokenOut.model_validate(tok, from_attributes=True)
        item.username = username
        items.append(item)
    return AdminApiTokenList(items=items)


@admin_router.delete("/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Revoke any user's API token (admin)")
async def admin_revoke_token(
    token_id: uuid.UUID,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Revoke any user's API token by id. Admin only. Returns 404 if not found,
    and 204 No Content on success (or if the token was already revoked)."""
    q = await db.execute(select(ApiToken).where(ApiToken.id == token_id))
    row = q.scalar_one_or_none()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Token not found")
    if row.revoked_at is not None:
        return None
    await revoke_token(db, token_id, reason="admin")
    await write_audit(
        db, "api_token_revoke",
        user_id=admin.id, username=admin.username, role_at_time=admin.role,
        outcome="success",
        resource_type="api_token", resource_id=str(row.id), resource_label=row.name,
        details={"target_user_id": str(row.user_id)},
    )
    await db.commit()
    return None
