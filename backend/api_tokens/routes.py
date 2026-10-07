"""API token endpoints: issue / list / revoke (self), plus admin list / revoke."""
import uuid

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api_tokens.service import issue_token, revoke_token
from audit.service import write_audit
from auth.deps import current_user, require_admin
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from models import ApiToken, User
from notifications.service import commit_and_push, notify_api_token_revoked
from schemas import (AdminApiTokenList, AdminApiTokenOut, ApiTokenCreate,
                     ApiTokenIssued, ApiTokenList, ApiTokenOut)


router = APIRouter()
admin_router = APIRouter()


# ─── Self-service (any authenticated user) ──────────────────────────────────

_NOT_FOUND = {404: {"model": ApiErrorBody, "description": "token_not_found"}}


async def _deny_issue(db: AsyncSession, user: User, req: ApiTokenCreate, code: str, detail: str) -> None:
    """Audit a refused create (outcome denied), then raise the flat 403."""
    await write_audit(
        db, "api_token_issue",
        user_id=user.id, username=user.username, role_at_time=user.role,
        outcome="denied",
        resource_type="api_token", resource_label=req.name,
        details={"reason": code, "role": req.role, "expires_in_days": req.expires_in_days},
    )
    await db.commit()
    raise ApiError(status.HTTP_403_FORBIDDEN, code, detail)


@router.post("", response_model=ApiTokenIssued, summary="Issue an API token for myself",
             responses={403: {"model": ApiErrorBody,
                              "description": "token_create_requires_session | token_role_exceeds_user"}})
async def create_token(
    req: ApiTokenCreate,
    request: Request,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> ApiTokenIssued:
    """Issue a new API token for the calling user with a name, a role (yours or lower)
    and a required expiry of 1 to 90 days. Needs an interactive browser session (cookie,
    i.e. password + TOTP login): a call authenticated with an API token gets 403
    token_create_requires_session, so a token can never mint another. The plain token is
    in this response only; FENRIR stores just its SHA-256 hash. 403 token_role_exceeds_user
    if the role is above yours. Audited as api_token_issue (refusals with outcome denied)."""
    if getattr(request.state, "auth_method", None) == "api_token":
        await _deny_issue(db, user, req, "token_create_requires_session",
                          "Creating an API token needs an interactive login (password + TOTP), "
                          "not an API token. Use Settings → Account → API tokens or `fenrir-mcp login`.")
    try:
        plain, row = await issue_token(
            db, user=user, name=req.name, role=req.role,
            expires_in_days=req.expires_in_days,
        )
    except ValueError as e:
        await _deny_issue(db, user, req, "token_role_exceeds_user", str(e))

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


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Revoke one of my API tokens",
               responses=_NOT_FOUND)
async def revoke_my_token(
    token_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Revoke one of the calling user's own API tokens by id. Authenticated user.
    404 token_not_found if it does not exist or is not the caller's (another user's
    token is never revealed); 204 No Content on success or if already revoked.
    Takes effect on the token's next request. Audited as api_token_revoke."""
    q = await db.execute(select(ApiToken).where(ApiToken.id == token_id))
    row = q.scalar_one_or_none()
    if not row or row.user_id != user.id:
        raise ApiError(status.HTTP_404_NOT_FOUND, "token_not_found", "Token not found")
    if row.revoked_at is not None:
        return None
    await revoke_token(db, token_id, reason="user")
    await write_audit(
        db, "api_token_revoke",
        user_id=user.id, username=user.username, role_at_time=user.role,
        outcome="success",
        resource_type="api_token", resource_id=str(row.id), resource_label=row.name,
        details={"reason": "user"},
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


@admin_router.delete("/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Revoke any user's API token (admin)",
                     responses=_NOT_FOUND)
async def admin_revoke_token(
    token_id: uuid.UUID,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Revoke any user's API token by id. Admin only (403 insufficient_role otherwise).
    404 token_not_found; 204 No Content on success or if already revoked. Takes effect
    on the token's next request. Audited as api_token_revoke; the owner, when not the
    admin, gets an in-app notification."""
    q = await db.execute(select(ApiToken).where(ApiToken.id == token_id))
    row = q.scalar_one_or_none()
    if not row:
        raise ApiError(status.HTTP_404_NOT_FOUND, "token_not_found", "Token not found")
    if row.revoked_at is not None:
        return None
    await revoke_token(db, token_id, reason="admin")
    await write_audit(
        db, "api_token_revoke",
        user_id=admin.id, username=admin.username, role_at_time=admin.role,
        outcome="success",
        resource_type="api_token", resource_id=str(row.id), resource_label=row.name,
        details={"target_user_id": str(row.user_id), "reason": "admin"},
    )
    await notify_api_token_revoked(db, row.user_id, row.name, admin)
    await commit_and_push(db)
    return None
