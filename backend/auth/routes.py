"""Auth endpoints: setup, login (+ TOTP step 2), logout, change password, TOTP setup/enable/disable."""
import base64
import io
import uuid
from datetime import datetime

import qrcode
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.bootstrap import (consume_bootstrap_token, read_bootstrap_token)
from auth.deps import current_session, current_user
from auth.service import (PENDING_TOTP_COOKIE, clear_pending_totp_cookie,
                          clear_session_cookie, consume_pending_totp,
                          clear_login_failures, clear_totp_failures,
                          create_session, is_login_locked, is_totp_locked,
                          issue_pending_totp, record_login_failure,
                          record_totp_failure, revoke_session, set_pending_totp_cookie,
                          set_session_cookie, verify_user_totp)
from core.config import settings
from core.database import get_db
from core.security import (ahash_password, averify_password, encrypt_secret,
                           hash_password, new_totp_secret, totp_provisioning_uri)
from models import User, UserSession
from schemas import (ChangePasswordRequest, LoginRequest, LoginResponse,
                     SetupRequest, TotpDisableRequest, TotpEnableRequest,
                     TotpSetupResponse, TotpVerifyRequest, UserOut)

router = APIRouter()

# Decoy hash for login timing-equalisation. When the username doesn't exist (or
# is inactive) we still run one argon2 verify against this fixed hash, so a valid
# username can't be distinguished from an invalid one by response latency
# (~50–100 ms argon2 cost either way). Computed once at import.
_DECOY_HASH = hash_password("fenrir-decoy-password-do-not-use")


# ─── First-run setup ─────────────────────────────────────────────────────────

@router.get("/setup-check", summary="Check if first-run setup is needed")
async def setup_check(db: AsyncSession = Depends(get_db)) -> dict:
    """Report whether the instance has no users yet and first-run setup is required.
    Public, no authentication. Returns {"needs_setup": bool}."""
    n = (await db.execute(select(func.count(User.id)))).scalar_one()
    return {"needs_setup": int(n) == 0}


@router.get("/policy", summary="Get public auth policy hints")
async def auth_policy() -> dict:
    """Public auth-policy hints for the UI. No secrets. No authentication.
    Returns {"totp_required": bool} indicating whether TOTP enrolment is mandatory."""
    return {"totp_required": settings.totp_required}


@router.post("/setup", response_model=UserOut, summary="Complete first-run admin setup")
async def setup(req: SetupRequest, request: Request, response: Response,
                db: AsyncSession = Depends(get_db)) -> UserOut:
    """Create the first admin user on a fresh instance, validated against the
    one-time bootstrap token. Returns 410 if setup is already complete and 403 on
    an invalid token. Establishes a session cookie and returns the new user."""
    n = (await db.execute(select(func.count(User.id)))).scalar_one()
    if int(n) > 0:
        raise HTTPException(status.HTTP_410_GONE, "Setup already complete")

    expected = read_bootstrap_token()
    if not expected or expected != req.token:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid bootstrap token")

    user = User(
        id=uuid.uuid4(),
        username=req.username,
        email=req.email,
        full_name=req.full_name,
        hashed_password=await ahash_password(req.password),
        role="admin",
        is_active=True,
        force_totp_enrol=settings.totp_required,
    )
    db.add(user)
    await db.flush()

    token, _ = await create_session(db, user, request=request, label="bootstrap")
    await write_audit(
        db, "setup_completed",
        user_id=user.id, username=user.username, role_at_time=user.role,
        outcome="success",
        resource_type="user", resource_id=str(user.id), resource_label=user.username,
    )
    await db.commit()
    consume_bootstrap_token()

    set_session_cookie(response, token)
    return UserOut.model_validate(user)


# ─── Login (step 1: password) ────────────────────────────────────────────────

@router.post("/login", response_model=LoginResponse, summary="Log in with username and password")
async def login(req: LoginRequest, request: Request, response: Response,
                db: AsyncSession = Depends(get_db)) -> LoginResponse:
    """Authenticate with username and password (step 1). On success either sets a
    session cookie and returns status "ok", or, if the user has TOTP enabled,
    returns status "totp_required" and sets a pending-TOTP cookie for step 2.
    Returns 401 on invalid credentials and 429 when rate-limit locked."""
    if await is_login_locked(req.username):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed attempts. Try again later.")

    q = await db.execute(select(User).where(func.lower(User.username) == req.username.lower()))
    user = q.scalar_one_or_none()

    if user and user.is_active:
        ok = await averify_password(req.password, user.hashed_password)
    else:
        # Run a dummy verify so absent/inactive accounts cost the same as present
        # ones — closes the timing side-channel that enumerates valid usernames.
        await averify_password(req.password, _DECOY_HASH)
        ok = False
    if not ok:
        await record_login_failure(req.username)
        await write_audit(
            db, "login_fail",
            username=req.username,
            outcome="failure",
            details={"reason": "invalid_credentials"},
            user_agent=(request.headers.get("user-agent") or "")[:512],
        )
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    await clear_login_failures(req.username)

    # TOTP gate
    if user.totp_enabled:
        if await is_totp_locked(user.id):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "TOTP locked. Contact an admin.")
        pending = await issue_pending_totp(user.id)
        set_pending_totp_cookie(response, pending)
        return LoginResponse(status="totp_required", user=None)

    token, _ = await create_session(db, user, request=request)
    await write_audit(
        db, "login_success",
        user_id=user.id, username=user.username, role_at_time=user.role,
        outcome="success",
        user_agent=(request.headers.get("user-agent") or "")[:512],
    )
    await db.commit()
    set_session_cookie(response, token)
    return LoginResponse(status="ok", user=UserOut.model_validate(user))


# ─── Login (step 2: TOTP) ────────────────────────────────────────────────────

@router.post("/totp/verify", response_model=LoginResponse, summary="Verify TOTP code to finish login")
async def totp_verify(req: TotpVerifyRequest, request: Request, response: Response,
                      db: AsyncSession = Depends(get_db)) -> LoginResponse:
    """Complete login (step 2) by verifying the TOTP code against the pending-TOTP
    challenge cookie set during password login. On success sets a session cookie
    and returns status "ok". Returns 400 if the challenge is missing or expired,
    401 on an invalid code, and 429 when TOTP is rate-limit locked."""
    pending = request.cookies.get(PENDING_TOTP_COOKIE)
    if not pending:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No pending TOTP challenge")
    user_id = await consume_pending_totp(pending)
    clear_pending_totp_cookie(response)
    if not user_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "TOTP challenge expired")

    if await is_totp_locked(user_id):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "TOTP locked. Contact an admin.")

    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account unavailable")

    if not verify_user_totp(user, req.code):
        await record_totp_failure(user.id)
        await write_audit(
            db, "totp_verify_fail",
            user_id=user.id, username=user.username, role_at_time=user.role,
            outcome="failure",
        )
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid TOTP code")

    await clear_totp_failures(user.id)
    token, _ = await create_session(db, user, request=request)
    await write_audit(
        db, "login_success",
        user_id=user.id, username=user.username, role_at_time=user.role,
        outcome="success",
        details={"with_totp": True},
        user_agent=(request.headers.get("user-agent") or "")[:512],
    )
    await db.commit()
    set_session_cookie(response, token)
    return LoginResponse(status="ok", user=UserOut.model_validate(user))


# ─── Logout ──────────────────────────────────────────────────────────────────

@router.post("/logout", summary="Log out the current session")
async def logout(request: Request, response: Response,
                 session=Depends(current_session), db: AsyncSession = Depends(get_db)) -> dict:
    """Revoke the caller's current session and clear the session cookie.
    Authenticated user. Returns {"status": "ok"}."""
    user, sess = session
    await revoke_session(db, sess, reason="user")
    await write_audit(
        db, "logout",
        outcome="success",
        resource_type="session", resource_id=str(sess.id),
    )
    await db.commit()
    clear_session_cookie(response)
    return {"status": "ok"}


# ─── Change password ─────────────────────────────────────────────────────────

@router.post("/change-password", summary="Change the current user's password")
async def change_password(req: ChangePasswordRequest, request: Request,
                          user: User = Depends(current_user),
                          db: AsyncSession = Depends(get_db)) -> dict:
    """Change the calling user's password after verifying the current one.
    Authenticated user. Returns 401 if the current password is wrong and 400 if
    the new password matches the old. Returns {"status": "ok"} on success."""
    if not await averify_password(req.current_password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Current password is incorrect")
    if req.new_password == req.current_password:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "New password must differ")
    user.hashed_password = await ahash_password(req.new_password)
    user.force_password_change = False
    await write_audit(
        db, "password_change",
        user_id=user.id, username=user.username,
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return {"status": "ok"}


# ─── TOTP setup / enable / disable ──────────────────────────────────────────

@router.post("/totp/setup", response_model=TotpSetupResponse, summary="Generate a TOTP secret and QR code")
async def totp_setup(user: User = Depends(current_user),
                     db: AsyncSession = Depends(get_db)) -> TotpSetupResponse:
    """Generate a fresh TOTP secret for the calling user and return it with a
    provisioning URI and a base64 PNG QR code. Authenticated user. Not enabled
    until /totp/enable verifies a code; returns 400 if TOTP is already enabled."""
    if user.totp_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "TOTP already enabled — disable first to rotate")
    secret = new_totp_secret()
    user.totp_secret_enc = encrypt_secret(secret)
    await db.commit()

    uri = totp_provisioning_uri(secret, user.username)
    qr_img = qrcode.make(uri)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    data_url = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")
    return TotpSetupResponse(secret=secret, provisioning_uri=uri, qr_code_data_url=data_url)


@router.post("/totp/enable", summary="Enable TOTP after verifying a code")
async def totp_enable(req: TotpEnableRequest, request: Request,
                      user: User = Depends(current_user),
                      db: AsyncSession = Depends(get_db)) -> dict:
    """Enable TOTP for the calling user by verifying a code against the pending
    secret from /totp/setup. Authenticated user. Returns 400 if TOTP is already
    enabled or no secret was set up, 401 on an invalid code, {"status": "ok"} on success."""
    if user.totp_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "TOTP already enabled")
    if not user.totp_secret_enc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Run /totp/setup first")
    if not verify_user_totp(_tmp_user_with_secret(user), req.code):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid TOTP code")
    user.totp_enabled = True
    user.force_totp_enrol = False
    await write_audit(
        db, "totp_enable", user_id=user.id, username=user.username,
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return {"status": "ok"}


@router.post("/totp/disable", summary="Disable TOTP for the current user")
async def totp_disable(req: TotpDisableRequest, request: Request,
                       user: User = Depends(current_user),
                       db: AsyncSession = Depends(get_db)) -> dict:
    """Disable TOTP for the calling user after verifying their password (and the
    current TOTP code if one is supplied). Authenticated user. Clears the stored
    secret. Returns 401 on a bad password or code, {"status": "ok"} on success."""
    if not await averify_password(req.password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Password incorrect")
    if user.totp_enabled and req.code and not verify_user_totp(user, req.code):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid TOTP code")
    user.totp_enabled = False
    user.totp_secret_enc = None
    await write_audit(
        db, "totp_disable", user_id=user.id, username=user.username,
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return {"status": "ok"}


# Helper: verify_user_totp expects user.totp_enabled=True. For initial enrol we
# need to verify against the *pending* secret. This shim flips the flag for the
# verification only.
def _tmp_user_with_secret(u: User) -> User:
    proxy = type("P", (), {"totp_enabled": True, "totp_secret_enc": u.totp_secret_enc})()
    return proxy
