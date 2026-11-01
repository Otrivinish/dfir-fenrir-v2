"""GET /api/readiness: organisation-level preparation checks (E1), computed fresh on each request.

Admins and analysts only (it describes security posture; viewers get 403). It reads state and
never blocks anything: POST /api/incidents does not consult it.

RD: an admin can defer a failing check for good (POST / DELETE /api/readiness/deferrals). The
check keeps running; it only drops out of the failing counts the Dashboard banner and the New
incident list use.
"""
from datetime import datetime, timezone
from typing import Annotated, Literal, Optional

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import require_admin, require_analyst
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from models import ReadinessDeferral, User
from readiness.checks import CHECKS, evaluate

router = APIRouter()


class ReadinessDeferralOut(BaseModel):
    by_name: str = Field(description="Who deferred it (their name when they deferred it).")
    at: datetime = Field(description="When it was deferred (UTC).")
    reason: Optional[str] = Field(default=None, description="Why, if a reason was given. Always null for non-admins "
                                                            "on admin_totp and audit_anchor (their details are "
                                                            "admin-only).")


class ReadinessCheck(BaseModel):
    id: str = Field(description="Stable machine id (e.g. on_call_14d). Ids are never renamed; new checks add ids.")
    title: str = Field(description="What the check requires, in plain words.")
    level: Literal["blocker", "warning"] = Field(
        description="blocker: fix before the next incident; warning: should be fixed. audit_anchor drops to "
                    "warning while the latest anchor is missing or stale; a failed verification is a blocker.")
    status: Literal["pass", "fail", "unknown"] = Field(
        description="unknown: the data source is missing or the check could not run. Never a pass.")
    detail: str = Field(description="What was found: counts, ages and UTC calendar dates. Never usernames or emails. "
                                    "For non-admins, admin_totp and audit_anchor carry only their status "
                                    "(\"Failing; an admin has details.\").")
    csf: list[str] = Field(description="NIST CSF 2.0 subcategory IDs this check evidences, or another standard's "
                                       "reference (e.g. ISO/IEC 27041). Empty when none applies.")
    fix_route: Optional[str] = Field(default=None, description="GUI path where it is fixed. Most fixes need an admin.")
    deferral: Optional[ReadinessDeferralOut] = Field(
        default=None, description="RD: set while an admin has deferred this check. The check still runs and "
                                  "reports its status; a deferred check is left out of blockers_failing / "
                                  "warnings_failing. Null while a check deferred as a warning is a blocker.")


class ReadinessSummary(BaseModel):
    blockers_failing: int = Field(description="Checks with level blocker and status fail that are not deferred. "
                                              "The Dashboard banner shows while this is above 0.")
    warnings_failing: int = Field(description="Checks with level warning and status fail that are not deferred.")
    unknown: int = Field(description="Checks that could not be evaluated (status unknown), deferred or not.")
    blockers_deferred: int = Field(description="RD: checks with level blocker and status fail that are deferred.")
    warnings_deferred: int = Field(description="RD: checks with level warning and status fail that are deferred.")


class Readiness(BaseModel):
    generated_at: datetime = Field(description="When the checks ran (UTC).")
    summary: ReadinessSummary
    checks: list[ReadinessCheck]


@router.get("", response_model=Readiness, summary="Get organisation readiness")
async def get_readiness(
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> Readiness:
    """Run the organisation-level readiness checks now and return each one's status. Admins and
    analysts only; viewers get 403. Analysts see admin_totp and audit_anchor's status only (their
    details name attack targets); admins see every detail. A check that errors reports unknown and
    never affects the others.

    v1 checks (id, level, NIST CSF 2.0): admins_active (blocker, GV.RR-02) ≥2 active admins;
    admin_totp (blocker, PR.AA-03) TOTP enforced and every active admin enrolled;
    operational_roles (blocker, GV.RR-02) Incident Commander, Communications Lead and Legal Liaison
    roles active; on_call_14d (blocker, GV.RR-02) an active responder on call every UTC day of the
    next 14 (only analyst and admin accounts count; a viewer can't respond); matrix_high_critical (blocker, RS.CO-02) ≥1 required stakeholder-matrix rule for High
    and for Critical; playbooks_core (warning, ID.IM-04) the Ransomware and Data-breach playbook
    templates exist and were marked reviewed within 12 months (I3: last_reviewed_at, not updated_at); threat_intel (warning, ID.RA-02) ≥1
    enrichment API key and every enabled feed pulled within 24 h; smtp (warning) email configured;
    validated_tools (warning, ISO/IEC 27041) ≥1 active validated tool; backup_recent (blocker,
    PR.DS-11) newest backup under 26 h old and the last manual run not failed (a fresh backup that is
    not age-encrypted fails at warning level); audit_anchor
    (PR.PS-04) the audit-monitor's latest anchor verified within 26 h (blocker if verification failed,
    warning if missing or stale).

    Added by E2 (after the v1 checks): dpo_role (blocker, GV.RR-02 + GV.OC-03) the Data Protection
    Officer operational role is active; on_call_oob (blocker, RS.CO-02) every active responder on call
    (analyst or admin) in the next 14 UTC days has an out-of-band contact in their roster profile (fails when no one is
    on call); contacts_directory (warning, RS.CO-03) the Contacts directory has at least one entry of
    each of supervisory_authority, csirt, law_enforcement, insurer, ir_firm and media_pr, and every
    entry of those types was verified within 90 days.

    RD: a check an admin deferred carries `deferral` {by_name, at, reason}; it still reports its status but is left
    out of blockers_failing / warnings_failing (counted in blockers_deferred / warnings_deferred).

    Not checked in v1: restore tests, tabletop exercises, a jurisdiction profile, whether a test email
    actually sends, and validated tools per acquisition type."""
    return Readiness(**await evaluate(db, is_admin=user.role == "admin"))


class ReadinessDeferIn(BaseModel):
    check_ids: list[Annotated[str, Field(max_length=64)]] = Field(min_length=1, max_length=32,
                                 description="Check ids to defer (e.g. [\"on_call_14d\", \"on_call_oob\"]). Each "
                                             "must be failing or unknown now and not already deferred.")
    reason: Optional[str] = Field(default=None, max_length=500,
                                  description="Optional: why the organisation lives with it. Blank = none.")


_TITLES = {meta["id"]: meta["title"] for meta, _ in CHECKS}


@router.post("/deferrals", response_model=Readiness, status_code=status.HTTP_201_CREATED,
             summary="Defer failing readiness checks",
             responses={409: {"model": ApiErrorBody,
                              "description": "check_not_failing (a check passes now) or already_deferred"},
                        422: {"model": ApiErrorBody, "description": "unknown_check (an id that isn't a check)"}})
async def defer_readiness_checks(
    req: ReadinessDeferIn,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> Readiness:
    """Defer one or more checks for good: each stays deferred until an admin undoes it (DELETE). A deferred check
    still runs and still reports its status, and the Readiness page still lists it; it is left out of
    summary.blockers_failing / warnings_failing, so the Dashboard banner and the New incident list stop showing it.
    A blocker that starts failing later still shows, and so does a check deferred as a warning that is now a
    blocker (audit_anchor, backup_recent): it can be deferred again at the new level. Only a check that is failing or unknown now can be deferred
    (409 check_not_failing); all or none are deferred. Each deferral is audit-logged (readiness_check_deferred).
    Admin only. Returns the readiness checks as they are now."""
    ids = sorted(set(req.check_ids))    # one insert order for every request: two overlapping ones can't deadlock
    if bad := [i for i in ids if i not in _TITLES]:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "unknown_check", f"Not a readiness check: {', '.join(bad)}")
    current = {c["id"]: c for c in (await evaluate(db, is_admin=True))["checks"]}
    if done := [i for i in ids if current[i]["deferral"] is not None]:
        raise ApiError(status.HTTP_409_CONFLICT, "already_deferred", f"Already deferred: {', '.join(done)}")
    if passing := [i for i in ids if current[i]["status"] == "pass"]:
        raise ApiError(status.HTTP_409_CONFLICT, "check_not_failing",
                       f"Only a failing check can be deferred; passing now: {', '.join(passing)}")
    reason = (req.reason or "").strip() or None
    name = (user.full_name or "").strip() or user.username
    at = datetime.now(timezone.utc)
    try:
        # A row that no longer applies (deferred as a warning, a blocker now) is replaced; the audit log keeps it.
        # Only such rows: one another admin has just made still conflicts below (409), never gets overwritten.
        await db.execute(delete(ReadinessDeferral).where(
            ReadinessDeferral.check_id.in_([i for i in ids if current[i]["level"] == "blocker"]),
            ReadinessDeferral.level == "warning"))
        for i in ids:
            db.add(ReadinessDeferral(check_id=i, deferred_by_id=user.id, deferred_by_name=name, deferred_at=at,
                                     level=current[i]["level"], reason=reason))
            await db.flush()
            await write_audit(
                db, "readiness_check_deferred", outcome="success",
                resource_type="readiness_check", resource_id=i, resource_label=_TITLES[i],
                details={"level": current[i]["level"], "status": current[i]["status"], "reason": reason},
            )
        await db.commit()
    except IntegrityError:                                 # another admin deferred one of them meanwhile
        await db.rollback()
        raise ApiError(status.HTTP_409_CONFLICT, "already_deferred", "Already deferred: another admin just deferred it")
    return Readiness(**await evaluate(db, is_admin=True))


@router.delete("/deferrals/{check_id}", response_model=Readiness, summary="Undo a readiness deferral",
               responses={404: {"model": ApiErrorBody, "description": "not_deferred"}})
async def remove_readiness_deferral(
    check_id: str,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> Readiness:
    """Undo a deferral: the check counts in summary.blockers_failing / warnings_failing again while it fails, and
    the Dashboard banner shows it again. Audit-logged (readiness_deferral_removed, with who deferred it, when and
    why). Admin only; 404 not_deferred when the check isn't deferred. Returns the readiness checks as they are now."""
    d = (await db.execute(select(ReadinessDeferral).where(ReadinessDeferral.check_id == check_id)
                          .with_for_update())).scalar_one_or_none()
    if d is None:
        raise ApiError(status.HTTP_404_NOT_FOUND, "not_deferred", "That readiness check isn't deferred")
    await write_audit(
        db, "readiness_deferral_removed", outcome="success",
        resource_type="readiness_check", resource_id=check_id, resource_label=_TITLES.get(check_id, check_id),
        details={"deferred_by": d.deferred_by_name, "deferred_at": d.deferred_at.isoformat().replace("+00:00", "Z"), "reason": d.reason},
    )
    await db.delete(d)
    await db.commit()
    return Readiness(**await evaluate(db, is_admin=True))
