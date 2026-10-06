"""GET /api/readiness: organisation-level preparation checks (E1), computed fresh on each request.

Admins and analysts only (it describes security posture; viewers get 403). It reads state and
never blocks anything: POST /api/incidents does not consult it.
"""
from datetime import datetime
from typing import Literal, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import require_analyst
from core.database import get_db
from models import User
from readiness.checks import evaluate

router = APIRouter()


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


class ReadinessSummary(BaseModel):
    blockers_failing: int = Field(description="Checks with level blocker and status fail.")
    warnings_failing: int = Field(description="Checks with level warning and status fail.")
    unknown: int = Field(description="Checks that could not be evaluated (status unknown).")


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

    Not checked in v1: restore tests, tabletop exercises, a jurisdiction profile, whether a test email
    actually sends, and validated tools per acquisition type."""
    return Readiness(**await evaluate(db, is_admin=user.role == "admin"))
