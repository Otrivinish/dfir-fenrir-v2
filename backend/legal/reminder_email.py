"""Out-of-app deadline reminder email (J2, R27), sent by the reminder loop (legal/reminders.py) for each
reminder it has just claimed: a legal deadline's T-12h / T-2h / overdue stage (B4) and an overdue required
stakeholder notification (I2).

Owner decision 2026-10-06:
- Recipients: the incident's Legal Liaison and Incident Commander (active, able to see the incident, with an
  email address); when there is none, every active admin with an email address.
- Content: ONLY the incident ref, the regulation / obligation name and the time left, plus the app path to
  open. Never the title, description or any other incident content. A custom deadline is named by its
  regulation only (its article and obligation are free text).
- Never sent under Dark Operation or TLP:RED: `core.outbound_policy.outbound_allowed(inc)` decides, read
  fresh at send time; a blocked email is audited `reminder_email_suppressed` with the reason.

Org switch: Settings → Integrations → Email → "Email deadline reminders" (`smtp.deadline_reminders`).
Unset = on, but only a configured transport (SMTP or Graph) can send; off = no email (in-app reminders
continue). When off or without a transport nothing is attempted and nothing is audited.

Once per reminder: the loop's conditional claim (reminder_stage / reminder_sent_at, committed before this
runs) is the persisted marker, so a restart never resends. At most once: a failed send is audited
`reminder_email_failed` and logged (exception type only), never retried; sends stop after
EMAIL_BUDGET_SECONDS in one tick (the rest are audited failed, reason time_budget).
"""
import asyncio
import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from core.outbound_policy import outbound_allowed
from mailer.service import _get as _get_setting, send_email, transport_configured
from models import Incident, IncidentAssignment, OperationalRole, User
from notifications.service import _incident_recipients

log = logging.getLogger("legal.reminder_email")

TOGGLE_KEY = "smtp.deadline_reminders"
RECIPIENT_ROLE_KEYS = ("legal_liaison", "incident_commander")
SEND_TIMEOUT_SECONDS = 20
EMAIL_BUDGET_SECONDS = 90


@dataclass
class EmailJob:
    kind: str                 # legal_deadline | stakeholder_notification
    item_id: uuid.UUID        # the deadline / obligation row
    incident_id: uuid.UUID
    stage: int                # legal: 1 T-12h, 2 T-2h, 3 overdue; stakeholder: 3 (overdue)
    what: str                 # regulation / obligation name: platform strings only
    due_at: datetime
    path: str                 # app path to open, e.g. /incidents/<id>/legal


async def toggle_state(db: AsyncSession) -> Optional[bool]:
    """The stored org choice: True / False, or None when never set (default)."""
    v = await _get_setting(db, TOGGLE_KEY)
    return None if v is None else v == "on"


async def enabled(db: AsyncSession) -> bool:
    return await transport_configured(db) and (await toggle_state(db)) is not False


async def recipients(db: AsyncSession, incident_id: uuid.UUID) -> tuple[list[User], bool]:
    """(users, fallback): the incident's Legal Liaison(s) and IC(s) who can see it and have an email;
    else every active admin with an email (fallback=True)."""
    can_see = {u.id for u in await _incident_recipients(db, incident_id)}
    holders = (await db.execute(
        select(User).join(IncidentAssignment, IncidentAssignment.user_id == User.id)
        .join(OperationalRole, OperationalRole.id == IncidentAssignment.role_id)
        .where(IncidentAssignment.incident_id == incident_id, OperationalRole.key.in_(RECIPIENT_ROLE_KEYS),
               User.is_active == True)  # noqa: E712
    )).scalars().all()
    picked = [u for u in holders if u.id in can_see and u.email]
    fallback = not picked
    if fallback:
        picked = list((await db.execute(
            select(User).where(User.is_active == True, User.role == "admin")  # noqa: E712
        )).scalars().all())
    seen, out = set(), []
    for u in picked:
        key = (u.email or "").strip().lower()
        if key and key not in seen:
            seen.add(key)
            out.append(u)
    return out, fallback


def time_left(due_at: datetime, now: datetime) -> str:
    secs = int((due_at - now).total_seconds())
    h, m = divmod(abs(secs) // 60, 60)
    span = f"{h} h {m} min" if h else f"{m} min"
    return f"{span} left" if secs > 0 else f"overdue by {span}"


def compose(ref: str, job: EmailJob, now: datetime) -> tuple[str, str]:
    left = time_left(job.due_at, now)
    subject = f"[FENRIR] {ref}: {job.what} - {left}"
    body = (
        "FENRIR deadline reminder\n\n"
        f"Incident:   {ref}\n"
        f"Obligation: {job.what}\n"
        f"Time left:  {left} (as of {now.strftime('%Y-%m-%dT%H:%M:%SZ')})\n"
        f"Open:       {job.path}\n\n"
        "This email carries only the incident reference and the deadline. Sign in to FENRIR for the details.\n"
    )
    return subject, body


async def send_jobs(db: AsyncSession, jobs: list[EmailJob], now: datetime) -> int:
    """Send (or suppress) the email for each claimed reminder. Returns the number of emails sent. Never raises."""
    if not jobs:
        return 0
    try:
        if not await enabled(db):
            return 0
    except Exception as e:  # noqa: BLE001
        log.warning("reminder email: settings unreadable (%s)", type(e).__name__)
        return 0
    started, sent = time.monotonic(), 0
    for job in jobs:
        base = {"kind": job.kind, "item_id": str(job.item_id), "stage": job.stage}
        try:
            inc = (await db.execute(select(Incident).where(Incident.id == job.incident_id)
                                    .execution_options(populate_existing=True))).scalar_one()
            allowed, reason = outbound_allowed(inc)
            if not allowed:
                await write_audit(db, "reminder_email_suppressed", outcome="success", resource_type="incident",
                                  resource_id=str(inc.id), resource_label=inc.ref, details={**base, "reason": reason})
                await db.commit()
                continue
            if time.monotonic() - started > EMAIL_BUDGET_SECONDS:
                await write_audit(db, "reminder_email_failed", outcome="failure", resource_type="incident",
                                  resource_id=str(inc.id), resource_label=inc.ref,
                                  details={**base, "reason": "time_budget"})
                await db.commit()
                continue
            users, fallback = await recipients(db, inc.id)
            subject, body = compose(inc.ref, job, now)
            ok_ids, failed_ids = [], []
            for u in users:
                try:
                    ok = await asyncio.wait_for(send_email(db, u.email, subject, body), SEND_TIMEOUT_SECONDS)
                except Exception:  # noqa: BLE001 — timeout or transport error: counted as failed, not retried
                    ok = False
                (ok_ids if ok else failed_ids).append(str(u.id))
            sent += len(ok_ids)
            details = {**base, "recipients": ok_ids, "failed": failed_ids, "fallback_admins": fallback}
            if not users:
                details["reason"] = "no_recipients"
            await write_audit(db, "reminder_email_sent" if ok_ids else "reminder_email_failed",
                              outcome="success" if ok_ids else "failure", resource_type="incident",
                              resource_id=str(inc.id), resource_label=inc.ref, details=details)
            await db.commit()
        except Exception as e:  # noqa: BLE001 — one bad reminder must not stop the others
            await db.rollback()
            log.warning("reminder email: %s %s skipped (%s)", job.kind, job.item_id, type(e).__name__)
    if sent:
        log.info("reminder email: %d email(s) sent", sent)
    return sent
