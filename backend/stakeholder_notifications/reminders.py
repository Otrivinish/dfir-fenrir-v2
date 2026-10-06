"""In-app reminder for overdue stakeholder notifications (I2). Run from the legal reminders loop
(legal/reminders.py, one 5-minute tick, one worker).

One reminder per obligation, once it is overdue: a required, active (not superseded), pending
obligation past due_at with no reminder yet. It goes to the incident's assignees who can still
see it, else to everyone with access (as the legal reminders). Closed and Dark Operation
incidents are included: in-app notifications stay on (A1, H3). J2: after the claim is committed, the
same reminder is emailed (ref, "Notify <role> (<category>)" and how long overdue, nothing else) by
legal/reminder_email.py, under its rules (org switch, transport, outbound policy: never under Dark
Operation or TLP:RED). No webhooks, and the tracker itself never notifies a stakeholder.

Each obligation is claimed with a conditional UPDATE (reminder_sent_at still NULL, still pending,
not superseded, due_at unchanged) and committed with its notifications, so it is reminded at most
once even with two loops. Obligations already overdue when the tracker was deployed were stamped
at backfill (core/database.py), so the deploy fired no burst. Logs carry counts and exception types only.
"""
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, update

from core.database import SessionLocal
from legal.reminder_email import EmailJob, send_jobs as send_reminder_emails
from models import Incident, StakeholderNotification as SN
from notifications.service import _create_and_push, commit_and_push, discard_pushes

log = logging.getLogger("stakeholder_notifications.reminders")


async def tick(now: Optional[datetime] = None, session_factory=SessionLocal) -> int:
    """One pass. Returns the number of in-app notifications created."""
    from legal.reminders import _recipients   # local: legal.reminders imports this module's tick

    now = now or datetime.now(timezone.utc)
    sent = 0
    async with session_factory() as db:
        due = (await db.execute(
            select(SN.id, SN.incident_id, SN.role, SN.category, SN.due_at, Incident.ref)
            .join(Incident, Incident.id == SN.incident_id)
            .where(SN.status == "pending", SN.required.is_(True), SN.superseded_at.is_(None),
                   SN.reminder_sent_at.is_(None), SN.due_at <= now)
            .order_by(SN.due_at)
            .limit(500)
        )).all()
        recipients: dict = {}
        emails: list[EmailJob] = []
        for row in due:
            try:
                claimed = (await db.execute(
                    update(SN)
                    .where(SN.id == row.id, SN.reminder_sent_at.is_(None), SN.status == "pending",
                           SN.superseded_at.is_(None), SN.due_at == row.due_at)
                    .values(reminder_sent_at=now, updated_at=SN.updated_at)   # a reminder is not an edit
                    .execution_options(synchronize_session=False)
                )).rowcount
                if claimed != 1:
                    continue
                if row.incident_id not in recipients:
                    recipients[row.incident_id] = await _recipients(db, row.incident_id)
                title = f"{row.ref} · Notify {row.role}: overdue"[:255]
                body = (f"The stakeholder matrix requires notifying {row.role} ({row.category}). "
                        "Record it on Comms › Notifications once done.")
                for user_id in recipients[row.incident_id]:
                    await _create_and_push(db, user_id, type="stakeholder_notification", title=title, body=body,
                                           incident_id=row.incident_id)
                await commit_and_push(db)
                sent += len(recipients[row.incident_id])
                emails.append(EmailJob(
                    kind="stakeholder_notification", item_id=row.id, incident_id=row.incident_id, stage=3,
                    what=f"Notify {row.role} ({row.category})"[:300], due_at=row.due_at,
                    path=f"/incidents/{row.incident_id}/comms/notifications"))
            except Exception as e:  # noqa: BLE001 — one bad row must not stop the others
                await db.rollback()
                discard_pushes(db)
                log.warning("stakeholder reminders: obligation %s skipped (%s)", row.id, type(e).__name__)
        await send_reminder_emails(db, emails, now)   # after every claim is committed; never raises
    return sent
