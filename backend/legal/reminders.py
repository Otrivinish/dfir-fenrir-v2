"""In-app reminders for regulatory deadlines: T-12h, T-2h and overdue.

A background loop (started from main.py's lifespan, like the syslog forwarder; the backend
runs one worker, so there is one loop) ticks every 5 minutes. Each tick looks at open
deadlines (pending / in_progress) due within 12 hours whose `reminder_stage` is below the
stage they have reached, and sends ONE in-app notification per deadline for the highest
stage reached — to the incident's assignees who can still see it, else to everyone with
access. Closed incidents are included (obligations outlive closure), and so are Dark
Operation incidents: in-app notifications stay on under Dark Operation (A1). J2: after a stage is
claimed and committed, legal/reminder_email.py emails the incident's Legal Liaison and IC (else
admins) the ref, the regulation and the time left only, unless the org switch is off, no mail
transport is configured, or `core.outbound_policy.outbound_allowed(inc)` blocks it (Dark Operation /
TLP:RED, audited `reminder_email_suppressed`). No webhooks.

Each deadline is claimed with a conditional UPDATE (… WHERE reminder_stage = <old>, the status
still open and deadline_at unchanged) and committed with its notifications, so a stage is sent at
most once even if two loops ran, and never for a deadline completed, waived or re-anchored since it
was read. WebSocket pushes go out only after that commit; a row that fails is rolled back and its
pushes are dropped. Re-anchoring resets the stage to 0 (legal/routes.py). Logs carry counts and exception types
only: no incident titles, obligations or user names.
"""
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, update

from core.database import SessionLocal
from legal.reminder_email import EmailJob, send_jobs as send_reminder_emails
from models import Incident, IncidentAssignment, RegulatoryDeadline
from notifications.service import _create_and_push, _incident_recipients, commit_and_push, discard_pushes
from stakeholder_notifications.reminders import tick as stakeholder_tick

log = logging.getLogger("legal.reminders")

TICK_SECONDS = 300
TICK_TIMEOUT_SECONDS = 120
OPEN_STATUSES = ("pending", "in_progress")
# Stage: 1 = due within 12 h, 2 = due within 2 h, 3 = overdue.
_WINDOWS = ((3, timedelta(0)), (2, timedelta(hours=2)), (1, timedelta(hours=12)))
_PHRASE = {1: "due in under 12 h", 2: "due in under 2 h", 3: "overdue"}

_task: Optional[asyncio.Task] = None


def target_stage(deadline_at: datetime, now: datetime) -> int:
    """Reminder stage a deadline has reached at `now` (0 = none yet)."""
    left = deadline_at - now
    for stage, window in _WINDOWS:
        if left <= window:
            return stage
    return 0


async def _recipients(db, incident_id) -> list:
    """User ids: assignees who can still see the incident (active, with access); when there
    are none, everyone with access."""
    allowed = [u.id for u in await _incident_recipients(db, incident_id)]
    assignee_ids = set((await db.execute(
        select(IncidentAssignment.user_id).where(
            IncidentAssignment.incident_id == incident_id,
            IncidentAssignment.user_id.is_not(None),
        )
    )).scalars().all())
    return [uid for uid in allowed if uid in assignee_ids] or allowed


async def tick(now: Optional[datetime] = None, session_factory=SessionLocal) -> int:
    """One pass. Returns the number of notifications created."""
    from legal.routes import _TEMPLATES_BY_KEY, article_label   # local: legal.routes imports FastAPI deps

    now = now or datetime.now(timezone.utc)
    sent = 0
    async with session_factory() as db:
        due = (await db.execute(
            select(RegulatoryDeadline.id, RegulatoryDeadline.incident_id, RegulatoryDeadline.regulation,
                   RegulatoryDeadline.article, RegulatoryDeadline.obligation, RegulatoryDeadline.deadline_at,
                   RegulatoryDeadline.reminder_stage, Incident.ref)
            .join(Incident, Incident.id == RegulatoryDeadline.incident_id)
            .where(RegulatoryDeadline.status.in_(OPEN_STATUSES),
                   RegulatoryDeadline.reminder_stage < 3,
                   RegulatoryDeadline.deadline_at <= now + timedelta(hours=12))
            .order_by(RegulatoryDeadline.deadline_at)
            .limit(500)
        )).all()
        recipients: dict = {}
        emails: list[EmailJob] = []
        for row in due:
            stage = target_stage(row.deadline_at, now)
            if stage <= row.reminder_stage:
                continue
            try:
                claimed = (await db.execute(
                    update(RegulatoryDeadline)
                    .where(RegulatoryDeadline.id == row.id, RegulatoryDeadline.reminder_stage == row.reminder_stage,
                           RegulatoryDeadline.status.in_(OPEN_STATUSES),
                           RegulatoryDeadline.deadline_at == row.deadline_at)
                    # a reminder is not an edit: keep updated_at as it is
                    .values(reminder_stage=stage, updated_at=RegulatoryDeadline.updated_at)
                    .execution_options(synchronize_session=False)
                )).rowcount
                if claimed != 1:
                    continue                  # already sent, or completed / waived / re-anchored since read
                if row.incident_id not in recipients:
                    recipients[row.incident_id] = await _recipients(db, row.incident_id)
                internal = bool(_TEMPLATES_BY_KEY.get((row.regulation, row.article, row.obligation), {})
                                .get("internal_target"))
                what = "target" if internal else "deadline"
                label = " ".join(x for x in (row.regulation, article_label(row.regulation, row.article,
                                                                          row.obligation)) if x)
                title = f"{row.ref} · {label} {what} {_PHRASE[stage]}"[:255]
                body = row.obligation[:200] + ("…" if len(row.obligation) > 200 else "")
                for user_id in recipients[row.incident_id]:
                    await _create_and_push(db, user_id, type="legal_deadline", title=title, body=body,
                                           incident_id=row.incident_id)
                await commit_and_push(db)     # pushes only after this row's commit
                sent += len(recipients[row.incident_id])
                # J2: the email names a template deadline by its label and obligation (platform strings);
                # a custom one by its regulation only (its article / obligation are free text).
                emails.append(EmailJob(
                    kind="legal_deadline", item_id=row.id, incident_id=row.incident_id, stage=stage,
                    what=(f"{label} {what} ({row.obligation})" if (row.regulation, row.article, row.obligation)
                          in _TEMPLATES_BY_KEY else f"{row.regulation} custom {what}")[:300],
                    due_at=row.deadline_at, path=f"/incidents/{row.incident_id}/legal"))
            except Exception as e:  # noqa: BLE001 — one bad row must not stop the others
                await db.rollback()
                discard_pushes(db)            # never push a rolled-back notification
                log.warning("legal reminders: deadline %s skipped (%s)", row.id, type(e).__name__)
        await send_reminder_emails(db, emails, now)   # after every claim is committed; never raises
    return sent


async def _run() -> None:
    first = True
    while True:
        try:
            sent = await asyncio.wait_for(tick(), timeout=TICK_TIMEOUT_SECONDS)
            if sent:
                log.info("legal reminders: %d notification(s) sent", sent)
            if first:
                log.info("legal reminders: first tick completed")
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001 — the loop never dies
            log.warning("legal reminders: tick failed (%s)", type(e).__name__)
        # I2: overdue stakeholder notifications, same loop and rules (in-app only).
        try:
            sent = await asyncio.wait_for(stakeholder_tick(), timeout=TICK_TIMEOUT_SECONDS)
            if sent:
                log.info("stakeholder reminders: %d notification(s) sent", sent)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001 — the loop never dies
            log.warning("stakeholder reminders: tick failed (%s)", type(e).__name__)
        first = False
        await asyncio.sleep(TICK_SECONDS)


async def start_reminders() -> None:
    global _task
    if _task and not _task.done():
        return
    _task = asyncio.create_task(_run(), name="legal-reminders")
    log.info("legal reminders: loop started (tick %ss)", TICK_SECONDS)


async def stop_reminders() -> None:
    global _task
    if not _task:
        return
    _task.cancel()
    try:
        await _task
    except (asyncio.CancelledError, Exception):  # noqa: BLE001
        pass
    _task = None
