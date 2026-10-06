"""I4 (R25) — incident-start checks (audit Appendix C3, "At incident start").

What should be in place soon after an incident is opened. Warnings only: nothing here blocks
anything (gates are I5). A missing check is a warning, and turns overdue START_CHECK_OVERDUE_AFTER
after the incident was created. Computed fresh on every read, for GET …/start-checks and the snapshot.
"""
from datetime import timedelta
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from models import (Incident, IncidentAssignment, OperationalRole, PlaybookTask, PlaybookTemplate,
                    RegulatoryDeadline, User, utcnow)
from schemas import IncidentStartChecks, StakeholderNotificationSummary, StartCheck
from stakeholder_notifications.service import rollup as notifications_rollup

# Owner decision 2026-10-06: a missing start check becomes overdue 60 minutes after creation.
START_CHECK_OVERDUE_AFTER = timedelta(minutes=60)

# Types that start regulatory clocks (personal data, extortion, payment fraud): Legal should be initialised.
LEGAL_TYPES = ("ransomware", "data_breach", "bec")
# Types that suggest email compromise: the attacker may read the mailbox, so decide on Dark Operation.
EMAIL_COMPROMISE_TYPES = ("phishing", "bec")
PERSONAL_DATA_TAG = "personal-data"

_ROLES = (("ic_assigned", "incident_commander", "Incident Commander assigned"),
          ("comms_lead_assigned", "communications_lead", "Communications Lead assigned"),
          ("legal_liaison_assigned", "legal_liaison", "Legal Liaison assigned"))


def _legal_reason(inc: Incident) -> Optional[str]:
    if inc.incident_type in LEGAL_TYPES:
        return f"type {inc.incident_type}"
    if inc.information_impact == "privacy":
        return "information impact: privacy (personal data)"
    if PERSONAL_DATA_TAG in (inc.tags or []):
        return f"tagged {PERSONAL_DATA_TAG}"
    return None


async def evaluate(db: AsyncSession, inc: Incident,
                   notifications: Optional[StakeholderNotificationSummary] = None) -> IncidentStartChecks:
    created = inc.created_at
    overdue_at = created + START_CHECK_OVERDUE_AFTER
    missing = "overdue" if utcnow() >= overdue_at else "warning"
    items: list[StartCheck] = []

    def add(key, label, ok, route, detail=None, status=None):
        items.append(StartCheck(key=key, label=label, status="ok" if ok else (status or missing),
                                detail=detail, route=route))

    held = set((await db.execute(
        select(OperationalRole.key)
        .join(IncidentAssignment, IncidentAssignment.role_id == OperationalRole.id)
        .join(User, User.id == IncidentAssignment.user_id)
        .where(IncidentAssignment.incident_id == inc.id, User.is_active == True)  # noqa: E712
    )).scalars())
    for key, role_key, label in _ROLES:
        add(key, label, role_key in held, "assignments")

    add("detected_at_set", "Detection time recorded", inc.detected_at is not None, "details",
        detail="The SIEM alert carried no time of its own: this is when FENRIR received it."
               if inc.detected_at_source == "received" else None)

    # J1: a SIEM alert whose category maps to no FENRIR type opens the incident without one (never a guessed type).
    add("type_set", "Incident type set", inc.incident_type is not None, "details",
        detail="The SIEM alert carried no category FENRIR maps to an incident type: choose one on Details."
               if inc.incident_type is None and inc.detection_method == "siem_alert" else None)

    tasks = int((await db.execute(
        select(func.count()).select_from(PlaybookTask)
        .where(PlaybookTask.incident_id == inc.id, PlaybookTask.archived_at.is_(None))
    )).scalar() or 0)
    detail = None
    if not tasks and inc.incident_type:
        names = [t.name for t in (await db.execute(
            select(PlaybookTemplate).order_by(PlaybookTemplate.is_system.desc(), PlaybookTemplate.name)
        )).scalars() if inc.incident_type in (t.incident_types or [])]
        if names:
            detail = "Suggested for this type: " + ", ".join(names) + "."
    add("playbook_applied", "Playbook applied", tasks > 0, "playbook", detail)

    if reason := _legal_reason(inc):
        has_legal = (await db.execute(
            select(RegulatoryDeadline.id).where(RegulatoryDeadline.incident_id == inc.id).limit(1)
        )).scalar_one_or_none() is not None
        add("legal_initialised", "Legal deadlines initialised", has_legal, "legal", f"Applies: {reason}.")

    if inc.incident_type in EMAIL_COMPROMISE_TYPES:
        decided = bool(inc.dark_operation) or inc.dark_operation_decided_at is not None
        add("dark_operation_decided", "Dark Operation decided", decided, "comms/oob",
            None if decided else "Email compromise suspected: decide whether to go dark (on or off).")

    s = notifications or await notifications_rollup(db, inc.id)
    add("notifications_on_time", "No stakeholder notification overdue", s.overdue == 0, "comms/notifications",
        f"{s.overdue} overdue" if s.overdue else None, status="overdue")

    count = lambda st: sum(1 for i in items if i.status == st)   # noqa: E731
    return IncidentStartChecks(total=len(items), ok=count("ok"), warning=count("warning"), overdue=count("overdue"),
                               overdue_after_minutes=int(START_CHECK_OVERDUE_AFTER.total_seconds() // 60),
                               overdue_at=overdue_at, items=items)
