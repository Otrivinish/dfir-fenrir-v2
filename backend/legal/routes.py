"""Regulatory deadline tracking — GDPR / NIS2 / DORA / PCI-DSS / HIPAA / CCPA."""
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from incidents.access import get_accessible_incident
from models import RegulatoryDeadline, Incident, TimelineEvent, User

router = APIRouter()


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


# ── Regulation templates ──────────────────────────────────────────────────────

REGULATION_TEMPLATES: dict[str, list[dict]] = {
    "GDPR": [
        {
            "article": "Article 33",
            "obligation": "Notify supervisory authority (DPA) of personal data breach",
            "recipient": "National Data Protection Authority (DPA)",
            "deadline_hours": 72,
            "is_mandatory": True,
            "notes": (
                "Required unless breach is unlikely to result in risk to individuals. "
                "Include: nature of breach, categories/number of data subjects, likely "
                "consequences, measures taken/proposed."
            ),
        },
        {
            "article": "Article 34",
            "obligation": "Notify affected individuals of high-risk personal data breach",
            "recipient": "Affected data subjects",
            "deadline_hours": 72,
            "is_mandatory": False,
            "notes": (
                "Required when breach is likely to result in HIGH RISK to rights and freedoms. "
                "Not required if data was encrypted/pseudonymised or subsequent measures ensure "
                "high risk no longer likely."
            ),
        },
    ],
    "NIS2": [
        {
            "article": "Article 23(1) — Early Warning",
            "obligation": "Submit early warning to CSIRT / competent authority",
            "recipient": "National CSIRT / Competent Authority",
            "deadline_hours": 24,
            "is_mandatory": True,
            "notes": (
                "For significant incidents only. Must indicate whether incident is suspected "
                "to be caused by unlawful or malicious acts."
            ),
        },
        {
            "article": "Article 23(1) — Incident Notification",
            "obligation": "Submit full incident notification to CSIRT / competent authority",
            "recipient": "National CSIRT / Competent Authority",
            "deadline_hours": 72,
            "is_mandatory": True,
            "notes": (
                "Full notification including: initial assessment, severity, indicators of "
                "compromise, and whether incident has cross-border impact."
            ),
        },
        {
            "article": "Article 23(4) — Final Report",
            "obligation": "Submit final incident report",
            "recipient": "National CSIRT / Competent Authority",
            "deadline_hours": 720,
            "is_mandatory": True,
            "notes": (
                "Detailed description of incident, type of threat / root cause, applied / "
                "ongoing mitigation measures, cross-border impact if applicable."
            ),
        },
    ],
    "DORA": [
        {
            "article": "Article 19 — Initial Notification",
            "obligation": "Initial notification of major ICT-related incident",
            "recipient": "Competent Authority (Financial Regulator)",
            "deadline_hours": 4,
            "is_mandatory": True,
            "notes": (
                "For major ICT incidents only (as classified per DORA criteria). "
                "Financial entities must notify without undue delay."
            ),
        },
        {
            "article": "Article 19 — Intermediate Report",
            "obligation": "Submit intermediate report on major ICT incident",
            "recipient": "Competent Authority",
            "deadline_hours": 72,
            "is_mandatory": True,
            "notes": "Updated status on the incident including any new significant information.",
        },
        {
            "article": "Article 19 — Final Report",
            "obligation": "Submit final report on major ICT incident",
            "recipient": "Competent Authority",
            "deadline_hours": 720,
            "is_mandatory": True,
            "notes": "Root cause analysis and measures implemented to prevent recurrence.",
        },
    ],
    "PCI_DSS": [
        {
            "article": "Requirement 12.10.4",
            "obligation": "Notify payment card brands of suspected breach",
            "recipient": "Visa / Mastercard / Amex / relevant card brands",
            "deadline_hours": 24,
            "is_mandatory": True,
            "notes": (
                "Notify immediately upon suspicion of compromise. Contact your acquiring "
                "bank who will escalate to card brands."
            ),
        },
        {
            "article": "Requirement 12.10.4",
            "obligation": "Engage PCI Forensic Investigator (PFI)",
            "recipient": "PCI-approved Forensic Investigator",
            "deadline_hours": 72,
            "is_mandatory": True,
            "notes": "A PFI must be engaged within 72 hours of a confirmed or suspected cardholder data breach.",
        },
    ],
    "HIPAA": [
        {
            "article": "45 CFR 164.410",
            "obligation": "Notify affected individuals of PHI breach",
            "recipient": "Affected individuals",
            "deadline_hours": 1440,
            "is_mandatory": True,
            "notes": (
                "Written notification within 60 days of discovery. "
                "For breaches >500 residents of a state, also notify prominent media."
            ),
        },
        {
            "article": "45 CFR 164.408",
            "obligation": "Notify HHS Secretary of PHI breach",
            "recipient": "U.S. Department of Health and Human Services (HHS)",
            "deadline_hours": 1440,
            "is_mandatory": True,
            "notes": (
                "Breaches affecting 500+ individuals: notify HHS within 60 days. "
                "Breaches <500: notify HHS annually via HHS website."
            ),
        },
    ],
    "CCPA": [
        {
            "article": "Cal. Civ. Code § 1798.82",
            "obligation": "Notify affected California residents of data breach",
            "recipient": "Affected California residents",
            "deadline_hours": 720,
            "is_mandatory": True,
            "notes": (
                "Required when unencrypted personal information of California residents is "
                "disclosed to an unauthorised person. Notice must be in the specified format."
            ),
        },
        {
            "article": "Cal. Civ. Code § 1798.82(f)",
            "obligation": "Submit sample notification to California Attorney General",
            "recipient": "California Attorney General",
            "deadline_hours": 720,
            "is_mandatory": False,
            "notes": (
                "Required only if breach affects more than 500 California residents. "
                "Submit simultaneously with notification to individuals."
            ),
        },
    ],
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _to_out(d: RegulatoryDeadline) -> dict:
    now = _now_utc()
    deadline_at = d.deadline_at.replace(tzinfo=timezone.utc) if d.deadline_at.tzinfo is None else d.deadline_at
    hours_left = (deadline_at - now).total_seconds() / 3600
    is_overdue = hours_left < 0 and d.status not in ("completed", "waived")
    return {
        "id":                 str(d.id),
        "incident_id":        str(d.incident_id),
        "regulation":         d.regulation,
        "article":            d.article,
        "obligation":         d.obligation,
        "recipient":          d.recipient,
        "deadline_hours":     d.deadline_hours,
        "breach_detected_at": d.breach_detected_at.isoformat(),
        "deadline_at":        d.deadline_at.isoformat(),
        "status":             d.status,
        "completed_at":       d.completed_at.isoformat() if d.completed_at else None,
        "completion_notes":   d.completion_notes,
        "is_mandatory":       d.is_mandatory,
        "notes":              d.notes,
        "hours_remaining":    round(hours_left, 2),
        "is_overdue":         is_overdue,
        "created_at":         d.created_at.isoformat(),
    }


async def _get_deadline(db: AsyncSession, deadline_id: uuid.UUID) -> RegulatoryDeadline:
    row = (await db.execute(
        select(RegulatoryDeadline).where(RegulatoryDeadline.id == deadline_id)
    )).scalar_one_or_none()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Deadline not found")
    return row


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/{incident_id}/legal/templates", summary="List regulatory deadline templates")
async def get_templates(_: User = Depends(current_user)):
    """Return the built-in regulatory notification templates (GDPR, NIS2, DORA, PCI-DSS, HIPAA, CCPA).

    Each template lists its article, obligation, deadline window in hours, and whether it is
    mandatory. Static reference data; requires an authenticated user but no incident access.
    """
    return {
        reg: [
            {
                "article": t["article"],
                "obligation": t["obligation"],
                "deadline_hours": t["deadline_hours"],
                "is_mandatory": t["is_mandatory"],
            }
            for t in templates
        ]
        for reg, templates in REGULATION_TEMPLATES.items()
    }


@router.get("/{incident_id}/legal/deadlines", summary="List regulatory deadlines")
async def list_deadlines(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    """List an incident's regulatory notification deadlines, ordered by due time.

    Each entry includes computed `hours_remaining` and an `is_overdue` flag derived against the
    current UTC time. Requires read access to the incident.
    """
    await _get_incident(db, incident_id, user)
    rows = (await db.execute(
        select(RegulatoryDeadline)
        .where(RegulatoryDeadline.incident_id == incident_id)
        .order_by(RegulatoryDeadline.deadline_at)
    )).scalars().all()
    return [_to_out(r) for r in rows]


class InitBody(BaseModel):
    regulations: list[str]
    breach_detected_at: str   # ISO 8601 UTC string


@router.post("/{incident_id}/legal/deadlines/initialize", status_code=status.HTTP_201_CREATED,
             summary="Initialize deadlines from templates")
async def initialize_deadlines(
    incident_id: uuid.UUID,
    body: InitBody,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Create regulatory deadlines for an incident by expanding the named regulation templates.

    Each template's `deadline_at` is computed from the supplied breach-detected timestamp (ISO 8601
    UTC) plus its deadline window. Requires the analyst role and write access; the action is
    audit-logged. Returns the list of created deadlines.
    """
    await _get_incident(db, incident_id, user)
    breach_dt = datetime.fromisoformat(body.breach_detected_at.replace("Z", "+00:00"))

    added = []
    for reg in body.regulations:
        templates = REGULATION_TEMPLATES.get(reg, [])
        for tmpl in templates:
            d = RegulatoryDeadline(
                incident_id=incident_id,
                regulation=reg,
                breach_detected_at=breach_dt,
                deadline_at=breach_dt + timedelta(hours=tmpl["deadline_hours"]),
                created_by_id=user.id,
                **{k: v for k, v in tmpl.items()},
            )
            db.add(d)
            added.append(d)

    await write_audit(db, "legal_initialize", user_id=user.id,
                      details={"incident_id": str(incident_id),
                               "regulations": body.regulations, "added": len(added)})
    await db.commit()
    for d in added:
        await db.refresh(d)
    return [_to_out(d) for d in added]


class DeadlineCreate(BaseModel):
    regulation: str
    article: Optional[str] = None
    obligation: str
    recipient: Optional[str] = None
    deadline_hours: int
    breach_detected_at: str
    is_mandatory: bool = True
    notes: Optional[str] = None


@router.post("/{incident_id}/legal/deadlines", status_code=status.HTTP_201_CREATED,
             summary="Create a regulatory deadline")
async def create_deadline(
    incident_id: uuid.UUID,
    body: DeadlineCreate,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Create a single custom regulatory deadline for an incident.

    The `deadline_at` is computed from the supplied breach-detected timestamp (ISO 8601 UTC) plus
    `deadline_hours`. Requires the analyst role and write access; the action is audit-logged.
    Returns the created deadline.
    """
    await _get_incident(db, incident_id, user)
    breach_dt = datetime.fromisoformat(body.breach_detected_at.replace("Z", "+00:00"))
    d = RegulatoryDeadline(
        incident_id=incident_id,
        regulation=body.regulation,
        article=body.article,
        obligation=body.obligation,
        recipient=body.recipient,
        deadline_hours=body.deadline_hours,
        breach_detected_at=breach_dt,
        deadline_at=breach_dt + timedelta(hours=body.deadline_hours),
        is_mandatory=body.is_mandatory,
        notes=body.notes,
        created_by_id=user.id,
    )
    db.add(d)
    await write_audit(db, "legal_deadline_create", user_id=user.id,
                      details={"incident_id": str(incident_id), "regulation": body.regulation})
    await db.commit()
    await db.refresh(d)
    return _to_out(d)


class DeadlineUpdate(BaseModel):
    status: Optional[str] = None      # pending | in_progress | completed | waived
    completion_notes: Optional[str] = None
    notes: Optional[str] = None


@router.patch("/{incident_id}/legal/deadlines/{deadline_id}", summary="Update a regulatory deadline")
async def update_deadline(
    incident_id: uuid.UUID,
    deadline_id: uuid.UUID,
    body: DeadlineUpdate,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Update a regulatory deadline's status (pending/in_progress/completed/waived) or notes.

    Completing a deadline stamps `completed_at`/`completed_by`; a status change to in_progress,
    completed or waived also writes a system timeline event. Invalid status returns 422; a deadline
    not in this incident returns 404. Requires the analyst role and write access; the change is
    audit-logged. Returns the updated deadline.
    """
    await _get_incident(db, incident_id, user)
    d = await _get_deadline(db, deadline_id)
    if d.incident_id != incident_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Deadline not found")

    valid_statuses = {"pending", "in_progress", "completed", "waived"}
    status_changed_to = None
    if body.status is not None:
        if body.status not in valid_statuses:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"status must be one of {sorted(valid_statuses)}")
        if body.status != d.status:
            status_changed_to = body.status
        d.status = body.status
        if body.status == "completed" and not d.completed_at:
            d.completed_at = _now_utc()
            d.completed_by_id = user.id
    if body.completion_notes is not None:
        d.completion_notes = body.completion_notes
    if body.notes is not None:
        d.notes = body.notes

    await write_audit(db, "legal_deadline_update", user_id=user.id,
                      details={"incident_id": str(incident_id), "deadline_id": str(deadline_id),
                               "status": d.status})

    if status_changed_to in ("in_progress", "completed", "waived"):
        status_label = {"in_progress": "In progress", "completed": "Completed", "waived": "Waived"}[status_changed_to]
        db.add(TimelineEvent(
            id=uuid.uuid4(),
            incident_id=incident_id,
            event_time=_now_utc(),
            source="Legal",
            event_type="Regulatory Deadline",
            description=f"[{d.regulation}] {d.obligation} — {status_label}",
            origin="system",
            is_system=True,
            external_safe=False,
            system_source="legal_deadline",
            created_by_id=user.id,
        ))

    await db.commit()
    await db.refresh(d)
    return _to_out(d)


@router.delete("/{incident_id}/legal/deadlines/{deadline_id}", status_code=status.HTTP_204_NO_CONTENT,
               summary="Delete a regulatory deadline")
async def delete_deadline(
    incident_id: uuid.UUID,
    deadline_id: uuid.UUID,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Delete a regulatory deadline from an incident.

    Returns 404 if the deadline is not in this incident. Requires the analyst role and write
    access; the deletion is audit-logged. Returns 204 No Content.
    """
    await _get_incident(db, incident_id, user)
    d = await _get_deadline(db, deadline_id)
    if d.incident_id != incident_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Deadline not found")
    await write_audit(db, "legal_deadline_delete", user_id=user.id,
                      details={"incident_id": str(incident_id), "regulation": d.regulation})
    await db.delete(d)
    await db.commit()
