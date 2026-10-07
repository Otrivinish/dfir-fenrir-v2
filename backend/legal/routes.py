"""Regulatory deadline tracking — GDPR / NIS2 / DORA / PCI-DSS / HIPAA / CCPA.

Each deadline runs from its own anchor (`breach_detected_at`): the per-regulation
`anchors` entry, else the request's `breach_detected_at`, else the incident's
Detected time. In-app reminders (T-12h, T-2h, overdue) come from legal/reminders.py.
"""
import calendar
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from incidents.access import get_accessible_incident
from models import RegulatoryDeadline, Incident, TimelineEvent, User

router = APIRouter()

_CLOSED_409 = {409: {"model": ApiErrorBody, "description": "incident_closed"}}


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


def _ensure_open(inc: Incident) -> None:
    """409 incident_closed for structural changes (add, delete, re-anchor) once the incident
    is closed. Status and notes updates stay allowed: obligations such as the NIS2 final
    report outlive closure."""
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed",
                       "Incident is closed: deadlines can still be completed, waived or annotated, "
                       "but not added, deleted or re-anchored. Re-open the incident first.")


# K5 (R41): an anchor is when the organisation became aware, so it can't be in the future;
# same clock-skew allowance as incidents.routes.DETECTED_AT_SKEW.
ANCHOR_SKEW = timedelta(minutes=2)


def _check_anchor(anchor: datetime, field: str) -> None:
    """422 anchor_in_future when `anchor` is later than now + ANCHOR_SKEW."""
    if _as_utc(anchor) > _now_utc() + ANCHOR_SKEW:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "anchor_in_future",
                       f"{field} cannot be in the future: the anchor is when the organisation became aware")


def _reason(raw: Optional[str], code: str, field: str) -> str:
    """The trimmed justification; 422 `code` unless it is 10–2000 characters."""
    text = (raw or "").strip()
    if not 10 <= len(text) <= 2000:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, code,
                       f"{field} is required: 10 to 2000 characters")
    return text


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
            # Art. 34 says "without undue delay" and sets no fixed window: the 72h is an
            # internal target, flagged as such (`internal_target` in the API output).
            "internal_target": True,
            "notes": (
                "Internal target, not a statutory deadline: Art. 34 requires notice "
                "\"without undue delay\" and sets no fixed window. "
                "Required when breach is likely to result in HIGH RISK to rights and freedoms. "
                "Not required if data was encrypted/pseudonymised or subsequent measures ensure "
                "high risk no longer likely."
            ),
        },
    ],
    "NIS2": [
        {
            "article": "Article 23(1) — Early Warning",
            "label": "Article 23(4)(a) — Early warning",
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
            "label": "Article 23(4)(b) — Incident notification",
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
            "label": "Article 23(4)(d) — Final report",
            "obligation": "Submit final incident report",
            "recipient": "National CSIRT / Competent Authority",
            "deadline_hours": 720,           # nominal; the deadline is 1 calendar month
            "deadline_months": 1,
            "is_mandatory": True,
            "notes": (
                "Due one month after the incident notification (Art. 23(4)(d)): until that is "
                "completed this runs from the anchor; completing the 72h notification re-anchors "
                "it to the completion time. "
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


# Template identity = (regulation, article, obligation): the idempotency key for
# initialise, and how a stored row finds its template flags. These strings therefore
# never change once shipped. A template's optional "label" is what is displayed instead
# of `article` (the NIS2 points of Art. 23(4)); it can change without touching the key.
_TEMPLATES_BY_KEY: dict[tuple, dict] = {
    (reg, t["article"], t["obligation"]): t
    for reg, templates in REGULATION_TEMPLATES.items() for t in templates
}


def article_label(regulation: str, article: Optional[str], obligation: str) -> Optional[str]:
    """The article as displayed: the template's label, else the stored article."""
    return _TEMPLATES_BY_KEY.get((regulation, article, obligation), {}).get("label") or article
_NIS2_NOTIFICATION = ("NIS2", "Article 23(1) — Incident Notification",
                      "Submit full incident notification to CSIRT / competent authority")
_NIS2_FINAL = ("NIS2", "Article 23(4) — Final Report", "Submit final incident report")
assert _NIS2_NOTIFICATION in _TEMPLATES_BY_KEY and _NIS2_FINAL in _TEMPLATES_BY_KEY
_OPEN_STATUSES = ("pending", "in_progress")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime) -> datetime:
    """Aware UTC datetime; a naive value is taken as UTC (as on incidents)."""
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _key(d: RegulatoryDeadline) -> tuple:
    return (d.regulation, d.article, d.obligation)


def add_months(dt: datetime, months: int) -> datetime:
    """Calendar-month arithmetic in UTC: same day-of-month and time of day, `months` later;
    when the target month is shorter, the last day of that month (Jan 31 + 1 month =
    Feb 28, or Feb 29 in a leap year; Mar 31 + 1 month = Apr 30)."""
    dt = _as_utc(dt)
    m0 = dt.month - 1 + months
    year, month = dt.year + m0 // 12, m0 % 12 + 1
    return dt.replace(year=year, month=month, day=min(dt.day, calendar.monthrange(year, month)[1]))


def _window(anchor: datetime, deadline_hours: int, deadline_months: Optional[int]) -> tuple[datetime, int]:
    """(deadline_at, deadline_hours) for an anchor. A calendar-month rule stores the real
    number of hours in that window (e.g. 744 for a 31-day month)."""
    anchor = _as_utc(anchor)
    if deadline_months:
        due = add_months(anchor, deadline_months)
        return due, int((due - anchor).total_seconds() // 3600)
    return anchor + timedelta(hours=deadline_hours), deadline_hours


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def _z(dt: Optional[datetime]) -> Optional[str]:
    """API output (F4 / R42): UTC ISO 8601 with a Z suffix, sub-second precision kept; a naive
    value is UTC. Audit details keep `_iso` (their recorded form)."""
    return _as_utc(dt).isoformat().replace("+00:00", "Z") if dt else None


def _row_copy(d: RegulatoryDeadline) -> dict:
    """Every stored column of a deadline, for the audit record of a delete."""
    return {c.name: (str(v) if isinstance(v, uuid.UUID) else _iso(v) if isinstance(v, datetime) else v)
            for c in RegulatoryDeadline.__table__.columns
            for v in [getattr(d, c.key)]}


def _reanchor(d: RegulatoryDeadline, anchor: datetime) -> dict:
    """Move a deadline to a new anchor, recompute its due time and re-arm its reminders.
    Returns the old → new values for the audit record."""
    tmpl = _TEMPLATES_BY_KEY.get(_key(d), {})
    old = {"old_anchor": _iso(d.breach_detected_at), "old_deadline_at": _iso(d.deadline_at)}
    d.breach_detected_at = _as_utc(anchor)
    d.deadline_at, d.deadline_hours = _window(anchor, d.deadline_hours, tmpl.get("deadline_months"))
    d.reminder_stage = 0
    return {**old, "new_anchor": _iso(d.breach_detected_at), "new_deadline_at": _iso(d.deadline_at)}


def _to_out(d: RegulatoryDeadline) -> dict:
    now = _now_utc()
    deadline_at = d.deadline_at.replace(tzinfo=timezone.utc) if d.deadline_at.tzinfo is None else d.deadline_at
    hours_left = (deadline_at - now).total_seconds() / 3600
    is_overdue = hours_left < 0 and d.status not in ("completed", "waived")
    tmpl = _TEMPLATES_BY_KEY.get(_key(d), {})
    return {
        "id":                 str(d.id),
        "incident_id":        str(d.incident_id),
        "regulation":         d.regulation,
        "article":            d.article,
        # Display form of `article` (e.g. NIS2 "Article 23(4)(a) — Early warning"); `article`
        # stays the stable template key.
        "article_label":      article_label(d.regulation, d.article, d.obligation),
        "obligation":         d.obligation,
        "recipient":          d.recipient,
        "deadline_hours":     d.deadline_hours,
        "breach_detected_at": _z(d.breach_detected_at),
        "deadline_at":        _z(d.deadline_at),
        "status":             d.status,
        "completed_at":       _z(d.completed_at),
        "completion_notes":   d.completion_notes,
        "is_mandatory":       d.is_mandatory,
        # Template flags: an internal planning target rather than a statutory deadline
        # (GDPR Art. 34), and a calendar-month window (NIS2 final report).
        "internal_target":    bool(tmpl.get("internal_target")),
        "deadline_months":    tmpl.get("deadline_months"),
        "notes":              d.notes,
        "hours_remaining":    round(hours_left, 2),
        "is_overdue":         is_overdue,
        "created_at":         _z(d.created_at),
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

    Each template lists its article (the stable key), article_label (how it is displayed:
    NIS2 rows show their Art. 23(4) point — (a) early warning, (b) incident notification,
    (d) final report), obligation, deadline window in hours, and whether it is mandatory.
    Static reference data; requires an authenticated user but no incident access.
    """
    return {
        reg: [
            {
                "article": t["article"],
                "article_label": t.get("label") or t["article"],
                "obligation": t["obligation"],
                "deadline_hours": t["deadline_hours"],
                "deadline_months": t.get("deadline_months"),
                "internal_target": bool(t.get("internal_target")),
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
    current UTC time, plus `internal_target` (an internal planning target, not a statutory
    deadline — GDPR Art. 34), `deadline_months` (calendar-month window — NIS2 final report) and
    `article_label` (the article as displayed; NIS2 rows show their Art. 23(4) point).
    Requires read access to the incident.
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
    # Default anchor for every regulation in this request; falls back to the incident's
    # detected_at when omitted. ISO 8601 (naive = UTC).
    breach_detected_at: Optional[datetime] = None
    # Per-regulation anchors, e.g. {"NIS2": "2026-10-01T08:00:00Z"}; win over the default.
    anchors: dict[str, datetime] = {}


@router.post("/{incident_id}/legal/deadlines/initialize", status_code=status.HTTP_201_CREATED,
             summary="Initialize deadlines from templates",
             responses={**_CLOSED_409, 422: {"model": ApiErrorBody, "description": "anchor_required or anchor_in_future"}})
async def initialize_deadlines(
    incident_id: uuid.UUID,
    body: InitBody,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Create regulatory deadlines for an incident by expanding the named regulation templates.

    Each regulation's anchor is `anchors[REG]`, else `breach_detected_at`, else the incident's
    `detected_at`; with none of these, 422 code anchor_required and nothing is created. An anchor
    later than now (2-minute clock-skew allowance) is 422 code anchor_in_future. Each
    template's `deadline_at` is its anchor plus its window (the NIS2 final report: one calendar
    month). Idempotent: a template row the incident already has (same regulation, article and
    obligation) is skipped, so re-initialising never duplicates. A closed incident returns 409
    code incident_closed. Requires the analyst role; audit-logged. Returns only the newly
    created deadlines (an empty list when everything already existed).
    """
    inc = await _get_incident(db, incident_id, user)
    _ensure_open(inc)

    anchors: dict[str, tuple[datetime, str]] = {}
    for reg in dict.fromkeys(body.regulations):
        if reg not in REGULATION_TEMPLATES:
            continue                      # unknown names create nothing (as before)
        if reg in body.anchors:
            anchors[reg] = (body.anchors[reg], "anchors")
        elif body.breach_detected_at is not None:
            anchors[reg] = (body.breach_detected_at, "breach_detected_at")
        elif inc.detected_at is not None:
            anchors[reg] = (inc.detected_at, "detected_at")
        else:
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "anchor_required",
                           f"No anchor for {reg}: the incident has no Detected time. "
                           f"Pass breach_detected_at or anchors.{reg}, or set the incident's detected_at.")
        _check_anchor(anchors[reg][0], f"The {reg} anchor")

    existing = set((await db.execute(
        select(RegulatoryDeadline.regulation, RegulatoryDeadline.article, RegulatoryDeadline.obligation)
        .where(RegulatoryDeadline.incident_id == incident_id)
    )).all())

    added, skipped = [], 0
    for reg, (anchor, _src) in anchors.items():
        for tmpl in REGULATION_TEMPLATES.get(reg, []):
            key = (reg, tmpl["article"], tmpl["obligation"])
            if key in existing:
                skipped += 1
                continue
            existing.add(key)
            deadline_at, hours = _window(anchor, tmpl["deadline_hours"], tmpl.get("deadline_months"))
            d = RegulatoryDeadline(
                incident_id=incident_id,
                regulation=reg,
                article=tmpl["article"],
                obligation=tmpl["obligation"],
                recipient=tmpl["recipient"],
                deadline_hours=hours,
                breach_detected_at=_as_utc(anchor),
                deadline_at=deadline_at,
                is_mandatory=tmpl["is_mandatory"],
                notes=tmpl["notes"],
                created_by_id=user.id,
            )
            db.add(d)
            added.append(d)

    await write_audit(db, "legal_initialize", user_id=user.id,
                      details={"incident_id": str(incident_id),
                               "regulations": body.regulations, "added": len(added), "skipped": skipped,
                               "anchors": {reg: {"at": _iso(_as_utc(a)), "source": src}
                                           for reg, (a, src) in anchors.items()}})
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
    # Anchor; defaults to the incident's detected_at. ISO 8601 (naive = UTC).
    breach_detected_at: Optional[datetime] = None
    is_mandatory: bool = True
    notes: Optional[str] = None


@router.post("/{incident_id}/legal/deadlines", status_code=status.HTTP_201_CREATED,
             summary="Create a regulatory deadline",
             responses={**_CLOSED_409, 422: {"model": ApiErrorBody, "description": "anchor_required or anchor_in_future"}})
async def create_deadline(
    incident_id: uuid.UUID,
    body: DeadlineCreate,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Create a single custom regulatory deadline for an incident.

    `deadline_at` = anchor + `deadline_hours`, where the anchor is `breach_detected_at` or, when
    omitted, the incident's `detected_at` (422 code anchor_required when neither is set; 422 code
    anchor_in_future when it is later than now, 2-minute skew allowance). A closed incident
    returns 409 code incident_closed. Requires the analyst role; audit-logged. Returns the
    created deadline.
    """
    inc = await _get_incident(db, incident_id, user)
    _ensure_open(inc)
    anchor = body.breach_detected_at or inc.detected_at
    if anchor is None:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "anchor_required",
                       "No anchor: the incident has no Detected time. Pass breach_detected_at "
                       "or set the incident's detected_at.")
    _check_anchor(anchor, "breach_detected_at")
    d = RegulatoryDeadline(
        incident_id=incident_id,
        regulation=body.regulation,
        article=body.article,
        obligation=body.obligation,
        recipient=body.recipient,
        deadline_hours=body.deadline_hours,
        breach_detected_at=_as_utc(anchor),
        deadline_at=_as_utc(anchor) + timedelta(hours=body.deadline_hours),
        is_mandatory=body.is_mandatory,
        notes=body.notes,
        created_by_id=user.id,
    )
    db.add(d)
    await write_audit(db, "legal_deadline_create", user_id=user.id,
                      details={"incident_id": str(incident_id), "regulation": body.regulation,
                               "anchor": _iso(_as_utc(anchor)),
                               "anchor_source": "breach_detected_at" if body.breach_detected_at else "detected_at"})
    await db.commit()
    await db.refresh(d)
    return _to_out(d)


class DeadlineUpdate(BaseModel):
    status: Optional[str] = None      # pending | in_progress | completed | waived
    # Required (10+ characters) when waiving: the waiver's justification.
    completion_notes: Optional[str] = None
    notes: Optional[str] = None
    # Re-anchor: a new anchor recomputes deadline_at; needs `reason` (10+ characters).
    breach_detected_at: Optional[datetime] = None
    reason: Optional[str] = None


@router.patch("/{incident_id}/legal/deadlines/{deadline_id}", summary="Update a regulatory deadline",
              responses={**_CLOSED_409,
                         422: {"model": ApiErrorBody,
                               "description": "notes_required, reason_required or anchor_in_future"}})
async def update_deadline(
    incident_id: uuid.UUID,
    deadline_id: uuid.UUID,
    body: DeadlineUpdate,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Update a regulatory deadline's status (pending/in_progress/completed/waived) or notes,
    or re-anchor it.

    - Waiving needs `completion_notes` of 10+ characters as the justification (422 code
      notes_required); a waived deadline's notes can't be blanked.
    - Re-anchor: `breach_detected_at` + `reason` (10+ characters, else 422 code reason_required)
      moves the anchor and recomputes `deadline_at`; audited with old and new values. A new
      anchor later than now (2-minute skew allowance) is 422 code anchor_in_future. A closed
      incident returns 409 code incident_closed for a re-anchor; status and notes updates stay
      allowed after closure.
    - Completing the NIS2 72h incident notification re-anchors the open NIS2 final report to
      that completion time + 1 calendar month (Art. 23(4)(d)), audited.
    - Completing stamps `completed_at`/`completed_by`; a status change to in_progress, completed
      or waived writes a system timeline event.

    Invalid status returns 422; a deadline not in this incident returns 404. Requires the
    analyst role; audit-logged. Returns the updated deadline.
    """
    inc = await _get_incident(db, incident_id, user)
    d = await _get_deadline(db, deadline_id)
    if d.incident_id != incident_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Deadline not found")

    reanchor_reason = None
    if body.breach_detected_at is not None:
        _ensure_open(inc)
        reanchor_reason = _reason(body.reason, "reason_required", "reason")
        _check_anchor(body.breach_detected_at, "breach_detected_at")

    valid_statuses = {"pending", "in_progress", "completed", "waived"}
    status_changed_to = None
    if body.status is not None:
        if body.status not in valid_statuses:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"status must be one of {sorted(valid_statuses)}")
        if body.status != d.status:
            status_changed_to = body.status
    if status_changed_to == "waived":
        _reason(body.completion_notes, "notes_required", "completion_notes (the waiver justification)")
    elif (body.status or d.status) == "waived" and body.completion_notes is not None:
        _reason(body.completion_notes, "notes_required", "completion_notes (the waiver justification)")

    if body.status is not None:
        d.status = body.status
        if body.status == "completed" and not d.completed_at:
            d.completed_at = _now_utc()
            d.completed_by_id = user.id
    if body.completion_notes is not None:
        d.completion_notes = body.completion_notes.strip() if d.status == "waived" else body.completion_notes
    if body.notes is not None:
        d.notes = body.notes

    await write_audit(db, "legal_deadline_update", user_id=user.id,
                      details={"incident_id": str(incident_id), "deadline_id": str(deadline_id),
                               "status": d.status})

    if reanchor_reason is not None:
        change = _reanchor(d, body.breach_detected_at)
        await write_audit(db, "legal_deadline_reanchor", user_id=user.id,
                          details={"incident_id": str(incident_id), "deadline_id": str(deadline_id),
                                   "regulation": d.regulation, "article": d.article,
                                   "reason": reanchor_reason, "auto": False, **change})

    # NIS2 Art. 23(4)(d): the final report is due one month after the incident notification.
    if status_changed_to == "completed" and _key(d) == _NIS2_NOTIFICATION and d.completed_at:
        finals = (await db.execute(
            select(RegulatoryDeadline).where(
                RegulatoryDeadline.incident_id == incident_id,
                RegulatoryDeadline.regulation == _NIS2_FINAL[0],
                RegulatoryDeadline.article == _NIS2_FINAL[1],
                RegulatoryDeadline.obligation == _NIS2_FINAL[2],
                RegulatoryDeadline.status.in_(_OPEN_STATUSES),
            )
        )).scalars().all()
        for f in finals:
            change = _reanchor(f, d.completed_at)
            await write_audit(db, "legal_deadline_reanchor", user_id=user.id,
                              details={"incident_id": str(incident_id), "deadline_id": str(f.id),
                                       "regulation": f.regulation, "article": f.article, "auto": True,
                                       "triggered_by": str(d.id),
                                       "reason": "NIS2 Art. 23(4)(d): final report due one month after "
                                                 "the incident notification, completed at "
                                                 + _iso(_as_utc(d.completed_at)),
                                       **change})

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


class DeadlineDelete(BaseModel):
    reason: Optional[str] = Field(default=None, description="Why the deadline is deleted (10–2000 characters).")


@router.delete("/{incident_id}/legal/deadlines/{deadline_id}", status_code=status.HTTP_204_NO_CONTENT,
               summary="Delete a regulatory deadline",
               responses={**_CLOSED_409, 422: {"model": ApiErrorBody, "description": "reason_required"}})
async def delete_deadline(
    incident_id: uuid.UUID,
    deadline_id: uuid.UUID,
    body: Optional[DeadlineDelete] = None,
    reason: Optional[str] = Query(None, deprecated=True,
                                  description="Fallback for older clients: send the reason in the JSON "
                                              "body instead (query strings land in access logs)."),
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Delete a regulatory deadline from an incident. A reason is required: JSON body
    `{"reason": "…"}` (10–2000 characters, else 422 code reason_required); `?reason=` is still
    accepted as a deprecated fallback, and the body wins when both are sent. The audit record
    keeps the reason and a full copy of the deleted row.

    Returns 404 if the deadline is not in this incident, 409 code incident_closed on a closed
    incident. Requires the analyst role. Returns 204 No Content.
    """
    inc = await _get_incident(db, incident_id, user)
    d = await _get_deadline(db, deadline_id)
    if d.incident_id != incident_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Deadline not found")
    _ensure_open(inc)
    why = _reason(body.reason if body is not None and body.reason is not None else reason,
                  "reason_required", "reason")
    await write_audit(db, "legal_deadline_delete", user_id=user.id,
                      details={"incident_id": str(incident_id), "deadline_id": str(deadline_id),
                               "regulation": d.regulation, "reason": why, "deleted": _row_copy(d)})
    await db.delete(d)
    await db.commit()
