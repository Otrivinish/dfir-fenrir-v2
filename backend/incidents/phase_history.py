"""K2 (R38) — time in phase, read from the incident's append-only audit rows (GS-8: they can't be rewritten).

incident_create gives the opening phase (the period starts at the incident's created_at); an
incident_update whose changes include "phase" enters that phase; incident_close ends the current period;
incident_reopen starts a new one in its details.phase. Moving back to a phase starts a new period.
"""
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import AuditLog, Incident
from schemas import IncidentPhaseHistory, PhasePeriod, PhaseTotal

UTC = timezone.utc
PHASE_ORDER = ("preparation", "detection_and_analysis", "containment_eradication_recovery", "post_incident")
_ACTIONS = ("incident_create", "incident_update", "incident_close", "incident_reopen")


def _utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _end(p: PhasePeriod, at: datetime, how: str) -> None:
    p.left_at = max(at, p.entered_at)
    p.duration_seconds = int((p.left_at - p.entered_at).total_seconds())
    p.ended_by = how


async def phase_history(db: AsyncSession, inc: Incident) -> IncidentPhaseHistory:
    rows = (await db.execute(
        select(AuditLog.timestamp, AuditLog.action, AuditLog.details, AuditLog.outcome)
        .where(AuditLog.resource_type == "incident", AuditLog.resource_id == str(inc.id),
               AuditLog.action.in_(_ACTIONS))
        .order_by(AuditLog.timestamp)
    )).all()

    opening, steps = None, []          # steps: (at, kind enter|close|reopen, phase, from_phase)
    for ts, action, details, outcome in rows:
        if outcome not in (None, "success"):
            continue
        d = details if isinstance(details, dict) else {}
        if action == "incident_create":
            opening = d.get("phase") or opening
        elif action == "incident_update" and "phase" in (d.get("changes") or {}):
            steps.append((_utc(ts), "enter", d["changes"]["phase"], d.get("from_phase")))
        elif action == "incident_close":
            steps.append((_utc(ts), "close", None, None))
        elif action == "incident_reopen":
            steps.append((_utc(ts), "reopen", d.get("phase"), d.get("from_phase")))
    if opening is None:                # no create row (seeded / pre-audit incidents): infer it
        opening = next((s[3] for s in steps if s[3]), None) or inc.phase

    periods = [PhasePeriod(phase=opening, entered_at=_utc(inc.created_at))]
    is_open = True
    for at, kind, phase, _ in steps:
        last = periods[-1]
        if kind == "close":
            if is_open:
                _end(last, at, "close")
                is_open = False
            continue
        if is_open:
            _end(last, at, "phase_change")
        periods.append(PhasePeriod(phase=phase or last.phase, entered_at=max(at, last.entered_at)))
        is_open = True

    # The row is the truth for "now": a phase or status reached without an audit row still shows.
    if is_open and periods[-1].phase != inc.phase:
        _end(periods[-1], _utc(inc.updated_at), "phase_change")
        periods.append(PhasePeriod(phase=inc.phase, entered_at=periods[-1].left_at))
    if is_open and inc.status == "closed":
        _end(periods[-1], _utc(inc.closed_at or inc.updated_at), "close")
        is_open = False

    totals: dict[str, list[int]] = {}
    for p in periods:
        if p.duration_seconds is not None:
            totals.setdefault(p.phase, []).append(p.duration_seconds)
    completed = [PhaseTotal(phase=ph, seconds=sum(totals[ph]), periods=len(totals[ph]))
                 for ph in PHASE_ORDER if ph in totals]
    return IncidentPhaseHistory(phase=inc.phase, entered_at=periods[-1].entered_at, closed=not is_open,
                                periods=periods, completed=completed)
