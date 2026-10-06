"""Stakeholder notification tracker (I2, R22): the stakeholder matrix turned into per-incident
obligations with a countdown. NIST CSF 2.0 RS.CO-02 (internal and external stakeholders are
notified of incidents); NIST SP 800-61 R3 Respond — coordination and communication.

Clock (owner decision 2026-10-03): a matrix rule's countdown starts when the incident FIRST
reaches the rule's severity (`incident_severity_levels`). The initial severity is anchored at
the incident's awareness time, detected_at (else created_at); a later change at the time of
the change. Each newly reached level is audited (`incident_severity_reached`).

Matching: a rule applies when rule.severity == the incident's current severity (exactly, as
the matrix banner always matched) and its `incident_types` is empty or holds the incident's
type. `sync()` makes the obligations follow: a missing one is created (a snapshot of the rule,
due = level reached + the rule's SLA); one whose rule no longer matches is kept and marked
superseded; one that matches again is reactivated with its original due time. Called on
incident create, a severity or type change, and a matrix rule create / update / delete (for
every open incident). A closed incident is never re-synced. Each sync that changes something
writes one `stakeholder_notification_sync` audit row.

`summarize()` is what the snapshot, the list and (later, I5) the gate read. No FastAPI imports.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from models import (Incident, IncidentSeverityLevel, IncidentStakeholder, StakeholderMatrixRule,
                    StakeholderNotification, User, utcnow)
from schemas import SeverityLevelOut, StakeholderNotificationOut, StakeholderNotificationSummary

TRANSITIONS: dict[str, tuple[str, ...]] = {
    "pending":      ("notified", "not_required"),
    "notified":     ("pending",),
    "not_required": ("pending",),
}
TIME_SKEW = timedelta(minutes=2)   # as incidents.routes.DETECTED_AT_SKEW


def as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def iso_z(dt: Optional[datetime]) -> Optional[str]:
    return as_utc(dt).isoformat().replace("+00:00", "Z") if dt else None


def rule_matches(rule: StakeholderMatrixRule, severity: str, incident_type: Optional[str]) -> bool:
    types = rule.incident_types or []
    return rule.severity == severity and (not types or incident_type in types)


def is_overdue(o: StakeholderNotification, now: datetime) -> bool:
    return o.status == "pending" and o.superseded_at is None and as_utc(o.due_at) < now


async def record_level(db: AsyncSession, inc: Incident, *, at: datetime, source: str,
                       user_id=None, from_severity: Optional[str] = None) -> bool:
    """Store when `inc` first reached its current severity; audited. False if it was reached before."""
    known = (await db.execute(select(IncidentSeverityLevel.id).where(
        IncidentSeverityLevel.incident_id == inc.id, IncidentSeverityLevel.severity == inc.severity))).first()
    if known:
        return False
    db.add(IncidentSeverityLevel(incident_id=inc.id, severity=inc.severity, reached_at=at, source=source,
                                 recorded_by_id=user_id))
    await db.flush()
    await write_audit(
        db, "incident_severity_reached", outcome="success",
        resource_type="incident", resource_id=str(inc.id), resource_label=(inc.title or "")[:255],
        details={"ref": inc.ref, "severity": inc.severity, "reached_at": iso_z(at), "source": source,
                 "from_severity": from_severity},
    )
    return True


async def levels(db: AsyncSession, incident_id) -> list[IncidentSeverityLevel]:
    return list((await db.execute(
        select(IncidentSeverityLevel).where(IncidentSeverityLevel.incident_id == incident_id)
        .order_by(IncidentSeverityLevel.reached_at, IncidentSeverityLevel.severity)
    )).scalars().all())


def _supersede_reason(o: StakeholderNotification, rule: Optional[StakeholderMatrixRule], severity: str) -> str:
    if rule is None:
        return "rule_removed"
    if o.severity != severity:
        return "severity_changed"
    if rule.severity != o.severity:
        return "rule_changed"
    return "incident_type"


async def sync(db: AsyncSession, inc: Incident, *, cause: str, user_id=None) -> Optional[dict]:
    """Bring the incident's obligations in line with the matrix (see module doc). Returns the
    audited change summary, or None when nothing changed (or the incident is closed)."""
    if inc.status == "closed":
        return None
    # Serialise syncs of one incident (FOR NO KEY UPDATE on its row, held until commit).
    await db.execute(select(Incident.id).where(Incident.id == inc.id).with_for_update(key_share=True))
    now = utcnow()
    reached = {lv.severity: lv.reached_at for lv in await levels(db, inc.id)}
    if inc.severity not in reached:                 # defensive: every path records the level first
        await record_level(db, inc, at=now, source="change", user_id=user_id)
        reached[inc.severity] = now
    clock = as_utc(reached[inc.severity])
    rules = {r.id: r for r in (await db.execute(select(StakeholderMatrixRule))).scalars().all()}
    matching = {rid: r for rid, r in rules.items() if rule_matches(r, inc.severity, inc.incident_type)}
    obs = list((await db.execute(
        select(StakeholderNotification).where(StakeholderNotification.incident_id == inc.id)
        .with_for_update()
    )).scalars().all())
    have = {(o.rule_id, o.severity): o for o in obs if o.rule_id}

    created, superseded, reactivated = [], [], []
    for rid, r in matching.items():
        o = have.get((rid, r.severity))
        if o is None:
            o = StakeholderNotification(
                incident_id=inc.id, rule_id=rid, severity=r.severity, role=r.role, category=r.category,
                required=bool(r.required), notify_within_minutes=r.notify_within_minutes, clock_start_at=clock,
                due_at=clock + timedelta(minutes=r.notify_within_minutes), status="pending",
                created_at=now, updated_at=now)
            db.add(o)
            created.append(o)
        elif o.superseded_at is not None:
            o.superseded_at = o.superseded_reason = None
            reactivated.append(o)
    for o in obs:
        if o.superseded_at is not None or o in reactivated:
            continue
        r = matching.get(o.rule_id)
        if r is None or r.severity != o.severity:
            o.superseded_at = now
            o.superseded_reason = _supersede_reason(o, rules.get(o.rule_id), inc.severity)
            superseded.append(o)
    if not (created or superseded or reactivated):
        return None
    await db.flush()
    change = {
        "incident_id": str(inc.id), "ref": inc.ref, "cause": cause,
        "severity": inc.severity, "incident_type": inc.incident_type,
        "created": [{"id": str(o.id), "rule_id": str(o.rule_id), "role": o.role, "severity": o.severity,
                     "required": o.required, "due_at": iso_z(o.due_at)} for o in created],
        "superseded": [{"id": str(o.id), "role": o.role, "severity": o.severity, "reason": o.superseded_reason}
                       for o in superseded],
        "reactivated": [{"id": str(o.id), "role": o.role, "severity": o.severity} for o in reactivated],
    }
    await write_audit(
        db, "stakeholder_notification_sync", outcome="success", user_id=user_id,
        resource_type="incident", resource_id=str(inc.id), resource_label=(inc.title or "")[:255],
        details=change,
    )
    return change


async def sync_open_incidents(db: AsyncSession, *, cause: str, user_id=None) -> int:
    """sync() every open incident (after a matrix rule change). Returns how many changed."""
    incs = (await db.execute(select(Incident).where(Incident.status != "closed").order_by(Incident.id))).scalars().all()
    changed = 0
    for inc in incs:
        if await sync(db, inc, cause=cause, user_id=user_id):
            changed += 1
    return changed


async def obligations(db: AsyncSession, incident_id) -> list[StakeholderNotification]:
    """Active first, then by due time and role."""
    return list((await db.execute(
        select(StakeholderNotification).where(StakeholderNotification.incident_id == incident_id)
        .order_by(StakeholderNotification.superseded_at.is_not(None), StakeholderNotification.due_at,
                  StakeholderNotification.role, StakeholderNotification.id)
    )).scalars().all())


def summarize(obs: list[StakeholderNotification], now: Optional[datetime] = None) -> StakeholderNotificationSummary:
    now = now or utcnow()
    req = [o for o in obs if o.required and o.superseded_at is None]
    pending = [o for o in req if o.status == "pending"]
    return StakeholderNotificationSummary(
        required_total=sum(1 for o in req if o.status != "not_required"),
        notified=sum(1 for o in req if o.status == "notified"),
        overdue=sum(1 for o in pending if as_utc(o.due_at) < now),
        not_required=sum(1 for o in req if o.status == "not_required"),
        next_due_at=min((o.due_at for o in pending), default=None),
    )


async def rollup(db: AsyncSession, incident_id) -> StakeholderNotificationSummary:
    return summarize(await obligations(db, incident_id))


def levels_out(rows: list[IncidentSeverityLevel]) -> list[SeverityLevelOut]:
    return [SeverityLevelOut(severity=lv.severity, reached_at=lv.reached_at, source=lv.source) for lv in rows]


async def to_out(db: AsyncSession, obs: list[StakeholderNotification]) -> list[StakeholderNotificationOut]:
    now = utcnow()
    uids = {u for o in obs for u in (o.notified_by_id, o.updated_by_id) if u}
    names = dict((await db.execute(select(User.id, User.username).where(User.id.in_(uids)))).all()) if uids else {}
    sids = {o.stakeholder_id for o in obs if o.stakeholder_id}
    snames = dict((await db.execute(select(IncidentStakeholder.id, IncidentStakeholder.name)
                                    .where(IncidentStakeholder.id.in_(sids)))).all()) if sids else {}
    return [StakeholderNotificationOut(
        id=o.id, rule_id=o.rule_id, severity=o.severity, role=o.role, category=o.category, required=o.required,
        notify_within_minutes=o.notify_within_minutes, clock_start_at=o.clock_start_at, due_at=o.due_at,
        status=o.status, allowed_transitions=list(TRANSITIONS[o.status]), overdue=is_overdue(o, now),
        superseded=o.superseded_at is not None, superseded_at=o.superseded_at, superseded_reason=o.superseded_reason,
        notified_at=o.notified_at, notified_by_id=o.notified_by_id, notified_by_username=names.get(o.notified_by_id),
        channel=o.channel, oob_log_id=o.oob_log_id, stakeholder_id=o.stakeholder_id,
        stakeholder_name=snames.get(o.stakeholder_id), note=o.note, not_required_reason=o.not_required_reason,
        created_at=o.created_at, updated_at=o.updated_at, updated_by_username=names.get(o.updated_by_id),
    ) for o in obs]
