"""Recovery tracker (I1, R21): per-system restore and validation in NIST SP 800-61 R3 Containment,
Eradication & Recovery — CSF 2.0 RC.RP-02 (recovery actions performed), RC.RP-03 (restoration
assets checked before use: the restore point), RC.RP-05 (restored assets verified, normal
operation confirmed: validation and the monitoring window).

In scope = the incident's compromised entities of a system type (the C2 scope list). A system has
no record until its first write (state not_started). A record whose entity leaves scope (flag
cleared, type changed) is kept, but is no longer listed or counted.

`rollup()` is what the snapshot, the recovery list and (later) Gate 1 read. No FastAPI imports.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import Entity, Incident, RecoveryRecord, User, utcnow
from schemas import RecoveryChecklistItem, RecoverySummary, RecoverySystemOut

SYSTEM_TYPES = ("host", "service", "network_range")
STATES = ("not_started", "restoring", "restored", "validated", "not_required")
TRANSITIONS: dict[str, tuple[str, ...]] = {
    "not_started":  ("restoring", "not_required"),
    "restoring":    ("restored", "not_started"),
    "restored":     ("validated", "restoring"),
    "validated":    ("restoring",),
    "not_required": ("not_started",),
}
# Going back a step needs a reason and clears the sign-offs after it.
BACKWARD = {("restoring", "not_started"), ("restored", "restoring"), ("validated", "restoring"),
            ("not_required", "not_started")}
DONE_STATES = ("validated", "not_required")
TIME_SKEW = timedelta(minutes=2)   # as incidents.routes.DETECTED_AT_SKEW


def as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def in_scope(incident_id) -> tuple:
    return (Entity.incident_id == incident_id, Entity.compromised.is_(True), Entity.type.in_(SYSTEM_TYPES))


def is_in_scope(ent: Entity) -> bool:
    return bool(ent.compromised) and ent.type in SYSTEM_TYPES


async def scope_rows(db: AsyncSession, incident_id) -> list[tuple[Entity, Optional[RecoveryRecord]]]:
    """Every in-scope system with its record (or None), ordered by type, value."""
    return [tuple(r) for r in (await db.execute(
        select(Entity, RecoveryRecord)
        .outerjoin(RecoveryRecord, RecoveryRecord.entity_id == Entity.id)
        .where(*in_scope(incident_id))
        .order_by(Entity.type, Entity.value, Entity.id)
    )).all()]


def same_person(rec: Optional[RecoveryRecord]) -> bool:
    return bool(rec and rec.validated_by_id and rec.validated_by_id == rec.restored_by_id)


async def to_out(db: AsyncSession, rows: list[tuple[Entity, Optional[RecoveryRecord]]]) -> list[RecoverySystemOut]:
    ids = {uid for _, r in rows if r for uid in (r.restored_by_id, r.validated_by_id, r.updated_by_id) if uid}
    names = dict((await db.execute(select(User.id, User.username).where(User.id.in_(ids)))).all()) if ids else {}
    out = []
    for ent, rec in rows:
        state = rec.state if rec else "not_started"
        base = dict(entity_id=ent.id, entity_type=ent.type, entity_value=ent.value, entity_name=ent.name,
                    criticality=ent.criticality, state=state, allowed_transitions=list(TRANSITIONS[state]))
        if rec:
            base.update(
                record_id=rec.id, not_required_reason=rec.not_required_reason,
                restore_point_ref=rec.restore_point_ref, restore_point_at=rec.restore_point_at,
                restored_at=rec.restored_at, restored_by_id=rec.restored_by_id,
                restored_by_username=names.get(rec.restored_by_id),
                validation_method=rec.validation_method,
                validation_checklist=[RecoveryChecklistItem(**i) for i in (rec.validation_checklist or [])],
                validated_at=rec.validated_at, validated_by_id=rec.validated_by_id,
                validated_by_username=names.get(rec.validated_by_id),
                same_person_validation=same_person(rec),
                monitoring_start=rec.monitoring_start, monitoring_end=rec.monitoring_end, notes=rec.notes,
                updated_at=rec.updated_at, updated_by_username=names.get(rec.updated_by_id))
        out.append(RecoverySystemOut(**base))
    return out


def summarize(inc: Incident, rows: list[tuple[Entity, Optional[RecoveryRecord]]]) -> RecoverySummary:
    counts = dict.fromkeys(STATES, 0)
    for _, rec in rows:
        counts[rec.state if rec else "not_started"] += 1
    total = len(rows)
    complete = total > 0 and counts["validated"] + counts["not_required"] == total
    now = utcnow()
    return RecoverySummary(
        total=total, **counts, complete=complete,
        same_person_validations=sum(1 for _, r in rows if r and r.state == "validated" and same_person(r)),
        monitoring_started=sum(1 for _, r in rows if r and r.monitoring_start and as_utc(r.monitoring_start) <= now),
        can_declare_recovered=complete and inc.recovered_at is None and inc.status != "closed",
    )


async def rollup(db: AsyncSession, inc: Incident) -> RecoverySummary:
    return summarize(inc, await scope_rows(db, inc.id))
