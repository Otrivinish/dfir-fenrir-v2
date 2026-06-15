"""Incident endpoints — list / create / get / update / close.

Standards alignment (per CLAUDE.md § Standards alignment):
- severity uses internal Low/Medium/High/Critical; NCISS values are derived
  at report time via a fixed mapping (critical→emergency, high→severe,
  medium→medium, low→low).
- phase    uses NIST SP 800-61 R3 phase names.
- tlp      uses TLP 2.0.
CSF 2.0 function tagging lives at the report level, not on individual incidents.
"""
import base64
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from core.tags import normalize_tags
from incidents.access import accessible_filter, get_accessible_incident
from models import (AffectedSystem, Entity, Evidence, IOC, Incident,
                    IncidentAssignment, PlaybookTask, TimelineEvent, User,
                    incident_teams, utcnow)
from notifications.service import notify_incident_created, notify_phase_changed
from schemas import (IncidentCreate, IncidentList, IncidentOut, IncidentSnapshot,
                     IncidentUpdate, IncidentState, Phase, Severity, Tlp)

router = APIRouter()


async def _fire_hooks(db, event: str, inc: Incident, extra_facts=None) -> None:
    """Dispatch outbound webhooks + email alert. Best-effort; never raises."""
    try:
        from outbound_webhooks.service import dispatch_incident_event
        await dispatch_incident_event(
            db, event,
            inc_title=inc.title, inc_ref=inc.ref,
            inc_severity=inc.severity, inc_phase=inc.phase,
            extra_facts=extra_facts,
        )
    except Exception:
        pass
    if event == "incident_created" and inc.severity in ("high", "critical"):
        try:
            from mailer.service import send_admin_alert
            await send_admin_alert(
                db,
                f"[FENRIR] New {inc.severity.upper()} incident: {inc.title}",
                f"Ref: {inc.ref}\nSeverity: {inc.severity}\nTitle: {inc.title}\n\n{inc.description or ''}",
            )
        except Exception:
            pass


# ─── Cursor helpers (opaque, offset-encoded for now) ─────────────────────────
# Cursor pagination per CLAUDE.md § API-first. Opaque to clients — clients
# never construct or mutate cursors, only echo them back.

def _encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"o": offset}).encode()).decode().rstrip("=")


def _decode_cursor(cursor: Optional[str]) -> int:
    if not cursor:
        return 0
    try:
        pad = "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(cursor + pad).decode())
        o = int(data.get("o", 0))
        return max(0, o)
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid cursor")


# ─── List ────────────────────────────────────────────────────────────────────

@router.get("", response_model=IncidentList, summary="List incidents")
async def list_incidents(
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
    status_filter: Optional[IncidentState] = Query(default=None, alias="status"),
    severity:      Optional[Severity]      = Query(default=None),
    phase:         Optional[Phase]         = Query(default=None),
    tlp:           Optional[Tlp]           = Query(default=None),
    tag:           Optional[str]           = Query(default=None,
                                                   description="Filter by tag (canonical lowercase-dashed)"),
    mine:          bool                    = Query(default=False),
    limit:         int                     = Query(default=50, ge=1, le=200),
    cursor:        Optional[str]           = Query(default=None),
) -> IncidentList:
    """List incidents the caller can access, newest first, with cursor pagination.

    Restricted to incidents visible to the caller via the team-based access
    filter (admins see all). Optional filters: status, severity, phase, tlp,
    tag (canonical lowercase-dashed), and mine (only incidents the caller
    created). Paginate with limit (1-200) and the opaque cursor. Returns
    {items, next_cursor}.
    """
    offset = _decode_cursor(cursor)

    stmt = select(Incident).order_by(Incident.created_at.desc(), Incident.id)
    stmt = stmt.where(accessible_filter(user))
    if status_filter: stmt = stmt.where(Incident.status       == status_filter)
    if severity:      stmt = stmt.where(Incident.severity     == severity)
    if phase:         stmt = stmt.where(Incident.phase        == phase)
    if tlp:           stmt = stmt.where(Incident.tlp          == tlp)
    if mine:          stmt = stmt.where(Incident.created_by_id == user.id)
    if tag:
        # tags is a JSON list — case-folded match against the canonical form.
        # Cast to text and ILIKE keeps things index-free but readable; tag
        # volume is small per row.
        from core.tags import normalize_tag
        canonical = normalize_tag(tag)
        if canonical:
            stmt = stmt.where(
                func.cast(Incident.tags, type_=None).ilike(f'%"{canonical}"%')
            )

    # Fetch limit+1 to determine if there's a next page.
    stmt = stmt.offset(offset).limit(limit + 1)
    rows = (await db.execute(stmt)).scalars().all()

    has_more = len(rows) > limit
    items = [IncidentOut.model_validate(r) for r in rows[:limit]]
    next_cursor = _encode_cursor(offset + limit) if has_more else None
    return IncidentList(items=items, next_cursor=next_cursor)


# ─── Create ──────────────────────────────────────────────────────────────────

@router.post("", response_model=IncidentOut, status_code=status.HTTP_201_CREATED)
async def create_incident(
    req: IncidentCreate, request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> IncidentOut:
    inc_num = (await db.execute(text("SELECT nextval('incident_seq')"))).scalar()
    inc = Incident(
        id=uuid.uuid4(),
        incident_number=inc_num,
        title=req.title,
        description=req.description,
        severity=req.severity,
        phase=req.phase,
        tlp=req.tlp,
        triage_state=req.triage_state,
        incident_type=req.incident_type,
        detection_method=req.detection_method,
        reporter=req.reporter,
        created_by_id=user.id,
        occurred_at=req.occurred_at,
        tags=normalize_tags(req.tags),
    )
    db.add(inc)
    await db.flush()

    if req.team_ids and user.role == "admin":
        for team_id in req.team_ids:
            await db.execute(
                incident_teams.insert().values(incident_id=inc.id, team_id=team_id)
            )

    await write_audit(
        db, "incident_create",
        outcome="success",
        resource_type="incident", resource_id=str(inc.id), resource_label=inc.title,
        details={"severity": inc.severity, "phase": inc.phase, "tlp": inc.tlp},
    )
    await db.commit()
    await db.refresh(inc)
    await _fire_hooks(db, "incident_created", inc)
    await notify_incident_created(db, user.id, inc.id, inc.title)
    return IncidentOut.model_validate(inc)


# ─── Read one ────────────────────────────────────────────────────────────────

@router.get("/{incident_id}", response_model=IncidentOut)
async def get_incident(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> IncidentOut:
    inc = await get_accessible_incident(db, incident_id, user)
    return IncidentOut.model_validate(inc)


# ─── Snapshot (at-a-glance counts for the Details landing tab) ──────────────

@router.get("/{incident_id}/snapshot", response_model=IncidentSnapshot)
async def get_incident_snapshot(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> IncidentSnapshot:
    # Access check via the standard helper; raises 404 on no-access.
    await get_accessible_incident(db, incident_id, user)

    async def _count(model) -> int:
        stmt = select(func.count()).select_from(model).where(model.incident_id == incident_id)
        return int((await db.execute(stmt)).scalar() or 0)

    iocs             = await _count(IOC)
    entities         = await _count(Entity)
    evidence         = await _count(Evidence)
    timeline         = await _count(TimelineEvent)
    affected_systems = await _count(AffectedSystem)
    assignments      = await _count(IncidentAssignment)

    # Playbook: group by status in a single round-trip.
    pb_stmt = (
        select(PlaybookTask.status, func.count())
        .where(PlaybookTask.incident_id == incident_id)
        .group_by(PlaybookTask.status)
    )
    pb_rows = (await db.execute(pb_stmt)).all()
    by_status = {row[0]: int(row[1]) for row in pb_rows}
    pb_done    = by_status.get("done", 0)
    pb_skipped = by_status.get("skipped", 0)
    pb_total   = sum(by_status.values()) - pb_skipped   # matches sidebar widget convention

    return IncidentSnapshot(
        iocs=iocs, entities=entities, evidence=evidence, timeline=timeline,
        affected_systems=affected_systems, assignments=assignments,
        playbook_total=pb_total, playbook_done=pb_done, playbook_skipped=pb_skipped,
    )


# ─── Update ──────────────────────────────────────────────────────────────────

@router.patch("/{incident_id}", response_model=IncidentOut)
async def update_incident(
    incident_id: uuid.UUID, req: IncidentUpdate, request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> IncidentOut:
    inc = await get_accessible_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    changed: dict[str, object] = {}
    for field in ("title", "description", "severity", "phase", "tlp", "triage_state", "incident_type", "detection_method", "reporter"):
        new = getattr(req, field)
        if new is not None and new != getattr(inc, field):
            setattr(inc, field, new)
            changed[field] = new

    # Datetime fields: use model_fields_set to allow explicit null-set (clearing).
    for field in ("occurred_at", "contained_at"):
        if field in req.model_fields_set:
            val = getattr(req, field)
            setattr(inc, field, val)
            changed[field] = val.isoformat() if val else None

    # Auto-set contained_at on CER phase transition if not already set
    # and not explicitly overridden in this request.
    if (
        "phase" in changed
        and changed["phase"] == "containment_eradication_recovery"
        and "contained_at" not in req.model_fields_set
        and inc.contained_at is None
    ):
        ts = utcnow().replace(microsecond=0)   # truncate µs: UI can only set minute precision
        inc.contained_at = ts
        changed["contained_at"] = ts.isoformat()

    # Team assignment — admin-only: replace the full list when explicitly provided.
    if "team_ids" in req.model_fields_set and user.role == "admin":
        await db.execute(
            incident_teams.delete().where(incident_teams.c.incident_id == incident_id)
        )
        for team_id in (req.team_ids or []):
            await db.execute(
                incident_teams.insert().values(incident_id=inc.id, team_id=team_id)
            )
        changed["team_ids"] = [str(t) for t in (req.team_ids or [])]

    # Tags — replace the full list when explicitly provided. Normalise at the
    # boundary so storage stays in canonical lowercase-dashed form.
    if "tags" in req.model_fields_set:
        inc.tags = normalize_tags(req.tags)
        changed["tags"] = inc.tags

    if changed:
        await write_audit(
            db, "incident_update",
            outcome="success",
            resource_type="incident", resource_id=str(inc.id), resource_label=inc.title,
            details={"changes": changed},
        )
    await db.commit()
    await db.refresh(inc)
    if "phase" in changed:
        await _fire_hooks(db, "phase_changed", inc,
                          extra_facts=[{"name": "New Phase", "value": inc.phase.replace("_", " ").title()}])
        await notify_phase_changed(
            db, user.id, inc.id,
            inc.ref or str(inc.id), inc.title, inc.phase,
        )
    elif "severity" in changed:
        await _fire_hooks(db, "severity_changed", inc,
                          extra_facts=[{"name": "New Severity", "value": inc.severity.title()}])
    return IncidentOut.model_validate(inc)


# ─── Close ───────────────────────────────────────────────────────────────────

@router.post("/{incident_id}/close", response_model=IncidentOut)
async def close_incident(
    incident_id: uuid.UUID, request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> IncidentOut:
    inc = await get_accessible_incident(db, incident_id, user)
    if inc.status == "closed":
        return IncidentOut.model_validate(inc)

    inc.status = "closed"
    inc.closed_at = utcnow()
    inc.phase = "post_incident"

    await write_audit(
        db, "incident_close",
        outcome="success",
        resource_type="incident", resource_id=str(inc.id), resource_label=inc.title,
    )
    await db.commit()
    await db.refresh(inc)
    await _fire_hooks(db, "incident_resolved", inc)
    return IncidentOut.model_validate(inc)


# ─── Reopen ──────────────────────────────────────────────────────────────────

@router.post("/{incident_id}/reopen", response_model=IncidentOut)
async def reopen_incident(
    incident_id: uuid.UUID, request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> IncidentOut:
    inc = await get_accessible_incident(db, incident_id, user)
    if inc.status == "open":
        return IncidentOut.model_validate(inc)

    inc.status = "open"
    inc.closed_at = None
    inc.phase = "containment_eradication_recovery"

    await write_audit(
        db, "incident_reopen",
        outcome="success",
        resource_type="incident", resource_id=str(inc.id), resource_label=inc.title,
    )
    await db.commit()
    await db.refresh(inc)
    return IncidentOut.model_validate(inc)
