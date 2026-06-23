"""Per-incident timeline event CRUD.

Mounted at prefix="/api/incidents".
Ordered by event_time ASC (oldest event first) — forensic chronological order.
"""
import base64
import json
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
import lolbins.service as lolbins_svc
from incidents.access import get_accessible_incident
from models import Incident, TimelineEvent, User
from schemas import (
    TimelineEventBatchCreate,
    TimelineEventBatchResult,
    TimelineEventCreate,
    TimelineEventList,
    TimelineEventOut,
    TimelineEventUpdate,
)

router = APIRouter()


def _encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"o": offset}).encode()).decode().rstrip("=")


def _decode_cursor(cursor: Optional[str]) -> int:
    if not cursor:
        return 0
    try:
        pad = "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(cursor + pad).decode())
        return max(0, int(data.get("o", 0)))
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid cursor")


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


async def _username_map(db: AsyncSession, user_ids) -> dict[uuid.UUID, str]:
    """Resolve {user_id: username} for a set of author ids (skips None/missing)."""
    ids = {i for i in user_ids if i}
    if not ids:
        return {}
    rows = (await db.execute(select(User.id, User.username).where(User.id.in_(ids)))).all()
    return {uid: uname for uid, uname in rows}


# ─── List ─────────────────────────────────────────────────────────────────────

@router.get("/{incident_id}/timeline", response_model=TimelineEventList, summary="List timeline events")
async def list_timeline_events(
    incident_id:    uuid.UUID,
    user:           User         = Depends(current_user),
    db:             AsyncSession = Depends(get_db),
    limit:          int          = Query(default=200, ge=1, le=500),
    cursor:         Optional[str]= Query(default=None),
    include_system: bool         = Query(default=True),
) -> TimelineEventList:
    """List an incident's timeline events in forensic chronological order (event_time ASC).

    Cursor-paginated via `limit` and opaque `cursor`. Set `include_system=False` to omit
    system-generated events; the response then carries `system_event_count` for those hidden.
    Requires read access to the incident. Returns a paginated TimelineEventList.
    """
    await _get_incident(db, incident_id, user)
    offset = _decode_cursor(cursor)

    stmt = (
        select(TimelineEvent)
        .where(TimelineEvent.incident_id == incident_id)
        .order_by(TimelineEvent.event_time, TimelineEvent.created_at)
    )
    if not include_system:
        stmt = stmt.where(TimelineEvent.is_system == False)  # noqa: E712

    rows = (await db.execute(stmt.offset(offset).limit(limit + 1))).scalars().all()

    has_more    = len(rows) > limit
    page        = rows[:limit]
    umap        = await _username_map(db, [r.created_by_id for r in page])
    for r in page:
        r.created_by_username = umap.get(r.created_by_id)
    items       = [TimelineEventOut.model_validate(r) for r in page]
    next_cursor = _encode_cursor(offset + limit) if has_more else None

    system_count = 0
    if not include_system:
        system_count = (await db.execute(
            select(func.count()).where(
                TimelineEvent.incident_id == incident_id,
                TimelineEvent.is_system == True,  # noqa: E712
            )
        )).scalar_one()

    return TimelineEventList(items=items, next_cursor=next_cursor, system_event_count=system_count)


# ─── Create ───────────────────────────────────────────────────────────────────

@router.post("/{incident_id}/timeline",
             response_model=TimelineEventOut,
             status_code=status.HTTP_201_CREATED,
             summary="Create a timeline event")
async def create_timeline_event(
    incident_id: uuid.UUID,
    req: TimelineEventCreate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> TimelineEventOut:
    """Add a single timeline event to an incident, capturing time, host, source and MITRE mapping.

    Rejects events on a closed incident with 409. Requires the analyst role and write access to
    the incident; the action is audit-logged. Returns the created TimelineEventOut.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    ev = TimelineEvent(
        id=uuid.uuid4(),
        incident_id=incident_id,
        event_time=req.event_time,
        hostname=req.hostname,
        source=req.source,
        event_type=req.event_type,
        description=req.description.strip(),
        raw_log=req.raw_log,
        ir_phase=req.ir_phase,
        mitre_tactic_id=req.mitre_tactic_id,
        mitre_tactic_name=req.mitre_tactic_name,
        mitre_technique_id=req.mitre_technique_id,
        mitre_technique_name=req.mitre_technique_name,
        origin="system" if req.is_system else "manual",
        is_system=req.is_system,
        system_source=req.system_source if req.is_system else None,
        external_safe=not req.is_system,
        created_by_id=user.id,
    )
    db.add(ev)
    await db.flush()

    await write_audit(
        db, "timeline_event_create",
        user_id=user.id, username=user.username,
        resource_type="timeline_event", resource_id=str(ev.id),
        details={
            "incident_id": str(incident_id),
            "event_time": ev.event_time.isoformat(),
            "mitre_technique_id": ev.mitre_technique_id,
            "description": ev.description[:120],
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    ev.created_by_username = user.username
    return TimelineEventOut.model_validate(ev)


# ─── Update ───────────────────────────────────────────────────────────────────

@router.patch("/{incident_id}/timeline/{event_id}", response_model=TimelineEventOut,
              summary="Update a timeline event")
async def update_timeline_event(
    incident_id: uuid.UUID,
    event_id:    uuid.UUID,
    req: TimelineEventUpdate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> TimelineEventOut:
    """Partially update fields of an existing timeline event (time, host, source, MITRE, etc.).

    Only changed fields are applied and audit-logged. Rejects edits on a closed incident with 409
    and returns 404 if the event is not in this incident. Requires the analyst role and write
    access. Returns the updated TimelineEventOut.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    ev = (await db.execute(
        select(TimelineEvent).where(
            TimelineEvent.id == event_id,
            TimelineEvent.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not ev:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Event not found")

    changed: dict[str, object] = {}
    if req.event_time           is not None and req.event_time != ev.event_time:
        ev.event_time = req.event_time;                          changed["event_time"] = True
    if req.hostname             is not None and req.hostname != (ev.hostname or ""):
        ev.hostname = req.hostname;                              changed["hostname"] = req.hostname
    if req.source               is not None and req.source != (ev.source or ""):
        ev.source = req.source;                                  changed["source"] = req.source
    if req.event_type           is not None and req.event_type != (ev.event_type or ""):
        ev.event_type = req.event_type;                          changed["event_type"] = req.event_type
    if req.description          is not None and req.description.strip() != ev.description:
        ev.description = req.description.strip();                changed["description"] = True
    if req.raw_log              is not None and req.raw_log != (ev.raw_log or ""):
        ev.raw_log = req.raw_log;                                changed["raw_log"] = True
    if req.ir_phase             is not None and req.ir_phase != ev.ir_phase:
        ev.ir_phase = req.ir_phase;                              changed["ir_phase"] = req.ir_phase
    if req.mitre_tactic_id      is not None and req.mitre_tactic_id != (ev.mitre_tactic_id or ""):
        ev.mitre_tactic_id = req.mitre_tactic_id;               changed["mitre_tactic_id"] = req.mitre_tactic_id
    if req.mitre_tactic_name    is not None and req.mitre_tactic_name != (ev.mitre_tactic_name or ""):
        ev.mitre_tactic_name = req.mitre_tactic_name;           changed["mitre_tactic_name"] = req.mitre_tactic_name
    if req.mitre_technique_id   is not None and req.mitre_technique_id != (ev.mitre_technique_id or ""):
        ev.mitre_technique_id = req.mitre_technique_id;         changed["mitre_technique_id"] = req.mitre_technique_id
    if req.mitre_technique_name is not None and req.mitre_technique_name != (ev.mitre_technique_name or ""):
        ev.mitre_technique_name = req.mitre_technique_name;     changed["mitre_technique_name"] = req.mitre_technique_name

    if changed:
        await write_audit(
            db, "timeline_event_update",
            user_id=user.id, username=user.username,
            resource_type="timeline_event", resource_id=str(ev.id),
            details={"incident_id": str(incident_id), "changes": changed},
            ip_address=request.client.host if request.client else None,
        )
    await db.commit()
    umap = await _username_map(db, [ev.created_by_id])
    ev.created_by_username = umap.get(ev.created_by_id)
    return TimelineEventOut.model_validate(ev)


# ─── Batch create (forensic import) ──────────────────────────────────────────

@router.post("/{incident_id}/timeline/batch",
             response_model=TimelineEventBatchResult,
             status_code=status.HTTP_201_CREATED,
             summary="Batch import timeline events")
async def batch_create_timeline_events(
    incident_id: uuid.UUID,
    req: TimelineEventBatchCreate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> TimelineEventBatchResult:
    """Bulk-create many timeline events from a forensic import in one request.

    Each event is inserted independently; per-item failures are collected rather than aborting the
    batch. Rejects imports on a closed incident with 409. Requires the analyst role and write
    access; the import is audit-logged. Returns a TimelineEventBatchResult with the created count
    and any errors.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    created = 0
    errors: list[str] = []

    for i, item in enumerate(req.events):
        try:
            ev = TimelineEvent(
                id=uuid.uuid4(),
                incident_id=incident_id,
                event_time=item.event_time,
                hostname=item.hostname,
                source=item.source,
                event_type=item.event_type,
                description=item.description.strip(),
                raw_log=item.raw_log,
                ir_phase=item.ir_phase,
                mitre_tactic_id=item.mitre_tactic_id,
                mitre_tactic_name=item.mitre_tactic_name,
                mitre_technique_id=item.mitre_technique_id,
                mitre_technique_name=item.mitre_technique_name,
                origin="forensic_import",
                created_by_id=user.id,
            )
            db.add(ev)
            await db.flush()
            created += 1
        except Exception as exc:
            errors.append(f"[{i}] {exc}")

    await write_audit(
        db, "timeline_batch_import",
        user_id=user.id, username=user.username,
        resource_type="timeline_event", resource_id=str(incident_id),
        details={
            "incident_id": str(incident_id),
            "created": created,
            "errors": len(errors),
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return TimelineEventBatchResult(created=created, errors=errors)


# ─── LOLBin correlation scan ──────────────────────────────────────────────────
# Literal sub-path registered before /{event_id} parametric routes.

@router.get("/{incident_id}/timeline/lolbin-scan", summary="Scan timeline for LOLBins")
async def lolbin_scan_timeline(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Scan all timeline events for LOLBin/GTFOBin mentions in description + raw_log.

    Returns {hits, cache_empty}. Hits are only events that matched ≥1 entry.
    If the LOLBins cache is cold, returns cache_empty=True and an empty hits list.
    """
    await _get_incident(db, incident_id, user)

    if not lolbins_svc.status()["synced"]:
        # Block on the first call until the cache is warm so the first lolbin
        # render isn't empty. Subsequent calls find the cache already loaded.
        await lolbins_svc.ensure_loaded()
        if not lolbins_svc.status()["synced"]:
            # Sync failed (e.g. offline). Soft-fail so the timeline still loads.
            return {"hits": [], "cache_empty": True}

    rows = (await db.execute(
        select(TimelineEvent)
        .where(TimelineEvent.incident_id == incident_id)
        .order_by(TimelineEvent.event_time.asc())
    )).scalars().all()

    hits = []
    for ev in rows:
        text = (ev.description or "") + " " + (ev.raw_log or "")
        matches = lolbins_svc.lookup_in_text(text)
        if matches:
            hits.append({
                "event_id":    str(ev.id),
                "event_time":  ev.event_time.isoformat() if ev.event_time else None,
                "hostname":    ev.hostname,
                "event_type":  ev.event_type,
                "description": (ev.description or "")[:200],
                "matches":     matches,
            })

    return {"hits": hits, "cache_empty": False}


# ─── Delete ───────────────────────────────────────────────────────────────────

@router.delete("/{incident_id}/timeline/{event_id}", summary="Delete a timeline event")
async def delete_timeline_event(
    incident_id: uuid.UUID,
    event_id:    uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Permanently delete a timeline event from an incident.

    Rejects deletion on a closed incident with 409 and returns 404 if the event is not in this
    incident. Requires the analyst role and write access; the deletion is audit-logged. Returns
    `{"status": "ok"}`.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    ev = (await db.execute(
        select(TimelineEvent).where(
            TimelineEvent.id == event_id,
            TimelineEvent.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not ev:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Event not found")

    await write_audit(
        db, "timeline_event_delete",
        user_id=user.id, username=user.username,
        resource_type="timeline_event", resource_id=str(ev.id),
        details={
            "incident_id": str(incident_id),
            "description": ev.description[:120],
            "mitre_technique_id": ev.mitre_technique_id,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(ev)
    await db.commit()
    return {"status": "ok"}
