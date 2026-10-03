"""Per-incident timeline event CRUD.

Mounted at prefix="/api/incidents".
Ordered by event_time ASC (oldest event first) — forensic chronological order;
`?sort=-event_time` lists newest first.
"""
import base64
import json
import uuid
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
import lolbins.service as lolbins_svc
from incidents.access import get_accessible_incident
from models import Entity, Evidence, ForensicImport, Incident, TimelineEvent, User
from schemas import (
    TimelineEventBatchCreate,
    TimelineEventBatchResult,
    TimelineEventCreate,
    TimelineEventList,
    TimelineEventOut,
    TimelineEventUpdate,
)

router = APIRouter()


def _encode_cursor(offset: int, desc: bool = False) -> str:
    data = {"o": offset, "d": 1} if desc else {"o": offset}
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def _decode_cursor(cursor: Optional[str], desc: bool = False) -> int:
    """Offset from a cursor. A cursor carries its sort direction ("d"), so one from the other
    direction is rejected instead of silently paging the wrong order."""
    if not cursor:
        return 0
    try:
        pad = "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(cursor + pad).decode())
        offset = max(0, int(data.get("o", 0)))
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid cursor")
    if bool(data.get("d")) != desc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid cursor: it belongs to the other sort order")
    return offset


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


# system_source values only the server writes (M2): closure, gate_override, milestone and triage
# (incidents/routes.py), respond_action, respond_action_revert and decision (respond/routes.py),
# legal_deadline (legal/routes.py). A client-made event may not claim one, so an analyst's event can
# never pass for the server's record. Compared trimmed and case-insensitively. "manual" (the Timeline
# "Annotate" modal) and any other label stay allowed. Add a new server source here too.
RESERVED_SYSTEM_SOURCES = frozenset({
    "closure", "gate_override", "milestone", "triage",
    "respond_action", "respond_action_revert", "decision", "legal_deadline",
})

_ENTITY_ERRORS = {404: {"model": ApiErrorBody, "description": "entity_not_found"},
                  409: {"model": ApiErrorBody, "description": "incident_closed"},
                  422: {"model": ApiErrorBody, "description": "entity_other_incident (or a validation error)"}}


async def _entity(db: AsyncSession, incident_id: uuid.UUID, entity_id: uuid.UUID) -> Entity:
    """The entity an event happened on: 404 if unknown, 422 if it is another incident's."""
    ent = await db.get(Entity, entity_id)
    if ent is None:
        raise ApiError(status.HTTP_404_NOT_FOUND, "entity_not_found", "Entity not found")
    if ent.incident_id != incident_id:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "entity_other_incident",
                       "Entity belongs to another incident; pick one from this incident")
    return ent


async def _resolve_provenance(db: AsyncSession, events) -> None:
    """C5 — set the read-only evidence_identifier / parser_version of imported events (2 queries)."""
    ev_ids  = {e.evidence_id for e in events if e.evidence_id}
    imp_ids = {e.forensic_import_id for e in events if e.forensic_import_id}
    idents = dict((await db.execute(
        select(Evidence.id, Evidence.identifier).where(Evidence.id.in_(ev_ids)))).all()) if ev_ids else {}
    versions = dict((await db.execute(
        select(ForensicImport.id, ForensicImport.parser_version).where(ForensicImport.id.in_(imp_ids)))).all()) if imp_ids else {}
    for e in events:
        e.evidence_identifier = idents.get(e.evidence_id)
        e.parser_version = versions.get(e.forensic_import_id)


# C5 — fields copied from the exhibit by an import promote; immutable once promoted.
_IMPORTED_FACTS = ("event_time", "hostname", "source", "event_type", "description", "raw_log")


def _audit_value(v):
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    if hasattr(v, "isoformat"):
        return v.isoformat()
    return str(v)


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
    sort:           Literal["event_time", "-event_time"] = Query(
        default="event_time",
        description="event_time = oldest first (forensic chronological order, the default); "
                    "-event_time = newest first. A cursor only continues the order it came from "
                    "(400 otherwise)."),
) -> TimelineEventList:
    """List an incident's timeline events in forensic chronological order (event_time ASC),
    or newest first with `sort=-event_time`.

    Cursor-paginated via `limit` and opaque `cursor`. Set `include_system=False` to omit
    system-generated events; the response then carries `system_event_count` for those hidden.
    Requires read access to the incident. Returns a paginated TimelineEventList.
    """
    await _get_incident(db, incident_id, user)
    desc = sort == "-event_time"
    offset = _decode_cursor(cursor, desc)

    # id last: a total order, so rows with equal times page deterministically (both directions)
    keys = (TimelineEvent.event_time, TimelineEvent.created_at, TimelineEvent.id)
    stmt = (
        select(TimelineEvent)
        .where(TimelineEvent.incident_id == incident_id)
        .order_by(*(k.desc() for k in keys) if desc else keys)
    )
    if not include_system:
        stmt = stmt.where(TimelineEvent.is_system == False)  # noqa: E712

    rows = (await db.execute(stmt.offset(offset).limit(limit + 1))).scalars().all()

    has_more    = len(rows) > limit
    page        = rows[:limit]
    umap        = await _username_map(db, [r.created_by_id for r in page])
    for r in page:
        r.created_by_username = umap.get(r.created_by_id)
    await _resolve_provenance(db, page)
    items       = [TimelineEventOut.model_validate(r) for r in page]
    next_cursor = _encode_cursor(offset + limit, desc) if has_more else None

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
             responses={**_ENTITY_ERRORS,
                        422: {"model": ApiErrorBody,
                              "description": "entity_other_incident, reserved_system_source (or a validation error)"}},
             summary="Create a timeline event")
async def create_timeline_event(
    incident_id: uuid.UUID,
    req: TimelineEventCreate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> TimelineEventOut:
    """Add a single timeline event to an incident, capturing time, host, source and MITRE mapping.

    `entity_id` links the event to the in-scope entity (host, account, …) it happened on: 404
    `entity_not_found`, 422 `entity_other_incident`. An empty `hostname` takes the entity's
    value. `is_system=true` makes it an analyst annotation (shown with the system events);
    its `system_source` is a free label such as "manual", but the sources the server writes
    itself (closure, gate_override, milestone, triage, respond_action, respond_action_revert,
    decision, legal_deadline) are refused with 422 `reserved_system_source`. Rejects events on
    a closed incident with 409. Requires the analyst role and write access to the incident;
    the action is audit-logged. Returns the created TimelineEventOut.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")
    if req.system_source and req.system_source.strip().lower() in RESERVED_SYSTEM_SOURCES:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "reserved_system_source",
                       f"system_source \"{req.system_source.strip()}\" is reserved for events the server "
                       "writes itself; use \"manual\" (or leave it out) for an analyst annotation.")
    ent = await _entity(db, incident_id, req.entity_id) if req.entity_id else None

    ev = TimelineEvent(
        id=uuid.uuid4(),
        incident_id=incident_id,
        event_time=req.event_time,
        hostname=req.hostname or (ent.value[:256] if ent else None),
        entity_id=req.entity_id,
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
            "entity_id": str(ev.entity_id) if ev.entity_id else None,
            "description": ev.description[:120],
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    ev.created_by_username = user.username
    return TimelineEventOut.model_validate(ev)


# ─── Update ───────────────────────────────────────────────────────────────────

@router.patch("/{incident_id}/timeline/{event_id}", response_model=TimelineEventOut,
              responses={**_ENTITY_ERRORS,
                         409: {"model": ApiErrorBody, "description": "incident_closed or imported_fact_immutable"}},
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

    Only changed fields are applied and audit-logged, each as `{field: {from, to}}`; omitted or
    null fields stay as they are, except `entity_id` and `ir_phase`: sent as null they unlink /
    clear. A linked entity is checked as on create (404 / 422); when the event then has no
    hostname it takes the entity's value. An event with recorded provenance — promoted from a
    Timeline Import or an exhibit, or carrying a `time_basis` (e.g. a YARA match placed at its
    scan time): `forensic_import_id`, `evidence_id` or `time_basis` set — keeps its recorded facts:
    event_time, hostname, source, event_type, description, raw_log: changing one returns 409
    `imported_fact_immutable` (sending the unchanged value is fine; descriptions compare
    without surrounding whitespace); ir_phase, ATT&CK and entity_id stay editable, and linking
    an entity doesn't fill its hostname. Rejects edits on a closed incident with 409 `incident_closed` and
    returns 404 if the event is not in this incident. Requires the analyst role and write access.
    Returns the updated TimelineEventOut.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")

    ev = (await db.execute(
        select(TimelineEvent).where(
            TimelineEvent.id == event_id,
            TimelineEvent.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not ev:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Event not found")
    sent = req.model_fields_set
    # Provenance, not just the import link (M3): the import FK is RESTRICT now, but an event that
    # names an exhibit or a time basis is a recorded fact either way.
    imported = (ev.forensic_import_id is not None or ev.evidence_id is not None
                or ev.time_basis is not None)

    # Proposed new values, by the same "is it a change?" rules as before.
    new: dict[str, object] = {}
    if req.event_time           is not None and req.event_time != ev.event_time:
        new["event_time"] = req.event_time
    if req.hostname             is not None and req.hostname != (ev.hostname or ""):
        new["hostname"] = req.hostname
    if req.source               is not None and req.source != (ev.source or ""):
        new["source"] = req.source
    if req.event_type           is not None and req.event_type != (ev.event_type or ""):
        new["event_type"] = req.event_type
    if req.description          is not None and req.description.strip() != (ev.description or "").strip():
        new["description"] = req.description.strip()
    if req.raw_log              is not None and req.raw_log != (ev.raw_log or ""):
        new["raw_log"] = req.raw_log
    if imported and (locked := [f for f in _IMPORTED_FACTS if f in new]):
        origin = ("an exhibit" if ev.evidence_id else
                  "a Timeline Import" if ev.forensic_import_id else "a recorded detection")
        raise ApiError(status.HTTP_409_CONFLICT, "imported_fact_immutable",
                       f"This event was imported from {origin}; "
                       f"its facts can't be edited ({', '.join(locked)}). Annotate it with the IR phase, "
                       "ATT&CK or an entity link instead.")
    ent = await _entity(db, incident_id, req.entity_id) if "entity_id" in sent and req.entity_id else None
    if "ir_phase" in sent and req.ir_phase != ev.ir_phase:
        new["ir_phase"] = req.ir_phase
    if "entity_id" in sent and req.entity_id != ev.entity_id:
        new["entity_id"] = req.entity_id
    if ent is not None and not new.get("hostname", ev.hostname) and not imported:
        new["hostname"] = ent.value[:256]
    if req.mitre_tactic_id      is not None and req.mitre_tactic_id != (ev.mitre_tactic_id or ""):
        new["mitre_tactic_id"] = req.mitre_tactic_id
    if req.mitre_tactic_name    is not None and req.mitre_tactic_name != (ev.mitre_tactic_name or ""):
        new["mitre_tactic_name"] = req.mitre_tactic_name
    if req.mitre_technique_id   is not None and req.mitre_technique_id != (ev.mitre_technique_id or ""):
        new["mitre_technique_id"] = req.mitre_technique_id
    if req.mitre_technique_name is not None and req.mitre_technique_name != (ev.mitre_technique_name or ""):
        new["mitre_technique_name"] = req.mitre_technique_name

    # C5 — every audited change records before and after.
    changed: dict[str, object] = {}
    for field, value in new.items():
        changed[field] = {"from": _audit_value(getattr(ev, field)), "to": _audit_value(value)}
        setattr(ev, field, value)

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
    await _resolve_provenance(db, [ev])
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
    batch. An item whose `entity_id` is not an entity of this incident is skipped with an error;
    an empty `hostname` takes the linked entity's value. Imported events are never system events:
    an item's `is_system` / `system_source` are ignored. Rejects imports on a closed incident with
    409. Requires the analyst role and write access; the import is audit-logged. Returns a
    TimelineEventBatchResult with the created count and any errors.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")

    wanted = {item.entity_id for item in req.events if item.entity_id}
    entity_values = dict((await db.execute(
        select(Entity.id, Entity.value).where(Entity.id.in_(wanted), Entity.incident_id == incident_id)
    )).all()) if wanted else {}

    created = 0
    errors: list[str] = []

    for i, item in enumerate(req.events):
        if item.entity_id and item.entity_id not in entity_values:
            errors.append(f"[{i}] entity_id {item.entity_id} is not an entity of this incident")
            continue
        try:
            ev = TimelineEvent(
                id=uuid.uuid4(),
                incident_id=incident_id,
                event_time=item.event_time,
                hostname=item.hostname or (entity_values[item.entity_id][:256] if item.entity_id else None),
                entity_id=item.entity_id,
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
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")

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
            # provenance of what was deleted (L5)
            "event_time":         ev.event_time.isoformat() if ev.event_time else None,
            "evidence_id":        str(ev.evidence_id) if ev.evidence_id else None,
            "forensic_import_id": str(ev.forensic_import_id) if ev.forensic_import_id else None,
            "import_event_index": ev.import_event_index,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(ev)
    await db.commit()
    return {"status": "ok"}
