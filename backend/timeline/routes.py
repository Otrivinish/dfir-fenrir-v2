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
from sqlalchemy import and_, exists, func, not_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
import lolbins.service as lolbins_svc
from incidents.access import get_accessible_incident
from models import (BrowserHistoryUpload, DefenderPdfImport, EmailAnalysis, Entity, Evidence, ForensicImport, Incident,
                    IOC, IocTimelineLink, PCAPAnalysis, TimelineEvent, User)
from schemas import (
    TimelineEventBatchCreate,
    TimelineEventBatchResult,
    TimelineEventCreate,
    TimelineEventList,
    TimelineEventOut,
    TimelineEventUpdate,
    TimelineIocRef,
    TimelineOrigin,
)

router = APIRouter()


# L11, accepted: a row deleted between two page reads makes an offset cursor skip one row; the war room pages by keyset.
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
    "ic_transfer",   # J4: Incident Commander moved on handoff acknowledgement
})


def _server_generated(ev: TimelineEvent) -> bool:
    """F3 (R59) — a system event the server wrote itself (reserved system_source). It is the
    record of what the platform did (closure, gate override, milestone, triage, respond action /
    revert, decision, legal deadline), so no client may edit or delete it: 409
    system_event_immutable. Analyst annotations ("manual" and other labels) stay editable."""
    return bool(ev.is_system and (ev.system_source or "").strip().lower() in RESERVED_SYSTEM_SOURCES)


# K3 (R39) — a key event: the analyst's flag (is_key), an ATT&CK tactic or technique, or an event the server
# recorded itself (as J3's "Insert key timeline events" counts milestones). `?key=true` filters on KEY_EVENT;
# _key_event is the same rule on a loaded row (an empty string counts as no ATT&CK, as in SQL).
KEY_EVENT = or_(
    TimelineEvent.is_key == True,  # noqa: E712
    func.coalesce(TimelineEvent.mitre_tactic_id, "") != "",
    func.coalesce(TimelineEvent.mitre_technique_id, "") != "",
    and_(TimelineEvent.is_system == True,  # noqa: E712
         func.lower(func.trim(TimelineEvent.system_source)).in_(RESERVED_SYSTEM_SOURCES)),
)


def _key_event(ev: TimelineEvent) -> bool:
    return bool(ev.is_key or ev.mitre_tactic_id or ev.mitre_technique_id or _server_generated(ev))


async def _decorate(db: AsyncSession, events) -> None:
    """Read-only fields set on loaded rows: server_generated, key_event and the linked IOCs (one query)."""
    links: dict[uuid.UUID, list[TimelineIocRef]] = {}
    ids = [e.id for e in events]
    if ids:
        for ev_id, ioc_id, typ, value, mal in (await db.execute(
            select(IocTimelineLink.timeline_event_id, IOC.id, IOC.type, IOC.value, IOC.malicious)
            .join(IOC, IOC.id == IocTimelineLink.ioc_id)
            .where(IocTimelineLink.timeline_event_id.in_(ids))
            .order_by(IOC.value)
        )).all():
            links.setdefault(ev_id, []).append(TimelineIocRef(id=ioc_id, type=typ, value=value, malicious=mal))
    for e in events:
        e.server_generated = _server_generated(e)
        e.key_event = _key_event(e)
        e.linked_iocs = links.get(e.id, [])


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _refuse_server_event(ev: TimelineEvent, verb: str) -> None:
    if _server_generated(ev):
        raise ApiError(status.HTTP_409_CONFLICT, "system_event_immutable",
                       f"This event was recorded by FENRIR itself ({ev.system_source}); it can't be {verb}. "
                       "Add an annotation event instead.")

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


# The parser named in a Timeline Import run record (forensic/routes.py audits the same name).
_TIMELINE_PARSER = "FENRIR timeline parser"


async def _resolve_provenance(db: AsyncSession, events) -> None:
    """C5/G4/G3 — set the read-only evidence_identifier / parser_name / parser_version of imported
    events (at most 6 queries; L26: email relay hops name their analysis run)."""
    ev_ids  = {e.evidence_id for e in events if e.evidence_id}
    imp_ids = {e.forensic_import_id for e in events if e.forensic_import_id}
    def_ids = {e.defender_import_id for e in events if e.defender_import_id}
    pcap_ids = {e.pcap_analysis_id for e in events if e.pcap_analysis_id}
    web_ids = {e.browser_history_upload_id for e in events if e.browser_history_upload_id}
    mail_ids = {e.email_analysis_id for e in events if e.email_analysis_id}
    runs = {}      # G3 — PCAP analyses / browser-history uploads (/ L26 email analyses): (name, version)
    if pcap_ids:
        runs.update({r[0]: (r[1], r[2]) for r in (await db.execute(
            select(PCAPAnalysis.id, PCAPAnalysis.analyser_name, PCAPAnalysis.analyser_version)
            .where(PCAPAnalysis.id.in_(pcap_ids)))).all()})
    if web_ids:
        runs.update({r[0]: (r[1], r[2]) for r in (await db.execute(
            select(BrowserHistoryUpload.id, BrowserHistoryUpload.parser_name, BrowserHistoryUpload.parser_version)
            .where(BrowserHistoryUpload.id.in_(web_ids)))).all()})
    if mail_ids:
        runs.update({r[0]: (r[1], r[2]) for r in (await db.execute(
            select(EmailAnalysis.id, EmailAnalysis.analyser_name, EmailAnalysis.analyser_version)
            .where(EmailAnalysis.id.in_(mail_ids)))).all()})
    idents = dict((await db.execute(
        select(Evidence.id, Evidence.identifier).where(Evidence.id.in_(ev_ids)))).all()) if ev_ids else {}
    versions = dict((await db.execute(
        select(ForensicImport.id, ForensicImport.parser_version).where(ForensicImport.id.in_(imp_ids)))).all()) if imp_ids else {}
    defender = {r[0]: (r[1], r[2]) for r in (await db.execute(
        select(DefenderPdfImport.id, DefenderPdfImport.parser_name, DefenderPdfImport.parser_version)
        .where(DefenderPdfImport.id.in_(def_ids)))).all()} if def_ids else {}
    for e in events:
        e.evidence_identifier = idents.get(e.evidence_id)
        if e.defender_import_id in defender:
            e.parser_name, e.parser_version = defender[e.defender_import_id]
        elif (e.pcap_analysis_id or e.browser_history_upload_id or e.email_analysis_id) in runs:
            e.parser_name, e.parser_version = runs[e.pcap_analysis_id or e.browser_history_upload_id
                                                   or e.email_analysis_id]
        else:
            e.parser_version = versions.get(e.forensic_import_id)
            e.parser_name = _TIMELINE_PARSER if e.forensic_import_id and e.parser_version else None


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
    entity_id:      Optional[uuid.UUID] = Query(default=None, description="Only events linked to this entity."),
    ioc_id:         Optional[uuid.UUID] = Query(default=None, description="Only events linked to this IOC."),
    ir_phase:       Optional[Literal["preparation", "detection_and_analysis", "containment_eradication_recovery",
                                     "post_incident", "none"]] = Query(
        default=None, description="Only events tagged with this 800-61 phase; none = no phase set."),
    origin:         Optional[TimelineOrigin] = Query(
        default=None, description="manual (analyst-entered), forensic_import (imported from an exhibit or an "
                                  "analysis run) or system (recorded by FENRIR, or an analyst annotation)."),
    key:            Optional[bool] = Query(default=None, description="true = key events only (key_event), "
                                                                     "false = the others."),
    q:              Optional[str] = Query(default=None, min_length=1, max_length=200, description=(
        "Text search, case-insensitive, in description, hostname, log source, event type, raw log and the "
        "ATT&CK ids and names.")),
) -> TimelineEventList:
    """List an incident's timeline events in forensic chronological order (event_time ASC),
    or newest first with `sort=-event_time`.

    Cursor-paginated via `limit` and opaque `cursor`; the filters (entity_id, ioc_id, ir_phase,
    origin, key, q) combine with AND and are applied before paging, so a cursor continues the
    same filtered list (send the same filters with it). Set `include_system=False` to omit
    system-generated events; the response then carries `system_event_count` for those hidden.
    Each event carries `key_event` (flagged, ATT&CK-tagged or server-recorded) and its
    `linked_iocs`. Requires read access to the incident. Returns a paginated TimelineEventList.
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
    if entity_id is not None:
        stmt = stmt.where(TimelineEvent.entity_id == entity_id)
    if ioc_id is not None:
        stmt = stmt.where(exists().where(IocTimelineLink.timeline_event_id == TimelineEvent.id,
                                         IocTimelineLink.ioc_id == ioc_id))
    if ir_phase == "none":
        stmt = stmt.where(TimelineEvent.ir_phase.is_(None))
    elif ir_phase is not None:
        stmt = stmt.where(TimelineEvent.ir_phase == ir_phase)
    if origin is not None:
        stmt = stmt.where(TimelineEvent.origin == origin)
    if key is not None:
        stmt = stmt.where(KEY_EVENT if key else not_(KEY_EVENT))
    if q and q.strip():
        pat = _like(q.strip())
        stmt = stmt.where(or_(*(func.coalesce(c, "").ilike(pat, escape="\\") for c in (
            TimelineEvent.description, TimelineEvent.hostname, TimelineEvent.source, TimelineEvent.event_type,
            TimelineEvent.raw_log, TimelineEvent.mitre_tactic_id, TimelineEvent.mitre_tactic_name,
            TimelineEvent.mitre_technique_id, TimelineEvent.mitre_technique_name))))

    rows = (await db.execute(stmt.offset(offset).limit(limit + 1))).scalars().all()

    has_more    = len(rows) > limit
    page        = rows[:limit]
    umap        = await _username_map(db, [r.created_by_id for r in page])
    for r in page:
        r.created_by_username = umap.get(r.created_by_id)
    await _decorate(db, page)
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
    decision, legal_deadline, ic_transfer) are refused with 422 `reserved_system_source`. Rejects events on
    a closed incident with 409. `is_key=true` flags it a key event. Requires the analyst role and write
    access to the incident; the action is audit-logged. Returns the created TimelineEventOut.
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
        is_key=req.is_key,
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
            **({"is_key": True} if ev.is_key else {}),
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    ev.created_by_username = user.username
    await _decorate(db, [ev])
    return TimelineEventOut.model_validate(ev)


# ─── Update ───────────────────────────────────────────────────────────────────

@router.patch("/{incident_id}/timeline/{event_id}", response_model=TimelineEventOut,
              responses={**_ENTITY_ERRORS,
                         409: {"model": ApiErrorBody, "description": "incident_closed, system_event_immutable "
                                                                     "or imported_fact_immutable"}},
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
    Timeline Import, a Defender import, a PCAP analysis (`pcap_analysis_id`), a browser history
    upload (`browser_history_upload_id`), an email analysis's relay hops (`email_analysis_id`) or an
    exhibit, or carrying a `time_basis` (e.g. a YARA match placed at its scan time):
    `forensic_import_id`, `defender_import_id`, `pcap_analysis_id`, `browser_history_upload_id`,
    `email_analysis_id`, `evidence_id` or `time_basis` set — keeps its recorded facts:
    event_time, hostname, source, event_type, description, raw_log: changing one returns 409
    `imported_fact_immutable` (sending the unchanged value is fine; descriptions compare
    without surrounding whitespace); ir_phase, ATT&CK, is_key and entity_id stay editable, and linking
    an entity doesn't fill its hostname. Rejects edits on a closed incident with 409 `incident_closed` and
    returns 404 if the event is not in this incident. An event the server recorded itself
    (`server_generated`: is_system with a reserved system_source — closure, gate_override, milestone,
    triage, respond_action, respond_action_revert, decision, legal_deadline, ic_transfer) can't be edited at all,
    IR phase and ATT&CK included: 409 `system_event_immutable`. Requires the analyst role and write
    access. Returns the updated TimelineEventOut.
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
    _refuse_server_event(ev, "edited")
    sent = req.model_fields_set
    # Provenance, not just the import link (M3): the import FK is RESTRICT now, but an event that
    # names an exhibit or a time basis is a recorded fact either way.
    imported = (ev.forensic_import_id is not None or ev.defender_import_id is not None
                or ev.pcap_analysis_id is not None or ev.browser_history_upload_id is not None
                or ev.email_analysis_id is not None or ev.evidence_id is not None or ev.time_basis is not None)

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
        # L32: name the run first (each run event also names its exhibit), then the exhibit.
        origin = ("a Timeline Import" if ev.forensic_import_id else
                  "a Defender import" if ev.defender_import_id else
                  "a PCAP analysis" if ev.pcap_analysis_id else
                  "a browser history upload" if ev.browser_history_upload_id else
                  "an email analysis (mail relay hops)" if ev.email_analysis_id else
                  "an exhibit" if ev.evidence_id else "a recorded detection")
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
    if req.is_key is not None and req.is_key != ev.is_key:
        new["is_key"] = req.is_key

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
    await _decorate(db, [ev])
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

    Each event is inserted in its own savepoint; per-item failures are collected rather than
    aborting the batch (a row the database rejects rolls back alone). An item whose `entity_id` is not an entity of this incident is skipped with an error;
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
        # K5 (R49): per-row savepoint (as iocs/routes.py batch create): without it, one row the
        # database rejects left the session failed and lost the whole batch.
        sp = await db.begin_nested()
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
                is_key=item.is_key,
                origin="forensic_import",
                created_by_id=user.id,
            )
            db.add(ev)
            await db.flush()
            await sp.commit()
            created += 1
        except Exception as exc:
            await sp.rollback()
            # The exception class only: a DB error's text carries the SQL and the row's values.
            errors.append(f"[{i}] rejected by the database ({type(exc).__name__})")

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

@router.delete("/{incident_id}/timeline/{event_id}", summary="Delete a timeline event",
               responses={409: {"model": ApiErrorBody, "description": "incident_closed or system_event_immutable"}})
async def delete_timeline_event(
    incident_id: uuid.UUID,
    event_id:    uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Permanently delete a timeline event from an incident.

    Rejects deletion on a closed incident with 409 `incident_closed` and returns 404 if the event is
    not in this incident. An event the server recorded itself (`server_generated`) can't be deleted:
    409 `system_event_immutable`. Requires the analyst role and write access; the deletion is
    audit-logged. Returns `{"status": "ok"}`.
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
    _refuse_server_event(ev, "deleted")

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
            "defender_import_id": str(ev.defender_import_id) if ev.defender_import_id else None,
            "pcap_analysis_id":   str(ev.pcap_analysis_id) if ev.pcap_analysis_id else None,
            "browser_history_upload_id": str(ev.browser_history_upload_id) if ev.browser_history_upload_id else None,
            "email_analysis_id":  str(ev.email_analysis_id) if ev.email_analysis_id else None,
            "source_record_id":   str(ev.source_record_id) if ev.source_record_id else None,
            "import_event_index": ev.import_event_index,
            "recorded_event_time": ev.recorded_event_time.isoformat() if ev.recorded_event_time else None,
            "clock_offset_seconds": ev.clock_offset_seconds,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(ev)
    await db.commit()
    return {"status": "ok"}
