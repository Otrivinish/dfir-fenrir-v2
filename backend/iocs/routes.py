"""Per-incident IOC endpoints.

Mounted at `prefix="/api/incidents"` alongside the incidents router; path
patterns (`/{incident_id}/iocs/...`) don't collide with incident-level routes.

Standards alignment: vocabulary follows 800-61 R3 ("indicator of compromise").
"""
import asyncio
import base64
import json
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select, tuple_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from incidents.access import get_accessible_incident
import lolbins.service as lol_svc
from models import IOC, Incident, IocTimelineLink, ThreatIntelIOC, TimelineEvent, User
from osint.service import SOURCES, enrich_one, source_available
from schemas import (
    EnrichResultItem,
    IocEnrichAllRequest, IocEnrichAllResponse,
    IocTimelineLinkCreate, IocTimelineLinkList, IocTimelineLinkOut,
    IocType, IOCCreate, IOCList, IOCOut, IOCUpdate,
    TiScanResult,
)

router = APIRouter()


# Cursor helpers mirror incidents.routes — opaque offset-encoded.
# (Extract to core/cursors.py when a third caller lands.)
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
    """Resolve {user_id: username} for a set of adder ids (skips None/missing)."""
    ids = {i for i in user_ids if i}
    if not ids:
        return {}
    rows = (await db.execute(select(User.id, User.username).where(User.id.in_(ids)))).all()
    return {uid: uname for uid, uname in rows}


def _norm_tags(tags: list[str] | None) -> list[str]:
    """Compat shim — delegate to the canonical normaliser in core.tags.
    See core/tags.py for the dash/forbidden-char/cap rules."""
    from core.tags import normalize_tags
    return normalize_tags(tags)


def _lolbin_check(ioc_type: str, value: str) -> tuple[bool, Optional[str]]:
    """For file_path IOCs: extract the base filename and look it up in the LOLBins cache."""
    if ioc_type != "file_path":
        return False, None
    name = value.replace("\\", "/").split("/")[-1].strip()
    if not name:
        return False, None
    entry = lol_svc.lookup(name)
    if entry:
        return True, entry.get("name", name)
    return False, None


def _apply_lolbin(out: IOCOut) -> None:
    hit, name = _lolbin_check(out.type, out.value)
    if hit:
        out.lolbin_hit  = True
        out.lolbin_name = name


# ─── List ────────────────────────────────────────────────────────────────────

@router.get("/{incident_id}/iocs", response_model=IOCList, summary="List IOCs for an incident")
async def list_iocs(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
    type:   Optional[IocType] = Query(default=None),
    tag:    Optional[str]     = Query(default=None, description="Filter by tag (canonical lowercase-dashed)"),
    limit:  int               = Query(default=50, ge=1, le=200),
    cursor: Optional[str]     = Query(default=None),
) -> IOCList:
    """List indicators of compromise for an incident, newest first.

    Supports optional filtering by `type` and `tag` (canonical lowercase-dashed),
    and cursor-based pagination via `limit` and `cursor`. Each item is enriched
    with threat-intel match info and a LOLBins flag for file_path IOCs. Requires
    an authenticated user with access to the incident. Returns a paginated
    `IOCList` with `items` and `next_cursor`.
    """
    await _get_incident(db, incident_id, user)
    offset = _decode_cursor(cursor)

    stmt = (
        select(IOC)
        .where(IOC.incident_id == incident_id)
        .order_by(IOC.added_at.desc(), IOC.id)
    )
    if type:
        stmt = stmt.where(IOC.type == type)
    if tag:
        from core.tags import normalize_tag
        canonical = normalize_tag(tag)
        if canonical:
            stmt = stmt.where(
                func.cast(IOC.tags, type_=None).ilike(f'%"{canonical}"%')
            )

    stmt = stmt.offset(offset).limit(limit + 1)
    rows = (await db.execute(stmt)).scalars().all()

    has_more = len(rows) > limit
    items    = [IOCOut.model_validate(r) for r in rows[:limit]]

    # Enrich with TI match info: one extra query against indexed (type, value)
    if items:
        pairs = [(i.type, i.value) for i in items]
        ti_hits = (await db.execute(
            select(ThreatIntelIOC.type, ThreatIntelIOC.value, ThreatIntelIOC.feed_name)
            .where(tuple_(ThreatIntelIOC.type, ThreatIntelIOC.value).in_(pairs))
        )).all()
        if ti_hits:
            ti_map = {(r.type, r.value): r.feed_name for r in ti_hits}
            for ioc in items:
                feed = ti_map.get((ioc.type, ioc.value))
                if feed:
                    ioc.ti_matched      = True
                    ioc.ti_match_source = feed
        # LOLBins check — in-memory, O(1) per file_path IOC
        for ioc in items:
            _apply_lolbin(ioc)

    # Resolve adder usernames for display (batched)
    umap = await _username_map(db, [i.added_by_id for i in items])
    for ioc in items:
        ioc.added_by_username = umap.get(ioc.added_by_id)

    next_cursor = _encode_cursor(offset + limit) if has_more else None
    return IOCList(items=items, next_cursor=next_cursor)


# ─── Create ──────────────────────────────────────────────────────────────────

@router.post("/{incident_id}/iocs",
             response_model=IOCOut,
             status_code=status.HTTP_201_CREATED,
             summary="Create an IOC")
async def create_ioc(
    incident_id: uuid.UUID,
    req: IOCCreate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> IOCOut:
    """Create a new indicator of compromise on an incident.

    Rejects the request if the incident is closed (409) or if an identical IOC
    already exists on it (409). On creation the IOC is auto-checked against the
    threat-intel database and the result is reflected in the response. Requires
    the analyst role and access to the incident. Returns the created `IOCOut`.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    ioc = IOC(
        id=uuid.uuid4(),
        incident_id=incident_id,
        type=req.type,
        value=req.value.strip(),
        notes=req.notes,
        source=req.source or "manual",
        malicious=req.malicious,
        confidence=req.confidence,
        tags=_norm_tags(req.tags),
        entity_id=req.entity_id,
        added_by_id=user.id,
    )
    db.add(ioc)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "This IOC already exists on this incident")

    # Auto-check TI before committing so the response carries the hit
    ti_hit = (await db.execute(
        select(ThreatIntelIOC)
        .where(ThreatIntelIOC.type == ioc.type, ThreatIntelIOC.value == ioc.value)
        .limit(1)
    )).scalar_one_or_none()

    await write_audit(
        db, "ioc_create",
        user_id=user.id, username=user.username,
        resource_type="ioc", resource_id=str(ioc.id),
        details={
            "incident_id": str(incident_id), "type": ioc.type, "value": ioc.value,
            **({"ti_match": ti_hit.feed_name} if ti_hit else {}),
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    out = IOCOut.model_validate(ioc)
    out.added_by_username = user.username
    if ti_hit:
        out.ti_matched      = True
        out.ti_match_source = ti_hit.feed_name
    _apply_lolbin(out)
    return out


# ─── TI scan ─────────────────────────────────────────────────────────────────
# Literal path — declared before /{ioc_id} routes so FastAPI matches it first.

@router.post("/{incident_id}/iocs/scan-ti", response_model=TiScanResult,
             summary="Scan incident IOCs against threat intel")
async def scan_ti(
    incident_id: uuid.UUID,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> TiScanResult:
    """Check every IOC on the incident against the global threat-intel database.

    Requires the analyst role and access to the incident. Returns a
    `TiScanResult` with the number of IOCs scanned, the number of hits, and the
    matching IOCs annotated with the source feed name.
    """
    await _get_incident(db, incident_id, user)

    rows = (await db.execute(
        select(IOC).where(IOC.incident_id == incident_id)
    )).scalars().all()

    if not rows:
        return TiScanResult(scanned=0, hits=0, matches=[])

    pairs = [(r.type, r.value) for r in rows]
    ti_hits = (await db.execute(
        select(ThreatIntelIOC.type, ThreatIntelIOC.value, ThreatIntelIOC.feed_name)
        .where(tuple_(ThreatIntelIOC.type, ThreatIntelIOC.value).in_(pairs))
    )).all()

    ti_map = {(r.type, r.value): r.feed_name for r in ti_hits}
    matches = [
        {"ioc_id": str(r.id), "type": r.type, "value": r.value,
         "feed_name": ti_map[(r.type, r.value)]}
        for r in rows if (r.type, r.value) in ti_map
    ]
    return TiScanResult(scanned=len(rows), hits=len(matches), matches=matches)


# ─── Batch enrichment ────────────────────────────────────────────────────────
# Literal path — must be declared before /{ioc_id} routes so FastAPI matches it first.

@router.post("/{incident_id}/iocs/enrich-all", response_model=IocEnrichAllResponse,
             summary="Enrich all incident IOCs via OSINT")
async def enrich_all_iocs(
    incident_id: uuid.UUID,
    req: IocEnrichAllRequest,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> IocEnrichAllResponse:
    """Enrich all IOCs for an incident with OSINT sources (cached where possible).

    Uses the caller-supplied `sources` from the request body, or all available
    sources when none are given; capped at the 500 most recent IOCs. Runs
    sequentially per IOC (parallel within each IOC's sources) to avoid hammering
    external rate limits. Results are cached in EnrichmentCache. Requires an
    authenticated user with access to the incident. Returns an
    `IocEnrichAllResponse` with counts and per-IOC enrichment results.
    """
    await _get_incident(db, incident_id, user)

    rows = (await db.execute(
        select(IOC)
        .where(IOC.incident_id == incident_id)
        .order_by(IOC.added_at.desc(), IOC.id)
        .limit(500)   # reasonable cap — enrich-all on 500 IOCs is a heavyweight call
    )).scalars().all()

    # Determine sources to use: caller-supplied or all available
    requested = req.sources or list(SOURCES.keys())
    available_sources = [
        sid for sid in requested
        if await source_available(sid, db)
    ]

    results: dict[str, list[EnrichResultItem]] = {}
    enriched = 0

    for ioc in rows:
        applicable = [
            sid for sid in available_sources
            if ioc.type in SOURCES[sid]["supported_types"]
        ]
        if not applicable:
            continue

        raw_list = await asyncio.gather(
            *[enrich_one(db, ioc.value, ioc.type, sid) for sid in applicable],
            return_exceptions=True,
        )

        ioc_results: list[EnrichResultItem] = []
        for sid, raw in zip(applicable, raw_list):
            if isinstance(raw, Exception):
                ioc_results.append(EnrichResultItem(
                    source=sid, available=True, from_cache=False,
                    data=None, error=str(raw),
                ))
            else:
                ioc_results.append(EnrichResultItem(source=sid, **raw))

        results[str(ioc.id)] = ioc_results
        enriched += 1

    return IocEnrichAllResponse(
        ioc_count=len(rows),
        enriched_count=enriched,
        results=results,
    )


# ─── Per-IOC enrichment ──────────────────────────────────────────────────────
# Literal sub-path /{ioc_id}/enrich — registered before PATCH /{ioc_id} so
# FastAPI matches the longer path segment first.

@router.post("/{incident_id}/iocs/{ioc_id}/enrich",
             summary="Enrich a single IOC via OSINT")
async def enrich_single_ioc(
    incident_id: uuid.UUID,
    ioc_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> list[EnrichResultItem]:
    """Enrich a single IOC against all available OSINT sources applicable to its
    type (cached where possible). Returns 404 if the IOC is not found on the
    incident. Requires an authenticated user with access to the incident.
    Returns a list of `EnrichResultItem`, one per source (empty if none apply).
    """
    await _get_incident(db, incident_id, user)

    ioc = (await db.execute(
        select(IOC).where(IOC.id == ioc_id, IOC.incident_id == incident_id)
    )).scalar_one_or_none()
    if not ioc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "IOC not found")

    applicable = [
        sid for sid in SOURCES
        if ioc.type in SOURCES[sid]["supported_types"]
        and await source_available(sid, db)
    ]
    if not applicable:
        return []

    raw_list = await asyncio.gather(
        *[enrich_one(db, ioc.value, ioc.type, sid) for sid in applicable],
        return_exceptions=True,
    )

    results = []
    for sid, raw in zip(applicable, raw_list):
        if isinstance(raw, Exception):
            results.append(EnrichResultItem(
                source=sid, available=True, from_cache=False,
                data=None, error=str(raw),
            ))
        else:
            results.append(EnrichResultItem(source=sid, **raw))
    return results


# ─── Update (notes only in MVP) ──────────────────────────────────────────────

@router.patch("/{incident_id}/iocs/{ioc_id}", response_model=IOCOut,
              summary="Update an IOC")
async def update_ioc(
    incident_id: uuid.UUID,
    ioc_id: uuid.UUID,
    req: IOCUpdate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> IOCOut:
    """Partially update an IOC's notes, malicious flag, confidence, tags, or
    linked entity. The malicious and entity_id fields are tri-state, so an
    explicit null clears them. Returns 409 if the incident is closed and 404 if
    the IOC is not found. Requires the analyst role and access to the incident.
    Returns the updated `IOCOut`.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    ioc = (await db.execute(
        select(IOC).where(IOC.id == ioc_id, IOC.incident_id == incident_id)
    )).scalar_one_or_none()
    if not ioc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "IOC not found")

    changed: dict[str, object] = {}
    # type/value are editable; re-check the (incident, type, value) uniqueness
    # constraint and reject a collision with a clear 409 before mutating.
    new_type  = req.type if req.type is not None else ioc.type
    new_value = req.value.strip() if req.value is not None else ioc.value
    if (new_type, new_value) != (ioc.type, ioc.value):
        dup = (await db.execute(
            select(IOC.id).where(
                IOC.incident_id == incident_id,
                IOC.type == new_type,
                IOC.value == new_value,
                IOC.id != ioc.id,
            )
        )).scalar_one_or_none()
        if dup:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "An IOC with this type and value already exists on this incident",
            )
        if new_type != ioc.type:
            ioc.type = new_type
            changed["type"] = new_type
        if new_value != ioc.value:
            ioc.value = new_value
            changed["value"] = new_value
    if req.notes is not None and req.notes != (ioc.notes or ""):
        ioc.notes = req.notes
        changed["notes"] = req.notes
    # Tri-state: an explicit `null` must be honoured, so check whether the
    # caller actually set the field rather than whether the value is non-null.
    if "malicious" in req.model_fields_set and req.malicious != ioc.malicious:
        ioc.malicious = req.malicious
        changed["malicious"] = req.malicious
    if req.confidence is not None and req.confidence != ioc.confidence:
        ioc.confidence = req.confidence
        changed["confidence"] = req.confidence
    if req.tags is not None:
        norm = _norm_tags(req.tags)
        if norm != list(ioc.tags or []):
            ioc.tags = norm
            changed["tags"] = norm
    if "entity_id" in req.model_fields_set:
        val = req.entity_id
        if val != ioc.entity_id:
            ioc.entity_id = val
            changed["entity_id"] = str(val) if val else None

    if changed:
        await write_audit(
            db, "ioc_update",
            user_id=user.id, username=user.username,
            resource_type="ioc", resource_id=str(ioc.id),
            details={"incident_id": str(incident_id), "changes": changed},
            ip_address=request.client.host if request.client else None,
        )
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "An IOC with this type and value already exists on this incident",
        )
    out = IOCOut.model_validate(ioc)
    umap = await _username_map(db, [ioc.added_by_id])
    out.added_by_username = umap.get(ioc.added_by_id)
    _apply_lolbin(out)
    return out


# ─── Timeline-event links (many-to-many) ──────────────────────────────────────

async def _get_ioc(db: AsyncSession, incident_id: uuid.UUID, ioc_id: uuid.UUID) -> IOC:
    ioc = (await db.execute(
        select(IOC).where(IOC.id == ioc_id, IOC.incident_id == incident_id)
    )).scalar_one_or_none()
    if not ioc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "IOC not found")
    return ioc


@router.get("/{incident_id}/iocs/{ioc_id}/timeline-links",
            response_model=IocTimelineLinkList,
            summary="List timeline events linked to an IOC")
async def list_ioc_timeline_links(
    incident_id: uuid.UUID,
    ioc_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> IocTimelineLinkList:
    """List the timeline events linked to an IOC, oldest first.

    Requires an authenticated user with access to the incident. Returns an
    `IocTimelineLinkList` of the linked events (id, time, description).
    """
    await _get_incident(db, incident_id, user)
    await _get_ioc(db, incident_id, ioc_id)
    rows = (await db.execute(
        select(TimelineEvent.id, TimelineEvent.event_time, TimelineEvent.description)
        .join(IocTimelineLink, IocTimelineLink.timeline_event_id == TimelineEvent.id)
        .where(IocTimelineLink.ioc_id == ioc_id)
        .order_by(TimelineEvent.event_time)
    )).all()
    return IocTimelineLinkList(items=[
        IocTimelineLinkOut(event_id=r.id, event_time=r.event_time, description=r.description)
        for r in rows
    ])


@router.post("/{incident_id}/iocs/{ioc_id}/timeline-links",
             response_model=IocTimelineLinkOut,
             status_code=status.HTTP_201_CREATED,
             summary="Link a timeline event to an IOC")
async def link_ioc_timeline_event(
    incident_id: uuid.UUID,
    ioc_id: uuid.UUID,
    req: IocTimelineLinkCreate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> IocTimelineLinkOut:
    """Link an existing timeline event (same incident) to an IOC.

    Rejects on a closed incident (409), unknown IOC or event (404), or an
    already-existing link (409). Requires the analyst role and access to the
    incident; the action is audit-logged. Returns the linked event.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    await _get_ioc(db, incident_id, ioc_id)

    ev = (await db.execute(
        select(TimelineEvent).where(
            TimelineEvent.id == req.event_id,
            TimelineEvent.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not ev:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Timeline event not found")

    db.add(IocTimelineLink(
        id=uuid.uuid4(), ioc_id=ioc_id, timeline_event_id=ev.id, created_by_id=user.id,
    ))
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "This event is already linked to the IOC")

    await write_audit(
        db, "ioc_timeline_link",
        user_id=user.id, username=user.username,
        resource_type="ioc", resource_id=str(ioc_id),
        details={"incident_id": str(incident_id), "timeline_event_id": str(ev.id)},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return IocTimelineLinkOut(event_id=ev.id, event_time=ev.event_time, description=ev.description)


@router.delete("/{incident_id}/iocs/{ioc_id}/timeline-links/{event_id}",
               summary="Unlink a timeline event from an IOC")
async def unlink_ioc_timeline_event(
    incident_id: uuid.UUID,
    ioc_id: uuid.UUID,
    event_id: uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Remove the link between a timeline event and an IOC.

    Rejects on a closed incident (409) and returns 404 if no such link exists.
    Requires the analyst role and access to the incident; audit-logged.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    link = (await db.execute(
        select(IocTimelineLink).where(
            IocTimelineLink.ioc_id == ioc_id,
            IocTimelineLink.timeline_event_id == event_id,
        )
    )).scalar_one_or_none()
    if not link:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Link not found")
    await db.delete(link)
    await write_audit(
        db, "ioc_timeline_unlink",
        user_id=user.id, username=user.username,
        resource_type="ioc", resource_id=str(ioc_id),
        details={"incident_id": str(incident_id), "timeline_event_id": str(event_id)},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return {"ok": True}


# ─── Delete ──────────────────────────────────────────────────────────────────

@router.delete("/{incident_id}/iocs/{ioc_id}", summary="Delete an IOC")
async def delete_ioc(
    incident_id: uuid.UUID,
    ioc_id: uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Delete an IOC from an incident. Returns 409 if the incident is closed and
    404 if the IOC is not found. Requires the analyst role and access to the
    incident. Returns `{"status": "ok"}` on success.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    ioc = (await db.execute(
        select(IOC).where(IOC.id == ioc_id, IOC.incident_id == incident_id)
    )).scalar_one_or_none()
    if not ioc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "IOC not found")

    await write_audit(
        db, "ioc_delete",
        user_id=user.id, username=user.username,
        resource_type="ioc", resource_id=str(ioc.id),
        details={"incident_id": str(incident_id), "type": ioc.type, "value": ioc.value},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(ioc)
    await db.commit()
    return {"status": "ok"}
