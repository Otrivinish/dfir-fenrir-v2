"""Threat intelligence feed management and global IOC database endpoints.

Feed CRUD + pull are admin-only.  Browsing the global TI IOC database is
analyst-accessible (read-only).
"""
import base64
import json
import uuid
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from sqlalchemy import and_, distinct, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_admin, require_analyst
from core.database import get_db
from incidents.access import accessible_filter
from models import IOC, Incident, ThreatFeed, ThreatIntelIOC, User
from schemas import (
    ThreatFeedCreate, ThreatFeedOut, ThreatFeedUpdate,
    ThreatIntelIOCList, ThreatIntelIOCOut,
)
from threat_intel.ingest import ingest_feed_bg, validate_feed_url
from threat_intel.seeds import DEFAULT_FEEDS

router = APIRouter()


# ─── Cursor helpers ──────────────────────────────────────────────────────────

def _enc(offset: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"o": offset}).encode()).decode().rstrip("=")


def _dec(cursor: Optional[str]) -> int:
    if not cursor:
        return 0
    try:
        pad = "=" * (-len(cursor) % 4)
        return max(0, int(json.loads(base64.urlsafe_b64decode(cursor + pad).decode()).get("o", 0)))
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid cursor")


# ─── Hub: summary stats ──────────────────────────────────────────────────────

@router.get("/summary", summary="Get threat intel summary stats")
async def ti_summary(
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Aggregate stats for the Threat Intel Hub KPI bar: total TI IOCs,
    total feeds, active (enabled) feeds, and the count of incidents that
    have at least one IOC matching the global TI database. Analyst access
    required. Returns a flat dict of integer counters."""
    total_iocs = (await db.execute(
        select(func.count(ThreatIntelIOC.id))
    )).scalar_one()

    feeds = (await db.execute(select(ThreatFeed))).scalars().all()

    incidents_with_matches = (await db.execute(
        select(func.count()).select_from(
            select(distinct(IOC.incident_id))
            .join(ThreatIntelIOC, and_(
                IOC.type == ThreatIntelIOC.type,
                IOC.value == ThreatIntelIOC.value,
            ))
            .subquery()
        )
    )).scalar_one()

    return {
        "total_iocs": total_iocs,
        "total_feeds": len(feeds),
        "active_feeds": sum(1 for f in feeds if f.enabled),
        "incidents_with_matches": incidents_with_matches,
    }


# ─── Hub: cross-incident TI matches ──────────────────────────────────────────

@router.get("/incident-matches", summary="List incidents matching TI IOCs")
async def ti_incident_matches(
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
    limit:  int           = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
) -> dict:
    """Incidents that have at least one IOC matching the TI database.

    Ordered by match count descending (most-hit incidents first).
    Access-controlled: analysts only see incidents they can access.
    """
    offset = _dec(cursor)
    filt   = accessible_filter(user)

    match_count = func.count(distinct(IOC.id)).label("match_count")
    stmt = (
        select(Incident, match_count)
        .join(IOC, IOC.incident_id == Incident.id)
        .join(ThreatIntelIOC, and_(
            IOC.type  == ThreatIntelIOC.type,
            IOC.value == ThreatIntelIOC.value,
        ))
        .where(filt)
        .group_by(Incident.id)
        .order_by(match_count.desc(), Incident.created_at.desc())
        .offset(offset)
        .limit(limit + 1)
    )
    rows = (await db.execute(stmt)).all()

    has_more = len(rows) > limit
    items = [
        {
            "incident_id": str(r.Incident.id),
            "title":       r.Incident.title,
            "severity":    r.Incident.severity,
            "status":      r.Incident.status,
            "created_at":  r.Incident.created_at.isoformat() if r.Incident.created_at else None,
            "match_count": r.match_count,
        }
        for r in rows[:limit]
    ]
    return {"items": items, "next_cursor": _enc(offset + limit) if has_more else None}


# ─── Feed list ───────────────────────────────────────────────────────────────

@router.get("/feeds", response_model=list[ThreatFeedOut], summary="List threat feeds")
async def list_feeds(
    _: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> list[ThreatFeedOut]:
    """List all configured threat intelligence feeds, ordered by name.
    Analyst access required. Returns the full feed list (no pagination)."""
    rows = (await db.execute(select(ThreatFeed).order_by(ThreatFeed.name))).scalars().all()
    return [ThreatFeedOut.model_validate(r) for r in rows]


# ─── Seed defaults ───────────────────────────────────────────────────────────

@router.post("/feeds/init", status_code=status.HTTP_200_OK, summary="Seed default threat feeds")
async def init_feeds(
    request: Request,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Seed the built-in default threat feeds. Idempotent: inserts only the
    default feeds that don't already exist (matched by URL), so it is safe to
    call repeatedly. Admin access required. Returns the number of feeds
    created and a summary message."""
    created = 0
    for spec in DEFAULT_FEEDS:
        existing = (await db.execute(
            select(ThreatFeed).where(ThreatFeed.url == spec["url"])
        )).scalar_one_or_none()
        if existing:
            continue
        feed = ThreatFeed(id=uuid.uuid4(), **spec)
        db.add(feed)
        created += 1

    if created:
        await write_audit(
            db, "ti_feeds_init",
            user_id=user.id, username=user.username,
            resource_type="threat_feed", resource_id="bulk",
            details={"created": created},
            ip_address=request.client.host if request.client else None,
        )
        await db.commit()

    return {"created": created, "message": f"{created} default feed(s) added"}


# ─── Create custom feed ──────────────────────────────────────────────────────

@router.post("/feeds", response_model=ThreatFeedOut, status_code=status.HTTP_201_CREATED,
             summary="Create a custom threat feed")
async def create_feed(
    req: ThreatFeedCreate,
    request: Request,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ThreatFeedOut:
    """Create a custom threat intelligence feed from the supplied name, URL,
    feed/IOC type, pull interval and parser config. The URL is SSRF-validated
    before saving; duplicate URLs return 409. Admin access required. Returns
    the created feed."""
    try:
        validate_feed_url(req.url)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))

    feed = ThreatFeed(
        id=uuid.uuid4(),
        name=req.name,
        url=req.url,
        feed_type=req.feed_type,
        ioc_type=req.ioc_type,
        pull_interval_hours=req.pull_interval_hours,
        parser_config=req.parser_config,
    )
    db.add(feed)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "A feed with that URL already exists")

    await write_audit(
        db, "ti_feed_create",
        user_id=user.id, username=user.username,
        resource_type="threat_feed", resource_id=str(feed.id),
        details={"name": feed.name, "url": feed.url},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return ThreatFeedOut.model_validate(feed)


# ─── Update feed ─────────────────────────────────────────────────────────────

@router.patch("/feeds/{feed_id}", response_model=ThreatFeedOut, summary="Update a threat feed")
async def update_feed(
    feed_id: uuid.UUID,
    req: ThreatFeedUpdate,
    request: Request,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ThreatFeedOut:
    """Update a threat feed's enabled flag, pull interval, and/or parser
    config (only the supplied fields change). Returns 404 if the feed is
    unknown. Admin access required. Returns the updated feed."""
    feed = (await db.execute(select(ThreatFeed).where(ThreatFeed.id == feed_id))).scalar_one_or_none()
    if not feed:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Feed not found")

    changed: dict = {}
    if req.enabled is not None and req.enabled != feed.enabled:
        feed.enabled = req.enabled
        changed["enabled"] = req.enabled
    if req.pull_interval_hours is not None and req.pull_interval_hours != feed.pull_interval_hours:
        feed.pull_interval_hours = req.pull_interval_hours
        changed["pull_interval_hours"] = req.pull_interval_hours
    if req.parser_config is not None:
        feed.parser_config = req.parser_config
        changed["parser_config"] = True

    if changed:
        await write_audit(
            db, "ti_feed_update",
            user_id=user.id, username=user.username,
            resource_type="threat_feed", resource_id=str(feed.id),
            details={"changes": changed},
            ip_address=request.client.host if request.client else None,
        )
    await db.commit()
    return ThreatFeedOut.model_validate(feed)


# ─── Delete feed ─────────────────────────────────────────────────────────────

@router.delete("/feeds/{feed_id}", summary="Delete a threat feed")
async def delete_feed(
    feed_id: uuid.UUID,
    request: Request,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Delete a threat feed and cascade-delete all of its TI IOCs. Returns
    404 if the feed is unknown. Admin access required. Returns a status
    acknowledgement."""
    feed = (await db.execute(select(ThreatFeed).where(ThreatFeed.id == feed_id))).scalar_one_or_none()
    if not feed:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Feed not found")

    await write_audit(
        db, "ti_feed_delete",
        user_id=user.id, username=user.username,
        resource_type="threat_feed", resource_id=str(feed.id),
        details={"name": feed.name},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(feed)   # CASCADE deletes threat_intel_iocs for this feed
    await db.commit()
    return {"status": "ok"}


# ─── Pull a single feed ──────────────────────────────────────────────────────

@router.post("/feeds/{feed_id}/pull", status_code=status.HTTP_202_ACCEPTED,
             summary="Pull a threat feed")
async def pull_feed(
    feed_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    request: Request,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Queue an ingest of a single threat feed; the fetch/parse runs as a
    background task and the call returns 202 immediately. Returns 404 if the
    feed is unknown. Admin access required. Returns the queued status with the
    feed id and name."""
    feed = (await db.execute(select(ThreatFeed).where(ThreatFeed.id == feed_id))).scalar_one_or_none()
    if not feed:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Feed not found")

    await write_audit(
        db, "ti_feed_pull",
        user_id=user.id, username=user.username,
        resource_type="threat_feed", resource_id=str(feed.id),
        details={"name": feed.name},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    background_tasks.add_task(ingest_feed_bg, feed.id)
    return {"status": "pull_queued", "feed_id": str(feed.id), "feed_name": feed.name}


# ─── Pull all enabled feeds ──────────────────────────────────────────────────

@router.post("/feeds/pull-all", status_code=status.HTTP_202_ACCEPTED,
             summary="Pull all enabled threat feeds")
async def pull_all_feeds(
    background_tasks: BackgroundTasks,
    request: Request,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Queue an ingest for every enabled threat feed; each fetch/parse runs as
    a background task and the call returns 202 immediately. Admin access
    required. Returns the queued status with the number of feeds queued."""
    feeds = (await db.execute(
        select(ThreatFeed).where(ThreatFeed.enabled == True)
    )).scalars().all()

    await write_audit(
        db, "ti_feeds_pull_all",
        user_id=user.id, username=user.username,
        resource_type="threat_feed", resource_id="bulk",
        details={"count": len(feeds)},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    for feed in feeds:
        background_tasks.add_task(ingest_feed_bg, feed.id)

    return {"status": "pull_queued", "feeds_queued": len(feeds)}


# ─── Global TI IOC database browser ──────────────────────────────────────────

@router.get("/iocs", response_model=ThreatIntelIOCList, summary="Browse global TI IOCs")
async def list_ti_iocs(
    _: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
    type:   Optional[str] = Query(default=None),
    q:      Optional[str] = Query(default=None, max_length=256),
    limit:  int           = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
) -> ThreatIntelIOCList:
    """Browse the global threat-intel IOC database, newest last-seen first.
    Optional `type` filter and `q` substring match on the IOC value; paginates
    via opaque `cursor` (up to `limit` per page). Analyst access required.
    Returns the matching IOCs with a total count and next cursor."""
    offset = _dec(cursor)

    stmt = select(ThreatIntelIOC).order_by(ThreatIntelIOC.last_seen_at.desc(), ThreatIntelIOC.id)
    if type:
        stmt = stmt.where(ThreatIntelIOC.type == type)
    if q:
        stmt = stmt.where(ThreatIntelIOC.value.ilike(f"%{q}%"))

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar_one()

    rows = (await db.execute(stmt.offset(offset).limit(limit + 1))).scalars().all()
    has_more    = len(rows) > limit
    items       = [ThreatIntelIOCOut.model_validate(r) for r in rows[:limit]]
    next_cursor = _enc(offset + limit) if has_more else None

    return ThreatIntelIOCList(items=items, total=total, next_cursor=next_cursor)
