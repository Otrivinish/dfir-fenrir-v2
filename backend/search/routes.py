"""Global search endpoint — fans out to incidents, IOCs, entities, timeline events."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy import Text, cast, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import require_analyst
from core.database import get_db
from core.tags import normalize_tag
from incidents.access import accessible_filter
from models import Entity, IOC, Incident, TimelineEvent, User

router = APIRouter(prefix="/api/search", tags=["Search"])


@router.get("")
async def global_search(
    q: str = Query(..., min_length=2, max_length=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    term = f"%{q}%"
    filt = accessible_filter(current_user)

    # Also match against the canonical tag form so a query of "APT 28" or "apt_28"
    # hits an `apt-28` tag — same normalisation the storage layer uses.
    canonical = normalize_tag(q) or ""
    tag_needle = f'%"{canonical}"%' if canonical else None

    inc_match = [Incident.title.ilike(term), Incident.description.ilike(term)]
    if tag_needle:
        inc_match.append(cast(Incident.tags, Text).ilike(tag_needle))

    incidents = (await db.execute(
        select(Incident)
        .where(filt)
        .where(or_(*inc_match))
        .order_by(Incident.created_at.desc())
        .limit(5)
    )).scalars().all()

    ioc_match = [IOC.value.ilike(term), IOC.notes.ilike(term), IOC.source.ilike(term)]
    if tag_needle:
        ioc_match.append(cast(IOC.tags, Text).ilike(tag_needle))

    iocs = (await db.execute(
        select(IOC)
        .join(Incident, IOC.incident_id == Incident.id)
        .where(filt)
        .where(or_(*ioc_match))
        .order_by(IOC.added_at.desc())
        .limit(5)
    )).scalars().all()

    entities = (await db.execute(
        select(Entity)
        .join(Incident, Entity.incident_id == Incident.id)
        .where(filt)
        .where(or_(Entity.value.ilike(term), Entity.name.ilike(term)))
        .order_by(Entity.added_at.desc())
        .limit(5)
    )).scalars().all()

    timeline_events = (await db.execute(
        select(TimelineEvent)
        .join(Incident, TimelineEvent.incident_id == Incident.id)
        .where(filt)
        .where(or_(
            TimelineEvent.description.ilike(term),
            TimelineEvent.hostname.ilike(term),
            TimelineEvent.source.ilike(term),
        ))
        .order_by(TimelineEvent.event_time.desc())
        .limit(5)
    )).scalars().all()

    # Batch-load incident refs for sub-resources
    sub_ids = {r.incident_id for r in (*iocs, *entities, *timeline_events)}
    inc_map: dict = {}
    if sub_ids:
        rows = (await db.execute(
            select(Incident.id, Incident.incident_number, Incident.title)
            .where(Incident.id.in_(sub_ids))
        )).all()
        for row in rows:
            ref = f"INC-{row.incident_number:04d}" if row.incident_number else "INC-????"
            inc_map[row.id] = {"ref": ref, "title": row.title}

    return {
        "incidents": [
            {
                "id":       str(r.id),
                "ref":      r.ref or "INC-????",
                "title":    r.title,
                "severity": r.severity,
                "status":   r.status,
                "phase":    r.phase,
                "tags":     list(r.tags or []),
            }
            for r in incidents
        ],
        "iocs": [
            {
                "id":             str(r.id),
                "type":           r.type,
                "value":          r.value,
                "tags":           list(r.tags or []),
                "incident_id":    str(r.incident_id),
                "incident_ref":   inc_map.get(r.incident_id, {}).get("ref", ""),
                "incident_title": inc_map.get(r.incident_id, {}).get("title", ""),
            }
            for r in iocs
        ],
        "entities": [
            {
                "id":             str(r.id),
                "type":           r.type,
                "value":          r.value,
                "name":           r.name,
                "incident_id":    str(r.incident_id),
                "incident_ref":   inc_map.get(r.incident_id, {}).get("ref", ""),
                "incident_title": inc_map.get(r.incident_id, {}).get("title", ""),
            }
            for r in entities
        ],
        "timeline_events": [
            {
                "id":             str(r.id),
                "description":    r.description,
                "hostname":       r.hostname,
                "source":         r.source,
                "incident_id":    str(r.incident_id),
                "incident_ref":   inc_map.get(r.incident_id, {}).get("ref", ""),
                "incident_title": inc_map.get(r.incident_id, {}).get("title", ""),
            }
            for r in timeline_events
        ],
    }
