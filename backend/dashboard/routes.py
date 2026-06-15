from datetime import timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, cast, Date
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import require_analyst
from core.database import get_db
from incidents.access import accessible_filter
from models import (
    Evidence, IOC, Incident, IncidentAssignment, RegulatoryDeadline,
    RespondAction, TimelineEvent, User, utcnow,
)

router = APIRouter()

_METRICS_DAYS = 30
_FEED_DAYS    = 14


def _minutes(td) -> float:
    return td.total_seconds() / 60


@router.get("/summary")
async def dashboard_summary(
    mine: bool = Query(default=False),
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
):
    cutoff = utcnow() - timedelta(days=_METRICS_DAYS)
    # Scope every aggregate to incidents the caller can access (admins: all),
    # plus the optional "mine" filter. Without the access filter these counts /
    # MTTx leak across team-restricted incidents.
    mine_filter = [accessible_filter(user)]
    if mine:
        mine_filter.append(Incident.created_by_id == user.id)

    # Open incidents by severity
    open_rows = (await db.execute(
        select(Incident.severity, func.count().label("n"))
        .where(Incident.status == "open", *mine_filter)
        .group_by(Incident.severity)
    )).all()
    open_by_sev = {r.severity: r.n for r in open_rows}
    open_total  = sum(open_by_sev.values())

    # MTTD — mean time from occurred_at to created_at (detect delay)
    mttd_rows = (await db.execute(
        select(Incident.occurred_at, Incident.created_at)
        .where(Incident.occurred_at.isnot(None), Incident.created_at >= cutoff, *mine_filter)
    )).all()
    mttd_deltas = [
        _minutes(r.created_at - r.occurred_at)
        for r in mttd_rows
        if r.occurred_at < r.created_at
    ]

    # MTTR — mean time from created_at to closed_at (full response)
    mttr_rows = (await db.execute(
        select(Incident.created_at, Incident.closed_at)
        .where(
            Incident.status == "closed",
            Incident.closed_at.isnot(None),
            Incident.closed_at >= cutoff,
            *mine_filter,
        )
    )).all()
    mttr_deltas = [_minutes(r.closed_at - r.created_at) for r in mttr_rows]

    # MTTC — mean time from created_at to contained_at
    mttc_rows = (await db.execute(
        select(Incident.created_at, Incident.contained_at)
        .where(Incident.contained_at.isnot(None), Incident.contained_at >= cutoff, *mine_filter)
    )).all()
    mttc_deltas = [_minutes(r.contained_at - r.created_at) for r in mttc_rows]

    # Opened in the 30-day window (count)
    opened_30d = (await db.execute(
        select(func.count())
        .select_from(Incident)
        .where(Incident.created_at >= cutoff, *mine_filter)
    )).scalar() or 0

    # Closed in the 30-day window (count) — using closed_at, not status, so the
    # number tracks "incidents that completed their lifecycle in this window".
    closed_30d = (await db.execute(
        select(func.count())
        .select_from(Incident)
        .where(
            Incident.closed_at.isnot(None),
            Incident.closed_at >= cutoff,
            *mine_filter,
        )
    )).scalar() or 0

    crit_high = (open_by_sev.get("critical", 0) or 0) + (open_by_sev.get("high", 0) or 0)

    def avg(vals):
        return round(sum(vals) / len(vals), 1) if vals else None

    return {
        "open_total":          open_total,
        "open_by_sev":         open_by_sev,
        "critical_high":       crit_high,
        "opened_30d":          opened_30d,
        "closed_30d":          closed_30d,
        "closure_rate_30d":    round(closed_30d / opened_30d * 100, 1) if opened_30d else None,
        "mttd_minutes":        avg(mttd_deltas),
        "mttr_minutes":        avg(mttr_deltas),
        "mttc_minutes":        avg(mttc_deltas),
        "mttd_sample":         len(mttd_deltas),
        "mttr_sample":         len(mttr_deltas),
        "mttc_sample":         len(mttc_deltas),
        "metrics_window_days": _METRICS_DAYS,
    }


@router.get("/activity")
async def dashboard_activity(
    mine:  bool = Query(default=False),
    limit: int  = Query(default=50, ge=1, le=200),
    user:  User = Depends(require_analyst),
    db:    AsyncSession = Depends(get_db),
):
    cutoff = utcnow() - timedelta(days=_FEED_DAYS)
    # Scope the feed to accessible incidents — every sub-query below joins
    # Incident, so accessible_filter applies uniformly. Without it the activity
    # stream leaks titles / IOC values / timeline text of restricted incidents.
    inc_filter = [accessible_filter(user)]
    if mine:
        inc_filter.append(Incident.created_by_id == user.id)

    items: list[dict] = []

    # Incidents created (and closed) in the window
    inc_rows = (await db.execute(
        select(
            Incident.id.label("inc_id"),
            Incident.title.label("inc_title"),
            Incident.severity,
            Incident.closed_at,
            Incident.created_at,
        )
        .where(Incident.created_at >= cutoff, *inc_filter)
        .order_by(Incident.created_at.desc())
        .limit(limit)
    )).all()
    for r in inc_rows:
        items.append({
            "event_type":     "incident_created",
            "label":          r.inc_title,
            "incident_id":    str(r.inc_id),
            "incident_title": r.inc_title,
            "meta":           r.severity,
            "ts":             r.created_at.isoformat(),
        })
        if r.closed_at and r.closed_at >= cutoff:
            items.append({
                "event_type":     "incident_closed",
                "label":          r.inc_title,
                "incident_id":    str(r.inc_id),
                "incident_title": r.inc_title,
                "meta":           None,
                "ts":             r.closed_at.isoformat(),
            })

    # IOCs added
    ioc_rows = (await db.execute(
        select(
            IOC.type.label("ioc_type"),
            IOC.value.label("ioc_value"),
            IOC.added_at,
            Incident.id.label("inc_id"),
            Incident.title.label("inc_title"),
        )
        .join(Incident, IOC.incident_id == Incident.id)
        .where(IOC.added_at >= cutoff, *inc_filter)
        .order_by(IOC.added_at.desc())
        .limit(limit)
    )).all()
    for r in ioc_rows:
        items.append({
            "event_type":     "ioc_added",
            "label":          f"{r.ioc_type}:{r.ioc_value}",
            "incident_id":    str(r.inc_id),
            "incident_title": r.inc_title,
            "meta":           r.ioc_type,
            "ts":             r.added_at.isoformat(),
        })

    # Timeline events added
    tl_rows = (await db.execute(
        select(
            TimelineEvent.event_type,
            TimelineEvent.description,
            TimelineEvent.created_at,
            Incident.id.label("inc_id"),
            Incident.title.label("inc_title"),
        )
        .join(Incident, TimelineEvent.incident_id == Incident.id)
        .where(TimelineEvent.created_at >= cutoff, *inc_filter)
        .order_by(TimelineEvent.created_at.desc())
        .limit(limit)
    )).all()
    for r in tl_rows:
        items.append({
            "event_type":     "timeline_event",
            "label":          (r.description or r.event_type or "")[:120],
            "incident_id":    str(r.inc_id),
            "incident_title": r.inc_title,
            "meta":           r.event_type,
            "ts":             r.created_at.isoformat(),
        })

    # Respond actions added
    ra_rows = (await db.execute(
        select(
            RespondAction.category,
            RespondAction.title.label("ra_title"),
            RespondAction.created_at,
            Incident.id.label("inc_id"),
            Incident.title.label("inc_title"),
        )
        .join(Incident, RespondAction.incident_id == Incident.id)
        .where(RespondAction.created_at >= cutoff, *inc_filter)
        .order_by(RespondAction.created_at.desc())
        .limit(limit)
    )).all()
    for r in ra_rows:
        items.append({
            "event_type":     "respond_action",
            "label":          r.ra_title or r.category,
            "incident_id":    str(r.inc_id),
            "incident_title": r.inc_title,
            "meta":           r.category,
            "ts":             r.created_at.isoformat(),
        })

    # Evidence collected
    ev_rows = (await db.execute(
        select(
            Evidence.kind,
            Evidence.identifier,
            Evidence.collected_at,
            Incident.id.label("inc_id"),
            Incident.title.label("inc_title"),
        )
        .join(Incident, Evidence.incident_id == Incident.id)
        .where(Evidence.collected_at >= cutoff, *inc_filter)
        .order_by(Evidence.collected_at.desc())
        .limit(limit)
    )).all()
    for r in ev_rows:
        items.append({
            "event_type":     "evidence_collected",
            "label":          r.identifier,
            "incident_id":    str(r.inc_id),
            "incident_title": r.inc_title,
            "meta":           r.kind,
            "ts":             r.collected_at.isoformat(),
        })

    items.sort(key=lambda x: x["ts"], reverse=True)
    return {"items": items[:limit]}


# ─── Legal: per-incident regulatory deadline summary ──────────────────────────
# Powers the Dashboard "Legal" column. One row per incident with active legal
# obligations, each obligation summarised as { regulation, status }.

@router.get("/legal-summary")
async def dashboard_legal_summary(
    mine: bool = Query(default=False),
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
):
    # Build the same incident scope as the open-incidents table so the column
    # only includes incidents the operator is allowed to see.
    inc_filter = [accessible_filter(user)]
    if mine:
        inc_filter.append(Incident.created_by_id == user.id)

    rows = (await db.execute(
        select(
            RegulatoryDeadline.incident_id,
            RegulatoryDeadline.regulation,
            RegulatoryDeadline.status,
            RegulatoryDeadline.deadline_at,
        )
        .join(Incident, RegulatoryDeadline.incident_id == Incident.id)
        .where(*inc_filter)
        .order_by(RegulatoryDeadline.regulation)
    )).all()

    now = utcnow()
    open_statuses = {"pending", "in_progress"}
    by_incident: dict[str, list[dict]] = {}
    overdue_total = 0
    for r in rows:
        overdue = (r.status in open_statuses) and r.deadline_at < now
        if overdue:
            overdue_total += 1
        by_incident.setdefault(str(r.incident_id), []).append({
            "regulation":  r.regulation,
            "status":      r.status,
            "deadline_at": r.deadline_at.isoformat(),
            "is_overdue":  overdue,
        })
    return {"by_incident": by_incident, "overdue_total": overdue_total}


# ─── Trend — opened vs closed per day, last N days ───────────────────────────

@router.get("/trend")
async def dashboard_trend(
    days: int  = Query(default=30, ge=1, le=365),
    mine: bool = Query(default=False),
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
):
    cutoff = utcnow() - timedelta(days=days)
    # Scope the trend to accessible incidents (admins: all) + optional "mine".
    mine_filter = [accessible_filter(user)]
    if mine:
        mine_filter.append(Incident.created_by_id == user.id)

    # Opened per day — group by DATE(created_at).
    opened_rows = (await db.execute(
        select(
            cast(Incident.created_at, Date).label("d"),
            func.count().label("n"),
        )
        .where(Incident.created_at >= cutoff, *mine_filter)
        .group_by(cast(Incident.created_at, Date))
    )).all()
    opened_map = {r.d.isoformat(): r.n for r in opened_rows}

    # Closed per day — group by DATE(closed_at).
    closed_rows = (await db.execute(
        select(
            cast(Incident.closed_at, Date).label("d"),
            func.count().label("n"),
        )
        .where(
            Incident.closed_at.isnot(None),
            Incident.closed_at >= cutoff,
            *mine_filter,
        )
        .group_by(cast(Incident.closed_at, Date))
    )).all()
    closed_map = {r.d.isoformat(): r.n for r in closed_rows}

    # Build a dense series — one entry per day in the window, zero-filled.
    today = utcnow().date()
    series = []
    for i in range(days - 1, -1, -1):
        d = (today - timedelta(days=i)).isoformat()
        series.append({
            "date":   d,
            "opened": opened_map.get(d, 0),
            "closed": closed_map.get(d, 0),
        })

    return {"days": days, "series": series}


# ─── Workload — active-incident count per assignee ───────────────────────────

@router.get("/workload")
async def dashboard_workload(
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
):
    """Per-user active incident assignment count, ordered descending.

    Only counts assignments on open incidents the caller can access.
    """
    rows = (await db.execute(
        select(
            IncidentAssignment.user_id,
            IncidentAssignment.username,
            func.count(func.distinct(IncidentAssignment.incident_id)).label("n"),
        )
        .join(Incident, IncidentAssignment.incident_id == Incident.id)
        .where(
            Incident.status == "open",
            accessible_filter(user),
            IncidentAssignment.user_id.isnot(None),
        )
        .group_by(IncidentAssignment.user_id, IncidentAssignment.username)
        .order_by(func.count(func.distinct(IncidentAssignment.incident_id)).desc())
    )).all()

    return {
        "items": [
            {"user_id": str(r.user_id), "username": r.username, "active_count": r.n}
            for r in rows
        ],
    }


# ─── Top MITRE tactics — open-incident activity ──────────────────────────────

@router.get("/top-tactics")
async def dashboard_top_tactics(
    limit: int = Query(default=8, ge=1, le=20),
    user:  User = Depends(require_analyst),
    db:    AsyncSession = Depends(get_db),
):
    """Most-seen MITRE tactics across timeline events of currently-open
    incidents the caller can access.
    """
    rows = (await db.execute(
        select(
            TimelineEvent.mitre_tactic_id,
            TimelineEvent.mitre_tactic_name,
            func.count().label("n"),
        )
        .join(Incident, TimelineEvent.incident_id == Incident.id)
        .where(
            Incident.status == "open",
            TimelineEvent.mitre_tactic_id.isnot(None),
            accessible_filter(user),
        )
        .group_by(TimelineEvent.mitre_tactic_id, TimelineEvent.mitre_tactic_name)
        .order_by(func.count().desc())
        .limit(limit)
    )).all()

    return {
        "items": [
            {
                "tactic_id":   r.mitre_tactic_id,
                "tactic_name": r.mitre_tactic_name,
                "count":       r.n,
            }
            for r in rows
        ],
    }


# ─── Top tags — usage rollup across open incidents the caller can see ───────

@router.get("/top-tags")
async def dashboard_top_tags(
    scope: str  = Query(default="incident", regex="^(incident|ioc|all)$"),
    limit: int  = Query(default=8, ge=1, le=20),
    user:  User = Depends(require_analyst),
    db:    AsyncSession = Depends(get_db),
):
    """Usage-ranked tags across OPEN incidents the caller can access.

    Parallels `/dashboard/top-tactics`. We deliberately filter to open
    incidents so the widget surfaces what's active, not historical noise.
    """
    counter: dict[str, int] = {}

    def _bump(tags):
        for t in (tags or []):
            if isinstance(t, str) and t:
                counter[t] = counter.get(t, 0) + 1

    if scope in ("incident", "all"):
        rows = (await db.execute(
            select(Incident.tags)
            .where(Incident.status == "open", accessible_filter(user))
        )).scalars().all()
        for tags in rows:
            _bump(tags)

    if scope in ("ioc", "all"):
        rows = (await db.execute(
            select(IOC.tags)
            .join(Incident, IOC.incident_id == Incident.id)
            .where(Incident.status == "open", accessible_filter(user))
        )).scalars().all()
        for tags in rows:
            _bump(tags)

    items = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
    return {
        "scope": scope,
        "items": [{"tag": t, "count": n} for t, n in items],
    }
