"""Portfolio-level metrics — cross-incident analytics.

Mounted at /api/metrics.  No new models; pure SQL aggregations.
"""
from collections import defaultdict
from datetime import timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import require_analyst
from core.database import get_db
from models import (
    Incident, IncidentAssignment, IOC, PlaybookTask, TimelineEvent, User, utcnow,
)

router = APIRouter()


def _week_label(dt) -> str:
    iso = dt.date().isocalendar()
    return f"{iso[0]}-W{iso[1]:02d}"


def _minutes(seconds) -> float | None:
    if seconds is None:
        return None
    f = float(seconds)
    return round(f / 60, 1) if f >= 0 else None


@router.get("")
async def portfolio_metrics(
    window_days: int = Query(default=90, ge=7, le=365),
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    cutoff = utcnow() - timedelta(days=window_days)

    # ── 1. Status summary ────────────────────────────────────────────────────

    status_rows = (await db.execute(
        select(Incident.status, func.count().label("n"))
        .group_by(Incident.status)
    )).all()
    total        = sum(r.n for r in status_rows)
    open_count   = next((r.n for r in status_rows if r.status == "open"),   0)
    closed_count = next((r.n for r in status_rows if r.status == "closed"), 0)

    phase_rows = (await db.execute(
        select(Incident.phase, func.count().label("n"))
        .where(Incident.status == "open")
        .group_by(Incident.phase)
    )).all()
    open_by_phase = {r.phase: r.n for r in phase_rows}

    sev_rows = (await db.execute(
        select(Incident.severity, func.count().label("n"))
        .group_by(Incident.severity)
    )).all()
    by_severity = {r.severity: r.n for r in sev_rows}

    # ── 2. Volume by week (incidents opened + closed) ─────────────────────

    _wk_opened = func.date_trunc("week", Incident.created_at)
    opened_rows = (await db.execute(
        select(_wk_opened.label("wk"), func.count().label("n"))
        .where(Incident.created_at >= cutoff)
        .group_by(_wk_opened)
        .order_by(_wk_opened)
    )).all()

    _wk_closed = func.date_trunc("week", Incident.closed_at)
    closed_rows = (await db.execute(
        select(_wk_closed.label("wk"), func.count().label("n"))
        .where(
            Incident.closed_at.isnot(None),
            Incident.closed_at >= cutoff,
        )
        .group_by(_wk_closed)
        .order_by(_wk_closed)
    )).all()

    week_vol: dict[str, dict] = defaultdict(lambda: {"opened": 0, "closed": 0})
    for r in opened_rows:
        week_vol[_week_label(r.wk)]["opened"] = r.n
    for r in closed_rows:
        week_vol[_week_label(r.wk)]["closed"] = r.n
    volume_by_week = [{"week": w, **d} for w, d in sorted(week_vol.items())]

    # ── 3. Severity trend (opened incidents per week by severity) ─────────

    _wk_sev = func.date_trunc("week", Incident.created_at)
    sev_trend_rows = (await db.execute(
        select(_wk_sev.label("wk"), Incident.severity, func.count().label("n"))
        .where(Incident.created_at >= cutoff)
        .group_by(_wk_sev, Incident.severity)
        .order_by(_wk_sev)
    )).all()

    sev_week: dict[str, dict] = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0})
    for r in sev_trend_rows:
        sev_week[_week_label(r.wk)][r.severity] = r.n
    severity_trend = [{"week": w, **d} for w, d in sorted(sev_week.items())]

    # ── 4. TTx by week (for closed incidents) ─────────────────────────────

    _wk_ttx = func.date_trunc("week", Incident.closed_at)
    ttx_rows = (await db.execute(
        select(
            _wk_ttx.label("wk"),
            func.avg(
                func.extract("epoch", Incident.created_at - Incident.occurred_at)
            ).label("mttd_s"),
            func.avg(
                func.extract("epoch", Incident.closed_at - Incident.created_at)
            ).label("mttr_s"),
            func.avg(
                func.extract("epoch", Incident.contained_at - Incident.created_at)
            ).label("mttc_s"),
        )
        .where(
            Incident.status == "closed",
            Incident.closed_at.isnot(None),
            Incident.closed_at >= cutoff,
        )
        .group_by(_wk_ttx)
        .order_by(_wk_ttx)
    )).all()

    ttx_by_week = [
        {
            "week": _week_label(r.wk),
            "mttd": _minutes(r.mttd_s),
            "mttr": _minutes(r.mttr_s),
            "mttc": _minutes(r.mttc_s),
        }
        for r in ttx_rows
    ]

    # ── 5. Incident types (top 10, all time) ──────────────────────────────

    type_rows = (await db.execute(
        select(Incident.incident_type, func.count().label("n"))
        .where(Incident.incident_type.isnot(None))
        .group_by(Incident.incident_type)
        .order_by(func.count().desc())
        .limit(10)
    )).all()
    incident_types = [{"type": r.incident_type, "count": r.n} for r in type_rows]

    # ── 6. Top MITRE tactics (all timeline events) ────────────────────────

    mitre_rows = (await db.execute(
        select(
            TimelineEvent.mitre_tactic_id,
            TimelineEvent.mitre_tactic_name,
            func.count().label("n"),
        )
        .where(TimelineEvent.mitre_tactic_id.isnot(None))
        .group_by(TimelineEvent.mitre_tactic_id, TimelineEvent.mitre_tactic_name)
        .order_by(func.count().desc())
        .limit(10)
    )).all()
    top_mitre_tactics = [
        {
            "tactic_id":   r.mitre_tactic_id,
            "tactic_name": r.mitre_tactic_name or r.mitre_tactic_id,
            "count":       r.n,
        }
        for r in mitre_rows
    ]

    # ── 7. IOC type distribution (all incidents) ──────────────────────────

    ioc_rows = (await db.execute(
        select(IOC.type, func.count().label("n"))
        .group_by(IOC.type)
        .order_by(func.count().desc())
    )).all()
    ioc_type_distribution = [{"type": r.type, "count": r.n} for r in ioc_rows]

    # ── 8. Analyst load — open incidents per assigned analyst ─────────────

    load_rows = (await db.execute(
        select(
            IncidentAssignment.username,
            func.count(func.distinct(IncidentAssignment.incident_id)).label("n"),
        )
        .join(Incident, Incident.id == IncidentAssignment.incident_id)
        .where(Incident.status == "open")
        .group_by(IncidentAssignment.username)
        .order_by(func.count(func.distinct(IncidentAssignment.incident_id)).desc())
        .limit(15)
    )).all()
    analyst_load = [{"username": r.username, "open_count": r.n} for r in load_rows]

    # ── 9. Playbook completion stats ──────────────────────────────────────

    pb_rows = (await db.execute(
        select(
            PlaybookTask.incident_id,
            PlaybookTask.status,
            func.count().label("n"),
        )
        .group_by(PlaybookTask.incident_id, PlaybookTask.status)
    )).all()

    pb_by_inc: dict = defaultdict(lambda: {"done": 0, "skipped": 0, "total": 0})
    for r in pb_rows:
        pb_by_inc[str(r.incident_id)]["total"] += r.n
        if r.status == "done":
            pb_by_inc[str(r.incident_id)]["done"] += r.n
        elif r.status == "skipped":
            pb_by_inc[str(r.incident_id)]["skipped"] += r.n

    completion_pcts = []
    for stats in pb_by_inc.values():
        denom = stats["total"] - stats["skipped"]
        if denom > 0:
            completion_pcts.append(stats["done"] / denom * 100)

    playbook_stats = {
        "avg_completion_pct":      round(sum(completion_pcts) / len(completion_pcts), 1) if completion_pcts else None,
        "incidents_with_playbook": len(pb_by_inc),
    }

    return {
        "window_days":            window_days,
        "status_summary": {
            "total":         total,
            "open":          open_count,
            "closed":        closed_count,
            "open_by_phase": open_by_phase,
            "by_severity":   by_severity,
        },
        "volume_by_week":         volume_by_week,
        "severity_trend":         severity_trend,
        "ttx_by_week":            ttx_by_week,
        "incident_types":         incident_types,
        "top_mitre_tactics":      top_mitre_tactics,
        "ioc_type_distribution":  ioc_type_distribution,
        "analyst_load":           analyst_load,
        "playbook_stats":         playbook_stats,
    }
