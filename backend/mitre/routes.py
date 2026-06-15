"""Per-incident MITRE ATT&CK coverage aggregation + global matrix endpoint.

router       → mounted at prefix="/api/incidents"
global_router → mounted at prefix="/api/mitre"
"""
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import current_user, require_analyst
from core.database import get_db
from incidents.access import accessible_filter, get_accessible_incident
from models import Incident, TimelineEvent, User

router = APIRouter()
global_router = APIRouter()


# ─── Global coverage schemas ──────────────────────────────────────────────────

class IncidentRef(BaseModel):
    id: uuid.UUID
    ref: Optional[str] = None
    title: str
    severity: Optional[str] = None
    model_config = {"from_attributes": True}


class TechniqueHit(BaseModel):
    tactic_id: str
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    incident_count: int
    incidents: list[IncidentRef]


class GlobalMitreCoverage(BaseModel):
    techniques: list[TechniqueHit]
    summary: dict


# ─── Global: coverage across all accessible incidents ─────────────────────────

@global_router.get("/coverage", response_model=GlobalMitreCoverage,
                   summary="Get global MITRE coverage")
async def get_global_mitre_coverage(
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> GlobalMitreCoverage:
    """
    Aggregate MITRE ATT&CK technique observations across all incidents the
    user can access. Returns per-technique incident counts and incident refs
    for the click-through detail panel.
    """
    # Step 1: distinct (tactic_id, technique_id, technique_name, incident_id) rows.
    stmt = (
        select(
            TimelineEvent.mitre_tactic_id,
            TimelineEvent.mitre_technique_id,
            TimelineEvent.mitre_technique_name,
            TimelineEvent.incident_id,
        )
        .join(Incident, Incident.id == TimelineEvent.incident_id)
        .where(
            TimelineEvent.mitre_tactic_id.isnot(None),
            accessible_filter(user),
        )
        .distinct()
    )
    rows = (await db.execute(stmt)).all()

    # Aggregate in Python: (tactic_id, technique_id) → set of incident_ids.
    tech_map: dict[tuple, dict] = {}
    all_incident_ids: set[uuid.UUID] = set()
    for row in rows:
        key = (row.mitre_tactic_id, row.mitre_technique_id)
        if key not in tech_map:
            tech_map[key] = {
                "tactic_id": row.mitre_tactic_id,
                "technique_id": row.mitre_technique_id,
                "technique_name": row.mitre_technique_name,
                "incident_ids": set(),
            }
        tech_map[key]["incident_ids"].add(row.incident_id)
        all_incident_ids.add(row.incident_id)

    # Step 2: batch-load incident refs.
    inc_map: dict[uuid.UUID, dict] = {}
    if all_incident_ids:
        inc_rows = (await db.execute(
            select(
                Incident.id,
                Incident.incident_number,
                Incident.title,
                Incident.severity,
            ).where(Incident.id.in_(all_incident_ids))
        )).all()
        for r in inc_rows:
            inc_map[r.id] = {
                "id": r.id,
                "ref": f"INC-{r.incident_number:04d}" if r.incident_number else None,
                "title": r.title,
                "severity": r.severity,
            }

    # Build response list.
    techniques = [
        TechniqueHit(
            tactic_id=data["tactic_id"],
            technique_id=data["technique_id"],
            technique_name=data["technique_name"],
            incident_count=len(data["incident_ids"]),
            incidents=[
                IncidentRef(**inc_map[iid])
                for iid in data["incident_ids"]
                if iid in inc_map
            ],
        )
        for data in tech_map.values()
    ]

    return GlobalMitreCoverage(
        techniques=techniques,
        summary={
            "tactics_observed": len({t.tactic_id for t in techniques}),
            "techniques_observed": len(techniques),
            "incidents_with_mitre": len(all_incident_ids),
        },
    )


@router.get("/{incident_id}/mitre/coverage", summary="Get incident MITRE coverage")
async def get_mitre_coverage(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Aggregate MITRE ATT&CK tactic and technique observations for a single incident.

    Groups the incident's timeline events by tactic, then by technique, with per-level event
    counts. Returns 422 for a malformed incident_id. Requires the analyst role and access to the
    incident. Returns the tactics breakdown plus a summary of tactics/techniques observed.
    """
    try:
        iid = uuid.UUID(incident_id)
    except ValueError:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid incident_id")

    await get_accessible_incident(db, iid, user)

    rows = (await db.execute(
        select(
            TimelineEvent.mitre_tactic_id,
            TimelineEvent.mitre_tactic_name,
            TimelineEvent.mitre_technique_id,
            TimelineEvent.mitre_technique_name,
        ).where(
            TimelineEvent.incident_id == iid,
            TimelineEvent.mitre_tactic_id.isnot(None),
        )
    )).all()

    # tactic_id → { tactic_name, event_count, techniques: { technique_id → { name, count } } }
    tactics: dict[str, dict] = {}
    for row in rows:
        tac = row.mitre_tactic_id
        if tac not in tactics:
            tactics[tac] = {
                "tactic_id": tac,
                "tactic_name": row.mitre_tactic_name,
                "event_count": 0,
                "techniques": {},
            }
        tactics[tac]["event_count"] += 1

        if row.mitre_technique_id:
            tid = row.mitre_technique_id
            techs = tactics[tac]["techniques"]
            if tid not in techs:
                techs[tid] = {
                    "technique_id": tid,
                    "technique_name": row.mitre_technique_name,
                    "event_count": 0,
                }
            techs[tid]["event_count"] += 1

    result_tactics = [
        {
            "tactic_id": t["tactic_id"],
            "tactic_name": t["tactic_name"],
            "event_count": t["event_count"],
            "techniques": list(t["techniques"].values()),
        }
        for t in tactics.values()
    ]

    total_techniques = sum(len(t["techniques"]) for t in tactics.values())

    return {
        "incident_id": str(iid),
        "tactics": result_tactics,
        "summary": {
            "tactics_observed": len(tactics),
            "techniques_observed": total_techniques,
        },
    }
