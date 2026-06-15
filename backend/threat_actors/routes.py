"""Threat actor library + per-incident attribution routes."""
import asyncio
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst, require_admin
from core.database import get_db
from incidents.access import accessible_filter, get_accessible_incident
from models import IOC, Incident, IncidentAttribution, ThreatActor, TimelineEvent, User
from threat_actors import scoring, sync as ta_sync
from schemas import (
    ActorIncidentLink,
    ActorIncidentLinkList,
    AttributionSuggestList,
    AttributionSuggestion,
    IncidentAttributionCreate,
    IncidentAttributionList,
    IncidentAttributionOut,
    IncidentAttributionUpdate,
    ThreatActorCreate,
    ThreatActorList,
    ThreatActorOut,
    ThreatActorUpdate,
)

# ─── Global threat actor library ─────────────────────────────────────────────

global_router = APIRouter()


def _actor_out(a: ThreatActor) -> ThreatActorOut:
    return ThreatActorOut.model_validate(a)


@global_router.get("/threat-actors", response_model=ThreatActorList,
                   summary="List threat actors")
async def list_threat_actors(
    q:          str | None = Query(default=None, description="Search name or aliases"),
    motivation: str | None = Query(default=None),
    db:         AsyncSession = Depends(get_db),
    _:          User = Depends(current_user),
) -> ThreatActorList:
    """List threat actors from the global library, ordered by name. Optional
    `q` matches name or aliases and `motivation` filters by motivation. Any
    authenticated user. Returns the matching actors (no pagination)."""
    stmt = select(ThreatActor).order_by(ThreatActor.name)
    if q:
        term = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(ThreatActor.name).like(term),
                func.cast(ThreatActor.aliases, type_=None).ilike(term),
            )
        )
    if motivation:
        stmt = stmt.where(ThreatActor.motivation == motivation)
    rows = (await db.execute(stmt)).scalars().all()
    return ThreatActorList(items=[_actor_out(r) for r in rows])


@global_router.get("/threat-actors/{actor_id}", response_model=ThreatActorOut,
                   summary="Get a threat actor")
async def get_threat_actor(
    actor_id: uuid.UUID,
    db:       AsyncSession = Depends(get_db),
    _:        User = Depends(current_user),
) -> ThreatActorOut:
    """Get a single threat actor by id. Returns 404 if unknown. Any
    authenticated user. Returns the full actor record."""
    a = await _get_actor_or_404(db, actor_id)
    return _actor_out(a)


@global_router.post("/threat-actors", response_model=ThreatActorOut,
                    status_code=status.HTTP_201_CREATED,
                    summary="Create a threat actor")
async def create_threat_actor(
    req:  ThreatActorCreate,
    user: User = Depends(require_admin),
    db:   AsyncSession = Depends(get_db),
) -> ThreatActorOut:
    """Create a custom (non-system) threat actor. Returns 409 if an actor with
    the same name already exists. Admin access required. Returns the created
    actor."""
    existing = (await db.execute(
        select(ThreatActor).where(ThreatActor.name == req.name)
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Threat actor '{req.name}' already exists")

    actor = ThreatActor(
        id=uuid.uuid4(),
        name=req.name,
        aliases=req.aliases,
        description=req.description,
        country_of_origin=req.country_of_origin,
        motivation=req.motivation,
        associated_techniques=req.associated_techniques,
        typical_targets=req.typical_targets,
        is_system=False,
    )
    db.add(actor)
    await db.commit()
    await db.refresh(actor)
    return _actor_out(actor)


@global_router.patch("/threat-actors/{actor_id}", response_model=ThreatActorOut,
                     summary="Update a threat actor")
async def update_threat_actor(
    actor_id: uuid.UUID,
    req:      ThreatActorUpdate,
    user:     User = Depends(require_admin),
    db:       AsyncSession = Depends(get_db),
) -> ThreatActorOut:
    """Update a custom threat actor (only the supplied fields change). Locked
    for `is_system=True` rows — those are MITRE-synced and shouldn't drift from
    the upstream catalogue, so they return 409. Returns 404 if unknown. Admin
    access required. Returns the updated actor."""
    actor = await _get_actor_or_404(db, actor_id)
    if actor.is_system:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "System threat actors are read-only (synced from MITRE ATT&CK)",
        )
    for field, value in req.model_dump(exclude_unset=True).items():
        setattr(actor, field, value)
    await db.commit()
    await db.refresh(actor)
    return _actor_out(actor)


@global_router.delete("/threat-actors/{actor_id}", status_code=status.HTTP_204_NO_CONTENT,
                      summary="Delete a threat actor")
async def delete_threat_actor(
    actor_id: uuid.UUID,
    user:     User = Depends(require_admin),
    db:       AsyncSession = Depends(get_db),
) -> None:
    """Delete a custom threat actor. System (MITRE-synced) actors cannot be
    deleted and return 409; unknown ids return 404. Admin access required.
    Returns 204 No Content."""
    actor = await _get_actor_or_404(db, actor_id)
    if actor.is_system:
        raise HTTPException(status.HTTP_409_CONFLICT, "System threat actors cannot be deleted")
    await db.delete(actor)
    await db.commit()


# ─── Cross-reference: incidents attributed to a given actor ──────────────────

@global_router.get(
    "/threat-actors/{actor_id}/attributions",
    response_model=ActorIncidentLinkList,
    summary="List incidents attributed to an actor",
)
async def list_actor_attributions(
    actor_id: uuid.UUID,
    user:     User = Depends(current_user),
    db:       AsyncSession = Depends(get_db),
) -> ActorIncidentLinkList:
    """Return all incidents this actor is attributed to that the caller is
    permitted to see. Powers the per-actor "Linked incidents" panel on the
    `/threat-actors` browser page."""
    await _get_actor_or_404(db, actor_id)
    from models import Incident as _Inc   # local import to keep top-line list short

    rows = (await db.execute(
        select(
            IncidentAttribution.id.label("attribution_id"),
            IncidentAttribution.confidence,
            IncidentAttribution.score,
            IncidentAttribution.created_at,
            IncidentAttribution.created_by_username,
            _Inc.id.label("incident_id"),
            _Inc.incident_number,
            _Inc.title,
            _Inc.status,
            _Inc.severity,
        )
        .join(_Inc, IncidentAttribution.incident_id == _Inc.id)
        .where(
            IncidentAttribution.threat_actor_id == actor_id,
            accessible_filter(user),
        )
        .order_by(IncidentAttribution.created_at.desc())
    )).all()

    return ActorIncidentLinkList(items=[
        ActorIncidentLink(
            attribution_id=r.attribution_id,
            incident_id=r.incident_id,
            incident_ref=f"INC-{r.incident_number:04d}" if r.incident_number else None,
            incident_title=r.title,
            incident_status=r.status,
            severity=r.severity,
            confidence=r.confidence,
            score=r.score,
            attributed_at=r.created_at,
            attributed_by=r.created_by_username,
        )
        for r in rows
    ])


async def _get_actor_or_404(db: AsyncSession, actor_id: uuid.UUID) -> ThreatActor:
    a = (await db.execute(
        select(ThreatActor).where(ThreatActor.id == actor_id)
    )).scalar_one_or_none()
    if not a:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Threat actor not found")
    return a


# ─── Per-incident attribution ────────────────────────────────────────────────

incident_router = APIRouter()


def _attr_out(a: IncidentAttribution) -> IncidentAttributionOut:
    return IncidentAttributionOut.model_validate(a)


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User):
    return await get_accessible_incident(db, incident_id, user)


async def _get_attribution(
    db: AsyncSession, incident_id: uuid.UUID, attribution_id: uuid.UUID
) -> IncidentAttribution:
    row = (await db.execute(
        select(IncidentAttribution).where(
            IncidentAttribution.id == attribution_id,
            IncidentAttribution.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Attribution not found")
    return row


@incident_router.get("/{incident_id}/attributions", response_model=IncidentAttributionList,
                     summary="List incident attributions")
async def list_attributions(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db:   AsyncSession = Depends(get_db),
) -> IncidentAttributionList:
    """List the threat-actor attributions recorded for an incident, oldest
    first. The caller must be able to access the incident (404 otherwise).
    Returns the attribution list."""
    await _get_incident(db, incident_id, user)
    rows = (await db.execute(
        select(IncidentAttribution)
        .where(IncidentAttribution.incident_id == incident_id)
        .order_by(IncidentAttribution.created_at)
    )).scalars().all()
    return IncidentAttributionList(items=[_attr_out(r) for r in rows])


@incident_router.post("/{incident_id}/attributions", response_model=IncidentAttributionOut,
                      status_code=status.HTTP_201_CREATED,
                      summary="Create an incident attribution")
async def create_attribution(
    incident_id: uuid.UUID,
    req:  IncidentAttributionCreate,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> IncidentAttributionOut:
    """Attribute an incident to a threat actor, either by `threat_actor_id`
    (library actor) or a free-text `actor_label`; one of the two is required.
    Rejects closed incidents (409). Analyst access required and the caller must
    be able to access the incident. Returns the created attribution."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    actor_label = req.actor_label
    if req.threat_actor_id:
        actor = await _get_actor_or_404(db, req.threat_actor_id)
        actor_label = actor.name

    if not req.threat_actor_id and not actor_label:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Provide either threat_actor_id or actor_label",
        )

    row = IncidentAttribution(
        id=uuid.uuid4(),
        incident_id=incident_id,
        threat_actor_id=req.threat_actor_id,
        actor_label=actor_label,
        confidence=req.confidence,
        score=req.score,
        evidence=req.evidence,
        analyst_notes=req.analyst_notes,
        supporting_ioc_ids=req.supporting_ioc_ids,
        supporting_timeline_ids=req.supporting_timeline_ids,
        created_by_id=user.id,
        created_by_username=user.username,
    )
    db.add(row)
    await db.flush()

    await write_audit(
        db, "attribution_create",
        resource_type="attribution", resource_id=str(row.id),
        resource_label=f"{actor_label} ({req.confidence})",
        details={"incident_id": str(incident_id)},
    )
    await db.commit()
    await db.refresh(row)
    return _attr_out(row)


@incident_router.patch("/{incident_id}/attributions/{attribution_id}",
                       response_model=IncidentAttributionOut,
                       summary="Update an incident attribution")
async def update_attribution(
    incident_id:    uuid.UUID,
    attribution_id: uuid.UUID,
    req:  IncidentAttributionUpdate,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> IncidentAttributionOut:
    """Update an incident attribution (only the supplied fields change).
    Rejects closed incidents (409) and returns 404 for unknown incident or
    attribution. Analyst access required and the caller must be able to access
    the incident. Returns the updated attribution."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    row = await _get_attribution(db, incident_id, attribution_id)

    for field, value in req.model_dump(exclude_unset=True).items():
        setattr(row, field, value)

    await write_audit(
        db, "attribution_update",
        resource_type="attribution", resource_id=str(row.id),
        resource_label=row.actor_label or "unknown",
        details={"incident_id": str(incident_id)},
    )
    await db.commit()
    await db.refresh(row)
    return _attr_out(row)


@incident_router.delete("/{incident_id}/attributions/{attribution_id}",
                        status_code=status.HTTP_204_NO_CONTENT,
                        summary="Delete an incident attribution")
async def delete_attribution(
    incident_id:    uuid.UUID,
    attribution_id: uuid.UUID,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> None:
    """Delete an attribution from an incident. Rejects closed incidents (409)
    and returns 404 for unknown incident or attribution. Analyst access
    required and the caller must be able to access the incident. Returns 204
    No Content."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    row = await _get_attribution(db, incident_id, attribution_id)

    await write_audit(
        db, "attribution_delete",
        resource_type="attribution", resource_id=str(row.id),
        resource_label=row.actor_label or "unknown",
        details={"incident_id": str(incident_id)},
    )
    await db.delete(row)
    await db.commit()


# ─── Attribution suggestion engine ───────────────────────────────────────────
# Three scoring signals (see threat_actors.scoring):
#   ttp_match     — incident timeline technique ∩ actor MITRE techniques
#   malware_match — actor software name appearing in incident IOC values
#   victimology   — incident_type → motivation map matches actor's motivation
# The first call after a cold start triggers a MITRE ATT&CK sync (background
# task with sync_lock) so subsequent calls hit a warm catalogue.

@incident_router.get("/{incident_id}/attributions/suggest",
                     response_model=AttributionSuggestList,
                     summary="Suggest threat actors for an incident")
async def suggest_attributions(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db:   AsyncSession = Depends(get_db),
) -> AttributionSuggestList:
    """Score and rank candidate threat actors for an incident using three
    signals (TTP overlap, malware/software name in IOCs, victimology) and
    return the top 10, skipping already-attributed actors. On a cold MITRE
    catalogue it kicks off a background sync and flags `cache_warming`. The
    caller must be able to access the incident. Returns ranked suggestions
    with per-actor evidence and incident technique/IOC counts."""
    inc = await _get_incident(db, incident_id, user)

    # Cold-start: kick off the MITRE sync as a background task — don't block
    # the request. Already-warm calls fall through to scoring immediately.
    cache_warming = False
    if not ta_sync.status()["synced"]:
        cache_warming = True
        try:
            asyncio.create_task(ta_sync.sync())
        except Exception:
            pass

    # Timeline techniques (with names for evidence strings).
    tech_rows = (await db.execute(
        select(TimelineEvent.mitre_technique_id, TimelineEvent.mitre_technique_name)
        .where(
            TimelineEvent.incident_id == incident_id,
            TimelineEvent.mitre_technique_id.is_not(None),
        )
    )).all()
    incident_techniques: set[str] = {(r[0] or "").upper() for r in tech_rows if r[0]}
    technique_name_map: dict[str, str] = {
        (r[0] or "").upper(): (r[1] or "") for r in tech_rows if r[0]
    }

    # IOC values for the malware_match signal.
    ioc_rows = (await db.execute(
        select(IOC.value).where(IOC.incident_id == incident_id)
    )).scalars().all()
    incident_ioc_values = [v for v in ioc_rows if v]

    # Skip actors already attributed so the modal only shows new candidates.
    existing_rows = (await db.execute(
        select(IncidentAttribution.threat_actor_id)
        .where(
            IncidentAttribution.incident_id == incident_id,
            IncidentAttribution.threat_actor_id.is_not(None),
        )
    )).scalars().all()
    already_attributed = {str(r) for r in existing_rows if r}

    all_actors = (await db.execute(select(ThreatActor))).scalars().all()

    suggestions: list[AttributionSuggestion] = []
    for actor in all_actors:
        if str(actor.id) in already_attributed:
            continue
        evidence = scoring.build_evidence_for_actor(
            actor_techniques=actor.associated_techniques or [],
            actor_software=actor.software or [],
            actor_motivation=actor.motivation or "",
            incident_techniques=incident_techniques,
            incident_technique_name_map=technique_name_map,
            incident_ioc_values=incident_ioc_values,
            incident_type=inc.incident_type or "",
        )
        if not evidence:
            continue
        score = scoring.calculate_score(evidence)
        suggestions.append(AttributionSuggestion(
            actor=_actor_out(actor),
            score=score,
            confidence=scoring.score_to_confidence(score),
            evidence=evidence,
            matched_techniques=[e["technique_id"] for e in evidence if e.get("technique_id")],
        ))

    suggestions.sort(key=lambda s: s.score, reverse=True)

    return AttributionSuggestList(
        incident_technique_count=len(incident_techniques),
        incident_ioc_count=len(incident_ioc_values),
        cache_warming=cache_warming,
        suggestions=suggestions[:10],
    )


# ─── Admin: manual sync trigger ──────────────────────────────────────────────

@global_router.post("/threat-actors/sync", status_code=status.HTTP_202_ACCEPTED,
                    summary="Sync threat actors from MITRE")
async def trigger_mitre_sync(
    force: bool = Query(default=False),
    _:     User = Depends(require_admin),
) -> dict:
    """Kick off a MITRE ATT&CK sync in the background. Returns 202 immediately
    so the admin UI doesn't have to wait the ~5 s the bundle fetch + parse
    takes. Status is polled via GET `/threat-actors/sync-status`."""
    asyncio.create_task(ta_sync.sync(force=force))
    return {"started": True, "force": force, **ta_sync.status()}


@global_router.get("/threat-actors/sync-status", summary="Get MITRE sync status")
async def mitre_sync_status(
    _: User = Depends(current_user),
) -> dict:
    """Return the current MITRE ATT&CK sync status (whether the catalogue is
    synced, in progress, last run, etc.). Any authenticated user. Returns the
    sync status dict."""
    return ta_sync.status()
