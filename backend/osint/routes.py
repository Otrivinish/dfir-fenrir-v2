"""OSINT enrichment endpoints.

Mounted at prefix="/api/osint" — not incident-scoped.
Enrichment is a global service; results are cached per (tool, indicator).
The caller selects which sources to query per indicator.
"""
import asyncio

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user
from core.database import get_db
from core.errors import ApiErrorBody
from core.outbound_policy import OPEN_TLP, require_outbound_confirmation
from incidents.access import accessible_filter, get_accessible_incident
from models import IOC, Incident, User
from schemas import EnrichRequest, EnrichResponse, EnrichResultItem, OsintSourceOut, OsintSourcesResponse

from .service import SOURCES, enrich_one, source_available

router = APIRouter()


@router.get("/sources", response_model=OsintSourcesResponse,
            summary="List OSINT enrichment sources")
async def list_sources(
    _: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> OsintSourcesResponse:
    """Return all configured enrichment sources and their availability."""
    out = []
    for sid, meta in SOURCES.items():
        out.append(OsintSourceOut(
            id=sid,
            label=meta["label"],
            description=meta["description"],
            available=await source_available(sid, db),
            public=meta["public"],
            supported_types=meta["supported_types"],
        ))
    return OsintSourcesResponse(sources=out)


async def _policy_incident(db: AsyncSession, req: EnrichRequest, user: User):
    """The incident whose outbound policy governs this lookup: `incident_id` when given
    (access-checked, 404 otherwise); else the first incident the caller can see that holds the
    indicator as an IOC and blocks automatic outbound (Dark Operation or TLP:RED); else None."""
    if req.incident_id:
        return await get_accessible_incident(db, req.incident_id, user)
    return (await db.execute(
        select(Incident).join(IOC, IOC.incident_id == Incident.id)
        .where(func.lower(IOC.value) == req.indicator.strip().lower(), accessible_filter(user),
               or_(Incident.dark_operation.is_not(False), Incident.tlp.not_in(OPEN_TLP)))
        .order_by(Incident.created_at).limit(1)
    )).scalars().first()


@router.post("/enrich", response_model=EnrichResponse,
             summary="Enrich an indicator (OSINT)",
             responses={404: {"model": ApiErrorBody, "description": "incident_id not found or not accessible"},
                        409: {"model": ApiErrorBody, "description": "outbound_confirmation_required (Dark "
                              "Operation or TLP:RED incident; body has `reason`)"}})
async def enrich_indicator(
    req: EnrichRequest,
    request: Request,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> EnrichResponse:
    """Enrich a single indicator with one or more selected sources in parallel.

    Records one audit entry per call covering every source requested (not one per
    source) -- the indicator value/type/sources are logged, since an indicator is not
    sensitive in the way a note or comment body is; it's the same value that would be
    logged the moment it's added as an IOC.

    Outbound policy (H3): when `incident_id` is given -- or, without it, when an
    incident you can see holds this indicator as an IOC -- and that incident is
    Dark Operation or TLP:RED, the call is 409 outbound_confirmation_required
    unless `confirm_outbound` is true; a confirmed lookup is audited first as
    `outbound_manual_lookup` on that incident (sources, type; no value).
    """
    # Deduplicate requested sources while preserving order
    seen: set[str] = set()
    sources = [s for s in req.sources if not (s in seen or seen.add(s))]  # type: ignore[func-returns-value]
    inc = await _policy_incident(db, req, user)
    if inc is not None:
        await require_outbound_confirmation(db, inc, confirm=req.confirm_outbound, kind="osint_enrich",
                                            user=user, request=request, providers=sources, ioc_type=req.ioc_type)

    tasks = [enrich_one(db, req.indicator, req.ioc_type, source) for source in sources]
    raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    results: list[EnrichResultItem] = []
    for source, raw in zip(sources, raw_results):
        if isinstance(raw, Exception):
            results.append(EnrichResultItem(
                source=source, available=True, from_cache=False,
                data=None, error=str(raw),
            ))
        else:
            results.append(EnrichResultItem(source=source, **raw))

    await write_audit(
        db, "osint_enrich",
        user_id=user.id, username=user.username,
        resource_type="osint_indicator", resource_id=req.indicator,
        details={"ioc_type": req.ioc_type, "sources": sources},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    return EnrichResponse(indicator=req.indicator, ioc_type=req.ioc_type, results=results)
