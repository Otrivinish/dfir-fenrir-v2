"""OSINT enrichment endpoints.

Mounted at prefix="/api/osint" — not incident-scoped.
Enrichment is a global service; results are cached per (tool, indicator).
The caller selects which sources to query per indicator.
"""
import asyncio

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import current_user
from core.database import get_db
from models import User
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


@router.post("/enrich", response_model=EnrichResponse,
             summary="Enrich an indicator (OSINT)")
async def enrich_indicator(
    req: EnrichRequest,
    _: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> EnrichResponse:
    """Enrich a single indicator with one or more selected sources in parallel."""
    # Deduplicate requested sources while preserving order
    seen: set[str] = set()
    sources = [s for s in req.sources if not (s in seen or seen.add(s))]  # type: ignore[func-returns-value]

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

    return EnrichResponse(indicator=req.indicator, ioc_type=req.ioc_type, results=results)
