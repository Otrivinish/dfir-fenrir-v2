"""LOLBins & GTFOBins reference database API."""
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status

from auth.deps import current_user, require_admin
from models import User
import lolbins.service as svc

router = APIRouter()


@router.get("/status", summary="Get LOLBins database status")
async def get_status(_: User = Depends(current_user)) -> dict:
    """Return the status of the LOLBins/GTFOBins reference database.

    Reports load state and last-sync information. Requires an authenticated user.
    """
    return svc.status()


@router.post("/sync", status_code=status.HTTP_202_ACCEPTED,
             summary="Force re-sync of the LOLBins database")
async def force_sync(
    background_tasks: BackgroundTasks,
    _: User = Depends(require_admin),
) -> dict:
    """Trigger a full re-sync from upstream (admin only). Runs in background."""
    svc._last_sync = 0.0
    background_tasks.add_task(svc.sync, force=True)
    return {"message": "Sync started in background"}


@router.get("/lookup", summary="Look up a LOLBin")
async def lookup_binary(
    name: str = Query(..., min_length=1, max_length=100),
    _: User = Depends(current_user),
) -> dict:
    """Exact binary name lookup — strips .exe, case-insensitive."""
    await svc.ensure_loaded()
    entry = svc.lookup(name)
    if not entry:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            f"'{name}' not found in LOLBins/GTFOBins database")
    return entry


@router.get("/search", summary="Search LOLBins and GTFOBins")
async def search(
    q:        str          = Query(default="", max_length=100),
    platform: Optional[str] = Query(default=None, pattern="^(windows|linux)$"),
    _: User = Depends(current_user),
) -> list:
    """Full-text search across names, descriptions, technique types."""
    await svc.ensure_loaded()
    if not q:
        return svc.get_all(platform)
    return svc.search(q, platform)


@router.get("/check-text", summary="Scan text for LOLBin mentions")
async def check_text(
    text: str = Query(..., max_length=2000),
    _: User = Depends(current_user),
) -> dict:
    """Scan free text for LOLBin/GTFOBin mentions (used by timeline enrichment)."""
    await svc.ensure_loaded()
    matches = svc.lookup_in_text(text)
    return {"matches": matches, "count": len(matches)}
