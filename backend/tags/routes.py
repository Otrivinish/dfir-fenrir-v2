"""Tag typeahead — distinct tag values across rows the caller can see.

Powers the `<TagInput>` typeahead in the UI. Tag suggestions are ranked by
usage count (descending) so the most-used tag in the platform surfaces first,
then alphabetically. Access-controlled per scope (incident-tag suggestions
are filtered by `accessible_filter`).
"""
from collections import Counter
from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import current_user
from core.database import get_db
from incidents.access import accessible_filter
from models import IOC, Incident, User

router = APIRouter()

Scope = Literal["incident", "ioc", "all"]


@router.get("")
async def list_tags(
    scope: Scope = Query(default="all"),
    q:     str   = Query(default="", description="Substring filter on tag name"),
    limit: int   = Query(default=50, ge=1, le=200),
    user:  User  = Depends(current_user),
    db:    AsyncSession = Depends(get_db),
) -> dict:
    """Return `{items: [{tag, count, scope}], total}` — usage-ranked tag suggestions.

    `scope=incident` walks all incidents the caller can access; `scope=ioc`
    walks IOCs on those same incidents; `scope=all` merges both with the IOC
    count subsumed into the same bucket so a tag used in both contexts shows
    one row with combined count.
    """
    needle = (q or "").strip().lower()
    counter: Counter[str] = Counter()
    tag_scopes: dict[str, set[str]] = {}

    def _bump(tag: str, where: str) -> None:
        if not isinstance(tag, str):
            return
        t = tag.strip().lower()
        if not t:
            return
        if needle and needle not in t:
            return
        counter[t] += 1
        tag_scopes.setdefault(t, set()).add(where)

    if scope in ("incident", "all"):
        rows = (await db.execute(
            select(Incident.tags).where(accessible_filter(user))
        )).scalars().all()
        for tags in rows:
            for t in (tags or []):
                _bump(t, "incident")

    if scope in ("ioc", "all"):
        rows = (await db.execute(
            select(IOC.tags)
            .join(Incident, IOC.incident_id == Incident.id)
            .where(accessible_filter(user))
        )).scalars().all()
        for tags in rows:
            for t in (tags or []):
                _bump(t, "ioc")

    items = sorted(
        counter.items(),
        key=lambda kv: (-kv[1], kv[0]),
    )[:limit]
    return {
        "items": [
            {"tag": t, "count": n, "scopes": sorted(tag_scopes.get(t, []))}
            for t, n in items
        ],
        "total": len(counter),
    }
