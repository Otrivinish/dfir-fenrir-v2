"""TE — the one rule that resolves a typed value (a timeline event's host, a name typed in a picker)
to an entity of the incident. Used by the timeline (suggestions, bulk link), the importers and
`GET …/entities?match=`.

Rule (D2): the text equals the entity's value case-insensitively, both trimmed. Several matches
(the unique key is case-sensitive, so `DC01` and `dc01` can both exist, or a host and a service
share a name) narrow to the exact-case match, then to the host; still more than one = no match.
Any entity type matches: for cloud sources the parser stores the user / principal in `hostname`.
"""
import uuid
from typing import Iterable, NamedTuple, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from models import Entity


class EntityRef(NamedTuple):
    id:          uuid.UUID
    type:        str
    value:       str
    compromised: bool


def _key(text: Optional[str]) -> str:
    return (text or "").strip().lower()


async def load_index(db: AsyncSession, incident_id: uuid.UUID,
                     texts: Optional[Iterable[Optional[str]]] = None) -> dict[str, list[EntityRef]]:
    """The incident's entities keyed by matching key, in one query. With `texts`, only the entities
    those texts can match (a page of events); without, all of them (an import)."""
    stmt = select(Entity.id, Entity.type, Entity.value, Entity.compromised).where(Entity.incident_id == incident_id)
    if texts is not None:
        keys = {_key(t) for t in texts} - {""}
        if not keys:
            return {}
        stmt = stmt.where(func.lower(func.trim(Entity.value)).in_(keys))
    index: dict[str, list[EntityRef]] = {}
    for row in (await db.execute(stmt)).all():
        index.setdefault(_key(row.value), []).append(EntityRef(*row))
    return index


def match(index: dict[str, list[EntityRef]], text: Optional[str]) -> Optional[EntityRef]:
    """The entity `text` resolves to, or None (no match, or still ambiguous after the tie-breaks)."""
    pool = index.get(_key(text), [])
    if len(pool) > 1:
        exact = [e for e in pool if e.value.strip() == (text or "").strip()]
        pool = exact or pool
    if len(pool) > 1:
        hosts = [e for e in pool if e.type == "host"]
        pool = hosts or pool
    return pool[0] if len(pool) == 1 else None


def link_rows(index: dict[str, list[EntityRef]], rows: list[dict]) -> None:
    """Importers: set `entity_id` on new timeline_events row dicts to the entity their hostname resolves
    to (rows that already name an entity keep it). Every row gets the key, None when nothing matches:
    a multi-row INSERT needs the same columns in every row."""
    for r in rows:
        if not r.get("entity_id"):
            m = match(index, r.get("hostname"))
            r["entity_id"] = m.id if m else None
