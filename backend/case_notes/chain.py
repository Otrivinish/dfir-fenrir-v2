"""CN-2: a case note is the chain of its revisions. Revision 1 is an entry that corrects nothing; an
edit is a new entry naming the current revision in `corrects_id` (uq_case_notes_corrects_id keeps
the chain linear). `root_id` (the note's stable id = revision 1's id) and the revision number are
computed here on read -- never stored, as case_notes rows are append-only."""
import uuid

from sqlalchemy import literal, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from models import CaseNote


def chain_cte(incident_id: uuid.UUID):
    """(id, root_id, revision, root_author_id) of every case note of the incident (recursive CTE);
    root_author_id is the note's author (of revision 1)."""
    base = (select(CaseNote.id.label("id"), CaseNote.id.label("root_id"), literal(1).label("revision"),
                   CaseNote.author_id.label("root_author_id"))
            .where(CaseNote.incident_id == incident_id, CaseNote.corrects_id.is_(None))
            .cte("cn_chain", recursive=True))
    nxt = aliased(CaseNote)
    return base.union_all(
        select(nxt.id, base.c.root_id, base.c.revision + 1, base.c.root_author_id).where(nxt.corrects_id == base.c.id))


async def revision_meta(db: AsyncSession, incident_id: uuid.UUID, ids: list[uuid.UUID] | None = None
                        ) -> dict[uuid.UUID, tuple[uuid.UUID, int, uuid.UUID]]:
    """{entry id: (root_id, revision, root_author_id)} for the given entries of the incident (all when
    ids is None)."""
    c = chain_cte(incident_id)
    stmt = select(c.c.id, c.c.root_id, c.c.revision, c.c.root_author_id)
    if ids is not None:
        stmt = stmt.where(c.c.id.in_(ids))
    return {i: (r, v, a) for i, r, v, a in (await db.execute(stmt)).all()}
