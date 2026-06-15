"""Per-incident OSINT session CRUD.

Mounted at prefix="/api/incidents".
Each session stores the raw pasted text, extracted indicators, and enrichment
results so the analyst can reload their work after a page refresh.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import current_user, require_analyst
from core.database import get_db
from incidents.access import get_accessible_incident
from models import Incident, OSINTSession, User
from schemas import (
    OSINTSessionCreate,
    OSINTSessionList,
    OSINTSessionOut,
    OSINTSessionUpdate,
)

router = APIRouter()


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


@router.get("/{incident_id}/osint/sessions", response_model=OSINTSessionList,
            summary="List OSINT sessions for an incident")
async def list_osint_sessions(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> OSINTSessionList:
    """List the most recent OSINT sessions for an incident (up to 20, newest first).

    Requires access to the incident. Returns each session's raw text, extracted
    indicators, and cached enrichment results.
    """
    await _get_incident(db, incident_id, user)
    rows = (await db.execute(
        select(OSINTSession)
        .where(OSINTSession.incident_id == incident_id)
        .order_by(OSINTSession.created_at.desc())
        .limit(20)
    )).scalars().all()
    return OSINTSessionList(sessions=[OSINTSessionOut.model_validate(r) for r in rows])


@router.post("/{incident_id}/osint/sessions",
             response_model=OSINTSessionOut,
             status_code=status.HTTP_201_CREATED,
             summary="Create an OSINT session")
async def create_osint_session(
    incident_id: uuid.UUID,
    req: OSINTSessionCreate,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> OSINTSessionOut:
    """Create a new OSINT session storing the raw pasted text and extracted indicators.

    Enrichment results start empty and are filled in via later updates. Requires the
    analyst role and access to the incident. Returns the created session.
    """
    await _get_incident(db, incident_id, user)
    session = OSINTSession(
        id=uuid.uuid4(),
        incident_id=incident_id,
        raw_text=req.raw_text,
        indicators=req.indicators,
        results={},
        created_by_id=user.id,
        created_by=user.username,
    )
    db.add(session)
    await db.commit()
    return OSINTSessionOut.model_validate(session)


@router.patch("/{incident_id}/osint/sessions/{session_id}",
              response_model=OSINTSessionOut,
              summary="Update an OSINT session")
async def update_osint_session(
    incident_id: uuid.UUID,
    session_id:  uuid.UUID,
    req: OSINTSessionUpdate,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> OSINTSessionOut:
    """Partially update an OSINT session's raw text, indicators, and/or enrichment results.

    Only the provided fields are changed; omitted fields are left untouched. Requires the
    analyst role and access to the incident. Returns 404 if the session does not exist for
    that incident, otherwise the updated session.
    """
    await _get_incident(db, incident_id, user)
    session = (await db.execute(
        select(OSINTSession).where(
            OSINTSession.id == session_id,
            OSINTSession.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not session:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")

    if req.raw_text   is not None: session.raw_text   = req.raw_text
    if req.indicators is not None: session.indicators = req.indicators
    if req.results    is not None: session.results    = req.results

    await db.commit()
    return OSINTSessionOut.model_validate(session)


@router.delete("/{incident_id}/osint/sessions/{session_id}",
               status_code=status.HTTP_204_NO_CONTENT,
               summary="Delete an OSINT session")
async def delete_osint_session(
    incident_id: uuid.UUID,
    session_id:  uuid.UUID,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete an OSINT session.

    Requires the analyst role and access to the incident. Returns 404 if the session does
    not exist for that incident, otherwise 204 with no body.
    """
    await _get_incident(db, incident_id, user)
    session = (await db.execute(
        select(OSINTSession).where(
            OSINTSession.id == session_id,
            OSINTSession.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not session:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    await db.delete(session)
    await db.commit()
