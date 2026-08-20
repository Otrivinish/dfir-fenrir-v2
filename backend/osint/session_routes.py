"""Per-incident OSINT session CRUD.

Mounted at prefix="/api/incidents".
Each session stores the raw pasted text, extracted indicators, and enrichment
results so the analyst can reload their work after a page refresh.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
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
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> OSINTSessionOut:
    """Create a new OSINT session storing the raw pasted text and extracted indicators.

    Enrichment results start empty and are filled in via later updates. Requires the
    analyst role and access to the incident. Rejected if the incident is closed.
    Records an audit entry (metadata only -- indicator count, not the raw text or
    indicator values). Returns the created session.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

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
    await db.flush()
    await write_audit(
        db, "osint_session_create",
        user_id=user.id, username=user.username,
        resource_type="osint_session", resource_id=str(session.id),
        details={"incident_id": str(incident_id), "indicator_count": len(req.indicators)},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return OSINTSessionOut.model_validate(session)


@router.patch("/{incident_id}/osint/sessions/{session_id}",
              response_model=OSINTSessionOut,
              summary="Update an OSINT session")
async def update_osint_session(
    incident_id: uuid.UUID,
    session_id:  uuid.UUID,
    req: OSINTSessionUpdate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> OSINTSessionOut:
    """Partially update an OSINT session's raw text, indicators, and/or enrichment results.

    Only the provided fields are changed; omitted fields are left untouched. Requires the
    analyst role and access to the incident. Rejected if the incident is closed. Returns
    404 if the session does not exist for that incident. Records an audit entry (which
    fields changed, not their values). Returns the updated session.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    session = (await db.execute(
        select(OSINTSession).where(
            OSINTSession.id == session_id,
            OSINTSession.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not session:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")

    changed_fields = []
    if req.raw_text   is not None: session.raw_text   = req.raw_text;   changed_fields.append("raw_text")
    if req.indicators is not None: session.indicators = req.indicators; changed_fields.append("indicators")
    if req.results    is not None: session.results    = req.results;    changed_fields.append("results")

    if changed_fields:
        await write_audit(
            db, "osint_session_update",
            user_id=user.id, username=user.username,
            resource_type="osint_session", resource_id=str(session.id),
            details={"incident_id": str(incident_id), "changed_fields": changed_fields},
            ip_address=request.client.host if request.client else None,
        )
    await db.commit()
    return OSINTSessionOut.model_validate(session)


@router.delete("/{incident_id}/osint/sessions/{session_id}",
               status_code=status.HTTP_204_NO_CONTENT,
               summary="Delete an OSINT session")
async def delete_osint_session(
    incident_id: uuid.UUID,
    session_id:  uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete an OSINT session.

    Requires the analyst role and access to the incident. Rejected if the incident is
    closed. Returns 404 if the session does not exist for that incident. Records an
    audit entry. Otherwise 204 with no body.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    session = (await db.execute(
        select(OSINTSession).where(
            OSINTSession.id == session_id,
            OSINTSession.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not session:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")

    await write_audit(
        db, "osint_session_delete",
        user_id=user.id, username=user.username,
        resource_type="osint_session", resource_id=str(session.id),
        details={"incident_id": str(incident_id)},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(session)
    await db.commit()
