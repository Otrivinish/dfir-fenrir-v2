"""Incident handoffs — shift-change snapshot per incident + global pending queue."""
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from incidents.access import get_accessible_incident
from models import (
    Entity, Incident, IncidentHandoff, IOC, PlaybookTask,
    RespondAction, TimelineEvent, User,
)
from notifications.service import notify_handoff
from schemas import (
    IncidentHandoffAcknowledge,
    IncidentHandoffCreate,
    IncidentHandoffList,
    IncidentHandoffOut,
)

router = APIRouter()


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


async def _build_snapshot(db: AsyncSession, incident_id: uuid.UUID, inc: Incident) -> dict:
    """Capture incident state counters at the moment the handoff is created."""
    ioc_count = (await db.execute(
        select(func.count()).select_from(IOC).where(IOC.incident_id == incident_id)
    )).scalar() or 0

    timeline_count = (await db.execute(
        select(func.count()).select_from(TimelineEvent).where(TimelineEvent.incident_id == incident_id)
    )).scalar() or 0

    pb_total = (await db.execute(
        select(func.count()).select_from(PlaybookTask).where(PlaybookTask.incident_id == incident_id)
    )).scalar() or 0
    pb_done = (await db.execute(
        select(func.count()).select_from(PlaybookTask).where(
            PlaybookTask.incident_id == incident_id,
            PlaybookTask.status == "done",
        )
    )).scalar() or 0

    entity_count = (await db.execute(
        select(func.count()).select_from(Entity).where(Entity.incident_id == incident_id)
    )).scalar() or 0
    compromised_count = (await db.execute(
        select(func.count()).select_from(Entity).where(
            Entity.incident_id == incident_id,
            Entity.compromised == True,  # noqa: E712
        )
    )).scalar() or 0

    respond_total = (await db.execute(
        select(func.count()).select_from(RespondAction).where(RespondAction.incident_id == incident_id)
    )).scalar() or 0
    respond_done = (await db.execute(
        select(func.count()).select_from(RespondAction).where(
            RespondAction.incident_id == incident_id,
            RespondAction.status == "done",
        )
    )).scalar() or 0

    return {
        "phase":            inc.phase,
        "severity":         inc.severity,
        "ioc_count":        ioc_count,
        "timeline_count":   timeline_count,
        "playbook_done":    pb_done,
        "playbook_total":   pb_total,
        "entity_count":     entity_count,
        "compromised_count": compromised_count,
        "respond_done":     respond_done,
        "respond_total":    respond_total,
    }


def _to_out(h: IncidentHandoff) -> IncidentHandoffOut:
    return IncidentHandoffOut.model_validate(h)


# ─── Per-incident routes ─────────────────────────────────────────────────────

@router.get("/{incident_id}/handoffs", response_model=IncidentHandoffList,
            summary="List handoffs")
async def list_handoffs(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> IncidentHandoffList:
    """List the incident's shift-change handoffs, newest first. Requires access
    to the incident.
    """
    await _get_incident(db, incident_id, user)
    rows = (await db.execute(
        select(IncidentHandoff)
        .where(IncidentHandoff.incident_id == incident_id)
        .order_by(IncidentHandoff.created_at.desc())
    )).scalars().all()
    return IncidentHandoffList(items=[_to_out(r) for r in rows])


@router.post("/{incident_id}/handoffs", response_model=IncidentHandoffOut,
             status_code=status.HTTP_201_CREATED,
             summary="Create a shift-change handoff")
async def create_handoff(
    incident_id: uuid.UUID,
    req: IncidentHandoffCreate,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> IncidentHandoffOut:
    """Create a shift-change handoff from the current analyst to an incoming
    user. Requires the analyst role; you cannot hand off to yourself, and the
    incoming user must be active. Rejected if the incident is closed. Captures a
    snapshot of incident state counters, audits and notifies the recipient, and
    returns the new handoff in `pending` status.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    if req.incoming_user_id == user.id:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "Cannot hand off to yourself")

    incoming = (await db.execute(
        select(User).where(User.id == req.incoming_user_id, User.is_active == True)  # noqa: E712
    )).scalar_one_or_none()
    if not incoming:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incoming user not found or inactive")

    snapshot = await _build_snapshot(db, incident_id, inc)

    row = IncidentHandoff(
        id=uuid.uuid4(),
        incident_id=incident_id,
        outgoing_user_id=user.id,
        outgoing_username=user.username,
        incoming_user_id=incoming.id,
        incoming_username=incoming.username,
        note=req.note,
        current_hypothesis=req.current_hypothesis,
        hypothesis_confidence=req.hypothesis_confidence,
        key_findings=req.key_findings,
        warnings=req.warnings,
        threads=req.threads or [],
        ruled_out=req.ruled_out or [],
        pending=req.pending or [],
        next_steps=req.next_steps or [],
        open_questions=req.open_questions or [],
        snapshot_data=snapshot,
    )
    db.add(row)
    await db.flush()

    await write_audit(
        db, "handoff_create",
        resource_type="handoff", resource_id=str(row.id),
        resource_label=f"{user.username} → {incoming.username}",
        details={"incident_id": str(incident_id)},
    )
    await notify_handoff(
        db,
        recipient_id=incoming.id,
        incident_id=incident_id,
        incident_ref=inc.ref or str(incident_id),
        outgoing_username=user.username,
    )
    await db.commit()
    await db.refresh(row)
    return _to_out(row)


@router.patch("/{incident_id}/handoffs/{handoff_id}/acknowledge",
              response_model=IncidentHandoffOut,
              summary="Acknowledge a handoff")
async def acknowledge_handoff(
    incident_id: uuid.UUID,
    handoff_id:  uuid.UUID,
    req: IncidentHandoffAcknowledge,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> IncidentHandoffOut:
    """Acknowledge a pending handoff, optionally with an acknowledgement note.
    Requires the analyst role; only the designated incoming analyst or an admin
    may acknowledge. Stamps `acknowledged_at`, marks the handoff acknowledged
    (no-op if already acknowledged), audits the action, and returns the handoff.
    """
    await _get_incident(db, incident_id, user)

    row = (await db.execute(
        select(IncidentHandoff).where(
            IncidentHandoff.id == handoff_id,
            IncidentHandoff.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Handoff not found")

    # Only the designated incoming analyst or an admin may acknowledge.
    if user.role != "admin" and row.incoming_user_id != user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "Only the designated incoming analyst can acknowledge this handoff")

    if row.status == "acknowledged":
        return _to_out(row)

    from models import utcnow
    row.status = "acknowledged"
    row.acknowledged_at = utcnow()
    row.acknowledged_note = req.acknowledged_note

    await write_audit(
        db, "handoff_acknowledge",
        resource_type="handoff", resource_id=str(row.id),
        resource_label=f"{row.outgoing_username} → {row.incoming_username}",
        details={"incident_id": str(incident_id)},
    )
    await db.commit()
    await db.refresh(row)
    return _to_out(row)


# ─── Global pending queue ────────────────────────────────────────────────────

pending_router = APIRouter()


@pending_router.get("/handoffs/pending", response_model=IncidentHandoffList,
                    summary="List my pending handoffs")
async def list_pending_handoffs(
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> IncidentHandoffList:
    """All pending handoffs across incidents where the current user is the
    designated incoming analyst, newest first.
    """
    rows = (await db.execute(
        select(IncidentHandoff)
        .where(
            IncidentHandoff.incoming_user_id == user.id,
            IncidentHandoff.status == "pending",
        )
        .order_by(IncidentHandoff.created_at.desc())
    )).scalars().all()
    return IncidentHandoffList(items=[_to_out(r) for r in rows])
