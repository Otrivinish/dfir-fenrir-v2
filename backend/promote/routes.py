"""J4 (R33): promote a War Room message or an incident comment to a timeline event or a Respond decision.

The new record keeps a soft reference to its source (promoted_from_kind + promoted_from_id, no FK, so it
survives the message being deleted). One message promotes at most once per kind of record (partial
UNIQUE index; 409 already_promoted).
"""
import uuid

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import require_analyst
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from incidents.access import get_accessible_incident
from models import ChatMessage, Comment, Decision, TimelineEvent, User
from respond.routes import add_decision_timeline_event
from schemas import PromoteRequest, PromoteResult

router = APIRouter()

_SOURCES = {"warroom": (ChatMessage, "War Room"), "comment": (Comment, "Comments")}


@router.post("/{incident_id}/promote", response_model=PromoteResult, status_code=status.HTTP_201_CREATED,
             summary="Promote a War Room message or comment",
             responses={404: {"model": ApiErrorBody, "description": "message_not_found (unknown, or on another "
                                                                    "incident)"},
                        409: {"model": ApiErrorBody, "description": "incident_closed, already_promoted"}})
async def promote_message(
    incident_id: uuid.UUID,
    req: PromoteRequest,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> PromoteResult:
    """Turn a War Room message (`source_kind` warroom) or a comment (`comment`) of THIS incident into a
    timeline event (`target` timeline_event) or a Respond decision (`decision`).

    `text` (default: the message text) becomes the event description / decision summary; `event_time`
    (UTC, default: the message's time) the event time / decided_at. A decision takes `outcome` (default
    pending) and `rationale`, and gets the usual Decision system timeline event. The timeline event is an
    ordinary analyst event (origin manual, source "War Room" / "Comments", type "Note"), editable later.
    The new record carries `promoted_from_kind` / `promoted_from_id`; the promotion is audited
    (`message_promote`). Requires the analyst role; 404 message_not_found (unknown or another
    incident's), 409 incident_closed, 409 already_promoted (this message already made that kind of record).
    """
    inc = await get_accessible_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")
    model, source_label = _SOURCES[req.source_kind]
    msg = await db.get(model, req.source_id)
    if msg is None or msg.incident_id != incident_id:
        raise ApiError(status.HTTP_404_NOT_FOUND, "message_not_found",
                       "No such message on this incident (War Room messages and comments of this incident only).")
    target_model = TimelineEvent if req.target == "timeline_event" else Decision
    existing = (await db.execute(select(target_model.id).where(
        target_model.promoted_from_kind == req.source_kind,
        target_model.promoted_from_id == req.source_id))).scalar_one_or_none()
    if existing:
        raise ApiError(status.HTTP_409_CONFLICT, "already_promoted",
                       f"This message is already promoted to a {req.target.replace('_', ' ')} ({existing}).")

    text = (req.text if req.text is not None else msg.body).strip()[:4096]
    if not text:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "text_required", "The text can't be empty.")
    when = req.event_time or msg.created_at

    if req.target == "timeline_event":
        rec = TimelineEvent(
            id=uuid.uuid4(), incident_id=incident_id, event_time=when, source=source_label,
            event_type="Note", description=text, origin="manual", is_system=False, external_safe=True,
            created_by_id=user.id, promoted_from_kind=req.source_kind, promoted_from_id=req.source_id,
        )
    else:
        rec = Decision(
            id=uuid.uuid4(), incident_id=incident_id, summary=text, rationale=req.rationale,
            outcome=req.outcome or "pending", decided_at=when, tags=[], created_by_id=user.id,
            promoted_from_kind=req.source_kind, promoted_from_id=req.source_id,
        )
    db.add(rec)
    try:
        await db.flush()
    except IntegrityError:   # a concurrent promote of the same message won the unique index
        await db.rollback()
        raise ApiError(status.HTTP_409_CONFLICT, "already_promoted",
                       f"This message is already promoted to a {req.target.replace('_', ' ')}.")
    if req.target == "decision":
        add_decision_timeline_event(db, rec, incident_id, user)
    await write_audit(
        db, "message_promote",
        user_id=user.id, username=user.username,
        resource_type=req.target, resource_id=str(rec.id),
        details={"incident_id": str(incident_id), "source_kind": req.source_kind,
                 "source_id": str(req.source_id), "target": req.target, "text": text[:120]},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return PromoteResult(target=req.target, id=rec.id, source_kind=req.source_kind, source_id=req.source_id)
