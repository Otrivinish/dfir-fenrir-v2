"""Stakeholder notification tracker (I2, R22). Mounted at prefix="/api/incidents".

GET   /{id}/stakeholder-notifications        obligations + roll-up + severity levels (any role with access)
GET   /{id}/stakeholder-notifications/{nid}  one obligation
PATCH /{id}/stakeholder-notifications/{nid}  record it notified / not required, or undo / correct (analyst or admin)

The obligations themselves come from the stakeholder matrix (service.sync); nothing here creates
or deletes one. This tracker never sends anything: it records that a person told the
stakeholder. Every write is audited (`stakeholder_notification_update`; free text as a length
only). A closed incident still accepts recording a notification (pending → notified: a duty
that outlives closure, like adding an out-of-band log entry); every other change is 409
incident_closed.
"""
import base64
import json
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from incidents.access import get_accessible_incident
from models import IncidentStakeholder, OOBLog, StakeholderNotification, User, utcnow
from schemas import (NotificationStatus, StakeholderNotificationList, StakeholderNotificationOut,
                     StakeholderNotificationUpdate)
from stakeholder_notifications.service import (TIME_SKEW, TRANSITIONS, as_utc, iso_z, levels, levels_out,
                                               obligations, summarize, to_out)

router = APIRouter()

_RECORD = ("notified_at", "channel", "oob_log_id", "stakeholder_id")      # the recorded notification
_COLS = ("status", "notified_at", "notified_by_id", "channel", "oob_log_id", "stakeholder_id", "note",
         "not_required_reason")
_TEXT = ("note", "not_required_reason")                                     # audited as a length only

_READ_ERRORS = {404: {"model": ApiErrorBody, "description": "incident not found / no access, or notification_not_found"}}
_WRITE_ERRORS = {
    403: {"model": ApiErrorBody, "description": "viewer role"},
    404: {"model": ApiErrorBody, "description": "incident not found / no access, or notification_not_found"},
    409: {"model": ApiErrorBody, "description": "incident_closed (only pending → notified is allowed on a closed "
                                                "incident); invalid_transition (with from_status, to_status, allowed)"},
    422: {"model": ApiErrorBody, "description": "empty_update, reason_required, channel_required, "
                                                "not_required_reason_required, field_not_applicable, time_in_future, "
                                                "oob_entry_not_found, stakeholder_not_found"},
}


def _err422(code: str, detail: str):
    return ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, code, detail)


def _blank(v) -> bool:
    return not (isinstance(v, str) and v.strip())


def _clean(v):
    if isinstance(v, str):
        v = v.strip()
        return v or None
    return v


def _encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"o": offset}).encode()).decode().rstrip("=")


def _decode_cursor(cursor: Optional[str]) -> int:
    if not cursor:
        return 0
    try:
        return max(0, int(json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode())["o"]))
    except Exception:
        raise ApiError(status.HTTP_400_BAD_REQUEST, "invalid_cursor", "Invalid cursor")


def _audit_value(field: str, v):
    if field in _TEXT:
        return {"chars": len(v)} if v else None
    if hasattr(v, "isoformat"):
        return iso_z(v)
    return str(v) if isinstance(v, uuid.UUID) else v


@router.get("/{incident_id}/stakeholder-notifications", response_model=StakeholderNotificationList,
            summary="List the stakeholder notification tracker",
            responses={400: {"model": ApiErrorBody, "description": "invalid_cursor"}, **_READ_ERRORS})
async def list_stakeholder_notifications(
    incident_id: uuid.UUID,
    status_: Optional[NotificationStatus] = Query(default=None, alias="status", description="Only this status"),
    active: Optional[bool] = Query(default=None, description="true = not superseded only; false = superseded only"),
    limit: int = Query(default=200, ge=1, le=500),
    cursor: Optional[str] = Query(default=None),
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> StakeholderNotificationList:
    """The incident's notification obligations, one per stakeholder-matrix rule that matches (or
    matched) its severity and type: active first, then by due time. Each has its countdown
    (`clock_start_at` = when the incident first reached the rule's severity, `due_at`), `overdue`,
    and what was recorded (notified at / by / channel, links, or the not-required reason).
    Superseded obligations (the rule no longer matches) are kept and flagged. `summary` (over all
    obligations, not only this page): `required_total`, `notified`, `overdue`, `not_required`,
    `next_due_at` — required rules only. `severity_levels`: when each severity was first reached.
    Any role with access to the incident (404 otherwise). Nothing is ever sent from here."""
    await get_accessible_incident(db, incident_id, user)
    obs = await obligations(db, incident_id)
    summary = summarize(obs)
    if status_:
        obs = [o for o in obs if o.status == status_]
    if active is not None:
        obs = [o for o in obs if (o.superseded_at is None) == active]
    offset = _decode_cursor(cursor)
    page = obs[offset:offset + limit]
    more = offset + limit < len(obs)
    return StakeholderNotificationList(
        items=await to_out(db, page), next_cursor=_encode_cursor(offset + limit) if more else None,
        summary=summary, severity_levels=levels_out(await levels(db, incident_id)))


async def _one(db: AsyncSession, incident_id: uuid.UUID, nid: uuid.UUID, *, lock: bool = False) -> StakeholderNotification:
    stmt = select(StakeholderNotification).where(StakeholderNotification.id == nid,
                                                 StakeholderNotification.incident_id == incident_id)
    if lock:
        stmt = stmt.with_for_update()
    o = (await db.execute(stmt)).scalar_one_or_none()
    if o is None:
        raise ApiError(status.HTTP_404_NOT_FOUND, "notification_not_found", "Notification not found in this incident")
    return o


@router.get("/{incident_id}/stakeholder-notifications/{notification_id}", response_model=StakeholderNotificationOut,
            summary="Get one stakeholder notification", responses=_READ_ERRORS)
async def get_stakeholder_notification(
    incident_id: uuid.UUID,
    notification_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> StakeholderNotificationOut:
    """One obligation of the incident. Any role with access."""
    await get_accessible_incident(db, incident_id, user)
    return (await to_out(db, [await _one(db, incident_id, notification_id)]))[0]


@router.patch("/{incident_id}/stakeholder-notifications/{notification_id}", response_model=StakeholderNotificationOut,
              summary="Record or change a stakeholder notification", responses=_WRITE_ERRORS)
async def update_stakeholder_notification(
    incident_id: uuid.UUID,
    notification_id: uuid.UUID,
    req: StakeholderNotificationUpdate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> StakeholderNotificationOut:
    """Record that the stakeholder was told, or that this notification is not required, or undo /
    correct either (analyst or admin). Steps: pending → notified | not_required; notified /
    not_required → pending with `reason` (422 reason_required), which clears what was recorded
    (409 invalid_transition for any other step). notified needs `channel` (422 channel_required);
    `notified_at` defaults to now, not in the future (422 time_in_future, 2 min clock-skew
    allowance); the caller is recorded as notified_by. `oob_log_id` / `stakeholder_id` must be
    this incident's (422 oob_entry_not_found / stakeholder_not_found). not_required needs
    `not_required_reason`. Correcting a recorded notification's time, channel or links needs
    `reason`. A superseded obligation can still be recorded. Closed incident: only pending →
    notified (with its fields and note) is allowed, else 409 incident_closed. Audited as
    `stakeholder_notification_update`; a request that changes nothing writes nothing."""
    inc = await get_accessible_incident(db, incident_id, user)
    sent = req.model_fields_set
    if not sent:
        raise _err422("empty_update", "Nothing to update")
    o = await _one(db, incident_id, notification_id, lock=True)
    before = {c: getattr(o, c) for c in _COLS}
    v = dict(before)
    frm = o.status
    if "status" in sent and req.status is None:
        raise _err422("field_not_applicable", "status cannot be null")
    to = req.status if "status" in sent else frm
    now = utcnow()

    if inc.status == "closed" and not (frm == "pending" and to == "notified"
                                       and sent <= {"status", *_RECORD, "note"}):
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed",
                       "Incident is closed: only recording a pending notification as notified is allowed")
    if to != frm:
        if to not in TRANSITIONS[frm]:
            raise ApiError(status.HTTP_409_CONFLICT, "invalid_transition", f"A notification cannot go from {frm} to {to}",
                           extra={"from_status": frm, "to_status": to, "allowed": list(TRANSITIONS[frm])})
        if to == "pending" and _blank(req.reason):
            raise _err422("reason_required", f"Undoing {frm} needs a reason")
        v["status"] = to
        if to == "pending":
            v.update(notified_at=None, notified_by_id=None, channel=None, oob_log_id=None, stakeholder_id=None,
                     not_required_reason=None)
        elif to == "notified":
            v.update(notified_at=now, notified_by_id=user.id)

    for f in _RECORD:
        if f in sent:
            if v["status"] != "notified":
                raise _err422("field_not_applicable", f"{f} is recorded only with status notified")
            if f == "notified_at" and req.notified_at is None:
                raise _err422("field_not_applicable", "notified_at cannot be cleared while notified")
            v[f] = as_utc(req.notified_at) if f == "notified_at" else getattr(req, f)
    if frm == "notified" and to == "notified" and any(v[f] != before[f] for f in _RECORD) and _blank(req.reason):
        raise _err422("reason_required", "Correcting a recorded notification needs a reason")
    if "not_required_reason" in sent:
        if v["status"] != "not_required":
            raise _err422("field_not_applicable", "not_required_reason is kept only while the status is not_required")
        v["not_required_reason"] = _clean(req.not_required_reason)
    if "note" in sent:
        v["note"] = _clean(req.note)

    if v["status"] == "notified" and not v["channel"]:
        raise _err422("channel_required", "Say how the stakeholder was notified (channel)")
    if v["status"] == "not_required" and _blank(v["not_required_reason"]):
        raise _err422("not_required_reason_required", "Say why this notification is not needed (not_required_reason)")
    if v["notified_at"] is not None and as_utc(v["notified_at"]) > now + TIME_SKEW:
        raise _err422("time_in_future", "notified_at cannot be in the future")
    if v["oob_log_id"] and v["oob_log_id"] != before["oob_log_id"] and not (await db.execute(
            select(OOBLog.id).where(OOBLog.id == v["oob_log_id"], OOBLog.incident_id == incident_id))).first():
        raise _err422("oob_entry_not_found", "oob_log_id is not an out-of-band log entry of this incident")
    if v["stakeholder_id"] and v["stakeholder_id"] != before["stakeholder_id"] and not (await db.execute(
            select(IncidentStakeholder.id).where(IncidentStakeholder.id == v["stakeholder_id"],
                                                 IncidentStakeholder.incident_id == incident_id))).first():
        raise _err422("stakeholder_not_found", "stakeholder_id is not a stakeholder of this incident")

    changed = [c for c in _COLS if v[c] != before[c]]
    if not changed:
        return (await to_out(db, [o]))[0]
    for c in changed:
        setattr(o, c, v[c])
    o.updated_by_id, o.updated_at = user.id, now
    await write_audit(
        db, "stakeholder_notification_update",
        user_id=user.id, username=user.username,
        resource_type="stakeholder_notification", resource_id=str(o.id), resource_label=o.role[:255],
        details={"incident_id": str(incident_id), "role": o.role, "severity": o.severity, "required": o.required,
                 "due_at": iso_z(o.due_at), "from_status": frm, "to_status": o.status, "changed": changed,
                 "values": {c: _audit_value(c, getattr(o, c)) for c in changed if c != "status"},
                 "reason": _clean(req.reason), "incident_closed": inc.status == "closed",
                 "late": o.status == "notified" and as_utc(o.notified_at) > as_utc(o.due_at)},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return (await to_out(db, [o]))[0]
