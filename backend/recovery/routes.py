"""Recovery tracker (I1, R21). Mounted at prefix="/api/incidents".

GET   /{id}/recovery              in-scope systems with their records + the roll-up (any role with access)
GET   /{id}/recovery/{entity_id}  one system
PATCH /{id}/recovery/{entity_id}  change it: fields and/or one state step (analyst or admin)

Rules (recovery/service.py): not_started → restoring | not_required; restoring → restored;
restored → validated; going back needs a reason. Every write is audited (`recovery_update`, with
from_state / to_state and the changed fields; free text as a length only). A closed incident is
read-only (409 incident_closed). Nothing here sets the incident's recovered_at: the roll-up says
when Declare recovered can be offered.
"""
import base64
import json
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from incidents.access import get_accessible_incident
from models import Entity, RecoveryRecord, User, utcnow
from recovery.service import (BACKWARD, TIME_SKEW, TRANSITIONS, as_utc, is_in_scope, same_person, scope_rows,
                              summarize, to_out)
from schemas import RecoveryList, RecoveryState, RecoverySystemOut, RecoveryUpdate

router = APIRouter()

_PLAIN = ("restore_point_ref", "restore_point_at", "monitoring_start", "monitoring_end", "notes", "validation_method")
_TEXT = ("notes", "validation_method", "not_required_reason")     # audited as a length only
_COLS = ("state", "not_required_reason", "restore_point_ref", "restore_point_at", "restored_at", "restored_by_id",
         "validation_method", "validation_checklist", "validated_at", "validated_by_id", "monitoring_start",
         "monitoring_end", "notes")

_READ_ERRORS = {404: {"model": ApiErrorBody, "description": "incident not found / no access, or entity_not_found"}}
_WRITE_ERRORS = {
    403: {"model": ApiErrorBody, "description": "viewer role"},
    404: {"model": ApiErrorBody, "description": "incident not found / no access, or entity_not_found"},
    409: {"model": ApiErrorBody, "description": "incident_closed; not_in_scope (the entity is not a compromised "
                                                "host / service / network_range); invalid_transition (with "
                                                "from_state, to_state, allowed)"},
    422: {"model": ApiErrorBody, "description": "empty_update, reason_required, not_required_reason_required, "
                                                "restore_point_required, validation_method_required, "
                                                "field_not_applicable, time_in_future, restore_point_after_restore, "
                                                "validated_before_restored, monitoring_window_invalid"},
}


def _blank(v) -> bool:
    return not (isinstance(v, str) and v.strip())


def _clean(v):
    if isinstance(v, datetime):
        return as_utc(v)
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


def _err422(code: str, detail: str):
    return ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, code, detail)


def _audit_value(field: str, v):
    if field in _TEXT:
        return {"chars": len(v)} if v else None
    if field == "validation_checklist":
        return {"items": len(v or []), "done": sum(1 for i in (v or []) if i.get("done"))}
    if hasattr(v, "isoformat"):
        return as_utc(v).isoformat().replace("+00:00", "Z")
    return str(v) if isinstance(v, uuid.UUID) else v


@router.get("/{incident_id}/recovery", response_model=RecoveryList, summary="List the recovery tracker",
            responses={400: {"model": ApiErrorBody, "description": "invalid_cursor"}, **_READ_ERRORS})
async def list_recovery(
    incident_id: uuid.UUID,
    state: Optional[RecoveryState] = Query(default=None, description="Only systems in this state"),
    limit: int = Query(default=200, ge=1, le=500),
    cursor: Optional[str] = Query(default=None),
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> RecoveryList:
    """The incident's in-scope systems (compromised host / service / network_range entities), ordered
    by type and value, each with its recovery record (`record_id` null and state not_started until
    the first write), plus `summary`: per-state counts over all of them (not only this page),
    `complete`, `same_person_validations`, `monitoring_started` and `can_declare_recovered`.
    Any role with access to the incident (404 otherwise)."""
    inc = await get_accessible_incident(db, incident_id, user)
    rows = await scope_rows(db, incident_id)
    summary = summarize(inc, rows)
    if state:
        rows = [r for r in rows if (r[1].state if r[1] else "not_started") == state]
    offset = _decode_cursor(cursor)
    page = rows[offset:offset + limit]
    more = offset + limit < len(rows)
    return RecoveryList(items=await to_out(db, page), next_cursor=_encode_cursor(offset + limit) if more else None,
                        summary=summary)


async def _entity(db: AsyncSession, incident_id: uuid.UUID, entity_id: uuid.UUID, *, lock: bool = False) -> Entity:
    stmt = select(Entity).where(Entity.id == entity_id, Entity.incident_id == incident_id)
    if lock:   # serialises writes to one system, including its first (record-creating) write
        stmt = stmt.with_for_update(key_share=True)   # FOR NO KEY UPDATE
    ent = (await db.execute(stmt)).scalar_one_or_none()
    if ent is None:
        raise ApiError(status.HTTP_404_NOT_FOUND, "entity_not_found", "Entity not found in this incident")
    return ent


@router.get("/{incident_id}/recovery/{entity_id}", response_model=RecoverySystemOut,
            summary="Get one system's recovery record", responses=_READ_ERRORS)
async def get_recovery(
    incident_id: uuid.UUID,
    entity_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> RecoverySystemOut:
    """One system of the incident (`entity_id`). An entity that is not in scope is still returned
    (with its record, if one was kept) so a link never dangles. Any role with access."""
    await get_accessible_incident(db, incident_id, user)
    ent = await _entity(db, incident_id, entity_id)
    rec = (await db.execute(select(RecoveryRecord).where(RecoveryRecord.entity_id == ent.id))).scalar_one_or_none()
    return (await to_out(db, [(ent, rec)]))[0]


@router.patch("/{incident_id}/recovery/{entity_id}", response_model=RecoverySystemOut,
              summary="Update one system's recovery record", responses=_WRITE_ERRORS)
async def update_recovery(
    incident_id: uuid.UUID,
    entity_id: uuid.UUID,
    req: RecoveryUpdate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> RecoverySystemOut:
    """Set fields and/or move `state` one step (analyst or admin). The system must be in scope
    (409 not_in_scope). Allowed steps are each item's `allowed_transitions` (409 invalid_transition
    otherwise); going back needs `reason` (422 reason_required) and clears restored_* / validated_*
    as needed. restored → needs `restore_point_ref`; validated → needs `validation_method`;
    not_required → needs `not_required_reason`. restored_at / validated_at default to now; the
    caller is recorded as restored_by / validated_by. A validator who also restored the system is
    allowed, flagged `same_person_validation`. Times: not in the future (restore_point_at,
    restored_at, validated_at); restore_point_at ≤ restored_at ≤ validated_at; monitoring_end ≥
    monitoring_start (422). Audited as `recovery_update`; a request that changes nothing writes
    nothing."""
    inc = await get_accessible_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")
    sent = req.model_fields_set
    if not sent:
        raise _err422("empty_update", "Nothing to update")
    ent = await _entity(db, incident_id, entity_id, lock=True)
    if not is_in_scope(ent):
        raise ApiError(status.HTTP_409_CONFLICT, "not_in_scope",
                       "Only compromised hosts, services and network ranges are tracked for recovery")

    rec = (await db.execute(
        select(RecoveryRecord).where(RecoveryRecord.entity_id == ent.id).with_for_update()
    )).scalar_one_or_none()
    new = rec is None
    if new:
        rec = RecoveryRecord(id=uuid.uuid4(), incident_id=incident_id, entity_id=ent.id, state="not_started",
                             validation_checklist=[])
    # Work on a copy (v) and touch the row only once every rule holds, so a refused request
    # leaves nothing dirty in the session.
    before = {c: getattr(rec, c) for c in _COLS}
    v = dict(before)
    frm = rec.state
    if "state" in sent and req.state is None:
        raise _err422("field_not_applicable", "state cannot be null")
    to = req.state if "state" in sent else frm
    now = utcnow()

    if to != frm:
        if to not in TRANSITIONS[frm]:
            raise ApiError(status.HTTP_409_CONFLICT, "invalid_transition",
                           f"A system cannot go from {frm} to {to}",
                           extra={"from_state": frm, "to_state": to, "allowed": list(TRANSITIONS[frm])})
        if (frm, to) in BACKWARD and _blank(req.reason):
            raise _err422("reason_required", f"Going back from {frm} to {to} needs a reason")

    for f in _PLAIN:
        if f in sent:
            v[f] = _clean(getattr(req, f))
    if "validation_checklist" in sent:
        v["validation_checklist"] = [i.model_dump() for i in (req.validation_checklist or [])]

    if to != frm:
        if (frm, to) in BACKWARD:
            v["not_required_reason"] = None
            if to == "restoring":
                v.update(restored_at=None, restored_by_id=None, validated_at=None, validated_by_id=None)
        elif to == "restored":
            v.update(restored_at=now, restored_by_id=user.id)
        elif to == "validated":
            v.update(validated_at=now, validated_by_id=user.id)
        v["state"] = to

    if "not_required_reason" in sent:
        if v["state"] != "not_required":
            raise _err422("field_not_applicable", "not_required_reason is only kept while the state is not_required")
        v["not_required_reason"] = _clean(req.not_required_reason)
    for f, states in (("restored_at", ("restored", "validated")), ("validated_at", ("validated",))):
        if f in sent:
            if getattr(req, f) is None or v["state"] not in states:
                raise _err422("field_not_applicable", f"{f} can be set only while the state is {' or '.join(states)}")
            v[f] = as_utc(getattr(req, f))

    if v["state"] == "not_required" and _blank(v["not_required_reason"]):
        raise _err422("not_required_reason_required", "Say why this system needs no restore (not_required_reason)")
    if v["state"] in ("restored", "validated") and _blank(v["restore_point_ref"]):
        raise _err422("restore_point_required", "Record the restore point (restore_point_ref) the system was restored from")
    if v["state"] == "validated" and _blank(v["validation_method"]):
        raise _err422("validation_method_required", "Record how the system was validated (validation_method)")
    for f in ("restore_point_at", "restored_at", "validated_at"):
        if v[f] is not None and as_utc(v[f]) > now + TIME_SKEW:
            raise _err422("time_in_future", f"{f} cannot be in the future")
    if v["restore_point_at"] and v["restored_at"] and as_utc(v["restore_point_at"]) > as_utc(v["restored_at"]):
        raise _err422("restore_point_after_restore", "restore_point_at cannot be after restored_at")
    if v["validated_at"] and v["restored_at"] and as_utc(v["validated_at"]) < as_utc(v["restored_at"]):
        raise _err422("validated_before_restored", "validated_at cannot be before restored_at")
    if v["monitoring_start"] and v["monitoring_end"] and as_utc(v["monitoring_end"]) < as_utc(v["monitoring_start"]):
        raise _err422("monitoring_window_invalid", "monitoring_end cannot be before monitoring_start")

    changed = [c for c in _COLS if v[c] != before[c]]
    if not changed:   # nothing to write
        return (await to_out(db, [(ent, None if new else rec)]))[0]

    for c in changed:
        setattr(rec, c, v[c])
    rec.updated_by_id, rec.updated_at = user.id, now
    if new:
        db.add(rec)
        await db.flush()
    await write_audit(
        db, "recovery_update",
        user_id=user.id, username=user.username,
        resource_type="recovery_record", resource_id=str(rec.id), resource_label=ent.value[:255],
        details={"incident_id": str(incident_id), "entity_id": str(ent.id), "entity_value": ent.value,
                 "from_state": frm, "to_state": rec.state, "created": new, "changed": changed,
                 "values": {c: _audit_value(c, getattr(rec, c)) for c in changed if c != "state"},
                 "reason": _clean(req.reason), "same_person_validation": same_person(rec)},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return (await to_out(db, [(ent, rec)]))[0]
