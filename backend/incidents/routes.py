"""Incident endpoints — list / create / get / update / close / reopen.

Standards alignment (per CLAUDE.md § Standards alignment):
- severity uses internal Low/Medium/High/Critical; NCISS values are derived
  at report time via a fixed mapping (critical→emergency, high→severe,
  medium→medium, low→low).
- phase    uses NIST SP 800-61 R3 phase names.
- tlp      uses TLP 2.0.
CSF 2.0 function tagging lives at the report level, not on individual incidents.
"""
import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Union

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import Text, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from core.tags import canonical_tag_or_422, normalize_tags
from incidents.access import (DPO_ROLE_KEY, LEAD_ROLE_KEYS, accessible_filter, get_accessible_incident,
                              held_role_keys, incident_capabilities, is_incident_dpo, is_incident_lead,
                              not_incident_lead, require_incident_person)
from incidents.gates import GATE_LABEL, GATES, evaluate_gate, gate_state, sign_off_out
from incidents.phase_history import phase_history
from incidents.reference import assign as assign_reference
from incidents.start_checks import evaluate as evaluate_start_checks
from models import (ClosureChecklistItem, Decision, Entity, EntityEvent, EntityFile, Evidence, IOC, Incident,
                    IncidentAssignment, IncidentGateSignOff, IncidentHandoff, OperationalRole, PlaybookTask, RespondAction, Team,
                    TimelineEvent, User, incident_teams, user_team, utcnow)
from notifications.service import PHASE_LABEL, notify_assignment, notify_incident_created, notify_phase_changed
from outbound_webhooks.service import suppressed_by_outbound_policy
from recovery.service import rollup as recovery_rollup
from stakeholder_notifications.service import (record_level as record_severity_level, rollup as notifications_rollup,
                                               sync as sync_notifications)
from schemas import (INCIDENT_CREATE_REQUIRED, GateName, GateResult, GateSignOffCreate, GateSignOffOut, GateUnmetBody,
                     IncidentAccess, IncidentClose, IncidentCreate,
                     IncidentGates, IncidentList, IncidentListItem, IncidentOut, IncidentPhaseHistory, IncidentReopen, IncidentSnapshot,
                     IncidentStartChecks, IncidentUpdate, IncidentState, Phase, RespondCategoryCount, Severity, Tlp)

router = APIRouter()


async def _fire_hooks(db, event: str, inc: Incident, extra_facts=None) -> None:
    """Dispatch outbound webhooks + email alert. Best-effort; never raises.
    Blocked (and audited) under Dark Operation or TLP:RED (H3) — fail closed."""
    if await suppressed_by_outbound_policy(db, event, inc):
        return
    try:
        from outbound_webhooks.service import dispatch_incident_event
        await dispatch_incident_event(
            db, event,
            inc_title=inc.title, inc_ref=inc.ref,
            inc_severity=inc.severity, inc_phase=inc.phase,
            extra_facts=extra_facts,
        )
    except Exception:
        pass
    if event == "incident_created" and inc.severity in ("high", "critical"):
        try:
            from mailer.service import send_admin_alert
            await send_admin_alert(
                db,
                f"[FENRIR] New {inc.severity.upper()} incident: {inc.title}",
                f"Ref: {inc.ref}\nSeverity: {inc.severity}\nTitle: {inc.title}\n\n{inc.description or ''}",
            )
        except Exception:
            pass


# ─── Cursor helpers (opaque, offset-encoded for now) ─────────────────────────
# Cursor pagination per CLAUDE.md § API-first. Opaque to clients — clients
# never construct or mutate cursors, only echo them back.

# L11, accepted: a row deleted between two page reads makes an offset cursor skip one row; the war room pages by keyset.
def _encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"o": offset}).encode()).decode().rstrip("=")


def _decode_cursor(cursor: Optional[str]) -> int:
    if not cursor:
        return 0
    try:
        pad = "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(cursor + pad).decode())
        o = int(data.get("o", 0))
        return max(0, o)
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid cursor")


# ─── Detection time rules ────────────────────────────────────────────────────
# detected_at and the response milestones may be at most this far ahead of the
# server clock (client skew).
DETECTED_AT_SKEW = timedelta(minutes=2)


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt   # naive = UTC


def _check_detected_at(occurred_at: Optional[datetime], detected_at: Optional[datetime],
                       *, check_future: bool = True) -> None:
    """422 code detected_before_occurred when detected_at is before occurred_at, or
    (check_future) code detected_in_future when later than now + DETECTED_AT_SKEW."""
    if detected_at is None:
        return
    if check_future and _as_utc(detected_at) > utcnow() + DETECTED_AT_SKEW:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "detected_in_future",
                       "detected_at cannot be in the future")
    if occurred_at is not None and _as_utc(detected_at) < _as_utc(occurred_at):
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "detected_before_occurred",
                       "detected_at cannot be before occurred_at")


# Response milestones, in order. Each is declared by an analyst (plain PATCH);
# the first time one is set, a system timeline event records it.
MILESTONES = ("contained_at", "eradicated_at", "recovered_at")
_MILESTONE_EVENT = {
    "contained_at":  "Containment declared",
    "eradicated_at": "Eradication declared",
    "recovered_at":  "Recovery declared",
}


def _check_milestones(values: dict[str, Optional[datetime]], sent: set[str],
                      detected_at: Optional[datetime], occurred_at: Optional[datetime]) -> None:
    """422 when a milestone in `sent` is later than now + DETECTED_AT_SKEW (code
    milestone_in_future), earlier than detected_at (milestone_before_detection) or earlier
    than occurred_at (milestone_before_occurred); or when eradicated_at / recovered_at is
    before contained_at, or recovered_at is before eradicated_at (milestone_out_of_order).
    `values`, `detected_at` and `occurred_at` are the values the row would end up with."""
    for f in MILESTONES:
        v = values[f]
        if f not in sent or v is None:
            continue
        if _as_utc(v) > utcnow() + DETECTED_AT_SKEW:
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "milestone_in_future",
                           f"{f} cannot be in the future")
        if detected_at is not None and _as_utc(v) < _as_utc(detected_at):
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "milestone_before_detection",
                           f"{f} cannot be before detected_at")
        if occurred_at is not None and _as_utc(v) < _as_utc(occurred_at):
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "milestone_before_occurred",
                           f"{f} cannot be before occurred_at")
    for later, earlier in (("eradicated_at", "contained_at"), ("recovered_at", "contained_at"),
                           ("recovered_at", "eradicated_at")):
        a, b = values[later], values[earlier]
        if a is not None and b is not None and _as_utc(a) < _as_utc(b):
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "milestone_out_of_order",
                           f"{later} cannot be before {earlier}")


# ─── Phase gates (incidents/gates.py) ────────────────────────────────────────
# 800-61 R3 order. Moving to an earlier phase needs a reason; Preparation is never a
# target (it is the readiness work before any incident).
PHASE_ORDER = ("preparation", "detection_and_analysis", "containment_eradication_recovery", "post_incident")
REASON_MIN = 10


def _phase_reason(raw: Optional[str]) -> str:
    """The trimmed phase_reason; 422 phase_reason_required when missing or under 10 characters."""
    reason = (raw or "").strip()
    if len(reason) < REASON_MIN:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "phase_reason_required",
                       f"phase_reason is required: at least {REASON_MIN} characters, to move to an "
                       "earlier phase or to override a gate")
    return reason


def _triage_reason(raw: Optional[str],
                   why: str = "to mark the incident a false or benign positive outside Detection & Analysis") -> str:
    """The trimmed triage_reason; 422 triage_reason_required when missing or under 10 characters."""
    reason = (raw or "").strip()
    if len(reason) < REASON_MIN:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "triage_reason_required",
                       f"triage_reason is required: at least {REASON_MIN} characters, {why} "
                       "(it can then be closed without Gate 2)")
    return reason


_TRIAGE_LABEL = {"suspected": "Suspected", "confirmed": "Confirmed",
                 "false_positive": "False Positive", "benign_positive": "Benign Positive"}


def _require_gate(result: GateResult, override: bool, how: str) -> Optional[GateResult]:
    """409 gate_unmet unless the gate is met or `override` is set. Returns the result when
    it is being overridden (the caller audits it), else None."""
    if result.met:
        return None
    if not override:
        raise ApiError(
            status.HTTP_409_CONFLICT, "gate_unmet",
            f"{GATE_LABEL[result.gate]} not met: {'; '.join(i.label for i in result.unmet)}. "
            f"Fix these, or resend with override_gate=true {how}.",
            extra={"gate": result.gate,
                   "unmet": [i.model_dump(mode="json", exclude_none=True) for i in result.unmet],
                   "warnings": [i.model_dump(mode="json", exclude_none=True) for i in result.warnings]},
        )
    return result


async def _record_override(db: AsyncSession, inc: Incident, user: User, result: GateResult,
                           reason: str, ir_phase: str, details: dict) -> None:
    """Audit row incident_gate_override + a system timeline event for an overridden gate."""
    keys = [i.key for i in result.unmet]
    db.add(TimelineEvent(
        id=uuid.uuid4(),
        incident_id=inc.id,
        event_time=utcnow(),
        source="Incident",
        event_type="Gate overridden",
        description=f"{GATE_LABEL[result.gate]} overridden with {len(keys)} item(s) unmet "
                    f"({'; '.join(i.label for i in result.unmet)}): {reason}",
        ir_phase=ir_phase,
        origin="system",
        is_system=True,
        external_safe=False,
        system_source="gate_override",
        created_by_id=user.id,
    ))
    await write_audit(
        db, "incident_gate_override",
        outcome="success",
        resource_type="incident", resource_id=str(inc.id), resource_label=inc.title,
        details={"gate": result.gate, "unmet": keys, "warnings": [i.key for i in result.warnings],
                 "reason": reason, **details},
    )


# ─── List ────────────────────────────────────────────────────────────────────

@router.get("", response_model=IncidentList, summary="List incidents")
async def list_incidents(
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
    status_filter: Optional[IncidentState] = Query(default=None, alias="status"),
    severity:      Optional[Severity]      = Query(default=None),
    phase:         Optional[Phase]         = Query(default=None),
    tlp:           Optional[Tlp]           = Query(default=None),
    tag:           Optional[str]           = Query(default=None,
                                                   description="Filter by tag (canonical lowercase-dashed); a value with no usable characters is 422 invalid_tag"),
    mine:          bool                    = Query(default=False),
    ref:           Optional[str]           = Query(default=None, max_length=32,
                                                   description="Exact incident reference, e.g. INC-2026-00009 or INC-0002 (case-insensitive)"),
    limit:         int                     = Query(default=50, ge=1, le=200),
    cursor:        Optional[str]           = Query(default=None),
) -> IncidentList:
    """List incidents the caller can access, newest first, with cursor pagination.

    Restricted to incidents visible to the caller via the team-based access
    filter (admins see all). Optional filters: status, severity, phase, tlp,
    tag (canonical lowercase-dashed), mine (only incidents the caller
    created) and ref (exact incident reference, legacy INC-NNNN or
    PREFIX-YYYY-NNNNN). Paginate with limit (1-200) and the opaque cursor. Returns
    {items, next_cursor}; each item also carries `incident_commander` (the IC's username, or null).
    """
    offset = _decode_cursor(cursor)

    stmt = select(Incident).order_by(Incident.created_at.desc(), Incident.id)
    stmt = stmt.where(accessible_filter(user))
    if status_filter: stmt = stmt.where(Incident.status       == status_filter)
    if severity:      stmt = stmt.where(Incident.severity     == severity)
    if phase:         stmt = stmt.where(Incident.phase        == phase)
    if tlp:           stmt = stmt.where(Incident.tlp          == tlp)
    if mine:          stmt = stmt.where(Incident.created_by_id == user.id)
    if ref:           stmt = stmt.where(Incident.ref == ref.strip().upper())
    if tag:
        # tags is a `json` list — case-folded whole-tag match against the canonical form.
        # The canonical form is [a-z0-9-./:] only (no LIKE wildcard, quote or JSON escape),
        # so '%"tag"%' on the JSON text matches exactly one complete element. Unindexed:
        # tag volume is small per row.
        stmt = stmt.where(cast(Incident.tags, Text).ilike(f'%"{canonical_tag_or_422(tag)}"%'))

    # Fetch limit+1 to determine if there's a next page.
    stmt = stmt.offset(offset).limit(limit + 1)
    rows = (await db.execute(stmt)).scalars().all()

    has_more = len(rows) > limit
    page = rows[:limit]
    # L3 (R48): each incident's Incident Commander (earliest IC assignment), one query for the page.
    ic_by_incident: dict = {}
    if page:
        for inc_id, username in (await db.execute(
            select(IncidentAssignment.incident_id, IncidentAssignment.username)
            .join(OperationalRole, OperationalRole.id == IncidentAssignment.role_id)
            .where(IncidentAssignment.incident_id.in_([r.id for r in page]),
                   OperationalRole.key == "incident_commander")
            .order_by(IncidentAssignment.assigned_at, IncidentAssignment.id)
        )).all():
            ic_by_incident.setdefault(inc_id, username)
    items = [IncidentListItem.model_validate(r).model_copy(update={"incident_commander": ic_by_incident.get(r.id)})
             for r in page]
    next_cursor = _encode_cursor(offset + limit) if has_more else None
    return IncidentList(items=items, next_cursor=next_cursor)


# ─── Create ──────────────────────────────────────────────────────────────────

async def _create_team_ids(db: AsyncSession, user: User, requested: list[uuid.UUID]) -> list[uuid.UUID]:
    """F2 — the teams a new incident starts restricted to, de-duplicated. 422 team_not_found
    for an unknown team; a non-admin may only pick teams they belong to (409 would_lock_out,
    the PATCH rule for a lead), so the creator can always see what they opened."""
    team_ids = list(dict.fromkeys(requested or []))
    if not team_ids:
        return []
    known = set((await db.execute(select(Team.id).where(Team.id.in_(team_ids)))).scalars())
    if unknown := [str(t) for t in team_ids if t not in known]:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "team_not_found",
                       f"Unknown team id(s): {', '.join(unknown)}")
    if user.role != "admin":
        mine = set((await db.execute(
            select(user_team.c.team_id).where(user_team.c.user_id == user.id))).scalars())
        if foreign := [str(t) for t in team_ids if t not in mine]:
            raise ApiError(status.HTTP_409_CONFLICT, "would_lock_out",
                           f"You can only restrict a new incident to teams you belong to (not a member of: "
                           f"{', '.join(foreign)}). Ask an admin to add other teams.")
    return team_ids


# I4 intake fields: optional at create, editable (and clearable) by PATCH.
INTAKE_FIELDS = ("functional_impact", "information_impact", "recoverability", "severity_rationale", "alert_reference")


def _clean(v):
    return (v.strip() or None) if isinstance(v, str) else v


async def _check_new_ic(db: AsyncSession, user_id: uuid.UUID, team_ids: list[uuid.UUID]) -> User:
    """I4 — the Incident Commander named at create, checked before the reference is allocated so a
    refusal never uses up an incident number: the F2 rules (404 user_not_found; 422 assignee_no_access
    when deactivated or unable to see the incident), with visibility judged on the requested team_ids.
    require_incident_person re-checks against the stored row before the assignment is written."""
    person = await db.get(User, user_id)
    if person is None:
        raise ApiError(status.HTTP_404_NOT_FOUND, "user_not_found",
                       "Unknown user for the Incident Commander: no account has this id.")
    if not person.is_active:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "assignee_no_access",
                       "The selected account is deactivated: choose an active user as the Incident Commander.")
    if team_ids and person.role != "admin" and (await db.execute(
            select(user_team.c.team_id).where(user_team.c.user_id == person.id,
                                              user_team.c.team_id.in_(team_ids)).limit(1)
    )).scalar_one_or_none() is None:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "assignee_no_access",
                       f"{person.username} can't see this incident (not in any of its teams), so can't be the "
                       "Incident Commander. Add one of their teams, or choose someone else.")
    return person


@router.post("", response_model=IncidentOut, status_code=status.HTTP_201_CREATED,
             responses={404: {"model": ApiErrorBody, "description": "user_not_found (ic_user_id)"},
                        409: {"model": ApiErrorBody, "description": "would_lock_out (team_ids)"},
                        422: {"model": ApiErrorBody,
                              "description": "required_fields_missing (body adds fields[]), team_not_found, "
                                             "detected_before_occurred, detected_in_future, assignee_no_access, "
                                             "ic_role_unavailable or triage_reason_required"}})
async def create_incident(
    req: IncidentCreate, request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> IncidentOut:
    """Open an incident. Required: title, severity, incident_type, detection_method and
    detected_at; any missing or null is 422 code required_fields_missing, with every missing
    one in `fields`. phase must be detection_and_analysis or
    containment_eradication_recovery. detected_at is stored as given (the
    server never fills it in; detected_at_source becomes reported); 422 when it is before
    occurred_at or in the future (2 min clock-skew allowance).

    Optional intake, all written in the same transaction as the incident and audited with it:
    ic_user_id assigns that user as Incident Commander (F2 people rules: 404 user_not_found,
    422 assignee_no_access; the IC role must be active, else 422 ic_role_unavailable; the IC
    gets an in-app notification unless it is the creator); functional_impact,
    information_impact, recoverability (NIST SP 800-61 categories), severity_rationale,
    alert_reference; first_host adds a compromised host entity (in scope); first_ioc adds an
    IOC with source "intake". dark_operation sent explicitly records the Dark Operation
    decision (dark_operation_decided_at). See GET …/start-checks for what should follow.

    team_ids restricts the incident to those teams from the start (empty = visible to
    everyone). An unknown team is 422 code team_not_found. An admin may pick any team; an
    analyst only teams they belong to (409 code would_lock_out otherwise), so the creator
    always keeps access. The teams are audited with the creation.

    triage_state false_positive or benign_positive with a phase other than
    detection_and_analysis needs triage_reason (at least 10 characters; 422 code
    triage_reason_required), as on PATCH: such an incident can be closed without Gate 2.
    A triage_reason is audited with the creation and adds a system timeline event
    ("Triage set")."""
    missing = [f for f in INCIDENT_CREATE_REQUIRED if _clean(getattr(req, f)) is None]
    if missing:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "required_fields_missing",
                       f"Missing required field(s): {', '.join(missing)}.", extra={"fields": missing})
    _check_detected_at(req.occurred_at, req.detected_at)
    if req.triage_state in CLOSABLE_ANY_PHASE and req.phase != "detection_and_analysis":
        triage_reason = _triage_reason(req.triage_reason)
    else:
        triage_reason = (req.triage_reason or "").strip() or None
    team_ids = await _create_team_ids(db, user, req.team_ids)
    ic_role = None
    if req.ic_user_id is not None:
        await _check_new_ic(db, req.ic_user_id, team_ids)
        ic_role = (await db.execute(select(OperationalRole).where(
            OperationalRole.key == "incident_commander", OperationalRole.is_active == True)  # noqa: E712
        )).scalar_one_or_none()
        if ic_role is None:
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "ic_role_unavailable",
                           "The Incident Commander operational role is inactive or missing: an admin must restore "
                           "it (Settings → Operational roles) before an IC can be assigned.")
    decided = "dark_operation" in req.model_fields_set
    inc_num, inc_ref, created_at = await assign_reference(db)
    inc = Incident(
        id=uuid.uuid4(),
        incident_number=inc_num,
        ref=inc_ref,
        created_at=created_at,
        title=req.title,
        description=req.description,
        severity=req.severity,
        phase=req.phase,
        tlp=req.tlp,
        triage_state=req.triage_state,
        incident_type=req.incident_type,
        detection_method=req.detection_method,
        reporter=req.reporter,
        created_by_id=user.id,
        occurred_at=req.occurred_at,
        detected_at=req.detected_at,
        detected_at_source="reported",
        tags=normalize_tags(req.tags),
        dark_operation=req.dark_operation,
        dark_operation_decided_at=created_at if decided else None,
        **{f: _clean(getattr(req, f)) for f in INTAKE_FIELDS},
    )
    db.add(inc)
    await db.flush()

    for team_id in team_ids:
        await db.execute(
            incident_teams.insert().values(incident_id=inc.id, team_id=team_id)
        )

    # I4 optional intake: IC, first host, first IOC — same transaction, each audited like its own endpoint.
    ic = None
    if ic_role is not None:
        ic = await require_incident_person(db, inc.id, req.ic_user_id, "the Incident Commander")
        row = IncidentAssignment(id=uuid.uuid4(), incident_id=inc.id, user_id=ic.id, username=ic.username,
                                 role_id=ic_role.id, role_label=ic_role.label, notes="Assigned at intake",
                                 assigned_by_id=user.id, assigned_by_username=user.username)
        db.add(row)
        await db.flush()
        await write_audit(db, "assignment_create", resource_type="assignment", resource_id=str(row.id),
                          resource_label=f"{ic.username} → {ic_role.label}",
                          details={"incident_id": str(inc.id), "source": "intake"})
    host = None
    if req.first_host is not None and req.first_host.strip():
        host = Entity(id=uuid.uuid4(), incident_id=inc.id, type="host", value=req.first_host.strip(),
                      criticality="medium", attributes={}, compromised=True, added_by_id=user.id)
        db.add(host)
        await db.flush()
        for title in ("Entity added", "Marked as compromised"):
            db.add(EntityEvent(id=uuid.uuid4(), entity_id=host.id, incident_id=inc.id, event_type="system",
                               title=title, actor_id=user.id))
        await write_audit(db, "entity_create", resource_type="entity", resource_id=str(host.id),
                          details={"incident_id": str(inc.id), "type": "host", "value": host.value,
                                   "compromised": True, "source": "intake"})
    ioc = None
    if req.first_ioc is not None and req.first_ioc.value.strip():
        ioc = IOC(id=uuid.uuid4(), incident_id=inc.id, type=req.first_ioc.type, value=req.first_ioc.value.strip(),
                  source="intake", confidence=50, tags=[], added_by_id=user.id)
        db.add(ioc)
        await db.flush()
        await write_audit(db, "ioc_create", resource_type="ioc", resource_id=str(ioc.id),
                          details={"incident_id": str(inc.id), "type": ioc.type, "value": ioc.value,
                                   "source": "intake"})

    if triage_reason:
        db.add(TimelineEvent(
            id=uuid.uuid4(),
            incident_id=inc.id,
            event_time=created_at,
            source="Incident",
            event_type="Triage set",
            description=f"Opened as {_TRIAGE_LABEL.get(inc.triage_state, inc.triage_state)} in "
                        f"{_PHASE_LABEL.get(inc.phase, inc.phase)}: {triage_reason}",
            ir_phase=inc.phase,
            origin="system",
            is_system=True,
            external_safe=False,
            system_source="triage",
            created_by_id=user.id,
        ))

    await write_audit(
        db, "incident_create",
        outcome="success",
        resource_type="incident", resource_id=str(inc.id), resource_label=inc.title,
        details={"ref": inc.ref, "severity": inc.severity, "phase": inc.phase, "tlp": inc.tlp,
                 "dark_operation": inc.dark_operation, "dark_operation_decided": decided,
                 "detected_at": inc.detected_at.isoformat() if inc.detected_at else None,
                 "incident_type": inc.incident_type, "detection_method": inc.detection_method,
                 **{f: getattr(inc, f) for f in INTAKE_FIELDS if getattr(inc, f) is not None},
                 **({"ic_user_id": str(ic.id)} if ic else {}),
                 **({"first_host_entity_id": str(host.id)} if host else {}),
                 **({"first_ioc_id": str(ioc.id)} if ioc else {}),
                 **({"team_ids": [str(t) for t in team_ids]} if team_ids else {}),
                 **({"triage_state": inc.triage_state, "triage_reason": triage_reason} if triage_reason else {})},
    )
    # I2: the opening severity counts from the awareness time (detected_at, else the creation time);
    # the stakeholder-matrix obligations for it are created now.
    await record_severity_level(db, inc, at=inc.detected_at or created_at, source="initial", user_id=user.id)
    await sync_notifications(db, inc, cause="incident_created", user_id=user.id)
    if ic is not None and ic.id != user.id:
        await notify_assignment(        # commits the whole creation, then pushes
            db, assignee_id=ic.id, incident_id=inc.id, incident_ref=inc.ref,
            role_label=ic_role.label, assigner_username=user.username,
        )
    else:
        await db.commit()
    await db.refresh(inc)
    await _fire_hooks(db, "incident_created", inc)
    await notify_incident_created(db, user.id, inc.id, inc.ref or str(inc.id), user.username, inc.severity)
    return IncidentOut.model_validate(inc)


# ─── Read one ────────────────────────────────────────────────────────────────

@router.get("/{incident_id}", response_model=IncidentOut)
async def get_incident(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> IncidentOut:
    inc = await get_accessible_incident(db, incident_id, user)
    return IncidentOut.model_validate(inc)


# ─── Snapshot (at-a-glance counts for the Details landing tab) ──────────────

@router.get("/{incident_id}/snapshot", response_model=IncidentSnapshot)
async def get_incident_snapshot(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> IncidentSnapshot:
    # Access check via the standard helper; raises 404 on no-access.
    inc = await get_accessible_incident(db, incident_id, user)

    async def _count(model) -> int:
        stmt = select(func.count()).select_from(model).where(model.incident_id == incident_id)
        return int((await db.execute(stmt)).scalar() or 0)

    iocs             = await _count(IOC)
    entities         = await _count(Entity)
    evidence         = await _count(Evidence)
    timeline         = await _count(TimelineEvent)
    # C2: affected systems = compromised entities.
    affected_systems = int((await db.execute(
        select(func.count()).select_from(Entity)
        .where(Entity.incident_id == incident_id, Entity.compromised == True)  # noqa: E712
    )).scalar() or 0)
    assignments      = await _count(IncidentAssignment)

    # Playbook: group by status in a single round-trip.
    pb_stmt = (
        select(PlaybookTask.status, func.count())
        .where(PlaybookTask.incident_id == incident_id, PlaybookTask.archived_at.is_(None))   # I3: current plan
        .group_by(PlaybookTask.status)
    )
    pb_rows = (await db.execute(pb_stmt)).all()
    by_status = {row[0]: int(row[1]) for row in pb_rows}
    pb_done    = by_status.get("done", 0)
    pb_skipped = by_status.get("skipped", 0)
    pb_total   = sum(by_status.values()) - pb_skipped   # matches sidebar widget convention

    # Incident rail counts (D2).
    files = await _count(EntityFile)
    rs_rows = (await db.execute(
        select(RespondAction.category, RespondAction.status, func.count())
        .where(RespondAction.incident_id == incident_id)
        .group_by(RespondAction.category, RespondAction.status)
    )).all()
    rs_by_status: dict[str, int] = {}
    for _cat, st, n in rs_rows:
        rs_by_status[st] = rs_by_status.get(st, 0) + int(n)
    respond_open  = rs_by_status.get("open", 0) + rs_by_status.get("in_progress", 0)
    respond_total = sum(rs_by_status.values())

    def _respond(cats: tuple[str, ...]) -> RespondCategoryCount:   # K2: the split Respond pages' rail counts
        rows = [(st, int(n)) for cat, st, n in rs_rows if cat in cats]
        return RespondCategoryCount(total=sum(n for _, n in rows), done=sum(n for st, n in rows if st == "done"),
                                    open=sum(n for st, n in rows if st in ("open", "in_progress")))
    decisions = await _count(Decision)
    handoffs_pending = int((await db.execute(
        select(func.count()).select_from(IncidentHandoff)
        .where(IncidentHandoff.incident_id == incident_id, IncidentHandoff.status == "pending")
    )).scalar() or 0)
    notifications = await notifications_rollup(db, inc.id)

    return IncidentSnapshot(
        iocs=iocs, entities=entities, evidence=evidence, timeline=timeline,
        affected_systems=affected_systems, assignments=assignments,
        playbook_total=pb_total, playbook_done=pb_done, playbook_skipped=pb_skipped,
        files=files, respond_open=respond_open, respond_total=respond_total,
        handoffs_pending=handoffs_pending, recovery=await recovery_rollup(db, inc),
        notifications=notifications, start_checks=await evaluate_start_checks(db, inc, notifications),
        respond_containment=_respond(("containment",)),
        respond_eradication_recovery=_respond(("eradication", "recovery")),
        decisions=decisions, phase_history=await phase_history(db, inc),
    )


# ─── Time in phase (K2, R38) ─────────────────────────────────────────────────

@router.get("/{incident_id}/phase-history", response_model=IncidentPhaseHistory, summary="Get the time in each phase")
async def get_incident_phase_history(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> IncidentPhaseHistory:
    """How long the incident has been in its current phase, and how long each earlier phase took. Read
    from the incident's append-only audit rows: incident_create (the opening phase, from created_at), every
    incident_update that changed the phase, incident_close (ends the current period) and incident_reopen
    (starts a new one). Moving back to a phase starts a new period. Any user with access to the incident
    may read; also in GET …/snapshot as phase_history.

    Returns {phase, entered_at (start of the current period), closed, periods[] oldest first, each
    {phase, entered_at, left_at, duration_seconds, ended_by phase_change|close} (left_at and duration
    null while current), completed[] {phase, seconds, periods}: each phase's finished periods added up}.
    All times UTC."""
    inc = await get_accessible_incident(db, incident_id, user)
    return await phase_history(db, inc)


# ─── Incident-start checks (I4) ──────────────────────────────────────────────

@router.get("/{incident_id}/start-checks", response_model=IncidentStartChecks,
            summary="Get the incident-start checks")
async def get_incident_start_checks(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> IncidentStartChecks:
    """What should be in place soon after the incident was opened, evaluated now. Warnings
    only: nothing is blocked. Any user with access to the incident may read.

    items[] holds only the checks that apply, each {key, label, status, detail, route}:
    ic_assigned, comms_lead_assigned, legal_liaison_assigned (an active user holds the
    role here); detected_at_set; playbook_applied (at least one current task; detail
    names the templates suggested for the type); legal_initialised (at least one legal
    deadline; applies to types ransomware, data_breach and bec, information_impact
    privacy, or the tag personal-data); dark_operation_decided (Dark Operation is on or was
    explicitly decided; applies to types phishing and bec); notifications_on_time (no
    stakeholder notification overdue). A missing check is `warning` until
    overdue_after_minutes (60) after the incident was created, then `overdue`;
    notifications_on_time is `overdue` as soon as a notification is. route is the incident
    sub-page where it is fixed, relative to /incidents/{id}/."""
    inc = await get_accessible_incident(db, incident_id, user)
    return await evaluate_start_checks(db, inc)


# ─── Phase gates ─────────────────────────────────────────────────────────────

@router.get("/{incident_id}/gates", response_model=IncidentGates, summary="Get the phase-gate status")
async def get_incident_gates(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> IncidentGates:
    """Both phase gates, evaluated now by the same code that enforces them. Read-only;
    any user with access to the incident may read.

    items[] holds, for gate `post_incident` (Gate 1, checked by every PATCH that moves the
    incident into post_incident and by a re-open into post_incident) and gate `close` (Gate 2,
    checked by POST …/close; exempt for a false or benign positive): {gate, label, met, exempt,
    checks[], unmet[], warnings[], carried_forward[], sign_offs_required[], sign_offs[],
    state_sha256}. checks[] lists every check that applies, each {key, label, level block|warn,
    status met|unmet, detail, fix_hint, route (the incident sub-page where it is fixed)}; unmet[]
    is the unmet block-level checks (what 409 gate_unmet reports; `met` is true when it is
    empty), warnings[] the unmet warn-level ones (never blocking; recorded in the transition's
    audit row). carried_forward[] are open legal deadlines that do not block, with `due_at`.

    Gate 1 block: contained_at, eradicated_at, recovered_at set; no containment / eradication /
    recovery action open or in progress; mandatory legal deadlines due or within 72 h completed
    or waived; every in-scope system validated or not required (Recovery); every required
    stakeholder notification notified or not required; for a personal-data breach a GDPR / NIS2
    obligation recorded, plus the DPO's sign-off when one was waived. Gate 1 warn: deferred
    action without a reason; no system in scope.
    Gate 2 block: resolution summary; lessons learned Final with a conducted date, participants,
    and an owner and due date on every action item; checklist started and every active item
    (except incident_closed) checked or N/A; no non-Preparation playbook task open; legal
    deadlines already due handled; a cost entry or a business-impact assessment with content;
    every exhibit still held has a custodian and is on legal hold; no working-copy download
    issued or in progress; every LE package acknowledged; the IC's sign-off, and the DPO's for a
    breach. Gate 2 warn: N/A item or skipped task without a reason; open Preparation tasks;
    executive and full reports not generated after the last audited change.
    Sign off with POST …/gates/{gate}/sign-off."""
    inc = await get_accessible_incident(db, incident_id, user)
    return IncidentGates(incident_id=inc.id, items=[await evaluate_gate(db, inc, g) for g in GATES])


@router.post("/{incident_id}/gates/{gate}/sign-off", response_model=GateSignOffOut,
             status_code=status.HTTP_201_CREATED, summary="Sign off a phase gate",
             responses={403: {"model": ApiErrorBody, "description": "not_incident_lead (role ic), not_incident_dpo "
                                                                    "(role dpo)"},
                        409: {"model": ApiErrorBody, "description": "incident_closed, or sign_off_not_required "
                                                                    "(the gate doesn't need that role's sign-off now)"},
                        422: {"model": ApiErrorBody, "description": "role_required, statement_required"}})
async def sign_off_gate(
    incident_id: uuid.UUID, gate: GateName, req: GateSignOffCreate,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> GateSignOffOut:
    """Record the Incident Commander's (role ic) or the DPO's (role dpo) sign-off on a gate.
    Body {role, statement}: statement at least 10 characters (422 code statement_required);
    missing role is 422 code role_required.

    Who: role ic — the incident lead (an analyst assigned Incident Commander or Deputy IC on this
    incident, or an admin), else 403 code not_incident_lead; role dpo — an analyst assigned the
    data_protection_officer role on this incident, or an admin, else 403 code not_incident_dpo.
    The role must be in the gate's sign_offs_required (GET …/gates), else 409 code
    sign_off_not_required: close always needs ic, and dpo for a personal-data breach;
    post_incident needs dpo when a breach's GDPR / NIS2 obligation was waived as not required.
    A closed incident is 409 code incident_closed.

    Append-only: the record keeps the signer, the basis (signed_as), the statement, server time,
    and the gate's block-level checks as they are now with their SHA-256 (state_sha256). A later
    sign-off by the same role is added beside it. Only sign-offs made since the incident was last
    re-opened count. Audited (incident_gate_sign_off); it appears in the full report and the LE
    package. Signing doesn't change the phase: the gate still needs its other checks met."""
    statement = (req.statement or "").strip()
    if req.role is None:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "role_required", "role is required: ic or dpo")
    if len(statement) < REASON_MIN:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "statement_required",
                       f"statement is required: at least {REASON_MIN} characters")
    # Lock the row: a sign-off and a phase change / close on the same incident are serialised.
    inc = await get_accessible_incident(db, incident_id, user, for_update=True)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")
    if req.role == "ic" and not await is_incident_lead(db, user, inc):
        raise not_incident_lead("give the Incident Commander's sign-off")
    if req.role == "dpo" and not await is_incident_dpo(db, user, inc):
        raise ApiError(status.HTTP_403_FORBIDDEN, "not_incident_dpo",
                       "Only the analyst assigned Data Protection Officer on this incident, or an admin, can "
                       "give the DPO's sign-off.")
    result = await evaluate_gate(db, inc, gate)
    if req.role not in result.sign_offs_required:
        raise ApiError(status.HTTP_409_CONFLICT, "sign_off_not_required",
                       f"{GATE_LABEL[gate]} doesn't need a {'DPO' if req.role == 'dpo' else 'IC'} sign-off now"
                       + (" (false or benign positive: the gate is exempt)." if result.exempt else "."))
    state, sha = gate_state(inc.id, gate, result.checks)
    basis = LEAD_ROLE_KEYS if req.role == "ic" else (DPO_ROLE_KEY,)
    held = [k for k in await held_role_keys(db, user, inc) if k in basis]
    row = IncidentGateSignOff(
        id=uuid.uuid4(), incident_id=inc.id, gate=gate, role=req.role, user_id=user.id, username=user.username,
        signed_as=",".join(held) or "admin",
        signed_at=utcnow(), statement=statement, gate_state=state, state_sha256=sha)
    db.add(row)
    await db.flush()
    await write_audit(
        db, "incident_gate_sign_off",
        outcome="success",
        resource_type="incident", resource_id=str(inc.id), resource_label=inc.title,
        details={"sign_off_id": str(row.id), "gate": gate, "role": req.role, "signed_as": row.signed_as,
                 "statement": statement, "state_sha256": sha,
                 "unmet": [i.key for i in result.unmet], "warnings": [i.key for i in result.warnings]},
    )
    await db.commit()
    return sign_off_out(row, current=True, state_sha256=sha)


# ─── Caller's rights on the incident (E3) ────────────────────────────────────

@router.get("/{incident_id}/access", response_model=IncidentAccess, summary="Get my rights on the incident")
async def get_incident_access(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> IncidentAccess:
    """What the caller may do on this incident beyond their platform role, evaluated now
    (the same checks the endpoints enforce), so clients hold no permission rule.
    Not visible: 404. is_lead is true for an admin, or for an analyst (effective role: an
    API token's role cap applies) assigned as Incident Commander or Deputy Incident
    Commander here; a viewer is never lead, even when assigned. Removing the assignment
    ends the rights on the next request. capabilities: read_audit_log, manage_le_package, manage_disclosures,
    set_teams, override_gate, remove_any_assignment, replace_playbook (lead); assign_lead_roles (lead, or,
    while no active analyst/admin holds IC or Deputy, the creator or today's on-call
    analyst); remove_own_assignment (analysts and admins)."""
    inc = await get_accessible_incident(db, incident_id, user)
    is_lead, caps = await incident_capabilities(db, user, inc)
    return IncidentAccess(is_lead=is_lead, capabilities=caps)


# ─── Update ──────────────────────────────────────────────────────────────────

@router.patch("/{incident_id}", response_model=IncidentOut,
              responses={409: {"model": Union[GateUnmetBody, ApiErrorBody],
                               "description": "gate_unmet (body adds gate and unmet[]), "
                                              "phase_transition_invalid, incident_closed, would_unrestrict "
                                              "or would_lock_out"},
                         403: {"model": ApiErrorBody,
                               "description": "not_incident_lead (override_gate or team_ids)"}})
async def update_incident(
    incident_id: uuid.UUID, req: IncidentUpdate, request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> IncidentOut:
    """Partial update. A closed incident is 409 code incident_closed. 422 code
    detected_before_occurred when detected_at would end up before occurred_at (stored
    values count for fields not in the request), code detected_in_future when it is in
    the future. Errors are {detail, code}.

    Response milestones (contained_at, eradicated_at, recovered_at) are declared
    here, never set by the server (a phase change does not set them). 422 when one
    sent is in the future (code milestone_in_future), before the incident's detected_at
    (milestone_before_detection) or before its occurred_at (milestone_before_occurred)
    — stored or sent in the same request — or when eradicated_at / recovered_at would
    end up before contained_at, or recovered_at before eradicated_at
    (milestone_out_of_order). Setting a milestone that was empty adds one system
    timeline event ("Containment declared", "Eradication declared", "Recovery
    declared"); changing or clearing it is audited only.

    Setting triage_state to false_positive or benign_positive while the incident is (or
    ends up, with phase in the same request) outside detection_and_analysis needs
    triage_reason (at least 10 characters; 422 code triage_reason_required), because such
    an incident can be closed without Gate 2. A triage change with a triage_reason is
    audited with it and adds a system timeline event ("Triage changed").

    Phase changes follow 800-61 R3 order. phase=preparation is 409 code
    phase_transition_invalid. Moving to an earlier phase needs phase_reason (at least 10
    characters; 422 code phase_reason_required). Moving into post_incident runs Gate 1
    (see GET …/gates; milestones sent in the same request count): unmet is 409 code
    gate_unmet with {gate, unmet[]}. override_gate=true with a phase_reason proceeds
    anyway and writes an incident_gate_override audit row plus a system timeline event;
    a phase_reason alone never overrides. override_gate=true with a phase change needs
    incident-lead rights (admin, or an analyst assigned as Incident Commander or Deputy):
    403 code not_incident_lead otherwise. The gate check and the change are one
    transaction: if the check fails or errors, nothing changes.

    team_ids replaces the incident's teams and needs incident-lead rights (403 code
    not_incident_lead); only an admin can clear the teams of a restricted incident (409
    code would_unrestrict); an unknown team is 422 code team_not_found. A lead who is not
    an admin may only add teams they belong to, and must keep at least one of their own
    teams on the incident (409 code would_lock_out).

    dark_operation is not changed here: sending it is 422 code use_dark_operation_endpoint
    (toggle it with PATCH /api/incidents/{id}/oob/dark-operation, which audits the change).

    Moving a false or benign positive out of detection_and_analysis (a phase change, with
    triage_state staying false_positive / benign_positive) also needs triage_reason (422 code
    triage_reason_required); it is audited and posted as a system timeline event ("Triage set")."""
    if "dark_operation" in req.model_fields_set:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "use_dark_operation_endpoint",
                       "dark_operation can't be changed with PATCH /api/incidents/{id}: use "
                       "PATCH /api/incidents/{id}/oob/dark-operation with {\"enabled\": true|false}.")
    # A phase change checks gates and order against the row, so lock it until commit.
    inc = await get_accessible_incident(db, incident_id, user, for_update=req.phase is not None)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")

    sent = req.model_fields_set
    old_phase = inc.phase
    old_triage = inc.triage_state
    phase_change = req.phase is not None and req.phase != inc.phase
    if phase_change and req.override_gate and not await is_incident_lead(db, user, inc):
        raise not_incident_lead("override a phase gate")

    # Teams decide who can see the incident: the incident lead only (E3).
    new_team_ids = None
    if "team_ids" in sent:
        if not await is_incident_lead(db, user, inc):
            raise not_incident_lead("set its teams")
        new_team_ids = list(dict.fromkeys(req.team_ids or []))
        if not new_team_ids and user.role != "admin" and (await db.execute(
                select(incident_teams.c.team_id).where(incident_teams.c.incident_id == inc.id).limit(1)
        )).scalar_one_or_none() is not None:
            raise ApiError(status.HTTP_409_CONFLICT, "would_unrestrict",
                           "Only an admin can remove every team from a restricted incident: that would "
                           "make it visible to everyone.")
        known = set((await db.execute(select(Team.id).where(Team.id.in_(new_team_ids)))).scalars()) \
            if new_team_ids else set()
        if unknown := [str(t) for t in new_team_ids if t not in known]:
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "team_not_found",
                           f"Unknown team id(s): {', '.join(unknown)}")
        # A non-admin lead can't widen visibility to teams they're not in, or lock themselves out.
        if new_team_ids and user.role != "admin":
            mine = set((await db.execute(
                select(user_team.c.team_id).where(user_team.c.user_id == user.id))).scalars())
            current = set((await db.execute(
                select(incident_teams.c.team_id).where(incident_teams.c.incident_id == inc.id))).scalars())
            if foreign := [str(t) for t in new_team_ids if t not in current and t not in mine]:
                raise ApiError(status.HTTP_409_CONFLICT, "would_lock_out",
                               f"You can only add teams you belong to (not a member of: {', '.join(foreign)}). "
                               "Ask an admin to add other teams.")
            if not mine.intersection(new_team_ids):
                raise ApiError(status.HTTP_409_CONFLICT, "would_lock_out",
                               "Keep at least one of your own teams on the incident: without one you could no "
                               "longer see it. Ask an admin to hand it to another team.")

    phase_reason = None
    if phase_change:
        if req.phase == "preparation":
            raise ApiError(status.HTTP_409_CONFLICT, "phase_transition_invalid",
                           "An incident can't be moved to Preparation: Preparation is the readiness "
                           "work done before any incident.")
        if PHASE_ORDER.index(req.phase) < PHASE_ORDER.index(inc.phase) or req.override_gate:
            phase_reason = _phase_reason(req.phase_reason)
        elif (req.phase_reason or "").strip():
            phase_reason = req.phase_reason.strip()

    # A false / benign positive closes without Gate 2: outside D&A that needs a reason.
    triage_reason = None
    leaves_da_as_fp = False
    if req.triage_state is not None and req.triage_state != inc.triage_state:
        end_phase = req.phase if req.phase is not None else inc.phase
        if req.triage_state in CLOSABLE_ANY_PHASE and end_phase != "detection_and_analysis":
            triage_reason = _triage_reason(req.triage_reason)
        elif (req.triage_reason or "").strip():
            triage_reason = req.triage_reason.strip()
    elif phase_change and inc.phase == "detection_and_analysis" and inc.triage_state in CLOSABLE_ANY_PHASE:
        # M2: an FP/BP set inside D&A (no reason needed there) must not leave D&A without one,
        # or it reaches closure without Gate 2 and without any recorded justification.
        triage_reason = _triage_reason(req.triage_reason,
                                       "to move a false or benign positive out of Detection & Analysis")
        leaves_da_as_fp = True

    if "occurred_at" in sent or "detected_at" in sent:
        _check_detected_at(
            req.occurred_at if "occurred_at" in sent else inc.occurred_at,
            req.detected_at if "detected_at" in sent else inc.detected_at,
            check_future="detected_at" in sent,
        )
    if sent & set(MILESTONES):
        _check_milestones({f: getattr(req if f in sent else inc, f) for f in MILESTONES}, sent,
                          detected_at=req.detected_at if "detected_at" in sent else inc.detected_at,
                          occurred_at=req.occurred_at if "occurred_at" in sent else inc.occurred_at)
    newly_declared = [f for f in MILESTONES
                      if f in sent and getattr(req, f) is not None and getattr(inc, f) is None]

    # Gate 1 runs before anything is changed; an unmet gate or an error leaves the incident as it was.
    overridden, gate = None, None
    if phase_change and req.phase == "post_incident":
        gate = await evaluate_gate(db, inc, "post_incident",
                                   milestones={f: getattr(req if f in sent else inc, f) for f in MILESTONES})
        overridden = _require_gate(gate, req.override_gate, "and a phase_reason of at least 10 characters")

    changed: dict[str, object] = {}
    old_severity = inc.severity
    for field in ("title", "description", "severity", "phase", "tlp", "triage_state", "incident_type", "detection_method", "reporter"):
        new = getattr(req, field)
        if new is not None and new != getattr(inc, field):
            setattr(inc, field, new)
            changed[field] = new

    # Datetime fields: use model_fields_set to allow explicit null-set (clearing).
    for field in ("occurred_at", "detected_at", *MILESTONES):
        if field in req.model_fields_set:
            val = getattr(req, field)
            setattr(inc, field, val)
            changed[field] = val.isoformat() if val else None
    if "detected_at" in sent:      # I4: a time set here was entered by a person or API client
        inc.detected_at_source = "reported" if req.detected_at is not None else None

    # I4 intake fields: null (or blank text) clears.
    for field in INTAKE_FIELDS:
        if field in sent:
            val = _clean(getattr(req, field))
            if val != getattr(inc, field):
                setattr(inc, field, val)
                changed[field] = val

    # A milestone set for the first time goes on the timeline, at the declared time.
    for field in newly_declared:
        db.add(TimelineEvent(
            id=uuid.uuid4(),
            incident_id=inc.id,
            event_time=getattr(inc, field),
            source="Incident",
            event_type=_MILESTONE_EVENT[field],
            description=_MILESTONE_EVENT[field],
            ir_phase="containment_eradication_recovery",
            origin="system",
            is_system=True,
            external_safe=False,
            system_source="milestone",
            created_by_id=user.id,
        ))

    # Team assignment — incident lead only (checked above): replace the full list.
    if new_team_ids is not None:
        await db.execute(
            incident_teams.delete().where(incident_teams.c.incident_id == incident_id)
        )
        for team_id in new_team_ids:
            await db.execute(
                incident_teams.insert().values(incident_id=inc.id, team_id=team_id)
            )
        changed["team_ids"] = [str(t) for t in new_team_ids]

    # Tags — replace the full list when explicitly provided. Normalise at the
    # boundary so storage stays in canonical lowercase-dashed form.
    if "tags" in req.model_fields_set:
        inc.tags = normalize_tags(req.tags)
        changed["tags"] = inc.tags

    if overridden:
        await _record_override(db, inc, user, overridden, phase_reason, inc.phase,
                               {"from_phase": old_phase, "to_phase": inc.phase})

    if leaves_da_as_fp and "phase" in changed:
        db.add(TimelineEvent(
            id=uuid.uuid4(),
            incident_id=inc.id,
            event_time=utcnow(),
            source="Incident",
            event_type="Triage set",
            description=f"Moved to {_PHASE_LABEL.get(inc.phase, inc.phase)} as "
                        f"{_TRIAGE_LABEL.get(inc.triage_state, inc.triage_state)}: {triage_reason}",
            ir_phase=inc.phase,
            origin="system",
            is_system=True,
            external_safe=False,
            system_source="triage",
            created_by_id=user.id,
        ))

    if "triage_state" in changed and triage_reason:
        db.add(TimelineEvent(
            id=uuid.uuid4(),
            incident_id=inc.id,
            event_time=utcnow(),
            source="Incident",
            event_type="Triage changed",
            description=f"Triage state {_TRIAGE_LABEL.get(old_triage, old_triage)} → "
                        f"{_TRIAGE_LABEL.get(inc.triage_state, inc.triage_state)}: {triage_reason}",
            ir_phase=inc.phase,
            origin="system",
            is_system=True,
            external_safe=False,
            system_source="triage",
            created_by_id=user.id,
        ))

    if changed:
        details: dict = {"changes": changed}
        if "phase" in changed:
            details["from_phase"] = old_phase
            if phase_reason:
                details["phase_reason"] = phase_reason
            if gate is not None:     # I5: Gate 1 ran; its warnings never block, they are recorded here
                details["gate"] = "overridden" if overridden else "met"
                details["gate_warnings"] = [i.key for i in gate.warnings]
        if "triage_state" in changed:
            details["from_triage_state"] = old_triage
            if triage_reason:
                details["triage_reason"] = triage_reason
        elif leaves_da_as_fp and "phase" in changed:
            details["triage_state"] = inc.triage_state
            details["triage_reason"] = triage_reason
        await write_audit(
            db, "incident_update",
            outcome="success",
            resource_type="incident", resource_id=str(inc.id), resource_label=inc.title,
            details=details,
        )
    # I2: a severity reached for the first time starts its matrix rules' clocks now; a severity or
    # type change re-derives the stakeholder notification obligations (never deleting one).
    if "severity" in changed:
        await record_severity_level(db, inc, at=utcnow(), source="change", user_id=user.id, from_severity=old_severity)
    if "severity" in changed or "incident_type" in changed:
        await sync_notifications(db, inc, cause="severity_changed" if "severity" in changed else "type_changed",
                                 user_id=user.id)
    await db.commit()
    await db.refresh(inc)
    # L3 (R47): a phase and a severity change in one update fire both events (each through
    # _fire_hooks, i.e. the outbound policy), the severity one is no longer dropped.
    if "phase" in changed:
        await _fire_hooks(db, "phase_changed", inc,
                          extra_facts=[{"name": "New Phase", "value": PHASE_LABEL.get(inc.phase, inc.phase)}])
    if "severity" in changed:
        await _fire_hooks(db, "severity_changed", inc,
                          extra_facts=[{"name": "New Severity", "value": inc.severity.title()}])
    if "phase" in changed:
        await notify_phase_changed(
            db, user.id, inc.id,
            inc.ref or str(inc.id), user.username, inc.phase,
        )
    return IncidentOut.model_validate(inc)


# ─── Close ───────────────────────────────────────────────────────────────────
# "Resolve" is a phase change to post_incident (PATCH); closing is this separate,
# reasoned sign-off. Re-opening needs a reason and a target phase.

# Triage states that may be closed from any phase.
CLOSABLE_ANY_PHASE = ("false_positive", "benign_positive")
_PHASE_LABEL = {
    "detection_and_analysis":           "Detection & Analysis",
    "containment_eradication_recovery": "Containment, Eradication & Recovery",
    "post_incident":                    "Post-Incident",
}


def _reason(raw: Optional[str]) -> str:
    """The trimmed reason; 422 reason_required when missing or under 10 characters."""
    reason = (raw or "").strip()
    if len(reason) < 10:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "reason_required",
                       "reason is required: at least 10 characters")
    return reason


async def _set_closed_item(db: AsyncSession, incident_id: uuid.UUID, user: Optional[User]) -> bool:
    """Tick (user given) or untick (None) the "incident_closed" closure-checklist item.
    Only when the incident's checklist exists; returns whether the item was found."""
    item = (await db.execute(select(ClosureChecklistItem).where(
        ClosureChecklistItem.incident_id == incident_id,
        ClosureChecklistItem.item_key == "incident_closed",
        ClosureChecklistItem.is_active.is_(True),
    ))).scalar_one_or_none()
    if item is None:
        return False
    item.checked       = user is not None
    item.checked_by_id = user.id if user else None
    item.checked_by    = (user.full_name or user.username) if user else None
    item.checked_at    = utcnow() if user else None
    return True


def _closure_event(inc: Incident, user: User, event_type: str, description: str,
                   at: datetime) -> TimelineEvent:
    return TimelineEvent(
        id=uuid.uuid4(),
        incident_id=inc.id,
        event_time=at,
        source="Incident",
        event_type=event_type,
        description=description,
        ir_phase=inc.phase,
        origin="system",
        is_system=True,
        external_safe=False,
        system_source="closure",
        created_by_id=user.id,
    )


@router.post("/{incident_id}/close", response_model=IncidentOut,
             responses={409: {"model": Union[GateUnmetBody, ApiErrorBody],
                              "description": "phase_not_post_incident, or gate_unmet (body adds gate "
                                             "and unmet[])"},
                        403: {"model": ApiErrorBody, "description": "not_incident_lead (override_gate)"}})
async def close_incident(
    incident_id: uuid.UUID, req: IncidentClose, request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> IncidentOut:
    """Close (sign off) an incident. Body {reason}: the sign-off statement, at least
    10 characters (422 code reason_required).

    The incident must be in post_incident (409 code phase_not_post_incident), unless
    its triage_state is false_positive or benign_positive. Gate 2 must be met (see GET
    …/gates; unmet is 409 code gate_unmet with {gate, unmet[]}); override_gate=true
    closes anyway, with the reason as the justification, and writes an
    incident_gate_override audit row plus a system timeline event. A false or benign
    positive skips Gate 2; the close audit row records gate=skipped, and a close from
    containment_eradication_recovery or post_incident also adds a "Gate 2 skipped" system
    timeline event carrying the reason. override_gate=true needs incident-lead rights (admin,
    or an analyst assigned as Incident Commander or Deputy): 403 code not_incident_lead
    otherwise. The incident row is locked, and the gate check and the close are one
    transaction. The phase is not changed.

    Sets status=closed, closed_at and closed_by_id; ticks the "incident_closed"
    closure-checklist item if the checklist exists; writes an audit row and a system
    timeline event carrying the reason. Already closed: returned unchanged.
    To move an incident to Post-Incident ("Resolve"), PATCH phase=post_incident."""
    reason = _reason(req.reason)
    inc = await get_accessible_incident(db, incident_id, user, for_update=True)
    if inc.status == "closed":
        return IncidentOut.model_validate(inc)
    if req.override_gate and not await is_incident_lead(db, user, inc):
        raise not_incident_lead("override a phase gate")
    if inc.phase != "post_incident" and inc.triage_state not in CLOSABLE_ANY_PHASE:
        raise ApiError(status.HTTP_409_CONFLICT, "phase_not_post_incident",
                       "Move the incident to Post-Incident before closing it; only a false or "
                       "benign positive can be closed from another phase.")

    # Gate 2 runs before anything is changed; an unmet gate or an error leaves the incident open.
    gate = await evaluate_gate(db, inc, "close")
    overridden = _require_gate(gate, req.override_gate, "(the reason is recorded as the justification)")

    now = utcnow()
    inc.status = "closed"
    inc.closed_at = now
    inc.closed_by_id = user.id
    ticked = await _set_closed_item(db, inc.id, user)
    db.add(_closure_event(inc, user, "Incident closed", f"Incident closed: {reason}", now))
    if gate.exempt and inc.phase != "detection_and_analysis":
        db.add(_closure_event(inc, user, "Gate 2 skipped",
                              f"Gate 2 skipped (false/benign positive, closed from "
                              f"{_PHASE_LABEL.get(inc.phase, inc.phase)}): {reason}", now))
    if overridden:
        await _record_override(db, inc, user, overridden, reason, inc.phase, {})

    await write_audit(
        db, "incident_close",
        outcome="success",
        resource_type="incident", resource_id=str(inc.id), resource_label=inc.title,
        details={"reason": reason, "phase": inc.phase, "triage_state": inc.triage_state,
                 "checklist_item_ticked": ticked,
                 "gate": "skipped" if gate.exempt else "overridden" if overridden else "met",
                 "gate_warnings": [i.key for i in gate.warnings]},
    )
    await db.commit()
    await db.refresh(inc)
    await _fire_hooks(db, "incident_resolved", inc)   # event key kept (B3); the card reads "Incident Closed" (L3, R47)
    return IncidentOut.model_validate(inc)


# ─── Reopen ──────────────────────────────────────────────────────────────────

@router.post("/{incident_id}/reopen", response_model=IncidentOut,
             responses={409: {"model": GateUnmetBody,
                              "description": "gate_unmet (body adds gate and unmet[]): re-opening into "
                                             "post_incident from another phase with Gate 1 unmet"},
                        403: {"model": ApiErrorBody, "description": "not_incident_lead (override_gate)"}})
async def reopen_incident(
    incident_id: uuid.UUID, req: IncidentReopen, request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> IncidentOut:
    """Re-open a closed incident. Body {reason, phase}: reason at least 10 characters
    (422 code reason_required); phase is detection_and_analysis,
    containment_eradication_recovery or post_incident (missing: 422 code
    phase_required).

    Re-opening into post_incident an incident that was closed in another phase (a false or
    benign positive closed from detection_and_analysis or containment_eradication_recovery)
    enters Post-Incident, so Gate 1 runs as on PATCH (see GET …/gates): unmet is 409 code
    gate_unmet with {gate, unmet[]}. override_gate=true re-opens anyway, with the reason as
    the justification, and writes an incident_gate_override audit row plus a system timeline
    event. override_gate=true needs incident-lead rights (admin, or an analyst assigned as
    Incident Commander or Deputy): 403 code not_incident_lead otherwise. An incident closed
    in post_incident and re-opened there does not change phase, so Gate 1 does not run. The
    incident row is locked, and the gate check and the re-open are one transaction.

    Sets status=open and the phase; clears closed_at and closed_by_id; unticks the
    "incident_closed" closure-checklist item; writes an audit row (with the previous
    closer, and `gate` met / overridden when Gate 1 ran) and a system timeline event
    carrying the reason. Already open: returned unchanged."""
    reason = _reason(req.reason)
    if req.phase is None:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "phase_required",
                       "phase is required: detection_and_analysis, "
                       "containment_eradication_recovery or post_incident")
    inc = await get_accessible_incident(db, incident_id, user, for_update=True)
    if inc.status == "open":
        return IncidentOut.model_validate(inc)
    if req.override_gate and not await is_incident_lead(db, user, inc):
        raise not_incident_lead("override a phase gate")

    # Gate 1 runs before anything is changed; an unmet gate or an error leaves the incident closed.
    gate_status, overridden, gate_warnings = None, None, []
    if req.phase == "post_incident" and inc.phase != "post_incident":
        gate = await evaluate_gate(db, inc, "post_incident")
        overridden = _require_gate(gate, req.override_gate, "(the reason is recorded as the justification)")
        gate_status = "overridden" if overridden else "met"
        gate_warnings = [i.key for i in gate.warnings]

    previous = {"from_phase": inc.phase,
                "previous_closed_at": inc.closed_at.isoformat() if inc.closed_at else None,
                "previous_closed_by_id": str(inc.closed_by_id) if inc.closed_by_id else None}
    inc.status = "open"
    inc.closed_at = None
    inc.closed_by_id = None
    inc.phase = req.phase
    unticked = await _set_closed_item(db, inc.id, None)
    db.add(_closure_event(inc, user, "Incident re-opened",
                          f"Incident re-opened to {_PHASE_LABEL[req.phase]}: {reason}", utcnow()))
    if overridden:
        await _record_override(db, inc, user, overridden, reason, inc.phase,
                               {"from_phase": previous["from_phase"], "to_phase": inc.phase, "on": "reopen"})

    await write_audit(
        db, "incident_reopen",
        outcome="success",
        resource_type="incident", resource_id=str(inc.id), resource_label=inc.title,
        details={"reason": reason, "phase": inc.phase, **previous, "checklist_item_unticked": unticked,
                 **({"gate": gate_status, "gate_warnings": gate_warnings} if gate_status else {})},
    )
    await db.commit()
    await db.refresh(inc)
    return IncidentOut.model_validate(inc)
