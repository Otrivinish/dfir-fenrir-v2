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
from incidents.access import (accessible_filter, get_accessible_incident, incident_capabilities,
                              is_incident_lead, not_incident_lead)
from incidents.gates import GATE_LABEL, GATES, evaluate_gate
from incidents.reference import assign as assign_reference
from models import (ClosureChecklistItem, Entity, EntityFile, Evidence, IOC, Incident,
                    IncidentAssignment, IncidentHandoff, PlaybookTask, RespondAction, Team,
                    TimelineEvent, User, incident_teams, user_team, utcnow)
from notifications.service import notify_incident_created, notify_phase_changed
from outbound_webhooks.service import suppressed_by_dark_operation
from schemas import (GateResult, GateUnmetBody, IncidentAccess, IncidentClose, IncidentCreate, IncidentGates, IncidentList,
                     IncidentOut, IncidentReopen, IncidentSnapshot, IncidentUpdate, IncidentState, Phase,
                     Severity, Tlp)

router = APIRouter()


async def _fire_hooks(db, event: str, inc: Incident, extra_facts=None) -> None:
    """Dispatch outbound webhooks + email alert. Best-effort; never raises.
    Blocked (and audited) unless Dark Operation is off — fail closed."""
    if await suppressed_by_dark_operation(db, event, inc):
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
            extra={"gate": result.gate, "unmet": [i.model_dump(mode="json", exclude_none=True)
                                                  for i in result.unmet]},
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
        details={"gate": result.gate, "unmet": keys, "reason": reason, **details},
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
    {items, next_cursor}.
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
    items = [IncidentOut.model_validate(r) for r in rows[:limit]]
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


@router.post("", response_model=IncidentOut, status_code=status.HTTP_201_CREATED,
             responses={409: {"model": ApiErrorBody, "description": "would_lock_out (team_ids)"},
                        422: {"model": ApiErrorBody,
                              "description": "team_not_found, detected_before_occurred, detected_in_future "
                                             "or triage_reason_required"}})
async def create_incident(
    req: IncidentCreate, request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> IncidentOut:
    """Open an incident. phase must be detection_and_analysis or
    containment_eradication_recovery. detected_at is stored as given (the
    server never fills it in); 422 when it is before occurred_at or in the
    future (2 min clock-skew allowance).

    team_ids restricts the incident to those teams from the start (empty = visible to
    everyone). An unknown team is 422 code team_not_found. An admin may pick any team; an
    analyst only teams they belong to (409 code would_lock_out otherwise), so the creator
    always keeps access. The teams are audited with the creation.

    triage_state false_positive or benign_positive with a phase other than
    detection_and_analysis needs triage_reason (at least 10 characters; 422 code
    triage_reason_required), as on PATCH: such an incident can be closed without Gate 2.
    A triage_reason is audited with the creation and adds a system timeline event
    ("Triage set")."""
    _check_detected_at(req.occurred_at, req.detected_at)
    if req.triage_state in CLOSABLE_ANY_PHASE and req.phase != "detection_and_analysis":
        triage_reason = _triage_reason(req.triage_reason)
    else:
        triage_reason = (req.triage_reason or "").strip() or None
    team_ids = await _create_team_ids(db, user, req.team_ids)
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
        tags=normalize_tags(req.tags),
        dark_operation=req.dark_operation,
    )
    db.add(inc)
    await db.flush()

    for team_id in team_ids:
        await db.execute(
            incident_teams.insert().values(incident_id=inc.id, team_id=team_id)
        )

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
                 "dark_operation": inc.dark_operation,
                 "detected_at": inc.detected_at.isoformat() if inc.detected_at else None,
                 **({"team_ids": [str(t) for t in team_ids]} if team_ids else {}),
                 **({"triage_state": inc.triage_state, "triage_reason": triage_reason} if triage_reason else {})},
    )
    await db.commit()
    await db.refresh(inc)
    await _fire_hooks(db, "incident_created", inc)
    await notify_incident_created(db, user.id, inc.id, inc.title)
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
    await get_accessible_incident(db, incident_id, user)

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
        .where(PlaybookTask.incident_id == incident_id)
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
        select(RespondAction.status, func.count())
        .where(RespondAction.incident_id == incident_id)
        .group_by(RespondAction.status)
    )).all()
    rs_by_status = {row[0]: int(row[1]) for row in rs_rows}
    respond_open  = rs_by_status.get("open", 0) + rs_by_status.get("in_progress", 0)
    respond_total = sum(rs_by_status.values())
    handoffs_pending = int((await db.execute(
        select(func.count()).select_from(IncidentHandoff)
        .where(IncidentHandoff.incident_id == incident_id, IncidentHandoff.status == "pending")
    )).scalar() or 0)

    return IncidentSnapshot(
        iocs=iocs, entities=entities, evidence=evidence, timeline=timeline,
        affected_systems=affected_systems, assignments=assignments,
        playbook_total=pb_total, playbook_done=pb_done, playbook_skipped=pb_skipped,
        files=files, respond_open=respond_open, respond_total=respond_total,
        handoffs_pending=handoffs_pending,
    )


# ─── Phase gates ─────────────────────────────────────────────────────────────

@router.get("/{incident_id}/gates", response_model=IncidentGates, summary="Get the phase-gate status")
async def get_incident_gates(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> IncidentGates:
    """Both phase gates, evaluated now by the same code that enforces them. Read-only;
    any user with access to the incident may read.

    items[] holds {gate, label, met, exempt, unmet[], carried_forward[]} for gate
    `post_incident` (Gate 1, checked by every PATCH that moves the incident into
    post_incident) and gate `close` (Gate 2, checked by POST …/close; exempt for a
    false or benign positive). Each unmet item has a stable `key`, a `label` and optional
    `detail`, `fix_hint` and `route` (the incident sub-page where it is fixed);
    carried-forward items are open legal deadlines that do not block, with `due_at`.

    Gate 1: contained_at, eradicated_at, recovered_at set; no containment / eradication /
    recovery action open or in progress; mandatory legal deadlines that are due or have a
    window of 72 h or less completed or waived. Gate 2: resolution summary filled in;
    lessons learned Final with a conducted date, participants, and an owner and due date on
    every action item; closure checklist started and every active item except
    incident_closed checked; no playbook task open or in progress; legal deadlines already
    due completed or waived; a cost entry or a business-impact assessment with content."""
    inc = await get_accessible_incident(db, incident_id, user)
    return IncidentGates(incident_id=inc.id, items=[await evaluate_gate(db, inc, g) for g in GATES])


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
    ends the rights on the next request. capabilities: read_audit_log, manage_le_package,
    set_teams, override_gate, remove_any_assignment (lead); assign_lead_roles (lead, or,
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
    overridden = None
    if phase_change and req.phase == "post_incident":
        gate = await evaluate_gate(db, inc, "post_incident",
                                   milestones={f: getattr(req if f in sent else inc, f) for f in MILESTONES})
        overridden = _require_gate(gate, req.override_gate, "and a phase_reason of at least 10 characters")

    changed: dict[str, object] = {}
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
    await db.commit()
    await db.refresh(inc)
    if "phase" in changed:
        await _fire_hooks(db, "phase_changed", inc,
                          extra_facts=[{"name": "New Phase", "value": inc.phase.replace("_", " ").title()}])
        await notify_phase_changed(
            db, user.id, inc.id,
            inc.ref or str(inc.id), inc.title, inc.phase,
        )
    elif "severity" in changed:
        await _fire_hooks(db, "severity_changed", inc,
                          extra_facts=[{"name": "New Severity", "value": inc.severity.title()}])
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
                 "gate": "skipped" if gate.exempt else "overridden" if overridden else "met"},
    )
    await db.commit()
    await db.refresh(inc)
    await _fire_hooks(db, "incident_resolved", inc)
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
    gate_state, overridden = None, None
    if req.phase == "post_incident" and inc.phase != "post_incident":
        gate = await evaluate_gate(db, inc, "post_incident")
        overridden = _require_gate(gate, req.override_gate, "(the reason is recorded as the justification)")
        gate_state = "overridden" if overridden else "met"

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
                 **({"gate": gate_state} if gate_state else {})},
    )
    await db.commit()
    await db.refresh(inc)
    return IncidentOut.model_validate(inc)
