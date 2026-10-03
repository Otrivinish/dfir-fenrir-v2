"""Phase gates v1: what must be true before an incident enters Post-Incident (Gate 1)
and before it is closed (Gate 2).

`evaluate_gate()` is the only implementation. GET /api/incidents/{id}/gates reports it;
PATCH /api/incidents/{id} (any move into post_incident) and POST …/close enforce it in
the same transaction as the write, so a failed evaluation never lets a transition
through. The frontend only renders what this returns.

Standards: NIST SP 800-61 R3 with CSF 2.0 — Gate 1 = RS.MI-01/02 (incidents contained
and eradicated) and RC.RP-01..06 (recovery executed, verified, its end declared); Gate 2 =
ID.IM-03/04 (improvements from lessons learned) — plus the CISA IR playbook's post-incident activity.
v1 checks only what the data model records; see docs/standards-map.md §L1.
"""
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from models import (BusinessImpact, ClosureChecklistItem, Incident, IncidentCost, LessonsLearned,
                    PlaybookTask, RegulatoryDeadline, RespondAction, utcnow)
from schemas import GateItem, GateName, GateResult

GATES: tuple[GateName, ...] = ("post_incident", "close")
GATE_LABEL = {
    "post_incident": "Gate 1 (Containment, Eradication & Recovery → Post-Incident)",
    "close":         "Gate 2 (Post-Incident → Closed)",
}
# A false or benign positive closes without Gate 2 (the close route audits the skip).
CLOSE_EXEMPT_TRIAGE = ("false_positive", "benign_positive")

_WORK_OPEN     = ("open", "in_progress")       # respond actions and playbook tasks
_DEADLINE_OPEN = ("pending", "in_progress")    # legal deadlines
_GATE1_WINDOW_HOURS = 72                       # Gate 1: mandatory deadlines this short block even before due
_MILESTONES = (("contained_at", "Contained"), ("eradicated_at", "Eradicated"), ("recovered_at", "Recovered"))
_BIA_FIELDS = ("financial", "operational", "data_exposure", "reputational", "regulatory", "legal", "notes")
_NAMES_MAX = 5


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _names(names: list[str]) -> str:
    more = len(names) - _NAMES_MAX
    return "; ".join(names[:_NAMES_MAX]) + (f"; and {more} more" if more > 0 else "")


def _blank(v) -> bool:
    return not (isinstance(v, str) and v.strip())


def _deadline_name(d: RegulatoryDeadline) -> str:
    from legal.routes import article_label   # local: legal.routes imports FastAPI deps
    article = article_label(d.regulation, d.article, d.obligation)
    return f"{d.regulation} {article}" if article else f"{d.regulation}: {d.obligation}"


async def _open_deadlines(db: AsyncSession, incident_id) -> list[RegulatoryDeadline]:
    return list((await db.execute(
        select(RegulatoryDeadline)
        .where(RegulatoryDeadline.incident_id == incident_id,
               RegulatoryDeadline.status.in_(_DEADLINE_OPEN))
        .order_by(RegulatoryDeadline.deadline_at)
    )).scalars().all())


def _carried(d: RegulatoryDeadline) -> GateItem:
    return GateItem(key="legal_deadline_open", label=f"{_deadline_name(d)} — {d.obligation}",
                    due_at=_as_utc(d.deadline_at), route="legal")


async def _gate1(db: AsyncSession, inc: Incident, milestones: dict) -> tuple[list, list]:
    unmet, carried = [], []
    for field, label in _MILESTONES:
        if milestones[field] is None:
            unmet.append(GateItem(
                key=f"{field}_missing", label=f"{label} time not declared",
                fix_hint=f"Declare {label.lower()} in the incident header, or set it on Details ({field})",
                route="details"))

    actions = (await db.execute(
        select(RespondAction.title, RespondAction.category, RespondAction.status)
        .where(RespondAction.incident_id == inc.id,
               RespondAction.category.in_(("containment", "eradication", "recovery")),
               RespondAction.status.in_(_WORK_OPEN))
        .order_by(RespondAction.category, RespondAction.order_index, RespondAction.created_at)
    )).all()
    if actions:
        unmet.append(GateItem(
            key="respond_actions_open",
            label=f"{len(actions)} containment / eradication / recovery action(s) still open or in progress",
            detail=_names([f"{a.title} ({a.category}, {a.status.replace('_', ' ')})" for a in actions]),
            fix_hint="Mark each Done or Deferred on Respond", route="respond"))

    now = utcnow()
    blocking = []
    for d in await _open_deadlines(db, inc.id):
        if d.is_mandatory and (_as_utc(d.deadline_at) <= now or d.deadline_hours <= _GATE1_WINDOW_HOURS):
            blocking.append(d)
        else:
            carried.append(_carried(d))
    if blocking:
        unmet.append(GateItem(
            key="legal_deadlines_open",
            label=f"{len(blocking)} mandatory legal deadline(s) due or with a window of "
                  f"{_GATE1_WINDOW_HOURS} h or less, not completed or waived",
            detail=_names([_deadline_name(d) for d in blocking]),
            fix_hint="Complete them, or waive them with a justification, on Legal", route="legal"))
    return unmet, carried


async def _gate2(db: AsyncSession, inc: Incident) -> tuple[list, list]:
    unmet, carried = [], []
    ll = (await db.execute(
        select(LessonsLearned).where(LessonsLearned.incident_id == inc.id)
    )).scalar_one_or_none()

    missing = [name for name, v in (("what happened", ll and ll.incident_narrative),
                                    ("root cause", ll and ll.root_cause_description),
                                    ("recommendations", ll and ll.report_security_recommendations)) if _blank(v)]
    if missing:
        unmet.append(GateItem(
            key="lessons_summary_incomplete", label="Resolution summary incomplete",
            detail="Missing: " + ", ".join(missing),
            fix_hint="Fill it in on Details → Resolution summary (or Post-Incident → Lessons Learned)",
            route="details"))
    if not ll or ll.status != "final":
        unmet.append(GateItem(
            key="lessons_not_final", label="Lessons learned is not Final",
            fix_hint="Set Status to Final on Post-Incident → Lessons Learned", route="post-incident"))
    if not ll or ll.conducted_at is None:
        unmet.append(GateItem(
            key="lessons_conducted_at_missing", label="Lessons-learned review date not set",
            fix_hint="Set Date conducted on Post-Incident → Lessons Learned", route="post-incident"))
    if not ll or not any(not _blank(p) for p in (ll.participants or [])):
        unmet.append(GateItem(
            key="lessons_participants_missing", label="No lessons-learned participants recorded",
            fix_hint="Add Participants on Post-Incident → Lessons Learned", route="post-incident"))
    incomplete = [ai for ai in ((ll and ll.action_items) or [])
                  if not isinstance(ai, dict) or _blank(ai.get("owner")) or _blank(ai.get("due_date"))]
    if incomplete:
        unmet.append(GateItem(
            key="lessons_action_items_incomplete",
            label=f"{len(incomplete)} lessons-learned action item(s) without an owner or due date",
            detail=_names([(ai.get("action") if isinstance(ai, dict) and not _blank(ai.get("action"))
                            else "(untitled)") for ai in incomplete]),
            fix_hint="Give each an Owner and a Due date on Post-Incident → Lessons Learned",
            route="post-incident"))

    items = (await db.execute(
        select(ClosureChecklistItem)
        .where(ClosureChecklistItem.incident_id == inc.id)
        .order_by(ClosureChecklistItem.sort_order)
    )).scalars().all()
    if not items:
        unmet.append(GateItem(
            key="checklist_not_started", label="Closure checklist not started",
            fix_hint="Work through Post-Incident → Closure Checklist", route="post-incident"))
    else:
        # "Incident formally closed" is ticked by the close itself.
        unchecked = [i.label for i in items
                     if i.is_active and not i.checked and i.item_key != "incident_closed"]
        if unchecked:
            unmet.append(GateItem(
                key="checklist_incomplete", label=f"{len(unchecked)} closure-checklist item(s) not checked",
                detail=_names(unchecked),
                fix_hint="Check them on Post-Incident → Closure Checklist", route="post-incident"))

    tasks = (await db.execute(
        select(PlaybookTask.title)
        .where(PlaybookTask.incident_id == inc.id, PlaybookTask.status.in_(_WORK_OPEN))
        .order_by(PlaybookTask.order_index, PlaybookTask.created_at)
    )).scalars().all()
    if tasks:
        unmet.append(GateItem(
            key="playbook_tasks_open", label=f"{len(tasks)} playbook task(s) open or in progress",
            detail=_names(list(tasks)),
            fix_hint="Mark each Done, or Skipped with a reason, on Playbook", route="playbook"))

    now = utcnow()
    overdue = []
    for d in await _open_deadlines(db, inc.id):
        if _as_utc(d.deadline_at) <= now:
            overdue.append(d)
        else:
            carried.append(_carried(d))
    if overdue:
        unmet.append(GateItem(
            key="legal_deadlines_overdue",
            label=f"{len(overdue)} legal deadline(s) past due, not completed or waived",
            detail=_names([_deadline_name(d) for d in overdue]),
            fix_hint="Complete them, or waive them with a justification, on Legal", route="legal"))

    costs = (await db.execute(
        select(func.count()).select_from(IncidentCost).where(IncidentCost.incident_id == inc.id)
    )).scalar() or 0
    bia = (await db.execute(
        select(BusinessImpact).where(BusinessImpact.incident_id == inc.id)
    )).scalar_one_or_none()
    # Opening the Reports tab creates an empty assessment, so only one with content counts.
    if not costs and not (bia and any(not _blank(getattr(bia, f)) for f in _BIA_FIELDS)):
        unmet.append(GateItem(
            key="costs_missing", label="No cost entry and no business-impact assessment",
            fix_hint="Add a cost, or fill in the business impact, on Post-Incident → Reports",
            route="post-incident"))
    return unmet, carried


async def evaluate_gate(db: AsyncSession, incident: Incident, gate: GateName, *,
                        milestones: Optional[dict] = None) -> GateResult:
    """Evaluate one gate for `incident` now. Read-only.

    gate "post_incident" (Gate 1): contained_at, eradicated_at and recovered_at are set;
    no containment / eradication / recovery action is open or in progress; every mandatory
    legal deadline that is due, or whose window is 72 h or less, is completed or waived.
    Other open deadlines are carried forward.

    gate "close" (Gate 2): the resolution summary (what happened, root cause,
    recommendations) is filled in; lessons learned is Final, with a conducted date,
    participants, and an owner and due date on every action item; the closure checklist
    exists and every active item except "incident_closed" is checked; no playbook task is
    open or in progress; every legal deadline already due is completed or waived (future
    ones are carried forward); there is a cost entry or a business-impact assessment with
    content. Exempt (met) for a false or benign positive.

    `milestones` overrides the stored contained/eradicated/recovered values (a PATCH that
    declares them and changes phase in one request)."""
    if gate == "close" and incident.triage_state in CLOSE_EXEMPT_TRIAGE:
        return GateResult(gate=gate, label=GATE_LABEL[gate], met=True, exempt=True)
    if gate == "post_incident":
        ms = milestones or {f: getattr(incident, f) for f, _ in _MILESTONES}
        unmet, carried = await _gate1(db, incident, ms)
    else:
        unmet, carried = await _gate2(db, incident)
    return GateResult(gate=gate, label=GATE_LABEL[gate], met=not unmet, unmet=unmet, carried_forward=carried)
