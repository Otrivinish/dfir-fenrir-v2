"""Phase gates v2 (I5, R23): what must be true before an incident enters Post-Incident (Gate 1)
and before it is closed (Gate 2).

`evaluate_gate()` is the only implementation. GET /api/incidents/{id}/gates reports it;
PATCH /api/incidents/{id} (any move into post_incident), POST …/close and POST …/reopen (into
post_incident from another phase) enforce it in the same transaction as the write, so a failed
evaluation never lets a transition through; POST …/gates/{gate}/sign-off records a sign-off over
its state. The frontend only renders what this returns.

Every check has a level (owner decision 2026-10-03):
- block: legal and integrity, plus every v1 check (they keep their level). An unmet block-level
  check stops the transition (409 gate_unmet) unless the incident lead overrides it with a reason.
- warn: hygiene. Shown, and recorded in the transition audit; it never stops a transition.

Standards: NIST SP 800-61 R3 with CSF 2.0 — Gate 1 = RS.MI-01/02 (incidents contained
and eradicated), RC.RP-01..05 (recovery executed and verified: I1) and RS.CO-02 (stakeholders
notified: I2); Gate 2 = ID.IM-03/04 (improvements from lessons learned) and RC.RP-06 (end of
recovery declared, documentation completed) — plus the CISA IR playbook's post-incident activity
and the audit's D3 closure spec (sign-offs, evidence custody, report after the last change).
See docs/standards-map.md §L1.
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from incidents.start_checks import PERSONAL_DATA_TAG
from models import (AuditLog, BusinessImpact, ClosureChecklistItem, CustodyExport, Evidence, EvidenceCopy,
                    GeneratedReport, Incident, IncidentCost, IncidentGateSignOff, LePackage, LessonsLearned,
                    PlaybookTask, RegulatoryDeadline, RespondAction, utcnow)
from recovery.service import scope_rows as recovery_scope_rows
from schemas import GateItem, GateName, GateResult, GateSignOffOut
from stakeholder_notifications.service import obligations as notification_obligations

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
_CER = ("containment", "eradication", "recovery")
_BIA_FIELDS = ("financial", "operational", "data_exposure", "reputational", "regulatory", "legal", "notes")
_NAMES_MAX = 5
# Breach: the personal-data heuristic I4 uses (no personal-data flag exists), plus the breach type.
BREACH_TYPES = ("data_breach",)
_BREACH_REGULATIONS = ("GDPR", "NIS2")
_EVIDENCE_DISPOSED = ("destroyed", "returned", "archived")
_REPORT_TYPES = (("exec", "Executive"), ("full", "Full"))
# Audited actions that read or hand out data without changing it: not a "data change" for report staleness.
_NON_DATA_ACTIONS = ("report_generate", "report_download", "incident_audit_view", "audit_export_create",
                     "audit_export_download", "audit_export_download_denied", "evidence_export_download",
                     "evidence_export_download_denied", "collection_package_download",
                     "collection_package_download_denied", "ioc_export", "outbound_notification_suppressed",
                     "outbound_lookup_suppressed")
SIGN_OFF_KEYS = {"ic": "ic_sign_off_missing", "dpo": "dpo_sign_off_missing"}
_ROLE_LABEL = {"ic": "Incident Commander", "dpo": "Data Protection Officer"}


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _z(dt: datetime) -> str:
    return _as_utc(dt).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _names(names: list[str]) -> str:
    more = len(names) - _NAMES_MAX
    return "; ".join(names[:_NAMES_MAX]) + (f"; and {more} more" if more > 0 else "")


def _blank(v) -> bool:
    return not (isinstance(v, str) and v.strip())


def _check(key: str, ok: bool, met_label: str, label: str, level: str = "block", **kw) -> GateItem:
    """A check: `met_label` when it holds; `label` (+ detail, fix_hint, route) when it doesn't."""
    if ok:
        return GateItem(key=key, label=met_label, level=level, status="met")
    return GateItem(key=key, label=label, level=level, status="unmet", **kw)


def breach_reason(inc: Incident) -> Optional[str]:
    """Why the incident counts as a personal-data breach (DPO sign-off applies), or None."""
    if inc.incident_type in BREACH_TYPES:
        return f"type {inc.incident_type}"
    if inc.information_impact == "privacy":
        return "information impact: privacy (personal data)"
    if PERSONAL_DATA_TAG in (inc.tags or []):
        return f"tagged {PERSONAL_DATA_TAG}"
    return None


def _deadline_name(d: RegulatoryDeadline) -> str:
    from legal.routes import article_label   # local: legal.routes imports FastAPI deps
    article = article_label(d.regulation, d.article, d.obligation)
    return f"{d.regulation} {article}" if article else f"{d.regulation}: {d.obligation}"


async def _deadlines(db: AsyncSession, incident_id) -> list[RegulatoryDeadline]:
    return list((await db.execute(
        select(RegulatoryDeadline).where(RegulatoryDeadline.incident_id == incident_id)
        .order_by(RegulatoryDeadline.deadline_at, RegulatoryDeadline.id)
    )).scalars().all())


def _carried(d: RegulatoryDeadline) -> GateItem:
    return GateItem(key="legal_deadline_open", label=f"{_deadline_name(d)} — {d.obligation}",
                    due_at=_as_utc(d.deadline_at), route="legal")


# ─── Sign-offs ───────────────────────────────────────────────────────────────

def gate_state(incident_id, gate: GateName, checks: list[GateItem]) -> tuple[list[dict], str]:
    """(state, sha256): the gate's block-level checks as shown (key, status, label, detail), without the
    sign-off checks (a sign-off can't cover itself). What a sign-off records and its hash."""
    state = [{"key": c.key, "status": c.status, "label": c.label, "detail": c.detail}
             for c in checks if c.level == "block" and c.key not in SIGN_OFF_KEYS.values()]
    canon = json.dumps({"incident_id": str(incident_id), "gate": gate, "checks": state},
                       sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return state, hashlib.sha256(canon.encode("utf-8")).hexdigest()


async def last_reopened_at(db: AsyncSession, incident_id) -> Optional[datetime]:
    """When the incident was last re-opened (from the append-only audit log), or None."""
    ts = (await db.execute(
        select(func.max(AuditLog.timestamp))
        .where(AuditLog.action == "incident_reopen", AuditLog.resource_type == "incident",
               AuditLog.resource_id == str(incident_id))
    )).scalar()
    return _as_utc(ts) if ts else None


def sign_off_out(r: IncidentGateSignOff, *, current: bool, state_sha256: Optional[str]) -> GateSignOffOut:
    return GateSignOffOut(id=r.id, gate=r.gate, role=r.role, user_id=r.user_id, username=r.username,
                          signed_as=r.signed_as, signed_at=r.signed_at, statement=r.statement,
                          state_sha256=r.state_sha256, current=current,
                          matches_current_state=current and r.state_sha256 == state_sha256)


async def sign_off_history(db: AsyncSession, incident_id) -> list[dict]:
    """Every sign-off on the incident, oldest first, for the report and the LE package. `current` = made
    since the last re-open (only those count for a gate); timestamps UTC Z."""
    since = await last_reopened_at(db, incident_id)
    rows = (await db.execute(
        select(IncidentGateSignOff).where(IncidentGateSignOff.incident_id == incident_id)
        .order_by(IncidentGateSignOff.signed_at, IncidentGateSignOff.id)
    )).scalars().all()
    return [{"id": str(r.id), "gate": r.gate, "gate_label": GATE_LABEL.get(r.gate, r.gate), "role": r.role,
             "role_label": _ROLE_LABEL.get(r.role, r.role), "username": r.username, "signed_as": r.signed_as,
             "signed_at": _z(r.signed_at), "statement": r.statement, "state_sha256": r.state_sha256,
             "current": since is None or _as_utc(r.signed_at) > since} for r in rows]


async def _current_sign_offs(db: AsyncSession, incident_id, gate: GateName) -> list[IncidentGateSignOff]:
    """This gate's sign-offs made since the last re-open, newest first."""
    since = await last_reopened_at(db, incident_id)
    q = select(IncidentGateSignOff).where(IncidentGateSignOff.incident_id == incident_id,
                                          IncidentGateSignOff.gate == gate)
    if since is not None:
        q = q.where(IncidentGateSignOff.signed_at > since)
    return list((await db.execute(q.order_by(IncidentGateSignOff.signed_at.desc(),
                                              IncidentGateSignOff.id))).scalars().all())


def _sign_off_check(role: str, signed: list[IncidentGateSignOff], why: str) -> GateItem:
    mine = [s for s in signed if s.role == role]
    who = _ROLE_LABEL[role]
    return _check(
        SIGN_OFF_KEYS[role], bool(mine),
        f"{who} signed off" + (f" ({mine[0].username})" if mine else ""),
        f"{who} sign-off missing", detail=why,
        fix_hint=f"Sign off in this gate's panel: the {'incident lead (IC / Deputy)' if role == 'ic' else 'DPO'} "
                 "or an admin")


# ─── Gate 1: C/E/R → Post-Incident ───────────────────────────────────────────

async def _gate1(db: AsyncSession, inc: Incident, milestones: dict,
                 deadlines: list[RegulatoryDeadline]) -> tuple[list[GateItem], list[GateItem], list[str], Optional[str]]:
    """(checks, carried, sign-offs required, why the DPO must sign)."""
    checks, carried = [], []
    for field, label in _MILESTONES:
        checks.append(_check(
            f"{field}_missing", milestones[field] is not None, f"{label} time declared",
            f"{label} time not declared",
            fix_hint=f"Declare {label.lower()} in the incident header, or set it on Details ({field})",
            route="details"))

    actions = (await db.execute(
        select(RespondAction.title, RespondAction.category, RespondAction.status, RespondAction.defer_reason)
        .where(RespondAction.incident_id == inc.id, RespondAction.category.in_(_CER))
        .order_by(RespondAction.category, RespondAction.order_index, RespondAction.created_at)
    )).all()
    open_ = [a for a in actions if a.status in _WORK_OPEN]
    checks.append(_check(
        "respond_actions_open", not open_,
        "No containment / eradication / recovery action open or in progress",
        f"{len(open_)} containment / eradication / recovery action(s) still open or in progress",
        detail=_names([f"{a.title} ({a.category}, {a.status.replace('_', ' ')})" for a in open_]),
        fix_hint="Mark each Done or Deferred (with a reason) on Respond", route="respond"))
    deferred = [a for a in actions if a.status == "deferred"]
    if deferred:
        no_reason = [a for a in deferred if _blank(a.defer_reason)]
        checks.append(_check(
            "respond_deferred_reason_missing", not no_reason, "Every deferred action has a reason",
            f"{len(no_reason)} deferred action(s) without a reason", level="warn",
            detail=_names([f"{a.title} ({a.category})" for a in no_reason]),
            fix_hint="Edit each on Respond and give the defer reason", route="respond"))

    now = utcnow()
    blocking = []
    for d in deadlines:
        if d.status not in _DEADLINE_OPEN:
            continue
        if d.is_mandatory and (_as_utc(d.deadline_at) <= now or d.deadline_hours <= _GATE1_WINDOW_HOURS):
            blocking.append(d)
        else:
            carried.append(_carried(d))
    checks.append(_check(
        "legal_deadlines_open", not blocking,
        f"Mandatory legal deadlines due or within {_GATE1_WINDOW_HOURS} h completed or waived",
        f"{len(blocking)} mandatory legal deadline(s) due or with a window of "
        f"{_GATE1_WINDOW_HOURS} h or less, not completed or waived",
        detail=_names([_deadline_name(d) for d in blocking]),
        fix_hint="Complete them, or waive them with a justification, on Legal", route="legal"))

    # I1: every in-scope system restored and validated, or not required.
    systems = await recovery_scope_rows(db, inc.id)
    if not systems:
        checks.append(_check(
            "no_systems_in_scope", False, "", "No systems in scope: confirm none needed restoring", level="warn",
            detail="No compromised host, service or network range is on the scope list, so nothing was "
                   "restored or validated.",
            fix_hint="Mark the affected systems compromised on Entities, or confirm that none were affected",
            route="recovery"))
    else:
        undone = [(e, r) for e, r in systems if not r or r.state not in ("validated", "not_required")]
        checks.append(_check(
            "systems_not_validated", not undone,
            f"All {len(systems)} in-scope system(s) validated or not required",
            f"{len(undone)} of {len(systems)} in-scope system(s) not validated or marked not required",
            detail=_names([f"{e.value} ({(r.state if r else 'not_started').replace('_', ' ')})" for e, r in undone]),
            fix_hint="Restore and validate each, or mark it not required with a reason, on Recovery",
            route="recovery"))

    # I2: every required stakeholder notification logged (notified) or recorded as not required.
    required = [o for o in await notification_obligations(db, inc.id) if o.required and o.superseded_at is None]
    if required:
        pending = [o for o in required if o.status == "pending"]
        checks.append(_check(
            "notifications_outstanding", not pending,
            "Every required stakeholder notification logged or marked not required",
            f"{len(pending)} required stakeholder notification(s) not logged",
            detail=_names([f"{o.role.replace('_', ' ')} ({o.category})" for o in pending]),
            fix_hint="Record each as notified (when, how) or not required (why) on Comms → Notifications",
            route="comms/notifications"))

    # Personal-data breach: GDPR / NIS2 recorded; one waived as "not required" needs the DPO's sign-off.
    signs, dpo_why = [], None
    if reason := breach_reason(inc):
        regs = [d for d in deadlines if d.regulation in _BREACH_REGULATIONS]
        checks.append(_check(
            "breach_obligations_not_recorded", bool(regs), "GDPR / NIS2 obligations recorded",
            "Personal-data breach: no GDPR or NIS2 obligation recorded", detail=f"Applies: {reason}.",
            fix_hint="Initialise them on Legal; complete each, or waive it as not required (the DPO then signs off)",
            route="legal"))
        waived = [d for d in regs if d.status == "waived"]
        if waived:
            signs = ["dpo"]
            dpo_why = (f"Personal-data breach ({reason}); waived as not required: "
                       + _names([_deadline_name(d) for d in waived]))
    return checks, carried, signs, dpo_why


# ─── Gate 2: Post-Incident → Closed ──────────────────────────────────────────

async def _last_data_change(db: AsyncSession, incident_id) -> Optional[datetime]:
    """The latest successful audited change on the incident (reads and report saves excluded)."""
    prefix = f"/api/incidents/{incident_id}"
    ts = (await db.execute(
        select(func.max(AuditLog.timestamp)).where(
            or_(AuditLog.request_path == prefix, AuditLog.request_path.like(f"{prefix}/%"),
                and_(AuditLog.resource_type == "incident", AuditLog.resource_id == str(incident_id))),
            AuditLog.action.not_in(_NON_DATA_ACTIONS),
            or_(AuditLog.outcome.is_(None), AuditLog.outcome == "success"))
    )).scalar()
    return _as_utc(ts) if ts else None


async def _report_check(db: AsyncSession, inc: Incident) -> GateItem:
    latest = dict((await db.execute(
        select(GeneratedReport.report_type, func.max(GeneratedReport.generated_at))
        .where(GeneratedReport.incident_id == inc.id).group_by(GeneratedReport.report_type)
    )).all())
    changed = await _last_data_change(db, inc.id)
    stale = []
    for rtype, label in _REPORT_TYPES:
        at = latest.get(rtype)
        if at is None:
            stale.append(f"{label}: never generated")
        elif changed is not None and _as_utc(at) < changed:
            stale.append(f"{label}: generated {_z(at)}")
    return _check(
        "report_stale", not stale, "Executive and full reports generated after the last change",
        "Final report not regenerated after the last change", level="warn",
        detail="; ".join(stale) + (f" — last change {_z(changed)}" if changed and stale else ""),
        fix_hint="Generate and save the executive and full reports on Post-Incident → Reports",
        route="post-incident")


async def _evidence_checks(db: AsyncSession, inc: Incident) -> list[GateItem]:
    from evidence.exports import effective_status as export_status      # local: avoid import cycles
    from evidence.working_copies import effective_status as copy_status
    checks = []
    items = (await db.execute(
        select(Evidence).where(Evidence.incident_id == inc.id, Evidence.status.not_in(_EVIDENCE_DISPOSED))
        .order_by(Evidence.identifier, Evidence.id)
    )).scalars().all()
    if items:
        label = lambda e: f"{e.identifier} {e.name}"   # noqa: E731
        no_custodian = [e for e in items if not e.current_custodian_id and _blank(e.current_custodian_external_name)]
        checks.append(_check(
            "evidence_custodian_missing", not no_custodian, "Every exhibit held has a custodian",
            f"{len(no_custodian)} exhibit(s) without a custodian",
            detail=_names([label(e) for e in no_custodian]),
            fix_hint="Record the current custodian on Evidence → Items", route="evidence"))
        undecided = [e for e in items if not e.legal_hold]
        checks.append(_check(
            "evidence_disposition_missing", not undecided,
            "Every exhibit held is on legal hold (the others are disposed of)",
            f"{len(undecided)} exhibit(s) neither on legal hold nor disposed of",
            detail=_names([label(e) for e in undecided]),
            fix_hint="Put each on legal hold, or record its disposition (archive, return or destroy), on Evidence",
            route="evidence"))
        now = utcnow()
        copies = (await db.execute(
            select(EvidenceCopy, Evidence.identifier).join(Evidence, Evidence.id == EvidenceCopy.evidence_id)
            .where(Evidence.incident_id == inc.id, EvidenceCopy.kind == "download",
                   EvidenceCopy.status.in_(("issued", "downloading")))
        )).all()
        out = [f"{c.copy_identifier or ident} ({copy_status(c, now)})" for c, ident in copies
               if copy_status(c, now) in ("issued", "downloading")]
        checks.append(_check(
            "evidence_working_copy_open", not out, "No working-copy download issued or in progress",
            f"{len(out)} working-copy download(s) issued or in progress", detail=_names(out),
            fix_hint="Let each download finish or its link expire (10 minutes), on Evidence", route="evidence"))
    packages = (await db.execute(
        select(LePackage, CustodyExport).join(CustodyExport, CustodyExport.id == LePackage.custody_export_id)
        .where(LePackage.incident_id == inc.id).order_by(LePackage.prepared_at)
    )).all()
    if packages:
        unacked = [p for p, x in packages if p.acknowledged_at is None and export_status(x) != "revoked"]
        checks.append(_check(
            "le_package_unacknowledged", not unacked, "Every law-enforcement package acknowledged by its recipient",
            f"{len(unacked)} law-enforcement package(s) not acknowledged by the recipient",
            detail=_names([f"{p.case_reference} → {p.requesting_authority}" for p in unacked]),
            fix_hint="Record the recipient's acknowledgement on Post-Incident → LE Package", route="post-incident"))
    return checks


async def _gate2(db: AsyncSession, inc: Incident,
                 deadlines: list[RegulatoryDeadline]) -> tuple[list[GateItem], list[GateItem], list[str], int]:
    """(checks, carried, sign-offs required, open Preparation tasks)."""
    checks, carried = [], []
    ll = (await db.execute(
        select(LessonsLearned).where(LessonsLearned.incident_id == inc.id)
    )).scalar_one_or_none()

    missing = [name for name, v in (("what happened", ll and ll.incident_narrative),
                                    ("root cause", ll and ll.root_cause_description),
                                    ("recommendations", ll and ll.report_security_recommendations)) if _blank(v)]
    checks.append(_check(
        "lessons_summary_incomplete", not missing, "Resolution summary filled in", "Resolution summary incomplete",
        detail="Missing: " + ", ".join(missing),
        fix_hint="Fill it in on Details → Resolution summary (or Post-Incident → Lessons Learned)", route="details"))
    checks.append(_check(
        "lessons_not_final", bool(ll and ll.status == "final"), "Lessons learned is Final",
        "Lessons learned is not Final",
        fix_hint="Set Status to Final on Post-Incident → Lessons Learned", route="post-incident"))
    checks.append(_check(
        "lessons_conducted_at_missing", bool(ll and ll.conducted_at is not None), "Lessons-learned review date set",
        "Lessons-learned review date not set",
        fix_hint="Set Date conducted on Post-Incident → Lessons Learned", route="post-incident"))
    checks.append(_check(
        "lessons_participants_missing", bool(ll and any(not _blank(p) for p in (ll.participants or []))),
        "Lessons-learned participants recorded", "No lessons-learned participants recorded",
        fix_hint="Add Participants on Post-Incident → Lessons Learned", route="post-incident"))
    incomplete = [ai for ai in ((ll and ll.action_items) or [])
                  if not isinstance(ai, dict) or _blank(ai.get("owner")) or _blank(ai.get("due_date"))]
    checks.append(_check(
        "lessons_action_items_incomplete", not incomplete, "Every lessons-learned action item has an owner and due date",
        f"{len(incomplete)} lessons-learned action item(s) without an owner or due date",
        detail=_names([(ai.get("action") if isinstance(ai, dict) and not _blank(ai.get("action"))
                        else "(untitled)") for ai in incomplete]),
        fix_hint="Give each an Owner and a Due date on Post-Incident → Lessons Learned", route="post-incident"))

    items = (await db.execute(
        select(ClosureChecklistItem)
        .where(ClosureChecklistItem.incident_id == inc.id)
        .order_by(ClosureChecklistItem.sort_order)
    )).scalars().all()
    if not items:
        checks.append(_check(
            "checklist_not_started", False, "", "Closure checklist not started",
            fix_hint="Work through Post-Incident → Closure Checklist", route="post-incident"))
    else:
        # "Incident formally closed" is ticked by the close itself; an N/A item counts as done.
        active = [i for i in items if i.is_active and i.item_key != "incident_closed"]
        unchecked = [i.label for i in active if not i.checked and not i.not_applicable]
        checks.append(_check(
            "checklist_incomplete", not unchecked, "Every closure-checklist item checked or not applicable",
            f"{len(unchecked)} closure-checklist item(s) not checked", detail=_names(unchecked),
            fix_hint="Check them, or mark them N/A with a reason, on Post-Incident → Closure Checklist",
            route="post-incident"))
        na = [i for i in active if i.not_applicable]
        if na:
            no_reason = [i.label for i in na if _blank(i.na_reason)]
            checks.append(_check(
                "checklist_na_reason_missing", not no_reason, "Every N/A checklist item has a reason",
                f"{len(no_reason)} N/A checklist item(s) without a reason", level="warn", detail=_names(no_reason),
                fix_hint="Give the reason on Post-Incident → Closure Checklist", route="post-incident"))

    tasks = (await db.execute(
        select(PlaybookTask.title, PlaybookTask.phase, PlaybookTask.status, PlaybookTask.skip_reason)
        .where(PlaybookTask.incident_id == inc.id, PlaybookTask.archived_at.is_(None))
        .order_by(PlaybookTask.order_index, PlaybookTask.created_at)
    )).all()
    open_tasks = [t.title for t in tasks if t.status in _WORK_OPEN and t.phase != "preparation"]
    checks.append(_check(
        "playbook_tasks_open", not open_tasks, "No playbook task open or in progress",
        f"{len(open_tasks)} playbook task(s) open or in progress", detail=_names(open_tasks),
        fix_hint="Mark each Done, or Skipped with a reason, on Playbook", route="playbook"))
    # I3/I5 (R24): open 800-61 Preparation tasks are organisation readiness work: they warn, never block.
    prep = [t for t in tasks if t.phase == "preparation"]
    prep_open = [t.title for t in prep if t.status in _WORK_OPEN]
    if prep:
        checks.append(_check(
            "preparation_tasks_open", not prep_open, "No Preparation-phase task open",
            f"{len(prep_open)} Preparation-phase playbook task(s) still open", level="warn",
            detail=_names(prep_open),
            fix_hint="Readiness work: finish it, or carry it into the lessons-learned action items, on Playbook",
            route="playbook"))
    skipped = [t for t in tasks if t.status == "skipped"]
    if skipped:
        no_reason = [t.title for t in skipped if _blank(t.skip_reason)]
        checks.append(_check(
            "playbook_skip_reason_missing", not no_reason, "Every skipped playbook task has a reason",
            f"{len(no_reason)} skipped playbook task(s) without a reason", level="warn", detail=_names(no_reason),
            fix_hint="Give each a skip reason on Playbook", route="playbook"))

    now = utcnow()
    overdue = []
    for d in deadlines:
        if d.status not in _DEADLINE_OPEN:
            continue
        if _as_utc(d.deadline_at) <= now:
            overdue.append(d)
        else:
            carried.append(_carried(d))
    checks.append(_check(
        "legal_deadlines_overdue", not overdue, "Every legal deadline already due completed or waived",
        f"{len(overdue)} legal deadline(s) past due, not completed or waived",
        detail=_names([_deadline_name(d) for d in overdue]),
        fix_hint="Complete them, or waive them with a justification, on Legal", route="legal"))

    costs = (await db.execute(
        select(func.count()).select_from(IncidentCost).where(IncidentCost.incident_id == inc.id)
    )).scalar() or 0
    bia = (await db.execute(
        select(BusinessImpact).where(BusinessImpact.incident_id == inc.id)
    )).scalar_one_or_none()
    # Opening the Reports tab creates an empty assessment, so only one with content counts.
    checks.append(_check(
        "costs_missing", bool(costs or (bia and any(not _blank(getattr(bia, f)) for f in _BIA_FIELDS))),
        "Costs or business impact entered", "No cost entry and no business-impact assessment",
        fix_hint="Add a cost, or fill in the business impact, on Post-Incident → Reports", route="post-incident"))

    checks += await _evidence_checks(db, inc)
    checks.append(await _report_check(db, inc))
    return checks, carried, ["ic"] + (["dpo"] if breach_reason(inc) else []), len(prep_open)


async def evaluate_gate(db: AsyncSession, incident: Incident, gate: GateName, *,
                        milestones: Optional[dict] = None) -> GateResult:
    """Evaluate one gate for `incident` now. Read-only. Only checks that apply are listed.

    gate "post_incident" (Gate 1). Block: contained_at, eradicated_at and recovered_at set; no
    containment / eradication / recovery action open or in progress; every mandatory legal deadline
    that is due, or whose window is 72 h or less, completed or waived (other open deadlines are
    carried forward); every in-scope system validated or not required (I1); every required
    stakeholder notification notified or not required (I2); for a personal-data breach (type
    data_breach, information impact privacy, or tag personal-data), a GDPR or NIS2 obligation
    recorded, and the DPO's sign-off when one was waived as not required. Warn: a deferred C/E/R
    action without a reason; no system in scope at all.

    gate "close" (Gate 2). Block: the resolution summary (what happened, root cause,
    recommendations); lessons learned Final, with a conducted date, participants, and an owner and
    due date on every action item; the closure checklist exists and every active item except
    "incident_closed" is checked or N/A; no playbook task outside Preparation open or in progress;
    every legal deadline already due completed or waived (future ones carried forward); a cost entry
    or a business-impact assessment with content; every exhibit still held has a custodian and is
    on legal hold (else it must be disposed of), no working-copy download issued or in progress,
    every LE package acknowledged; the IC's sign-off, and the DPO's for a breach. Warn: N/A
    checklist items without a reason, skipped tasks without a reason, open Preparation tasks, and
    the executive and full reports not generated after the last audited change. Exempt (met) for
    a false or benign positive.

    `milestones` overrides the stored contained/eradicated/recovered values (a PATCH that
    declares them and changes phase in one request)."""
    if gate == "close" and incident.triage_state in CLOSE_EXEMPT_TRIAGE:
        return GateResult(gate=gate, label=GATE_LABEL[gate], met=True, exempt=True)
    deadlines = await _deadlines(db, incident.id)
    signed = await _current_sign_offs(db, incident.id, gate)
    prep_open = None
    if gate == "post_incident":
        ms = milestones or {f: getattr(incident, f) for f, _ in _MILESTONES}
        checks, carried, signs, dpo_why = await _gate1(db, incident, ms, deadlines)
        if signs:
            checks.append(_sign_off_check("dpo", signed, dpo_why))
    else:
        checks, carried, signs, prep_open = await _gate2(db, incident, deadlines)
        checks.append(_sign_off_check("ic", signed, "The Incident Commander approves the close (D3)."))
        if "dpo" in signs:
            checks.append(_sign_off_check(
                "dpo", signed, f"Personal-data breach ({breach_reason(incident)}): the DPO approves the close."))
    _, sha = gate_state(incident.id, gate, checks)
    unmet = [c for c in checks if c.status == "unmet" and c.level == "block"]
    return GateResult(
        gate=gate, label=GATE_LABEL[gate], met=not unmet, unmet=unmet,
        warnings=[c for c in checks if c.status == "unmet" and c.level == "warn"], checks=checks,
        carried_forward=carried, sign_offs_required=signs,
        sign_offs=[sign_off_out(r, current=True, state_sha256=sha) for r in signed], state_sha256=sha,
        open_preparation_tasks=prep_open)
