"""Report data assembly — assembles all per-incident data for client-side rendering.

Also exposes the audit-grade history flow:
  POST   /{incident_id}/reports                    — save a freshly-rendered HTML report
  GET    /{incident_id}/reports/history            — list saved reports for the incident
  POST   /{incident_id}/reports/{report_id}/download — re-download with mandatory access_reason
"""
import asyncio
import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from affected_systems.routes import compromised_systems
from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from files.routes import report_file_present, report_image_digest
from incidents.access import get_accessible_incident
from models import (
    AuditLog, BusinessImpact, ClosureChecklistItem, Decision, Entity, EntityFile, EntityRelation,
    Evidence, GeneratedReport, Incident, IncidentAssignment, IncidentAttribution,
    IncidentCost, IncidentStakeholder, IOC, LessonsLearned, OOBLog, OperationalRole,
    PlaybookTask, RegulatoryDeadline, ReportAccess, RespondAction, ThreatActor,
    ThreatIntelIOC, TimelineEvent, User,
)
from schemas import nciss_severity
from sqlalchemy import tuple_

router = APIRouter()

_EXCLUDE = {"oob_passphrase"}

# E4: the roles that sign the report off (operational role key → default label), in print order.
SIGN_OFF_ROLES = (
    ("incident_commander",      "Incident Commander"),
    ("deputy_commander",        "Deputy Incident Commander"),
    ("legal_liaison",           "Legal Liaison"),
    ("data_protection_officer", "Data Protection Officer"),
)


def _utc_z(dt: Optional[datetime]) -> Optional[str]:
    """ISO 8601 in UTC with a Z suffix (sub-second precision kept); a naive value is UTC."""
    if dt is None:
        return None
    dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _passphrase_redactor(passphrase: Optional[str]):
    """text → text with the incident's OOB passphrase replaced by "[passphrase]" (case-insensitive;
    its words may be joined by hyphens, spaces or underscores). Identity when there is none."""
    words = [w for w in re.split(r"[\s\-_]+", passphrase or "") if w]
    if not words:
        return lambda text: text
    pat = re.compile(r"[\s\-_]*".join(map(re.escape, words)), re.IGNORECASE)
    return lambda text: pat.sub("[passphrase]", text) if text else text


def _deadline_compliance(d: RegulatoryDeadline, now: datetime) -> tuple[str, Optional[float]]:
    """Was the regulatory deadline met? Returns (compliance, hours_late).

    met      — completed on or before deadline_at
    violated — completed after deadline_at, or still open past deadline_at
    pending  — still open, deadline not yet reached
    waived   — explicitly waived
    """
    if d.status == "waived":
        return "waived", None
    if d.status == "completed":
        done = d.completed_at or now
        late = (done - d.deadline_at).total_seconds() / 3600
        return ("violated", round(late, 1)) if late > 0 else ("met", None)
    late = (now - d.deadline_at).total_seconds() / 3600
    return ("violated", round(late, 1)) if late > 0 else ("pending", None)


@router.get("/{incident_id}/reports/data", summary="Get report data")
async def get_report_data(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    """Assemble the complete data bundle for an incident report, for client-side rendering.

    Aggregates the incident with its IOCs (threat-intel enriched), entities and relations,
    timeline, playbook tasks, respond actions, decisions, closure checklist, lessons learned,
    evidence summary, business impact, costs, a MITRE summary computed from the timeline,
    assignments, regulatory deadlines (with met/violated compliance), stakeholders (identity +
    role only), threat-actor attributions and affected systems. Sensitive fields (e.g.
    oob_passphrase, stakeholder contact details) are excluded. Requires read access to the
    incident (returns 404 otherwise).

    E4 additions:
    - `incident.nciss_severity`: the NCISS value for the internal severity
      (critical→emergency, high→severe, medium→medium, low→low).
    - `report_files[]`: the Supporting-documents files picked as report figures, oldest
      first: {id, name, mime, size, sha256, caption, integrity}. Metadata only, never the
      image bytes; sha256 is of the original file, stored when it was picked (a figure
      picked before that is hashed now). integrity is "ok", or "failed" when the stored
      data is missing, the wrong size, or fails decryption/authentication; sha256 and mime
      are then null and the figure must not be embedded. The renderer fetches each image
      from …/files/{id}/download (409 file_integrity_failed for tampered bytes) and checks
      its SHA-256 against this one.
    - `oob_log[]`: the out-of-band communications log, oldest first (stakeholder, channel,
      direction, summary, verified, verification method, logged by, time). The OOB
      passphrase and responders' out-of-band contact details are never included; the
      incident's current passphrase typed into a free-text field shows as "[passphrase]".
    - `closure`: {closed, closed_at, closed_by, reason} from the close sign-off (reason =
      the statement given at Close, read from that close's audit row; null while open).
      Timeline events never supply it.
    - The E4 timestamps (`oob_log[].created_at`, `closure.closed_at`) are UTC ISO 8601
      with a Z suffix.
    - `sign_offs[]`: Incident Commander, Deputy, Legal Liaison and DPO, each with the
      users assigned to that role on this incident ({username, name}; empty if none).
    """
    # Access gate — returns 404 (not 403) for incidents the caller can't see,
    # matching the rest of the per-incident routers. Without this any analyst
    # could dump a team-restricted incident's full case file.
    inc = await get_accessible_incident(db, incident_id, user)

    iocs = (await db.execute(
        select(IOC).where(IOC.incident_id == incident_id).order_by(IOC.added_at)
    )).scalars().all()

    entities = (await db.execute(
        select(Entity).where(Entity.incident_id == incident_id).order_by(Entity.criticality.desc())
    )).scalars().all()

    entity_relations = (await db.execute(
        select(EntityRelation)
        .where(EntityRelation.incident_id == incident_id)
        .order_by(EntityRelation.created_at)
    )).scalars().all()

    timeline = (await db.execute(
        select(TimelineEvent)
        .where(TimelineEvent.incident_id == incident_id)
        .order_by(TimelineEvent.event_time)
    )).scalars().all()

    tasks = (await db.execute(
        select(PlaybookTask)
        .where(PlaybookTask.incident_id == incident_id)
        .order_by(PlaybookTask.order_index)
    )).scalars().all()

    actions = (await db.execute(
        select(RespondAction)
        .where(RespondAction.incident_id == incident_id)
        .order_by(RespondAction.category, RespondAction.order_index)
    )).scalars().all()

    decisions = (await db.execute(
        select(Decision)
        .where(Decision.incident_id == incident_id)
        .order_by(Decision.created_at)
    )).scalars().all()

    checklist = (await db.execute(
        select(ClosureChecklistItem)
        .where(ClosureChecklistItem.incident_id == incident_id)
        .order_by(ClosureChecklistItem.sort_order)
    )).scalars().all()

    ll = (await db.execute(
        select(LessonsLearned).where(LessonsLearned.incident_id == incident_id)
    )).scalar_one_or_none()

    evidence = (await db.execute(
        select(Evidence).where(Evidence.incident_id == incident_id)
    )).scalars().all()

    bia = (await db.execute(
        select(BusinessImpact).where(BusinessImpact.incident_id == incident_id)
    )).scalar_one_or_none()

    costs = (await db.execute(
        select(IncidentCost)
        .where(IncidentCost.incident_id == incident_id)
        .order_by(IncidentCost.category, IncidentCost.id)
    )).scalars().all()

    assignments = (await db.execute(
        select(IncidentAssignment)
        .where(IncidentAssignment.incident_id == incident_id)
        .order_by(IncidentAssignment.role_label)
    )).scalars().all()

    deadlines = (await db.execute(
        select(RegulatoryDeadline)
        .where(RegulatoryDeadline.incident_id == incident_id)
        .order_by(RegulatoryDeadline.deadline_at)
    )).scalars().all()

    stakeholders = (await db.execute(
        select(IncidentStakeholder)
        .where(IncidentStakeholder.incident_id == incident_id)
        .order_by(IncidentStakeholder.type, IncidentStakeholder.name)
    )).scalars().all()

    attributions = (await db.execute(
        select(IncidentAttribution, ThreatActor)
        .outerjoin(ThreatActor, ThreatActor.id == IncidentAttribution.threat_actor_id)
        .where(IncidentAttribution.incident_id == incident_id)
        .order_by(IncidentAttribution.created_at)
    )).all()

    # C2: affected systems = the incident's compromised entities, in the old row shape.
    affected_systems = await compromised_systems(db, incident_id)

    # E4: report figures (metadata + the SHA-256 of the original) and the OOB log. The hash stored when
    # the figure was picked is used after a cheap size check; a figure picked before hashes were
    # stored is decrypted and hashed here. Both in a thread; a bad figure is (None, None), never a 500.
    report_files = (await db.execute(
        select(EntityFile)
        .where(EntityFile.incident_id == incident_id, EntityFile.include_in_report.is_(True))
        .order_by(EntityFile.uploaded_at, EntityFile.id)
    )).scalars().all()
    figure_rows = [(f.file_path, f.nonce_hex, f.file_size, f.report_sha256, f.report_mime) for f in report_files]
    digests = await asyncio.to_thread(lambda: [
        ((sha, mime) if report_file_present(path, size, nonce) else (None, None)) if sha
        else report_image_digest(path, nonce, size)
        for path, nonce, size, sha, mime in figure_rows])

    oob_log = (await db.execute(
        select(OOBLog).where(OOBLog.incident_id == incident_id).order_by(OOBLog.created_at)
    )).scalars().all()

    sign_off_roles = {key: (rid, label) for rid, key, label in (await db.execute(
        select(OperationalRole.id, OperationalRole.key, OperationalRole.label)
        .where(OperationalRole.key.in_([k for k, _ in SIGN_OFF_ROLES]))
    )).all()}

    # TI-match enrichment for IOCs — same single-query pattern as list_iocs.
    ti_map: dict[tuple, str] = {}
    if iocs:
        pairs = [(i.type, i.value) for i in iocs]
        ti_hits = (await db.execute(
            select(ThreatIntelIOC.type, ThreatIntelIOC.value, ThreatIntelIOC.feed_name)
            .where(tuple_(ThreatIntelIOC.type, ThreatIntelIOC.value).in_(pairs))
        )).all()
        ti_map = {(r.type, r.value): r.feed_name for r in ti_hits}

    # MITRE summary — computed from timeline
    tactic_map: dict = {}
    for ev in timeline:
        if not ev.mitre_tactic_id:
            continue
        if ev.mitre_tactic_id not in tactic_map:
            tactic_map[ev.mitre_tactic_id] = {
                "tactic_id":   ev.mitre_tactic_id,
                "tactic_name": ev.mitre_tactic_name,
                "total":       0,
                "techniques":  {},
            }
        tactic_map[ev.mitre_tactic_id]["total"] += 1
        if ev.mitre_technique_id:
            tid = ev.mitre_technique_id
            techs = tactic_map[ev.mitre_tactic_id]["techniques"]
            if tid not in techs:
                techs[tid] = {
                    "technique_id":   tid,
                    "technique_name": ev.mitre_technique_name,
                    "count":          0,
                }
            techs[tid]["count"] += 1

    mitre_summary = [
        {**t, "techniques": list(t["techniques"].values())}
        for t in tactic_map.values()
    ]

    iocs_out = []
    for i in iocs:
        feed = ti_map.get((i.type, i.value))
        d = jsonable_encoder(i)
        if feed:
            d["ti_matched"] = True
            d["ti_match_source"] = feed
        else:
            d["ti_matched"] = False
        iocs_out.append(d)

    # Resolve assignee / decider UUIDs → usernames for respond actions, decisions
    # and playbook tasks
    assignee_ids = {a.assignee_id for a in actions if a.assignee_id}
    assignee_ids |= {d.decided_by_id for d in decisions if d.decided_by_id}
    assignee_ids |= {t.assignee_id for t in tasks if t.assignee_id}
    # E4: OOB log authors, the closer and the assignees (sign-off names).
    assignee_ids |= {o.created_by_id for o in oob_log if o.created_by_id}
    assignee_ids |= {a.user_id for a in assignments if a.user_id}
    if inc.closed_by_id:
        assignee_ids.add(inc.closed_by_id)
    username_map = {}
    fullname_map = {}
    if assignee_ids:
        users = (await db.execute(
            select(User.id, User.username, User.full_name).where(User.id.in_(assignee_ids))
        )).all()
        username_map = {str(u.id): u.username for u in users}
        fullname_map = {str(u.id): u.full_name for u in users}
    actions_out = []
    for a in actions:
        d = jsonable_encoder(a)
        d["performed_by"] = username_map.get(str(a.assignee_id), "") if a.assignee_id else ""
        actions_out.append(d)

    tasks_out = []
    for t in tasks:
        d = jsonable_encoder(t)
        d["assignee_username"] = username_map.get(str(t.assignee_id), "") if t.assignee_id else ""
        tasks_out.append(d)

    decisions_out = []
    for dec in decisions:
        d = jsonable_encoder(dec)
        d["decided_by_username"] = username_map.get(str(dec.decided_by_id), "") if dec.decided_by_id else ""
        decisions_out.append(d)

    now = datetime.now(timezone.utc)
    deadlines_out = []
    for dl in deadlines:
        compliance, hours_late = _deadline_compliance(dl, now)
        deadlines_out.append({
            "regulation":   dl.regulation,
            "article":      dl.article,
            "obligation":   dl.obligation,
            "recipient":    dl.recipient,
            "deadline_at":  dl.deadline_at.isoformat(),
            "status":       dl.status,
            "completed_at": dl.completed_at.isoformat() if dl.completed_at else None,
            "is_mandatory": dl.is_mandatory,
            "compliance":   compliance,
            "hours_late":   hours_late,
        })

    # Stakeholders: identity + role only. Contact methods and notes are
    # deliberately left out — reports can be shared under TLP:CLEAR/GREEN.
    stakeholders_out = [
        {"name": s.name, "title": s.title, "organization": s.organization, "type": s.type}
        for s in stakeholders
    ]

    attributions_out = []
    for attr, actor in attributions:
        attributions_out.append({
            "actor_name":          actor.name if actor else attr.actor_label,
            "actor_mitre_id":      actor.mitre_id if actor else None,
            "actor_motivation":    actor.motivation if actor else None,
            "actor_country":       actor.country_of_origin if actor else None,
            "confidence":          attr.confidence,
            "score":               attr.score,
            "analyst_notes":       attr.analyst_notes,
            "supporting_ioc_count":      len(attr.supporting_ioc_ids or []),
            "supporting_timeline_count": len(attr.supporting_timeline_ids or []),
            "created_by_username": attr.created_by_username,
            "created_at":          attr.created_at.isoformat() if attr.created_at else None,
        })

    incident_out = jsonable_encoder(inc, exclude=_EXCLUDE)
    incident_out["nciss_severity"] = nciss_severity(inc.severity)

    report_files_out = [
        {"id": str(f.id), "name": f.original_name, "mime": mime, "size": f.file_size,
         "sha256": sha, "caption": f.report_caption, "integrity": "ok" if sha else "failed"}
        for f, (sha, mime) in zip(report_files, digests)
    ]

    redact = _passphrase_redactor(inc.oob_passphrase)
    oob_log_out = [
        {
            "stakeholder_name":    redact(o.stakeholder_name),
            "channel":             o.channel,
            "direction":           o.direction,
            "summary":             redact(o.summary),
            "verified":            o.verified,
            "verification_method": redact(o.verification_method),
            "created_by_username": username_map.get(str(o.created_by_id)) if o.created_by_id else None,
            "created_at":          _utc_z(o.created_at),
        }
        for o in oob_log
    ]

    # Close sign-off: the reason from the latest incident_close audit row. Only close_incident writes
    # that row and audit_logs is append-only, so a client can't forge it (a timeline event can be).
    close_reason = None
    if inc.status == "closed":
        details = (await db.execute(
            select(AuditLog.details)
            .where(AuditLog.action == "incident_close", AuditLog.resource_type == "incident",
                   AuditLog.resource_id == str(inc.id))
            .order_by(AuditLog.timestamp.desc()).limit(1)
        )).scalar_one_or_none()
        if isinstance(details, dict) and isinstance(details.get("reason"), str):
            close_reason = details["reason"]
    closure = {
        "closed":    inc.status == "closed",
        "closed_at": _utc_z(inc.closed_at),
        "closed_by": username_map.get(str(inc.closed_by_id)) if inc.closed_by_id else None,
        "reason":    close_reason,
    }

    sign_offs = []
    for key, default_label in SIGN_OFF_ROLES:
        rid, label = sign_off_roles.get(key, (None, default_label))
        sign_offs.append({
            "role_key":   key,
            "role_label": label,
            "assignees":  [
                {"username": a.username,
                 "name": (fullname_map.get(str(a.user_id)) if a.user_id else None) or a.username}
                for a in assignments if rid is not None and a.role_id == rid
            ],
        })

    return {
        "generated_at":     now.isoformat(),
        "incident":         incident_out,
        "iocs":             iocs_out,
        "entities":         jsonable_encoder(list(entities)),
        "entity_relations": jsonable_encoder(list(entity_relations)),
        "timeline_events":  jsonable_encoder(list(timeline)),
        "playbook_tasks":   tasks_out,
        "respond_actions":  actions_out,
        "decisions":        decisions_out,
        "lessons_learned":  jsonable_encoder(ll) if ll else None,
        "closure_checklist": jsonable_encoder([c for c in checklist if getattr(c, "is_active", True)]),
        "evidence_summary": {
            "total":    len(evidence),
            "active":   sum(1 for e in evidence if e.status == "active"),
            "disposed": sum(1 for e in evidence if e.status in ("destroyed", "returned", "archived")),
            "digital":  sum(1 for e in evidence if e.kind == "digital_file"),
            "physical": sum(1 for e in evidence if e.kind == "physical_item"),
        },
        "business_impact":  jsonable_encoder(bia) if bia else None,
        "costs":            jsonable_encoder(list(costs)),
        "mitre_summary":    mitre_summary,
        "assignments":      jsonable_encoder(list(assignments)),
        "regulatory_deadlines": deadlines_out,
        "stakeholders":     stakeholders_out,
        "attributions":     attributions_out,
        "affected_systems": jsonable_encoder(list(affected_systems)),
        "report_files":     report_files_out,
        "oob_log":          oob_log_out,
        "closure":          closure,
        "sign_offs":        sign_offs,
    }


# ─── Report history (save, list, re-download) ────────────────────────────────

class ReportSaveRequest(BaseModel):
    report_type:    str  = Field(min_length=1, max_length=16)
    template_id:    str  = Field(min_length=1, max_length=32)
    classification: str  = Field(min_length=1, max_length=64)
    audience:       Optional[str] = Field(default=None, max_length=256)
    footer_text:    Optional[str] = Field(default=None, max_length=512)
    html:           str  = Field(min_length=1)


class ReportSaveResponse(BaseModel):
    id:           uuid.UUID
    sha256:       str
    file_size:    int
    generated_at: datetime


class ReportHistoryItem(BaseModel):
    id:                 uuid.UUID
    report_type:        str
    template_id:        str
    classification:     str
    audience:           Optional[str]
    footer_text:        Optional[str]
    sha256:             str
    file_size:          int
    generated_by_id:    Optional[uuid.UUID]
    generated_at:       datetime
    access_count:       int


class DownloadReportRequest(BaseModel):
    access_reason: str = Field(min_length=1, max_length=4096)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@router.post("/{incident_id}/reports", response_model=ReportSaveResponse,
             status_code=status.HTTP_201_CREATED, summary="Save a generated report")
async def save_report(
    incident_id: uuid.UUID,
    body:        ReportSaveRequest,
    request:     Request,
    user:        User = Depends(require_analyst),
    db:          AsyncSession = Depends(get_db),
) -> ReportSaveResponse:
    """Persist a freshly-rendered HTML report into the incident's audit-grade report history.

    Stores the report HTML with its type, template, classification, audience and footer, and
    records the SHA-256 and byte size for integrity. Requires the analyst role and write access;
    the save is audit-logged. Returns the new report id, SHA-256, file size and generation time.
    """
    inc = await get_accessible_incident(db, incident_id, user)
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")

    sha = _sha256_hex(body.html)
    size = len(body.html.encode("utf-8"))
    row = GeneratedReport(
        incident_id=incident_id,
        report_type=body.report_type,
        template_id=body.template_id,
        classification=body.classification,
        audience=body.audience,
        footer_text=body.footer_text,
        sha256=sha,
        file_size=size,
        html_content=body.html,
        generated_by_id=user.id,
    )
    db.add(row)
    await db.flush()

    await write_audit(
        db, "report_generate",
        user_id=user.id, username=user.username,
        resource_type="report", resource_id=str(row.id),
        details={
            "incident_id":    str(incident_id),
            "report_type":    body.report_type,
            "template_id":    body.template_id,
            "classification": body.classification,
            "sha256":         sha,
            "size_bytes":     size,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    await db.refresh(row)
    return ReportSaveResponse(
        id=row.id, sha256=row.sha256,
        file_size=row.file_size, generated_at=row.generated_at,
    )


@router.get("/{incident_id}/reports/history", response_model=list[ReportHistoryItem],
            summary="List saved report history")
async def list_report_history(
    incident_id: uuid.UUID,
    user:        User = Depends(current_user),
    db:          AsyncSession = Depends(get_db),
) -> list[ReportHistoryItem]:
    """List the saved reports for an incident, newest first, with per-report access counts.

    Returns metadata only (type, template, classification, SHA-256, size, generator, access count)
    — not the report HTML. Requires read access to the incident.
    """
    await get_accessible_incident(db, incident_id, user)
    rows = (await db.execute(
        select(GeneratedReport)
        .where(GeneratedReport.incident_id == incident_id)
        .order_by(GeneratedReport.generated_at.desc())
    )).scalars().all()

    # Per-row access counts in a single query — avoids N+1.
    from sqlalchemy import func
    counts = {}
    if rows:
        c_rows = (await db.execute(
            select(ReportAccess.report_id, func.count().label("n"))
            .where(ReportAccess.report_id.in_([r.id for r in rows]))
            .group_by(ReportAccess.report_id)
        )).all()
        counts = {r.report_id: r.n for r in c_rows}

    return [
        ReportHistoryItem(
            id=r.id,
            report_type=r.report_type,
            template_id=r.template_id,
            classification=r.classification,
            audience=r.audience,
            footer_text=r.footer_text,
            sha256=r.sha256,
            file_size=r.file_size,
            generated_by_id=r.generated_by_id,
            generated_at=r.generated_at,
            access_count=counts.get(r.id, 0),
        )
        for r in rows
    ]


@router.post("/{incident_id}/reports/{report_id}/download", summary="Download a saved report")
async def download_saved_report(
    incident_id: uuid.UUID,
    report_id:   uuid.UUID,
    body:        DownloadReportRequest,
    request:     Request,
    user:        User = Depends(require_analyst),
    db:          AsyncSession = Depends(get_db),
) -> Response:
    """Re-download a saved report. Mandatory access_reason is audit-logged.

    Returns the HTML body as an attachment with the SHA-256 in the response
    headers so the caller can verify integrity end-to-end.
    """
    await get_accessible_incident(db, incident_id, user)
    row = (await db.execute(
        select(GeneratedReport).where(
            GeneratedReport.id == report_id,
            GeneratedReport.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")

    # Record access BEFORE returning bytes so we don't lose the audit on stream errors.
    access = ReportAccess(
        report_id=row.id,
        accessed_by_id=user.id,
        access_reason=body.access_reason.strip(),
        ip_address=request.client.host if request.client else None,
    )
    db.add(access)
    await write_audit(
        db, "report_download",
        user_id=user.id, username=user.username,
        resource_type="report", resource_id=str(row.id),
        details={
            "incident_id":  str(incident_id),
            "sha256":       row.sha256,
            "reason":       body.access_reason[:200],
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    filename = f"fenrir-report-{row.report_type}-{str(row.id)[:8]}.html"
    return Response(
        content=row.html_content,
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Report-SHA256":     row.sha256,
            "Cache-Control":       "no-store",
        },
    )
