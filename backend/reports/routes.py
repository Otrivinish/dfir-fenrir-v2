"""Report data assembly — assembles all per-incident data for client-side rendering.

Also exposes the audit-grade history flow:
  POST   /{incident_id}/reports                    — save a freshly-rendered HTML report
  GET    /{incident_id}/reports/history            — list saved reports for the incident
  POST   /{incident_id}/reports/{report_id}/download — re-download with mandatory access_reason
"""
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from incidents.access import get_accessible_incident
from models import (
    BusinessImpact, ClosureChecklistItem, Decision, Entity, EntityRelation,
    Evidence, GeneratedReport, Incident, IncidentAssignment, IncidentCost,
    IOC, LessonsLearned, PlaybookTask, ReportAccess, RespondAction,
    ThreatIntelIOC, TimelineEvent, User,
)
from sqlalchemy import tuple_

router = APIRouter()

_EXCLUDE = {"oob_passphrase"}


@router.get("/{incident_id}/reports/data", summary="Get report data")
async def get_report_data(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    """Assemble the complete data bundle for an incident report, for client-side rendering.

    Aggregates the incident with its IOCs (threat-intel enriched), entities and relations,
    timeline, playbook tasks, respond actions, decisions, closure checklist, lessons learned,
    evidence summary, business impact, costs, a MITRE summary computed from the timeline, and
    assignments. Sensitive fields (e.g. oob_passphrase) are excluded. Requires read access to the
    incident (returns 404 otherwise).
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

    return {
        "generated_at":     datetime.now(timezone.utc).isoformat(),
        "incident":         jsonable_encoder(inc, exclude=_EXCLUDE),
        "iocs":             iocs_out,
        "entities":         jsonable_encoder(list(entities)),
        "entity_relations": jsonable_encoder(list(entity_relations)),
        "timeline_events":  jsonable_encoder(list(timeline)),
        "playbook_tasks":   jsonable_encoder(list(tasks)),
        "respond_actions":  jsonable_encoder(list(actions)),
        "decisions":        jsonable_encoder(list(decisions)),
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
