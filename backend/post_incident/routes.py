"""Post-incident activity: closure checklist, lessons learned, MITRE summary.

Mounted at prefix="/api/incidents".
"""
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from incidents.access import get_accessible_incident
from models import (
    ClosureChecklistItem, Entity, Evidence, Incident,
    IOC, LessonsLearned, PlaybookTask, RespondAction, TimelineEvent, User,
)
from schemas import (
    ClosureChecklistCreate,
    ClosureChecklistItemOut,
    ClosureChecklistList,
    ClosureChecklistMeta,
    ClosureChecklistToggle,
    LessonsLearnedOut,
    LessonsLearnedUpdate,
    MitreSummaryOut,
    MitreTacticSummary,
    MitreTechniqueCount,
)

router = APIRouter()

# ─── Standard closure items ───────────────────────────────────────────────────
# Ordered list; item_key is stable (used for dedup on seed).

_CLOSURE_ITEMS: list[tuple[str, str]] = [
    ("containment_verified",   "Containment actions verified effective"),
    ("malware_eradicated",     "Malware / artefacts eradicated from all affected systems"),
    ("vulnerabilities_patched","Vulnerabilities exploited have been patched or mitigated"),
    ("accounts_remediated",    "Compromised accounts disabled or credentials reset"),
    ("evidence_preserved",     "All digital evidence preserved per chain-of-custody policy"),
    ("monitoring_confirmed",   "Enhanced monitoring confirmed active on affected systems"),
    ("stakeholders_notified",  "All required stakeholders and authorities notified"),
    ("legal_compliance_review","Legal and regulatory compliance obligations reviewed"),
    ("timeline_complete",      "Incident timeline reviewed and finalised"),
    ("lessons_documented",     "Lessons learned documented and circulated"),
    ("playbook_updated",       "Playbooks / SOPs updated based on incident findings"),
    ("incident_closed",        "Incident formally closed and status updated in system"),
]


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


async def _seed_checklist(db: AsyncSession, incident_id: uuid.UUID) -> None:
    """Insert missing checklist items for this incident (idempotent)."""
    existing = set(
        (await db.execute(
            select(ClosureChecklistItem.item_key)
            .where(ClosureChecklistItem.incident_id == incident_id)
        )).scalars().all()
    )
    for i, (key, label) in enumerate(_CLOSURE_ITEMS):
        if key not in existing:
            db.add(ClosureChecklistItem(
                id=uuid.uuid4(),
                incident_id=incident_id,
                item_key=key,
                label=label,
                sort_order=i,
            ))
    await db.flush()


# ─── Closure checklist ────────────────────────────────────────────────────────

@router.get("/{incident_id}/post-incident/checklist",
            response_model=ClosureChecklistList,
            summary="Get the closure checklist")
async def list_checklist(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> ClosureChecklistList:
    """List the incident's closure checklist, seeding standard items on first read.

    Any authenticated user with access to the incident may read. The standard
    set of closure items is seeded idempotently if absent; soft-deleted
    (inactive) items are excluded. Returns `{items}` ordered by sort order.
    """
    await _get_incident(db, incident_id, user)
    await _seed_checklist(db, incident_id)
    await db.commit()

    rows = (await db.execute(
        select(ClosureChecklistItem)
        .where(
            ClosureChecklistItem.incident_id == incident_id,
            ClosureChecklistItem.is_active.is_(True),
        )
        .order_by(ClosureChecklistItem.sort_order)
    )).scalars().all()
    return ClosureChecklistList(items=[ClosureChecklistItemOut.model_validate(r) for r in rows])


@router.post("/{incident_id}/post-incident/checklist",
             response_model=ClosureChecklistItemOut,
             status_code=status.HTTP_201_CREATED,
             summary="Add a closure checklist item")
async def create_checklist_item(
    incident_id: uuid.UUID,
    req: ClosureChecklistCreate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> ClosureChecklistItemOut:
    """Add a custom item to an incident's closure checklist.

    Requires the analyst role; the incident must not be closed (409 otherwise).
    The item gets a unique `custom_*` key and is appended after existing items.
    The creation is audited and the new item is returned.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    max_order = (await db.execute(
        select(func.max(ClosureChecklistItem.sort_order))
        .where(ClosureChecklistItem.incident_id == incident_id)
    )).scalar() or 0

    item = ClosureChecklistItem(
        id=uuid.uuid4(),
        incident_id=incident_id,
        # Random key namespaced to avoid colliding with seeded defaults.
        item_key=f"custom_{uuid.uuid4().hex[:12]}",
        label=req.label.strip(),
        sort_order=max_order + 1,
    )
    db.add(item)
    await db.flush()

    await write_audit(
        db, "closure_checklist_create",
        user_id=user.id, username=user.username,
        resource_type="closure_checklist_item", resource_id=str(item.id),
        details={"incident_id": str(incident_id), "label": item.label, "item_key": item.item_key},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return ClosureChecklistItemOut.model_validate(item)


@router.delete("/{incident_id}/post-incident/checklist/{item_id}",
               status_code=status.HTTP_204_NO_CONTENT,
               summary="Delete a closure checklist item")
async def delete_checklist_item(
    incident_id: uuid.UUID,
    item_id:     uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Soft-delete (dismiss) a closure checklist item.

    Requires the analyst role; the incident must not be closed (409) and the
    item must exist and be active (404 otherwise). The item is marked inactive
    rather than removed, so the seed loop will not re-add a dismissed default.
    The action is audited and responds 204 No Content.
    """
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    item = (await db.execute(
        select(ClosureChecklistItem).where(
            ClosureChecklistItem.id == item_id,
            ClosureChecklistItem.incident_id == incident_id,
            ClosureChecklistItem.is_active.is_(True),
        )
    )).scalar_one_or_none()
    if not item:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Checklist item not found")

    # Soft delete — keeps the row so the seed loop doesn't re-add defaults
    # the analyst has explicitly dismissed.
    item.is_active = False

    await write_audit(
        db, "closure_checklist_delete",
        user_id=user.id, username=user.username,
        resource_type="closure_checklist_item", resource_id=str(item.id),
        details={"incident_id": str(incident_id), "item_key": item.item_key, "label": item.label},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.patch("/{incident_id}/post-incident/checklist/{item_id}",
              response_model=ClosureChecklistItemOut,
              summary="Toggle a closure checklist item")
async def toggle_checklist_item(
    incident_id: uuid.UUID,
    item_id:     uuid.UUID,
    req: ClosureChecklistToggle,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> ClosureChecklistItemOut:
    """Check or uncheck a closure checklist item.

    Requires the analyst role; returns 404 if the item is not found. Checking
    records the current user and timestamp; unchecking clears them. The change
    is audited and the updated item is returned.
    """
    await _get_incident(db, incident_id, user)

    item = (await db.execute(
        select(ClosureChecklistItem).where(
            ClosureChecklistItem.id == item_id,
            ClosureChecklistItem.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not item:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Checklist item not found")

    item.checked      = req.checked
    item.checked_by_id = user.id if req.checked else None
    item.checked_by    = (user.full_name or user.username) if req.checked else None
    item.checked_at    = datetime.now(timezone.utc) if req.checked else None

    await write_audit(
        db, "closure_checklist_toggle",
        user_id=user.id, username=user.username,
        resource_type="closure_checklist_item", resource_id=str(item.id),
        details={"incident_id": str(incident_id), "item_key": item.item_key, "checked": req.checked},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return ClosureChecklistItemOut.model_validate(item)


@router.patch("/{incident_id}/post-incident/checklist/{item_id}/meta",
              response_model=ClosureChecklistItemOut,
              summary="Update checklist item notes and assignee")
async def update_checklist_meta(
    incident_id: uuid.UUID,
    item_id:     uuid.UUID,
    req: ClosureChecklistMeta,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> ClosureChecklistItemOut:
    """Update the notes and/or assignee of a closure checklist item.

    Requires the analyst role; returns 404 if the item is not found, or if a
    supplied assignee is not an active user. An explicit null `assigned_to_id`
    clears the assignment. The change is audited and the updated item is
    returned.
    """
    await _get_incident(db, incident_id, user)

    item = (await db.execute(
        select(ClosureChecklistItem).where(
            ClosureChecklistItem.id == item_id,
            ClosureChecklistItem.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not item:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Checklist item not found")

    if req.notes is not None:
        item.notes = req.notes or None

    if req.assigned_to_id is not None:
        from models import User as UserModel
        assignee = (await db.execute(
            select(UserModel).where(UserModel.id == req.assigned_to_id, UserModel.is_active == True)
        )).scalar_one_or_none()
        if not assignee:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
        item.assigned_to_id = assignee.id
        item.assigned_to    = assignee.full_name or assignee.username
    elif req.assigned_to_id is None and "assigned_to_id" in req.model_fields_set:
        # Explicit null clears the assignment
        item.assigned_to_id = None
        item.assigned_to    = None

    await write_audit(
        db, "closure_checklist_meta",
        user_id=user.id, username=user.username,
        resource_type="closure_checklist_item", resource_id=str(item.id),
        details={"incident_id": str(incident_id), "item_key": item.item_key,
                 "assigned_to": item.assigned_to},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return ClosureChecklistItemOut.model_validate(item)


# ─── Lessons learned ─────────────────────────────────────────────────────────

@router.get("/{incident_id}/post-incident/lessons",
            response_model=LessonsLearnedOut,
            summary="Get the lessons-learned record")
async def get_lessons(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> LessonsLearnedOut:
    """Get the lessons-learned record for an incident.

    Any authenticated user with access to the incident may read. If no record
    exists yet, an empty draft is returned (not persisted) rather than a 404.
    """
    await _get_incident(db, incident_id, user)

    row = (await db.execute(
        select(LessonsLearned).where(LessonsLearned.incident_id == incident_id)
    )).scalar_one_or_none()

    if not row:
        return LessonsLearnedOut(
            id=uuid.uuid4(),
            incident_id=incident_id,
            status="draft",
            updated_at=datetime.now(timezone.utc),
        )
    return LessonsLearnedOut.model_validate(row)


@router.patch("/{incident_id}/post-incident/lessons",
              response_model=LessonsLearnedOut,
              summary="Save the lessons-learned record")
async def save_lessons(
    incident_id: uuid.UUID,
    req: LessonsLearnedUpdate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> LessonsLearnedOut:
    """Create or update the incident's lessons-learned record.

    Requires the analyst role. The record is upserted; only fields present in
    the request body are applied (covering narrative, root cause,
    effectiveness, observations, timeline metrics, action items, control
    improvements and report sections). The save is audited and the full record
    is returned.
    """
    await _get_incident(db, incident_id, user)

    row = (await db.execute(
        select(LessonsLearned).where(LessonsLearned.incident_id == incident_id)
    )).scalar_one_or_none()

    if not row:
        row = LessonsLearned(id=uuid.uuid4(), incident_id=incident_id)
        db.add(row)

    fields = req.model_fields_set
    if "status"                  in fields: row.status                  = req.status
    if "conducted_at"            in fields: row.conducted_at            = req.conducted_at
    if "facilitated_by"          in fields: row.facilitated_by          = req.facilitated_by
    if "participants"            in fields: row.participants            = req.participants or []
    if "incident_narrative"      in fields: row.incident_narrative      = req.incident_narrative
    if "root_cause_category"     in fields: row.root_cause_category     = req.root_cause_category
    if "root_cause_description"  in fields: row.root_cause_description  = req.root_cause_description
    if "contributing_factors"    in fields: row.contributing_factors    = req.contributing_factors or []
    if "effectiveness"           in fields: row.effectiveness           = req.effectiveness or {}
    if "what_went_well"          in fields: row.what_went_well          = req.what_went_well or []
    if "friction_points"         in fields: row.friction_points         = req.friction_points or []
    if "near_misses"             in fields: row.near_misses             = req.near_misses or []
    if "timeline_detection_mins"   in fields: row.timeline_detection_mins   = req.timeline_detection_mins
    if "timeline_escalation_mins"  in fields: row.timeline_escalation_mins  = req.timeline_escalation_mins
    if "timeline_containment_mins" in fields: row.timeline_containment_mins = req.timeline_containment_mins
    if "timeline_comms_mins"       in fields: row.timeline_comms_mins       = req.timeline_comms_mins
    if "timeline_remediation_mins" in fields: row.timeline_remediation_mins = req.timeline_remediation_mins
    if "action_items"            in fields: row.action_items            = req.action_items or []
    if "control_improvements"    in fields: row.control_improvements    = req.control_improvements or []
    if "report_what_worked_well"         in fields: row.report_what_worked_well         = req.report_what_worked_well
    if "report_what_could_improve"       in fields: row.report_what_could_improve       = req.report_what_could_improve
    if "report_security_recommendations" in fields: row.report_security_recommendations = req.report_security_recommendations
    if "report_remediation_short"        in fields: row.report_remediation_short        = req.report_remediation_short
    if "report_remediation_medium"       in fields: row.report_remediation_medium       = req.report_remediation_medium
    if "report_remediation_long"         in fields: row.report_remediation_long         = req.report_remediation_long

    row.updated_by_id = user.id
    row.updated_at    = datetime.now(timezone.utc)

    await write_audit(
        db, "lessons_learned_save",
        user_id=user.id, username=user.username,
        resource_type="lessons_learned", resource_id=str(incident_id),
        details={"incident_id": str(incident_id), "fields": list(fields)},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return LessonsLearnedOut.model_validate(row)


@router.get("/{incident_id}/post-incident/lessons/export",
            summary="Export lessons learned as HTML")
async def export_lessons(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Export the incident's lessons-learned record as a downloadable HTML report.

    Any authenticated user with access to the incident may export. Returns a
    self-contained, printable `text/html` document as a file attachment.
    """
    inc = await _get_incident(db, incident_id, user)

    row = (await db.execute(
        select(LessonsLearned).where(LessonsLearned.incident_id == incident_id)
    )).scalar_one_or_none()

    html = _render_lessons_html(inc, row)
    filename = f"LessonsLearned_{str(incident_id)[:8]}.html"
    return Response(
        content=html,
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ─── HTML export renderer ─────────────────────────────────────────────────────

_ROOT_CAUSE_LABELS = {
    "unpatched_system":   "Unpatched system / software",
    "misconfiguration":   "Misconfiguration",
    "access_control":     "Access control failure",
    "human_error":        "Human error",
    "social_engineering": "Social engineering / phishing",
    "vendor_third_party": "Vendor / third-party",
    "monitoring_gap":     "Monitoring / detection gap",
    "process_failure":    "Process failure",
    "unknown":            "Unknown",
    "other":              "Other",
}

_EFFECTIVENESS_DIMS = [
    ("detection",   "Detection",         "Speed and accuracy of threat detection"),
    ("containment", "Containment",       "Effectiveness of initial containment actions"),
    ("comms",       "Communications",    "Timeliness and clarity of internal and external comms"),
    ("roles",       "Roles & Responsibilities", "Clarity of assignment and adherence"),
    ("plan",        "IR Plan",           "Adequacy of the incident response plan"),
    ("docs",        "Documentation",     "Quality of evidence collection and record-keeping"),
]

_RATING_COLOR = {"good": "#16a34a", "acceptable": "#ca8a04", "poor": "#dc2626"}
_RATING_LABEL = {"good": "Good", "acceptable": "Acceptable", "poor": "Poor"}

_CONTROL_CATEGORIES = {
    "preventive":  "Preventive",
    "detective":   "Detective",
    "corrective":  "Corrective",
    "process":     "Process",
    "training":    "Training",
    "other":       "Other",
}


def _h(text: str) -> str:
    """Minimal HTML-escape."""
    return (str(text)
            .replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _render_lessons_html(inc, row) -> str:
    ll = row   # may be None

    def val(attr, default=""):
        if ll is None: return default
        v = getattr(ll, attr, None)
        return v if v is not None else default

    # ── header info
    inc_title = _h(getattr(inc, "title", str(inc.id)))
    inc_sev   = _h(getattr(inc, "severity", ""))
    inc_id_short = str(inc.id)[:8].upper()
    status_badge = _h(val("status", "draft")).upper()
    conducted = val("conducted_at", "")
    if conducted:
        conducted = str(conducted)[:10]
    facilitated_by = _h(val("facilitated_by", ""))
    participants   = val("participants", [])

    # ── root cause
    rc_cat  = val("root_cause_category", "")
    rc_label = _h(_ROOT_CAUSE_LABELS.get(rc_cat, rc_cat))
    rc_desc = _h(val("root_cause_description", ""))
    contrib = val("contributing_factors", [])

    # ── effectiveness
    eff = val("effectiveness", {})

    # ── observations
    wwg = val("what_went_well", [])
    fps = val("friction_points", [])
    nms = val("near_misses", [])

    # ── timeline
    tl_fields = [
        ("timeline_detection_mins",   "Detection"),
        ("timeline_escalation_mins",  "Escalation"),
        ("timeline_containment_mins", "Containment"),
        ("timeline_comms_mins",       "Comms"),
        ("timeline_remediation_mins", "Remediation"),
    ]
    tl_values = [(label, val(attr)) for attr, label in tl_fields]
    tl_max = max((v for _, v in tl_values if isinstance(v, int)), default=1) or 1

    # ── action items
    action_items = val("action_items", [])

    # ── control improvements
    ctrl_imps = val("control_improvements", [])

    # ── render helpers
    def section(title, body):
        return f"""
<div class="section">
  <h2 class="section-title">{_h(title)}</h2>
  <div class="section-body">{body}</div>
</div>"""

    def list_items(items):
        if not items: return '<p class="empty">None recorded.</p>'
        lis = "".join(f"<li>{_h(i)}</li>" for i in items)
        return f"<ul>{lis}</ul>"

    # effectiveness section
    eff_rows = ""
    for dim_id, dim_label, dim_desc in _EFFECTIVENESS_DIMS:
        d = eff.get(dim_id, {}) if isinstance(eff, dict) else {}
        rating = d.get("rating", "") if isinstance(d, dict) else ""
        notes  = d.get("notes",  "") if isinstance(d, dict) else ""
        color  = _RATING_COLOR.get(rating, "#6b7280")
        rlabel = _RATING_LABEL.get(rating, "Not rated")
        eff_rows += f"""
<tr>
  <td><strong>{_h(dim_label)}</strong><br><small>{_h(dim_desc)}</small></td>
  <td style="color:{color};font-weight:600;">{_h(rlabel)}</td>
  <td>{_h(notes)}</td>
</tr>"""

    # timeline bars
    tl_rows = ""
    for label, mins in tl_values:
        if not isinstance(mins, int):
            continue
        pct = round((mins / tl_max) * 100)
        tl_rows += f"""
<tr>
  <td style="width:140px;font-weight:500;">{_h(label)}</td>
  <td><div class="tl-bar" style="width:{pct}%;min-width:4px;"></div></td>
  <td style="width:60px;font-family:monospace;">{mins} min</td>
</tr>"""

    # action items table
    ai_rows = ""
    for ai in action_items:
        if not isinstance(ai, dict): continue
        pri   = str(ai.get("priority", "")).lower()
        pri_c = {"high": "#dc2626", "medium": "#ca8a04", "low": "#16a34a"}.get(pri, "#6b7280")
        st    = str(ai.get("status", "")).replace("_", " ").title()
        ai_rows += f"""
<tr>
  <td>{_h(ai.get("action",""))}</td>
  <td>{_h(ai.get("owner",""))}</td>
  <td style="font-family:monospace;">{_h(ai.get("due_date",""))}</td>
  <td style="color:{pri_c};font-weight:600;text-transform:capitalize;">{_h(ai.get("priority",""))}</td>
  <td>{_h(st)}</td>
</tr>"""

    # control improvements table
    ci_rows = ""
    for ci in ctrl_imps:
        if not isinstance(ci, dict): continue
        cat = _CONTROL_CATEGORIES.get(str(ci.get("category","")), str(ci.get("category","")))
        ci_rows += f"""
<tr>
  <td>{_h(ci.get("recommendation",""))}</td>
  <td>{_h(cat)}</td>
  <td style="text-transform:capitalize;">{_h(ci.get("priority",""))}</td>
</tr>"""

    parts = [
        section("Incident Narrative",
            f'<p>{_h(val("incident_narrative", ""))}</p>' if val("incident_narrative") else '<p class="empty">Not recorded.</p>'),
        section("Root Cause Analysis", f"""
<table class="kv">
  <tr><th>Category</th><td>{rc_label or '<em>Not categorised</em>'}</td></tr>
  <tr><th>Description</th><td>{rc_desc or '<em>Not recorded</em>'}</td></tr>
</table>
<h4>Contributing factors</h4>{list_items(contrib)}"""),
        section("Response Effectiveness", f"""
<table class="data">
  <thead><tr><th>Dimension</th><th style="width:120px;">Rating</th><th>Notes</th></tr></thead>
  <tbody>{eff_rows}</tbody>
</table>""" if eff_rows else '<p class="empty">Not assessed.</p>'),
        section("Observations", f"""
<div class="two-col">
  <div><h4>What went well</h4>{list_items(wwg)}</div>
  <div><h4>Friction points</h4>{list_items(fps)}</div>
</div>"""),
        section("Near Misses", list_items(nms)),
        section("Response Timeline", f"""
<table class="tl">{tl_rows}</table>""" if tl_rows else '<p class="empty">No metrics recorded.</p>'),
        section("Action Items", f"""
<table class="data">
  <thead><tr><th>Action</th><th>Owner</th><th>Due</th><th>Priority</th><th>Status</th></tr></thead>
  <tbody>{ai_rows}</tbody>
</table>""" if ai_rows else '<p class="empty">No action items.</p>'),
        section("Control Improvements", f"""
<table class="data">
  <thead><tr><th>Recommendation</th><th>Category</th><th>Priority</th></tr></thead>
  <tbody>{ci_rows}</tbody>
</table>""" if ci_rows else '<p class="empty">No improvements recorded.</p>'),
    ]

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lessons Learned — {inc_title}</title>
<style>
*,::before,::after{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px;color:#111;background:#fff;padding:32px;max-width:960px;margin:0 auto}}
h1{{font-size:22px;font-weight:700;margin-bottom:4px}}
h2{{font-size:16px;font-weight:600}}
h4{{font-size:13px;font-weight:600;margin:12px 0 6px}}
.meta{{color:#6b7280;font-size:13px;margin-bottom:24px;display:flex;gap:16px;flex-wrap:wrap}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase;background:#f3f4f6;color:#374151;border:1px solid #d1d5db}}
.badge.final{{background:#dbeafe;color:#1d4ed8;border-color:#93c5fd}}
.section{{border:1px solid #e5e7eb;border-radius:6px;margin-bottom:20px;overflow:hidden}}
.section-title{{background:#f9fafb;padding:10px 16px;font-size:14px;font-weight:600;border-bottom:1px solid #e5e7eb}}
.section-body{{padding:16px}}
p{{line-height:1.6}}
.empty{{color:#9ca3af;font-style:italic}}
ul{{padding-left:20px;line-height:2}}
table.kv{{width:100%;border-collapse:collapse}}
table.kv th{{width:160px;text-align:left;color:#6b7280;padding:4px 8px 4px 0;vertical-align:top}}
table.kv td{{padding:4px 0}}
table.data{{width:100%;border-collapse:collapse;font-size:13px}}
table.data th{{text-align:left;padding:6px 8px;background:#f3f4f6;border-bottom:2px solid #e5e7eb;font-weight:600}}
table.data td{{padding:6px 8px;border-bottom:1px solid #f3f4f6;vertical-align:top}}
table.data tr:last-child td{{border-bottom:none}}
.two-col{{display:grid;grid-template-columns:1fr 1fr;gap:24px}}
table.tl{{width:100%;border-collapse:collapse}}
table.tl td{{padding:5px 8px;vertical-align:middle}}
.tl-bar{{height:16px;background:#3b82f6;border-radius:3px;transition:width .3s}}
@media print{{body{{padding:16px}}.section{{break-inside:avoid}}}}
</style>
</head>
<body>
<h1>Lessons Learned — {inc_title}</h1>
<div class="meta">
  <span>ID: <strong>{inc_id_short}</strong></span>
  <span>Severity: <strong>{inc_sev}</strong></span>
  <span>Status: <span class="badge {'final' if status_badge == 'FINAL' else ''}">{status_badge}</span></span>
  {f'<span>Conducted: <strong>{_h(conducted)}</strong></span>' if conducted else ''}
  {f'<span>Facilitated by: <strong>{facilitated_by}</strong></span>' if facilitated_by else ''}
  {f'<span>Participants: {_h(", ".join(str(p) for p in participants))}</span>' if participants else ''}
</div>
{''.join(parts)}
<p style="margin-top:32px;font-size:11px;color:#9ca3af;text-align:right;">
  Generated {datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")} · DFIR-FENRIR v2
</p>
</body>
</html>"""


# ─── MITRE summary (computed from timeline_events) ───────────────────────────

@router.get("/{incident_id}/post-incident/mitre-summary",
            response_model=MitreSummaryOut,
            summary="Get the MITRE ATT&CK summary")
async def mitre_summary(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> MitreSummaryOut:
    """Summarise MITRE ATT&CK coverage computed from the incident's timeline.

    Any authenticated user with access to the incident may read. Timeline
    events tagged with a tactic and technique are aggregated into per-tactic,
    per-technique counts with origin breakdowns. Returns total events, mapped
    events, and the tactic/technique tree.
    """
    await _get_incident(db, incident_id, user)

    rows = (await db.execute(
        select(TimelineEvent)
        .where(TimelineEvent.incident_id == incident_id)
    )).scalars().all()

    total_events = len(rows)

    # Group by tactic → technique → origin counts.
    # tactic_id → {name, technique_id → {name, origins: {origin → count}}}
    tactic_map: dict[str, dict] = {}

    mapped = 0
    for ev in rows:
        if not ev.mitre_tactic_id or not ev.mitre_technique_id:
            continue
        mapped += 1

        tid = ev.mitre_tactic_id
        if tid not in tactic_map:
            tactic_map[tid] = {
                "name": ev.mitre_tactic_name or tid,
                "techniques": {},
            }

        tech_id = ev.mitre_technique_id
        techniques = tactic_map[tid]["techniques"]
        if tech_id not in techniques:
            techniques[tech_id] = {
                "name": ev.mitre_technique_name or tech_id,
                "origins": defaultdict(int),
            }
        techniques[tech_id]["origins"][ev.origin or "manual"] += 1

    tactics: list[MitreTacticSummary] = []
    for tactic_id, tdata in sorted(tactic_map.items()):
        techs: list[MitreTechniqueCount] = []
        total_for_tactic = 0
        for tech_id, ttech in sorted(tdata["techniques"].items()):
            count = sum(ttech["origins"].values())
            total_for_tactic += count
            techs.append(MitreTechniqueCount(
                technique_id=tech_id,
                technique_name=ttech["name"],
                count=count,
                origins=dict(ttech["origins"]),
            ))
        tactics.append(MitreTacticSummary(
            tactic_id=tactic_id,
            tactic_name=tdata["name"],
            total=total_for_tactic,
            techniques=techs,
        ))

    return MitreSummaryOut(
        total_events=total_events,
        mapped_events=mapped,
        tactics=tactics,
    )


# ─── Analytics ────────────────────────────────────────────────────────────────

@router.get("/{incident_id}/analytics",
            summary="Get incident analytics")
async def get_incident_analytics(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Compute aggregate analytics for an incident.

    Requires the analyst role. Returns a JSON object covering response timing
    (time-to-detect/contain/resolve in minutes), IOC and entity counts by type,
    timeline events by phase and MITRE coverage, playbook task completion,
    respond actions by category, and evidence counts by kind.
    """
    inc = await _get_incident(db, incident_id, user)

    def delta_mins(start, end):
        if not start or not end:
            return None
        secs = (end - start).total_seconds()
        return round(secs / 60) if secs >= 0 else None

    # ── Timing
    ttd = delta_mins(inc.occurred_at, inc.created_at)
    ttc = delta_mins(inc.created_at, inc.contained_at)
    ttr = delta_mins(inc.created_at, inc.closed_at)

    # ── IOCs by type
    ioc_rows = (await db.execute(
        select(IOC.type, func.count().label("n"))
        .where(IOC.incident_id == incident_id)
        .group_by(IOC.type)
        .order_by(func.count().desc())
    )).all()
    ioc_by_type = {r.type: r.n for r in ioc_rows}

    # ── Entities
    entity_rows = (await db.execute(
        select(Entity.type, func.count().label("n"))
        .where(Entity.incident_id == incident_id)
        .group_by(Entity.type)
        .order_by(func.count().desc())
    )).all()
    entity_by_type = {r.type: r.n for r in entity_rows}
    entity_compromised = (await db.execute(
        select(func.count()).where(
            Entity.incident_id == incident_id,
            Entity.compromised.is_(True),
        )
    )).scalar() or 0

    # ── Timeline events
    tl_rows = (await db.execute(
        select(TimelineEvent.ir_phase, func.count().label("n"))
        .where(TimelineEvent.incident_id == incident_id)
        .group_by(TimelineEvent.ir_phase)
    )).all()
    tl_by_phase = {(r.ir_phase or "unassigned"): r.n for r in tl_rows}
    tl_mitre = (await db.execute(
        select(func.count()).where(
            TimelineEvent.incident_id == incident_id,
            TimelineEvent.mitre_tactic_id.isnot(None),
        )
    )).scalar() or 0

    # ── Playbook tasks
    task_rows = (await db.execute(
        select(PlaybookTask.status, func.count().label("n"))
        .where(PlaybookTask.incident_id == incident_id)
        .group_by(PlaybookTask.status)
    )).all()
    task_by_status = {r.status: r.n for r in task_rows}
    task_total = sum(task_by_status.values())
    task_done = task_by_status.get("done", 0)
    task_skipped = task_by_status.get("skipped", 0)
    task_actionable = task_total - task_skipped
    task_pct = round((task_done / task_actionable) * 100) if task_actionable else 0

    # ── Respond actions
    resp_rows = (await db.execute(
        select(RespondAction.category, RespondAction.status, func.count().label("n"))
        .where(RespondAction.incident_id == incident_id)
        .group_by(RespondAction.category, RespondAction.status)
    )).all()
    resp_by_cat: dict[str, dict] = defaultdict(dict)
    for r in resp_rows:
        resp_by_cat[r.category][r.status] = r.n
    resp_total = sum(r.n for r in resp_rows)

    # ── Evidence
    ev_rows = (await db.execute(
        select(Evidence.kind, func.count().label("n"))
        .where(Evidence.incident_id == incident_id)
        .group_by(Evidence.kind)
    )).all()
    ev_by_kind = {r.kind: r.n for r in ev_rows}

    return {
        "timing": {"ttd_mins": ttd, "ttc_mins": ttc, "ttr_mins": ttr},
        "iocs":     {"total": sum(ioc_by_type.values()),    "by_type": ioc_by_type},
        "entities": {
            "total":       sum(entity_by_type.values()),
            "compromised": entity_compromised,
            "by_type":     entity_by_type,
        },
        "timeline": {
            "total":        sum(tl_by_phase.values()),
            "mitre_mapped": tl_mitre,
            "by_phase":     tl_by_phase,
        },
        "playbook": {
            "total":          task_total,
            "by_status":      task_by_status,
            "completion_pct": task_pct,
        },
        "respond":  {"total": resp_total, "by_category": {k: dict(v) for k, v in resp_by_cat.items()}},
        "evidence": {"total": sum(ev_by_kind.values()), "by_kind": ev_by_kind},
    }
