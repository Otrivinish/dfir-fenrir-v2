"""Inbound SIEM webhook endpoints — create incidents from SIEM alerts.

Auth: X-Fenrir-Key header (shared secret managed in Settings → Integrations).
Each adapter normalises the SIEM's native payload into a FENRIR incident.

J1 (R26): the key is checked before the body is read; the body is capped (413) and parsed by
inbound_webhooks/intake.py (a non-object or wrongly typed core field is a flat 422, never a 500).
A re-fire of an alert (same source + alert id, or the same rule + indicators) within
SIEM_DEDUP_WINDOW of the last firing attaches to its still-open incident (timeline event
"Alert re-fired", audited) instead of opening a new one. Indicators and hosts/users are extracted
onto the incident; the on-call responder and admins get an in-app notification.
"""
import hmac
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel
from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from core.security import decrypt_secret
from inbound_webhooks.intake import LABEL, SIEM_MAX_BODY_BYTES, Alert, normalise, parse_body
from incidents.reference import assign as assign_reference
from models import Entity, EntityEvent, Incident, IOC, PlatformSetting, SiemAlert, TimelineEvent
from notifications.service import notify_siem_incident
from outbound_webhooks.service import suppressed_by_outbound_policy
from stakeholder_notifications.service import record_level as record_severity_level, sync as sync_notifications

log = logging.getLogger(__name__)
router = APIRouter()

# A re-fire within this long of the same alert's last firing attaches to its open incident.
SIEM_DEDUP_WINDOW = timedelta(hours=24)


# ─── Auth ─────────────────────────────────────────────────────────────────────

async def _verify_key(db: AsyncSession, provided: Optional[str]) -> None:
    """403 with a flat {detail, code}: inbound_not_configured, invalid_key_configuration, or invalid_key (a
    wrong or missing X-Fenrir-Key: L4 R118, a missing header was FastAPI's list-shaped 422)."""
    row = (await db.execute(
        select(PlatformSetting).where(PlatformSetting.key == "inbound.siem_key")
    )).scalar_one_or_none()
    if not row:
        raise ApiError(403, "inbound_not_configured",
                       "Inbound webhook not configured — generate a key in Settings → Integrations")
    try:
        stored = decrypt_secret(row.encrypted_value)
    except Exception:
        raise ApiError(403, "invalid_key_configuration", "Invalid key configuration")
    # Constant-time compare — a plain `!=` leaks the shared secret byte-by-byte
    # via response timing. encode() because compare_digest wants equal-type args.
    if not hmac.compare_digest(stored.encode("utf-8"), (provided or "").encode("utf-8")):
        raise ApiError(403, "invalid_key", "Invalid or missing X-Fenrir-Key")


async def _read_body(request: Request) -> dict:
    """The JSON object body, at most SIEM_MAX_BODY_BYTES (413 payload_too_large), else 422 (intake.parse_body)."""
    too_big = ApiError(413, "payload_too_large",
                       f"The alert body is larger than {SIEM_MAX_BODY_BYTES} bytes.")
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > SIEM_MAX_BODY_BYTES:
        raise too_big
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > SIEM_MAX_BODY_BYTES:
            raise too_big
    return parse_body(bytes(buf))


# ─── Severity normalisation ───────────────────────────────────────────────────

_SEV_MAP: dict[str, str] = {
    "critical":      "critical",
    "high":          "high",
    "medium":        "medium",
    "low":           "low",
    "informational": "low",
    "info":          "low",
    "3":             "high",
    "2":             "medium",
    "1":             "low",
}


def _map_sev(raw: Any) -> str:
    return _SEV_MAP.get(str(raw or "").lower(), "medium")


# ─── Alert time ───────────────────────────────────────────────────────────────
# A vendor alert time more than this far before receipt is implausible (epoch 0,
# a replayed or mis-parsed field): the receipt time is used instead.
VENDOR_TIME_MAX_AGE = timedelta(days=30)


def _parse_alert_time(raw: Any) -> Optional[datetime]:
    """Vendor alert time -> aware UTC datetime; None when absent or unparseable.
    Accepts epoch seconds (number or numeric string, e.g. Splunk `_time`) and
    ISO 8601 strings. Never raises: a bad vendor value must not fail intake."""
    if isinstance(raw, bool) or not isinstance(raw, (str, int, float)):
        return None
    try:
        try:
            return datetime.fromtimestamp(float(raw), tz=timezone.utc)
        except ValueError:
            if not isinstance(raw, str):
                return None
        dt = datetime.fromisoformat(raw.strip())
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


# ─── Shared incident creation ─────────────────────────────────────────────────

async def _new_incident(
    db: AsyncSession,
    title: str,
    description: Optional[str],
    severity: str,
    reporter: str,
    alert_time: Any = None,
    *,
    incident_type: Optional[str] = None,
    alert_reference: Optional[str] = None,
    audit_extra: Optional[dict] = None,
) -> Incident:
    """Add the incident with its creation audit and stakeholder obligations, without committing."""
    inc_num, inc_ref, created_at = await assign_reference(db)
    # Detected = the vendor's alert time, capped at receipt; receipt time when the vendor time is
    # missing, unparseable or older than VENDOR_TIME_MAX_AGE before receipt (stated in the audit
    # row as vendor_time_too_old).
    vendor_time = _parse_alert_time(alert_time)
    too_old = vendor_time is not None and vendor_time < created_at - VENDOR_TIME_MAX_AGE
    if too_old:
        vendor_time = None
    detected_at = min(vendor_time, created_at) if vendor_time else created_at
    # I4: say where detected_at came from — never pass the receipt time off as the alert's time.
    detected_at_source = "alert" if vendor_time is not None and vendor_time <= created_at else "received"
    inc = Incident(
        id=uuid.uuid4(),
        incident_number=inc_num,
        ref=inc_ref,
        created_at=created_at,
        title=title[:200],
        description=description or None,
        severity=severity,
        reporter=reporter,
        detection_method="siem_alert",
        detected_at=detected_at,
        detected_at_source=detected_at_source,
        incident_type=incident_type,
        alert_reference=alert_reference,
    )
    db.add(inc)
    await db.flush()
    await write_audit(
        db, "incident_create",
        outcome="success",
        resource_type="incident", resource_id=str(inc.id), resource_label=inc.title,
        details={"ref": inc.ref, "severity": inc.severity, "reporter": reporter, "source": "siem_webhook",
                 "detected_at": detected_at.isoformat(), "detected_at_source": detected_at_source,
                 "vendor_time_used": vendor_time is not None,
                 "vendor_time_too_old": too_old, **(audit_extra or {})},
    )
    # I2: the opening severity counts from detected_at; its stakeholder-matrix obligations are created now.
    await record_severity_level(db, inc, at=detected_at, source="initial")
    await sync_notifications(db, inc, cause="incident_created")
    return inc


async def _create_incident(
    db: AsyncSession,
    title: str,
    description: Optional[str],
    severity: str,
    reporter: str,
    alert_time: Any = None,
) -> Incident:
    inc = await _new_incident(db, title, description, severity, reporter, alert_time)
    await db.commit()
    await db.refresh(inc)
    return inc


async def _post_hooks(db: AsyncSession, inc: Incident) -> None:
    """Fire outbound webhooks + email alert. Best-effort — errors are swallowed.
    Blocked (and audited) under Dark Operation or TLP:RED (H3) — fail closed."""
    if await suppressed_by_outbound_policy(db, "incident_created", inc):
        return
    try:
        from outbound_webhooks.service import dispatch_incident_event
        await dispatch_incident_event(
            db, "incident_created",
            inc_title=inc.title, inc_ref=inc.ref,
            inc_severity=inc.severity, inc_phase=inc.phase,
        )
    except Exception as exc:
        log.warning("Outbound webhook failed for SIEM incident: %s", exc)

    if inc.severity in ("high", "critical"):
        try:
            from mailer.service import send_admin_alert
            await send_admin_alert(
                db,
                f"[FENRIR] New {inc.severity.upper()} incident (SIEM): {inc.title}",
                f"A {inc.severity} severity incident was created via SIEM integration.\n\n"
                f"Ref: {inc.ref}\nTitle: {inc.title}\nReporter: {inc.reporter}\n"
                f"Description:\n{inc.description or '(none)'}",
            )
        except Exception as exc:
            log.warning("Admin alert failed for SIEM incident: %s", exc)


# ─── Extraction, dedup, intake ────────────────────────────────────────────────

async def _add_extracted(db: AsyncSession, inc_id: uuid.UUID, alert: Alert) -> tuple[int, int]:
    """Add the alert's IOCs (source = the alert reference) and in-scope host/user/ip entities (not marked
    compromised) that the incident doesn't have yet; each audited like its own endpoint. Returns the counts added."""
    ref = alert.reference
    n_ioc = n_ent = 0
    for t, v in alert.iocs:
        new_id = (await db.execute(
            pg_insert(IOC).values(id=uuid.uuid4(), incident_id=inc_id, type=t, value=v, source=ref, confidence=50,
                                  tags=["siem"])
            .on_conflict_do_nothing(index_elements=["incident_id", "type", "value"]).returning(IOC.id)
        )).scalar_one_or_none()
        if new_id:
            n_ioc += 1
            await write_audit(db, "ioc_create", resource_type="ioc", resource_id=str(new_id),
                              details={"incident_id": str(inc_id), "type": t, "value": v, "source": ref})
    for t, v in alert.entities:
        new_id = (await db.execute(
            pg_insert(Entity).values(id=uuid.uuid4(), incident_id=inc_id, type=t, value=v, criticality="medium",
                                     attributes={"source": ref}, compromised=False)
            .on_conflict_do_nothing(index_elements=["incident_id", "type", "value"]).returning(Entity.id)
        )).scalar_one_or_none()
        if new_id:
            n_ent += 1
            db.add(EntityEvent(id=uuid.uuid4(), entity_id=new_id, incident_id=inc_id, event_type="system",
                               title="Entity added"))
            await write_audit(db, "entity_create", resource_type="entity", resource_id=str(new_id),
                              details={"incident_id": str(inc_id), "type": t, "value": v, "compromised": False,
                                       "source": ref})
    return n_ioc, n_ent


async def _find_open_match(db: AsyncSession, alert: Alert, now: datetime) -> tuple[Optional[Incident], Optional[str]]:
    """The open incident this alert re-fires, by alert id first, then by content key; (None, None) if none."""
    for how, col, val in (("alert_id", SiemAlert.alert_id, alert.alert_id),
                          ("content", SiemAlert.content_key, alert.content_key)):
        if not val:
            continue
        inc = (await db.execute(
            select(Incident).join(SiemAlert, SiemAlert.incident_id == Incident.id)
            .where(SiemAlert.source == alert.source, col == val, Incident.status == "open",
                   SiemAlert.received_at >= now - SIEM_DEDUP_WINDOW)
            .order_by(SiemAlert.received_at.desc()).limit(1)
        )).scalar_one_or_none()
        if inc is not None:
            return inc, how
    return None, None


class SiemIntakeOut(BaseModel):
    id:          uuid.UUID
    ref:         str
    status:      Literal["created", "attached"]
    alert_count: int


async def _intake(db: AsyncSession, alert: Alert) -> SiemIntakeOut:
    reporter = LABEL[alert.source]
    # One intake per source at a time (xact lock): two copies of one alert can't both open an incident.
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext('fenrir.siem_intake'), hashtext(:s))")
                     .bindparams(s=alert.source))
    vendor_raw = next((t for t in alert.time_candidates if _parse_alert_time(t) is not None), None)
    vendor_time = _parse_alert_time(vendor_raw)
    now = datetime.now(timezone.utc)
    inc, how = await _find_open_match(db, alert, now)

    if inc is not None:
        count = int((await db.execute(
            select(func.count()).select_from(SiemAlert).where(SiemAlert.incident_id == inc.id))).scalar() or 0) + 1
        db.add(SiemAlert(id=uuid.uuid4(), incident_id=inc.id, source=alert.source, alert_id=alert.alert_id,
                         content_key=alert.content_key, alert_time=vendor_time, received_at=now, outcome="attached"))
        event_time = min(vendor_time, now) if vendor_time and vendor_time >= now - VENDOR_TIME_MAX_AGE else now
        db.add(TimelineEvent(
            id=uuid.uuid4(), incident_id=inc.id, event_time=event_time, source=f"SIEM ({reporter})",
            event_type="Alert re-fired",
            description=f"{reporter} alert re-fired: firing {count} on this incident"
                        + (f" (alert id {alert.alert_id})." if alert.alert_id else "."),
            ir_phase=inc.phase, origin="system", is_system=True, external_safe=False, system_source="siem",
        ))
        n_ioc, n_ent = await _add_extracted(db, inc.id, alert)
        await write_audit(
            db, "siem_alert_attached", outcome="success",
            resource_type="incident", resource_id=str(inc.id), resource_label=inc.ref,
            details={"source": alert.source, "alert_id": alert.alert_id, "matched_on": how, "alert_count": count,
                     "iocs_added": n_ioc, "entities_added": n_ent},
        )
        await db.commit()
        return SiemIntakeOut(id=inc.id, ref=inc.ref, status="attached", alert_count=count)

    inc = await _new_incident(
        db, alert.title, alert.description, _map_sev(alert.severity_raw), reporter, vendor_raw,
        incident_type=alert.incident_type, alert_reference=alert.reference,
        audit_extra={"alert_reference": alert.reference, "incident_type": alert.incident_type,
                     "category": alert.category},
    )
    db.add(SiemAlert(id=uuid.uuid4(), incident_id=inc.id, source=alert.source, alert_id=alert.alert_id,
                     content_key=alert.content_key, alert_time=vendor_time, received_at=now, outcome="created"))
    await _add_extracted(db, inc.id, alert)
    await db.commit()
    await db.refresh(inc)
    try:
        await notify_siem_incident(db, inc.id, inc.ref, reporter, inc.title)
    except Exception as exc:  # noqa: BLE001 — the incident exists; a failed in-app notice must not fail intake
        await db.rollback()
        log.warning("SIEM incident notification failed (%s)", type(exc).__name__)
    await _post_hooks(db, inc)
    return SiemIntakeOut(id=inc.id, ref=inc.ref, status="created", alert_count=1)


_DOC_TAIL = (
    " Authenticated via the shared `X-Fenrir-Key` header (403 invalid_key when missing or wrong), checked before the"
    " body is read."
    " The body must be a JSON object of at most 1 MiB (413 payload_too_large); invalid JSON, a non-object or a"
    " wrongly typed core field is 422 invalid_json / payload_not_object / invalid_field (`field`)."
    " A re-fire (same source + alert id, or the same rule + extracted indicators) within 24 h of the last firing"
    " attaches to that alert's open incident: status `attached`, a timeline event 'Alert re-fired', audited"
    " siem_alert_attached; otherwise a new incident (status `created`) with detection_method siem_alert,"
    " alert_reference `<source>:<alert id or rule>`, incident_type when the payload's category maps to one"
    " (else none: start check 'Incident type set'), IOCs (ip/domain/url/hash/email, source = the alert"
    " reference) and host/user/private-ip entities from known fields. The on-call responder and admins get an"
    " in-app notification; outbound webhooks and the admin email follow the outbound policy (H3)."
)
def _desc(text: str) -> str:
    return " ".join(text.split()) + _DOC_TAIL


_RESPONSES = {403: {"model": ApiErrorBody, "description": "invalid_key (missing or wrong X-Fenrir-Key), "
                    "inbound_not_configured or invalid_key_configuration"},
              413: {"model": ApiErrorBody, "description": "payload_too_large"},
              422: {"model": ApiErrorBody, "description": "invalid_json, payload_not_object or invalid_field"}}
_BODY = {"requestBody": {"required": True, "content": {"application/json": {
    "schema": {"type": "object", "additionalProperties": True, "description": "The SIEM's native alert payload."}}}}}


# ─── Splunk ───────────────────────────────────────────────────────────────────

@router.post("/splunk", summary="Create an incident from a Splunk alert", response_model=SiemIntakeOut,
             responses=_RESPONSES, openapi_extra=_BODY, description=_desc("""
    Create a FENRIR incident from a Splunk alert webhook (search_name, result.host/source/severity,
    results_link). detected_at is `result._time` (epoch or ISO 8601) capped at receipt; receipt time when it
    is missing, unparseable or more than 30 days before receipt (detected_at_source alert or received).
    Alert id = `sid`; rule = search_name; category = `result.category` / `result.incident_type`."""))
async def inbound_splunk(
    request: Request,
    x_fenrir_key: Optional[str] = Header(default=None, description="The shared inbound key (Settings → Integrations)."),
    db: AsyncSession = Depends(get_db),
) -> SiemIntakeOut:
    """Splunk alert -> incident, or attached to its open incident (see the route description)."""
    await _verify_key(db, x_fenrir_key)
    return await _intake(db, normalise("splunk", await _read_body(request)))



# ─── Microsoft Sentinel ───────────────────────────────────────────────────────

@router.post("/sentinel", summary="Create an incident from a Sentinel alert", response_model=SiemIntakeOut,
             responses=_RESPONSES, openapi_extra=_BODY, description=_desc("""
    Create a FENRIR incident from a Microsoft Sentinel alert webhook (title, description, severity,
    Entities[]). detected_at is `TimeGenerated` (or `properties.timeGenerated`) capped at receipt; receipt time
    when it is missing, unparseable or more than 30 days before receipt (detected_at_source alert or received).
    Alert id = `SystemAlertId`; rule = AlertType / AlertName / title."""))
async def inbound_sentinel(
    request: Request,
    x_fenrir_key: Optional[str] = Header(default=None, description="The shared inbound key (Settings → Integrations)."),
    db: AsyncSession = Depends(get_db),
) -> SiemIntakeOut:
    """Sentinel alert -> incident, or attached to its open incident (see the route description)."""
    await _verify_key(db, x_fenrir_key)
    return await _intake(db, normalise("sentinel", await _read_body(request)))



# ─── Elastic SIEM ─────────────────────────────────────────────────────────────

@router.post("/elastic", summary="Create an incident from an Elastic alert", response_model=SiemIntakeOut,
             responses=_RESPONSES, openapi_extra=_BODY, description=_desc("""
    Create a FENRIR incident from an Elastic SIEM alert webhook (rule.name/description/severity,
    context.reason, context.alerts[] with ECS fields). detected_at is `@timestamp`, else `event.created`
    (top level, then context.alerts[]), capped at receipt; receipt time when missing, unparseable or more than
    30 days before receipt (detected_at_source alert or received). Alert id = `kibana.alert.uuid` / `alert.id`;
    rule = rule.id / rule.name; category = `event.category`."""))
async def inbound_elastic(
    request: Request,
    x_fenrir_key: Optional[str] = Header(default=None, description="The shared inbound key (Settings → Integrations)."),
    db: AsyncSession = Depends(get_db),
) -> SiemIntakeOut:
    """Elastic alert -> incident, or attached to its open incident (see the route description)."""
    await _verify_key(db, x_fenrir_key)
    return await _intake(db, normalise("elastic", await _read_body(request)))

