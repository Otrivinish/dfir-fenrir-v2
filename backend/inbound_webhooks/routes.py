"""Inbound SIEM webhook endpoints — create incidents from SIEM alerts.

Auth: X-Fenrir-Key header (shared secret managed in Settings → Integrations).
Each adapter normalises the SIEM's native payload into a FENRIR incident.
"""
import hmac
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from core.database import get_db
from core.security import decrypt_secret
from incidents.reference import assign as assign_reference
from models import Incident, PlatformSetting
from outbound_webhooks.service import suppressed_by_outbound_policy

log = logging.getLogger(__name__)
router = APIRouter()


# ─── Auth ─────────────────────────────────────────────────────────────────────

async def _verify_key(db: AsyncSession, provided: str) -> None:
    row = (await db.execute(
        select(PlatformSetting).where(PlatformSetting.key == "inbound.siem_key")
    )).scalar_one_or_none()
    if not row:
        raise HTTPException(403, "Inbound webhook not configured — generate a key in Settings → Integrations")
    try:
        stored = decrypt_secret(row.encrypted_value)
    except Exception:
        raise HTTPException(403, "Invalid key configuration")
    # Constant-time compare — a plain `!=` leaks the shared secret byte-by-byte
    # via response timing. encode() because compare_digest wants equal-type args.
    if not hmac.compare_digest(stored.encode("utf-8"), (provided or "").encode("utf-8")):
        raise HTTPException(403, "Invalid X-Fenrir-Key")


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

async def _create_incident(
    db: AsyncSession,
    title: str,
    description: Optional[str],
    severity: str,
    reporter: str,
    alert_time: Any = None,
) -> Incident:
    inc_num, inc_ref, created_at = await assign_reference(db)
    # Detected = the vendor's alert time, capped at receipt; receipt time when
    # the vendor time is missing, unparseable or older than VENDOR_TIME_MAX_AGE
    # before receipt (stated in the audit row as vendor_time_too_old).
    vendor_time = _parse_alert_time(alert_time)
    too_old = vendor_time is not None and vendor_time < created_at - VENDOR_TIME_MAX_AGE
    if too_old:
        vendor_time = None
    detected_at = min(vendor_time, created_at) if vendor_time else created_at
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
    )
    db.add(inc)
    await db.flush()
    await write_audit(
        db, "incident_create",
        outcome="success",
        resource_type="incident", resource_id=str(inc.id), resource_label=inc.title,
        details={"ref": inc.ref, "severity": inc.severity, "reporter": reporter, "source": "siem_webhook",
                 "detected_at": detected_at.isoformat(), "vendor_time_used": vendor_time is not None,
                 "vendor_time_too_old": too_old},
    )
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


# ─── Splunk ───────────────────────────────────────────────────────────────────

@router.post("/splunk", summary="Create an incident from a Splunk alert")
async def inbound_splunk(
    payload: dict,
    x_fenrir_key: str = Header(...),
    db: AsyncSession = Depends(get_db),
):
    """Create a FENRIR incident from a Splunk alert webhook. Authenticated via
    the shared `X-Fenrir-Key` header (403 on mismatch). Normalises the Splunk
    payload (search name, host/source, severity) into an incident, then fires
    outbound webhooks and an admin alert for high/critical. Returns the new
    incident's id, ref and status. detection_method is siem_alert; detected_at
    is `result._time` (epoch or ISO 8601) capped at receipt; receipt time when it is
    missing, unparseable or more than 30 days before receipt."""
    await _verify_key(db, x_fenrir_key)

    result = payload.get("result") or {}
    title  = (payload.get("search_name") or result.get("alert_name") or "Splunk Alert")[:200]
    desc   = "\n".join(filter(None, [
        f"Splunk search: {payload.get('search_name', '')}",
        f"Host: {result.get('host', '')}",
        f"Source: {result.get('source', '')}",
        f"Results link: {payload.get('results_link', '')}",
    ]))
    sev = _map_sev(result.get("severity") or payload.get("severity", "medium"))

    inc = await _create_incident(db, title, desc, sev, "Splunk", result.get("_time"))
    await _post_hooks(db, inc)
    return {"id": str(inc.id), "ref": inc.ref, "status": "created"}


# ─── Microsoft Sentinel ───────────────────────────────────────────────────────

@router.post("/sentinel", summary="Create an incident from a Sentinel alert")
async def inbound_sentinel(
    payload: dict,
    x_fenrir_key: str = Header(...),
    db: AsyncSession = Depends(get_db),
):
    """Create a FENRIR incident from a Microsoft Sentinel alert webhook.
    Authenticated via the shared `X-Fenrir-Key` header (403 on mismatch).
    Normalises the Sentinel payload (title, description, severity) into an
    incident, then fires outbound webhooks and an admin alert for
    high/critical. Returns the new incident's id, ref and status.
    detection_method is siem_alert; detected_at is `TimeGenerated` capped at
    receipt; receipt time when it is missing, unparseable or more than 30 days
    before receipt."""
    await _verify_key(db, x_fenrir_key)

    title = (payload.get("title") or payload.get("name") or "Sentinel Alert")[:200]
    desc  = payload.get("description") or ""
    sev   = _map_sev(payload.get("severity", "medium"))

    inc = await _create_incident(db, title, desc, sev, "Microsoft Sentinel", payload.get("TimeGenerated"))
    await _post_hooks(db, inc)
    return {"id": str(inc.id), "ref": inc.ref, "status": "created"}


# ─── Elastic SIEM ─────────────────────────────────────────────────────────────

@router.post("/elastic", summary="Create an incident from an Elastic alert")
async def inbound_elastic(
    payload: dict,
    x_fenrir_key: str = Header(...),
    db: AsyncSession = Depends(get_db),
):
    """Create a FENRIR incident from an Elastic SIEM alert webhook.
    Authenticated via the shared `X-Fenrir-Key` header (403 on mismatch).
    Normalises the Elastic rule/context payload (name, description, severity)
    into an incident, then fires outbound webhooks and an admin alert for
    high/critical. Returns the new incident's id, ref and status.
    detection_method is siem_alert; detected_at is top-level `@timestamp`
    capped at receipt; receipt time when it is missing, unparseable or more
    than 30 days before receipt."""
    await _verify_key(db, x_fenrir_key)

    rule    = payload.get("rule") or {}
    context = payload.get("context") or {}
    ctx_rule = context.get("rule") or {}

    title = (rule.get("name") or payload.get("alertName") or "Elastic Alert")[:200]
    desc  = rule.get("description") or context.get("reason") or ""
    sev   = _map_sev(rule.get("severity") or ctx_rule.get("severity", "medium"))

    inc = await _create_incident(db, title, desc, sev, "Elastic SIEM", payload.get("@timestamp"))
    await _post_hooks(db, inc)
    return {"id": str(inc.id), "ref": inc.ref, "status": "created"}
