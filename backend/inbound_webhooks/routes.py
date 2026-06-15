"""Inbound SIEM webhook endpoints — create incidents from SIEM alerts.

Auth: X-Fenrir-Key header (shared secret managed in Settings → Integrations).
Each adapter normalises the SIEM's native payload into a FENRIR incident.
"""
import hmac
import logging
import uuid
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from core.database import get_db
from core.security import decrypt_secret
from models import Incident, PlatformSetting

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


# ─── Shared incident creation ─────────────────────────────────────────────────

async def _create_incident(
    db: AsyncSession,
    title: str,
    description: Optional[str],
    severity: str,
    reporter: str,
) -> Incident:
    inc_num = (await db.execute(text("SELECT nextval('incident_seq')"))).scalar()
    inc = Incident(
        id=uuid.uuid4(),
        incident_number=inc_num,
        title=title[:200],
        description=description or None,
        severity=severity,
        reporter=reporter,
    )
    db.add(inc)
    await db.flush()
    await write_audit(
        db, "incident_create",
        outcome="success",
        resource_type="incident", resource_id=str(inc.id), resource_label=inc.title,
        details={"severity": inc.severity, "reporter": reporter, "source": "siem_webhook"},
    )
    await db.commit()
    await db.refresh(inc)
    return inc


async def _post_hooks(db: AsyncSession, inc: Incident) -> None:
    """Fire outbound webhooks + email alert. Best-effort — errors are swallowed."""
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
    incident's id, ref and status."""
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

    inc = await _create_incident(db, title, desc, sev, "Splunk")
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
    high/critical. Returns the new incident's id, ref and status."""
    await _verify_key(db, x_fenrir_key)

    title = (payload.get("title") or payload.get("name") or "Sentinel Alert")[:200]
    desc  = payload.get("description") or ""
    sev   = _map_sev(payload.get("severity", "medium"))

    inc = await _create_incident(db, title, desc, sev, "Microsoft Sentinel")
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
    high/critical. Returns the new incident's id, ref and status."""
    await _verify_key(db, x_fenrir_key)

    rule    = payload.get("rule") or {}
    context = payload.get("context") or {}
    ctx_rule = context.get("rule") or {}

    title = (rule.get("name") or payload.get("alertName") or "Elastic Alert")[:200]
    desc  = rule.get("description") or context.get("reason") or ""
    sev   = _map_sev(rule.get("severity") or ctx_rule.get("severity", "medium"))

    inc = await _create_incident(db, title, desc, sev, "Elastic SIEM")
    await _post_hooks(db, inc)
    return {"id": str(inc.id), "ref": inc.ref, "status": "created"}
