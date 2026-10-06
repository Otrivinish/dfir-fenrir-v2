"""Outbound webhooks — Teams and Slack incident event notifications.

Uses Office 365 MessageCard format for Teams and Block Kit for Slack.
Fire-and-forget: errors are logged but never propagated to the caller.
"""
import asyncio
import logging
from typing import Optional
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from core.outbound_policy import outbound_allowed
from core.security import decrypt_secret
from models import Incident, PlatformSetting

log = logging.getLogger(__name__)

_SEV_COLOR = {
    "critical": "EF4444",
    "high":     "F97316",
    "medium":   "EAB308",
    "low":      "22D3EE",
}
_EVENT_EMOJI = {
    "incident_created":  "🚨",
    "phase_changed":     "🔄",
    "severity_changed":  "⚠",
    "incident_resolved": "✅",
}


async def suppressed_by_outbound_policy(db: AsyncSession, event: str, inc: Incident) -> bool:
    """Fail-closed guard for outbound incident sends (Teams/Slack webhooks and the
    admin alert email, SMTP or Graph), decided by `core.outbound_policy` (H3):
    blocked under Dark Operation or TLP:RED.

    Returns False (send allowed) only when the policy allows it. Otherwise the
    send is blocked: an `outbound_notification_suppressed` audit row records
    `{event, reason}` (reason `dark_operation` or `tlp_red`) — never the title
    or description — and True is returned. Never raises; any error still blocks.
    """
    try:
        allowed, reason = outbound_allowed(inc)
        if allowed:
            return False
        # Savepoint: a failed audit write must not poison the caller's session.
        async with db.begin_nested():
            await write_audit(
                db, "outbound_notification_suppressed",
                outcome="success",
                resource_type="incident", resource_id=str(inc.id), resource_label=inc.ref,
                details={"event": event, "reason": reason},
            )
        await db.commit()
        log.info("Outbound policy (%s): %s suppressed for incident %s", reason, event, inc.id)
    except Exception as exc:  # noqa: BLE001 — fail closed: block, never raise
        log.warning("Outbound policy: %s blocked for incident %s; audit row not written (%s)",
                    event, getattr(inc, "id", "?"), type(exc).__name__)
    return True


async def _get_url(db: AsyncSession, key: str) -> Optional[str]:
    row = (await db.execute(
        select(PlatformSetting).where(PlatformSetting.key == key)
    )).scalar_one_or_none()
    if not row:
        return None
    try:
        return decrypt_secret(row.encrypted_value)
    except Exception:
        return None


async def _post_teams(url: str, title: str, color: str, facts: list[dict]) -> None:
    payload = {
        "@type":    "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary":    title,
        "themeColor": color,
        "sections": [{
            "activityTitle":    title,
            "activitySubtitle": "DFIR FENRIR",
            "facts": [{"name": f["name"], "value": f["value"]} for f in facts],
            "markdown": False,
        }],
    }
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(url, json=payload)
            if r.status_code not in (200, 202):
                log.warning("Teams webhook %s: %s", r.status_code, r.text[:200])
    except Exception as exc:
        log.warning("Teams webhook error: %s", exc)


async def _post_slack(url: str, title: str, facts: list[dict]) -> None:
    fields = [
        {"type": "mrkdwn", "text": f"*{f['name']}*\n{f['value']}"}
        for f in facts[:10]
    ]
    payload = {
        "text": title,
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": title, "emoji": True}},
            {"type": "section", "fields": fields},
        ],
    }
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(url, json=payload)
            if r.status_code != 200:
                log.warning("Slack webhook %s: %s", r.status_code, r.text[:200])
    except Exception as exc:
        log.warning("Slack webhook error: %s", exc)


async def dispatch_incident_event(
    db: AsyncSession,
    event: str,
    inc_title: str,
    inc_ref: Optional[str],
    inc_severity: str,
    inc_phase: str,
    extra_facts: Optional[list[dict]] = None,
) -> None:
    """Fire outbound webhooks for an incident event. Never raises."""
    teams_url = await _get_url(db, "webhook.teams_url")
    slack_url = await _get_url(db, "webhook.slack_url")
    if not teams_url and not slack_url:
        return

    emoji   = _EVENT_EMOJI.get(event, "ℹ")
    label   = event.replace("_", " ").title()
    ref     = f" [{inc_ref}]" if inc_ref else ""
    title   = f"{emoji} {label}{ref}: {inc_title}"
    color   = _SEV_COLOR.get(inc_severity, "22D3EE")

    facts: list[dict] = [
        {"name": "Severity", "value": inc_severity.title()},
        {"name": "Phase",    "value": inc_phase.replace("_", " ").title()},
    ]
    if extra_facts:
        facts.extend(extra_facts)

    tasks = []
    if teams_url:
        tasks.append(_post_teams(teams_url, title, color, facts))
    if slack_url:
        tasks.append(_post_slack(slack_url, title, facts))
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
