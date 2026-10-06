"""Outbound policy (H3): may data about an incident leave the platform?

Automatic outbound is blocked while the incident is under Dark Operation or marked TLP:RED:
Teams/Slack webhooks and the alert email (SMTP or Microsoft Graph) on incident events, the
automatic SPF/DKIM/DMARC DNS lookups of email analysis, and every future automatic channel (the
J2 deadline-reminder email must call `outbound_allowed` too). Each block is audited by the
caller, with the reason (`dark_operation` / `tlp_red`) and no incident content.

Manual lookups (OSINT enrichment, IOC enrichment, the email domain check) stay allowed on such an
incident but need an explicit `confirm_outbound=true`, else 409 `outbound_confirmation_required`
with the reason; a confirmed lookup is audited as `outbound_manual_lookup` before it runs.
Other TLP levels are unchanged.

Fail closed: automatic outbound is allowed only when `dark_operation` is exactly False and the
TLP is a known non-RED marking. An unknown or missing marking counts as RED.
"""
from typing import Optional

from fastapi import Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from core.errors import ApiError

DARK_OPERATION = "dark_operation"
TLP_RED = "tlp_red"
OPEN_TLP = frozenset({"amber_strict", "amber", "green", "clear"})
_WHY = {DARK_OPERATION: "Dark Operation is on", TLP_RED: "the incident is TLP:RED"}


def outbound_block_reasons(inc) -> list[str]:
    """Every reason automatic outbound is blocked for `inc`, Dark Operation first ([] = allowed).
    Never raises; an unreadable incident counts as Dark Operation."""
    try:
        reasons = [] if inc.dark_operation is False else [DARK_OPERATION]
        if str(inc.tlp or "").strip().lower() not in OPEN_TLP:
            reasons.append(TLP_RED)
        return reasons
    except Exception:  # noqa: BLE001 -- fail closed
        return [DARK_OPERATION]


def outbound_allowed(inc) -> tuple[bool, Optional[str]]:
    """The policy point for every automatic outbound channel: (True, None), or (False, reason)."""
    reasons = outbound_block_reasons(inc)
    return (False, reasons[0]) if reasons else (True, None)


async def require_outbound_confirmation(db: AsyncSession, inc, *, confirm: bool, kind: str, user,
                                        request: Optional[Request], providers: list[str],
                                        ioc_type: Optional[str] = None, count: int = 1) -> None:
    """Gate a manual outbound lookup. No-op unless the incident blocks automatic outbound.
    Then: 409 `outbound_confirmation_required` (body carries `reason`) unless `confirm`; when
    confirmed, an `outbound_manual_lookup` audit row {kind, providers, ioc_type, count, reason}
    -- never the indicator value or a key -- is committed before the lookup runs."""
    allowed, reason = outbound_allowed(inc)
    if allowed:
        return
    if not confirm:
        raise ApiError(status.HTTP_409_CONFLICT, "outbound_confirmation_required",
                       f"Automatic outbound is suppressed because {_WHY[reason]}. This lookup sends the "
                       "indicator to outside services; resend with confirm_outbound=true to run it "
                       "(audited as outbound_manual_lookup).", extra={"reason": reason})
    await write_audit(
        db, "outbound_manual_lookup", user_id=user.id, username=user.username,
        resource_type="incident", resource_id=str(inc.id), resource_label=inc.ref, outcome="success",
        details={"kind": kind, "providers": providers, "ioc_type": ioc_type, "count": count, "reason": reason},
        ip_address=request.client.host if request and request.client else None,
    )
    await db.commit()
