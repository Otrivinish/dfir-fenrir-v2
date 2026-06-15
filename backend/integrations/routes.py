"""Admin integrations settings — SMTP/Graph, outbound webhooks, SIEM inbound key."""
import secrets
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import require_admin
from core.database import get_db
from core.security import decrypt_secret, encrypt_secret
from mailer.service import send_admin_alert
from models import PlatformSetting, User

router = APIRouter()


# ─── Key-value helpers ─────────────────────────────────────────────────────

async def _get(db: AsyncSession, key: str) -> Optional[str]:
    row = (await db.execute(
        select(PlatformSetting).where(PlatformSetting.key == key)
    )).scalar_one_or_none()
    if not row:
        return None
    try:
        return decrypt_secret(row.encrypted_value)
    except Exception:
        return None


async def _set(db: AsyncSession, key: str, value: str, user_id) -> None:
    enc = encrypt_secret(value)
    stmt = (
        pg_insert(PlatformSetting)
        .values(key=key, encrypted_value=enc, updated_by_id=user_id)
        .on_conflict_do_update(
            index_elements=["key"],
            set_={"encrypted_value": enc, "updated_by_id": user_id},
        )
    )
    await db.execute(stmt)


async def _del(db: AsyncSession, key: str) -> None:
    row = (await db.execute(
        select(PlatformSetting).where(PlatformSetting.key == key)
    )).scalar_one_or_none()
    if row:
        await db.delete(row)


# ─── SMTP / Graph config ──────────────────────────────────────────────────

class SmtpConfig(BaseModel):
    mode:          str             # "smtp" | "graph" | "" (disabled)
    host:          Optional[str] = None
    port:          Optional[int] = None
    username:      Optional[str] = None
    password:      Optional[str] = None   # omit to keep existing
    from_address:  Optional[str] = None
    admin_email:   Optional[str] = None
    graph_tenant_id:     Optional[str] = None
    graph_client_id:     Optional[str] = None
    graph_client_secret: Optional[str] = None  # omit to keep existing
    graph_sender:        Optional[str] = None


class SmtpConfigOut(BaseModel):
    mode:             str
    host:             Optional[str] = None
    port:             Optional[int] = None
    username:         Optional[str] = None
    password_set:     bool = False
    from_address:     Optional[str] = None
    admin_email:      Optional[str] = None
    graph_tenant_id:  Optional[str] = None
    graph_client_id:  Optional[str] = None
    graph_secret_set: bool = False
    graph_sender:     Optional[str] = None


@router.get("/smtp", response_model=SmtpConfigOut, summary="Get email (SMTP/Graph) config")
async def get_smtp_config(
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Get the outbound email configuration (SMTP or Microsoft Graph mode).
    Secrets are never returned — password/secret presence is reported via
    `password_set` / `graph_secret_set` booleans. Admin access required."""
    port_str = await _get(db, "smtp.port")
    return SmtpConfigOut(
        mode             = await _get(db, "smtp.mode") or "",
        host             = await _get(db, "smtp.host"),
        port             = int(port_str) if port_str and port_str.isdigit() else None,
        username         = await _get(db, "smtp.username"),
        password_set     = bool(await _get(db, "smtp.password")),
        from_address     = await _get(db, "smtp.from_address"),
        admin_email      = await _get(db, "smtp.admin_email"),
        graph_tenant_id  = await _get(db, "graph.tenant_id"),
        graph_client_id  = await _get(db, "graph.client_id"),
        graph_secret_set = bool(await _get(db, "graph.client_secret")),
        graph_sender     = await _get(db, "graph.sender"),
    )


@router.put("/smtp", status_code=204, summary="Save email (SMTP/Graph) config")
async def save_smtp_config(
    body: SmtpConfig,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Save the outbound email configuration. Only supplied fields are
    written; omit `password` / `graph_client_secret` to keep the existing
    stored secret. Secrets are encrypted at rest. Admin access required.
    Returns 204 No Content."""
    uid = user.id
    await _set(db, "smtp.mode", body.mode or "", uid)
    if body.host         is not None: await _set(db, "smtp.host",         body.host,            uid)
    if body.port         is not None: await _set(db, "smtp.port",         str(body.port),        uid)
    if body.username     is not None: await _set(db, "smtp.username",     body.username,         uid)
    if body.password     is not None: await _set(db, "smtp.password",     body.password,         uid)
    if body.from_address is not None: await _set(db, "smtp.from_address", body.from_address,     uid)
    if body.admin_email  is not None: await _set(db, "smtp.admin_email",  body.admin_email,      uid)
    if body.graph_tenant_id     is not None: await _set(db, "graph.tenant_id",     body.graph_tenant_id,     uid)
    if body.graph_client_id     is not None: await _set(db, "graph.client_id",     body.graph_client_id,     uid)
    if body.graph_client_secret is not None: await _set(db, "graph.client_secret", body.graph_client_secret, uid)
    if body.graph_sender        is not None: await _set(db, "graph.sender",        body.graph_sender,        uid)
    await db.commit()


@router.post("/smtp/test", status_code=204, summary="Send a test email")
async def test_smtp(
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Send a test email to the configured admin address using the current
    email settings. Returns 400 if delivery fails. Admin access required.
    Returns 204 No Content on success."""
    ok = await send_admin_alert(
        db,
        "FENRIR test email",
        "This is a test from DFIR FENRIR. Email delivery is configured correctly.",
    )
    if not ok:
        raise HTTPException(400, "Send failed — check configuration and server logs.")


# ─── Outbound webhooks (Teams / Slack) ──────────────────────────────────────

class WebhookConfig(BaseModel):
    teams_url: Optional[str] = None   # empty string = delete
    slack_url: Optional[str] = None


class WebhookConfigOut(BaseModel):
    teams_url_set:     bool
    slack_url_set:     bool
    teams_url_preview: Optional[str] = None
    slack_url_preview: Optional[str] = None


def _validate_webhook_url(url: str, label: str) -> None:
    """Reject webhook targets that could be used for SSRF. Outbound webhooks POST
    incident JSON to this URL on every event, so an unvalidated value lets an
    admin (or a hijacked admin session) aim the server at internal services."""
    from threat_intel.ingest import assert_safe_feed_url  # shared SSRF resolver
    p = urlparse(url)
    if p.scheme != "https":
        raise HTTPException(400, f"{label} webhook URL must use https")
    try:
        assert_safe_feed_url(url)
    except ValueError as exc:
        raise HTTPException(400, f"{label} webhook URL rejected: {exc}")


def _url_preview(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    try:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}/…"
    except Exception:
        return "configured"


@router.get("/webhooks", response_model=WebhookConfigOut, summary="Get outbound webhook config")
async def get_webhook_config(
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Get the outbound (Teams/Slack) webhook configuration. Full URLs are not
    returned — only `*_set` booleans and a redacted scheme/host preview. Admin
    access required."""
    teams = await _get(db, "webhook.teams_url")
    slack = await _get(db, "webhook.slack_url")
    return WebhookConfigOut(
        teams_url_set     = bool(teams),
        slack_url_set     = bool(slack),
        teams_url_preview = _url_preview(teams),
        slack_url_preview = _url_preview(slack),
    )


@router.put("/webhooks", status_code=204, summary="Save outbound webhook config")
async def save_webhook_config(
    body: WebhookConfig,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Save the outbound Teams/Slack webhook URLs. An empty string deletes a
    URL; omitting a field leaves it unchanged. URLs must be https and pass SSRF
    validation (400 otherwise). Stored encrypted at rest. Admin access
    required. Returns 204 No Content."""
    if body.teams_url is not None:
        if body.teams_url:
            _validate_webhook_url(body.teams_url, "Teams")
            await _set(db, "webhook.teams_url", body.teams_url, user.id)
        else:
            await _del(db, "webhook.teams_url")
    if body.slack_url is not None:
        if body.slack_url:
            _validate_webhook_url(body.slack_url, "Slack")
            await _set(db, "webhook.slack_url", body.slack_url, user.id)
        else:
            await _del(db, "webhook.slack_url")
    await db.commit()


# ─── SIEM inbound key ─────────────────────────────────────────────────────

class SiemKeyOut(BaseModel):
    configured: bool
    key:        Optional[str] = None   # only returned on generate


@router.get("/siem-key", response_model=SiemKeyOut, summary="Get SIEM inbound key status")
async def get_siem_key(
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Report whether an inbound SIEM webhook key is configured. The key value
    itself is never returned here (only on generate). Admin access required."""
    val = await _get(db, "inbound.siem_key")
    return SiemKeyOut(configured=bool(val))


@router.post("/siem-key/generate", response_model=SiemKeyOut, summary="Generate SIEM inbound key")
async def generate_siem_key(
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Generate and store a new inbound SIEM webhook key, replacing any
    existing one. The plaintext key is returned only in this response (stored
    encrypted at rest). Admin access required."""
    key = secrets.token_urlsafe(32)
    await _set(db, "inbound.siem_key", key, user.id)
    await db.commit()
    return SiemKeyOut(configured=True, key=key)


@router.delete("/siem-key", status_code=204, summary="Delete SIEM inbound key")
async def delete_siem_key(
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Delete the inbound SIEM webhook key, disabling inbound webhook auth
    until a new key is generated. Idempotent. Admin access required. Returns
    204 No Content."""
    await _del(db, "inbound.siem_key")
    await db.commit()


# ─── Syslog forwarding (RFC 5424) ─────────────────────────────────────────
# Two scopes:
#   • audit_only — every row written by audit.service.write_audit()
#   • all        — audit rows + Python `logging` records (WARNING+).
# Three transports: udp · tcp · tls (TLS 1.3, optional mTLS).
# Secrets (CA bundle, client cert/key) are encrypted at rest via PlatformSetting.

class SyslogConfigIn(BaseModel):
    enabled:     Optional[bool] = None
    host:        Optional[str]  = None
    port:        Optional[int]  = None
    protocol:    Optional[str]  = None    # udp | tcp | tls
    facility:    Optional[int]  = None    # 0–23 (RFC 5424 §6.2.1)
    app_name:    Optional[str]  = None
    scope:       Optional[str]  = None    # audit_only | all
    verify_tls:  Optional[bool] = None
    # PEM blobs — empty string clears, omitted leaves unchanged.
    ca_bundle:   Optional[str]  = None
    client_cert: Optional[str]  = None
    client_key:  Optional[str]  = None


class SyslogConfigOut(BaseModel):
    enabled:      bool
    host:         str
    port:         int
    protocol:     str
    facility:     int
    app_name:     str
    scope:        str
    verify_tls:   bool
    ca_bundle_set:   bool
    client_cert_set: bool
    client_key_set:  bool
    # Runtime status (best-effort, in-memory)
    connected:        bool
    sent_count:       int
    dropped_count:    int
    last_error:       Optional[str] = None
    last_success_at:  Optional[str] = None


@router.get("/syslog", response_model=SyslogConfigOut, summary="Get syslog forwarding config")
async def get_syslog_config(
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Get the RFC 5424 syslog forwarding configuration plus best-effort
    runtime status (connected, sent/dropped counts, last error/success). TLS
    secrets are reported only as `*_set` booleans. Admin access required."""
    from syslog_forwarder.service import load_config, forwarder
    cfg = await load_config(db)
    return SyslogConfigOut(
        enabled=cfg.enabled, host=cfg.host, port=cfg.port,
        protocol=cfg.protocol, facility=cfg.facility,
        app_name=cfg.app_name, scope=cfg.scope, verify_tls=cfg.verify_tls,
        ca_bundle_set   = bool(cfg.ca_bundle_pem),
        client_cert_set = bool(cfg.client_cert_pem),
        client_key_set  = bool(cfg.client_key_pem),
        connected     = forwarder.connected,
        sent_count    = forwarder.sent_count,
        dropped_count = forwarder.dropped_count,
        last_error    = forwarder.last_error,
        last_success_at = forwarder.last_success_at.isoformat() if forwarder.last_success_at else None,
    )


_SYSLOG_PROTOCOLS = {"udp", "tcp", "tls"}
_SYSLOG_SCOPES    = {"audit_only", "all"}


@router.put("/syslog", status_code=204, summary="Save syslog forwarding config")
async def save_syslog_config(
    body: SyslogConfigIn,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Save the syslog forwarding configuration and trigger an in-process
    reload so changes take effect immediately. Only supplied fields change;
    PEM blobs (CA/client cert/key) clear when empty and are left when omitted.
    Validates protocol, scope, facility and port (400 on bad values). Secrets
    encrypted at rest. Admin access required. Returns 204 No Content."""
    if body.protocol is not None and body.protocol not in _SYSLOG_PROTOCOLS:
        raise HTTPException(400, f"protocol must be one of {sorted(_SYSLOG_PROTOCOLS)}")
    if body.scope is not None and body.scope not in _SYSLOG_SCOPES:
        raise HTTPException(400, f"scope must be one of {sorted(_SYSLOG_SCOPES)}")
    if body.facility is not None and not (0 <= body.facility <= 23):
        raise HTTPException(400, "facility must be 0–23 (RFC 5424 §6.2.1)")
    if body.port is not None and not (1 <= body.port <= 65535):
        raise HTTPException(400, "port must be 1–65535")
    if body.host is not None and not body.host.strip() and body.enabled:
        raise HTTPException(400, "host is required when enabled")

    uid = user.id
    if body.enabled    is not None: await _set(db, "syslog.enabled",    "true" if body.enabled else "false", uid)
    if body.host       is not None: await _set(db, "syslog.host",        body.host.strip(),          uid)
    if body.port       is not None: await _set(db, "syslog.port",        str(body.port),             uid)
    if body.protocol   is not None: await _set(db, "syslog.protocol",    body.protocol,              uid)
    if body.facility   is not None: await _set(db, "syslog.facility",    str(body.facility),         uid)
    if body.app_name   is not None: await _set(db, "syslog.app_name",    body.app_name.strip() or "dfir-fenrir", uid)
    if body.scope      is not None: await _set(db, "syslog.scope",       body.scope,                 uid)
    if body.verify_tls is not None: await _set(db, "syslog.verify_tls", "true" if body.verify_tls else "false", uid)
    # PEM blobs — empty string deletes, presence updates, omission leaves it.
    for field, key in (("ca_bundle", "syslog.ca_bundle"),
                       ("client_cert", "syslog.client_cert"),
                       ("client_key", "syslog.client_key")):
        val = getattr(body, field)
        if val is None: continue
        if val.strip(): await _set(db, key, val, uid)
        else:           await _del(db, key)
    await db.commit()

    # Trigger an in-process reload so the new settings take effect immediately.
    from syslog_forwarder.service import forwarder
    await forwarder.reload(db)


@router.post("/syslog/test", summary="Send a test syslog message")
async def test_syslog(
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Send a test message to the configured syslog target using the current
    settings. Returns 400 with the failure reason if delivery fails. Admin
    access required. Returns `{ok, message}` on success."""
    from syslog_forwarder.service import forwarder
    ok, msg = await forwarder.send_test(db)
    if not ok:
        raise HTTPException(400, msg)
    return {"ok": True, "message": msg}
