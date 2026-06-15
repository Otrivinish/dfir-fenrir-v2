"""Email delivery — SMTP/STARTTLS or Microsoft Graph (M365 OAuth).

Mode controlled by `smtp.mode` PlatformSetting:
  "smtp"  — standard SMTP with STARTTLS
  "graph" — Microsoft Graph API (client credentials, no app password)
  absent  — email disabled; returns False silently
"""
import asyncio
import logging
import smtplib
from email.mime.text import MIMEText
from typing import Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.security import decrypt_secret
from models import PlatformSetting

log = logging.getLogger(__name__)


async def _get(db: AsyncSession, key: str) -> Optional[str]:
    row = (await db.execute(
        select(PlatformSetting).where(PlatformSetting.key == key)
    )).scalar_one_or_none()
    if row is None:
        return None
    try:
        return decrypt_secret(row.encrypted_value)
    except Exception:
        return None


async def _send_smtp(db: AsyncSession, to: str, subject: str, body: str) -> bool:
    host      = await _get(db, "smtp.host") or ""
    port_str  = await _get(db, "smtp.port")
    username  = await _get(db, "smtp.username") or ""
    password  = await _get(db, "smtp.password") or ""
    from_addr = await _get(db, "smtp.from_address") or username

    if not host:
        log.warning("SMTP host not configured")
        return False

    port = 587
    try:
        port = int(port_str) if port_str else 587
    except ValueError:
        pass

    msg = MIMEText(body, "plain", "utf-8")
    # Strip CR/LF from header values — `subject` can carry a SIEM-supplied
    # incident title, an attacker-controlled string. Newlines there are a
    # classic header-injection vector.
    msg["Subject"] = subject.replace("\r", " ").replace("\n", " ")
    msg["From"]    = from_addr
    msg["To"]      = to

    def _blocking():
        with smtplib.SMTP(host, port, timeout=15) as s:
            s.ehlo()
            s.starttls()
            if username:
                s.login(username, password)
            s.send_message(msg)

    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _blocking)
        return True
    except Exception as exc:
        log.warning("SMTP send failed: %s", exc)
        return False


async def _graph_token(tenant: str, client_id: str, secret: str) -> Optional[str]:
    url  = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": secret,
        "scope": "https://graph.microsoft.com/.default",
    }
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(url, data=data)
            if r.status_code != 200:
                log.warning("Graph token error %s: %s", r.status_code, r.text[:200])
                return None
            return r.json().get("access_token")
    except Exception as exc:
        log.warning("Graph token request failed: %s", exc)
        return None


async def _send_graph(db: AsyncSession, to: str, subject: str, body: str) -> bool:
    tenant  = await _get(db, "graph.tenant_id") or ""
    cid     = await _get(db, "graph.client_id") or ""
    secret  = await _get(db, "graph.client_secret") or ""
    sender  = await _get(db, "graph.sender") or ""

    if not all([tenant, cid, secret, sender]):
        log.warning("Microsoft Graph email: incomplete configuration")
        return False

    token = await _graph_token(tenant, cid, secret)
    if not token:
        return False

    payload = {
        "message": {
            "subject": subject,
            "body": {"contentType": "Text", "content": body},
            "toRecipients": [{"emailAddress": {"address": to}}],
        }
    }
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(
                f"https://graph.microsoft.com/v1.0/users/{sender}/sendMail",
                json=payload,
                headers={"Authorization": f"Bearer {token}"},
            )
            if r.status_code not in (200, 202):
                log.warning("Graph sendMail error %s: %s", r.status_code, r.text[:200])
                return False
            return True
    except Exception as exc:
        log.warning("Graph sendMail failed: %s", exc)
        return False


async def send_admin_alert(db: AsyncSession, subject: str, body: str) -> bool:
    """Send alert to admin_email. Returns True on success, False if disabled or failed."""
    mode = await _get(db, "smtp.mode")
    if not mode:
        return False
    admin_email = await _get(db, "smtp.admin_email")
    if not admin_email:
        return False
    try:
        if mode == "smtp":
            return await _send_smtp(db, admin_email, subject, body)
        if mode == "graph":
            return await _send_graph(db, admin_email, subject, body)
    except Exception as exc:
        log.exception("send_admin_alert failed: %s", exc)
    return False
