"""Tamper-evident audit log writer.

Each row's row_hash = sha256(prev_hash || canonical_json(payload)).
Concurrent inserts serialise on a Postgres advisory lock so prev_hash is
always the immediately preceding row's row_hash.

Hash versioning:
  v1 — original payload (timestamp, user_id, username, action, resource_type,
       resource_id, details, ip_address). Existing rows retain `hash_version=v1`.
  v2 — adds outcome, session_id, role_at_time, resource_label, request_method,
       request_path, request_id. New rows write `hash_version=v2`.

The verifier picks the canonicalisation by the row's `hash_version` column.
"""
import hashlib
import json
import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from audit.context import get_audit_context
from models import AuditLog

# Single int key for pg_advisory_xact_lock — chosen arbitrarily, must be stable.
_LOCK_KEY = 168000917  # 0xA001D17 → "A0 audit"

GENESIS_HASH = "0" * 64
HASH_VERSION_CURRENT = "v2"


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _row_hash(prev: str, payload: dict) -> str:
    return hashlib.sha256(prev.encode("ascii") + _canonical(payload)).hexdigest()


def _payload_v1(*, timestamp: datetime, user_id, username, action,
                resource_type, resource_id, details, ip_address) -> dict:
    return {
        "timestamp":     timestamp.isoformat(),
        "user_id":       str(user_id) if user_id else None,
        "username":      username,
        "action":        action,
        "resource_type": resource_type,
        "resource_id":   resource_id,
        "details":       details or {},
        "ip_address":    ip_address,
    }


def _payload_v2(*, timestamp: datetime, user_id, username, role_at_time,
                session_id, action, outcome, resource_type, resource_id,
                resource_label, ip_address, request_method, request_path,
                request_id, details) -> dict:
    return {
        "v":               "v2",
        "timestamp":       timestamp.isoformat(),
        "user_id":         str(user_id) if user_id else None,
        "username":        username,
        "role_at_time":    role_at_time,
        "session_id":      str(session_id) if session_id else None,
        "action":          action,
        "outcome":         outcome,
        "resource_type":   resource_type,
        "resource_id":     resource_id,
        "resource_label":  resource_label,
        "ip_address":      ip_address,
        "request_method":  request_method,
        "request_path":    request_path,
        "request_id":      request_id,
        "details":         details or {},
    }


async def write_audit(
    db: AsyncSession,
    action: str,
    *,
    # actor / target — caller supplies these explicitly (or relies on ctx fallback)
    user_id:      Optional[uuid.UUID] = None,
    username:     Optional[str]       = None,
    role_at_time: Optional[str]       = None,
    session_id:   Optional[uuid.UUID] = None,
    outcome:      Optional[str]       = None,   # success | failure | denied
    resource_type:  Optional[str]     = None,
    resource_id:    Optional[str]     = None,
    resource_label: Optional[str]     = None,
    details:        Optional[dict[str, Any]] = None,
    # request-context — defaults read from the audit ContextVar (audit middleware).
    ip_address:     Optional[str] = None,
    user_agent:     Optional[str] = None,
    request_id:     Optional[str] = None,
    request_method: Optional[str] = None,
    request_path:   Optional[str] = None,
) -> AuditLog:
    """Append one audit row, transactionally chained to the previous row."""
    ctx = get_audit_context()
    # Fall through to context for anything the caller didn't override.
    user_id        = user_id        if user_id        is not None else ctx.get("user_id")
    username       = username       if username       is not None else ctx.get("username")
    role_at_time   = role_at_time   if role_at_time   is not None else ctx.get("role_at_time")
    session_id     = session_id     if session_id     is not None else ctx.get("session_id")
    ip_address     = ip_address     if ip_address     is not None else ctx.get("ip_address")
    request_id     = request_id     if request_id     is not None else ctx.get("request_id")
    request_method = request_method if request_method is not None else ctx.get("request_method")
    request_path   = request_path   if request_path   is not None else ctx.get("request_path")

    # Serialise within the current transaction (audit chain integrity).
    await db.execute(text("SELECT pg_advisory_xact_lock(:k)").bindparams(k=_LOCK_KEY))

    # Fetch the most recent row_hash (within the same tx).
    prev_q = await db.execute(
        select(AuditLog.row_hash).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).limit(1)
    )
    prev_hash = prev_q.scalar_one_or_none() or GENESIS_HASH

    # Naive: audit_log.timestamp is a TIMESTAMP WITHOUT TIME ZONE column
    # (see models.py). Don't convert to tz-aware here without also migrating
    # the column — asyncpg will reject the bind otherwise. The hash chain
    # serialises this value, so changing its shape is also a chain break.
    now = datetime.utcnow()
    payload = _payload_v2(
        timestamp=now,
        user_id=user_id, username=username, role_at_time=role_at_time,
        session_id=session_id, action=action, outcome=outcome,
        resource_type=resource_type, resource_id=resource_id, resource_label=resource_label,
        ip_address=ip_address,
        request_method=request_method, request_path=request_path, request_id=request_id,
        details=details,
    )
    row_hash = _row_hash(prev_hash, payload)

    row = AuditLog(
        id=uuid.uuid4(),
        timestamp=now,
        user_id=user_id,
        username=username,
        role_at_time=role_at_time,
        session_id=session_id,
        action=action,
        outcome=outcome,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_label=resource_label,
        details=details or {},
        ip_address=ip_address,
        user_agent=user_agent,
        request_method=request_method,
        request_path=request_path,
        request_id=request_id,
        hash_version=HASH_VERSION_CURRENT,
        row_hash=row_hash,
        prev_hash=prev_hash,
    )
    db.add(row)
    await db.flush()  # caller commits

    # Best-effort fan-out to the external syslog forwarder (no-op if disabled).
    # Both 'audit_only' and 'all' scopes include audit rows. Local import keeps
    # the audit module free of a hard dependency on the forwarder package.
    try:
        from syslog_forwarder import forward_audit_row
        forward_audit_row(
            action=action, username=username, resource_type=resource_type,
            resource_id=resource_id, outcome=outcome, ip_address=ip_address,
            timestamp=now,
        )
    except Exception:  # noqa: BLE001 — never let forwarding break audit writes
        pass

    return row


def verify_row_hash(row: AuditLog) -> bool:
    """Recompute the row_hash of a stored row and compare. Tamper detector."""
    version = (row.hash_version or "v1")
    if version == "v1":
        payload = _payload_v1(
            timestamp=row.timestamp, user_id=row.user_id, username=row.username,
            action=row.action, resource_type=row.resource_type,
            resource_id=row.resource_id, details=row.details, ip_address=row.ip_address,
        )
    elif version == "v2":
        payload = _payload_v2(
            timestamp=row.timestamp, user_id=row.user_id, username=row.username,
            role_at_time=row.role_at_time, session_id=row.session_id,
            action=row.action, outcome=row.outcome,
            resource_type=row.resource_type, resource_id=row.resource_id,
            resource_label=row.resource_label, ip_address=row.ip_address,
            request_method=row.request_method, request_path=row.request_path,
            request_id=row.request_id, details=row.details,
        )
    else:
        return False
    return _row_hash(row.prev_hash, payload) == row.row_hash
