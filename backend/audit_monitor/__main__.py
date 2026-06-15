"""One-shot anchor tick for the audit-monitor sidecar: `python -m audit_monitor`.

The sidecar loops this on `ANCHOR_INTERVAL`. A detected tamper is recorded + logged at
ERROR but still exits 0 — the tick itself succeeded; we don't crash-loop the sidecar over
a (persisted, surfaced) finding. Only an unexpected error exits non-zero.
"""
from __future__ import annotations

import asyncio
import logging
import sys

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("fenrir.audit_monitor")


async def _ensure_schema() -> None:
    """Idempotently ensure our table exists — robust to a cold-boot race with the
    backend's create_all. Owner-level CREATE ... IF NOT EXISTS; a concurrent create just
    no-ops here."""
    from core.database import engine
    from models import AuditAnchor
    try:
        async with engine.begin() as conn:
            await conn.run_sync(lambda c: AuditAnchor.__table__.create(c, checkfirst=True))
    except Exception as e:  # noqa: BLE001 — already exists / raced create is fine
        log.info("audit_monitor: schema ensure skipped (%s)", e)


async def _main() -> None:
    from audit_monitor.anchor import run_anchor
    from core.database import SessionLocal
    await _ensure_schema()
    async with SessionLocal() as db:
        await run_anchor(db)
        await db.commit()


if __name__ == "__main__":
    try:
        asyncio.run(_main())
        sys.exit(0)
    except Exception as e:  # noqa: BLE001 — surface + non-zero so the loop's `|| true` logs it
        log.error("audit_monitor tick failed: %s", e)
        sys.exit(1)
