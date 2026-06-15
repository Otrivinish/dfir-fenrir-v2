"""GS-8 — chain-head anchoring + segment verification.

`run_anchor` certifies the audit chain head: it verifies the segment since the previous
anchor links cleanly (per-row hash + prev_hash linkage), checks `row_count` hasn't
dropped (deletion), RFC-3161 timestamps the head hash (best-effort), and records an
`AuditAnchor` row. Each anchor links back to the prior anchored head, so the chain of
anchors covers the whole log. The anchor table is separate from `audit_logs`, so this
never perturbs or recurses into the chain it certifies.
"""
from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy import func, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import GENESIS_HASH, verify_row_hash
from evidence.timestamping import timestamp_sha256
from models import AuditAnchor, AuditLog

log = logging.getLogger("fenrir.audit_monitor")


async def _latest_anchor(db: AsyncSession) -> Optional[AuditAnchor]:
    return (await db.execute(
        select(AuditAnchor).order_by(AuditAnchor.anchored_at.desc(), AuditAnchor.id.desc()).limit(1)
    )).scalars().first()


async def _head(db: AsyncSession) -> Optional[AuditLog]:
    return (await db.execute(
        select(AuditLog).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).limit(1)
    )).scalars().first()


def _verify_walk(rows, expected_first_prev: str) -> tuple[bool, Optional[str]]:
    """Walk rows in chain order; check each row_hash + prev_hash linkage.

    `expected_first_prev` is what rows[0].prev_hash must equal — GENESIS for the
    first-ever anchor, or the prior anchor's head hash for an incremental one. An empty
    `rows` (no new rows since the last anchor) is a clean pass.
    """
    prev = expected_first_prev
    for row in rows:
        if row.prev_hash != prev:
            return False, (f"row {row.id}: prev_hash linkage broken "
                           f"(expected {prev[:12]}…, got {(row.prev_hash or '')[:12]}…)")
        if not verify_row_hash(row):
            return False, f"row {row.id}: row_hash mismatch — content altered after write"
        prev = row.row_hash
    return True, None


async def run_anchor(db: AsyncSession) -> Optional[AuditAnchor]:
    """Verify + anchor the current chain head. Returns the new AuditAnchor (or None if
    the log is empty). Caller commits."""
    total = (await db.execute(select(func.count()).select_from(AuditLog))).scalar_one()
    head = await _head(db)
    if head is None:
        log.info("audit_monitor: empty audit log — nothing to anchor")
        return None

    prev_anchor = await _latest_anchor(db)

    if (prev_anchor is None or not prev_anchor.head_row_hash
            or prev_anchor.head_row_hash == GENESIS_HASH
            or prev_anchor.head_row_id is None):
        # First-ever anchor: verify the whole chain from genesis.
        seg_stmt = select(AuditLog).order_by(AuditLog.timestamp.asc(), AuditLog.id.asc())
        expected_first_prev = GENESIS_HASH
        baseline_count = 0
    else:
        # Incremental: rows strictly after the previously-anchored head, in chain order.
        seg_stmt = (
            select(AuditLog)
            .where(tuple_(AuditLog.timestamp, AuditLog.id)
                   > tuple_(prev_anchor.head_row_ts, prev_anchor.head_row_id))
            .order_by(AuditLog.timestamp.asc(), AuditLog.id.asc())
        )
        expected_first_prev = prev_anchor.head_row_hash
        baseline_count = prev_anchor.row_count

    rows = (await db.execute(seg_stmt)).scalars().all()
    ok, detail = _verify_walk(rows, expected_first_prev)

    # Deletion check: total must not have dropped below what we already certified.
    if total < baseline_count:
        ok = False
        detail = ((detail + "; ") if detail else "") + \
            f"row_count dropped {baseline_count}→{total} (rows deleted below anchor point)"

    # Best-effort external time anchor over the head hash (GS-4 helper; None if no TSA).
    tst = await timestamp_sha256(head.row_hash)

    anchor = AuditAnchor(
        head_row_id=head.id,
        head_row_ts=head.timestamp,
        head_row_hash=head.row_hash,
        row_count=total,
        verify_ok=ok,
        verify_detail=detail,
        tst=(tst or {}).get("tst_b64"),
        tst_time=(tst or {}).get("time"),
        tsa=(tst or {}).get("tsa"),
    )
    db.add(anchor)
    await db.flush()

    if ok:
        log.info("audit_monitor: anchored head %s… (%d rows, +%d this tick)%s",
                 head.row_hash[:12], total, len(rows), " [TSA]" if tst else " [no TSA]")
    else:
        log.error("AUDIT CHAIN TAMPER DETECTED at anchor %s: %s", anchor.id, detail)
    return anchor
