"""Mirror grace-period purge receipts → custody log (owner decision 2026-10-04, G-fix).

The backup container owns the evidence mirror (root-owned 0444 copies); the backend owns the audit
chain. backup.sh deletes the mirror copies of exhibits destroyed more than MIRROR_PURGE_GRACE_DAYS
ago and writes a receipt to /backups/mirror-purge-receipts/:

    FENRIR-MIRROR-PURGE-RECEIPT v1
    receipt_id <uuid>
    purged_at <YYYY-MM-DDTHH:MM:SSZ>
    grace_days <n>
    item <evidence uuid> <destroyed_at Z> <files> <bytes>
    ...

This module records each item as an `evidence_mirror_purged` row in that exhibit's custody log
(request_id = the receipt id, so a receipt is recorded once however often it is read). Zero trust:
a receipt counts only when it is a regular file owned by root and writable by nobody else — the
backend itself (uid 1001) can create files in /backups but never root-owned ones — and only for an
exhibit of this platform that is destroyed. Anything else is logged and skipped, never recorded.
Runs at startup and every INGEST_EVERY_SECONDS.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import stat
import uuid
from pathlib import Path
from typing import Optional

from sqlalchemy import select

from audit.service import write_audit
from core.config import settings
from core.database import SessionLocal
from models import AuditLog, Evidence

log = logging.getLogger("fenrir.backup.mirror_receipts")

ACTION = "evidence_mirror_purged"
INGEST_EVERY_SECONDS = 900
_MAX_RECEIPT_BYTES = 1024 * 1024
_TS = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_HEAD = re.compile(rf"FENRIR-MIRROR-PURGE-RECEIPT v1\nreceipt_id ({_UUID})\npurged_at ({_TS})\ngrace_days (\d+)\n")
_ITEM = re.compile(rf"item ({_UUID}) ({_TS}) (\d+) (\d+)")


def receipt_dir() -> Path:
    return Path(settings.backup_path) / "mirror-purge-receipts"


def parse_receipt(data: str) -> Optional[dict]:
    """The receipt's fields, or None when it is not exactly the v1 format."""
    m = _HEAD.match(data)
    if not m:
        return None
    items = []
    for line in data[m.end():].splitlines():
        im = _ITEM.fullmatch(line)
        if not im:
            return None
        items.append({"evidence_id": im.group(1), "destroyed_at": im.group(2),
                      "files": int(im.group(3)), "bytes": int(im.group(4))})
    if not items:
        return None
    return {"receipt_id": m.group(1), "purged_at": m.group(2), "grace_days": int(m.group(3)), "items": items}


def _read_trusted(path: Path) -> Optional[str]:
    """The receipt's text when it is a regular file owned by root (uid 0), writable by its owner only,
    and small; None otherwise (not opened through a symlink)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022 or st.st_size > _MAX_RECEIPT_BYTES:
            return None
        return os.read(fd, _MAX_RECEIPT_BYTES).decode("ascii")
    except (OSError, UnicodeDecodeError):
        return None
    finally:
        os.close(fd)


async def ingest_receipts(db) -> int:
    """Record every new receipt; returns the number of custody rows written. Commits per receipt."""
    d = receipt_dir()
    try:
        names = sorted(n for n in os.listdir(d) if n.endswith(".receipt"))
    except FileNotFoundError:
        return 0
    written = 0
    for name in names:
        text = _read_trusted(d / name)
        rec = parse_receipt(text) if text is not None else None
        if rec is None:
            log.warning("mirror purge receipt %s ignored: not a root-owned, read-only v1 receipt", name)
            continue
        done = (await db.execute(select(AuditLog.id).where(
            AuditLog.request_id == rec["receipt_id"], AuditLog.action == ACTION).limit(1))).first()
        if done:
            continue
        for idx, item in enumerate(rec["items"], start=1):
            ev = (await db.execute(select(Evidence.id, Evidence.incident_id, Evidence.status, Evidence.identifier)
                                   .where(Evidence.id == uuid.UUID(item["evidence_id"])))).first()
            if ev is None or ev.status != "destroyed":
                # Log the item's position, not the receipt-supplied value (it stays in the receipt file).
                log.warning("mirror purge receipt %s: item %d is not a destroyed exhibit here; not recorded",
                            name, idx)
                continue
            await write_audit(
                db, ACTION, username="backup:mirror-purge", role_at_time="backup-sidecar", outcome="success",
                resource_type="evidence", resource_id=str(ev.id), resource_label=ev.identifier,
                details={"incident_id": str(ev.incident_id), "receipt_id": rec["receipt_id"], "receipt": name,
                         "purged_at": rec["purged_at"], "destroyed_at": item["destroyed_at"],
                         "grace_days": rec["grace_days"], "mirror_files_deleted": item["files"],
                         "bytes": item["bytes"],
                         "note": "backup mirror copies of the destroyed exhibit purged after the grace period"},
                request_id=rec["receipt_id"], request_method="BACKUP", request_path="backup.sh mirror grace purge")
            written += 1
        await db.commit()
    return written


_task: Optional[asyncio.Task] = None


async def _loop() -> None:
    while True:
        try:
            async with SessionLocal() as db:
                n = await ingest_receipts(db)
            if n:
                log.info("recorded %d evidence_mirror_purged custody row(s)", n)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("mirror purge receipts could not be recorded; retrying in %d s", INGEST_EVERY_SECONDS)
        await asyncio.sleep(INGEST_EVERY_SECONDS)


def start() -> None:
    global _task
    _task = asyncio.create_task(_loop(), name="mirror-purge-receipts")


async def stop() -> None:
    if _task is not None:
        _task.cancel()
        try:
            await _task
        except asyncio.CancelledError:
            pass
