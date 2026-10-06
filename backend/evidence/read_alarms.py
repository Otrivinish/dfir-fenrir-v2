"""G1 stage 3a: make stored-file read problems loud (docs/streaming-aes-gcm-format.md §4.2).

evidence/crypto.py reports two events through its read-alarm sink, from whichever worker thread
did the read:

  read_failed      a file could not be read (missing, I/O error, wrong or missing KEK, bad
                   path). Never an integrity failure, so nothing is frozen; it must still be
                   seen. → audit `evidence_read_failed` (evidence store) or `file_read_failed`
                   (entity / incident Files store), outcome failure, + an in-app notification
                   to every active admin.
  kek_id_mismatch  a v2 file opened, but its advisory kek_id names another KEK (F-10). Once per
                   file per process. → audit `evidence_kek_id_mismatch` / `file_kek_id_mismatch`.

The audit row is written in its own session by a task on the event loop, after the read: a
failing request must not lose it, and the request's own transaction may hold the audit-chain
lock, so it is never awaited inline.

R90 / ROT-L7 (G-fix): one alarm per (event, store, path, reason) per DEDUP_WINDOW (15 min) — both
the audit row and the admin notification; repeats inside the window are counted and the next row
says how many were suppressed (`suppressed_repeats`). Pool-safe: at most MAX_CONCURRENT recordings
use a DB session at once and at most MAX_PENDING wait; beyond that an alarm is logged and dropped
(a wrong KEK can make every read fail at once). The actor and request fields come from the reading
request's audit context (asyncio.to_thread copies it into the worker thread). The row names the
resource when the path matches one (evidence.storage_path, an evidence photo, or
entity_files.file_path) and carries the store, path, format and reason class — never key
material.
"""
import asyncio
import logging
import threading
import time
import uuid
from typing import Callable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.context import get_audit_context
from audit.service import write_audit
from core.database import SessionLocal
from evidence import crypto
from models import Artifact, EntityFile, Evidence, Incident
from notifications.service import notify_stored_file_unreadable

log = logging.getLogger("fenrir.evidence.read_alarms")
_tasks: set[asyncio.Task] = set()

DEDUP_WINDOW_SECONDS = 15 * 60
MAX_CONCURRENT = 2                 # DB sessions the alarm recorder may use at once
MAX_PENDING = 50                   # alarms waiting to be recorded; beyond that they are logged and dropped
_seen: dict[tuple, float] = {}     # key → monotonic time of the last recorded alarm
_suppressed: dict[tuple, int] = {}
_seen_lock = threading.Lock()
_sem: asyncio.Semaphore | None = None


def admit(event: dict, now: float | None = None) -> tuple[bool, int]:
    """(record it?, repeats suppressed since the last recorded one) for this alarm — R90 de-duplication.
    Thread-safe: called from the reading thread."""
    key = (event.get("event"), event.get("store"), event.get("relative_path"), event.get("reason"))
    now = time.monotonic() if now is None else now
    with _seen_lock:
        last = _seen.get(key)
        if last is not None and now - last < DEDUP_WINDOW_SECONDS:
            _suppressed[key] = _suppressed.get(key, 0) + 1
            return False, 0
        _seen[key] = now
        if len(_seen) > 10_000:                                    # bounded memory
            for k in [k for k, t in _seen.items() if now - t >= DEDUP_WINDOW_SECONDS]:
                _seen.pop(k, None)
        return True, _suppressed.pop(key, 0)


def install(loop: asyncio.AbstractEventLoop | None = None) -> None:
    """Route crypto's read alarms to record() on `loop` (the running loop by default)."""
    global _sem
    loop = loop or asyncio.get_running_loop()
    _sem = asyncio.Semaphore(MAX_CONCURRENT)

    def sink(event: dict) -> None:
        ok, repeats = admit(event)
        if not ok:
            return
        ctx = dict(get_audit_context())
        loop.call_soon_threadsafe(_spawn, {**event, "suppressed_repeats": repeats}, ctx)
    crypto.set_read_alarm_sink(sink)


def _spawn(event: dict, ctx: dict) -> None:
    if len(_tasks) >= MAX_PENDING:
        log.error("read-alarm backlog full (%d pending): alarm not recorded: %s", len(_tasks), event)
        return
    task = asyncio.get_running_loop().create_task(record(event, ctx))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


async def record(event: dict, ctx: dict, session_factory: Callable = SessionLocal) -> None:
    try:
        if _sem is None:
            async with session_factory() as db:
                await record_in(db, event, ctx)
            return
        async with _sem:                                          # pool-safe (R90 / ROT-L7)
            async with session_factory() as db:
                await record_in(db, event, ctx)
    except Exception:
        log.exception("could not record the stored-file read alarm %s", event)


async def _resource(db: AsyncSession, store: str, path: str) -> tuple[str, uuid.UUID | None, uuid.UUID | None]:
    """(resource_type, resource_id, incident_id) of the row that owns `path`, ids None if none does."""
    if store == "evidence":
        row = (await db.execute(select(Evidence.id, Evidence.incident_id)
                                .where(Evidence.storage_path == path).limit(1))).first()
        parts = path.split("/")
        if row is None and len(parts) == 3 and parts[0] == "photos":
            try:
                eid = uuid.UUID(parts[1])
            except ValueError:
                eid = None
            if eid is not None:
                row = (await db.execute(select(Evidence.id, Evidence.incident_id).where(Evidence.id == eid))).first()
        return ("evidence", *(row or (None, None)))
    if store == "quarantine":                                       # H1: "<incident id>/<stored name>"
        inc, _, name = path.partition("/")
        try:
            inc_id = uuid.UUID(inc)
        except ValueError:
            return ("artifact", None, None)
        row = (await db.execute(select(Artifact.id, Artifact.incident_id).where(
            Artifact.incident_id == inc_id, Artifact.stored_filename == name).limit(1))).first()
        return ("artifact", *(row or (None, None)))
    row = (await db.execute(select(EntityFile.id, EntityFile.incident_id)
                            .where(EntityFile.file_path == path).limit(1))).first()
    kind = "entity_file" if path.startswith("entity-files/") else "incident_file"
    return (kind, *(row or (None, None)))


async def record_in(db: AsyncSession, event: dict, ctx: dict) -> None:
    """Write the audit row (and, for read_failed, notify admins) in `db`, then commit."""
    store, path, reason = event["store"], event["relative_path"], event["reason"]
    failed = event["event"] == "read_failed"
    rtype, rid, incident_id = await _resource(db, store, path)
    prefix = {"evidence": "evidence", "quarantine": "artifact"}.get(store, "file")
    await write_audit(
        db, f"{prefix}_read_failed" if failed else f"{prefix}_kek_id_mismatch",
        user_id=ctx.get("user_id"), username=ctx.get("username"), role_at_time=ctx.get("role_at_time"),
        session_id=ctx.get("session_id"), ip_address=ctx.get("ip_address"), request_id=ctx.get("request_id"),
        request_method=ctx.get("request_method"), request_path=ctx.get("request_path"),
        resource_type=rtype, resource_id=str(rid) if rid else None,
        outcome="failure" if failed else "success",
        details={"incident_id": str(incident_id) if incident_id else None, "store": store, "path": path,
                 "format": event.get("format"), "reason": reason, "frozen": False,
                 "suppressed_repeats": event.get("suppressed_repeats", 0),
                 "dedup_window_minutes": DEDUP_WINDOW_SECONDS // 60},
    )
    if not failed:
        await db.commit()
        return
    ref = None
    if incident_id is not None:
        ref = (await db.execute(select(Incident.ref).where(Incident.id == incident_id))).scalar_one_or_none()
    await notify_stored_file_unreadable(db, incident_id, ref,
                                        {"evidence": "An evidence file", "quarantine": "A quarantine artifact"}
                                        .get(store, "A stored file"), reason)
