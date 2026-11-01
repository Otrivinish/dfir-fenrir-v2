"""S6 (EG-4, HLD §3.5): container exhibits — the background manifest builder, and the rules the routes share.

One worker task, one build at a time (process-wide queue + lock). A build reads the exhibit's stored file in worker
threads (evidence/manifest_index.py: decryption, decompression, hashing never run on the event loop) and inserts the
entries in batches inside ONE transaction, committed together with manifest_status = built only when the whole
container was read without an error (F-12). Anything else rolls the entries back and records manifest_status =
failed with the reason: a cap, a container FENRIR can't parse, a v0 (legacy) file, a file that can't be read, or one
that fails authentication (then the exhibit is also frozen, as every other reader does). The exhibit itself is never
refused.

Restart: a row left `pending` is queued again at startup (start()); POST …/manifest/rebuild queues a failed or pending
one. A built manifest is never rebuilt: its rows are append-only.
"""
from __future__ import annotations

import asyncio
import itertools
import logging
import types
import uuid
from typing import AsyncIterator, Optional

from fastapi import status
from sqlalchemy import insert, select

from audit.service import write_audit
from core.config import settings
from core.database import SessionLocal
from core.errors import ApiError
from evidence import crypto, seekable
from evidence.crypto import EvidenceCryptoError, EvidenceIntegrityError
from evidence.manifest_index import ENTRY_FIELDS, INDEXED_FORMATS, Caps, IndexFailed, ManifestBuild
from evidence.working_copies import freeze_for_integrity
from models import Evidence, EvidenceManifestEntry

log = logging.getLogger("fenrir.evidence.manifest")

INSERT_BATCH = 1_000
READ_BATCH = 2_000
session_factory = SessionLocal          # the DB-rollback harness points this at its own transaction


def caps() -> Caps:
    return Caps(max_entries=settings.evidence_manifest_max_entries,
                max_uncompressed_bytes=settings.evidence_manifest_max_uncompressed_bytes,
                max_path_chars=settings.evidence_manifest_max_path_chars)


def initial_status(container_format: Optional[str]) -> Optional[str]:
    if container_format is None:
        return None
    return "pending" if container_format in INDEXED_FORMATS else "not_indexed"


def format_change(ev: Evidence, container_format: Optional[str]) -> dict:
    """The columns a new container_format sets on an unsealed exhibit ({} when unchanged). 422
    container_format_not_applicable (physical item), 409 manifest_built (the built manifest fixes the format)."""
    if container_format is not None and ev.kind != "digital_file":
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "container_format_not_applicable",
                       "Only a digital exhibit (a stored file) can be a container")
    if container_format == ev.container_format:
        return {}
    if ev.manifest_status == "built":
        raise ApiError(status.HTTP_409_CONFLICT, "manifest_built",
                       f"The manifest of this {ev.container_format} container is built: its format can't change")
    return {"container_format": container_format, "manifest_status": initial_status(container_format),
            "manifest_error": None}


# ── reading a built manifest (API, CSV, disclosure package) ─────────────────────────────────────────────────────

def entry_dict(row: EvidenceManifestEntry) -> dict:
    return {f: getattr(row, f) for f in ENTRY_FIELDS}


async def entry_batches(db, evidence_id: uuid.UUID, *conditions, batch: int = READ_BATCH) -> AsyncIterator[list[dict]]:
    """Every entry of the exhibit's manifest (optionally filtered), in seq order, `batch` at a time (keyset)."""
    after = 0
    while True:
        rows = (await db.execute(
            select(EvidenceManifestEntry)
            .where(EvidenceManifestEntry.evidence_id == evidence_id, EvidenceManifestEntry.seq > after, *conditions)
            .order_by(EvidenceManifestEntry.seq).limit(batch)
        )).scalars().all()
        if not rows:
            return
        after = rows[-1].seq
        yield [entry_dict(r) for r in rows]


# ── the queue ───────────────────────────────────────────────────────────────────────────────────────────────────

_queue: Optional[asyncio.Queue] = None
_worker: Optional[asyncio.Task] = None
_queued: set[uuid.UUID] = set()
_build_lock = asyncio.Lock()


def enqueue(evidence_id: uuid.UUID, requested_by: Optional[tuple] = None) -> None:
    """Queue a build (after the commit that set manifest_status = pending). A no-op before start() (the row stays
    pending and start() queues it) or when it is already queued. requested_by = (user id, username)."""
    if _queue is None or evidence_id in _queued:
        return
    _queued.add(evidence_id)
    _queue.put_nowait((evidence_id, requested_by))


async def _loop() -> None:
    while True:
        evidence_id, by = await _queue.get()
        _queued.discard(evidence_id)
        try:
            await build(evidence_id, requested_by=by)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("manifest build of %s failed", evidence_id)


async def requeue_pending() -> int:
    """Startup: queue every exhibit left pending (a build that died with the previous process). Returns the count."""
    async with session_factory() as db:
        ids = (await db.execute(select(Evidence.id).where(Evidence.manifest_status == "pending")
                                .order_by(Evidence.updated_at))).scalars().all()
    for evidence_id in ids:
        enqueue(evidence_id, None)
    return len(ids)


async def start() -> None:
    global _queue, _worker
    _queue = asyncio.Queue()
    _worker = asyncio.create_task(_loop(), name="evidence-manifest-builder")
    n = await requeue_pending()
    if n:
        log.warning("startup: queued %d container manifest(s) left pending", n)


async def stop() -> None:
    global _queue, _worker
    if _worker is not None:
        _worker.cancel()
        try:
            await _worker
        except asyncio.CancelledError:
            pass
    _queue, _worker = None, None
    _queued.clear()


# ── one build ───────────────────────────────────────────────────────────────────────────────────────────────────

def _open_source(fmt: str, rel: str, nonce_hex: str, size: int):
    """Blocking: the seekable view (zip; its open authenticates the final chunk) or the decrypting iterator (tar)."""
    if crypto.row_format(nonce_hex) == 0:
        raise seekable.LegacyFormat()
    if fmt == "zip":
        return seekable.open_view(rel, nonce_hex, size)
    return crypto.iter_decrypted(rel, nonce_hex, size)


def _take(gen, n: int) -> list[dict]:
    return list(itertools.islice(gen, n))


def _actor(requested_by: Optional[tuple]) -> dict:
    uid, name = requested_by or (None, None)
    return {"user_id": uid, "username": name}


async def build(evidence_id: uuid.UUID, *, requested_by: Optional[tuple] = None) -> Optional[str]:
    """Build one pending manifest. Returns built | failed, or None when there was nothing to do (not pending, not an
    indexed format, or the exhibit changed during the build: then it is queued again if still pending)."""
    async with _build_lock:
        async with session_factory() as db:
            ev = (await db.execute(select(Evidence).where(Evidence.id == evidence_id))).scalar_one_or_none()
            if ev is None or ev.manifest_status != "pending" or ev.container_format not in INDEXED_FORMATS:
                return None
            snap = (ev.container_format, ev.storage_path, ev.nonce_hex, ev.file_size_bytes)
            incident_id, identifier = ev.incident_id, ev.identifier
            mb = ManifestBuild(ev.container_format, caps())
            failure, frozen_reason = None, None
            try:
                if not ev.storage_path:
                    raise IndexFailed("no_stored_file", "the exhibit has no stored file")
                src = await asyncio.to_thread(_open_source, *snap)
                try:
                    gen = mb.entries(src)
                    while batch := await asyncio.to_thread(_take, gen, INSERT_BATCH):
                        await db.execute(insert(EvidenceManifestEntry),
                                         [{"evidence_id": evidence_id, **e} for e in batch])
                finally:
                    await asyncio.to_thread(src.close)
            except IndexFailed as e:
                failure = (e.reason, e.detail)
            except seekable.LegacyFormat:
                failure = ("legacy_format", "the stored file is in the legacy (v0) format, which has no seekable view")
            except EvidenceIntegrityError as e:
                failure, frozen_reason = ("integrity_failed", f"the stored file failed authentication ({e.reason})"), e.reason
            except EvidenceCryptoError as e:
                failure = ("read_error", f"the stored file could not be read ({e.reason})")
            except Exception as e:                       # a bug or a DB error: still record it, never leave it pending
                log.exception("manifest build of %s", evidence_id)
                failure = ("internal_error", type(e).__name__)
            if failure:
                await db.rollback()
                await _record_failure(db, evidence_id, incident_id, identifier, snap[0], failure, requested_by,
                                      frozen_reason)
                return "failed"

            row = (await db.execute(select(Evidence).where(Evidence.id == evidence_id)
                                    .with_for_update(of=Evidence).execution_options(populate_existing=True))).scalar_one()
            if row.manifest_status != "pending" or (row.container_format, row.storage_path, row.nonce_hex,
                                                    row.file_size_bytes) != snap:
                await db.rollback()                       # changed meanwhile: drop these entries
                if row.manifest_status == "pending":
                    enqueue(evidence_id, requested_by)
                return None
            row.manifest_status, row.manifest_error = "built", None
            row.manifest_sha256, row.manifest_entries = mb.manifest_sha256, mb.count
            row.manifest_builder, row.manifest_listing = mb.builder, mb.listing
            await write_audit(
                db, "evidence_manifest_built", **_actor(requested_by),
                resource_type="evidence", resource_id=str(evidence_id), outcome="success",
                details={"incident_id": str(incident_id), "identifier": identifier, "container_format": snap[0],
                         "manifest_sha256": mb.manifest_sha256, "manifest_entries": mb.count,
                         "manifest_builder": mb.builder, "manifest_listing": mb.listing,
                         "requeued_at_startup": requested_by is None},
            )
            await db.commit()
            log.info("manifest of %s built: %d entries, sha256 %s", evidence_id, mb.count, mb.manifest_sha256)
            return "built"


async def _record_failure(db, evidence_id, incident_id, identifier, fmt, failure, requested_by, frozen_reason) -> None:
    reason, detail = failure
    row = (await db.execute(select(Evidence).where(Evidence.id == evidence_id)
                            .with_for_update(of=Evidence).execution_options(populate_existing=True))).scalar_one()
    if row.manifest_status != "pending":
        await db.rollback()
        return
    row.manifest_status, row.manifest_error = "failed", f"{reason}: {detail}"[:2000]
    await write_audit(
        db, "evidence_manifest_failed", **_actor(requested_by),
        resource_type="evidence", resource_id=str(evidence_id), outcome="failure",
        details={"incident_id": str(incident_id), "identifier": identifier, "container_format": fmt,
                 "reason": reason, "detail": detail, "requeued_at_startup": requested_by is None},
    )
    if frozen_reason is not None:
        actor = types.SimpleNamespace(id=_actor(requested_by)["user_id"], username=_actor(requested_by)["username"])
        await freeze_for_integrity(db, evidence_id, user=actor, ip=None, incident_id=incident_id,
                                   reason=frozen_reason, recomputed=None, phase="manifest_build")
    await db.commit()
    log.warning("manifest of %s failed: %s: %s", evidence_id, reason, detail)
