"""G5 (R08): working copies — an analyst's download, recorded with the hash of what was sent.

Masters are never downloadable. A download is always issued as a registered working copy:

  issue     POST …/working-copies → a copy row (kind download, status issued, "<exhibit>-WC-n") and a
            one-time link: a 256-bit random token, stored only as its SHA-256, valid TOKEN_TTL for the
            issuing user only (the GET also needs that user's session or API token).
  download  GET …/working-copies/{id}/download?token=… claims the link atomically (issued → downloading,
            the token is cleared: one use), then streams the master's plaintext through G2's
            decrypted_download. FENRIR hashes exactly the bytes it hands to the transport (SHA-256, SHA-1,
            MD5, in worker threads) and records the outcome on the copy when the response ends:

  complete          every byte was sent; the copy's hashes are recorded and verified_against_master is
                    its SHA-256 = the master's recorded SHA-256
  aborted           the transfer stopped early: client_disconnected, or read_error (the stored file could
                    not be read part-way; evidence/crypto has already audited it and notified admins). The
                    bytes sent are kept; no hash is recorded for a partial copy.
  failed_integrity  the stored master failed its integrity check (end_reason integrity), or all bytes went
                    out but their SHA-256 differs from the recorded one (hash_mismatch). The exhibit is
                    frozen (verify_failed, audited evidence_verify_failed), as Verify does.

"complete" means the server sent every byte. Receipt is proved by the client: it hashes what it received
and compares it with the hash recorded on the copy.

The outcome is written by the response itself (TrackedDownload.__call__), inside the request, with the
request's own session (FastAPI closes request-scoped dependencies after the response is sent). The claim
is committed before the first byte, so no transaction is held open while the body streams.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import secrets
import uuid
from datetime import timedelta
from typing import AsyncIterator, Awaitable, Callable, Optional

import anyio
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from evidence.crypto import EvidenceCryptoError, EvidenceIntegrityError
from models import Evidence, EvidenceCopy, User, utcnow
from schemas import EvidenceCopyOut

log = logging.getLogger("fenrir.evidence.working_copies")

TOKEN_TTL = timedelta(minutes=10)          # to START the download; the transfer itself may take longer
# A copy still "downloading" this long after it started was cut by a restart (no request lives this long:
# Caddy's write timeout is 30 minutes); it is shown as aborted / interrupted.
INTERRUPTED_AFTER = timedelta(hours=1)


def new_token() -> tuple[str, str]:
    """(token, its SHA-256 hex). Only the hash is stored."""
    token = secrets.token_urlsafe(32)
    return token, token_hash(token)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_matches(stored_hash: Optional[str], token: str) -> bool:
    return bool(stored_hash) and hmac.compare_digest(stored_hash, token_hash(token))


# ─── Read model ────────────────────────────────────────────────────────────────────────────────

def copy_kind(c: EvidenceCopy) -> str:
    if c.kind:
        return c.kind
    return "export" if c.export_id else "legacy_record"


def effective_status(c: EvidenceCopy, now=None) -> str:
    """The stored status, with the two states only time can reach: an issued link never used → expired; a
    download cut by a restart (still downloading after INTERRUPTED_AFTER) → aborted."""
    kind = copy_kind(c)
    if kind == "export":
        return "exported"
    if kind == "legacy_record":
        return "legacy_unverified"
    now = now or utcnow()
    if c.status == "issued" and c.token_expires_at and c.token_expires_at <= now:
        return "expired"
    if c.status == "downloading" and c.download_started_at and c.download_started_at + INTERRUPTED_AFTER <= now:
        return "aborted"
    return c.status


def usable_for_examination(c: EvidenceCopy, corrected_ids: frozenset = frozenset(), now=None) -> bool:
    """A copy an examination may name: verified against the master, not discarded, not found altered —
    a complete download, a verified lab copy, or an export copy no L10 correction note disowns. A
    pre-G5 "Record copy" row never is: its hash is the master's, not the copy's."""
    if c.discarded_at is not None or c.altered_at is not None or not c.verified_against_master:
        return False
    kind = copy_kind(c)
    if kind == "download":
        return effective_status(c, now) == "complete"
    if kind == "lab_copy":
        return c.status == "verified"
    if kind == "export":
        return str(c.id) not in corrected_ids
    return False


def copy_out(c: EvidenceCopy, corrected_ids: frozenset = frozenset()) -> EvidenceCopyOut:
    now = utcnow()
    kind = copy_kind(c)
    status = effective_status(c, now)
    end_reason = c.end_reason
    if status == "aborted" and c.status == "downloading":
        end_reason = "interrupted"
    return EvidenceCopyOut(
        id=c.id, evidence_id=c.evidence_id, role=c.role, kind=kind,
        copy_identifier=c.copy_identifier, status=status,
        sha256=c.sha256, sha1=c.sha1, md5=c.md5,
        hash_source={"download": "server_stream", "lab_copy": "tool_reported"}.get(kind, "master"),
        verified_against_master=(bool(c.verified_against_master) and kind != "legacy_record"
                                 and str(c.id) not in corrected_ids),
        usable_for_examination=usable_for_examination(c, corrected_ids, now),
        created_by_id=c.created_by_id, created_by_qualifications=c.created_by_qualifications,
        created_at=c.created_at,
        issued_to_id=c.created_by_id if kind == "download" else None,
        token_expires_at=c.token_expires_at, download_started_at=c.download_started_at,
        completed_at=c.completed_at, bytes_sent=c.bytes_sent, end_reason=end_reason,
        purpose=c.purpose, destination_note=c.destination_note, copy_tool=c.copy_tool,
        export_id=c.export_id, discarded_at=c.discarded_at, altered_at=c.altered_at,
    )


def recorded_hash(c: EvidenceCopy, algorithm: str) -> Optional[str]:
    return {"sha256": c.sha256, "sha1": c.sha1, "md5": c.md5}[algorithm]


async def next_copy_seq(db: AsyncSession, evidence_id: uuid.UUID) -> int:
    """The next n of "<exhibit>-WC-n". The caller holds the exhibit row lock (FOR UPDATE), so two issues
    of the same exhibit can't pick the same n (the partial UNIQUE index backs it up)."""
    from sqlalchemy import func
    cur = (await db.execute(
        select(func.max(EvidenceCopy.copy_seq)).where(EvidenceCopy.evidence_id == evidence_id)
    )).scalar_one()
    return (cur or 0) + 1


# ─── The download ──────────────────────────────────────────────────────────────────────────────

class _Tally:
    """What the response has handed to the transport so far."""

    def __init__(self) -> None:
        self._h = (hashlib.sha256(), hashlib.sha1(), hashlib.md5())
        self.sent = 0
        self.finished = False            # every byte went out (the iterator was asked past the end)
        self.failure: Optional[str] = None          # integrity | read_error
        self.failure_reason: Optional[str] = None   # the crypto layer's reason class

    def update(self, part: bytes) -> None:
        for h in self._h:
            h.update(part)

    def hexdigests(self) -> tuple[str, str, str]:
        return tuple(h.hexdigest() for h in self._h)  # type: ignore[return-value]


async def _counted(inner: AsyncIterator[bytes], tally: _Tally) -> AsyncIterator[bytes]:
    """Hash each part off the event loop, hand it out, and count it as sent once the consumer comes
    back for the next one (StreamingResponse awaits send() in between)."""
    try:
        async for part in inner:
            await asyncio.to_thread(tally.update, part)
            yield part
            tally.sent += len(part)
        tally.finished = True
    except EvidenceIntegrityError as e:
        tally.failure, tally.failure_reason = "integrity", e.reason
        raise
    except EvidenceCryptoError as e:
        tally.failure, tally.failure_reason = "read_error", e.reason
        raise
    finally:
        aclose = getattr(inner, "aclose", None)
        if aclose is not None:
            with anyio.CancelScope(shield=True):
                await aclose()


async def _single(body: bytes) -> AsyncIterator[bytes]:
    yield body


class TrackedDownload(StreamingResponse):
    """A StreamingResponse that calls `on_end(tally)` once the response is over, however it ended
    (complete, client gone, cancelled, or the body raised), shielded from cancellation."""

    def __init__(self, inner: AsyncIterator[bytes], *, on_end: Callable[[_Tally], Awaitable[None]],
                 media_type: str, headers: dict) -> None:
        self.tally = _Tally()
        self._on_end = on_end
        super().__init__(_counted(inner, self.tally), media_type=media_type, headers=headers)

    async def __call__(self, scope, receive, send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            with anyio.CancelScope(shield=True):
                try:
                    await self.body_iterator.aclose()      # a disconnect leaves it suspended at a yield
                except Exception:                          # it already raised (integrity / read error)
                    pass
                await self._on_end(self.tally)


def tracked(resp: Response, size: int, *, on_end: Callable[[_Tally], Awaitable[None]],
            media_type: str, headers: dict) -> TrackedDownload:
    """Wrap what decrypted_download returned: a small or v0 file comes back authenticated whole
    (Response.body), a large one as a stream (StreamingResponse.body_iterator)."""
    inner = resp.body_iterator if isinstance(resp, StreamingResponse) else _single(resp.body)
    headers = {**headers, "Content-Length": str(size)}
    return TrackedDownload(inner, on_end=on_end, media_type=media_type, headers=headers)


async def freeze_for_integrity(db: AsyncSession, ev_id: uuid.UUID, *, user: User, ip: Optional[str],
                               incident_id: uuid.UUID, copy: Optional[EvidenceCopy] = None, reason: Optional[str],
                               recomputed: Optional[str], phase: str = "working_copy_download",
                               extra: Optional[dict] = None) -> bool:
    """The master failed its integrity check while it was read (a working copy, Verify, an export or an LE
    package: `phase`): re-read the exhibit under a row lock (SELECT … FOR UPDATE) and freeze it if it is
    still active (never overwrite a status changed meanwhile), audited evidence_verify_failed. Returns
    whether it was frozen. The caller commits."""
    ev = (await db.execute(
        select(Evidence).where(Evidence.id == ev_id).with_for_update(of=Evidence)
        .execution_options(populate_existing=True)
    )).scalar_one()
    status_before = ev.status
    frozen = status_before == "active"
    if frozen:
        ev.status = "verify_failed"
    details = {"incident_id": str(incident_id), "phase": phase}
    if copy is not None:
        details.update(working_copy_id=str(copy.id), copy_identifier=copy.copy_identifier)
    details.update({**(extra or {}), "sha256_recorded": ev.sha256, "sha256_recomputed": recomputed,
                    "reason": reason, "status_before": status_before, "frozen": frozen})
    await write_audit(
        db, "evidence_verify_failed",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id), outcome="failure",
        details=details,
        ip_address=ip,
    )
    return frozen


async def record_download_end(db: AsyncSession, *, copy_id: uuid.UUID, ev_id: uuid.UUID, master_sha256: str,
                              incident_id: uuid.UUID, user: User, ip: Optional[str], tally: _Tally) -> str:
    """Write the outcome of a download on its copy (+ custody log, + freeze on an integrity failure) and
    commit. Returns the status written."""
    copy = (await db.execute(
        select(EvidenceCopy).where(EvidenceCopy.id == copy_id).with_for_update(of=EvidenceCopy)
        .execution_options(populate_existing=True)
    )).scalar_one()
    copy.completed_at = utcnow()
    copy.bytes_sent = tally.sent
    recomputed = None
    if tally.finished and tally.failure is None:
        sha256, sha1, md5 = tally.hexdigests()
        copy.sha256, copy.sha1, copy.md5 = sha256, sha1, md5
        recomputed = sha256
        copy.verified_against_master = sha256 == master_sha256
        if copy.verified_against_master:
            copy.status, copy.end_reason = "complete", None
        else:
            copy.status, copy.end_reason = "failed_integrity", "hash_mismatch"
    elif tally.failure == "integrity":
        copy.status, copy.end_reason = "failed_integrity", "integrity"
    elif tally.failure == "read_error":
        copy.status, copy.end_reason = "aborted", "read_error"
    else:
        copy.status, copy.end_reason = "aborted", "client_disconnected"

    action = {"complete": "evidence_working_copy_complete", "aborted": "evidence_working_copy_aborted",
              "failed_integrity": "evidence_working_copy_failed"}[copy.status]
    await write_audit(
        db, action,
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev_id),
        outcome="success" if copy.status == "complete" else "failure",
        details={"incident_id": str(incident_id), "working_copy_id": str(copy.id),
                 "copy_identifier": copy.copy_identifier, "status": copy.status,
                 "end_reason": copy.end_reason, "bytes_sent": copy.bytes_sent,
                 "sha256": copy.sha256, "sha1": copy.sha1, "md5": copy.md5,
                 "master_sha256": master_sha256,
                 "matches_master": bool(copy.verified_against_master) if copy.status != "aborted" else None,
                 "read_failure": tally.failure_reason},
        ip_address=ip,
    )
    if copy.status == "failed_integrity":
        await freeze_for_integrity(db, ev_id, user=user, ip=ip, incident_id=incident_id, copy=copy,
                                   reason=copy.end_reason if tally.failure is None else tally.failure_reason,
                                   recomputed=recomputed)
    await db.commit()
    if copy.status != "complete":
        log.warning("working copy %s ended %s (%s) after %d bytes", copy.copy_identifier, copy.status,
                    copy.end_reason, tally.sent)
    return copy.status
