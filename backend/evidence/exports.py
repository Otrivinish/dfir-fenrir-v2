"""Build + encrypt evidence export bundles.

Flow (G2: one streaming pass, bounded memory whatever the exhibit sizes):
  1. Assemble a ZIP containing:
       - files/{evidence_id}__{filename}     plaintext evidence, decrypted chunk by chunk from
                                             /evidence (digital_file items with a stored file)
       - coc/{evidence_id}.json              per-item NIST-aligned CoC doc
       - audit/{evidence_id}.jsonl           per-item audit chain excerpt
       - manifest.json                       export-level summary
       - README.txt                          recipient instructions
     The ZIP is written to an unseekable stream (entries use data descriptors; ZIP64 where an
     entry or offset needs it).
  2. That stream is encrypted as it is produced with a fresh AES-256-GCM ephemeral key.
     Wire format: [12-byte nonce][ciphertext][16-byte GCM tag] — one GCM message, the same
     bytes a one-shot AESGCM.encrypt of the whole ZIP would give.
  3. The bundle is built in /evidence/.staging/ and moved to /evidence/exports/{export_id}.enc
     only when complete. Any failure (a stored file that fails authentication or can't be read
     mid-stream, F-12) discards it: nothing half-written is ever offered.

Plaintext exists only in memory, a chunk at a time; the recipient decrypts without ever
knowing the master KEK.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from core.config import settings
from models import AuditLog, CustodyExport, Evidence, Incident, User

from evidence.crypto import EvidenceIntegrityError, iter_decrypted
from evidence.hashing import hash_algorithm
from evidence.streaming import StagedOutput
from le_package.builder import _safe_filename

# The bundle is ONE AES-256-GCM message, and GCM encrypts at most 2^39 - 256 bits (about 64 GiB) per
# message (NIST SP 800-38D §5.2.1.1). Cap the stored bytes one export may embed well below that, leaving
# room for the ZIP structure and the records; a larger selection is refused up front (413).
EXPORT_MAX_PLAINTEXT_BYTES = 60 * 1024 ** 3


README = """\
DFIR-FENRIR v2 — Evidence Export Bundle
========================================

This archive contains evidence collected during an incident response,
exported under chain of custody. The outer file you downloaded is
AES-256-GCM encrypted; the inner ZIP holds the actual evidence and the
chain-of-custody documentation.

Decryption
----------
The export key was provided out-of-band by the sender. It is a 64-character
hex string (AES-256). To verify you have the correct key, compare the first
and last 8 characters against the `key_hint` value in the original transfer.

The bundle is [12-byte nonce][ciphertext][16-byte GCM tag]. Decrypt it with
the following Python 3 snippet (requires the `cryptography` package). It
streams, so it works for a bundle of any size and never holds it in memory
(the one-shot AESGCM(key).decrypt stops at 2 GiB):

    import os, sys
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    src, key = sys.argv[1], bytes.fromhex(sys.argv[2])
    size, part = os.path.getsize(src), sys.argv[1] + ".zip.part"
    with open(src, "rb") as f, open(part, "wb") as out:
        nonce = f.read(12)
        f.seek(size - 16)
        tag = f.read(16)
        f.seek(12)
        dec = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        left = size - 28
        try:
            while left:
                block = f.read(min(left, 1 << 20))
                left -= len(block)
                out.write(dec.update(block))
            dec.finalize()            # raises InvalidTag unless the whole bundle is intact
        except Exception:
            out.close()
            os.remove(part)           # never keep output from a bundle that failed
            raise
    os.replace(part, sys.argv[1] + ".zip")

Usage:   python3 decrypt.py bundle.enc <key-hex>

The output `.zip` is the standard ZIP file documented below (ZIP64 when an
item is larger than 4 GiB; any current unzip tool reads it).

Bundle contents
---------------
- manifest.json            Export-level summary + list of items
- coc/{evidence_id}.json   Per-item chain-of-custody document (NIST-aligned)
- audit/{evidence_id}.jsonl Per-item audit chain excerpt (one JSON event per line)
- files/...                Plaintext evidence files: only items whose file is stored
                           in FENRIR. Each manifest item says whether its bytes are
                           in this bundle (`bytes_included`); a physical item or a
                           digital item registered without a file is listed as
                           "not included" and is documented by its CoC record only.

Integrity
---------
Each item in manifest.json has its plaintext SHA-256 + SHA-1 + MD5 hashes,
matching the original recorded at collection time. After extraction, verify
each file's SHA-256 matches the manifest entry. If any hash mismatches,
the chain of custody is broken — contact the sender.

The bundle as received (the encrypted blob) also has a SHA-256 you can
verify before decrypting. The sender will have communicated it alongside
the key.
"""


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _z(dt: datetime | None) -> str | None:
    """UTC ISO 8601 with a Z suffix, sub-second precision kept; a naive value is UTC."""
    if dt is None:
        return None
    dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


EXCLUDED_DRAFT = "excluded: unsealed draft"


class ExhibitIntegrityError(EvidenceIntegrityError):
    """R3-3: an exhibit's stored file failed while it was bundled, either the decrypting stream (the
    crypto layer's reason) or the SHA-256 of the plaintext bundled vs the one recorded (hash_mismatch).
    Names the exhibit, so the caller can freeze it."""

    def __init__(self, evidence_id, reason: str | None, sha256_recomputed: str | None = None):
        super().__init__(f"exhibit {evidence_id}: {reason or 'integrity'}", reason=reason)
        self.evidence_id = evidence_id
        self.sha256_recomputed = sha256_recomputed


def is_unsealed_draft(ev: Evidence) -> bool:
    """M11 (owner, 2026-10-04): an item whose chain of custody is not sealed. Exports and LE packages leave
    it out unless the caller opts in."""
    return not ev.coc_sealed


def _has_stored_file(ev: Evidence) -> bool:
    """The item's bytes are stored (encrypted) in FENRIR, so the export can embed them."""
    return ev.kind == "digital_file" and bool(ev.storage_path) and bool(ev.nonce_hex)


def _bytes_note(ev: Evidence) -> str | None:
    """Why an item's bytes are not in the bundle (None = they are)."""
    if _has_stored_file(ev):
        return None
    if ev.kind == "physical_item":
        return "not included (physical item)"
    return "not included (no file stored in FENRIR)"


def _seal_fields(ev: Evidence) -> dict:
    """M11: the sealed state and lawful basis of an item, for manifests and inventories."""
    return {"coc_sealed": bool(ev.coc_sealed), "coc_sealed_at": _z(ev.coc_sealed_at),
            "lawful_basis": ev.lawful_basis}


def _path_in_zip(ev: Evidence) -> str:
    """M3: the item's file path inside the bundle, from the SANITISED original name (as in the LE
    package): no '/', '\\' or '..' from an uploaded filename can reach the ZIP entry name."""
    return f"files/{ev.id}__{_safe_filename(ev.original_filename or 'evidence.bin', max_len=80)}"


def _key_hint(key_hex: str) -> str:
    return f"{key_hex[:8]}…{key_hex[-8:]}"


def _build_coc_doc(inc: Incident, ev: Evidence, events: list[AuditLog]) -> dict:
    """Per-item NIST-aligned chain-of-custody JSON. Timestamps are UTC with a Z suffix."""
    return {
        "version": "1.0",
        "case": {
            "incident_id":    str(inc.id),
            "incident_title": inc.title,
            "severity":       inc.severity,
            "tlp":            inc.tlp,
            "phase":          inc.phase,
            "status":         inc.status,
        },
        "item": {
            "id":         str(ev.id),
            "identifier": ev.identifier,
            "name":       ev.name,
            "kind":       ev.kind,
            "tlp":        ev.tlp,
            "status":     ev.status,
            "description": ev.description,
            "collected_at":       _z(ev.collected_at),
            # C3 — when the image was taken / item seized (operator-stated; None when not
            # recorded). collected_at above is when the item was registered in FENRIR.
            "acquired_at":        _z(ev.acquired_at),
            "collected_by_id":    str(ev.collected_by_id) if ev.collected_by_id else None,
            "collected_location": ev.collected_location,
            "current_custodian_id": (
                str(ev.current_custodian_id) if ev.current_custodian_id else None
            ),
            "hashes": {
                "sha256": ev.sha256,
                "sha1":   ev.sha1,
                "md5":    ev.md5,
            } if ev.kind == "digital_file" else None,
            # C3 — the imaging tool's hashes and how the target hash compared with the
            # uploaded bytes: match | mismatch | not_checked | container_media (None = legacy
            # item without a target hash).
            "hash_check": {
                "acquisition_hash_source":    ev.acquisition_hash_source,
                "acquisition_hash_target":    ev.acquisition_hash_target,
                "target_hash_algorithm":      hash_algorithm(ev.acquisition_hash_target),
                "upload_hash_check":          ev.upload_hash_check,
            } if ev.kind == "digital_file" else None,
            "file": {
                "original_filename": ev.original_filename,
                "size_bytes":        ev.file_size_bytes,
                "mime_type":         ev.mime_type,
                "path_in_zip":       _path_in_zip(ev),
            } if _has_stored_file(ev) else None,
            # F4 (R07): whether this item's bytes are in the bundle, and why not when they aren't.
            "bytes_in_bundle": _has_stored_file(ev),
            "bytes_note":      _bytes_note(ev),
            "physical": {
                "make":  ev.make,
                "model": ev.model,
                "serial": ev.serial,
                "physical_location": ev.physical_location,
                "condition": ev.condition,
                "photos": ev.photos or [],
            } if ev.kind == "physical_item" else None,
            "disposed_at": _z(ev.disposed_at),
            "final_hash_at_disposition": ev.final_hash_at_disposition,
        },
        "custody_chain": [
            {
                "timestamp":  _z(e.timestamp),
                "actor":      e.username,
                "actor_id":   str(e.user_id) if e.user_id else None,
                "action":     e.action,
                "outcome":    e.outcome,
                "details":    e.details or {},
                "ip_address": e.ip_address,
                "audit_hash":      e.row_hash,
                "audit_prev_hash": e.prev_hash,
            }
            for e in events
        ],
    }


def _events_excerpt(events: list[AuditLog]) -> str:
    """JSON Lines (one event per line) for compact, line-by-line verification."""
    out = []
    for e in events:
        out.append(json.dumps({
            "id":          str(e.id),
            "timestamp":   _z(e.timestamp),
            "actor":       e.username,
            "action":      e.action,
            "outcome":     e.outcome,
            "details":     e.details or {},
            "audit_hash":      e.row_hash,
            "audit_prev_hash": e.prev_hash,
        }, sort_keys=True, separators=(",", ":")))
    return "\n".join(out) + ("\n" if out else "")


class _GcmSink:
    """Write-only, unseekable file object the ZIP writer writes into: what it gets is AES-256-GCM
    encrypted as it arrives and appended to the staged bundle, and the ciphertext is hashed on the
    way. zipfile sees no tell()/seek(), so it writes data descriptors instead of seeking back."""

    def __init__(self, f: BinaryIO, key: bytes, nonce: bytes):
        self._f = f
        self._enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        self.sha256 = hashlib.sha256(nonce)
        f.write(nonce)

    def write(self, data) -> int:
        ct = self._enc.update(data)
        self._f.write(ct)
        self.sha256.update(ct)
        return len(data)

    def flush(self) -> None:
        pass

    def finalize(self) -> None:
        tail = self._enc.finalize() + self._enc.tag
        self._f.write(tail)
        self.sha256.update(tail)


_ZIP_SLICE = 8 * 1024 * 1024      # a v0 file is decrypted whole: feed it to the ZIP writer in slices


def _zip_stored_file(zf: zipfile.ZipFile, name: str, storage_path: str, nonce_hex: str, size: int | None,
                     sha256: str | None = None, evidence_id=None) -> bool:
    """Stream a stored file's plaintext into its own ZIP entry (same entry metadata as writestr). The row
    size sizes the ZIP64 decision. Any exception from the decrypting stream (F-12) propagates: the caller
    discards the whole bundle. R3-3: the plaintext is hashed as it is bundled and compared with `sha256`
    (the exhibit's recorded SHA-256) at the end; a mismatch, or an integrity failure of the stream, raises
    ExhibitIntegrityError naming `evidence_id`. Returns whether the bytes were checked against a recorded
    hash (False when none is recorded)."""
    zinfo = zipfile.ZipInfo(name, date_time=time.localtime(time.time())[:6])
    zinfo.compress_type = zf.compression
    zinfo.external_attr = 0o600 << 16
    zinfo.file_size = size or 0
    h = hashlib.sha256()
    try:
        with zf.open(zinfo, "w") as dest:
            for part in iter_decrypted(storage_path, nonce_hex, size):
                mv = memoryview(part)
                for i in range(0, len(mv), _ZIP_SLICE):
                    piece = mv[i:i + _ZIP_SLICE]
                    h.update(piece)
                    dest.write(piece)
    except ExhibitIntegrityError:
        raise
    except EvidenceIntegrityError as e:
        raise ExhibitIntegrityError(evidence_id, e.reason or "integrity") from e
    if not sha256:
        return False
    digest = h.hexdigest()
    if digest != sha256.lower():
        raise ExhibitIntegrityError(evidence_id, "hash_mismatch", digest)
    return True


def _build_staged(parts: list[tuple[str, str | None, tuple | None]]) -> tuple[StagedOutput, str, int, str, set]:
    """Blocking: stream the inner ZIP (the digital items decrypted chunk by chunk, each hashed and checked,
    R3-3) through a fresh per-export AES-256-GCM key into a staged file in <evidence>/.staging/, NOT yet
    published. Memory stays bounded whatever the item sizes. Any failure discards the staged file and
    propagates. Returns (staged output, key_hex, bundle size, bundle SHA-256, ids whose bytes matched their
    recorded SHA-256). Call via asyncio.to_thread."""
    key_bytes = secrets.token_bytes(32)         # AES-256
    nonce     = os.urandom(12)
    out = StagedOutput()
    verified: set = set()
    try:
        sink = _GcmSink(out.file, key_bytes, nonce)
        with zipfile.ZipFile(sink, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, text, encrypted in parts:
                if encrypted:
                    if _zip_stored_file(zf, name, *encrypted) and len(encrypted) > 4:
                        verified.add(encrypted[4])
                else:
                    zf.writestr(name, text)
        sink.finalize()
        size = out.finish()
    except BaseException:
        out.discard()
        raise
    return out, key_bytes.hex(), size, sink.sha256.hexdigest(), verified


def _write_bundle(parts: list[tuple[str, str | None, tuple | None]],
                  rel_path: str) -> tuple[str, int, str]:
    """Blocking: _build_staged, then move the bundle to rel_path under evidence_path. Returns (key_hex,
    bundle size, bundle SHA-256)."""
    out, key_hex, size, sha, _verified = _build_staged(parts)
    try:
        out.commit(rel_path)
    except BaseException:
        out.discard()
        raise
    return key_hex, size, sha


async def plan_bundle(
    db: AsyncSession,
    inc: Incident,
    items: list[Evidence],
    exporter: User,
    recipient: str,
    purpose: str,
    acknowledgments: str | None,
    *,
    export_id: uuid.UUID,
    include_unsealed_drafts: bool = False,
) -> tuple[list, set[uuid.UUID], list[Evidence]]:
    """Everything the bundle holds, read from the DB: (parts for _build_staged, the ids whose bytes go in,
    the unsealed drafts left out). M11: an unsealed draft (is_unsealed_draft) is listed in the manifest as
    "excluded: unsealed draft" with no record or bytes, unless `include_unsealed_drafts`. Writes nothing."""
    excluded = [ev for ev in items if is_unsealed_draft(ev) and not include_unsealed_drafts]
    excluded_ids = {ev.id for ev in excluded}
    # Collect per-item events from the hash-chained audit log.
    events_by_item: dict[uuid.UUID, list[AuditLog]] = {}
    for ev in items:
        if ev.id in excluded_ids:
            continue
        q = await db.execute(
            select(AuditLog)
            .where(AuditLog.resource_type == "evidence",
                   AuditLog.resource_id   == str(ev.id))
            .order_by(AuditLog.timestamp.asc(), AuditLog.id.asc())
        )
        events_by_item[ev.id] = q.scalars().all()

    # What goes in the inner ZIP, in order: (name, text, (storage_path, nonce_hex, size, sha256, id) | None).
    # The DB-derived parts are built here; decrypting, zipping, encrypting and writing the bundle are
    # blocking CPU + I/O on up to GiBs, so they run in a worker thread (L8: never on the loop).
    parts: list = [("README.txt", README, None)]
    manifest_items = []
    embedded: set[uuid.UUID] = set()
    for ev in items:
        if ev.id in excluded_ids:
            manifest_items.append({
                "id": str(ev.id), "identifier": ev.identifier, "name": ev.name, "kind": ev.kind,
                "status": ev.status, "file_path": None, "bytes_included": False, "bytes_note": EXCLUDED_DRAFT,
                "excluded": EXCLUDED_DRAFT, **_seal_fields(ev),
            })
            continue
        coc = _build_coc_doc(inc, ev, events_by_item[ev.id])
        parts.append((f"coc/{ev.id}.json", json.dumps(coc, indent=2, sort_keys=True), None))
        parts.append((f"audit/{ev.id}.jsonl", _events_excerpt(events_by_item[ev.id]), None))

        file_path_in_zip = None
        if _has_stored_file(ev):
            # Decrypted from /evidence chunk by chunk (in the thread), hashed and checked against the
            # recorded SHA-256 (R3-3), and embedded as plaintext in the export. A failed decrypt or check
            # raises, so the whole export fails: every listed item is embedded.
            file_path_in_zip = _path_in_zip(ev)
            parts.append((file_path_in_zip, None,
                          (ev.storage_path, ev.nonce_hex, ev.file_size_bytes, ev.sha256, ev.id)))
            embedded.add(ev.id)

        manifest_items.append({
            "id":         str(ev.id),
            "identifier": ev.identifier,
            "name":       ev.name,
            "kind":       ev.kind,
            "tlp":        ev.tlp,
            "status":     ev.status,
            "sha256":     ev.sha256,
            "sha1":       ev.sha1,
            "md5":        ev.md5,
            "file_path":  file_path_in_zip,
            "bytes_included": file_path_in_zip is not None,
            "bytes_note":     _bytes_note(ev),
            "coc_path":   f"coc/{ev.id}.json",
            "audit_path": f"audit/{ev.id}.jsonl",
            "final_hash_at_disposition": ev.final_hash_at_disposition,
            **_seal_fields(ev),                  # M11, appended
        })

    manifest = {
        "version": "1.0",
        "export": {
            "id":              str(export_id),
            "created_at":      _z(_now_utc()),
            "created_by":      exporter.username,
            "created_by_id":   str(exporter.id),
            "recipient":       recipient,
            "purpose":         purpose,
            "acknowledgments": acknowledgments,
            "include_unsealed_drafts": include_unsealed_drafts,
            "excluded_unsealed_drafts": len(excluded),
        },
        "incident": {
            "id":       str(inc.id),
            "title":    inc.title,
            "severity": inc.severity,
            "tlp":      inc.tlp,
            "phase":    inc.phase,
            "status":   inc.status,
        },
        "items": manifest_items,
        "verification": {
            "spec": (
                "Outer bundle: AES-256-GCM, 12-byte nonce prefix + "
                "ciphertext + 16-byte tag. Inner files: plaintext, "
                "SHA-256 must match this manifest entry. Items with "
                "bytes_included=false have no file in this bundle."
            ),
            "decrypt_recipe": (
                "nonce = bundle[:12], tag = bundle[-16:], ciphertext = bundle[12:-16]; "
                "Cipher(AES(bytes.fromhex(key)), GCM(nonce, tag)).decryptor() over the ciphertext, "
                "streamed (README.txt). One-shot AESGCM(key).decrypt(nonce, bundle[12:], None) "
                "works only for bundles under 2 GiB."
            ),
        },
    }
    parts.append(("manifest.json", json.dumps(manifest, indent=2, sort_keys=True), None))
    return parts, embedded, excluded


_DOWNLOAD_CHUNK = 1024 * 1024


def open_bundle_for_download(export: CustodyExport) -> tuple[BinaryIO, int, str]:
    """Open the encrypted bundle on disk for streaming. Returns (open file, size in
    bytes, suggested_filename); stream it with iter_bundle(), which closes it.
    Blocking: call via asyncio.to_thread. Raises FileNotFoundError when the bundle
    is gone. Caller is responsible for status checks (consumed/expired/revoked)."""
    if not export.file_path:
        raise FileNotFoundError("Export bundle path missing")
    path = Path(settings.evidence_path) / export.file_path
    # Derive the suggested extension from the actual on-disk path so LE
    # packages (now AES-256 password ZIP, stored as `.zip`) and legacy
    # evidence custody exports (still AES-256-GCM, stored as `.enc`) each
    # serve with the correct extension.
    ext = Path(export.file_path).suffix or ".enc"
    suggested = f"fenrir-export-{export.id}{ext}"
    f = open(path, "rb")
    return f, os.fstat(f.fileno()).st_size, suggested


def iter_bundle(f: BinaryIO) -> Iterator[bytes]:
    """Yield the open bundle in 1 MiB chunks, then close it. A sync generator on
    purpose: StreamingResponse runs each step in a worker thread, so the event
    loop never reads the file and the bundle is never held whole in memory."""
    with f:
        while chunk := f.read(_DOWNLOAD_CHUNK):
            yield chunk


def is_expired(export: CustodyExport) -> bool:
    return _now_utc() >= export.expires_at


# R105 (G-fix B): a custody export's row is `pending` while its bundle is built (M1) and becomes `ready`
# (or `revoked` on a failure) when the build ends. A process that dies mid-build leaves the row pending for
# ever. BUILDING holds the exports this process is building right now; sweep_stale_pending() revokes the
# others once they are older than STALE_PENDING_AFTER (far beyond any build Caddy's 30-minute request window
# allows). A pending row never has a published bundle (file_path is set together with `ready`); its staged
# `.partial`, if one was left, is deleted by the staging sweep (crypto.sweep_staging: idle > 60 min, at
# startup and every minute).
BUILDING: set[uuid.UUID] = set()
STALE_PENDING_AFTER = timedelta(hours=2)


async def sweep_stale_pending(db: AsyncSession, *, by: str) -> int:
    """Revoke `pending` export rows older than STALE_PENDING_AFTER that no build in this process owns,
    each audited `evidence_export_create` (outcome failure, reason abandoned_pending). Commits. Returns
    how many."""
    cutoff = _now_utc() - STALE_PENDING_AFTER
    rows = (await db.execute(
        select(CustodyExport)
        .where(CustodyExport.status == "pending", CustodyExport.created_at < cutoff)
        .with_for_update(skip_locked=True)
    )).scalars().all()
    n = 0
    for x in rows:
        if x.id in BUILDING:
            continue
        x.status = "revoked"
        await write_audit(
            db, "evidence_export_create", outcome="failure",
            resource_type="custody_export", resource_id=str(x.id),
            details={"incident_id": str(x.incident_id), "recipient": x.recipient, "reason": "abandoned_pending",
                     "pending_since": _z(x.created_at), "older_than_hours": STALE_PENDING_AFTER.total_seconds() / 3600,
                     "by": by})
        n += 1
    await db.commit()
    return n


def effective_status(export: CustodyExport) -> str:
    """Reads `status` with expiry applied — DB row may say 'ready' but the
    clock has run out. Use this anywhere the UI shows status."""
    if export.status == "ready" and is_expired(export):
        return "expired"
    return export.status
