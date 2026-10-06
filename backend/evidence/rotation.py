"""Evidence KEK rotation tool (G1 stage 4). Protocol: docs/streaming-aes-gcm-format.md §6.4
(re-wrap, FENRKSJ1 journal, R-1 recovery, lock) and §5.4 (journalled rewrite: v0 → v2 migration,
v2 → v2 re-encrypt). Operator procedure: docs/evidence-kek-rotation.md.

Covers every consumer of EVIDENCE_KEK: evidence files and evidence photos (/evidence), entity and
incident "Files" (entity_files, /asset_logs), quarantine artifacts (artifacts, /quarantine; H1 — a legacy
plaintext artifact row is refused with "migrate first": python -m artifacts.encrypt_quarantine --apply),
and the collector RSA private keys in collection_packages. Run it as a one-off container from the backend image while backend,
analysis-worker and backup are stopped:

    docker compose run --rm --no-deps -v ./secrets/evidence_kek.new:/run/kek/new:ro backend \\
        python -m evidence.rotation plan --old-kek-file /run/secrets/evidence_kek --new-kek-file /run/kek/new

Commands (each dry by default; only --apply writes, after a typed confirmation unless --yes):
    plan            what `rotate` would do (default command; read-only)
    rotate          recover journals, then re-wrap v2 key slots (or, with --breach, re-encrypt
                    every file under a fresh data key), migrate v0 files to v2, re-encrypt the
                    collector keys; one custody/audit row per item, one summary row per run
    recover         §6.4 / §5.4 crash recovery only
    verify          every file opens with NEW and matches its recorded SHA-256 (read-only)
    mirror-verify   check a rebuilt backup mirror against /evidence and NEW; --apply records it

Keys are read from files only (never argv or environment) and never printed; only their advisory
ids (codec.kek_id) appear. Exit codes: 0 clean, 1 finished with failures or items needing
attention, 2 refused (nothing written), 3 stopped for manual action (journal and lock kept),
4 DO NOT SWAP THE KEK: a v0 file is still under OLD (after a swap it would read as tampered and be
frozen; G-fix ROT-M2).

Journals are recognised by name AND content (G-fix R3-1): `<file>.keyslot` / `<file>.rewrite` that
starts with FENRKSJ1 / FENRRWJ1, never a path a DB row references. A `<journal>.tmp` is deleted only
when it holds the magic or a torn prefix of it; anything else merely named like a journal is reported
and never deleted (a non-temporary one stops the run: a corrupt journal or a foreign file).

Importing this module has no side effects; nothing in the application imports it.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select, text

from audit.service import write_audit
from core.config import settings
from evidence import codec
from evidence import crypto as store
from models import Artifact, AuditLog, CollectionPackage, EntityFile, Evidence

LOCK_NAME = store.ROTATION_LOCK                    # <evidence_path>/.kek-rotation.lock
KEYSLOT = ".keyslot"                               # §6.4 journal: <file>.keyslot
REWRITE = ".rewrite"                               # §5.4 journal: <file>.rewrite
TMP = ".tmp"
KSJ_MAGIC = b"FENRKSJ1"
KSJ_LEN = 168                                      # magic 8 + imm 32 + old slot 48 + new slot 48 + SHA-256 32
RWJ_MAGIC = b"FENRRWJ1"
STAGE_RE = re.compile(r"rot-[0-9a-f]{32}\.partial")  # this tool's staging files in <root>/.staging/
BACKUP_ROLE = "fenrir_backup"                      # the backup sidecar's DB role (docker-compose.yml)
OPERATOR_RE = re.compile(r"[A-Za-z0-9._@-]{1,48}")
REKEY_ACTIONS = {"evidence": "evidence_storage_rekeyed", "photo": "evidence_storage_rekeyed",
                 "file": "file_storage_rekeyed", "artifact": "artifact_storage_rekeyed",
                 "collector": "collector_key_rekeyed"}
RESOURCE_TYPE = {"evidence": "evidence", "photo": "evidence", "file": "entity_file", "artifact": "artifact",
                 "collector": "collection_package"}
EXIT_OK, EXIT_ATTENTION, EXIT_REFUSED, EXIT_MANUAL, EXIT_DO_NOT_SWAP = 0, 1, 2, 3, 4
COLUMNS = ("rewrap", "migrate", "reencrypt", "record", "done", "attention", "failed")


class Refused(Exception):
    """A precondition failed. Nothing was written by this invocation."""


class ManualStop(Exception):
    """Stop the run and leave the journal and the lock in place: an operator must decide."""


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def say(msg: str) -> None:
    print(f"[{now()}] {msg}", file=sys.stderr, flush=True)


# ─── Keys ─────────────────────────────────────────────────────────────────────────────────────

def load_kek_file(path: str, label: str) -> bytes:
    """A KEK from a file: a regular file (no symlink), not writable by group or others, holding
    exactly 64 hex characters. The contents never appear in an error."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        raise Refused(f"{label} KEK file {path}: cannot open it ({e.strerror}); a symlink is refused") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Refused(f"{label} KEK file {path}: not a regular file")
        if st.st_mode & 0o022:
            raise Refused(f"{label} KEK file {path}: writable by group or others (mode "
                          f"{stat.S_IMODE(st.st_mode):04o}); run chmod go-w on it")
        raw = os.read(fd, 257)
    finally:
        os.close(fd)
    body = raw.strip()
    if len(body) != 64 or not re.fullmatch(rb"[0-9a-fA-F]{64}", body):
        raise Refused(f"{label} KEK file {path}: must hold exactly 64 hex characters (contents not shown)")
    if st.st_mode & 0o004:
        say(f"note: {label} KEK file {path} is world-readable inside the container (a compose bind "
            "mount keeps the host mode); keep it in a 0700 directory on the host")
    return bytes.fromhex(body.decode("ascii"))


def kid(kek: Optional[bytes]) -> Optional[str]:
    return codec.kek_id(kek).hex() if kek else None


# ─── Small durable-I/O helpers (also the crash-injection points of the tests) ────────────────

def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_all(fd: int, data) -> None:
    mv = memoryview(data)
    while mv:
        mv = mv[os.write(fd, mv):]


def _pread_exactly(fd: int, n: int, offset: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        part = os.pread(fd, n - len(buf), offset + len(buf))
        if not part:
            break
        buf += part
    return bytes(buf)


def _read_head(fd: int) -> tuple[bytes, bytes]:
    """The 80-byte header and the first stored segment (read-exactly, §2.3)."""
    return (_pread_exactly(fd, codec.HEADER_LEN, 0),
            _pread_exactly(fd, codec.SEGMENT_LEN, codec.HEADER_LEN))


def _write_durable(path: Path, data: bytes) -> None:
    """Journal write: <path>.tmp (O_EXCL, 0600), fsync, rename to <path>, fsync the directory."""
    tmp = path.with_name(path.name + TMP)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        _write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(tmp, path)
    _fsync_dir(path.parent)


def _pwrite_slot(fd: int, slot: bytes) -> None:
    """§6.4 step 6: pwrite the 48-byte key slot at offset 32, then fsync."""
    mv, off = memoryview(slot), codec.KEY_SLOT_OFFSET
    while mv:
        n = os.pwrite(fd, mv, off)
        mv, off = mv[n:], off + n
    os.fsync(fd)


def _unlink_durable(path: Path) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        return
    _fsync_dir(path.parent)


def _rename_into_place(staged: Path, target: Path) -> None:
    """§5.4 step 4: rename the staged file onto the target, fsync both directories."""
    os.rename(staged, target)
    _fsync_dir(target.parent)
    _fsync_dir(staged.parent)


def _resolve(root: Path, rel: str) -> Path:
    base = root.resolve()
    target = (base / rel).resolve()
    if not target.is_relative_to(base) or target == base:
        raise ValueError(f"path escapes its store: {rel!r}")
    return target


# ─── Opening checks ───────────────────────────────────────────────────────────────────────────

def opens(kek: bytes, header: bytes, seg0: bytes) -> Optional[bool]:
    """None if `kek` does not open the header AND decrypt the first segment; otherwise the
    decryptor's kek_id_matches (F-10)."""
    if len(header) != codec.HEADER_LEN or not seg0:
        return None
    try:
        d = codec.StreamDecryptor(kek, header)
        d.update(seg0)
    except codec.CodecError:
        return None
    return d.kek_id_matches


@dataclass
class Check:
    ok: bool
    reason: Optional[str] = None
    sha256: Optional[str] = None
    kek_id_matches: Optional[bool] = None


def check_v2(path: Path, kek: bytes, nonce_hex: Optional[str], size: Optional[int],
             sha256: Optional[str]) -> Check:
    """Full read in the §4.2 order: size, magic, header, nonce prefix (Q5), unwrap, chunks,
    finalize, SHA-256 (when one is recorded)."""
    try:
        f = open(path, "rb")
    except FileNotFoundError:
        return Check(False, "file_missing")
    except OSError as e:
        return Check(False, f"io_error: {e.strerror}")
    with f:
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            return Check(False, "malformed_row: no plaintext size")
        try:
            expected = codec.container_size(size)
        except ValueError:
            return Check(False, "malformed_row: size out of range")
        if os.fstat(f.fileno()).st_size != expected:
            return Check(False, "size_mismatch")
        header = codec.read_exactly(f.read, codec.HEADER_LEN)
        if not codec.is_streaming_format(header):
            return Check(False, "format_mismatch: not a v2 container")
        try:
            h = codec.decode_header(header)
        except codec.CodecError as e:
            return Check(False, f"bad_header: {e}")
        if nonce_hex is not None and not hmac.compare_digest(h.nonce_prefix.hex(), nonce_hex.lower()):
            return Check(False, "nonce_mismatch")
        try:
            dec = codec.StreamDecryptor(kek, header)
        except codec.CodecUnwrapError as e:
            return Check(False, "slot_corrupt" if e.kek_id_matches else "wrong_kek")
        hasher = hashlib.sha256()
        try:
            for seg in codec.iter_segments(f.read):
                hasher.update(dec.update(seg))
            dec.finalize()
        except codec.CodecIntegrityError as e:
            return Check(False, f"integrity: {e}")
    digest = hasher.hexdigest()
    if sha256 and not hmac.compare_digest(digest, sha256.lower()):
        return Check(False, "hash_mismatch", digest, dec.kek_id_matches)
    return Check(True, None, digest, dec.kek_id_matches)


def _decrypt_v0(path: Path, kek: bytes, nonce_hex: str, size: Optional[int]) -> bytes:
    """Whole-file v0 decrypt (raw KEK, 96-bit nonce from the row). Raises ValueError(reason)."""
    with open(path, "rb") as f:
        ct = f.read()
    if size is not None and len(ct) != size + 16:
        raise ValueError("size_mismatch")
    if codec.is_streaming_format(ct[:len(codec.MAGIC)]):
        raise ValueError("format_mismatch: v0 row, v2 file")
    try:
        return AESGCM(kek).decrypt(bytes.fromhex(nonce_hex), ct, None)
    except InvalidTag:
        raise ValueError("tag: does not open with this KEK, or the file is corrupt") from None


# ─── Inventory ────────────────────────────────────────────────────────────────────────────────

@dataclass
class Item:
    consumer: str                     # evidence | photo | file | artifact
    row_id: str
    photo_id: Optional[str]
    incident_id: Optional[str]
    rel: str
    nonce_hex: Optional[str]
    size: Optional[int]
    sha256: Optional[str]
    entity_id: Optional[str] = None
    # outcome
    action: str = ""
    result: str = ""
    reason: Optional[str] = None
    warnings: list = field(default_factory=list)
    nonce_hex_after: Optional[str] = None
    at: Optional[str] = None

    @property
    def store(self) -> str:
        return {"file": "files", "artifact": "quarantine"}.get(self.consumer, "evidence")

    @property
    def root(self) -> Path:
        return Path({"file": settings.logs_path, "artifact": settings.quarantine_path}
                    .get(self.consumer, settings.evidence_path))

    @property
    def plain(self) -> bool:
        """H1: a legacy plaintext quarantine artifact (nonce_hex NULL): no KEK involved; refused."""
        return self.consumer == "artifact" and self.nonce_hex is None

    @property
    def key(self) -> tuple:
        return (self.consumer, self.row_id, self.photo_id)

    @property
    def fmt(self) -> Optional[int]:
        return store.row_format(self.nonce_hex)

    def report(self) -> dict:
        return {"consumer": self.consumer, "id": self.row_id, "photo_id": self.photo_id,
                "incident_id": self.incident_id, "store": self.store, "path": self.rel,
                "format_before": None if self.fmt is None else f"v{self.fmt}", "action": self.action,
                "result": self.result, "reason": self.reason, "warnings": self.warnings,
                "nonce_hex_before": self.nonce_hex, "nonce_hex_after": self.nonce_hex_after, "at": self.at}


@dataclass
class KeyRow:
    row_id: str
    incident_id: Optional[str]
    wrapped: str
    action: str = ""
    result: str = ""
    reason: Optional[str] = None
    at: Optional[str] = None

    @property
    def key(self) -> tuple:
        return ("collector", self.row_id, None)

    def report(self) -> dict:
        return {"consumer": "collector", "id": self.row_id, "incident_id": self.incident_id,
                "action": self.action, "result": self.result, "reason": self.reason, "at": self.at}


CONSUMERS = ("evidence", "photo", "file", "artifact")
PLAIN_REASON = ("plain: a legacy plaintext quarantine file, under no KEK; migrate first "
                "(python -m artifacts.encrypt_quarantine --apply)")


def _s(v) -> Optional[str]:
    return None if v is None else str(v)


async def load_items(db) -> list[Item]:
    items: list[Item] = []
    for r in (await db.execute(select(Evidence.id, Evidence.incident_id, Evidence.storage_path,
                                      Evidence.nonce_hex, Evidence.file_size_bytes, Evidence.sha256)
                               .where(Evidence.storage_path.isnot(None)))).all():
        items.append(Item("evidence", str(r.id), None, _s(r.incident_id), r.storage_path, r.nonce_hex,
                          r.file_size_bytes, r.sha256))
    # ROT-H2: a destroyed exhibit's photos were deleted with it (their refs are cleared at destroy since
    # G-fix; rows destroyed before still carry them): they are not stored files any more.
    for r in (await db.execute(select(Evidence.id, Evidence.incident_id, Evidence.photos)
                               .where(Evidence.status != "destroyed"))).all():
        for p in (r.photos or []):
            if isinstance(p, dict) and p.get("storage_path"):
                items.append(Item("photo", str(r.id), _s(p.get("id")), _s(r.incident_id), p["storage_path"],
                                  p.get("nonce_hex"), p.get("size"), p.get("sha256")))
    for r in (await db.execute(select(EntityFile.id, EntityFile.incident_id, EntityFile.entity_id,
                                      EntityFile.file_path, EntityFile.nonce_hex, EntityFile.file_size,
                                      EntityFile.report_sha256))).all():
        items.append(Item("file", str(r.id), None, _s(r.incident_id), r.file_path, r.nonce_hex,
                          r.file_size, r.report_sha256, entity_id=_s(r.entity_id)))
    for r in (await db.execute(select(Artifact.id, Artifact.incident_id, Artifact.stored_filename,
                                      Artifact.nonce_hex, Artifact.file_size, Artifact.sha256_hash))).all():
        items.append(Item("artifact", str(r.id), None, _s(r.incident_id), f"{r.incident_id}/{r.stored_filename}",
                          r.nonce_hex, r.file_size, r.sha256_hash))
    items.sort(key=lambda i: (CONSUMERS.index(i.consumer), i.rel, i.row_id))
    return items


async def load_key_rows(db) -> list[KeyRow]:
    rows = (await db.execute(select(CollectionPackage.id, CollectionPackage.incident_id,
                                    CollectionPackage.enc_private_key)
                             .where(CollectionPackage.enc_private_key.isnot(None)))).all()
    return sorted((KeyRow(str(r.id), _s(r.incident_id), r.enc_private_key) for r in rows), key=lambda k: k.row_id)


async def load_ledger(db, new_kid: str) -> dict[tuple, list[dict]]:
    """Custody/audit rows this tool wrote for items now under NEW, keyed by item. Decides whether
    an item already under NEW still needs its record, and (breach) whether its data key is fresh."""
    rows = (await db.execute(select(AuditLog.details).where(
        AuditLog.action.in_(sorted(set(REKEY_ACTIONS.values())))))).scalars().all()
    ledger: dict[tuple, list[dict]] = {}
    for d in rows:
        if isinstance(d, dict) and d.get("kek_id_after") == new_kid:
            ledger.setdefault((d.get("consumer"), d.get("row_id"), d.get("photo_id")), []).append(d)
    return ledger


def _ledger_done(ledger, key, breach: bool, nonce_hex: Optional[str]) -> bool:
    for d in ledger.get(key, []):
        if not breach:
            return True
        if d.get("mode") == "breach" and (nonce_hex is None or d.get("nonce_hex_after") == nonce_hex):
            return True
    return False


def scan_orphans(items: list[Item]) -> list[str]:
    """v2 containers (and v0 `.nonce` sidecars) on disk that no row references: they would be left
    under OLD. Reported, never touched. Journals are skipped by content (journal_class), not by name."""
    known = {(i.store, str(Path(i.rel))) for i in items}
    out = []
    for name, root in (("evidence", Path(settings.evidence_path)), ("files", Path(settings.logs_path)),
                       ("quarantine", Path(settings.quarantine_path))):
        if not root.is_dir():
            continue
        for dirpath, dirs, files in os.walk(root):
            if Path(dirpath) == root:
                dirs[:] = [d for d in dirs if d != store.STAGING_DIR]
            for n in files:
                p = Path(dirpath) / n
                rel = str(p.relative_to(root))
                if n.endswith(".nonce") and name == "evidence":
                    if (name, rel[:-len(".nonce")]) not in known:
                        out.append(f"{name}:{rel}")
                    continue
                if (name, rel) in known or n == LOCK_NAME or journal_class(p) in _JOURNAL_CLASSES:
                    continue
                try:
                    with open(p, "rb", buffering=0) as f:
                        if codec.is_streaming_format(f.read(len(codec.MAGIC))):
                            out.append(f"{name}:{rel}")
                except OSError:
                    continue
    return sorted(out)


# ─── Classification (shared by plan and rotate) ───────────────────────────────────────────────

@dataclass
class Keys:
    old: Optional[bytes]
    new: bytes
    breach: bool = False
    # ROT-L6: this run resumes an unfinished `rotate` to the same NEW (its lock is still there). Only then is
    # a file that already opens with NEW but has no custody row one this tool re-wrapped before a crash
    # ("record"); otherwise it was written under NEW after the swap and has nothing to record ("done").
    resume: bool = False


def classify(item: Item, keys: Keys, ledger) -> None:
    """Set item.action (+ reason / warnings). Reads at most the header and first segment of v2."""
    item.warnings = []
    if item.plain:
        item.action, item.reason = "failed", PLAIN_REASON
        return
    if item.fmt is None:
        item.action, item.reason = "failed", "malformed_row: nonce_hex is not 14 or 24 hex"
        return
    try:
        path = _resolve(item.root, item.rel)
    except ValueError as e:
        item.action, item.reason = "failed", f"invalid_path: {e}"
        return
    if not os.path.lexists(path):
        item.action, item.reason = "attention", "file_missing"
        return
    if item.fmt == 0:
        if item.size is None:
            item.action, item.reason = "failed", "malformed_row: no plaintext size (v2 needs one)"
        elif os.path.getsize(path) != item.size + 16:
            item.action, item.reason = "failed", "size_mismatch"
        else:
            item.action = "migrate"            # v0 is never under NEW: this tool writes only v2
        return
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        item.action, item.reason = "failed", f"io_error: {e.strerror}"
        return
    try:
        header, seg0 = _read_head(fd)
        on_disk = os.fstat(fd).st_size
    finally:
        os.close(fd)
    if not codec.is_streaming_format(header):
        item.action, item.reason = "failed", "format_mismatch: v2 row, file has no FENRGCM header"
        return
    prefix_ok = len(header) >= 19 and header[12:19].hex() == (item.nonce_hex or "").lower()
    try:
        size_ok = isinstance(item.size, int) and on_disk == codec.container_size(item.size)
    except ValueError:
        size_ok = False
    if not prefix_ok:
        item.warnings.append("nonce_mismatch")
    if not size_ok:
        item.warnings.append("size_mismatch")
    with_new = opens(keys.new, header, seg0)
    with_old = opens(keys.old, header, seg0) if keys.old and with_new is None else None
    if keys.breach and (with_new is not None or with_old is not None):
        if with_new is not None and _ledger_done(ledger, item.key, True, item.nonce_hex):
            item.action = "done" if with_new else "attention"
            item.reason = None if with_new else "kek_id_mismatch: opens with NEW, advisory id names another KEK"
        elif not (prefix_ok and size_ok):
            item.action, item.reason = "failed", "refusing to re-encrypt: " + ", ".join(item.warnings)
        else:
            item.action = "reencrypt"
            if (with_new if with_new is not None else with_old) is False:
                item.warnings.append("kek_id_altered")
        return
    if with_new is not None:                                       # §6.4 step 2
        if not with_new:                                           # R-6: never skip silently
            item.action, item.reason = "attention", "kek_id_mismatch: opens with NEW, advisory id names another KEK"
        elif _ledger_done(ledger, item.key, False, None):
            item.action = "done"
        elif keys.resume:
            item.action = "record"
        else:                                                      # ROT-L6: never under OLD as far as we know
            item.action, item.reason = "done", "opens with NEW, no rotation record: written under NEW, nothing to record"
        return
    if with_old is None:                                           # §6.4 step 3
        item.action = "failed"
        item.reason = "cannot_open: neither key opens the key slot and first chunk" if keys.old else \
                      "does not open with NEW"
        return
    item.action = "rewrap"
    if with_old is False:
        item.warnings.append("kek_id_altered")


def classify_key(k: KeyRow, keys: Keys, ledger) -> Optional[bytes]:
    """Set k.action; return the plaintext when it must be re-encrypted."""
    try:
        nonce_hex, b64 = k.wrapped.split(":", 1)
        nonce, ct = bytes.fromhex(nonce_hex), base64.b64decode(b64, validate=True)
    except (ValueError, TypeError):
        k.action, k.reason = "failed", "malformed: not \"nonce_hex:base64\""
        return None
    for key, name in ((keys.new, "new"), (keys.old, "old")):
        if key is None:
            continue
        try:
            pt = AESGCM(key).decrypt(nonce, ct, None)
        except (InvalidTag, ValueError):            # ValueError: a nonce that is not 12 bytes
            continue
        if name == "new" and _ledger_done(ledger, k.key, keys.breach, None):
            k.action = "done"
            return None
        if name == "new" and not keys.breach:
            if keys.resume:
                k.action = "record"
            else:                                       # ROT-L6: created under NEW, nothing to record
                k.action, k.reason = "done", "opens with NEW, no rotation record: written under NEW, nothing to record"
            return None
        k.action = "reencrypt"
        return pt
    k.action, k.reason = "failed", "opens with neither key"
    return None


# ─── §6.4 re-wrap ─────────────────────────────────────────────────────────────────────────────

def keyslot_journal(header: bytes, new_header: bytes) -> bytes:
    body = KSJ_MAGIC + header[:32] + header[32:80] + new_header[32:80]
    return body + hashlib.sha256(body).digest()


def parse_keyslot_journal(data: bytes) -> Optional[tuple[bytes, bytes, bytes]]:
    if (len(data) != KSJ_LEN or data[:8] != KSJ_MAGIC
            or not hmac.compare_digest(hashlib.sha256(data[:136]).digest(), data[136:])):
        return None
    return data[8:40], data[40:88], data[88:136]


def rewrap_file(path: Path, old: bytes, new: bytes) -> str:
    """Re-wrap one v2 file's key slot, journalled (§6.4 steps 1–7). Returns "rewrapped",
    "already" or "cannot_open". Raises ManualStop once a journal exists and something is wrong."""
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)   # never a truncating mode
    try:
        header, seg0 = _read_head(fd)                                # 1
        if opens(new, header, seg0) is not None:                     # 2 (decided by unwrap, not kek_id)
            return "already"
        if opens(old, header, seg0) is None:                         # 3 verify before touching anything
            return "cannot_open"
        new_header = codec.rewrap_header(header, old, new)           # 4
        if opens(new, new_header, seg0) is None:
            return "cannot_open"
        journal = path.with_name(path.name + KEYSLOT)
        if os.path.lexists(journal) or os.path.lexists(journal.with_name(journal.name + TMP)):
            raise ManualStop(f"{journal}: a journal already exists; run recover")
        _write_durable(journal, keyslot_journal(header, new_header))  # 5
        try:
            _pwrite_slot(fd, new_header[codec.KEY_SLOT_OFFSET:])     # 6
            header2, seg02 = _read_head(fd)                          # 7
            if header2 != new_header or opens(new, header2, seg02) is None:
                raise ManualStop(f"{path}: the new key slot did not verify after the write; journal kept, run recover")
            _unlink_durable(journal)
        except ManualStop:
            raise
        except Exception as e:
            raise ManualStop(f"{path}: {type(e).__name__} after the journal was written ({e}); "
                             "journal kept, run recover") from e
        return "rewrapped"
    finally:
        os.close(fd)


def recover_keyslot(journal: Path, old: Optional[bytes], new: bytes, apply: bool) -> tuple[str, str]:
    """§6.4 recovery (R-1) for one <file>.keyslot. Returns (outcome, detail); outcome "manual"
    means nothing was written. Never writes a slot that has not verified in memory."""
    target = journal.with_name(journal.name[:-len(KEYSLOT)])
    try:
        with open(journal, "rb") as f:
            data = f.read(KSJ_LEN + 1)
    except OSError as e:
        return "manual", f"cannot read the journal ({e.strerror})"
    parsed = parse_keyslot_journal(data)
    if parsed is None:                                               # 1
        return "manual", "journal torn or corrupt (wrong length, magic or SHA-256): media corruption, not a crash; file not touched"
    imm, old_slot, new_slot = parsed
    if old is None:
        return "manual", "recovery needs both keys (--old-kek-file and --new-kek-file)"
    try:
        fd = os.open(target, (os.O_RDWR if apply else os.O_RDONLY) | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        return "manual", f"cannot open the file the journal names ({e.strerror})"
    try:
        header, seg0 = _read_head(fd)
        if len(header) != codec.HEADER_LEN or header[:32] != imm:   # 2
            return "manual", "the file's bytes 0-31 differ from the journal's (wrong file)"
        if (not hmac.compare_digest(old_slot[1:8], codec.kek_id(old))       # 3
                or not hmac.compare_digest(new_slot[1:8], codec.kek_id(new))):
            return "manual", (f"journal key ids (old {old_slot[1:8].hex()}, new {new_slot[1:8].hex()}) do not "
                              f"match the supplied keys (old {kid(old)}, new {kid(new)}); nothing written")
        if opens(new, header, seg0) is not None:                     # 4 the run had finished
            if apply:
                _unlink_durable(journal)
            return "finished", "file already opens with NEW; journal removed"
        for slot, key, outcome in ((new_slot, new, "rolled_forward"), (old_slot, old, "rolled_back")):   # 5
            if opens(key, imm + slot, seg0) is None:
                continue
            if apply:
                _pwrite_slot(fd, slot)
                header2, seg02 = _read_head(fd)
                if header2 != imm + slot or opens(key, header2, seg02) is None:
                    return "manual", "the slot written did not verify from disk; journal kept"
                _unlink_durable(journal)
            return outcome, ("NEW slot restored" if key is new else "OLD slot restored; redone in the next pass")
        return "manual", "neither journal slot opens the file's first chunk; nothing written"   # 6
    finally:
        os.close(fd)


# ─── §5.4 rewrite (v0 → v2 migration, v2 → v2 re-encrypt) ──────────────────────────────────────

def rewrite_journal(fields: dict) -> bytes:
    body = RWJ_MAGIC + b"\n" + json.dumps(fields, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    return body + hashlib.sha256(body).hexdigest().encode() + b"\n"


_RWJ_FIELDS = {"v", "consumer", "row_id", "photo_id", "target", "old_marker", "new_prefix", "staging",
               "kek_id_new", "mode", "run_id", "at"}


def parse_rewrite_journal(data: bytes) -> Optional[dict]:
    if not data.startswith(RWJ_MAGIC + b"\n") or len(data) < 80 or not data.endswith(b"\n"):
        return None
    body, digest = data[:-65], data[-65:-1]
    if not hmac.compare_digest(hashlib.sha256(body).hexdigest().encode(), digest):
        return None
    try:
        fields = json.loads(body[len(RWJ_MAGIC) + 1:-1])
    except ValueError:
        return None
    if not isinstance(fields, dict) or set(fields) != _RWJ_FIELDS or fields["v"] != 1:
        return None
    if (fields["consumer"] not in CONSUMERS or not STAGE_RE.fullmatch(str(fields["staging"]))
            or store.row_format(fields["new_prefix"]) != 2 or store.row_format(fields["old_marker"]) is None):
        return None
    return fields


def _chunked_encrypt(fd: int, enc: codec.StreamEncryptor, blocks: Iterable[bytes], hasher) -> int:
    """Feed plaintext pieces of any size; every full CHUNK_SIZE block is a non-final chunk, the
    remainder (possibly empty) the final chunk (§2.3, no look-ahead). Returns the plaintext length."""
    buf, n, cs = bytearray(), 0, codec.CHUNK_SIZE
    for b in blocks:
        mv = memoryview(b).cast("B")
        hasher.update(mv)
        n += len(mv)
        if buf:
            take = cs - len(buf)
            buf += mv[:take]
            mv = mv[take:]
            if len(buf) < cs:
                continue
            _write_all(fd, enc.update(bytes(buf)))
            buf.clear()
        while len(mv) >= cs:
            _write_all(fd, enc.update(mv[:cs]))
            mv = mv[cs:]
        buf += mv
    _write_all(fd, enc.finalize(bytes(buf)))
    return n


def _v2_plaintext(path: Path, key: bytes) -> Iterator[bytes]:
    with open(path, "rb") as f:
        dec = codec.StreamDecryptor(key, codec.read_exactly(f.read, codec.HEADER_LEN))
        for seg in codec.iter_segments(f.read):
            yield dec.update(seg)
        dec.finalize()


def stage_rewrite(item: Item, src_key: bytes, new: bytes) -> tuple[Path, str]:
    """§5.4 steps 1–2: decrypt the current file, write a fresh v2 container under NEW to
    <root>/.staging/rot-<hex>.partial (fsynced), then decrypt the staged file and check its
    plaintext against the source and the recorded SHA-256 / size. Returns (staged, new_prefix).
    Raises ValueError(reason) and leaves nothing behind when a check fails."""
    target = _resolve(item.root, item.rel)
    staging = item.root / store.STAGING_DIR
    staging.mkdir(mode=0o700, exist_ok=True)
    staged = staging / f"rot-{uuid.uuid4().hex}.partial"
    if item.fmt == 0:
        blocks: Iterable[bytes] = [_decrypt_v0(target, src_key, item.nonce_hex, item.size)]
    else:
        chk = check_v2(target, src_key, item.nonce_hex, item.size, None)   # size + Q5 + every chunk
        if not chk.ok:
            raise ValueError(f"source {chk.reason}")
        blocks = _v2_plaintext(target, src_key)
    fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    try:
        try:
            enc = codec.StreamEncryptor(new)
            _write_all(fd, enc.header)
            src_hash = hashlib.sha256()
            n = _chunked_encrypt(fd, enc, blocks, src_hash)
            os.fsync(fd)
        finally:
            os.close(fd)
        src_sha = src_hash.hexdigest()
        if item.sha256 and not hmac.compare_digest(src_sha, item.sha256.lower()):
            raise ValueError("hash_mismatch: the source plaintext does not match the recorded SHA-256")
        if item.size is not None and n != item.size:
            raise ValueError("size_mismatch: the source plaintext length differs from the row")
        prefix = codec.decode_header(enc.header).nonce_prefix.hex()
        chk = check_v2(staged, new, prefix, n, src_sha)                  # step 2, before the swap
        if not chk.ok:
            raise ValueError(f"staged copy did not verify ({chk.reason})")
    except BaseException:
        try:
            os.unlink(staged)
        except FileNotFoundError:
            pass
        raise
    return staged, prefix


async def commit_rewrite(sessions, item: Item, old_marker: str, new_prefix: str, details: dict) -> str:
    """§5.4 step 5: in one transaction, set the row's nonce_hex to the new prefix and write the
    custody/audit row. Returns "committed" or "already"; ManualStop if the row holds neither."""
    async with sessions() as db, db.begin():
        if item.consumer == "file":
            row = await db.get(EntityFile, uuid.UUID(item.row_id), with_for_update=True)
            current, path = (row.nonce_hex, row.file_path) if row else (None, None)
        elif item.consumer == "artifact":
            row = await db.get(Artifact, uuid.UUID(item.row_id), with_for_update=True)
            current, path = (row.nonce_hex, f"{row.incident_id}/{row.stored_filename}") if row else (None, None)
        else:
            row = await db.get(Evidence, uuid.UUID(item.row_id), with_for_update=True)
            if row is None:
                current = path = None
            elif item.consumer == "evidence":
                current, path = row.nonce_hex, row.storage_path
            else:
                entry = next((p for p in (row.photos or []) if isinstance(p, dict) and str(p.get("id")) == item.photo_id), None)
                current, path = (entry.get("nonce_hex"), entry.get("storage_path")) if entry else (None, None)
        if path != item.rel:
            raise ManualStop(f"{item.consumer} {item.row_id}: the row no longer names {item.rel!r}; journal kept")
        if current == new_prefix:
            return "already"
        if current != old_marker:
            raise ManualStop(f"{item.consumer} {item.row_id}: the row's nonce_hex is neither the old marker nor "
                             "the new prefix; journal kept")
        if item.consumer in ("file", "artifact"):
            row.nonce_hex = new_prefix
        elif item.consumer == "evidence":
            row.nonce_hex = new_prefix
        else:
            photos = [dict(p) if isinstance(p, dict) else p for p in row.photos]
            for p in photos:
                if isinstance(p, dict) and str(p.get("id")) == item.photo_id:
                    p["nonce_hex"] = new_prefix
            row.photos = photos
        await _audit_item(db, details)
    return "committed"


def _sidecar(item: Item, target: Path) -> Optional[Path]:
    """The v0 `.nonce` sidecar (evidence store only)."""
    return target.with_name(target.name + ".nonce") if item.store == "evidence" else None


async def rewrite_item(sessions, item: Item, src_key: bytes, keys: Keys, run: "Run") -> None:
    """§5.4 steps 1–6 for one file. Sets item.result; ManualStop after the journal exists."""
    operation = "migrate" if item.fmt == 0 else "reencrypt"
    try:
        staged, new_prefix = stage_rewrite(item, src_key, keys.new)      # 1–2
    except (ValueError, OSError, codec.CodecError) as e:
        item.result, item.reason = "failed", str(e)
        return
    target = _resolve(item.root, item.rel)
    journal = target.with_name(target.name + REWRITE)
    fields = {"v": 1, "consumer": item.consumer, "row_id": item.row_id, "photo_id": item.photo_id,
              "target": item.rel, "old_marker": item.nonce_hex, "new_prefix": new_prefix,
              "staging": staged.name, "kek_id_new": kid(keys.new), "mode": run.mode, "run_id": run.id,
              "at": now()}
    if os.path.lexists(journal) or os.path.lexists(journal.with_name(journal.name + TMP)):
        os.unlink(staged)
        raise ManualStop(f"{journal}: a journal already exists; run recover")
    try:
        _write_durable(journal, rewrite_journal(fields))                   # 3
    except BaseException:
        os.unlink(staged)
        raise
    try:
        _rename_into_place(staged, target)                                 # 4
        details = run.details(item, operation, src_key, keys.new, new_prefix, sha_verified=bool(item.sha256))
        await commit_rewrite(sessions, item, item.nonce_hex, new_prefix, details)   # 5
        side = _sidecar(item, target)                                      # 6
        if side is not None:
            _unlink_durable(side)
        _unlink_durable(journal)
    except ManualStop:
        raise
    except Exception as e:
        raise ManualStop(f"{target}: {type(e).__name__} after the rewrite journal was written ({e}); "
                         "journal kept, run recover") from e
    item.result, item.nonce_hex_after = operation, new_prefix


async def _load_row_for(sessions, consumer: str, row_id: str, photo_id: Optional[str]) -> Optional[Item]:
    async with sessions() as db:
        if consumer == "file":
            r = await db.get(EntityFile, uuid.UUID(row_id))
            return None if r is None else Item("file", row_id, None, _s(r.incident_id), r.file_path, r.nonce_hex,
                                               r.file_size, r.report_sha256, entity_id=_s(r.entity_id))
        if consumer == "artifact":
            r = await db.get(Artifact, uuid.UUID(row_id))
            return None if r is None else Item("artifact", row_id, None, _s(r.incident_id),
                                               f"{r.incident_id}/{r.stored_filename}", r.nonce_hex, r.file_size,
                                               r.sha256_hash)
        r = await db.get(Evidence, uuid.UUID(row_id))
        if r is None:
            return None
        if consumer == "evidence":
            return Item("evidence", row_id, None, _s(r.incident_id), r.storage_path, r.nonce_hex,
                        r.file_size_bytes, r.sha256)
        p = next((p for p in (r.photos or []) if isinstance(p, dict) and str(p.get("id")) == photo_id), None)
        return None if p is None else Item("photo", row_id, photo_id, _s(r.incident_id), p.get("storage_path"),
                                           p.get("nonce_hex"), p.get("size"), p.get("sha256"))


async def recover_rewrite(sessions, journal: Path, root: Path, keys: Keys, run: "Run",
                          apply: bool) -> tuple[str, str]:
    """§5.4 recovery for one <file>.rewrite: reconcile from the prefix on disk. Commits the row
    only after the renamed file has verified under NEW against the row's size and hash."""
    try:
        with open(journal, "rb") as f:
            fields = parse_rewrite_journal(f.read(65536))
    except OSError as e:
        return "manual", f"cannot read the journal ({e.strerror})"
    if fields is None:
        return "manual", "journal torn or corrupt (magic, fields or SHA-256): nothing written"
    if not hmac.compare_digest(str(fields["kek_id_new"]), kid(keys.new)):
        return "manual", (f"journal was written for NEW id {fields['kek_id_new']}, the supplied NEW is {kid(keys.new)}; "
                          "nothing written")
    target = journal.with_name(journal.name[:-len(REWRITE)])
    try:
        if _resolve(root, fields["target"]) != target.resolve():
            return "manual", "the journal names another file than the one it sits next to"
    except ValueError:
        return "manual", "the journal's target escapes its store"
    item = await _load_row_for(sessions, fields["consumer"], fields["row_id"], fields["photo_id"])
    if item is None or item.rel != fields["target"] or item.root.resolve() != root.resolve():
        return "manual", "no row names this file (deleted or changed); nothing written"
    staged = root / store.STAGING_DIR / fields["staging"]
    try:
        with open(target, "rb") as f:
            head = f.read(codec.HEADER_LEN)
    except OSError as e:
        return "manual", f"cannot read the target ({e.strerror})"
    is_v2 = codec.is_streaming_format(head) and len(head) == codec.HEADER_LEN
    prefix = head[12:19].hex() if is_v2 else None
    old, new_prefix = fields["old_marker"], fields["new_prefix"]
    if prefix == new_prefix:                                   # the rename happened
        chk = check_v2(target, keys.new, new_prefix, item.size, item.sha256)
        if not chk.ok:
            return "manual", f"the renamed file does not verify under NEW ({chk.reason}); nothing written"
        if item.nonce_hex not in (old, new_prefix):
            return "manual", "the row holds neither the old marker nor the new prefix; nothing written"
        if not apply:
            return "complete", "would commit the row and remove the journal"
        if item.nonce_hex == old:
            src_fmt = store.row_format(old)
            details = run.details(item, "migrate" if src_fmt == 0 else "reencrypt", None, keys.new, new_prefix,
                                  sha_verified=bool(item.sha256), recovered=True, mode=fields["mode"])
            await commit_rewrite(sessions, item, old, new_prefix, details)
        side = _sidecar(item, target)
        if side is not None:
            _unlink_durable(side)
        _unlink_durable(staged)
        _unlink_durable(journal)
        return "completed", "rename had happened: row committed / confirmed, journal removed"
    carries_old = (prefix == old) if store.row_format(old) == 2 else (not codec.is_streaming_format(head))
    if carries_old:                                            # the rename did not happen
        if item.nonce_hex != old:
            return "manual", "the file still carries the old marker but the row does not; nothing written"
        if apply:
            _unlink_durable(staged)
            _unlink_durable(journal)
        return "undone", "rename had not happened: staged copy and journal removed; redone in the next pass"
    return "manual", "the file carries neither the old marker nor the new prefix; nothing written"


# ─── Journal discovery and the recovery pass ──────────────────────────────────────────────────

def roots() -> list[Path]:
    return [Path(settings.evidence_path), Path(settings.logs_path), Path(settings.quarantine_path)]


# Journal-named files, longest suffix first (a ".keyslot.tmp" is a temporary journal, not a journal).
_JOURNAL_NAMES = ((KEYSLOT + TMP, "keyslot_tmp", KSJ_MAGIC), (REWRITE + TMP, "rewrite_tmp", RWJ_MAGIC),
                  (KEYSLOT, "keyslot", KSJ_MAGIC), (REWRITE, "rewrite", RWJ_MAGIC))
_JOURNAL_CLASSES = ("keyslot", "keyslot_tmp", "rewrite", "rewrite_tmp")


def journal_class(path: Path) -> Optional[str]:
    """What a file is by name AND content (R3-1; an 8-byte O_NOFOLLOW read): "keyslot" / "rewrite" for a
    journal (starts with its magic), "keyslot_tmp" / "rewrite_tmp" for a temporary journal never renamed
    into place (the magic, or a torn prefix of it, incl. empty), "unrecognised" for a file only named like
    one, None for any other name."""
    for suffix, key, magic in _JOURNAL_NAMES:
        if path.name.endswith(suffix):
            head = store.read_head(path, len(magic))
            if head is None:
                return "unrecognised"
            if key.endswith("_tmp"):
                return key if magic.startswith(head) else "unrecognised"
            return key if head == magic else "unrecognised"
    return None


async def referenced_paths(sessions) -> frozenset[str]:
    """Every stored-file path a DB row names (evidence files, evidence photos, entity / incident files),
    resolved. Such a path is never a journal, whatever its name and content (R3-1)."""
    out: set[str] = set()
    evid, logs = Path(settings.evidence_path), Path(settings.logs_path)
    async with sessions() as db:
        for (rel,) in (await db.execute(select(Evidence.storage_path).where(Evidence.storage_path.isnot(None)))).all():
            out.add(os.path.realpath(evid / rel))
        for (photos,) in (await db.execute(select(Evidence.photos))).all():
            for ph in (photos or []):
                if isinstance(ph, dict) and ph.get("storage_path"):
                    out.add(os.path.realpath(evid / ph["storage_path"]))
        for (rel,) in (await db.execute(select(EntityFile.file_path))).all():
            if rel:
                out.add(os.path.realpath(logs / rel))
        quar = Path(settings.quarantine_path)
        for inc, name in (await db.execute(select(Artifact.incident_id, Artifact.stored_filename))).all():
            out.add(os.path.realpath(quar / str(inc) / name))
    return frozenset(out)


def find_journals(referenced: frozenset = frozenset()) -> dict[str, list[Path]]:
    """Journals, temporary journals and this tool's staged copies under both stores, recognised by
    content (journal_class); "unrecognised" = files only named like a journal. A path in `referenced`
    (referenced_paths) is never any of these."""
    found = {"keyslot": [], "keyslot_tmp": [], "rewrite": [], "rewrite_tmp": [], "unrecognised": [], "staged": []}
    for root in roots():
        if not root.is_dir():
            continue
        for dirpath, dirs, files in os.walk(root):
            here = Path(dirpath)
            if here == root and store.STAGING_DIR in dirs:
                dirs.remove(store.STAGING_DIR)
                found["staged"] += sorted(p for p in (root / store.STAGING_DIR).iterdir()
                                          if STAGE_RE.fullmatch(p.name))
            for n in files:
                p = here / n
                kind = journal_class(p)
                if kind is not None and os.path.realpath(p) not in referenced:
                    found[kind].append(p)
    for v in found.values():
        v.sort()
    return found


def _root_of(path: Path) -> Path:
    for r in roots():
        if path.resolve().is_relative_to(r.resolve()):
            return r
    raise ValueError(f"{path} is outside the stores")


async def recovery_pass(sessions, keys: Keys, run: "Run", apply: bool,
                        referenced: Optional[frozenset] = None) -> list[dict]:
    """§6.4 + §5.4 recovery, before anything else. Returns one record per journal / stray file."""
    out = []
    if referenced is None:
        referenced = await referenced_paths(sessions)
    j = find_journals(referenced)
    for p in j["unrecognised"]:                         # R3-1: named like a journal, not one: never touched
        if p.name.endswith(TMP):
            out.append({"journal": str(p), "outcome": "unrecognised_tmp", "at": now(),
                        "detail": "named like a temporary journal but holds no journal magic: reported, never deleted"})
        else:
            out.append({"journal": str(p), "outcome": "manual", "at": now(),
                        "detail": "named like a journal but does not start with the journal magic, and no row "
                                  "references it: a corrupt journal or a foreign file. Nothing written; examine it"})
    for p in j["keyslot_tmp"] + j["rewrite_tmp"]:      # never renamed: its file was never modified
        if apply:
            _unlink_durable(p)
        out.append({"journal": str(p), "outcome": "stray_tmp_removed" if apply else "stray_tmp", "at": now(),
                    "detail": "temporary journal (magic or a torn prefix of it) that was never renamed into place"})
    for p in j["keyslot"]:
        outcome, detail = recover_keyslot(p, keys.old, keys.new, apply)
        out.append({"journal": str(p), "outcome": outcome, "detail": detail, "at": now()})
    for p in j["rewrite"]:
        try:
            outcome, detail = await recover_rewrite(sessions, p, _root_of(p), keys, run, apply)
        except ManualStop as e:
            outcome, detail = "manual", str(e)
        out.append({"journal": str(p), "outcome": outcome, "detail": detail, "at": now()})
    if any(r["outcome"] == "manual" for r in out):     # a manual stop writes nothing more
        apply = False
    staged_refs = set()
    for p in find_journals(referenced)["rewrite"]:      # journals still present after this pass
        try:
            with open(p, "rb") as f:
                fields = parse_rewrite_journal(f.read(65536))
            if fields:
                staged_refs.add(fields["staging"])
        except OSError:
            pass
    for p in j["staged"]:
        if p.name in staged_refs or not p.exists():
            continue
        if apply:
            _unlink_durable(p)
        out.append({"journal": str(p), "outcome": "orphan_staging_removed" if apply else "orphan_staging",
                    "detail": "this tool's staged copy with no journal (crash before step 3)", "at": now()})
    return out


# ─── Lock and stack check ─────────────────────────────────────────────────────────────────────

def read_lock_info() -> Optional[dict]:
    """The JSON a run wrote into the lock (None: no lock, or not readable as an object). Read-only."""
    data = store.read_head(Path(settings.evidence_path) / LOCK_NAME, 65536)
    if not data:
        return None
    try:
        info = json.loads(data)
    except ValueError:
        return None
    return info if isinstance(info, dict) else None


def pending_rotate(info: Optional[dict]) -> Optional[dict]:
    """The unfinished `rotate` a lock belongs to (R3-6 / ROT-L6), else None: written by rotate (command
    "rotate"; a stage-4 lock has "mode" and no command), or by a recover run that kept it for one."""
    if not info:
        return None
    if info.get("command") == "rotate" or ("mode" in info and "command" not in info):
        return info
    prior = info.get("pending_rotate")
    return prior if isinstance(prior, dict) else None


class RotationLock:
    """<evidence_path>/.kek-rotation.lock: created and fsynced (file + directory) and held with an
    exclusive flock before the first journal; the backend's startup gate refuses while it exists.
    `previous` = what the lock held before this run took it (an interrupted run's info, or None)."""

    def __init__(self):
        self.path = Path(settings.evidence_path) / LOCK_NAME
        self.fd: Optional[int] = None
        self.created = False
        self.previous: Optional[dict] = None

    def acquire(self, info: dict) -> None:
        existed = os.path.lexists(self.path)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise Refused(f"{self.path} is held by another running rotation tool") from None
        try:
            prev = json.loads(os.pread(fd, 65536, 0) or b"null")
        except ValueError:
            prev = None
        self.previous = prev if isinstance(prev, dict) else None
        if callable(info):                      # built from what the lock held (recover keeps a pending rotate)
            info = info(self.previous)
        os.ftruncate(fd, 0)
        os.pwrite(fd, (json.dumps(info, sort_keys=True) + "\n").encode(), 0)
        os.fsync(fd)
        _fsync_dir(self.path.parent)
        self.fd, self.created = fd, not existed

    def release(self, delete: bool) -> None:
        if self.fd is None:
            return
        if delete:
            _unlink_durable(self.path)
        os.close(self.fd)
        self.fd = None


async def other_sessions(sessions) -> list[dict]:
    """Other connections to this database as the app role (a running backend keeps a connection
    pool open for its whole life) or the backup role (a dump in progress)."""
    async with sessions() as db:
        rows = (await db.execute(text(
            "SELECT pid, usename, application_name, backend_start FROM pg_stat_activity "
            "WHERE datname = current_database() AND pid <> pg_backend_pid() "
            "AND usename IN (current_user, :backup) ORDER BY pid"), {"backup": BACKUP_ROLE})).all()
    return [{"pid": r.pid, "role": r.usename, "application_name": r.application_name,
             "since": r.backend_start.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
             if r.backend_start else None} for r in rows]


def _sessions_message(rows: list[dict]) -> str:
    return ("other database sessions are open (stop backend and backup first): "
            + "; ".join(f"pid {r['pid']} role {r['role']} app {r['application_name'] or '-'} since {r['since']}"
                        for r in rows))


def make_sessions():
    """A connection per session (NullPool), so this tool never holds a pooled connection that its
    own stack check would count."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool
    from core import database as cdb
    args: dict = {"server_settings": {"application_name": "fenrir-kek-rotation"}}
    ssl = cdb._db_ssl_context()
    if ssl is not None:
        args["ssl"] = ssl
    engine = create_async_engine(settings.database_url, poolclass=NullPool, connect_args=args)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


# ─── Audit / custody records ──────────────────────────────────────────────────────────────────

async def _audit_item(db, details: dict) -> None:
    consumer = details["consumer"]
    await write_audit(db, REKEY_ACTIONS[consumer], username=details["tool_user"], role_at_time="offline-tool",
                      outcome="success", resource_type=RESOURCE_TYPE[consumer], resource_id=details["row_id"],
                      details={k: v for k, v in details.items() if k != "tool_user"},
                      request_id=details["run_id"], request_method="CLI",
                      request_path=f"evidence.rotation {details['command']}")


@dataclass
class Run:
    id: str
    command: str
    mode: str                         # scheduled | breach
    operator: Optional[str]
    old_kid: Optional[str]
    new_kid: str
    started_at: str

    @property
    def tool_user(self) -> str:
        return f"cli:{self.operator or 'unknown'}"[:64]

    def details(self, item, operation: str, src_key: Optional[bytes], new: bytes, nonce_after: Optional[str],
                *, sha_verified, recovered: bool = False, mode: Optional[str] = None) -> dict:
        is_key = isinstance(item, KeyRow)
        d = {"consumer": "collector" if is_key else item.consumer, "row_id": item.row_id,
             "photo_id": None if is_key else item.photo_id, "incident_id": item.incident_id,
             "run_id": self.id, "command": self.command, "mode": mode or self.mode, "operation": operation,
             "operator": self.operator, "tool_user": self.tool_user,
             "kek_id_before": kid(src_key), "kek_id_after": kid(new), "at": now()}
        if not is_key:
            fmt_before = "v0" if item.fmt == 0 else "v2"
            d.update({"storage_path": item.rel, "format_before": fmt_before, "format_after": "v2",
                      "nonce_hex_before": item.nonce_hex, "nonce_hex_after": nonce_after or item.nonce_hex,
                      "sha256_verified": sha_verified if item.sha256 else "not_recorded"})
            if item.entity_id:
                d["entity_id"] = item.entity_id
        if recovered:
            d["recovered"] = True
        return d


async def write_summary(sessions, run: Run, action: str, outcome: str, extra: dict) -> None:
    async with sessions() as db, db.begin():
        await write_audit(db, action, username=run.tool_user, role_at_time="offline-tool", outcome=outcome,
                          resource_type="evidence_kek", resource_id=run.id,
                          details={"run_id": run.id, "command": run.command, "mode": run.mode,
                                   "operator": run.operator, "kek_id_old": run.old_kid, "kek_id_new": run.new_kid,
                                   "started_at": run.started_at, "finished_at": now(), **extra},
                          request_id=run.id, request_method="CLI", request_path=f"evidence.rotation {run.command}")


# ─── Output ───────────────────────────────────────────────────────────────────────────────────

def table(items: list[Item], keyrows: list[KeyRow], field_name: str) -> str:
    rows = []
    for name, group in (("evidence files", [i for i in items if i.consumer == "evidence"]),
                        ("evidence photos", [i for i in items if i.consumer == "photo"]),
                        ("entity/incident files", [i for i in items if i.consumer == "file"]),
                        ("quarantine artifacts", [i for i in items if i.consumer == "artifact"]),
                        ("collector keys", keyrows)):
        c = Counter(getattr(i, field_name) for i in group)
        warn = sum(1 for i in group if getattr(i, "warnings", None))
        rows.append((name, len(group), *(c.get(col, 0) for col in COLUMNS), warn))
    head = ("consumer", "total", *COLUMNS, "warn")
    widths = [max(len(str(r[i])) for r in rows + [head]) for i in range(len(head))]
    fmt = "  ".join(f"{{:<{widths[0]}}}" if i == 0 else f"{{:>{w}}}" for i, w in enumerate(widths))
    lines = [fmt.format(*head)] + [fmt.format(*r) for r in rows]
    for i in items:
        if getattr(i, field_name) in ("attention", "failed") or i.warnings:
            lines.append(f"  {getattr(i, field_name):9s} {i.consumer} {i.row_id}"
                         f"{'/' + i.photo_id if i.photo_id else ''} {i.store}:{i.rel}  "
                         f"{i.reason or ''}{' warnings=' + ','.join(i.warnings) if i.warnings else ''}")
    for k in keyrows:
        if getattr(k, field_name) in ("attention", "failed"):
            lines.append(f"  {getattr(k, field_name):9s} collector {k.row_id}  {k.reason or ''}")
    return "\n".join(lines)


def write_report(path: Optional[str], report: dict) -> None:
    if not path:
        return
    dest = Path(path)
    tmp = dest.with_name(dest.name + f".{uuid.uuid4().hex}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
    try:
        _write_all(fd, (json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(tmp, dest)
    say(f"report written to {dest}")


def confirm(args, what: str, expected: str) -> None:
    """Typed confirmation for every --apply (user rule), unless --yes."""
    if args.yes:
        return
    if not sys.stdin.isatty():
        raise Refused("--apply needs a typed confirmation on a terminal; re-run with a TTY or add --yes")
    print(f"\n{what}\nType the NEW KEK id ({expected}) to continue, anything else aborts: ", end="", flush=True)
    if sys.stdin.readline().strip() != expected:
        raise Refused("confirmation did not match; nothing was changed")


# ─── Commands ─────────────────────────────────────────────────────────────────────────────────

def _keys(args, need_old: bool) -> Keys:
    if not args.new_kek_file:
        raise Refused("--new-kek-file is required")
    new = load_kek_file(args.new_kek_file, "NEW")
    old = load_kek_file(args.old_kek_file, "OLD") if args.old_kek_file else None
    if need_old and old is None:
        raise Refused("--old-kek-file is required")
    if old is not None and hmac.compare_digest(old, new):
        raise Refused("OLD and NEW are the same key")
    return Keys(old, new, getattr(args, "breach", False))


def _check_operator(args) -> None:
    if args.apply and not (args.operator and OPERATOR_RE.fullmatch(args.operator)):
        raise Refused("--apply needs --operator NAME (letters, digits, . _ @ -; up to 48): it is recorded "
                      "in every custody/audit row")


def v0_under_old(items: list[Item], keys: Keys) -> list[Item]:
    """ROT-M2: v0 rows left failed / attention whose file still opens with OLD. After the KEK swap the
    backend would read each as tampered (a v0 tag failure is an integrity failure) and freeze it: the
    operator must not swap while any is left."""
    out = []
    for i in items:
        if i.fmt != 0 or i.result not in ("failed", "attention") or keys.old is None:
            continue
        try:
            _decrypt_v0(_resolve(i.root, i.rel), keys.old, i.nonce_hex, None)
        except (ValueError, OSError):
            continue
        out.append(i)
    return out


def _do_not_swap_message(stuck: list[Item]) -> str:
    return (f"DO NOT SWAP THE KEK: {len(stuck)} v0 file(s) are still under OLD (not migrated). After a swap the "
            "backend would read each one as tampered and freeze it. Fix them and re-run rotate, or keep the old "
            "KEK in service (runbook: exit code 4): " + "; ".join(f"{i.consumer} {i.row_id} {i.store}:{i.rel}"
                                                               for i in stuck[:20]))


async def cmd_rotate(args, sessions) -> int:
    """plan (= rotate without --apply) and rotate --apply."""
    keys = _keys(args, need_old=True)
    apply = bool(getattr(args, "apply", False))
    _check_operator(args)
    run = Run(str(uuid.uuid4()), "rotate" if apply else "plan", "breach" if keys.breach else "scheduled",
              args.operator, kid(keys.old), kid(keys.new), now())
    report = {"tool": "evidence.rotation", "run_id": run.id, "command": run.command, "mode": run.mode,
              "apply": apply, "started_at": run.started_at, "kek_id_old": run.old_kid, "kek_id_new": run.new_kid}
    lock_path = Path(settings.evidence_path) / LOCK_NAME
    sessions_open = await other_sessions(sessions)
    report["preconditions"] = {"other_db_sessions": sessions_open, "lock_present": os.path.lexists(lock_path)}
    if sessions_open:
        if apply:
            raise Refused(_sessions_message(sessions_open))
        say("WARNING: " + _sessions_message(sessions_open) + " (plan only: nothing is written)")
    referenced = await referenced_paths(sessions)
    prior = pending_rotate(read_lock_info())
    keys.resume = bool(prior) and prior.get("kek_id_new") == run.new_kid
    report["resumes_run"] = prior.get("run_id") if keys.resume else None

    async def classify_all() -> tuple[list[Item], list[KeyRow], dict]:
        async with sessions() as db:
            items, keyrows, ledger = await load_items(db), await load_key_rows(db), await load_ledger(db, run.new_kid)
        for i in items:
            classify(i, keys, ledger)
            i.result = i.action
        for k in keyrows:
            classify_key(k, keys, ledger)
            k.result = k.action
        return items, keyrows, ledger

    preview = await recovery_pass(sessions, keys, run, apply=False, referenced=referenced)
    items, keyrows, ledger = await classify_all()
    orphans = scan_orphans(items)
    print(f"KEK rotation {'plan' if not apply else 'preview'}  {now()}  mode {run.mode}  "
          f"OLD id {run.old_kid}  NEW id {run.new_kid}")
    if preview:
        print(f"journals to recover first: {len(preview)}")
        for r in preview:
            print(f"  {r['outcome']:16s} {r['journal']}  {r['detail']}")
    print(table(items, keyrows, "action"))
    if orphans:
        print(f"unreferenced KEK-encrypted files (not touched; they stay under OLD): {len(orphans)}")
        for o in orphans[:50]:
            print(f"  {o}")
    report.update({"recovery_preview": preview, "orphans": orphans})
    if not apply:
        report.update({"items": [i.report() for i in items], "collector_keys": [k.report() for k in keyrows],
                       "finished_at": now()})
        bad = any(i.action in ("attention", "failed") or i.warnings for i in items) or \
            any(k.action == "failed" for k in keyrows) or any(r["outcome"] == "manual" for r in preview)
        stuck = v0_under_old(items, keys)
        report["do_not_swap"] = [i.report() for i in stuck]
        report["exit_code"] = EXIT_DO_NOT_SWAP if stuck else EXIT_ATTENTION if bad else EXIT_OK
        write_report(args.report, report)
        if stuck:
            say(_do_not_swap_message(stuck))
        print("dry run: nothing was changed (add --apply to rotate)")
        return report["exit_code"]

    confirm(args, f"About to rotate {len(items)} stored files and {len(keyrows)} collector keys "
            f"({run.mode} mode) from OLD id {run.old_kid} to NEW id {run.new_kid}. Backend, analysis-worker "
            "and backup must be stopped, and a backup taken.", run.new_kid)
    lock = RotationLock()
    lock.acquire({"run_id": run.id, "command": "rotate", "started_at": run.started_at, "mode": run.mode,
                  "kek_id_old": run.old_kid, "kek_id_new": run.new_kid, "pid": os.getpid()})
    completed = untouched = False
    try:
        sessions_open = await other_sessions(sessions)          # re-check now that the gate is closed
        if sessions_open:
            untouched = True
            raise Refused(_sessions_message(sessions_open))
        recovery = await recovery_pass(sessions, keys, run, apply=True, referenced=referenced)
        report["recovery"] = recovery
        manual = [r for r in recovery if r["outcome"] == "manual"]
        if manual:
            raise ManualStop(f"{len(manual)} journal(s) need manual action: " + "; ".join(
                f"{r['journal']}: {r['detail']}" for r in manual))
        items, keyrows, ledger = await classify_all()
        for item in items:
            await process_item(sessions, item, keys, run)
        await process_keys(sessions, keyrows, keys, run, ledger)
        counts = dict(Counter(f"{i.consumer}:{i.result}" for i in items)
                      + Counter(f"collector:{k.result}" for k in keyrows))
        bad = any(i.result in ("attention", "failed") or i.warnings for i in items) or \
            any(k.result == "failed" for k in keyrows)
        stuck = v0_under_old(items, keys)
        await write_summary(sessions, run, "kek_rotation_run", "failure" if bad else "success",
                            {"counts": counts, "recovered_journals": len(recovery), "orphans": len(orphans),
                             "do_not_swap": len(stuck)})
        completed = True
        report.update({"items": [i.report() for i in items], "collector_keys": [k.report() for k in keyrows],
                       "do_not_swap": [i.report() for i in stuck], "finished_at": now(),
                       "exit_code": EXIT_DO_NOT_SWAP if stuck else EXIT_ATTENTION if bad else EXIT_OK})
        print(f"\nKEK rotation result  {now()}")
        print(table(items, keyrows, "result"))
        if stuck:
            say(_do_not_swap_message(stuck))
        return report["exit_code"]
    finally:
        # §6.4: the lock goes only after a run that ends with no journal left. An unexpected error
        # mid-pass keeps it too, so the backend cannot start on a half-rotated store unnoticed.
        left = find_journals(referenced)
        delete = not (left["keyslot"] or left["rewrite"]) and (completed or (untouched and lock.created))
        lock.release(delete=delete)
        report.setdefault("finished_at", now())
        report["lock_removed"] = delete
        write_report(args.report, report)


async def process_item(sessions, item: Item, keys: Keys, run: Run) -> None:
    item.at = now()
    path = None
    if item.action in ("rewrap", "migrate", "reencrypt", "record"):
        path = _resolve(item.root, item.rel)
    if item.action == "rewrap":
        try:
            outcome = rewrap_file(path, keys.old, keys.new)
        except OSError as e:
            item.result, item.reason = "failed", f"io_error: {e.strerror}"
            return
        if outcome == "cannot_open":
            item.result, item.reason = "failed", "cannot_open (changed since classification)"
            return
        details = run.details(item, "rewrap" if outcome == "rewrapped" else "recorded_on_resume",
                              keys.old, keys.new, None, sha_verified=False)
        details["sha256_verified"] = "not_checked (slot re-wrap; run verify)" if item.sha256 else "not_recorded"
        if item.warnings:
            details["warnings"] = item.warnings
        async with sessions() as db, db.begin():
            await _audit_item(db, details)
        item.result = "rewrap" if outcome == "rewrapped" else "record"
        say(f"{item.result:9s} {item.consumer} {item.row_id} {item.store}:{item.rel}")
    elif item.action in ("migrate", "reencrypt"):
        src_key = keys.old
        if item.fmt == 2:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                header, seg0 = _read_head(fd)
            finally:
                os.close(fd)
            src_key = keys.new if opens(keys.new, header, seg0) is not None else keys.old
        await rewrite_item(sessions, item, src_key, keys, run)
        say(f"{item.result:9s} {item.consumer} {item.row_id} {item.store}:{item.rel}"
            f"{'  ' + item.reason if item.reason else ''}")
    elif item.action == "record":
        details = run.details(item, "recorded_on_resume", keys.old, keys.new, None, sha_verified=False)
        details["sha256_verified"] = "not_checked (run verify)" if item.sha256 else "not_recorded"
        async with sessions() as db, db.begin():
            await _audit_item(db, details)
        item.result = "record"
    else:
        item.result = item.action


async def process_keys(sessions, keyrows: list[KeyRow], keys: Keys, run: Run, ledger) -> None:
    """Collector private keys: decrypt with OLD (or NEW), re-encrypt under NEW with a fresh nonce,
    verify, and update every row in ONE transaction with its custody/audit row."""
    async with sessions() as db, db.begin():
        for k in keyrows:
            k.at = now()
            row = await db.get(CollectionPackage, uuid.UUID(k.row_id), with_for_update=True)
            if row is None or row.enc_private_key is None:
                k.result, k.reason = "failed", "row vanished"
                continue
            k.wrapped = row.enc_private_key
            pt = classify_key(k, keys, ledger)
            k.result = k.action
            if k.action == "record":
                await _audit_item(db, run.details(k, "recorded_on_resume", keys.old, keys.new, None, sha_verified=None))
            if k.action != "reencrypt":
                continue
            src = keys.new if _key_opens(k.wrapped, keys.new) else keys.old
            nonce = os.urandom(12)
            ct = AESGCM(keys.new).encrypt(nonce, pt, None)
            if AESGCM(keys.new).decrypt(nonce, ct, None) != pt:
                k.result, k.reason = "failed", "re-encrypted key did not verify"
                continue
            row.enc_private_key = f"{nonce.hex()}:{base64.b64encode(ct).decode()}"
            await _audit_item(db, run.details(k, "reencrypt", src, keys.new, None, sha_verified=None))
            say(f"reencrypt collector key {k.row_id}")


def _key_opens(wrapped: str, key: Optional[bytes]) -> bool:
    if key is None:
        return False
    try:
        nonce_hex, b64 = wrapped.split(":", 1)
        AESGCM(key).decrypt(bytes.fromhex(nonce_hex), base64.b64decode(b64), None)
        return True
    except (ValueError, InvalidTag):
        return False


async def cmd_recover(args, sessions) -> int:
    keys = _keys(args, need_old=True)
    apply = bool(args.apply)
    _check_operator(args)
    run = Run(str(uuid.uuid4()), "recover", "scheduled", args.operator, kid(keys.old), kid(keys.new), now())
    report = {"tool": "evidence.rotation", "run_id": run.id, "command": "recover", "apply": apply,
              "started_at": run.started_at, "kek_id_old": run.old_kid, "kek_id_new": run.new_kid}
    lock_path = Path(settings.evidence_path) / LOCK_NAME
    referenced = await referenced_paths(sessions)
    preview = await recovery_pass(sessions, keys, run, apply=False, referenced=referenced)
    for r in preview:
        print(f"  {r['outcome']:16s} {r['journal']}  {r['detail']}")
    if not apply:
        report.update({"recovery_preview": preview, "lock_present": os.path.lexists(lock_path), "finished_at": now()})
        report["exit_code"] = EXIT_MANUAL if any(r["outcome"] == "manual" for r in preview) else EXIT_OK
        write_report(args.report, report)
        print(f"dry run: {len(preview)} journal(s); lock {'present' if os.path.lexists(lock_path) else 'absent'}; "
              "nothing was changed (add --apply)")
        return report["exit_code"]
    if not preview and not os.path.lexists(lock_path):
        print("nothing to recover: no journal and no lock")
        report.update({"finished_at": now(), "exit_code": EXIT_OK})
        write_report(args.report, report)
        return EXIT_OK
    sessions_open = await other_sessions(sessions)
    if sessions_open:
        raise Refused(_sessions_message(sessions_open))
    confirm(args, f"About to recover {len(preview)} journal(s) with OLD id {run.old_kid} and NEW id {run.new_kid}.",
            run.new_kid)
    lock = RotationLock()
    # R3-6: a lock an interrupted `rotate` left keeps naming that run (pending_rotate), so recover never
    # removes it and the next `rotate --apply` knows it resumes (ROT-L6).
    lock.acquire(lambda prev: {"run_id": run.id, "started_at": run.started_at, "command": "recover",
                               "pid": os.getpid(), "pending_rotate": pending_rotate(prev)})
    pending = pending_rotate(lock.previous)
    done = untouched = False
    try:
        sessions_open = await other_sessions(sessions)          # ROT-L8: re-check now that the gate is closed
        if sessions_open:
            untouched = True
            raise Refused(_sessions_message(sessions_open))
        recovery = await recovery_pass(sessions, keys, run, apply=True, referenced=referenced)
        manual = [r for r in recovery if r["outcome"] == "manual"]
        await write_summary(sessions, run, "kek_rotation_recover", "failure" if manual else "success",
                            {"journals": len(recovery), "manual": len(manual),
                             "outcomes": dict(Counter(r["outcome"] for r in recovery))})
        done = True
        report.update({"recovery": recovery, "finished_at": now(),
                       "exit_code": EXIT_MANUAL if manual else EXIT_OK})
        for r in recovery:
            print(f"  {r['outcome']:16s} {r['journal']}  {r['detail']}")
        if pending:
            print(f"recovery done. The lock is KEPT: an unfinished `rotate` (run {pending.get('run_id')}) wrote it. "
                  "Run the same `rotate --apply` again (idempotent) to finish the rotation, then `verify`; the "
                  "backend stays refused until then.")
        else:
            print("recovery done. The rotation itself may be unfinished: run `rotate --apply` again "
                  "(idempotent), then `verify`, before starting the backend.")
        return report["exit_code"]
    finally:
        left = find_journals(referenced)
        delete = not (left["keyslot"] or left["rewrite"]) and pending is None and (
            done or (untouched and lock.created))
        lock.release(delete=delete)
        report["lock_removed"] = delete
        report["lock_kept_for_rotate"] = pending.get("run_id") if pending else None
        write_report(args.report, report)


async def cmd_verify(args, sessions) -> int:
    """Every file opens with NEW and matches its recorded SHA-256; collector keys open with NEW.
    With --old-kek-file, also proves nothing opens with OLD any more."""
    keys = _keys(args, need_old=False)
    started = now()
    referenced = await referenced_paths(sessions)
    async with sessions() as db:
        items, keyrows = await load_items(db), await load_key_rows(db)
    fails = 0
    v0_stuck = []                          # ROT-M2: v0 files NEW does not open (still under OLD or corrupt)
    for i in items:
        i.at = now()
        if i.plain:
            i.result, i.reason = "failed", PLAIN_REASON
        elif i.fmt is None:
            i.result, i.reason = "failed", "malformed_row"
        elif i.fmt == 0:
            try:
                pt = _decrypt_v0(_resolve(i.root, i.rel), keys.new, i.nonce_hex, i.size)
                ok = not i.sha256 or hashlib.sha256(pt).hexdigest() == i.sha256.lower()
                i.result, i.reason = ("done", None) if ok else ("failed", "hash_mismatch")
            except FileNotFoundError:
                i.result, i.reason = "failed", "file_missing"
            except ValueError as e:
                i.result, i.reason = "failed", (f"v0 file not migrated, still under another KEK ({e}): once NEW is in "
                                                "service the backend reads it as tampered and freezes it")
                v0_stuck.append(i)
        else:
            try:
                chk = check_v2(_resolve(i.root, i.rel), keys.new, i.nonce_hex, i.size, i.sha256)
            except ValueError as e:
                chk = Check(False, f"invalid_path: {e}")
            i.result, i.reason = ("done", None) if chk.ok else ("failed", chk.reason)
            if chk.ok and chk.kek_id_matches is False:
                i.warnings.append("kek_id_mismatch")
            if chk.ok and keys.old is not None:
                with open(_resolve(i.root, i.rel), "rb") as f:
                    header = f.read(codec.HEADER_LEN)
                try:
                    codec.StreamDecryptor(keys.old, header)
                    i.result, i.reason = "failed", "still opens with OLD"
                except codec.CodecError:
                    pass
        fails += i.result == "failed"
    for k in keyrows:
        k.at = now()
        if _key_opens(k.wrapped, keys.new):
            nonce_hex, b64 = k.wrapped.split(":", 1)
            pem = AESGCM(keys.new).decrypt(bytes.fromhex(nonce_hex), base64.b64decode(b64), None)
            try:
                serialization.load_pem_private_key(pem, password=None)
                k.result = "done"
            except (ValueError, TypeError):
                k.result, k.reason = "failed", "not a PEM private key"
        else:
            k.result, k.reason = "failed", "does not open with NEW"
        if k.result == "done" and _key_opens(k.wrapped, keys.old):
            k.result, k.reason = "failed", "still opens with OLD"
        fails += k.result == "failed"
    left = find_journals(referenced)
    lock_present = os.path.lexists(Path(settings.evidence_path) / LOCK_NAME)
    stale = [str(p) for p in left["keyslot"] + left["rewrite"]]
    unrecognised = [str(p) for p in left["unrecognised"]]
    orphans = scan_orphans(items)
    print(f"KEK verify  {now()}  NEW id {kid(keys.new)}" + (f"  OLD id {kid(keys.old)} must not open" if keys.old else ""))
    print(table(items, keyrows, "result"))
    if stale or lock_present:
        print(f"rotation not finished: lock {'present' if lock_present else 'absent'}, {len(stale)} journal(s)")
    if orphans:
        print(f"unreferenced KEK-encrypted files: {len(orphans)} (not checked)")
    if unrecognised:
        print(f"files named like a journal that are not one (no magic, no row): {len(unrecognised)}")
        for u in unrecognised[:50]:
            print(f"  {u}")
    warn = any(i.warnings for i in items) or bool(orphans) or bool(unrecognised)
    code = EXIT_DO_NOT_SWAP if v0_stuck else EXIT_ATTENTION if (fails or stale or lock_present or warn) else EXIT_OK
    write_report(args.report, {"tool": "evidence.rotation", "command": "verify", "started_at": started,
                               "finished_at": now(), "kek_id_new": kid(keys.new), "kek_id_old": kid(keys.old),
                               "items": [i.report() for i in items], "collector_keys": [k.report() for k in keyrows],
                               "journals": stale, "unrecognised_journal_names": unrecognised,
                               "lock_present": lock_present, "orphans": orphans,
                               "do_not_swap": [i.report() for i in v0_stuck], "failed": fails, "exit_code": code})
    print(f"verify: {len(items)} files, {len(keyrows)} collector keys, {fails} failed")
    if v0_stuck:
        say(f"DO NOT RUN THE BACKEND WITH THIS KEK: {len(v0_stuck)} v0 file(s) do not open with NEW (not migrated). "
            "If the KEK was already swapped, put the old one back first (runbook: exit code 4).")
    return code


# ─── Backup mirror (F-2 / R-6): verify a rebuilt mirror before the old one is retired ─────────

MIRROR_SKIP_SUFFIXES = (".partial", KEYSLOT, KEYSLOT + TMP, REWRITE, REWRITE + TMP)


def mirror_listing(root: Path, *, source: bool) -> list[str]:
    """Relative paths of the regular files backup.sh mirrors from /evidence (source=True: skips
    the top-level .staging/, *.partial, journals and the lock), or of a mirror tree as is."""
    out = []
    for dirpath, dirs, files in os.walk(root):
        here = Path(dirpath)
        if source and here == root and store.STAGING_DIR in dirs:
            dirs.remove(store.STAGING_DIR)
        for n in files:
            if source and (n == LOCK_NAME or n.endswith(MIRROR_SKIP_SUFFIXES)):
                continue
            p = here / n
            if stat.S_ISREG(os.lstat(p).st_mode):
                out.append(str(p.relative_to(root)))
    return sorted(out, key=lambda s: s.encode())


def listing_sha256(paths: list[str]) -> str:
    """Same as `(cd DIR && find . -type f) | LC_ALL=C sort | sha256sum` in backup.sh."""
    return hashlib.sha256("".join(f"./{p}\n" for p in sorted(paths, key=lambda s: s.encode())).encode()).hexdigest()


def _file_sha(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


async def cmd_mirror_verify(args, sessions) -> int:
    keys = _keys(args, need_old=False)
    apply = bool(args.apply)
    _check_operator(args)
    mirror = Path(args.mirror)
    evid = Path(settings.evidence_path)
    if not mirror.is_dir():
        raise Refused(f"{mirror} is not a directory")
    journals = find_journals(await referenced_paths(sessions))
    if os.path.lexists(evid / LOCK_NAME) or journals["keyslot"] or journals["rewrite"]:
        raise Refused("a KEK rotation is in progress or did not finish (lock or journal present)")
    run = Run(str(uuid.uuid4()), "mirror-verify", "scheduled", args.operator, None, kid(keys.new), now())
    src, dst = mirror_listing(evid, source=True), mirror_listing(mirror, source=False)
    missing, extra = sorted(set(src) - set(dst)), sorted(set(dst) - set(src))
    # The scheduled mirror is copy-once and never pruned, so the mirror being replaced can hold the
    # only copy of files that have left /evidence (e.g. disposed exhibits). They are under OLD.
    old_mirror = Path(args.old_mirror) if args.old_mirror else (
        mirror.with_name(mirror.name[:-len(".next")]) if mirror.name.endswith(".next") else None)
    retained_only = sorted(set(mirror_listing(old_mirror, source=False)) - set(src)) \
        if old_mirror is not None and old_mirror.is_dir() else []
    differ = [p for p in sorted(set(src) & set(dst)) if _file_sha(evid / p) != _file_sha(mirror / p)]
    async with sessions() as db:
        items = [i for i in await load_items(db) if i.store == "evidence"]
    bad_items = []
    for i in items:
        if i.fmt != 2:
            bad_items.append((i, f"row is v{i.fmt}: not rotated"))
            continue
        try:
            chk = check_v2(_resolve(mirror, i.rel), keys.new, i.nonce_hex, i.size, i.sha256)
        except ValueError as e:
            chk = Check(False, str(e))
        if not chk.ok:
            bad_items.append((i, chk.reason))
    listing = listing_sha256(dst)
    ok = not (missing or extra or differ or bad_items)
    print(f"mirror verify  {now()}  {mirror}  NEW id {kid(keys.new)}")
    print(f"  files: source {len(src)}, mirror {len(dst)}; missing {len(missing)}, extra {len(extra)}, "
          f"content differs {len(differ)}; KEK-encrypted rows checked {len(items)}, failed {len(bad_items)}")
    for label, paths in (("missing", missing), ("extra", extra), ("differs", differ)):
        for p in paths[:50]:
            print(f"  {label:8s} {p}")
    for i, reason in bad_items[:50]:
        print(f"  failed   {i.consumer} {i.row_id} {i.rel}  {reason}")
    if retained_only:
        print(f"  NOTE: {len(retained_only)} file(s) exist only in the old mirror {old_mirror} (not in /evidence, "
              "e.g. copies of disposed exhibits or v0 sidecars). They stay under OLD. Do not purge the retired "
              "mirror or destroy OLD while any of them must be retained.")
        for p in retained_only[:50]:
            print(f"  retained {p}")
    report = {"tool": "evidence.rotation", "command": "mirror-verify", "run_id": run.id, "mirror": str(mirror),
              "started_at": run.started_at, "kek_id_new": run.new_kid, "listing_sha256": listing,
              "files": len(dst), "missing": missing, "extra": extra, "differs": differ,
              "failed_items": [dict(i.report(), reason=r) for i, r in bad_items], "ok": ok,
              "old_mirror": None if old_mirror is None else str(old_mirror), "retained_only_in_old_mirror": retained_only}
    if not ok or not apply:
        report.update({"finished_at": now(), "exit_code": EXIT_OK if ok else EXIT_ATTENTION})
        write_report(args.report, report)
        if ok:
            print("mirror verified (dry run: no marker, no records; add --apply)")
        return report["exit_code"]
    confirm(args, f"Record {mirror} as verified ({len(dst)} files) and the mirror it replaces as retired.",
            run.new_kid)
    by_ev: dict[str, list[Item]] = {}
    for i in items:
        by_ev.setdefault(i.row_id, []).append(i)
    async with sessions() as db, db.begin():
        for ev_id, group in by_ev.items():
            await write_audit(db, "evidence_mirror_rebuilt", username=run.tool_user, role_at_time="offline-tool",
                              outcome="success", resource_type="evidence", resource_id=ev_id,
                              details={"incident_id": group[0].incident_id, "run_id": run.id, "operator": run.operator,
                                       "mirror": mirror.name, "files": len(group), "kek_id": run.new_kid,
                                       "sha256_verified": all(bool(g.sha256) for g in group),
                                       "note": "backup mirror copy rebuilt from the rotated store and verified; "
                                               "the previous mirror copy is retired on swap"},
                              request_id=run.id, request_method="CLI", request_path="evidence.rotation mirror-verify")
        await write_audit(db, "evidence_mirror_rebuild", username=run.tool_user, role_at_time="offline-tool",
                          outcome="success", resource_type="evidence_mirror", resource_id=run.id,
                          details={"run_id": run.id, "operator": run.operator, "mirror": str(mirror),
                                   "files": len(dst), "rows_checked": len(items), "listing_sha256": listing,
                                   "kek_id": run.new_kid, "verified_at": now(),
                                   "replaces": None if old_mirror is None else str(old_mirror),
                                   "retained_only_in_old_mirror": len(retained_only)},
                          request_id=run.id, request_method="CLI", request_path="evidence.rotation mirror-verify")
    marker = mirror.with_name(mirror.name + ".verified")
    tmp = marker.with_name(marker.name + f".{uuid.uuid4().hex}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    try:
        _write_all(fd, (json.dumps({"mirror": mirror.name, "listing_sha256": listing, "files": len(dst),
                                    "run_id": run.id, "kek_id_new": run.new_kid, "verified_at": now()},
                                   sort_keys=True) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(tmp, marker)
    _fsync_dir(marker.parent)
    report.update({"marker": str(marker), "finished_at": now(), "exit_code": EXIT_OK})
    write_report(args.report, report)
    print(f"mirror verified and recorded; marker {marker} (backup.sh mirror-swap checks it)")
    return EXIT_OK


# ─── CLI ──────────────────────────────────────────────────────────────────────────────────────

def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m evidence.rotation",
                                description="Evidence KEK rotation (docs/evidence-kek-rotation.md). Dry run "
                                            "unless --apply.")
    sub = p.add_subparsers(dest="command")

    def common(sp, old_required=True):
        sp.add_argument("--old-kek-file", required=old_required, help="file holding the current KEK (64 hex)")
        sp.add_argument("--new-kek-file", required=True, help="file holding the new KEK (64 hex)")
        sp.add_argument("--report", help="write the JSON report to this file")

    def writes(sp):
        sp.add_argument("--apply", action="store_true", help="make the changes (default: dry run)")
        sp.add_argument("--operator", help="operator name recorded in the custody/audit rows")
        sp.add_argument("--yes", action="store_true", help="skip the typed confirmation")

    sp = sub.add_parser("plan", help="dry run of rotate (default)")
    common(sp)
    sp.add_argument("--breach", action="store_true", help="plan a breach re-encrypt (fresh data keys)")
    sp.set_defaults(apply=False, operator=None, yes=False)
    sp = sub.add_parser("rotate", help="rotate every KEK consumer (dry run unless --apply)")
    common(sp)
    writes(sp)
    sp.add_argument("--breach", action="store_true",
                    help="suspected KEK compromise: re-encrypt every file under a fresh data key instead of re-wrapping")
    sp = sub.add_parser("recover", help="crash recovery only (§6.4 / §5.4)")
    common(sp)
    writes(sp)
    sp = sub.add_parser("verify", help="check every file and collector key opens with NEW (read-only)")
    common(sp, old_required=False)
    sp = sub.add_parser("mirror-verify", help="check a rebuilt backup mirror; --apply records it")
    common(sp, old_required=False)
    writes(sp)
    sp.add_argument("--mirror", required=True, help="mirror directory, e.g. /backups/evidence-mirror.next")
    sp.add_argument("--old-mirror", help="the mirror it replaces (default: the same name without .next)")
    return p


async def _amain(args) -> int:
    engine, sessions = make_sessions()
    try:
        if args.command in ("plan", "rotate"):
            return await cmd_rotate(args, sessions)
        if args.command == "recover":
            return await cmd_recover(args, sessions)
        if args.command == "verify":
            return await cmd_verify(args, sessions)
        return await cmd_mirror_verify(args, sessions)
    finally:
        await engine.dispose()


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0].startswith("-"):
        argv.insert(0, "plan")
    args = parser().parse_args(argv)
    if args.command == "plan":
        args.breach = getattr(args, "breach", False)
    if args.command == "rotate" and not args.apply:
        args.command = "plan"
    try:
        return asyncio.run(_amain(args))
    except Refused as e:
        say(f"REFUSED: {e}")
        return EXIT_REFUSED
    except ManualStop as e:
        say(f"STOPPED FOR MANUAL ACTION: {e}")
        say("The lock and journal(s) are kept, so the backend will not start. See the runbook, "
            "'Crash recovery'.")
        return EXIT_MANUAL


if __name__ == "__main__":
    sys.exit(main())
