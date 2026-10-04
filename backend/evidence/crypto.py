"""AES-256-GCM encryption at rest for stored files: evidence (`evidence_path`, /evidence) and
the entity / incident "Files" store (`logs_path`, /asset_logs).

Two on-disk formats (docs/streaming-aes-gcm-format.md):

  v0 (legacy; read-only since G1 stage 3a): the whole file is one AES-256-GCM message under the
     raw KEK with a fresh 96-bit nonce, kept in the row (`nonce_hex`, 24 hex) and, for evidence, a
     `.nonce` sidecar. encrypt_file_bytes / decrypt_file_bytes stay: v0 reads need them, and the
     collector private keys (collectors/crypto.py, out of scope) still use them.
  v2 (FENRGCM, evidence/codec.py): an 80-byte header, then 1 MiB chunks under a per-file data key
     wrapped by a KEK-derived key. The row's `nonce_hex` holds the 7-byte nonce prefix (14 hex)
     and is checked against the header on every read (Q5). No sidecar. Every new file is written
     as v2, through a staging file (§4.4): whole (write_encrypted, write_encrypted_stream) or
     piece by piece (EncryptedStagingWriter, the stage-3b chunked upload sessions).

The row decides which format a read expects (§5.1: 24 hex = v0, 14 hex = v2); a file that
disagrees is an integrity failure. Every read follows the fixed §4.2 order and error mapping:

  EvidenceIntegrityError  the stored bytes are not what was written (tampering or corruption);
                          evidence callers freeze the item (verify_failed) as before.
  EvidenceCryptoError     the file cannot be read (missing, I/O error, wrong or missing KEK):
                          never frozen; reported to the read-alarm sink, which the backend wires
                          to an audit row + an admin notification (evidence/read_alarms.py).
                          `.reason` names the class.
  ValueError              a codec misuse (a caller bug): an internal error, never an integrity
                          record.

Master KEK: `settings.evidence_kek` (secret file `evidence_kek`). Everything here blocks (disk +
CPU); request handlers use the a* wrappers and the async stream functions, which run the work in
worker threads. v2 does at most 1 MiB of AES-GCM per call, so the event loop keeps getting the
GIL; a v0 file is still decrypted whole (1 GiB upload cap until G2).

Writer-only revert: set _WRITER_FORMAT = 0 (the pre-3a whole-file writer, kept as _write_v0).
Never revert the reader while v2 files exist: they would become unreadable
(ignore/revert/irw-G1/stage3a/README.md).
"""
import asyncio
import hashlib
import hmac
import logging
import os
import re
import stat
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator, Callable, Iterator, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.config import settings
from evidence import codec

log = logging.getLogger("fenrir.evidence.crypto")


class EvidenceCryptoError(RuntimeError):
    """Raised on KEK misconfig / decrypt failure / tag mismatch. From a read, a plain
    EvidenceCryptoError means the file could not be read; `reason` says why (file_missing,
    io_error, invalid_path, kek_unavailable, wrong_kek)."""

    def __init__(self, message: str = "", reason: Optional[str] = None):
        super().__init__(message)
        self.reason = reason


class EvidenceIntegrityError(EvidenceCryptoError):
    """The stored ciphertext failed AES-GCM authentication: these are not the bytes that were
    encrypted (tampering or corruption), as opposed to a file that could not be read at all.
    From a read, `reason` names the failed check (malformed_row, size_mismatch, format_mismatch,
    bad_header, nonce_mismatch, slot_corrupt, chunk_auth, truncated, tag)."""


def _load_key() -> bytes:
    kek = settings.evidence_kek
    if not kek:
        raise EvidenceCryptoError(
            "EVIDENCE_KEK is not set. Generate with `openssl rand -hex 32` "
            "and set it in the backend env. Backend refuses to start without it."
        )
    try:
        key = bytes.fromhex(kek)
    except ValueError as e:
        raise EvidenceCryptoError("EVIDENCE_KEK must be hex-encoded.") from e
    if len(key) != 32:
        raise EvidenceCryptoError(
            f"EVIDENCE_KEK must be exactly 64 hex chars (32 bytes); got {len(key)} bytes."
        )
    return key


def assert_kek_configured() -> None:
    """Call at startup to fail-fast if KEK is missing/malformed."""
    _load_key()


def encrypt_file_bytes(plaintext: bytes) -> tuple[bytes, str]:
    """v0: encrypt and return (ciphertext_with_tag, nonce_hex). No longer used for stored files
    (they are written as v2); collector private keys still use it."""
    key   = _load_key()
    nonce = os.urandom(12)                          # 96-bit nonce per AES-GCM spec
    aes   = AESGCM(key)
    ct    = aes.encrypt(nonce, plaintext, None)
    return ct, nonce.hex()


def decrypt_file_bytes(ciphertext: bytes, nonce_hex: str) -> bytes:
    """v0: decrypt and verify tag. Raises on tag mismatch."""
    key = _load_key()
    try:
        nonce = bytes.fromhex(nonce_hex)
    except ValueError as e:
        raise EvidenceCryptoError("Stored nonce is not valid hex.") from e
    aes = AESGCM(key)
    try:
        return aes.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise EvidenceIntegrityError("AES-GCM tag verification failed.") from e


def _base(root: Optional[str]) -> Path:
    return Path(root or settings.evidence_path).resolve()


def _safe_target(relative_path: str, root: Optional[str] = None) -> Path:
    """Resolve relative_path under the store root (default evidence_path), rejecting anything
    that escapes.

    Defence in depth — all current callers pre-sanitise the path, but enforcing
    the boundary here means a future caller (new endpoint, migration tool,
    poisoned DB row) cannot use this module to read/write outside the store.
    Also defeats symlink escapes because resolve() follows symlinks before the
    is_relative_to check.
    """
    base = _base(root)
    target = (base / relative_path).resolve()
    if not target.is_relative_to(base):
        raise EvidenceCryptoError(f"relative_path escapes the storage directory: {relative_path!r}",
                                  reason="invalid_path")
    return target


def _store_name(root: Optional[str]) -> str:
    return "evidence" if root is None or _base(root) == _base(None) else "files"


# ─── Read alarms (§4.2: every "cannot read" is loud; F-10: kek_id mismatch warning) ──────────
# The backend installs a sink at startup (evidence/read_alarms.py: audit row + admin notification).
# It is called from the reading thread and must not block. Without a sink the event is only logged.

_alarm_sink: Optional[Callable[[dict], None]] = None
_kek_id_warned: set[tuple[str, str]] = set()          # once per file per process
_kek_id_lock = threading.Lock()


def set_read_alarm_sink(sink: Optional[Callable[[dict], None]]) -> None:
    global _alarm_sink
    _alarm_sink = sink


def _alarm(event: str, relative_path: str, root: Optional[str], reason: str, fmt: Optional[int]) -> None:
    record = {"event": event, "store": _store_name(root), "relative_path": str(relative_path),
              "reason": reason, "format": None if fmt is None else f"v{fmt}"}
    log.warning("stored-file read alarm: %s", record)
    sink = _alarm_sink
    if sink is not None:
        try:
            sink(record)
        except Exception:                       # an alarm must never turn into a read failure
            log.exception("read-alarm sink failed for %s", record)


def _cannot_read(relative_path: str, root: Optional[str], fmt: Optional[int], reason: str,
                 message: str) -> EvidenceCryptoError:
    _alarm("read_failed", relative_path, root, reason, fmt)
    return EvidenceCryptoError(message, reason=reason)


def _warn_kek_id(relative_path: str, root: Optional[str]) -> None:
    key = (_store_name(root), str(relative_path))
    with _kek_id_lock:
        if key in _kek_id_warned:
            return
        _kek_id_warned.add(key)
    _alarm("kek_id_mismatch", relative_path, root, "kek_id_mismatch", 2)


# ─── Write (v2, staging protocol §4.4) ─────────────────────────────────────────────────────────

STAGING_DIR = ".staging"          # <root>/.staging/: same filesystem as the store (atomic rename),
PARTIAL_SUFFIX = ".partial"       # outside the per-incident tree, skipped by the backup mirror
STALE_PARTIAL_MINUTES = 60        # startup removes .partial files idle longer than this

# Staging files a writer of THIS process still has open (G-fix ROT-L1): the periodic sweep never removes
# one, however long it has been idle (a slow LE build, an upload session paused near its idle limit).
_LIVE_PARTIALS: set[str] = set()
_live_lock = threading.Lock()


def track_partial(path: Optional[Path], live: bool) -> None:
    """Register (live=True) or forget a staging file this process is writing."""
    if path is None:
        return
    with _live_lock:
        (_LIVE_PARTIALS.add if live else _LIVE_PARTIALS.discard)(os.path.realpath(path))
_WRITER_FORMAT = 2                # writer-only revert: 0 (see the module docstring)
_ASYNC_BATCH = 4 * codec.CHUNK_SIZE   # async sources: plaintext handed to the worker per hop


@dataclass(frozen=True)
class StoredFile:
    """What a row needs after a write."""
    relative_path: str
    nonce_hex: str        # v2: the 7-byte nonce prefix (14 hex, checked on every read); v0: the nonce
    sha256: str
    sha1: str
    md5: str
    size: int             # plaintext bytes


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _make_parents(target: Path, base: Path) -> None:
    """mkdir -p for target's directory under base; each new directory's entry is fsynced."""
    missing = []
    d = target.parent
    while d != base and not d.exists():
        missing.append(d)
        d = d.parent
    for d in reversed(missing):
        d.mkdir(exist_ok=True)
        _fsync_dir(d.parent)


class _V2Writer:
    """One v2 container written to <root>/.staging/<random>.partial (O_EXCL), the plaintext hashed
    (SHA-256 / SHA-1 / MD5) on the same pass. feed() any slices, finish() (fsync), then commit()
    (rename into place, fsync the target and staging directories) or discard().

    The methods run in worker threads; a lock serialises them, so discard() from the event loop
    (a cancelled request) waits for at most one feed() and never closes the descriptor under a
    write still in flight. Feed large inputs in slices (_feed_source) to keep that wait short."""

    def __init__(self, root: Optional[str]):
        self.root = root
        self.base = _base(root)
        self.staging = self.base / STAGING_DIR
        self.staging.mkdir(mode=0o700, exist_ok=True)
        self.partial: Optional[Path] = self.staging / f"{uuid.uuid4().hex}{PARTIAL_SUFFIX}"
        self._lock = threading.Lock()
        self._fd: Optional[int] = os.open(self.partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                                          0o644)
        track_partial(self.partial, True)
        try:
            self._enc = codec.StreamEncryptor(_load_key())
            self._write(self._enc.header)
        except BaseException:
            self.discard()
            raise
        self.nonce_hex = codec.decode_header(self._enc.header).nonce_prefix.hex()
        self._hashes = (hashlib.sha256(), hashlib.sha1(), hashlib.md5())
        self._buf = bytearray()
        self.size = 0

    def _write(self, data) -> None:
        if self._fd is None:
            raise EvidenceCryptoError("the staged write was aborted")
        mv = memoryview(data)
        while mv:
            mv = mv[os.write(self._fd, mv):]

    def feed(self, data) -> None:
        with self._lock:
            mv = memoryview(data).cast("B")
            if not mv:
                return
            if self._fd is None:
                raise EvidenceCryptoError("the staged write was aborted")
            for h in self._hashes:
                h.update(mv)
            self.size += len(mv)
            if self._buf:
                take = codec.CHUNK_SIZE - len(self._buf)
                self._buf += mv[:take]
                mv = mv[take:]
                if len(self._buf) < codec.CHUNK_SIZE:
                    return
                self._write(self._enc.update(bytes(self._buf)))
                self._buf.clear()
            while len(mv) >= codec.CHUNK_SIZE:
                self._write(self._enc.update(mv[:codec.CHUNK_SIZE]))
                mv = mv[codec.CHUNK_SIZE:]
            self._buf += mv

    def finish(self) -> None:
        with self._lock:
            self._write(self._enc.finalize(bytes(self._buf)))
            self._buf.clear()
            os.fsync(self._fd)
            os.close(self._fd)
            self._fd = None

    def stored(self, relative_path: str) -> StoredFile:
        sha256, sha1, md5 = (h.hexdigest() for h in self._hashes)
        return StoredFile(str(relative_path), self.nonce_hex, sha256, sha1, md5, self.size)

    def commit(self, relative_path: str) -> StoredFile:
        with self._lock:
            if self.partial is None or self._fd is not None:
                raise EvidenceCryptoError("the staged write is not complete")
            target = _safe_target(relative_path, self.root)
            _make_parents(target, self.base)
            if os.path.lexists(target):
                raise EvidenceCryptoError(f"refusing to overwrite a stored file: {relative_path!r}")
            os.rename(self.partial, target)
            track_partial(self.partial, False)
            self.partial = None
            _fsync_dir(target.parent)
            _fsync_dir(self.staging)
        return self.stored(relative_path)

    def discard(self) -> None:
        with self._lock:
            if self._fd is not None:
                try:
                    os.close(self._fd)
                except OSError:
                    pass
                self._fd = None
            if self.partial is not None:
                try:
                    self.partial.unlink()
                except FileNotFoundError:
                    pass
                track_partial(self.partial, False)
                self.partial = None


def _write_v0(plaintext: bytes, relative_path: str, root: Optional[str],
              accept: Optional[Callable[[StoredFile], None]]) -> StoredFile:
    """The pre-stage-3a writer (whole file in RAM; `.nonce` sidecar for evidence). Used only when
    _WRITER_FORMAT = 0 (writer-only revert)."""
    ct, nonce_hex = encrypt_file_bytes(plaintext)
    stored = StoredFile(str(relative_path), nonce_hex, hashlib.sha256(plaintext).hexdigest(),
                        hashlib.sha1(plaintext).hexdigest(), hashlib.md5(plaintext).hexdigest(), len(plaintext))
    if accept is not None:
        accept(stored)
    target = _safe_target(relative_path, root)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(ct)
    if root is None:
        target.with_suffix(target.suffix + ".nonce").write_text(nonce_hex)
    return stored


def _feed_source(w: _V2Writer, source) -> None:
    """Blocking: feed a bytes-like object or a blocking binary file object in CHUNK_SIZE slices,
    then finish."""
    if hasattr(source, "read"):
        while True:
            block = codec.read_exactly(source.read, codec.CHUNK_SIZE)
            if not block:
                break
            w.feed(block)
    else:
        mv = memoryview(source).cast("B")
        for i in range(0, len(mv), codec.CHUNK_SIZE):
            w.feed(mv[i:i + codec.CHUNK_SIZE])
    w.finish()


def write_encrypted(plaintext: bytes, relative_path: str, *, root: Optional[str] = None) -> StoredFile:
    """Encrypt + write under the store root (default evidence_path) as v2, through the staging
    file. Returns the StoredFile for the row. Blocking: use awrite_encrypted from handlers."""
    if _WRITER_FORMAT == 0:
        return _write_v0(plaintext, relative_path, root, None)
    w = _V2Writer(root)
    try:
        _feed_source(w, plaintext)
        return w.commit(relative_path)
    except BaseException:
        w.discard()
        raise


async def write_encrypted_stream(source, relative_path: str, *, root: Optional[str] = None,
                                 accept: Optional[Callable[[StoredFile], None]] = None) -> StoredFile:
    """Encrypt `source` into the store as v2 in one pass, hashing the plaintext on the way.

    `source`: a bytes-like object, a blocking binary file object (read in a worker thread), or an
    async iterable of bytes. The container goes to <root>/.staging/<random>.partial (O_EXCL), is
    fsynced, renamed to `relative_path` and both directories are fsynced (§4.4). `accept(stored)`,
    if given, runs after the staged file is complete and before it is moved into place; if it
    raises, the staged file is deleted (nothing is stored) and the exception propagates."""
    if _WRITER_FORMAT == 0:
        if hasattr(source, "__aiter__"):
            data = b"".join([part async for part in source])
        elif hasattr(source, "read"):
            data = await asyncio.to_thread(source.read)
        else:
            data = bytes(source)
        return await asyncio.to_thread(_write_v0, data, relative_path, root, accept)
    w = await asyncio.to_thread(_V2Writer, root)
    try:
        if hasattr(source, "__aiter__"):
            buf = bytearray()
            async for part in source:
                buf += part
                if len(buf) >= _ASYNC_BATCH:
                    await asyncio.to_thread(w.feed, bytes(buf))
                    buf.clear()
            await asyncio.to_thread(w.feed, bytes(buf))
            await asyncio.to_thread(w.finish)
        else:
            await asyncio.to_thread(_feed_source, w, source)
        if accept is not None:
            accept(w.stored(relative_path))
        return await asyncio.to_thread(w.commit, relative_path)
    except BaseException:
        w.discard()
        raise


class EncryptedStagingWriter:
    """The staging writer, fed piece by piece (G1 stage 3b: chunked upload sessions). Same
    protocol and result as write_encrypted_stream (v2 only; the writer-only revert does not
    apply to it):

      EncryptedStagingWriter(root)   creates <root>/.staging/<random>.partial (O_EXCL, 0644)
      write(data)                    hashes the plaintext (SHA-256 / SHA-1 / MD5), encrypts every
                                     full 1 MiB chunk to the partial file, keeps the rest (< 1 MiB)
                                     in memory: plaintext never reaches the disk
      finish()                       writes the final chunk and fsyncs; returns the hashes + size
                                     (StoredFile with relative_path ""), so a caller can check them
                                     before deciding; idempotent
      commit(relative_path, accept)  finish(), then accept(stored) (raise to refuse: the partial is
                                     deleted, nothing is stored), rename into place, fsync both
                                     directories; returns the StoredFile for the row
      abort()                        close + unlink the partial; idempotent

    Everything blocks (disk + CPU): handlers use the a* methods, which run in worker threads.
    The methods are serialised by the inner writer's lock, so abort() from another thread waits
    for at most one 1 MiB slice of a write() in flight. Any failure in commit() aborts."""

    def __init__(self, root: Optional[str] = None):
        self._w = _V2Writer(root)
        self._finished = False

    @property
    def size(self) -> int:
        """Plaintext bytes written so far."""
        return self._w.size

    @property
    def partial(self) -> Optional[Path]:
        """The staging file, or None once committed or aborted."""
        return self._w.partial

    def write(self, data) -> None:
        mv = memoryview(data).cast("B")
        for i in range(0, len(mv), codec.CHUNK_SIZE):
            self._w.feed(mv[i:i + codec.CHUNK_SIZE])

    def finish(self) -> StoredFile:
        gone = "the staged write was aborted or already committed"
        if self._w.partial is None:              # checked first: the encryptor finalizes only once
            raise EvidenceCryptoError(gone)
        if not self._finished:
            self._w.finish()
            self._finished = True
        if self._w.partial is None:              # aborted meanwhile
            raise EvidenceCryptoError(gone)
        return self._w.stored("")

    def commit(self, relative_path: str, *,
               accept: Optional[Callable[[StoredFile], None]] = None) -> StoredFile:
        try:
            stored = self.finish()
            if accept is not None:
                accept(StoredFile(str(relative_path), stored.nonce_hex, stored.sha256, stored.sha1,
                                  stored.md5, stored.size))
            return self._w.commit(relative_path)
        except BaseException:
            self.abort()
            raise

    def abort(self) -> None:
        self._w.discard()

    @classmethod
    async def aopen(cls, root: Optional[str] = None) -> "EncryptedStagingWriter":
        return await asyncio.to_thread(cls, root)

    async def awrite(self, data) -> None:
        await asyncio.to_thread(self.write, data)

    async def afinish(self) -> StoredFile:
        return await asyncio.to_thread(self.finish)

    async def acommit(self, relative_path: str, *,
                      accept: Optional[Callable[[StoredFile], None]] = None) -> StoredFile:
        return await asyncio.to_thread(self.commit, relative_path, accept=accept)

    async def aabort(self) -> None:
        await asyncio.to_thread(self.abort)


# ─── Read (both formats; §4.2 order, §5.1 detection) ──────────────────────────────────────────

_HEX = re.compile(r"[0-9a-fA-F]+")


def row_format(nonce_hex) -> Optional[int]:
    """The format a row says its file is in (§5.1): 2 for a 14-hex nonce prefix, 0 for a 24-hex
    v0 nonce, None for anything else (a malformed row)."""
    if isinstance(nonce_hex, str) and _HEX.fullmatch(nonce_hex):
        return {2 * codec.PREFIX_LEN: 2, 24: 0}.get(len(nonce_hex))
    return None


def stored_size(nonce_hex, plaintext_size: int) -> Optional[int]:
    """On-disk size of a stored file holding `plaintext_size` bytes in the row's format (v0:
    plaintext + the 16-byte tag; v2: codec.container_size), None for a malformed row."""
    fmt = row_format(nonce_hex)
    if fmt == 2:
        return codec.container_size(plaintext_size)
    if fmt == 0:
        return plaintext_size + 16
    return None


def _read_key(relative_path: str, root: Optional[str], fmt: int) -> bytes:
    try:
        return _load_key()
    except EvidenceCryptoError as e:
        raise _cannot_read(relative_path, root, fmt, "kek_unavailable", str(e)) from None


def iter_decrypted(relative_path: str, nonce_hex, size, *, root: Optional[str] = None) -> Iterator[bytes]:
    """Yield a stored file's plaintext: v2 chunk by chunk (≤ 1 MiB each, bounded RAM), v0 as one
    block. The row (`nonce_hex`, `size` = its plaintext byte count) fixes the expected format.

    Steps, in the §4.2 order (the first failure decides): 1 open + fstat, 2 the row is well-formed,
    3 v2 on-disk size == container_size(size), 4 the magic matches the row's format, 5 header,
    6 nonce_hex == header prefix (constant time), 7 unwrap, 8 chunks, 9 finalize.

    F-12: each yielded block is authentic, but the file is complete only when this generator
    ends without raising. A consumer must treat any exception as failure of the whole operation
    and record nothing as done before the end. Blocking."""
    try:
        path = _safe_target(relative_path, root)
    except EvidenceCryptoError as e:
        raise _cannot_read(relative_path, root, None, "invalid_path", str(e)) from None
    try:                                                                       # 1
        f = open(path, "rb")
    except FileNotFoundError:
        raise _cannot_read(relative_path, root, row_format(nonce_hex), "file_missing",
                           f"Stored file not found: {relative_path}") from None
    except OSError as e:
        raise _cannot_read(relative_path, root, row_format(nonce_hex), "io_error",
                           f"Stored file could not be opened: {relative_path} ({e.strerror})") from None
    with f:
        fmt = row_format(nonce_hex)
        try:
            st = os.fstat(f.fileno())
            if fmt is None:                                                    # 2
                raise EvidenceIntegrityError("The row's nonce_hex is not 14 or 24 hex characters.",
                                             reason="malformed_row")
            if fmt == 2:
                if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                    raise EvidenceIntegrityError("The v2 row has no valid plaintext size.", reason="malformed_row")
                try:
                    expected = codec.container_size(size)
                except ValueError:
                    raise EvidenceIntegrityError("The v2 row's size is out of range.", reason="malformed_row") from None
                if st.st_size != expected:                                     # 3
                    raise EvidenceIntegrityError(
                        f"The stored file is {st.st_size} bytes; its row's size needs {expected}.",
                        reason="size_mismatch")
            head = codec.read_exactly(f.read, len(codec.MAGIC))
            if codec.is_streaming_format(head) != (fmt == 2):                  # 4
                raise EvidenceIntegrityError("The stored file's format does not match its row.",
                                             reason="format_mismatch")
            key = _read_key(relative_path, root, fmt)
            if fmt == 0:
                f.seek(0)
                ct = f.read()                       # no head + rest concatenation (a whole-file copy)
                try:
                    plaintext = decrypt_file_bytes(ct, nonce_hex)
                except EvidenceIntegrityError as e:
                    e.reason = e.reason or "tag"
                    raise
                del ct
            else:
                header = head + codec.read_exactly(f.read, codec.HEADER_LEN - len(head))
                try:
                    h = codec.decode_header(header)                            # 5
                except codec.CodecError as e:
                    raise EvidenceIntegrityError(f"Invalid v2 header: {e}", reason="bad_header") from None
                if not hmac.compare_digest(bytes.fromhex(nonce_hex), h.nonce_prefix):   # 6
                    raise EvidenceIntegrityError("The row's nonce_hex does not match the file's nonce prefix.",
                                                 reason="nonce_mismatch")
                try:
                    dec = codec.StreamDecryptor(key, header)                   # 7
                except codec.CodecUnwrapError as e:
                    if e.kek_id_matches:
                        raise EvidenceIntegrityError(f"The key slot is corrupt: {e}", reason="slot_corrupt") from None
                    raise _cannot_read(relative_path, root, fmt, "wrong_kek",
                                       f"The stored file cannot be opened with the configured EVIDENCE_KEK: {e}") from None
                except codec.CodecError as e:
                    raise EvidenceIntegrityError(f"Invalid v2 header: {e}", reason="bad_header") from None
                if not dec.kek_id_matches:
                    _warn_kek_id(relative_path, root)
        except OSError as e:
            raise _cannot_read(relative_path, root, fmt, "io_error",
                               f"Stored file could not be read: {relative_path} ({e.strerror})") from None
        if fmt == 0:
            yield plaintext
            return
        segments = codec.iter_segments(f.read)
        while True:
            try:
                seg = next(segments, None)
            except OSError as e:
                raise _cannot_read(relative_path, root, fmt, "io_error",
                                   f"Stored file could not be read: {relative_path} ({e.strerror})") from None
            if seg is None:
                break
            try:
                pt = dec.update(seg)                                           # 8
            except codec.CodecIntegrityError as e:
                raise EvidenceIntegrityError(str(e), reason="chunk_auth") from None
            yield pt
        try:
            dec.finalize()                                                     # 9
        except codec.CodecIntegrityError as e:
            raise EvidenceIntegrityError(str(e), reason="truncated") from None


def read_decrypted(relative_path: str, nonce_hex: str, size: Optional[int] = None, *,
                   root: Optional[str] = None) -> bytes:
    """Read a stored file (either format) and return its whole plaintext. `size` = the row's
    plaintext size (required for v2: a v2 row without one is an integrity failure). Blocking."""
    return b"".join(iter_decrypted(relative_path, nonce_hex, size, root=root))


def sha256_decrypted(relative_path: str, nonce_hex: str, size: Optional[int], *,
                     root: Optional[str] = None) -> str:
    """SHA-256 of a stored file's plaintext, hashed as it is decrypted (v2: bounded RAM; v0: the
    file is decrypted whole). Blocking."""
    h = hashlib.sha256()
    for part in iter_decrypted(relative_path, nonce_hex, size, root=root):
        h.update(part)
    return h.hexdigest()


async def read_decrypted_stream(relative_path: str, row_nonce_hex: str, row_size: Optional[int], *,
                                root: Optional[str] = None, batch: int = 4) -> AsyncIterator[bytes]:
    """Async form of iter_decrypted: the work runs in worker threads, `batch` chunks per hop.
    Same F-12 contract: the stream is complete only when iteration ends without raising."""
    it = iter_decrypted(relative_path, row_nonce_hex, row_size, root=root)

    def pull() -> list[bytes]:
        out = []
        for part in it:
            out.append(part)
            if len(out) >= batch:
                break
        return out

    try:
        while True:
            parts = await asyncio.to_thread(pull)
            if not parts:
                return
            for part in parts:
                yield part
    finally:
        try:
            await asyncio.to_thread(it.close)
        except ValueError:          # still running in a cancelled hop; closed when collected
            pass


def delete_encrypted(relative_path: str) -> None:
    """Remove encrypted file + sidecar. Used on disposition. No-op if absent."""
    path = _safe_target(relative_path)
    sidecar = path.with_suffix(path.suffix + ".nonce")
    for p in (path, sidecar):
        try:
            p.unlink()
        except FileNotFoundError:
            pass


# ─── Startup (§6.4 gate, §4.4 stale staging files) ────────────────────────────────────────────

ROTATION_LOCK = ".kek-rotation.lock"
# A rotation journal is `<file>.keyslot` (§6.4) or `<file>.rewrite` (§5.4) AND starts with that journal's
# magic (G-fix R3-1). The name alone proves nothing: a stored file's name can end the same way (an
# uploaded "x.keyslot"), and must never block startup or be taken for a journal by the rotation tool.
JOURNAL_MAGIC = {".keyslot": b"FENRKSJ1", ".rewrite": b"FENRRWJ1"}


def read_head(path, n: int = 8) -> Optional[bytes]:
    """Up to `n` leading bytes of a regular file, opened O_NOFOLLOW (never a symlink, never blocks on a
    FIFO); None when it is not a readable regular file."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return os.pread(fd, n, 0)
    except OSError:
        return None
    finally:
        os.close(fd)


def journal_kind(path) -> Optional[str]:
    """".keyslot" / ".rewrite" when `path` is a rotation journal by name AND content (it starts with that
    journal's 8-byte magic), else None. A journal's `.tmp` is not a journal (never renamed into place)."""
    name = os.path.basename(path)
    for suffix, magic in JOURNAL_MAGIC.items():
        if name.endswith(suffix):
            return suffix if read_head(path, len(magic)) == magic else None
    return None


def check_storage_gate(roots: tuple[str, ...]) -> None:
    """Refuse to start while a KEK rotation or a v2 rewrite may have left a file half done (§6.4):
    the lock `<evidence_path>/.kek-rotation.lock`, or any `*.keyslot` / `*.rewrite` journal under
    `roots` (recognised by its magic, journal_kind: a stored file merely named like one is not a
    journal). Q4 reads "unwrap failed with a matching kek_id" as a corrupt key slot (integrity,
    freeze), which is sound only while no torn slot can exist. Raises RuntimeError."""
    lock = Path(settings.evidence_path) / ROTATION_LOCK
    if os.path.lexists(lock):
        raise RuntimeError(f"{lock} exists: a KEK rotation is running or did not finish. The backend "
                           "refuses to start until the rotation tool completes or recovers it.")
    for root in roots:
        for dirpath, _dirs, files in os.walk(root):
            hit = next((n for n in files if journal_kind(os.path.join(dirpath, n))), None)
            if hit:
                raise RuntimeError(f"{os.path.join(dirpath, hit)} exists: a key-slot or rewrite journal "
                                   "was left behind. The backend refuses to start until the tool that "
                                   "wrote it recovers it.")


def sweep_staging(root: str, older_than_minutes: int = STALE_PARTIAL_MINUTES) -> int:
    """Create <root>/.staging/ (0700) if needed and delete `*.partial` files idle longer than
    `older_than_minutes` (left by a crash; they never had a row), except the ones a writer of this
    process still has open (track_partial). Returns the count."""
    staging = Path(root) / STAGING_DIR
    staging.mkdir(mode=0o700, exist_ok=True)
    cutoff = time.time() - older_than_minutes * 60
    removed = 0
    with _live_lock:
        live = set(_LIVE_PARTIALS)
    for entry in os.scandir(staging):
        if (entry.name.endswith(PARTIAL_SUFFIX) and entry.is_file(follow_symlinks=False)
                and os.path.realpath(entry.path) not in live
                and entry.stat(follow_symlinks=False).st_mtime < cutoff):
            os.unlink(entry.path)
            removed += 1
    if removed:
        _fsync_dir(staging)
    return removed


# ─── Async wrappers — prefer these from request handlers ────────────────────
# Encrypt/decrypt is CPU-bound and grows linearly with file size, and it does
# blocking file I/O; on the event loop it would freeze every other request.

async def awrite_encrypted(plaintext: bytes, relative_path: str, *, root: Optional[str] = None) -> StoredFile:
    return await asyncio.to_thread(write_encrypted, plaintext, relative_path, root=root)


async def aread_decrypted(relative_path: str, nonce_hex: str, size: Optional[int] = None, *,
                          root: Optional[str] = None) -> bytes:
    return await asyncio.to_thread(read_decrypted, relative_path, nonce_hex, size, root=root)


async def asha256_decrypted(relative_path: str, nonce_hex: str, size: Optional[int], *,
                            root: Optional[str] = None) -> str:
    return await asyncio.to_thread(sha256_decrypted, relative_path, nonce_hex, size, root=root)


async def adelete_encrypted(relative_path: str) -> None:
    await asyncio.to_thread(delete_encrypted, relative_path)
