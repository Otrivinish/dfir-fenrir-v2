"""H1 (R06): the quarantine store (Artifacts, `/quarantine`) encrypted at rest.

Every new quarantine file is written as FENRGCM v2 (evidence/crypto.py, docs/streaming-aes-gcm-format.md
§4.2-4.4, unchanged codec) through `<quarantine>/.staging/` with `root=settings.quarantine_path`; the row
keeps the 7-byte nonce prefix in `artifacts.nonce_hex` (checked on every read, Q5) and `file_size` is the
plaintext size. Plaintext never reaches a disk: parsers and the analysis worker get a private copy on the
RAM-only parser tmpfs (PARSE_TMP_DIR, /run/fenrir-parse), deleted after use.

Row formats (the row decides, never the file):
  nonce_hex 14 hex  v2, read through crypto.iter_decrypted (§4.2 order, read alarms, integrity errors)
  nonce_hex NULL    "plain": a legacy plaintext file written before H1, read as-is (with a size check) until
                    `python -m artifacts.encrypt_quarantine --apply` migrates it

Errors: crypto.EvidenceCryptoError (cannot read: `.reason` file_missing / io_error / wrong_kek / ...) and
crypto.EvidenceIntegrityError (tampered or corrupt). Routes map them with read_error(). Everything here
blocks unless named a*; handlers run it in worker threads.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import re
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Iterator, Optional

import pyzipper
from fastapi import HTTPException, status

from core.config import settings
from core.errors import ApiError
from evidence import crypto
from forensic.parser import PARSE_TMP_DIR

CHUNK = 1024 * 1024
ZIP_PASSWORD = b"infected"
_PARSE_PREFIX = "fenrir-parse-"          # forensic.parser.sweep_parse_tmp removes leftovers at startup


def root() -> str:
    return settings.quarantine_path


def rel_path(incident_id, stored_filename: str) -> str:
    return f"{incident_id}/{stored_filename}"


def safe_filename(name: str) -> str:
    """Stored-name part from an uploaded name: special characters stripped, extension kept, ≤ 200 chars."""
    stem, ext = Path(name).stem, Path(name).suffix
    safe = re.sub(r"[^\w\-.]", "_", stem)[:200 - len(ext)]
    return (safe or "artifact") + re.sub(r"[^\w\-.]", "_", ext)


def stored_name(artifact_id, original_filename: str) -> str:
    """`<id>_<safe name>.enc`: new stored names end in .enc, never in a reserved suffix (G-fix R3-1)."""
    return f"{artifact_id}_{safe_filename(original_filename or 'artifact.bin')}.enc"


def is_encrypted(a) -> bool:
    return a.nonce_hex is not None


# ─── Write ─────────────────────────────────────────────────────────────────────────────────────

class Tap:
    """Wraps a blocking binary source or sink: SHA-512 and the first 2 KiB (for libmagic) of every byte
    that passes, and an optional size cap (413 when exceeded; the staged write is then discarded)."""

    def __init__(self, inner, cap: Optional[int] = None):
        self.inner, self.cap = inner, cap
        self.sha512 = hashlib.sha512()
        self.head = b""
        self.size = 0

    def _see(self, b) -> None:
        self.size += len(b)
        if self.cap is not None and self.size > self.cap:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, f"Upload exceeds {self.cap} bytes")
        self.sha512.update(b)
        if len(self.head) < 2048:
            self.head += bytes(b[:2048 - len(self.head)])

    def read(self, n: int = -1) -> bytes:
        b = self.inner.read(n)
        self._see(b)
        return b

    def write(self, b) -> int:
        self._see(b)
        self.inner.write(b)
        return len(b)


async def awrite(source, incident_id, stored_filename: str, *, cap: Optional[int] = None):
    """Encrypt `source` (bytes or a blocking binary file object) into the quarantine as v2 in one pass.
    Returns (StoredFile, Tap): StoredFile has nonce_hex / sha256 / md5 / size, the Tap sha512 and head."""
    tap = Tap(source if hasattr(source, "read") else _BytesReader(source), cap)
    stored = await crypto.write_encrypted_stream(tap, rel_path(incident_id, stored_filename), root=root())
    return stored, tap


class _BytesReader:
    def __init__(self, data):
        self.mv, self.pos = memoryview(data).cast("B"), 0

    def read(self, n: int = -1) -> bytes:
        end = len(self.mv) if n is None or n < 0 else min(len(self.mv), self.pos + n)
        out = bytes(self.mv[self.pos:end])
        self.pos = end
        return out


# ─── Read ──────────────────────────────────────────────────────────────────────────────────────

def iter_plaintext(a) -> Iterator[bytes]:
    """The artifact's bytes, ≤ 1 MiB at a time (bounded RAM), whatever its row format. F-12: complete
    only when the iteration ends without raising."""
    rel = rel_path(a.incident_id, a.stored_filename)
    if is_encrypted(a):
        yield from crypto.iter_decrypted(rel, a.nonce_hex, a.file_size, root=root())
        return
    try:
        path = crypto._safe_target(rel, root())
    except crypto.EvidenceCryptoError as e:
        raise crypto._cannot_read(rel, root(), None, "invalid_path", str(e)) from None
    try:
        f = open(path, "rb")
    except FileNotFoundError:
        raise crypto._cannot_read(rel, root(), None, "file_missing", f"Stored file not found: {rel}") from None
    except OSError as e:
        raise crypto._cannot_read(rel, root(), None, "io_error", f"Stored file could not be opened: {rel} ({e.strerror})") from None
    with f:
        if os.fstat(f.fileno()).st_size != a.file_size:
            raise crypto.EvidenceIntegrityError("The plaintext quarantine file's size differs from its row.",
                                                reason="size_mismatch")
        while True:
            try:
                block = f.read(CHUNK)
            except OSError as e:
                raise crypto._cannot_read(rel, root(), None, "io_error", f"Stored file could not be read: {rel} ({e.strerror})") from None
            if not block:
                return
            yield block


def read_all(a, max_bytes: int) -> bytes:
    """The whole artifact in memory, for the small legacy readers (emails, history DBs ≤ their upload
    caps). 413 when the row is larger than `max_bytes`."""
    if a.file_size is not None and a.file_size > max_bytes:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, f"The stored file exceeds {max_bytes} bytes")
    return b"".join(iter_plaintext(a))


def materialise(a) -> tuple[str, str]:
    """A private copy of the artifact's plaintext on the RAM-only parser tmpfs, for tools that need a path
    (the collection parser, the analysis worker upload). Returns (path, SHA-256 of the bytes written); the
    file exists only once the whole stream authenticated (F-12). The caller removes it with discard()."""
    if not os.path.isdir(PARSE_TMP_DIR):
        raise crypto.EvidenceCryptoError(f"Parser scratch space {PARSE_TMP_DIR} is unavailable; refusing to "
                                         "write the plaintext anywhere else", reason="io_error")
    fd, path = tempfile.mkstemp(dir=PARSE_TMP_DIR, prefix=_PARSE_PREFIX)
    h = hashlib.sha256()
    try:
        with os.fdopen(fd, "wb") as f:
            for part in iter_plaintext(a):
                h.update(part)
                f.write(part)
    except BaseException:
        discard(path)
        raise
    return path, h.hexdigest()


def discard(path: Optional[str]) -> None:
    if path:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def zip_infected(a):
    """The artifact in an AES-256 ZIP with the malware-analyst password `infected`, built on the RAM tmpfs
    (an unnamed file, gone when closed) from the authenticated stream. Returns (open file at 0, size)."""
    f = tempfile.TemporaryFile(dir=PARSE_TMP_DIR, prefix=_PARSE_PREFIX)
    try:
        with pyzipper.AESZipFile(f, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(ZIP_PASSWORD)
            zinfo = getattr(zf, "zipinfo_cls", zipfile.ZipInfo)(a.original_filename or a.stored_filename,
                                                               date_time=time.localtime(time.time())[:6])
            zinfo.compress_type = zf.compression
            zinfo.external_attr = 0o600 << 16
            zinfo.file_size = a.file_size or 0
            with zf.open(zinfo, "w") as dest:
                for part in iter_plaintext(a):
                    dest.write(part)
        size = f.tell()
        f.seek(0)
        return f, size
    except BaseException:
        f.close()
        raise


def unlink(incident_id, stored_filename: str) -> None:
    """Remove an artifact's stored file (either format); no-op if absent."""
    try:
        os.unlink(crypto._safe_target(rel_path(incident_id, stored_filename), root()))
    except FileNotFoundError:
        pass


def read_error(e: crypto.EvidenceCryptoError, *, missing_status: int = status.HTTP_404_NOT_FOUND,
               missing_detail: str = "File not found on disk") -> HTTPException:
    """The HTTP error for a failed quarantine read: a missing file keeps the route's old status; a file
    that fails authentication or its size check is 409 artifact_integrity_failed; anything else that
    cannot be read (wrong or missing KEK, I/O) is 503 artifact_read_error (already alarmed by crypto)."""
    if isinstance(e, crypto.EvidenceIntegrityError):
        return ApiError(status.HTTP_409_CONFLICT, "artifact_integrity_failed",
                        f"The stored artifact failed its integrity check ({e.reason or 'integrity'}); "
                        "it is not the file that was stored. Nothing was read.")
    if e.reason == "file_missing":
        return HTTPException(missing_status, missing_detail)
    return ApiError(status.HTTP_503_SERVICE_UNAVAILABLE, "artifact_read_error",
                    f"The stored artifact could not be read ({e.reason or 'error'}). Admins were notified.")


async def amaterialise(a) -> tuple[str, str]:
    return await asyncio.to_thread(materialise, a)


async def adiscard(path: Optional[str]) -> None:
    await asyncio.to_thread(discard, path)
