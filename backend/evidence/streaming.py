"""G2 (R04 part 2): bounded-RAM reads of stored files for downloads, export bundles and LE packages.

  decrypted_download()   a stored file (evidence photo, entity file, incident File) as an HTTP response
  StagedOutput           a large output file (export / LE bundle) built in <evidence>/.staging/ and moved into
                         place only once complete
  require_free_space()   507 insufficient_storage when the evidence volume (or another store's) lacks room

Every reader follows the streaming contract (docs/streaming-aes-gcm-format.md §6.3, F-12): each decrypted
chunk is authentic, but the file is complete only when the stream ends without an error, so any error is a
failure of the whole operation and nothing is offered or recorded as done before the end.

Downloads:
  * §4.2 steps 1-8 for the first chunk (open, size, format, header, nonce_hex, unwrap, chunk 0) run before any
    header is sent: a missing, unreadable or tampered file keeps its route's normal error status;
  * a file of at most SMALL_FILE_BYTES, and every v0 file (decrypted whole by design), is read to the end, and
    so fully authenticated, before the response starts: no partial body is ever sent for it;
  * a larger file streams with Content-Length = the row's plaintext size. If a later chunk fails, the body
    iterator raises, the body stops short of Content-Length and the server closes the connection, so the client
    sees a failed transfer, never a clean end of file. Content-Length is load-bearing: the BaseHTTPMiddleware
    in the stack ends the body cleanly when the app raises, and only uvicorn's length check ("Response content
    shorter than Content-Length") turns that into an abort. Never stream a stored file without it.
"""
from __future__ import annotations

import logging
import os
import uuid
from pathlib import Path
from typing import Optional

import anyio
from fastapi import status
from fastapi.responses import Response, StreamingResponse

from core.config import settings
from core.errors import ApiError
from evidence import crypto

log = logging.getLogger("fenrir.evidence.streaming")

# Up to this size a download is decrypted and authenticated to the end before its first byte is sent
# (16 MiB of RAM per request at most): a tampered file then gets its route's error status instead of an
# aborted transfer. Photos, screenshots and most entity files are under it.
SMALL_FILE_BYTES = 16 * 1024 * 1024

# Space kept free on the evidence volume (statvfs): an upload or a bundle that would leave less is refused.
FREE_SPACE_RESERVE = 1024 * 1024 * 1024


async def decrypted_download(relative_path: str, nonce_hex: str, size: Optional[int], *,
                             root: Optional[str] = None, media_type: str,
                             headers: Optional[dict] = None) -> Response:
    """The plaintext of a stored file as a response (rules above). Raises EvidenceIntegrityError /
    EvidenceCryptoError (and ValueError on a codec misuse) exactly as aread_decrypted does when the file
    fails before the response starts; the caller maps them as before."""
    headers = dict(headers or {})
    stream = crypto.read_decrypted_stream(relative_path, nonce_hex, size, root=root)

    async def close() -> None:
        with anyio.CancelScope(shield=True):         # also when the request was cancelled
            await stream.aclose()

    try:
        first = await anext(stream, b"")
        if crypto.row_format(nonce_hex) != 2 or size is None or size <= SMALL_FILE_BYTES:
            parts = [first]
            async for part in stream:
                parts.append(part)
            return Response(content=b"".join(parts), media_type=media_type, headers=headers)
    except BaseException:
        await close()
        raise

    async def body():
        try:
            yield first
            async for part in stream:
                yield part
        except Exception as e:
            # F-12: abort the transfer (see the module docstring). A cannot-read was already alarmed by crypto.
            log.error("download of %s aborted mid-stream (%s: %s)", relative_path, type(e).__name__,
                      getattr(e, "reason", None) or e)
            raise
        finally:
            await close()

    headers["Content-Length"] = str(size)
    return StreamingResponse(body(), media_type=media_type, headers=headers)


class StagedOutput:
    """A large output file (export or LE bundle) written to <evidence>/.staging/<random>.partial (O_EXCL) and
    moved into place only when complete: fsync, rename, fsync both directories (the §4.4 staging protocol). A
    failed build is discarded, so a half-written bundle is never offered, and the backup mirror never copies
    it (backup.sh skips .staging/ and *.partial; the startup sweep removes one left by a crash). `file` is a
    buffered, seekable binary file. Blocking: use from a worker thread."""

    def __init__(self) -> None:
        base = Path(settings.evidence_path).resolve()
        self.base = base
        self.staging = base / crypto.STAGING_DIR
        self.staging.mkdir(mode=0o700, exist_ok=True)
        self.path: Optional[Path] = self.staging / f"{uuid.uuid4().hex}{crypto.PARTIAL_SUFFIX}"
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o644)
        self.file = os.fdopen(fd, "wb")
        crypto.track_partial(self.path, True)        # the periodic staging sweep never removes it (ROT-L1)

    def finish(self) -> int:
        """Flush, fsync and close the staged file; returns its size."""
        self.file.flush()
        os.fsync(self.file.fileno())
        size = os.fstat(self.file.fileno()).st_size
        self.file.close()
        return size

    def commit(self, relative_path: str) -> None:
        """Move the finished file to `relative_path` under the evidence root (never over an existing file)."""
        target = crypto._safe_target(relative_path)
        crypto._make_parents(target, self.base)
        if os.path.lexists(target):
            raise crypto.EvidenceCryptoError(f"refusing to overwrite a stored file: {relative_path!r}")
        os.rename(self.path, target)
        crypto.track_partial(self.path, False)
        self.path = None
        crypto._fsync_dir(target.parent)
        crypto._fsync_dir(self.staging)

    def discard(self) -> None:
        """Close and delete the staged file; idempotent."""
        try:
            self.file.close()
        except OSError:
            pass
        if self.path is not None:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
            crypto.track_partial(self.path, False)
            self.path = None


def free_bytes(root: Optional[str] = None) -> int:
    """Bytes an unprivileged writer can still use on the volume of `root` (default: the evidence volume;
    statvfs, one cheap syscall)."""
    st = os.statvfs(root or settings.evidence_path)
    return st.f_bavail * st.f_frsize


def _gib(n: int) -> str:
    return f"{n / 1024 ** 3:.2f} GiB"


def require_free_space(needed: int, what: str, root: Optional[str] = None) -> None:
    """507 insufficient_storage unless the volume of `root` (default: the evidence volume) has `needed` bytes
    plus FREE_SPACE_RESERVE free. L2 (G-fix B): every write of a stored file checks it — the upload sessions,
    the multipart evidence / photo / File / entity-file routes, the direct analyser uploads and the imports."""
    free = free_bytes(root)
    if free < needed + FREE_SPACE_RESERVE:
        volume = {None: "the evidence volume", settings.evidence_path: "the evidence volume",
                  settings.logs_path: "the file store (entity and incident files)",
                  settings.quarantine_path: "the quarantine volume"}.get(root, "the storage volume")
        raise ApiError(status.HTTP_507_INSUFFICIENT_STORAGE, "insufficient_storage",
                       f"Not enough free space on {volume} for {what}: it needs {_gib(needed)} plus a "
                       f"{_gib(FREE_SPACE_RESERVE)} reserve, and {_gib(free)} is free. Nothing was stored. Ask an "
                       "admin to free space or extend the volume.")
