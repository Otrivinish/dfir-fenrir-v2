"""S6 (EG-4, HLD §2.4, §3.5): a seekable, read-only view of a stored FENRGCM v2 file, so `zipfile` can seek to a
container's central directory without decrypting the whole file first.

open_view() runs the §4.2 checks of crypto.iter_decrypted in the same order (1 open + fstat, 2 the row is well-formed,
3 on-disk size == container_size(size), 4 magic, 5 header, 6 nonce_hex == header prefix, 7 unwrap) with the same error
mapping, then authenticates the FINAL chunk at its index: together with step 3 this proves the file ends exactly where
the row says (truncation, extension, a dropped or moved final chunk all fail here). After that, read() decrypts and
authenticates each 1 MiB chunk it touches, at its own index (a swapped or moved chunk fails: the index and the final
flag are in the nonce), keeps a few decrypted chunks in a small LRU (bounded memory), and never returns a byte of a
chunk that failed. Any failure raises (EvidenceIntegrityError / EvidenceCryptoError): the caller records nothing (F-12).

No new crypto: the same key-slot opening and per-chunk AES-GCM as codec.StreamDecryptor (codec._open_key_slot /
_decrypt_chunk), addressed by index instead of in order. v0 (legacy whole-file) rows are not supported: LegacyFormat.
Blocking (pread + AES): call it from a worker thread.
"""
from __future__ import annotations

import hmac
import os
from collections import OrderedDict
from typing import Optional

from evidence import codec
from evidence import crypto
from evidence.crypto import EvidenceCryptoError, EvidenceIntegrityError

LRU_CHUNKS = 4


class LegacyFormat(EvidenceCryptoError):
    """The row is a v0 (whole-file AES-GCM) file: no chunks to address."""

    def __init__(self):
        super().__init__("v0 (legacy) stored files have no seekable view", reason="legacy_format")


class DecryptedView:
    """File-like (read / seek / tell / seekable / readable / close) over the plaintext of one v2 file."""

    def __init__(self, fd: int, dek: bytes, header: codec.Header, size: int, relative_path: str,
                 root: Optional[str]):
        self._fd, self._dek, self.size = fd, dek, size
        self._prefix, self._aad = header.nonce_prefix, header.aad
        self._rel, self._root = relative_path, root
        self._last = size // codec.CHUNK_SIZE           # index of the final chunk (it always exists)
        self._pos = 0
        self._lru: OrderedDict[int, bytes] = OrderedDict()

    # ── chunks ──
    def _chunk(self, i: int) -> bytes:
        pt = self._lru.get(i)
        if pt is not None:
            self._lru.move_to_end(i)
            return pt
        final = i == self._last
        length = (self.size - i * codec.CHUNK_SIZE + codec.TAG_LEN) if final else codec.SEGMENT_LEN
        try:
            seg = os.pread(self._fd, length, codec.HEADER_LEN + i * codec.SEGMENT_LEN)
        except OSError as e:
            raise crypto._cannot_read(self._rel, self._root, 2, "io_error",
                                      f"Stored file could not be read: {self._rel} ({e.strerror})") from None
        if len(seg) != length:                            # the file shrank after the size check
            raise EvidenceIntegrityError(f"chunk {i}: truncated ({len(seg)} of {length} bytes)", reason="truncated")
        try:
            pt = codec._decrypt_chunk(self._dek, self._prefix, i, final, self._aad, seg)
        except codec.CodecIntegrityError as e:
            raise EvidenceIntegrityError(str(e), reason="chunk_auth") from None
        self._lru[i] = pt
        if len(self._lru) > LRU_CHUNKS:
            self._lru.popitem(last=False)
        return pt

    # ── file protocol ──
    def read(self, n: int = -1) -> bytes:
        if self._fd is None:
            raise ValueError("I/O operation on a closed view")
        end = self.size if n is None or n < 0 else min(self.size, self._pos + n)
        out = bytearray()
        while self._pos < end:
            i, off = divmod(self._pos, codec.CHUNK_SIZE)
            piece = self._chunk(i)[off:off + (end - self._pos)]
            out += piece
            self._pos += len(piece)
        return bytes(out)

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        base = {os.SEEK_SET: 0, os.SEEK_CUR: self._pos, os.SEEK_END: self.size}[whence]
        if base + offset < 0:
            raise OSError(22, "negative seek position")
        self._pos = base + offset
        return self._pos

    def tell(self) -> int:
        return self._pos

    def seekable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        self._lru.clear()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def open_view(relative_path: str, nonce_hex, size, *, root: Optional[str] = None) -> DecryptedView:
    """The view of a stored v2 file whose row has `nonce_hex` (14 hex) and plaintext `size`. Raises LegacyFormat for
    a v0 row, EvidenceIntegrityError (tampered / corrupt / truncated / extended) or EvidenceCryptoError (cannot read:
    missing, I/O, wrong KEK) exactly as iter_decrypted would. Blocking."""
    fmt = crypto.row_format(nonce_hex)
    if fmt == 0:
        raise LegacyFormat()
    try:
        path = crypto._safe_target(relative_path, root)
    except EvidenceCryptoError as e:
        raise crypto._cannot_read(relative_path, root, None, "invalid_path", str(e)) from None
    try:                                                                       # 1
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    except FileNotFoundError:
        raise crypto._cannot_read(relative_path, root, fmt, "file_missing",
                                  f"Stored file not found: {relative_path}") from None
    except OSError as e:
        raise crypto._cannot_read(relative_path, root, fmt, "io_error",
                                  f"Stored file could not be opened: {relative_path} ({e.strerror})") from None
    try:
        try:
            st = os.fstat(fd)
            if fmt is None:                                                    # 2
                raise EvidenceIntegrityError("The row's nonce_hex is not 14 or 24 hex characters.",
                                             reason="malformed_row")
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                raise EvidenceIntegrityError("The v2 row has no valid plaintext size.", reason="malformed_row")
            try:
                expected = codec.container_size(size)
            except ValueError:
                raise EvidenceIntegrityError("The v2 row's size is out of range.", reason="malformed_row") from None
            if st.st_size != expected:                                         # 3
                raise EvidenceIntegrityError(f"The stored file is {st.st_size} bytes; its row's size needs {expected}.",
                                             reason="size_mismatch")
            header = os.pread(fd, codec.HEADER_LEN, 0)
            if not codec.is_streaming_format(header):                          # 4
                raise EvidenceIntegrityError("The stored file's format does not match its row.",
                                             reason="format_mismatch")
            try:
                h = codec.decode_header(header)                                # 5
            except codec.CodecError as e:
                raise EvidenceIntegrityError(f"Invalid v2 header: {e}", reason="bad_header") from None
            if not hmac.compare_digest(bytes.fromhex(nonce_hex), h.nonce_prefix):   # 6
                raise EvidenceIntegrityError("The row's nonce_hex does not match the file's nonce prefix.",
                                             reason="nonce_mismatch")
            key = crypto._read_key(relative_path, root, fmt)
            try:
                dek = codec._open_key_slot(key, h)                             # 7
            except codec.CodecUnwrapError as e:
                if e.kek_id_matches:
                    raise EvidenceIntegrityError(f"The key slot is corrupt: {e}", reason="slot_corrupt") from None
                raise crypto._cannot_read(relative_path, root, fmt, "wrong_kek",
                                          f"The stored file cannot be opened with the configured EVIDENCE_KEK: {e}") from None
            if not codec._kek_id_matches(key, h):
                crypto._warn_kek_id(relative_path, root)
        except OSError as e:
            raise crypto._cannot_read(relative_path, root, fmt, "io_error",
                                      f"Stored file could not be read: {relative_path} ({e.strerror})") from None
        view = DecryptedView(fd, dek, h, size, relative_path, root)
        view._chunk(view._last)                     # the final chunk, at its index: the file ends where the row says
        return view
    except BaseException:
        os.close(fd)
        raise
