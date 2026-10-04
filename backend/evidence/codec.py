"""FENRGCM v2 streaming evidence container: the pure codec.

Spec: docs/streaming-aes-gcm-format.md (revised 2026-10-04, stage 1b). This module does no
file I/O and reads no settings: callers pass the KEK and feed it bytes (or a `read` callable).

DORMANT until G1 stage 3: nothing imports it yet and nothing is written in this format.

Sealing has exactly one public path, StreamEncryptor, which draws the data key and the nonce
prefix from os.urandom itself; opening has one, StreamDecryptor; the key slot is rewritten only
through rewrap_header. Helpers that would let a caller choose a DEK or a prefix are private.

The byte layout below is the on-disk format. Changing a constant, label or field changes the
format; tests/test_codec.py pins it with known-answer vectors.

Header (HEADER_LEN = 80 bytes):
    0   7  magic         b"FENRGCM"
    7   1  version       0x02
    8   4  chunk_size    uint32 BE, must be CHUNK_SIZE
    12  7  nonce_prefix  random per file
    19 13  reserved      must be zero
    -- bytes 0..32 are immutable and are the AAD of every chunk --
    32  1  slot_type     0x01 = AES-KW under K_wrap, 40-byte wrapped DEK
    33  7  kek_id        HKDF-SHA256(KEK, info=b"FENRGCM/v2/kek-id", L=7), advisory
    40 40  wrapped_dek   AES key wrap (RFC 3394) of the 32-byte DEK under K_wrap
    -- bytes 32..80 are the key slot, the only bytes a KEK rotation rewrites --
K_wrap = HKDF-SHA256(ikm=KEK, salt absent, info=b"FENRGCM/v2/key-wrap", L=32); the raw KEK
never wraps anything. Chunks follow the header with no framing: every non-final chunk is
CHUNK_SIZE plaintext bytes (SEGMENT_LEN on disk); exactly one final chunk ends the file with
0..CHUNK_SIZE-1 plaintext bytes (TAG_LEN..SEGMENT_LEN-1 on disk). Chunk i is AES-256-GCM under
the DEK with nonce = nonce_prefix || uint32_BE(i) || final_flag and AAD = header[0:32].
"""
import hmac
import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap, aes_key_wrap

MAGIC              = b"FENRGCM"
VERSION            = 0x02
CHUNK_SIZE         = 1024 * 1024                 # plaintext bytes in every non-final chunk
TAG_LEN            = 16                          # AES-GCM tag, appended by AESGCM.encrypt
SEGMENT_LEN        = CHUNK_SIZE + TAG_LEN        # on-disk length of every non-final chunk
KEY_LEN            = 32                          # KEK, K_wrap and DEK are AES-256 keys
PREFIX_LEN         = 7
RESERVED_LEN       = 13
AAD_LEN            = 32                          # immutable header region = AAD of every chunk
SLOT_TYPE_AES_KW   = 0x01                        # the only key-slot type v2 defines
KEK_ID_LEN         = 7
WRAPPED_DEK_LEN    = 40                          # RFC 3394 output for a 32-byte key
KEY_SLOT_OFFSET    = AAD_LEN
KEY_SLOT_LEN       = 1 + KEK_ID_LEN + WRAPPED_DEK_LEN   # 48
HEADER_LEN         = AAD_LEN + KEY_SLOT_LEN      # 80
MAX_CHUNKS         = 2 ** 32                     # uint32 chunk index, final chunk included
HKDF_INFO_KEY_WRAP = b"FENRGCM/v2/key-wrap"
HKDF_INFO_KEK_ID   = b"FENRGCM/v2/kek-id"

_IMMUTABLE = struct.Struct(">7sBI7s13s")         # magic, version, chunk_size, prefix, reserved
assert _IMMUTABLE.size == AAD_LEN


class CodecError(RuntimeError):
    """The container cannot be decrypted. Base class. Defined here, not in crypto.py, because
    crypto.py imports settings; G1 stage 3 maps these onto EvidenceCryptoError there."""


class CodecFormatError(CodecError):
    """Not a container this reader accepts: wrong magic, unsupported version, unexpected
    chunk_size, non-zero reserved bytes, or an unknown key-slot type."""


class CodecUnwrapError(CodecError):
    """The KEK did not unwrap the data key: wrong KEK, or a corrupt key slot.

    `kek_id_matches` is True when the header's kek_id equals the supplied KEK's id (so the
    slot itself is corrupt), False when it names another KEK, None when not determined."""

    def __init__(self, message: str, kek_id_matches: bool | None = None):
        super().__init__(message)
        self.kek_id_matches = kek_id_matches


class CodecIntegrityError(CodecError):
    """The bytes are not what the writer produced: a chunk failed authentication, or the
    header or chunk stream is truncated or extended."""


@dataclass(frozen=True)
class Header:
    nonce_prefix: bytes
    slot_type: int
    kek_id: bytes
    wrapped_dek: bytes
    aad: bytes                                   # header[0:AAD_LEN]


def _check_len(name: str, value: bytes, n: int) -> None:
    if len(value) != n:
        raise ValueError(f"{name} must be {n} bytes, got {len(value)}")


def _hkdf(kek: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 (RFC 5869) with the salt absent, i.e. HashLen zero bytes (RFC 5869 §2.2)."""
    _check_len("KEK", kek, KEY_LEN)
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(kek)


def _wrap_key(kek: bytes) -> bytes:
    """K_wrap: the only key that wraps DEKs. The raw KEK never does."""
    return _hkdf(kek, HKDF_INFO_KEY_WRAP, KEY_LEN)


def kek_id(kek: bytes) -> bytes:
    """Advisory 7-byte identifier of a KEK. Not secret, not authenticated, never a key selector."""
    return _hkdf(kek, HKDF_INFO_KEK_ID, KEK_ID_LEN)


def _wrap_dek(kek: bytes, dek: bytes) -> bytes:
    _check_len("data key", dek, KEY_LEN)
    return aes_key_wrap(_wrap_key(kek), dek)


def _unwrap_dek(kek: bytes, wrapped_dek: bytes) -> bytes:
    _check_len("wrapped data key", wrapped_dek, WRAPPED_DEK_LEN)
    try:
        return aes_key_unwrap(_wrap_key(kek), wrapped_dek)
    except InvalidUnwrap:
        raise CodecUnwrapError("wrong KEK or corrupt header") from None


def is_streaming_format(prefix: bytes) -> bool:
    """True if `prefix` (the first bytes of a stored file) starts with the FENRGCM magic.
    False means a legacy v0 file (raw whole-file AES-GCM ciphertext, no header). Any version
    byte counts as streaming here; decode_header then rejects versions it does not support.
    Stage 3 decides the expected format from the DB row and treats disagreement as tampering."""
    return prefix[:len(MAGIC)] == MAGIC


def _encode_header(nonce_prefix: bytes, kek_id_: bytes, wrapped_dek: bytes) -> bytes:
    _check_len("nonce prefix", nonce_prefix, PREFIX_LEN)
    _check_len("KEK id", kek_id_, KEK_ID_LEN)
    _check_len("wrapped data key", wrapped_dek, WRAPPED_DEK_LEN)
    fixed = _IMMUTABLE.pack(MAGIC, VERSION, CHUNK_SIZE, nonce_prefix, bytes(RESERVED_LEN))
    return fixed + bytes([SLOT_TYPE_AES_KW]) + kek_id_ + wrapped_dek


def decode_header(buf: bytes) -> Header:
    """Parse and validate the 80-byte header. Does not unwrap the data key."""
    buf = bytes(buf)
    if not is_streaming_format(buf):
        raise CodecFormatError("not a FENRGCM container")
    if len(buf) > len(MAGIC) and buf[len(MAGIC)] != VERSION:   # another version's header may differ
        raise CodecFormatError(f"unsupported format version {buf[len(MAGIC)]}")
    if len(buf) < HEADER_LEN:
        raise CodecIntegrityError(f"truncated header ({len(buf)} of {HEADER_LEN} bytes)")
    if len(buf) > HEADER_LEN:
        raise ValueError(f"header must be {HEADER_LEN} bytes, got {len(buf)}")
    _magic, _version, chunk_size, prefix, reserved = _IMMUTABLE.unpack(buf[:AAD_LEN])
    if chunk_size != CHUNK_SIZE:
        raise CodecFormatError(f"unsupported chunk size {chunk_size}")
    if reserved != bytes(RESERVED_LEN):
        raise CodecFormatError("header reserved bytes are not zero")
    slot_type = buf[KEY_SLOT_OFFSET]
    if slot_type != SLOT_TYPE_AES_KW:
        raise CodecFormatError(f"unsupported key slot type {slot_type}")
    return Header(nonce_prefix=prefix,
                  slot_type=slot_type,
                  kek_id=buf[KEY_SLOT_OFFSET + 1:KEY_SLOT_OFFSET + 1 + KEK_ID_LEN],
                  wrapped_dek=buf[HEADER_LEN - WRAPPED_DEK_LEN:HEADER_LEN],
                  aad=buf[:AAD_LEN])


def chunk_aad(header: bytes) -> bytes:
    """AAD of every chunk: the immutable header region (bytes 0..32), never the key slot."""
    _check_len("header", header, HEADER_LEN)
    return bytes(header[:AAD_LEN])


def chunk_nonce(nonce_prefix: bytes, index: int, final: bool) -> bytes:
    """nonce_prefix (7) || uint32_BE(index) (4) || 0x01 if final else 0x00 (1) = 12 bytes."""
    _check_len("nonce prefix", nonce_prefix, PREFIX_LEN)
    if not 0 <= index < MAX_CHUNKS:
        raise ValueError(f"chunk index {index} out of range")
    return bytes(nonce_prefix) + index.to_bytes(4, "big") + (b"\x01" if final else b"\x00")


def container_size(plaintext_len: int) -> int:
    """On-disk size of a container holding `plaintext_len` bytes (header + chunks + one tag each).
    Stage 3 compares it with the file's size before decrypting."""
    if plaintext_len < 0:
        raise ValueError("plaintext_len must be >= 0")
    chunks = plaintext_len // CHUNK_SIZE + 1     # the final chunk always exists
    if chunks > MAX_CHUNKS:
        raise ValueError("plaintext too large for the format (max 2**32 chunks)")
    return HEADER_LEN + plaintext_len + chunks * TAG_LEN


def read_exactly(read, n: int) -> bytes:
    """Call `read(k)` until n bytes are collected or it returns b"" (EOF). Returns fewer than
    n bytes only at EOF, so a short read from a pipe, socket or slow filesystem can never be
    mistaken for the final chunk. `read` must block: a None return (non-blocking source with
    no data yet) raises ValueError instead of being taken for EOF."""
    buf = bytearray()
    while len(buf) < n:
        part = read(n - len(buf))
        if part is None:
            raise ValueError("read() returned None: the source is non-blocking; read must block")
        if not part:
            break
        buf += part
    return bytes(buf)


def iter_segments(read):
    """Yield the stored chunks after the header, each a read_exactly of SEGMENT_LEN bytes.
    Feed each to StreamDecryptor.update(), then call finalize() when this is exhausted."""
    while True:
        seg = read_exactly(read, SEGMENT_LEN)
        if not seg:
            return
        yield seg


def _encrypt_chunk(dek: bytes, nonce_prefix: bytes, index: int, final: bool,
                   aad: bytes, plaintext: bytes) -> bytes:
    """Seal one chunk. Non-final chunks must be exactly CHUNK_SIZE bytes; the final chunk
    0..CHUNK_SIZE-1 bytes, so a reader can tell them apart by length alone."""
    _check_len("AAD", aad, AAD_LEN)
    if final:
        if len(plaintext) >= CHUNK_SIZE:
            raise ValueError("final chunk must be shorter than CHUNK_SIZE")
    else:
        if len(plaintext) != CHUNK_SIZE:
            raise ValueError("non-final chunk must be exactly CHUNK_SIZE bytes")
        if index >= MAX_CHUNKS - 1:
            raise ValueError("no chunk index left for the final chunk")
    return AESGCM(dek).encrypt(chunk_nonce(nonce_prefix, index, final), plaintext, aad)


def _decrypt_chunk(dek: bytes, nonce_prefix: bytes, index: int, final: bool,
                   aad: bytes, ciphertext: bytes) -> bytes:
    _check_len("AAD", aad, AAD_LEN)
    nonce = chunk_nonce(nonce_prefix, index, final)
    try:
        return AESGCM(dek).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise CodecIntegrityError(f"chunk {index}: authentication failed") from None


def _kek_id_matches(kek: bytes, header: Header) -> bool:
    return hmac.compare_digest(header.kek_id, kek_id(kek))


def _open_key_slot(kek: bytes, header: Header) -> bytes:
    try:
        return _unwrap_dek(kek, header.wrapped_dek)
    except CodecUnwrapError:
        same = _kek_id_matches(kek, header)
        hint = "the key slot is corrupt" if same else (
            f"the file names KEK id {header.kek_id.hex()}, the supplied KEK is {kek_id(kek).hex()}")
        raise CodecUnwrapError(f"wrong KEK or corrupt header ({hint})", kek_id_matches=same) from None


def rewrap_header(header: bytes, old_kek: bytes, new_kek: bytes) -> bytes:
    """KEK rotation: return the same header with only the key slot (bytes 32..80) re-wrapped
    under new_kek. Bytes 0..32, and therefore every chunk tag, are unchanged. The caller must
    still prove the old slot opens chunk 0 before journalling (spec §6.4)."""
    h = decode_header(header)
    dek = _open_key_slot(old_kek, h)
    return h.aad + bytes([SLOT_TYPE_AES_KW]) + kek_id(new_kek) + _wrap_dek(new_kek, dek)


class StreamEncryptor:
    """Writer state machine and the only sealing path. Draws the DEK (32 bytes) and then the
    nonce prefix (7 bytes) from os.urandom.

    Write `header`, then `update()` for each full CHUNK_SIZE block, then exactly one
    `finalize()` with the remaining 0..CHUNK_SIZE-1 bytes (b"" when the input length is a
    multiple of CHUNK_SIZE, including an empty input). Nothing is complete until finalize()."""

    def __init__(self, kek: bytes):
        self._dek = os.urandom(KEY_LEN)
        self._prefix = os.urandom(PREFIX_LEN)
        self.header = _encode_header(self._prefix, kek_id(kek), _wrap_dek(kek, self._dek))
        self._aad = self.header[:AAD_LEN]
        self._index = 0
        self._done = False

    def _seal(self, plaintext: bytes, final: bool) -> bytes:
        if self._done:
            raise ValueError("stream already finalized")
        out = _encrypt_chunk(self._dek, self._prefix, self._index, final, self._aad, plaintext)
        self._index += 1
        self._done = final
        return out

    def update(self, chunk: bytes) -> bytes:
        return self._seal(chunk, final=False)

    def finalize(self, tail: bytes = b"") -> bytes:
        return self._seal(tail, final=True)


class StreamDecryptor:
    """Reader state machine and the only opening path.

    Construct from the 80-byte header (validates it and unwraps the DEK; `kek_id_matches`
    then says whether the header's advisory kek_id names the supplied KEK). Feed the stored
    chunks in order, one read_exactly of SEGMENT_LEN each (see iter_segments): a SEGMENT_LEN
    segment is a non-final chunk, a shorter one the final chunk. At EOF call `finalize()`.

    Contract: each update() returns plaintext authenticated as that chunk at that position,
    but the stream as a whole is unverified until finalize() returns (it may be truncated or
    extended). Consumers must treat any exception, from update() or finalize(), as failure of
    the whole operation and must not commit, publish or record anything before finalize()."""

    def __init__(self, kek: bytes, header: bytes):
        self.header = decode_header(header)
        self._dek = _open_key_slot(kek, self.header)
        self.kek_id_matches = _kek_id_matches(kek, self.header)
        self._index = 0
        self._done = False

    def update(self, segment: bytes) -> bytes:
        n = len(segment)
        if n == 0:
            raise ValueError("empty segment: at EOF call finalize()")
        if n > SEGMENT_LEN:
            raise ValueError(f"segment longer than {SEGMENT_LEN} bytes")
        if self._done:
            raise CodecIntegrityError("data after the final chunk")
        if n < TAG_LEN:
            raise CodecIntegrityError(f"chunk {self._index}: truncated ({n} bytes)")
        final = n < SEGMENT_LEN
        if not final and self._index >= MAX_CHUNKS - 1:
            raise CodecIntegrityError("chunk index overflow")
        pt = _decrypt_chunk(self._dek, self.header.nonce_prefix, self._index, final,
                            self.header.aad, segment)
        self._index += 1
        self._done = final
        return pt

    def finalize(self) -> None:
        if not self._done:
            raise CodecIntegrityError(f"truncated: no final chunk after {self._index} chunks")
