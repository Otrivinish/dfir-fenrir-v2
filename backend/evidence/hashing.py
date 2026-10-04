"""Hash helpers for evidence files.

SHA-256 is the primary integrity hash recorded in the Evidence row and used
for verification. SHA-1 and MD5 are recorded for legacy interop (court
systems, older forensic tools). An uploaded exhibit is hashed with all three
in the same pass that encrypts it (evidence/crypto.py write_encrypted_stream).
"""
import asyncio
import hashlib


def sha256_of(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# An imaging tool reports MD5, SHA-1 or SHA-256; the algorithm is inferred from
# the hex length (C3). Used to compare a typed hash only with a hash of the same kind.
_ALGORITHM_BY_LENGTH = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX = frozenset("0123456789abcdef")


def hash_algorithm(value: str | None) -> str | None:
    """'md5' | 'sha1' | 'sha256' for a 32/40/64-char hex string, else None."""
    if not value or not set(value.lower()) <= _HEX:
        return None
    return _ALGORITHM_BY_LENGTH.get(len(value))


def hashes_of(b: bytes) -> tuple[str, str, str]:
    """(sha256, sha1, md5) of an in-memory blob."""
    return hashlib.sha256(b).hexdigest(), hashlib.sha1(b).hexdigest(), hashlib.md5(b).hexdigest()


# Async wrapper — full-file hashing on a 500 MB upload takes ~500 ms and
# blocks the event loop. Use this from request handlers; the sync version is
# kept for places that already have a thread of their own (background tasks,
# CLI scripts).
async def ahashes_of(b: bytes) -> tuple[str, str, str]:
    return await asyncio.to_thread(hashes_of, b)


_SHA256_SLICE = 16 * 1024 * 1024   # 16 MiB


def sha256_chunked(b: bytes) -> str:
    """sha256_of a large in-memory blob, fed in 16 MiB zero-copy slices so the worker thread
    hands the GIL back between slices (CLAUDE.md: one long C call can still stall the loop)."""
    h = hashlib.sha256()
    mv = memoryview(b)
    for i in range(0, len(mv), _SHA256_SLICE):
        h.update(mv[i:i + _SHA256_SLICE])
    return h.hexdigest()


async def asha256_of(b: bytes) -> str:
    """SHA-256 off the event loop — use from request handlers instead of sha256_of."""
    return await asyncio.to_thread(sha256_chunked, b)
