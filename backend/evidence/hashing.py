"""Streaming multi-hash for evidence files.

SHA-256 is the primary integrity hash recorded in the Evidence row and used
for verification. SHA-1 and MD5 are recorded for legacy interop (court
systems, older forensic tools). All three are computed in a single streaming
pass.
"""
import asyncio
import hashlib
from typing import BinaryIO


CHUNK_SIZE = 64 * 1024   # 64 KiB


def multi_hash(stream: BinaryIO) -> tuple[bytes, str, str, str, int]:
    """Read `stream` to EOF and return (raw_bytes, sha256, sha1, md5, size).

    Single pass: hashes are computed as bytes flow through. For MVP we
    materialise the full file in memory so it can be encrypted in one shot
    (see crypto.encrypt_file_bytes). Streaming-encrypt is phase-2.
    """
    h256 = hashlib.sha256()
    h1   = hashlib.sha1()
    h_md = hashlib.md5()
    size = 0
    chunks: list[bytes] = []
    while True:
        chunk = stream.read(CHUNK_SIZE)
        if not chunk:
            break
        h256.update(chunk); h1.update(chunk); h_md.update(chunk)
        size += len(chunk)
        chunks.append(chunk)
    raw = b"".join(chunks)
    return raw, h256.hexdigest(), h1.hexdigest(), h_md.hexdigest(), size


def sha256_of(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# Async wrapper — full-file hashing on a 500 MB upload takes ~500 ms and
# blocks the event loop. Use this from request handlers; the sync version is
# kept for places that already have a thread of their own (background tasks,
# CLI scripts).
async def amulti_hash(stream: BinaryIO) -> tuple[bytes, str, str, str, int]:
    return await asyncio.to_thread(multi_hash, stream)
