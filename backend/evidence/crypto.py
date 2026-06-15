"""AES-256-GCM file encryption for evidence at rest.

Master KEK is loaded from `settings.evidence_kek` (env var `EVIDENCE_KEK`).
Each file is encrypted with a fresh 96-bit nonce; the nonce is stored on the
Evidence row (`nonce_hex`). The GCM authentication tag is appended to the
ciphertext by the `cryptography` library and travels with the file.

MVP: full file in memory (1 GiB cap enforced upstream). Streaming AES-CTR +
HMAC is a phase-2 hardening when larger files are needed.

Sync functions remain for legacy callers; async variants (a*) wrap them in
asyncio.to_thread so the event loop stays free during the CPU + blocking I/O.
Prefer the async variants from request handlers.
"""
import asyncio
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.config import settings


class EvidenceCryptoError(RuntimeError):
    """Raised on KEK misconfig / decrypt failure / tag mismatch."""


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
    """Encrypt and return (ciphertext_with_tag, nonce_hex)."""
    key   = _load_key()
    nonce = os.urandom(12)                          # 96-bit nonce per AES-GCM spec
    aes   = AESGCM(key)
    ct    = aes.encrypt(nonce, plaintext, None)
    return ct, nonce.hex()


def decrypt_file_bytes(ciphertext: bytes, nonce_hex: str) -> bytes:
    """Decrypt and verify tag. Raises on tag mismatch."""
    key = _load_key()
    try:
        nonce = bytes.fromhex(nonce_hex)
    except ValueError as e:
        raise EvidenceCryptoError("Stored nonce is not valid hex.") from e
    aes = AESGCM(key)
    try:
        return aes.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise EvidenceCryptoError("AES-GCM tag verification failed.") from e


def _safe_target(relative_path: str) -> Path:
    """Resolve relative_path under evidence_path, rejecting anything that escapes.

    Defence in depth — all current callers pre-sanitise the path, but enforcing
    the boundary here means a future caller (new endpoint, migration tool,
    poisoned DB row) cannot use this module to read/write outside /evidence.
    Also defeats symlink escapes because resolve() follows symlinks before the
    is_relative_to check.
    """
    base = Path(settings.evidence_path).resolve()
    target = (base / relative_path).resolve()
    if not target.is_relative_to(base):
        raise EvidenceCryptoError(f"relative_path escapes evidence directory: {relative_path!r}")
    return target


def write_encrypted(plaintext: bytes, relative_path: str) -> str:
    """Encrypt + write under evidence_path. Returns the relative path."""
    ct, nonce_hex = encrypt_file_bytes(plaintext)
    target = _safe_target(relative_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(ct)
    # Store nonce alongside as a sidecar — also persisted in DB (`nonce_hex`).
    # Sidecar is for offline recovery if DB is lost; DB is the source of truth.
    (target.with_suffix(target.suffix + ".nonce")).write_text(nonce_hex)
    return str(relative_path)


def read_decrypted(relative_path: str, nonce_hex: str) -> bytes:
    """Read encrypted file from evidence_path and decrypt."""
    path = _safe_target(relative_path)
    if not path.exists():
        raise EvidenceCryptoError(f"Evidence file not found: {relative_path}")
    return decrypt_file_bytes(path.read_bytes(), nonce_hex)


def delete_encrypted(relative_path: str) -> None:
    """Remove encrypted file + sidecar. Used on disposition. No-op if absent."""
    path = _safe_target(relative_path)
    sidecar = path.with_suffix(path.suffix + ".nonce")
    for p in (path, sidecar):
        try:
            p.unlink()
        except FileNotFoundError:
            pass


# ─── Async wrappers — prefer these from request handlers ────────────────────
# AES-GCM full-file encrypt/decrypt is CPU-bound and grows linearly with file
# size; blocking the event loop on a 500 MB upload freezes every other in-flight
# request for ~500 ms. Wrap whole functions (not just the crypto calls) because
# they also do blocking file I/O (read_bytes/write_bytes/unlink).

async def aencrypt_file_bytes(plaintext: bytes) -> tuple[bytes, str]:
    return await asyncio.to_thread(encrypt_file_bytes, plaintext)


async def adecrypt_file_bytes(ciphertext: bytes, nonce_hex: str) -> bytes:
    return await asyncio.to_thread(decrypt_file_bytes, ciphertext, nonce_hex)


async def awrite_encrypted(plaintext: bytes, relative_path: str) -> str:
    return await asyncio.to_thread(write_encrypted, plaintext, relative_path)


async def aread_decrypted(relative_path: str, nonce_hex: str) -> bytes:
    return await asyncio.to_thread(read_decrypted, relative_path, nonce_hex)


async def adelete_encrypted(relative_path: str) -> None:
    await asyncio.to_thread(delete_encrypted, relative_path)
