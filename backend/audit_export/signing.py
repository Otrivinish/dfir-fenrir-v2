"""Ed25519 signing service for audit-log export bundles.

Key model: a single per-instance Ed25519 seed loaded from `AUDIT_SIGNING_KEY`
(base64-encoded 32-byte seed). The matching public key is derived on demand
and exposed at GET /api/version so verifiers can pin the fingerprint.

The signing surface is small on purpose: callers pass raw bytes (the
canonical JSONL of an audit slice) and get back a 64-byte raw Ed25519
signature. The verifier path is symmetric and offered as a helper so the
frontend's WebCrypto verifier and the in-bundle README can quote the same
recipe.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from core.config import settings


class AuditSigningError(RuntimeError):
    """Raised on key misconfig or verification failure."""


def _decode_seed(raw: str) -> bytes:
    # Accept base64 (standard or url-safe, with or without padding).
    candidates = []
    s = raw.strip()
    candidates.append(s)
    # Pad to a multiple of 4 — base64 requires it.
    pad = "=" * (-len(s) % 4)
    candidates.append(s + pad)
    last_err: Exception | None = None
    for cand in candidates:
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                seed = decoder(cand)
                if len(seed) == 32:
                    return seed
                last_err = ValueError(
                    f"AUDIT_SIGNING_KEY decoded to {len(seed)} bytes; expected 32."
                )
            except Exception as e:
                last_err = e
    raise AuditSigningError(
        "AUDIT_SIGNING_KEY must be base64 of a 32-byte Ed25519 seed. "
        "Generate with `scripts/generate-audit-key.sh`."
    ) from last_err


def _load_private_key() -> Ed25519PrivateKey:
    raw = settings.audit_signing_key
    if not raw:
        raise AuditSigningError(
            "AUDIT_SIGNING_KEY is not set. Generate with "
            "`scripts/generate-audit-key.sh` and set it in the backend env. "
            "Backend refuses to start without it."
        )
    seed = _decode_seed(raw)
    return Ed25519PrivateKey.from_private_bytes(seed)


def assert_signing_key_configured() -> None:
    """Call at startup to fail-fast if the signing key is missing/malformed."""
    _load_private_key()


def sign_bytes(payload: bytes) -> bytes:
    """Return a 64-byte raw Ed25519 signature over `payload`."""
    return _load_private_key().sign(payload)


def public_key_pem() -> str:
    """Return the matching Ed25519 public key as a PEM-encoded string."""
    pub: Ed25519PublicKey = _load_private_key().public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def public_key_raw() -> bytes:
    """Return the raw 32-byte Ed25519 public key (for SHA-256 fingerprint)."""
    pub: Ed25519PublicKey = _load_private_key().public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_key_fingerprint() -> str:
    """SHA-256 hex of the raw public key bytes. 64-hex display fingerprint."""
    return hashlib.sha256(public_key_raw()).hexdigest()


def verify_bytes(payload: bytes, signature: bytes, pem: str | None = None) -> bool:
    """Verify a signature against the platform public key (or a supplied PEM).

    The `pem` argument lets a caller verify against an externally-supplied
    public key, which matches the way an offline verifier would work.
    """
    if pem is None:
        pub: Ed25519PublicKey = _load_private_key().public_key()
    else:
        loaded = serialization.load_pem_public_key(pem.encode("ascii"))
        if not isinstance(loaded, Ed25519PublicKey):
            raise AuditSigningError("Provided PEM is not an Ed25519 public key.")
        pub = loaded
    try:
        pub.verify(signature, payload)
        return True
    except InvalidSignature:
        return False
