"""Crypto primitives — password hashing, TOTP, secret-at-rest encryption, opaque tokens."""
import asyncio
import base64
import hashlib
import secrets
from typing import Tuple

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
from cryptography.fernet import Fernet

from core.config import settings


# ─── Passwords (argon2id) ────────────────────────────────────────────────────

_ph = PasswordHasher(time_cost=2, memory_cost=64 * 1024, parallelism=2)


def hash_password(plain: str) -> str:
    return _ph.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        _ph.verify(hashed, plain)
        return True
    except (VerifyMismatchError, InvalidHash, Exception):
        return False


# Argon2id is CPU- and memory-bound; sync calls freeze the single uvicorn
# worker for 50–100 ms per call. Async wrappers run the work in a thread so
# concurrent requests aren't blocked. argon2-cffi releases the GIL during the
# memory-hard phase, so threads (not processes) are the right pool here.
async def ahash_password(plain: str) -> str:
    return await asyncio.to_thread(hash_password, plain)


async def averify_password(plain: str, hashed: str) -> bool:
    return await asyncio.to_thread(verify_password, plain, hashed)


def needs_rehash(hashed: str) -> bool:
    try:
        return _ph.check_needs_rehash(hashed)
    except Exception:
        return False


# ─── Opaque session tokens ───────────────────────────────────────────────────

def new_session_token() -> str:
    """256-bit URL-safe random token."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """SHA-256 for storing token fingerprint in DB (defence in depth — DB leak doesn't expose live sessions)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ─── TOTP ────────────────────────────────────────────────────────────────────

def new_totp_secret() -> str:
    return pyotp.random_base32()


def verify_totp(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)
    except Exception:
        return False


def totp_provisioning_uri(secret: str, username: str, issuer: str = "FENRIR 2") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


# ─── Secret-at-rest encryption (TOTP secrets, future API keys) ──────────────

def _fernet() -> Fernet:
    # Derive a 32-byte key from SECRET_KEY deterministically.
    key = hashlib.sha256(settings.secret_key.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(ciphertext: str) -> str:
    return _fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")


# ─── Bootstrap token ─────────────────────────────────────────────────────────

def new_bootstrap_token() -> str:
    return secrets.token_urlsafe(24)
