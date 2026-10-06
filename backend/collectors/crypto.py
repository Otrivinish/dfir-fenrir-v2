"""X.509 collection encryption (U1) — keypair/cert generation + decryption.

Secure-by-default: every generated collector encrypts its output to a per-package
self-signed RSA cert. Only FENRIR holds the matching private key (wrapped under
EVIDENCE_KEK), so the collection is encrypted on the responder's media and only
FENRIR can read it — which also binds the output cryptographically to the package.

Validated end-to-end against Velociraptor v0.76.6 (docs/u1-collector-spike.md):
the container is a ZIP with plaintext `metadata.json` ([0].EncryptedPass =
base64 RSA-OAEP-SHA512 of the ZIP password, Scheme=X509) and a WZ-AES `data.zip`
member holding `results/`. Decryption is pure Python (cryptography + pyzipper).
"""
from __future__ import annotations

import base64
import json
import shutil
from datetime import datetime, timedelta, timezone

import pyzipper
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from evidence.crypto import decrypt_file_bytes, encrypt_file_bytes

RSA_KEY_SIZE = 4096


class CollectionDecryptError(RuntimeError):
    """Raised when an encrypted collection cannot be decrypted."""


def generate_keypair_and_cert(common_name: str) -> tuple[str, str, str]:
    """Return (cert_pem, sha256_fingerprint_hex, wrapped_private_key).

    The private key is PKCS8-PEM, AES-256-GCM-wrapped under EVIDENCE_KEK and
    encoded as "{nonce_hex}:{b64 ciphertext}" for the CollectionPackage row.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        # Long validity — single-use, but the responder may run the collector
        # days after generation and decryption can happen later still.
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()

    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    ct, nonce_hex = encrypt_file_bytes(priv_pem)
    wrapped = f"{nonce_hex}:{base64.b64encode(ct).decode()}"
    return cert_pem, fingerprint, wrapped


def _unwrap_private_key(wrapped: str):
    try:
        nonce_hex, b64ct = wrapped.split(":", 1)
        priv_pem = decrypt_file_bytes(base64.b64decode(b64ct), nonce_hex)
        return serialization.load_pem_private_key(priv_pem, password=None)
    except Exception as e:
        raise CollectionDecryptError(f"Could not unwrap the package private key: {e}") from e


def decrypt_collection_to(container, wrapped_private_key: str | None, out) -> bool:
    """Decrypt an X.509 Velociraptor container → inner plaintext ZIP written to `out`.

    `container` is a seekable binary file object (H1: the upload's RAM spool) and `out` a writable one
    (H1: the quarantine's encrypting staging writer), so no plaintext reaches a disk here.
    If the upload isn't an X.509-encrypted container (e.g. plaintext collection),
    it's copied through unchanged. Returns True if decryption happened.
    Streams the (potentially large) data.zip member — no whole-file-in-memory.
    """
    def passthrough() -> bool:
        container.seek(0)
        shutil.copyfileobj(container, out, length=1024 * 1024)
        return False

    with pyzipper.AESZipFile(container) as zf:
        names = set(zf.namelist())
        if "metadata.json" not in names or "data.zip" not in names:
            return passthrough()
        try:
            meta = json.loads(zf.read("metadata.json").decode())
            meta0 = meta[0] if isinstance(meta, list) else meta
        except Exception:
            return passthrough()
        if meta0.get("Scheme") != "X509":
            return passthrough()

        if not wrapped_private_key:
            raise CollectionDecryptError(
                "Collection is X.509-encrypted but the package has no stored key."
            )
        key = _unwrap_private_key(wrapped_private_key)
        try:
            password = key.decrypt(
                base64.b64decode(meta0["EncryptedPass"]),
                padding.OAEP(mgf=padding.MGF1(hashes.SHA512()), algorithm=hashes.SHA512(), label=None),
            )
        except Exception as e:
            raise CollectionDecryptError(
                "Failed to recover the collection password — wrong package or "
                f"corrupt container: {e}"
            ) from e
        zf.setpassword(password)
        with zf.open("data.zip") as src:
            shutil.copyfileobj(src, out, length=1024 * 1024)
    return True
