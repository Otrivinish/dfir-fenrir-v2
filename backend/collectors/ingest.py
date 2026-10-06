"""U1.2/X.509 — ingest a collector's output back into FENRIR.

The responder ran the package's collector on the target host and brings back the
Velociraptor output container. Flow:
  1. hash the container exactly as received (G4: SHA-256 + size, the run record's
     input hash) straight from the upload's RAM spool (never copied to a disk),
  2. DECRYPT it with the package's wrapped private key — the collector output is
     X.509-encrypted (encrypted on the responder's media; only FENRIR can read
     it). Non-encrypted uploads pass through unchanged,
  3. register the plaintext collection as a first-class Artifact (existing
     analysis tools + the U1.3 timeline-import parser operate on it). H1: the
     decrypted ZIP is streamed straight into the quarantine's encrypting writer
     (FENRGCM v2, artifacts/store.py); its plaintext never reaches a disk.

Returns the Artifact and the received container's SHA-256 + size so the route can
anchor both in the audit chain and record them on the package.
"""
from __future__ import annotations

import asyncio
import hashlib
import uuid

import magic
from fastapi import HTTPException, UploadFile, status

from artifacts import store as artifact_store
from collectors.crypto import CollectionDecryptError, decrypt_collection_to
from core.config import settings
from evidence.crypto import EncryptedStagingWriter
from models import Artifact

_CHUNK = 1024 * 1024   # 1 MiB
_ZIP_MAGIC = b"PK\x03\x04"


def _hash_container(src) -> tuple[bytes, str, int]:
    """Sync: hash the upload as received (G4), enforcing the size cap. Returns the first bytes (for
    ZIP-magic validation), the SHA-256 and the size. Caller runs this in an executor."""
    size = 0
    head = b""
    h256 = hashlib.sha256()
    cap = settings.collection_output_max_bytes
    src.seek(0)
    while True:
        chunk = src.read(_CHUNK)
        if not chunk:
            break
        size += len(chunk)
        h256.update(chunk)
        if size > cap:
            raise HTTPException(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                f"Collection output exceeds {cap} bytes",
            )
        if len(head) < 8:
            head += chunk[: 8 - len(head)]
    return head, h256.hexdigest(), size


async def register_collection_output(
    db, incident_id: uuid.UUID, package_name: str,
    upload: UploadFile, user, wrapped_private_key: str | None,
) -> tuple[Artifact, str, int]:
    """Stream (+ hash the container as received) → decrypt → register the plaintext collection
    as an Artifact. Returns (artifact, container_sha256, container_size)."""
    head, container_sha256, container_size = await asyncio.to_thread(_hash_container, upload.file)
    if head[:4] != _ZIP_MAGIC:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Upload is not a ZIP — expected the collector's encrypted output container.",
        )

    original = upload.filename or "collection.zip"
    artifact_id = uuid.uuid4()
    stored = artifact_store.stored_name(artifact_id, original)

    # Decrypt the X.509 container → plaintext inner collection ZIP (or pass it through if it wasn't
    # encrypted), streamed into the encrypting staging writer; renamed into place only when complete.
    writer = await EncryptedStagingWriter.aopen(artifact_store.root())
    tap = artifact_store.Tap(writer)
    try:
        await asyncio.to_thread(decrypt_collection_to, upload.file, wrapped_private_key, tap)
        sf = await writer.acommit(artifact_store.rel_path(incident_id, stored))
    except CollectionDecryptError as e:
        await writer.aabort()
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))
    except BaseException:
        await writer.aabort()
        raise
    mime_type = magic.from_buffer(tap.head[:2048], mime=True) if tap.head else None

    artifact = Artifact(
        id=artifact_id,
        incident_id=incident_id,
        original_filename=original,
        stored_filename=stored,
        file_size=sf.size,
        mime_type=mime_type,
        nonce_hex=sf.nonce_hex,
        md5_hash=sf.md5,
        sha256_hash=sf.sha256,
        sha512_hash=tap.sha512.hexdigest(),
        description=f"Collection output: {package_name}",
        analysis_status="pending",
        analysis_results={},
        uploaded_by_id=user.id,
        uploaded_by=user.username,
    )
    db.add(artifact)
    await db.flush()
    return artifact, container_sha256, container_size
