"""U1.2/X.509 — ingest a collector's output back into FENRIR.

The responder ran the package's collector on the target host and brings back the
Velociraptor output container. Flow:
  1. stream the upload to a temp file on the quarantine volume (GBs → never
     whole-file-in-memory),
  2. DECRYPT it with the package's wrapped private key — the collector output is
     X.509-encrypted (encrypted on the responder's media; only FENRIR can read
     it). Non-encrypted uploads pass through unchanged,
  3. register the plaintext collection as a first-class Artifact (existing
     analysis tools + the U1.3 timeline-import parser operate on it).

Returns the Artifact so the route can anchor output_sha256 in the audit chain
and link it to the package.
"""
from __future__ import annotations

import asyncio
import hashlib
import re
import uuid
from pathlib import Path

import magic
from fastapi import HTTPException, UploadFile, status

from collectors.crypto import CollectionDecryptError, decrypt_collection_to
from core.config import settings
from models import Artifact

_CHUNK = 1024 * 1024   # 1 MiB
_ZIP_MAGIC = b"PK\x03\x04"


def _safe_name(name: str) -> str:
    stem = Path(name).stem
    ext  = Path(name).suffix
    safe = re.sub(r"[^\w\-.]", "_", stem)[:200 - len(ext)]
    return (safe or "collection") + ext


def _quarantine_dir(incident_id: uuid.UUID) -> Path:
    return Path(settings.quarantine_path) / str(incident_id)


def _stream_upload(src, dst: Path) -> bytes:
    """Sync: stream `src` to `dst` with the size cap. Returns the first bytes
    (for ZIP-magic validation). Caller runs this in an executor."""
    size = 0
    head = b""
    cap = settings.collection_output_max_bytes
    with dst.open("wb") as f:
        while True:
            chunk = src.read(_CHUNK)
            if not chunk:
                break
            size += len(chunk)
            if size > cap:
                f.close()
                dst.unlink(missing_ok=True)
                raise HTTPException(
                    status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    f"Collection output exceeds {cap} bytes",
                )
            f.write(chunk)
            if len(head) < 8:
                head += chunk[: 8 - len(head)]
    return head


def _hash_file(path: Path) -> tuple[str, str, str, bytes, int]:
    """Sync streaming hash of the final plaintext. Returns
    (sha256, sha512, md5, head2k, size)."""
    h256, h512, hmd5 = hashlib.sha256(), hashlib.sha512(), hashlib.md5()
    size = 0
    head = b""
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            size += len(chunk)
            h256.update(chunk); h512.update(chunk); hmd5.update(chunk)
            if len(head) < 2048:
                head += chunk[: 2048 - len(head)]
    return h256.hexdigest(), h512.hexdigest(), hmd5.hexdigest(), head, size


async def register_collection_output(
    db, incident_id: uuid.UUID, package_name: str,
    upload: UploadFile, user, wrapped_private_key: str | None,
) -> Artifact:
    """Stream → decrypt → register the plaintext collection as an Artifact."""
    loop = asyncio.get_event_loop()
    out_dir = _quarantine_dir(incident_id)
    out_dir.mkdir(parents=True, exist_ok=True)

    tmp_path = out_dir / f".ingest-{uuid.uuid4()}.tmp"
    head = await loop.run_in_executor(None, lambda: _stream_upload(upload.file, tmp_path))
    if head[:4] != _ZIP_MAGIC:
        tmp_path.unlink(missing_ok=True)
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Upload is not a ZIP — expected the collector's encrypted output container.",
        )

    original = upload.filename or "collection.zip"
    artifact_id = uuid.uuid4()
    stored = f"{artifact_id}_{_safe_name(original)}"
    final_path = out_dir / stored

    # Decrypt the X.509 container → plaintext inner collection ZIP (or pass
    # through if it wasn't encrypted).
    try:
        await loop.run_in_executor(
            None, lambda: decrypt_collection_to(str(tmp_path), wrapped_private_key, str(final_path))
        )
    except CollectionDecryptError as e:
        tmp_path.unlink(missing_ok=True)
        final_path.unlink(missing_ok=True)
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))
    finally:
        tmp_path.unlink(missing_ok=True)

    sha256, sha512, md5, head2k, size = await loop.run_in_executor(
        None, lambda: _hash_file(final_path)
    )
    mime_type = magic.from_buffer(head2k[:2048], mime=True) if head2k else None

    artifact = Artifact(
        id=artifact_id,
        incident_id=incident_id,
        original_filename=original,
        stored_filename=stored,
        file_size=size,
        mime_type=mime_type,
        md5_hash=md5,
        sha256_hash=sha256,
        sha512_hash=sha512,
        description=f"Collection output: {package_name}",
        analysis_status="pending",
        analysis_results={},
        uploaded_by_id=user.id,
        uploaded_by=user.username,
    )
    db.add(artifact)
    await db.flush()
    return artifact
