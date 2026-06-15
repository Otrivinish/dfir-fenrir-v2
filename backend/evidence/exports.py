"""Build + encrypt evidence export bundles.

Flow:
  1. For each Evidence row: decrypt from /evidence using master KEK (if
     digital_file) to get plaintext bytes; record metadata + hashes.
  2. Assemble a ZIP containing:
       - files/{evidence_id}__{filename}     plaintext evidence
       - coc/{evidence_id}.json              per-item NIST-aligned CoC doc
       - audit/{evidence_id}.jsonl           per-item audit chain excerpt
       - manifest.json                       export-level summary
       - README.txt                          recipient instructions
  3. Encrypt the entire ZIP with a fresh AES-256-GCM ephemeral key.
     Wire format: [12-byte nonce][ciphertext][16-byte GCM tag] — single blob.
  4. Persist the encrypted blob under /evidence/exports/{export_id}.enc.

The plaintext-in-memory window during step 1-2 is the trade-off for letting
the recipient decrypt without ever knowing the master KEK. Phase-3 hardening
could stream-encrypt per-file.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from models import AuditLog, CustodyExport, Evidence, Incident, User

from evidence.crypto import aread_decrypted


README = """\
DFIR-FENRIR v2 — Evidence Export Bundle
========================================

This archive contains evidence collected during an incident response,
exported under chain of custody. The outer file you downloaded is
AES-256-GCM encrypted; the inner ZIP holds the actual evidence and the
chain-of-custody documentation.

Decryption
----------
The export key was provided out-of-band by the sender. It is a 64-character
hex string (AES-256). To verify you have the correct key, compare the first
and last 8 characters against the `key_hint` value in the original transfer.

Decrypt the bundle with the following Python 3 snippet (requires the
`cryptography` package):

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import sys

    bundle = open(sys.argv[1], "rb").read()
    nonce, ct = bundle[:12], bundle[12:]
    key = bytes.fromhex(sys.argv[2])
    plain = AESGCM(key).decrypt(nonce, ct, None)
    open(sys.argv[1] + ".zip", "wb").write(plain)

Usage:   python3 decrypt.py bundle.enc <key-hex>

The output `.zip` is the standard ZIP file documented below.

Bundle contents
---------------
- manifest.json            Export-level summary + list of items
- coc/{evidence_id}.json   Per-item chain-of-custody document (NIST-aligned)
- audit/{evidence_id}.jsonl Per-item audit chain excerpt (one JSON event per line)
- files/...                Plaintext evidence files (digital_file kind only)

Integrity
---------
Each item in manifest.json has its plaintext SHA-256 + SHA-1 + MD5 hashes,
matching the original recorded at collection time. After extraction, verify
each file's SHA-256 matches the manifest entry. If any hash mismatches,
the chain of custody is broken — contact the sender.

The bundle as received (the encrypted blob) also has a SHA-256 you can
verify before decrypting. The sender will have communicated it alongside
the key.
"""


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _hash_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _key_hint(key_hex: str) -> str:
    return f"{key_hex[:8]}…{key_hex[-8:]}"


def _build_coc_doc(inc: Incident, ev: Evidence, events: list[AuditLog]) -> dict:
    """Per-item NIST-aligned chain-of-custody JSON."""
    return {
        "version": "1.0",
        "case": {
            "incident_id":    str(inc.id),
            "incident_title": inc.title,
            "severity":       inc.severity,
            "tlp":            inc.tlp,
            "phase":          inc.phase,
            "status":         inc.status,
        },
        "item": {
            "id":         str(ev.id),
            "identifier": ev.identifier,
            "name":       ev.name,
            "kind":       ev.kind,
            "tlp":        ev.tlp,
            "status":     ev.status,
            "description": ev.description,
            "collected_at":       ev.collected_at.isoformat() if ev.collected_at else None,
            "collected_by_id":    str(ev.collected_by_id) if ev.collected_by_id else None,
            "collected_location": ev.collected_location,
            "current_custodian_id": (
                str(ev.current_custodian_id) if ev.current_custodian_id else None
            ),
            "hashes": {
                "sha256": ev.sha256,
                "sha1":   ev.sha1,
                "md5":    ev.md5,
            } if ev.kind == "digital_file" else None,
            "file": {
                "original_filename": ev.original_filename,
                "size_bytes":        ev.file_size_bytes,
                "mime_type":         ev.mime_type,
                "path_in_zip":       f"files/{ev.id}__{ev.original_filename or 'evidence.bin'}",
            } if ev.kind == "digital_file" and ev.storage_path else None,
            "physical": {
                "make":  ev.make,
                "model": ev.model,
                "serial": ev.serial,
                "physical_location": ev.physical_location,
                "condition": ev.condition,
                "photos": ev.photos or [],
            } if ev.kind == "physical_item" else None,
            "disposed_at": ev.disposed_at.isoformat() if ev.disposed_at else None,
            "final_hash_at_disposition": ev.final_hash_at_disposition,
        },
        "custody_chain": [
            {
                "timestamp":  e.timestamp.isoformat(),
                "actor":      e.username,
                "actor_id":   str(e.user_id) if e.user_id else None,
                "action":     e.action,
                "outcome":    e.outcome,
                "details":    e.details or {},
                "ip_address": e.ip_address,
                "audit_hash":      e.row_hash,
                "audit_prev_hash": e.prev_hash,
            }
            for e in events
        ],
    }


def _events_excerpt(events: list[AuditLog]) -> str:
    """JSON Lines (one event per line) for compact, line-by-line verification."""
    out = []
    for e in events:
        out.append(json.dumps({
            "id":          str(e.id),
            "timestamp":   e.timestamp.isoformat(),
            "actor":       e.username,
            "action":      e.action,
            "outcome":     e.outcome,
            "details":     e.details or {},
            "audit_hash":      e.row_hash,
            "audit_prev_hash": e.prev_hash,
        }, sort_keys=True, separators=(",", ":")))
    return "\n".join(out) + ("\n" if out else "")


async def build_bundle(
    db: AsyncSession,
    inc: Incident,
    items: list[Evidence],
    exporter: User,
    recipient: str,
    purpose: str,
    acknowledgments: str | None,
) -> tuple[CustodyExport, str, str]:
    """Build the encrypted bundle and persist a CustodyExport row.

    Returns (export_row, key_hex, download_url). The key is the only copy.
    Caller is responsible for committing the DB transaction.
    """
    export_id = uuid.uuid4()

    # Collect per-item events from the hash-chained audit log.
    events_by_item: dict[uuid.UUID, list[AuditLog]] = {}
    for ev in items:
        q = await db.execute(
            select(AuditLog)
            .where(AuditLog.resource_type == "evidence",
                   AuditLog.resource_id   == str(ev.id))
            .order_by(AuditLog.timestamp.asc(), AuditLog.id.asc())
        )
        events_by_item[ev.id] = q.scalars().all()

    # Assemble the inner ZIP in memory.
    buf = io.BytesIO()
    manifest_items = []
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.txt", README)

        for ev in items:
            coc = _build_coc_doc(inc, ev, events_by_item[ev.id])
            zf.writestr(f"coc/{ev.id}.json", json.dumps(coc, indent=2, sort_keys=True))
            zf.writestr(f"audit/{ev.id}.jsonl", _events_excerpt(events_by_item[ev.id]))

            file_path_in_zip = None
            if ev.kind == "digital_file" and ev.storage_path and ev.nonce_hex:
                # Decrypt from /evidence and embed plaintext in the export.
                plaintext = await aread_decrypted(ev.storage_path, ev.nonce_hex)
                file_path_in_zip = f"files/{ev.id}__{ev.original_filename or 'evidence.bin'}"
                zf.writestr(file_path_in_zip, plaintext)

            manifest_items.append({
                "id":         str(ev.id),
                "identifier": ev.identifier,
                "name":       ev.name,
                "kind":       ev.kind,
                "tlp":        ev.tlp,
                "status":     ev.status,
                "sha256":     ev.sha256,
                "sha1":       ev.sha1,
                "md5":        ev.md5,
                "file_path":  file_path_in_zip,
                "coc_path":   f"coc/{ev.id}.json",
                "audit_path": f"audit/{ev.id}.jsonl",
                "final_hash_at_disposition": ev.final_hash_at_disposition,
            })

        manifest = {
            "version": "1.0",
            "export": {
                "id":              str(export_id),
                "created_at":      _now_utc().isoformat(),
                "created_by":      exporter.username,
                "created_by_id":   str(exporter.id),
                "recipient":       recipient,
                "purpose":         purpose,
                "acknowledgments": acknowledgments,
            },
            "incident": {
                "id":       str(inc.id),
                "title":    inc.title,
                "severity": inc.severity,
                "tlp":      inc.tlp,
                "phase":    inc.phase,
                "status":   inc.status,
            },
            "items": manifest_items,
            "verification": {
                "spec": (
                    "Outer bundle: AES-256-GCM, 12-byte nonce prefix + "
                    "ciphertext + 16-byte tag. Inner files: plaintext, "
                    "SHA-256 must match this manifest entry."
                ),
                "decrypt_recipe": (
                    "AESGCM(bytes.fromhex(key)).decrypt(bundle[:12], bundle[12:], None)"
                ),
            },
        }
        zf.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True))

    plaintext_zip = buf.getvalue()

    # Encrypt the whole ZIP with a fresh per-export key.
    key_bytes = secrets.token_bytes(32)         # AES-256
    key_hex   = key_bytes.hex()
    nonce     = os.urandom(12)
    ct        = AESGCM(key_bytes).encrypt(nonce, plaintext_zip, None)
    bundle    = nonce + ct                       # nonce prefix for self-describing format
    bundle_sha256 = _hash_bytes(bundle)

    # Persist to disk.
    rel_path = f"exports/{export_id}.enc"
    target   = Path(settings.evidence_path) / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(bundle)

    # Generate the one-time token.
    token = secrets.token_urlsafe(32)

    from datetime import timedelta
    expires_at = _now_utc() + timedelta(hours=24)

    export = CustodyExport(
        id=export_id,
        incident_id=inc.id,
        exported_by_id=exporter.id,
        recipient=recipient,
        purpose=purpose,
        acknowledgments=acknowledgments,
        token=token,
        status="ready",
        file_path=rel_path,
        file_size=len(bundle),
        bundle_sha256=bundle_sha256,
        key_hint=_key_hint(key_hex),
        item_ids=[str(ev.id) for ev in items],
        created_at=_now_utc(),
        expires_at=expires_at,
    )
    db.add(export)
    await db.flush()

    download_url = f"/api/exports/{token}"
    return export, key_hex, download_url


def open_bundle_for_download(export: CustodyExport) -> tuple[bytes, str]:
    """Read the encrypted bundle from disk. Returns (bytes, suggested_filename).
    Caller is responsible for status checks (consumed/expired/revoked)."""
    if not export.file_path:
        raise FileNotFoundError("Export bundle path missing")
    path = Path(settings.evidence_path) / export.file_path
    if not path.exists():
        raise FileNotFoundError(f"Export bundle file missing: {path}")
    # Derive the suggested extension from the actual on-disk path so LE
    # packages (now AES-256 password ZIP, stored as `.zip`) and legacy
    # evidence custody exports (still AES-256-GCM, stored as `.enc`) each
    # serve with the correct extension.
    ext = Path(export.file_path).suffix or ".enc"
    suggested = f"fenrir-export-{export.id}{ext}"
    return path.read_bytes(), suggested


def is_expired(export: CustodyExport) -> bool:
    return _now_utc() >= export.expires_at


def effective_status(export: CustodyExport) -> str:
    """Reads `status` with expiry applied — DB row may say 'ready' but the
    clock has run out. Use this anywhere the UI shows status."""
    if export.status == "ready" and is_expired(export):
        return "expired"
    return export.status
