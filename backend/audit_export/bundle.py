"""Assemble a signed audit-log export bundle as an AES-256 password ZIP.

ZIP layout (encrypted via WinZip AES-256, openable with any standard tool):

    audit.pdf              — human-readable rendering (ReportLab)
    audit.jsonl            — canonical v2 payloads, lex-sorted keys, LF terminated
    audit.jsonl.sig        — 64-byte raw Ed25519 signature over audit.jsonl
    public_key.pem         — Ed25519 public key (PEM, SubjectPublicKeyInfo)
    manifest.json          — export metadata (filters, anchors, hashes, fingerprint)
    README.txt             — verification recipe

Operational openers — no Python or external tooling required:
  - macOS:   double-click → enter password
  - Windows: 7-Zip / WinRAR → enter password
  - Linux:   `unzip -P <password> bundle.zip`

The password is delivered out-of-band; the bundle is useless without it.
The Ed25519 signature over `audit.jsonl` is what makes the export tamper-
evident; the password ZIP is the confidentiality layer only.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import os
import secrets
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, BinaryIO

import pyzipper
from sqlalchemy.ext.asyncio import AsyncSession

from audit_export.pdf import render_pdf
from evidence.timestamping import timestamp_sha256
from audit_export.signing import (
    public_key_fingerprint,
    public_key_pem,
    sign_bytes,
)
from core.config import settings
from models import AuditExport, AuditLog, Incident, User


# ── Constants ────────────────────────────────────────────────────────────────

# 24h single-use download token, mirroring evidence exports.
TOKEN_TTL = timedelta(hours=24)
# 30d retention horizon for the bundle file on disk; purge cron lives elsewhere.
BUNDLE_TTL = timedelta(days=30)


README_TEMPLATE = """\
DFIR-FENRIR v2 — Signed Audit Log Export
========================================

This archive contains a slice of the tamper-evident audit log, extracted
under the filter recorded in manifest.json, accompanied by a detached
Ed25519 signature over audit.jsonl.

The archive is AES-256 password-protected (WinZip AE-2). The password
was delivered out of band; verify the first/last 4 characters against
`password_hint` in the transfer message.

Opening the archive
-------------------
  macOS:   double-click → enter password
  Windows: 7-Zip / WinRAR → enter password
  Linux:   unzip -P <password> bundle.zip
  Any modern archive tool will work — no Python required.

Verification (after extracting)
-------------------------------
1. Compare the SHA-256 of the password-protected ZIP you received against
   the `bundle_sha256` value the sender published.

2. Verify the Ed25519 signature over audit.jsonl — this is what makes the
   export tamper-evident:

    from cryptography.hazmat.primitives import serialization
    pub = serialization.load_pem_public_key(open("public_key.pem", "rb").read())
    pub.verify(open("audit.jsonl.sig", "rb").read(), open("audit.jsonl", "rb").read())
    # Raises cryptography.exceptions.InvalidSignature on tamper.

3. Confirm the SHA-256 of `public_key.pem`'s raw key bytes matches the
   fingerprint published at GET /api/version of the issuing instance —
   {fingerprint}.

4. Confirm `manifest.json.chain.first_prev_hash` equals audit.jsonl's
   first record's `prev_hash`, and `manifest.json.chain.last_row_hash`
   equals the last record's `row_hash`. The slice is a contiguous
   segment of the issuing instance's tamper-evident chain.

5. Optionally recompute each row's hash:
     row_hash = sha256(prev_hash_ascii || canonical_json(payload))
   The chain in this slice should reproduce byte-for-byte.

Reference: NIST SP 800-86 §3.1.2, ISO/IEC 27037 §6.1.
"""


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _password_hint(password: str) -> str:
    """Compact `XXXX…YYYY` hint so analysts can verify OOB key-handoff without
    revealing the full secret. Stored on the AuditExport row (DB column is
    still named `key_hint` for legacy reasons — semantically a password hint
    now)."""
    return f"{password[:4]}…{password[-4:]}"


# ── Canonical JSONL ──────────────────────────────────────────────────────────
# The same payload shape `audit.service._payload_v2` writes into the chain.
# Re-derive it here so a verifier can recompute row_hash without round-trip
# through the platform.

def _canonical_payload(row: AuditLog) -> dict[str, Any]:
    """Reproduce the v2 canonical payload from a stored row."""
    return {
        "v":               "v2",
        "timestamp":       row.timestamp.isoformat(),
        "user_id":         str(row.user_id) if row.user_id else None,
        "username":        row.username,
        "role_at_time":    row.role_at_time,
        "session_id":      str(row.session_id) if row.session_id else None,
        "action":          row.action,
        "outcome":         row.outcome,
        "resource_type":   row.resource_type,
        "resource_id":     row.resource_id,
        "resource_label":  row.resource_label,
        "ip_address":      row.ip_address,
        "request_method":  row.request_method,
        "request_path":    row.request_path,
        "request_id":      row.request_id,
        "details":         row.details or {},
    }


def _jsonl_record(row: AuditLog) -> dict[str, Any]:
    """One JSONL line: chain fields + canonical payload, lex-sorted at serialize."""
    return {
        "id":           str(row.id),
        "hash_version": row.hash_version or "v2",
        "prev_hash":    row.prev_hash,
        "row_hash":     row.row_hash,
        "payload":      _canonical_payload(row),
    }


def render_jsonl(rows: list[AuditLog]) -> bytes:
    """Serialize rows to canonical JSONL (LF-terminated, lex-sorted keys)."""
    lines = []
    for r in rows:
        lines.append(json.dumps(
            _jsonl_record(r),
            sort_keys=True, separators=(",", ":"), default=str,
        ))
    text = "\n".join(lines)
    if lines:
        text += "\n"
    return text.encode("utf-8")


# ── Bundle build ─────────────────────────────────────────────────────────────

async def build_audit_export(
    db:           AsyncSession,
    rows:         list[AuditLog],
    chain_head:   AuditLog | None,
    filters:      dict[str, Any],
    purpose:      str | None,
    exporter:     User,
    incident:     Incident | None,
) -> tuple[AuditExport, str, str]:
    """Build the encrypted bundle and persist an AuditExport row.

    Returns (export_row, password, download_url). The password is the only
    copy — it is not persisted server-side. Caller commits the surrounding
    transaction.
    """
    export_id = uuid.uuid4()
    now       = _now_utc()
    expires   = now + TOKEN_TTL
    retain    = now + BUNDLE_TTL

    # ── 1. Canonical JSONL + Ed25519 signature ──────────────────────────────
    # Steps 1 and 3–5 are CPU-bound / blocking and scale with the slice (up to
    # 50k rows; ReportLab ≈ 5 ms a row), so they run in worker threads: the
    # backend has one event loop, and inline they froze every request.
    jsonl_bytes, jsonl_sha, signature = await asyncio.to_thread(_jsonl_signed, rows)
    pubkey_pem    = public_key_pem()
    pubkey_fpr    = public_key_fingerprint()
    # GS-4 — RFC 3161 trusted timestamp over sha256(audit.jsonl), best-effort.
    jsonl_tst     = await timestamp_sha256(jsonl_sha)

    # ── 2. Manifest ─────────────────────────────────────────────────────────
    first = rows[0] if rows else None
    last  = rows[-1] if rows else None
    chain = {
        "first_row_id":   str(first.id) if first else None,
        "last_row_id":    str(last.id)  if last  else None,
        "first_prev_hash": first.prev_hash if first else None,
        "last_row_hash":  last.row_hash    if last  else None,
        "chain_head_id":   str(chain_head.id)         if chain_head else None,
        "chain_head_hash": chain_head.row_hash        if chain_head else None,
        "chain_head_ts":   chain_head.timestamp.isoformat() if chain_head else None,
    }
    manifest: dict[str, Any] = {
        "version": "1.0",
        "kind":    "audit_export",
        "export": {
            "id":           str(export_id),
            "created_at":   now.isoformat(),
            "created_by":   exporter.username,
            "created_by_id": str(exporter.id),
            "purpose":      purpose,
            "scope": (
                "incident" if incident is not None else "global"
            ),
        },
        "incident": ({
            "id":    str(incident.id),
            "ref":   incident.ref,
            "title": incident.title,
            "tlp":   incident.tlp,
        } if incident is not None else None),
        "filters":  filters,
        "row_count": len(rows),
        "chain":    chain,
        "signing": {
            "algorithm":          "ed25519",
            "public_key_fpr":     pubkey_fpr,
            "jsonl_sha256":       jsonl_sha,
            "signature_filename": "audit.jsonl.sig",
            "timestamp_token_filename": (
                "audit.jsonl.tst" if jsonl_tst else None
            ),  # RFC-3161 TST over jsonl_sha256 (present only when a TSA is configured)
        },
        "verification": {
            "spec": (
                "Outer bundle: AES-256-GCM, 12-byte nonce prefix + ciphertext + 16-byte tag. "
                "Inner audit.jsonl is signed by audit.jsonl.sig under public_key.pem. "
                "Each JSONL record exposes prev_hash/row_hash; row_hash recomputes as "
                "sha256(prev_hash_ascii || canonical_json(payload)) per audit/service.py."
            ),
        },
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")

    # ── 3–5. PDF, AES-256 password-protected ZIP, hash, write ───────────────
    # 24-char URL-safe base64 password — ~144 bits of entropy, well past the
    # WZAES brute-force horizon and short enough for an OOB handoff.
    password = secrets.token_urlsafe(18)
    rel_path = f"audit-exports/{export_id}.zip"
    target   = Path(settings.evidence_path) / rel_path
    bundle_sha, bundle_size = await asyncio.to_thread(
        _write_bundle, target, password,
        rows=rows, manifest=manifest, manifest_bytes=manifest_bytes, incident=incident,
        jsonl_bytes=jsonl_bytes, signature=signature, jsonl_tst=jsonl_tst,
        pubkey_pem=pubkey_pem, pubkey_fpr=pubkey_fpr,
    )

    # ── 6. Persist ──────────────────────────────────────────────────────────
    token = secrets.token_urlsafe(32)
    row = AuditExport(
        id=export_id,
        incident_id=(incident.id if incident is not None else None),
        exported_by_id=exporter.id,
        filters=filters,
        purpose=purpose,
        first_row_id=first.id if first else None,
        last_row_id=last.id   if last  else None,
        first_prev_hash=chain["first_prev_hash"],
        last_row_hash=chain["last_row_hash"],
        chain_head_hash=chain["chain_head_hash"],
        row_count=len(rows),
        jsonl_sha256=jsonl_sha,
        signature_b64=__b64_signature(signature),
        pubkey_fpr=pubkey_fpr,
        file_path=rel_path,
        file_size=bundle_size,
        bundle_sha256=bundle_sha,
        key_hint=_password_hint(password),
        token=token,
        status="ready",
        created_at=now,
        expires_at=expires,
        retention_until=retain,
    )
    db.add(row)
    await db.flush()

    return row, password, f"/api/audit-exports/{token}"


def _jsonl_signed(rows: list[AuditLog]) -> tuple[bytes, str, bytes]:
    """Blocking: canonical JSONL, its SHA-256 and the raw 64-byte Ed25519 signature over it."""
    jsonl_bytes = render_jsonl(rows)
    return jsonl_bytes, _sha256_hex(jsonl_bytes), sign_bytes(jsonl_bytes)


# ReportLab keeps module-level state; renders were serialised on the event loop before
# they moved to threads, so keep them one at a time.
_PDF_LOCK = threading.Lock()


def _write_bundle(
    target: Path, password: str, *,
    rows: list[AuditLog], manifest: dict[str, Any], manifest_bytes: bytes,
    incident: Incident | None, jsonl_bytes: bytes, signature: bytes,
    jsonl_tst: dict | None, pubkey_pem: str, pubkey_fpr: str,
) -> tuple[str, int]:
    """Blocking (ReportLab PDF, AES-256 ZIP, SHA-256, disk write): run via
    asyncio.to_thread. Returns (bundle_sha256, size in bytes)."""
    with _PDF_LOCK:
        pdf_bytes = render_pdf(rows=rows, manifest=manifest, incident=incident)

    buf = io.BytesIO()
    with pyzipper.AESZipFile(
        buf, "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as zf:
        zf.setpassword(password.encode("utf-8"))
        zf.writestr("audit.pdf",       pdf_bytes)
        zf.writestr("audit.jsonl",     jsonl_bytes)
        zf.writestr("audit.jsonl.sig", signature)
        if jsonl_tst:
            zf.writestr("audit.jsonl.tst", base64.b64decode(jsonl_tst["tst_b64"]))
        zf.writestr("public_key.pem",  pubkey_pem)
        zf.writestr("manifest.json",   manifest_bytes)
        zf.writestr(
            "README.txt",
            README_TEMPLATE.format(fingerprint=pubkey_fpr),
        )
    enc_bundle = buf.getvalue()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(enc_bundle)
    return _sha256_hex(enc_bundle), len(enc_bundle)


def __b64_signature(sig: bytes) -> str:
    """Internal: base64 the 64-byte signature for stable persistence."""
    import base64
    return base64.b64encode(sig).decode("ascii")


# ── Bundle read ──────────────────────────────────────────────────────────────

def open_bundle_for_download(export: AuditExport) -> tuple[BinaryIO, int, str]:
    """Open the encrypted bundle on disk for streaming. Returns (open file, size in
    bytes, suggested_filename); stream it with evidence.exports.iter_bundle(), which
    closes it. Blocking: call via asyncio.to_thread. Raises FileNotFoundError when
    the bundle is gone. Status / expiry checks belong to the caller.
    """
    if not export.file_path:
        raise FileNotFoundError("Bundle path missing on AuditExport row")
    path = Path(settings.evidence_path) / export.file_path
    scope = "global" if export.incident_id is None else f"inc-{export.incident_id}"
    suggested = f"fenrir-audit-{scope}-{export.id}.zip"
    f = open(path, "rb")
    return f, os.fstat(f.fileno()).st_size, suggested


def is_expired(export: AuditExport) -> bool:
    return _now_utc() >= export.expires_at


def effective_status(export: AuditExport) -> str:
    """status with expiry + retention applied. The DB row may say 'ready' but
    the 24h clock has run out (or the 30d retention has and the file is gone).
    """
    if export.status in ("consumed", "purged"):
        return export.status
    if export.status == "ready" and is_expired(export):
        return "expired"
    return export.status
