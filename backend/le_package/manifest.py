"""Manifest builder for the LE package.

A `Manifest` accumulates entries as the bundle is assembled, then emits:
  • MANIFEST.json  — canonical machine-readable manifest
  • MANIFEST.txt   — human-readable column-aligned equivalent
  • INTEGRITY.sha256 — `sha256sum --check INTEGRITY.sha256` compatible

Hashing model: every file written into the bundle is hashed (SHA-256 + SHA-512)
in-memory immediately, the same byte sequence is then written into the ZIP.
The manifest is the *authority* on what each file should hash to — receivers
re-derive on their end and compare.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Iterable


def _now_utc_iso() -> str:
    """UTC, ISO 8601, no microseconds, trailing Z. Matches the project rule."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class Manifest:
    def __init__(self, *, incident_id: str, incident_ref: str | None,
                 case_reference: str, platform_version: str) -> None:
        self._created_at = _now_utc_iso()
        self._incident_id = incident_id
        self._incident_ref = incident_ref
        self._case_reference = case_reference
        self._platform_version = platform_version
        self._entries: list[dict] = []

    @staticmethod
    def hash_bytes(data: bytes) -> tuple[str, str]:
        """Returns (sha256, sha512), both lowercase hex."""
        return hashlib.sha256(data).hexdigest(), hashlib.sha512(data).hexdigest()

    def add(self, *, path: str, data: bytes, mime: str, source: str) -> dict:
        """Record a file. Returns the manifest entry dict (for caller reference)."""
        sha256, sha512 = self.hash_bytes(data)
        entry = {
            "path":   path,
            "size":   len(data),
            "sha256": sha256,
            "sha512": sha512,
            "mime":   mime,
            "source": source,
        }
        self._entries.append(entry)
        return entry

    # ── Emit ────────────────────────────────────────────────────────────────

    def to_json(self, *, audit_anchor: dict | None) -> dict:
        return {
            "schema_version": "1.0",
            "generated_at_utc": self._created_at,
            "platform":         f"DFIR-FENRIR {self._platform_version}",
            "case_reference":   self._case_reference,
            "incident":         {"id": self._incident_id, "ref": self._incident_ref},
            "files":            sorted(self._entries, key=lambda e: e["path"]),
            "totals": {
                "file_count":  len(self._entries),
                "total_bytes": sum(e["size"] for e in self._entries),
            },
            "audit_anchor": audit_anchor,
            "verification": {
                "hash_algorithms":  ["sha256", "sha512"],
                "integrity_file":   "INTEGRITY.sha256 — `sha256sum --check INTEGRITY.sha256`",
                "manifest_hash":    "sha256(MANIFEST.json) is recorded in the hash-chained audit log "
                                    "at the time of generation; row_hash is exposed as audit_anchor.row_hash.",
                "hmac_sig":         "INTEGRITY.sig = HMAC-SHA-256(MANIFEST.json, bundle_kek). "
                                    "Holder of the (out-of-band) bundle KEK can re-derive and compare.",
                "trusted_timestamp": "MANIFEST.tst (when present) = RFC-3161 Time-Stamp Token over "
                                    "sha256(MANIFEST.json) from an external TSA. Verify independently of "
                                    "this platform's clock: `openssl ts -verify -data MANIFEST.json -in MANIFEST.tst`.",
            },
        }

    def to_text(self, *, audit_anchor: dict | None) -> str:
        lines = [
            "DFIR-FENRIR — LE PACKAGE MANIFEST",
            f"Generated:  {self._created_at}",
            f"Platform:   DFIR-FENRIR {self._platform_version}",
            f"Case ref:   {self._case_reference}",
            f"Incident:   {self._incident_ref or self._incident_id}",
            "",
            f"{'File':<70} {'Size':>14}  SHA-256",
            f"{'-' * 70} {'-' * 14}  {'-' * 64}",
        ]
        for e in sorted(self._entries, key=lambda x: x["path"]):
            lines.append(f"{e['path']:<70} {e['size']:>14,}  {e['sha256']}")
        lines += [
            "",
            f"Total files: {len(self._entries):,}",
            f"Total size:  {sum(e['size'] for e in self._entries):,} bytes",
        ]
        if audit_anchor:
            lines += [
                "",
                "Audit anchor (this package's existence is recorded in the platform's hash-chained audit log):",
                f"  row_id:   {audit_anchor.get('row_id')}",
                f"  row_hash: {audit_anchor.get('row_hash')}",
            ]
        return "\n".join(lines) + "\n"

    def to_integrity_sha256(self) -> str:
        """`sha256sum --check`-compatible text. Two-space separator; binary-mode '*' prefix."""
        lines = []
        for e in sorted(self._entries, key=lambda x: x["path"]):
            lines.append(f"{e['sha256']}  {e['path']}")
        return "\n".join(lines) + "\n"

    @property
    def entries(self) -> Iterable[dict]:
        return tuple(self._entries)

    @property
    def total_bytes(self) -> int:
        return sum(e["size"] for e in self._entries)

    @property
    def file_count(self) -> int:
        return len(self._entries)


def hmac_manifest(manifest_bytes: bytes, key: bytes) -> str:
    """HMAC-SHA-256 over the manifest bytes. Hex-encoded, lowercase."""
    return hmac.new(key, manifest_bytes, hashlib.sha256).hexdigest()
