"""EG-10 (S1) and EG-1 (S2): an exhibit's acquisition record and its source location record, as plain dicts.

Both outputs that leave the platform with an exhibit use them, so they say the same thing: the disclosure
package (le_package/builder.py: columns appended to 04_Evidence/Evidence_Inventory.csv and the `acquisition` /
`source` blocks of each file's .meta.json) and the custody export (evidence/exports.py: coc/{id}.json).

Recorded facts only: never a storage path, nonce, key or other internal. The RFC 3161 token itself is not
emitted, only whether there is one and the TSA's time.

S3 (EG-11) builds the record the seal binds from the same fields (seal_record_v1); S4 (EG-8/9) adds a photo's
record (photo_record).
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

# The acquisition record, in output order: Wizard A, the collection wizard (ISO/IEC 27037 §7), ISO/IEC 27041
# (tool validation, collector qualifications) and the seal with its trusted timestamp.
ACQUISITION_FIELDS = (
    "lawful_basis", "lawful_basis_note",
    "acquisition_tool", "acquisition_tool_version", "acquisition_tool_sha256", "acquisition_params",
    "acquisition_hash_source", "acquisition_hash_target", "acquired_at", "upload_hash_check",
    "write_blocker_used", "write_blocker_serial", "system_state", "live_justification", "network_isolated",
    "witness_user_id", "witness_name", "collected_as_role",
    "device_types", "handling_mode", "decision_factors", "acquisition_scope", "logical_acquisition_rationale",
    "system_time_offset", "system_time_offset_seconds", "screen_state", "changes_made", "device_details",
    "acquisition_tool_validated", "acquisition_tool_validation_ref", "acquisition_tool_validation_date",
    "collected_by_qualifications",
    "coc_sealed", "coc_sealed_at", "coc_sealed_by_id", "seal_tst_present", "seal_tst_time", "seal_tsa",
)

# The source location record (S2): the device (make / model / serial, also on digital exhibits) and where on it
# the bytes were, as recorded. source_path_norm is the server's search form (norm_v1, evidence/source.py).
SOURCE_FIELDS = (
    "source_system", "make", "model", "serial",
    "source_path", "source_path_style", "source_path_norm", "source_details", "source_unknown_reason",
)

# Appended to Evidence_Inventory.csv after its existing columns, which keep their order. Fields the inventory
# already had (lawful_basis, acquired_at_utc, upload_hash_check, coc_sealed, coc_sealed_at_utc, make, model,
# serial) are not repeated.
_IN_INVENTORY = {"lawful_basis", "acquired_at", "upload_hash_check", "coc_sealed", "coc_sealed_at",
                 "make", "model", "serial"}
INVENTORY_ACQUISITION_COLUMNS = tuple(f for f in ACQUISITION_FIELDS if f not in _IN_INVENTORY)
INVENTORY_SOURCE_COLUMNS = tuple(f for f in SOURCE_FIELDS if f not in _IN_INVENTORY)


def _value(v):
    if isinstance(v, datetime):
        v = v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v.astimezone(timezone.utc)
        return v.isoformat().replace("+00:00", "Z")
    if isinstance(v, uuid.UUID):
        return str(v)
    return v


def acquisition_record(ev) -> dict:
    return {f: (bool(ev.seal_tst) if f == "seal_tst_present"
                else bool(ev.coc_sealed) if f == "coc_sealed"
                else _value(getattr(ev, f))) for f in ACQUISITION_FIELDS}


def source_record(ev) -> dict:
    return {f: _value(getattr(ev, f)) for f in SOURCE_FIELDS}


def csv_value(v):
    """A list or object as compact JSON (sorted keys, so the cell is stable); anything else unchanged."""
    if isinstance(v, (dict, list)):
        return json.dumps(v, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    return v


# S4 (EG-8/9): a photo as recorded, for what leaves the platform (the disclosure package's photos.json, the custody
# export): never storage_path, nonce_hex or the API url.
PHOTO_FIELDS = ("id", "caption", "taken_at", "taken_by_id", "taken_by_name", "camera", "original_filename",
                "context", "mime_type", "sha256", "size")


def photo_record(p: dict) -> dict:
    return {k: p.get(k) for k in PHOTO_FIELDS}


# ── S3 (EG-11, HLD §3.8): the record the seal binds ─────────────────────────────────────────────────────────────
# Set by the seal itself, so not part of what it binds.
SEAL_OUTPUT_FIELDS = ("coc_sealed", "coc_sealed_at", "coc_sealed_by_id", "seal_tst_present", "seal_tst_time",
                      "seal_tsa")
SEAL_RECORD_ACQUISITION_FIELDS = tuple(f for f in ACQUISITION_FIELDS if f not in SEAL_OUTPUT_FIELDS)
# Top-level keys added after v1 that are in the record only when not null, so a v1 record of an exhibit without
# them stays byte-for-byte the same (S6 adds "manifest_sha256" here). Every other key is always present.
SEAL_RECORD_OPTIONAL_FIELDS: tuple[str, ...] = ("manifest_sha256",)

# S6 (EG-4): a container exhibit's manifest, as recorded (its entries go in their own files). Appended to the
# inventory after the source columns, in this order; the .meta.json `container_manifest` block.
MANIFEST_FIELDS = ("container_format", "manifest_status", "manifest_sha256", "manifest_entries", "manifest_builder",
                   "manifest_error", "manifest_listing")
INVENTORY_MANIFEST_COLUMNS = MANIFEST_FIELDS


def manifest_record(ev) -> dict:
    return {f: getattr(ev, f, None) for f in MANIFEST_FIELDS}


def seal_record_v1(ev) -> bytes:
    """The canonical record v1 the seal binds, as the exact bytes that are hashed (seal_record_sha256) and
    timestamped: UTF-8 JSON, sorted keys, compact separators, non-ASCII kept as is. Keys: v, id, identifier, kind,
    hashes {md5, sha1, sha256}, acquisition (ACQUISITION_FIELDS without the seal's own outputs), source
    (SOURCE_FIELDS) and photos [{id, sha256}] sorted by id (photos with an id: a caption-only photo without one
    has no bytes). A null value keeps its key, so the shape is stable; only SEAL_RECORD_OPTIONAL_FIELDS are
    left out when null. Values as in acquisition_record / source_record (datetimes UTC …Z, UUIDs as strings)."""
    acq = acquisition_record(ev)
    photos = [{"id": str(p["id"]), "sha256": p.get("sha256")} for p in ev.photos or []
              if isinstance(p, dict) and p.get("id")]
    record = {
        "v": 1,
        "id": str(ev.id),
        "identifier": ev.identifier,
        "kind": ev.kind,
        "hashes": {"md5": ev.md5, "sha1": ev.sha1, "sha256": ev.sha256},
        "acquisition": {f: acq[f] for f in SEAL_RECORD_ACQUISITION_FIELDS},
        "source": source_record(ev),
        "photos": sorted(photos, key=lambda p: p["id"]),
    }
    record.update({f: _value(getattr(ev, f, None)) for f in SEAL_RECORD_OPTIONAL_FIELDS
                   if getattr(ev, f, None) is not None})
    return json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")
