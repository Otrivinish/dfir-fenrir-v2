"""S5 (EG-6, HLD §3.7) — a supporting document's capture record, and what Register as exhibit pre-fills from it.

capture_columns() is the one check of the capture fields: both upload routes that write entity_files (incident Files
and entity attachments) and PATCH …/files/{id} call it. exhibit_prefill() maps a capture record onto a new draft
exhibit, through evidence.source.source_columns (the one source check). Pure: no DB, no I/O. The route checks a
captured_by_id against the incident (require_incident_person) and capture_sha256 against the bytes.

Values are stored as sent: nothing is trimmed ("" clears a field, like null), because capture_source and capture_url
feed an exhibit's verbatim source record (S2). capture_sha256 is lower-cased.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Mapping, Optional

from fastapi import status

from core.errors import ApiError
from evidence.source import shape_ok, source_columns
from schemas import offset_datetime

FIELDS = ("captured_at", "captured_by_id", "captured_by_name", "capture_tool", "capture_tool_version",
          "capture_method", "capture_source", "capture_url", "capture_context", "capture_sha256")
# capture_sha256 was checked against the bytes at upload, so it is never edited.
EDITABLE = tuple(f for f in FIELDS if f != "capture_sha256")
_TEXT = ("captured_by_name", "capture_tool", "capture_tool_version", "capture_source", "capture_url",
         "capture_context")
CAPTURED_AT_SKEW = timedelta(minutes=2)          # as C3's acquired_at: the capturer's clock may run a little ahead
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _refuse(code: str, detail: str) -> ApiError:
    return ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, code, detail + " Nothing was stored.")


def captured_at_utc(raw) -> Optional[datetime]:
    """None for None / "", else an aware UTC datetime. 422 invalid_captured_at unless an ISO 8601 date-time with an
    offset or Z, at most CAPTURED_AT_SKEW ahead of the server clock."""
    if raw is None or raw == "":
        return None
    dt = offset_datetime(raw)
    if dt is None:
        raise _refuse("invalid_captured_at", "captured_at must be an ISO 8601 date-time with an offset or Z, e.g. "
                      "2026-10-31T09:15:00+01:00 or 2026-10-31T08:15:00Z.")
    if dt > datetime.now(timezone.utc) + CAPTURED_AT_SKEW:
        raise _refuse("invalid_captured_at", "captured_at is in the future.")
    return dt


def capture_columns(sent: Mapping) -> dict:
    """The entity_files columns for the capture fields a request sent (only those), checked. null or "" clears a
    field. Setting captured_by_id clears captured_by_name and the other way round.
    422 invalid_captured_at, invalid_capture_text (a NUL, which Postgres can't store), invalid_hash_format
    (capture_sha256 not 64 hex), captured_by_conflict (both captured_by_id and captured_by_name)."""
    cols = {k: (None if v == "" else v) for k, v in sent.items()}
    for k in _TEXT:
        if cols.get(k) is not None and "\x00" in cols[k]:
            raise _refuse("invalid_capture_text", f"{k} contains a NUL character, which can't be stored.")
    if "captured_at" in cols:
        cols["captured_at"] = captured_at_utc(cols["captured_at"])
    if cols.get("capture_sha256") is not None:
        h = cols["capture_sha256"].strip().lower()
        if not _SHA256.fullmatch(h):
            raise _refuse("invalid_hash_format", "capture_sha256 must be a SHA-256: 64 hex characters.")
        cols["capture_sha256"] = h
    if cols.get("captured_by_id") and cols.get("captured_by_name"):
        raise _refuse("captured_by_conflict", "Send captured_by_id (a user) or captured_by_name (someone without an "
                      "account), not both.")
    if cols.get("captured_by_id"):
        cols["captured_by_name"] = None
    elif cols.get("captured_by_name"):
        cols["captured_by_id"] = None
    return cols


def jsonable(v):
    """An audit value: datetimes as UTC …Z (sub-second kept), UUIDs as strings."""
    if isinstance(v, datetime):
        return v.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(v, uuid.UUID):
        return str(v)
    return v


def audit_values(row) -> dict:
    """The capture record of an entity_files row (fields with a value), for its upload audit row."""
    return {k: jsonable(getattr(row, k)) for k in FIELDS if getattr(row, k, None) is not None}


def exhibit_prefill(ef) -> tuple[dict, list[dict]]:
    """(the evidence columns Register as exhibit pre-fills on a new draft, the source fields left empty).
    acquired_at ← captured_at; acquisition_tool / _version ← capture_tool / _version; screen_state ← capture_context;
    source_system ← capture_source; source_path ← capture_url, of style cloud_uri when it passes that style's rule
    (https, s3, gs, az, abfss), else other (an http or app URL); acquisition_hash_target ← capture_sha256 with
    upload_hash_check = match (owner decision 2026-11-01: the upload compared it with these bytes, and
    registering copies only bytes of the file's SHA-256). Never invents: a field with no capture value is
    left out. The source fields go through source_columns; one it refuses is left empty and reported as
    {field, code, detail}, never a refused registration."""
    cols: dict = {}
    for col, attr in (("acquired_at", "captured_at"), ("acquisition_tool", "capture_tool"),
                      ("acquisition_tool_version", "capture_tool_version"), ("screen_state", "capture_context")):
        if getattr(ef, attr, None) is not None:
            cols[col] = getattr(ef, attr)
    if ef.capture_sha256 is not None and ef.capture_sha256 == getattr(ef, "sha256", None):
        cols["acquisition_hash_target"], cols["upload_hash_check"] = ef.capture_sha256, "match"
    parts = []
    if ef.capture_source is not None:
        parts.append({"source_system": ef.capture_source})
    if ef.capture_url is not None:
        style = "cloud_uri" if shape_ok(ef.capture_url, "cloud_uri") else "other"
        parts.append({"source_path": ef.capture_url, "source_path_style": style})
    left_empty = []
    for part in parts:
        try:
            cols.update(source_columns(part))
        except ApiError as e:
            left_empty.append({"field": next(iter(part)), "code": e.code, "detail": e.detail})
    return cols, left_empty
