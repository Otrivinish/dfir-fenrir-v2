"""S4 (EG-9, FP-2) — an exhibit photo's record (docs/evidence-hld-2026-10-31.md §3.6): who took it (a user or a
name), with what camera, when, what it shows, and the upload's file name, next to the stored image's sha256 and size.

The checks every photo route runs: POST …/photos (an upload), PATCH …/evidence/{id} (edit by photo id, or the
reference-only photos it replaces) and the physical create (reference-only photos). Pure: no DB, no I/O. A
taken_by_id is checked against the incident by the route (require_incident_person), which needs the DB.

taken_at is stored as canonical UTC ISO 8601 …Z (sub-second precision kept to the microsecond); anything that is
not an ISO 8601 date-time with an offset or Z is refused, so a new entry can't break reading the exhibit (FP-2).
"""
from __future__ import annotations

from typing import Mapping, Optional

from fastapi import status

from core.errors import ApiError
from schemas import offset_datetime

# What a PATCH may change on an uploaded photo (R101). The server holds the rest: storage_path, nonce_hex, sha256,
# size, mime_type, original_filename, url, id.
EDITABLE = ("caption", "taken_at", "taken_by_id", "taken_by_name", "camera", "context")


def taken_at_utc(raw) -> Optional[str]:
    """The stored taken_at: None for None / "", else canonical UTC …Z. 422 invalid_taken_at otherwise."""
    if raw is None or raw == "":
        return None
    dt = offset_datetime(raw)
    if dt is None:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_taken_at",
                       "taken_at must be an ISO 8601 date-time with an offset or Z, e.g. 2026-10-31T09:15:00+01:00 "
                       "or 2026-10-31T08:15:00Z. Nothing was stored.")
    return dt.isoformat().replace("+00:00", "Z")


def _one_photographer(entry: dict) -> dict:
    if entry.get("taken_by_id") and entry.get("taken_by_name"):
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "taken_by_conflict",
                       "Send taken_by_id (a user) or taken_by_name (someone without an account), not both. Nothing "
                       "was stored.")
    return entry


def new_photo(*, taken_at, taken_by_id: Optional[str], taken_by_name, camera, context,
              uploader_id: str) -> dict:
    """The record fields of an uploaded photo. No photographer given = the uploader (taken_by_id)."""
    entry = {"taken_at": taken_at_utc(taken_at), "taken_by_id": taken_by_id or None,
             "taken_by_name": taken_by_name or None, "camera": camera or None, "context": context or None}
    if not (entry["taken_by_id"] or entry["taken_by_name"]):
        entry["taken_by_id"] = uploader_id
    return _one_photographer(entry)


def edited(stored: dict, sent: Mapping) -> dict:
    """An uploaded photo after a PATCH: only the EDITABLE fields sent (`sent`, JSON values) change. Setting
    taken_by_id clears taken_by_name and the other way round; both at once is 422 taken_by_conflict."""
    _one_photographer(dict(sent))
    out = {**stored, **sent}
    if "taken_at" in sent:
        out["taken_at"] = taken_at_utc(sent["taken_at"])
    if sent.get("taken_by_id"):
        out["taken_by_name"] = None
    elif sent.get("taken_by_name"):
        out["taken_by_id"] = None
    return out


def reference(sent: Mapping) -> dict:
    """A reference-only photo (no stored file) as sent, with its taken_at checked and made canonical."""
    return _one_photographer({**sent, "taken_at": taken_at_utc(sent.get("taken_at"))})
