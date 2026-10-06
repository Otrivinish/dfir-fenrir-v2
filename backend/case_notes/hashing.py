"""Canonical content hash of a case note (H2). Used by the create route (stored on the row and in
its audit row), the LE package (re-checked per entry) and reports."""
import hashlib
import json
from datetime import timezone

LINK_FIELDS = ("evidence_ids", "entity_ids", "ioc_ids", "timeline_event_ids")
TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def created_at_text(n) -> str:
    """created_at exactly as hashed: UTC, microseconds, Z."""
    return n.created_at.astimezone(timezone.utc).strftime(TS_FORMAT)


def content_sha256(n) -> str:
    """SHA-256 (hex) of the canonical entry: UTF-8 JSON, keys sorted, no spaces, link ids sorted,
    created_at as YYYY-MM-DDTHH:MM:SS.ffffffZ, absent ids as null. Recomputable from an export row."""
    doc = {
        "v": 1,
        "id": str(n.id),
        "incident_id": str(n.incident_id),
        "author_id": str(n.author_id),
        "created_at": created_at_text(n),
        "body": n.body,
        "corrects_id": str(n.corrects_id) if n.corrects_id else None,
        "source_scratchpad_id": str(n.source_scratchpad_id) if n.source_scratchpad_id else None,
        **{f: sorted(str(x) for x in (getattr(n, f) or [])) for f in LINK_FIELDS},
    }
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
