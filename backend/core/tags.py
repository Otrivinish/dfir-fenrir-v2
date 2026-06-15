"""Tag normalisation — shared by Incident, IOC, and any other tag-bearing model.

Per FENRIR2 design decision (2026-05-17): tags are freeform but normalised to
lowercase-dashed strings at the API boundary so 'APT 28' and 'apt-28' dedup
into the same tag. Cap at 20 per row to prevent abuse.

We deliberately do NOT store the original casing — keeping a single canonical
form makes typeahead deduplication trivial and avoids "APT28 vs apt28 vs
Apt28" sprawl in the catalogue.
"""
from __future__ import annotations

import re
from typing import Iterable

MAX_TAGS_PER_ROW = 20
MAX_TAG_LENGTH   = 64

# Collapse any run of whitespace/underscore/dash into a single dash.
_DASH_RUN = re.compile(r"[\s_\-]+")
# Strip anything that isn't alphanumeric, dash, dot, slash, or colon. Dots
# colons and slashes are kept because security tags often look like
# "cve-2024-1234", "ttp:t1059.001", "platform/windows".
_FORBIDDEN = re.compile(r"[^a-z0-9\-./:]")


def normalize_tag(raw: str) -> str | None:
    """Single tag → canonical form, or None if it normalises to empty."""
    if not raw:
        return None
    s = str(raw).strip().lower()
    s = _DASH_RUN.sub("-", s)
    s = _FORBIDDEN.sub("", s)
    s = s.strip("-./:")
    if not s:
        return None
    return s[:MAX_TAG_LENGTH]


def normalize_tags(raw: Iterable[str] | None) -> list[str]:
    """List of tags → deduped, normalised, capped at MAX_TAGS_PER_ROW.
    Preserves first-seen order so the UI can rely on a stable sort.
    """
    if not raw:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for r in raw:
        n = normalize_tag(r)
        if not n or n in seen:
            continue
        seen.add(n)
        out.append(n)
        if len(out) >= MAX_TAGS_PER_ROW:
            break
    return out
