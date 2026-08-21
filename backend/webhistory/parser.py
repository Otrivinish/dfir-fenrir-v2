"""Browser history SQLite parsing (Chrome/Edge/Brave's `History`, Firefox's
`places.sqlite`).

Extends the existing pattern already established in `forensic/parser.py`'s
`_parse_sqlite` (which only feeds a handful of candidate events into
Timeline Import, capped at 2,000 rows) -- this module is the full extraction
behind the dedicated Web Browser History page: every visit, visit_count,
transition type, and Chromium's typed search terms, with no realistic row
cap.

Safety, on top of what `forensic/parser.py` already does:
  - Connection opened **read-only + immutable** via a `file:` URI, not a
    plain writable connection -- the file is untrusted forensic evidence.
  - Only ever hardcoded, parameterized SELECTs against a schema confirmed
    via `sqlite_master` first -- never SQL built from file content.
  - No BLOB columns are ever read (favicons etc.) -- text/int fields only,
    so no image-decoding library is ever in the path.
  - A defensive row cap (`_MAX_ROWS`) guards against a pathological/crafted
    file, not real-world profiles -- real histories are nowhere near it.
  - The temp file is always unlinked in a `finally`, success or exception.
"""
import contextlib
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

SQLITE_MAGIC = b"SQLite format 3\x00"

_WEBKIT_EPOCH_OFFSET_US = 11_644_473_600_000_000  # microseconds between 1601-01-01 and 1970-01-01
_MAX_ROWS = 2_000_000  # defensive backstop, not a real-world limit

# Chromium `visits.transition` low byte (PAGE_TRANSITION_CORE_MASK = 0xFF).
_CHROMIUM_TRANSITIONS = {
    0: "link", 1: "typed", 2: "auto_bookmark", 3: "auto_subframe",
    4: "manual_subframe", 5: "generated", 6: "start_page", 7: "form_submit",
    8: "reload", 9: "keyword", 10: "keyword_generated",
}
# Chromium `downloads.state` (content::DownloadItem::DownloadState).
_CHROMIUM_DOWNLOAD_STATES = {0: "in_progress", 1: "complete", 2: "cancelled", 3: "interrupted"}
# Chromium `downloads.danger_type` -- only the common/stable values; anything
# else is passed through as its raw numeric code rather than guessed at.
_CHROMIUM_DANGER_TYPES = {
    0: "not_dangerous", 1: "dangerous_file", 2: "dangerous_url",
    3: "dangerous_content", 4: "maybe_dangerous_content", 5: "uncommon_content",
    6: "user_validated", 7: "dangerous_host", 8: "potentially_unwanted",
    9: "allowlisted_by_policy",
}

# Firefox `moz_historyvisits.visit_type`.
_FIREFOX_VISIT_TYPES = {
    1: "link", 2: "typed", 3: "bookmark", 4: "embed",
    5: "redirect_permanent", 6: "redirect_temporary", 7: "download",
    8: "framed_link", 9: "reload",
}


def _webkit_to_utc(microseconds: Optional[int]) -> Optional[datetime]:
    if not microseconds:
        return None
    try:
        unix_us = microseconds - _WEBKIT_EPOCH_OFFSET_US
        return datetime.fromtimestamp(unix_us / 1_000_000, tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None


def _prtime_to_utc(microseconds: Optional[int]) -> Optional[datetime]:
    if not microseconds:
        return None
    try:
        return datetime.fromtimestamp(microseconds / 1_000_000, tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None


def _host_of(url: str) -> Optional[str]:
    try:
        return urlparse(url).hostname or None
    except ValueError:
        return None


@contextlib.contextmanager
def _readonly_sqlite(content: bytes):
    """Write `content` to a throwaway temp file and open it read-only +
    immutable via a `file:` URI -- shared by every entry point in this
    module so the safety-critical bits (no writable handle, no execution,
    always cleaned up) live in exactly one place."""
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            f.write(content)
            tmp_path = f.name
        conn = sqlite3.connect(f"file:{tmp_path}?mode=ro&immutable=1", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def parse_history_db(content: bytes) -> dict:
    """Parse a Chromium or Firefox history SQLite file.

    Returns {"schema_family": "chromium"|"firefox", "visits": [...],
    "search_terms": [...], "truncated": bool}. Raises ValueError if the
    file isn't a recognized Chrome/Edge/Brave or Firefox history database.
    """
    with _readonly_sqlite(content) as conn:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}

        if "visits" in tables and "urls" in tables:
            return _parse_chromium(conn, tables)
        elif "moz_historyvisits" in tables and "moz_places" in tables:
            return _parse_firefox(conn)
        else:
            raise ValueError("Not a recognized Chrome/Edge/Brave or Firefox history database")


def parse_form_history_db(content: bytes) -> list[dict]:
    """Parse Firefox's separate `formhistory.sqlite` (moz_formhistory table)
    for search-bar queries.

    Only rows with fieldname == 'searchbar-history' are extracted -- the
    dedicated search-bar widget's remembered queries, the closest Firefox
    equivalent to Chromium's keyword_search_terms. Every other fieldname in
    this file is a generic per-site form field value (arbitrary text typed
    into any website's form, not a search) and is deliberately left alone:
    pulling those in under a tab labeled "Search terms" would silently mix
    in untargeted, potentially sensitive form data the analyst didn't ask
    for. Raises ValueError if the file isn't a recognized formhistory.sqlite.
    """
    with _readonly_sqlite(content) as conn:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        if "moz_formhistory" not in tables:
            raise ValueError("Not a recognized Firefox form history database")

        rows = conn.execute(
            "SELECT value, lastUsed FROM moz_formhistory "
            "WHERE fieldname = 'searchbar-history' ORDER BY lastUsed DESC LIMIT ?",
            (_MAX_ROWS,),
        ).fetchall()

    return [{"term": r["value"], "url": None, "visit_time": _prtime_to_utc(r["lastUsed"])} for r in rows]


def _parse_chromium(conn: sqlite3.Connection, tables: set) -> dict:
    rows = conn.execute(
        "SELECT v.visit_time, v.transition, u.url, u.title, u.visit_count "
        "FROM visits v JOIN urls u ON v.url = u.id "
        "ORDER BY v.visit_time DESC LIMIT ?",
        (_MAX_ROWS,),
    ).fetchall()

    visits = []
    for r in rows:
        ts = _webkit_to_utc(r["visit_time"])
        if ts is None:
            continue
        url = r["url"] or ""
        core = (r["transition"] or 0) & 0xFF
        visits.append({
            "url": url,
            "host": _host_of(url),
            "title": r["title"] or None,
            "visit_time": ts,
            "visit_count": r["visit_count"],
            "transition": _CHROMIUM_TRANSITIONS.get(core),
        })

    search_terms = []
    if "keyword_search_terms" in tables:
        term_rows = conn.execute(
            "SELECT kst.term, u.url, u.last_visit_time "
            "FROM keyword_search_terms kst JOIN urls u ON kst.url_id = u.id "
            "ORDER BY u.last_visit_time DESC LIMIT ?",
            (_MAX_ROWS,),
        ).fetchall()
        for r in term_rows:
            search_terms.append({
                "term": r["term"],
                "url": r["url"] or None,
                "visit_time": _webkit_to_utc(r["last_visit_time"]),
            })

    downloads = _parse_chromium_downloads(conn, tables) if "downloads" in tables else []

    return {
        "schema_family": "chromium",
        "visits": visits,
        "search_terms": search_terms,
        "downloads": downloads,
        "truncated": len(rows) >= _MAX_ROWS,
    }


def _parse_chromium_downloads(conn: sqlite3.Connection, tables: set) -> list[dict]:
    rows = conn.execute(
        "SELECT id, target_path, start_time, end_time, received_bytes, total_bytes, "
        "state, danger_type, mime_type FROM downloads "
        "ORDER BY start_time DESC LIMIT ?",
        (_MAX_ROWS,),
    ).fetchall()

    # The download's URL lives in a separate table -- one row per redirect hop;
    # the highest chain_index is the URL actually downloaded from.
    final_url_by_id: dict[int, str] = {}
    if "downloads_url_chains" in tables:
        for r in conn.execute("SELECT id, chain_index, url FROM downloads_url_chains ORDER BY id, chain_index"):
            final_url_by_id[r["id"]] = r["url"]  # last write per id wins, since ordered by chain_index ascending

    downloads = []
    for r in rows:
        danger = r["danger_type"]
        downloads.append({
            "url": final_url_by_id.get(r["id"]),
            "target_path": r["target_path"] or None,
            "start_time": _webkit_to_utc(r["start_time"]),
            "end_time": _webkit_to_utc(r["end_time"]),
            "received_bytes": r["received_bytes"],
            "total_bytes": r["total_bytes"],
            "state": _CHROMIUM_DOWNLOAD_STATES.get(r["state"], str(r["state"]) if r["state"] is not None else None),
            "danger": _CHROMIUM_DANGER_TYPES.get(danger, str(danger) if danger is not None else None),
            "mime_type": r["mime_type"] or None,
        })
    return downloads


def _parse_firefox(conn: sqlite3.Connection) -> dict:
    rows = conn.execute(
        "SELECT v.visit_date, v.visit_type, p.url, p.title, p.visit_count "
        "FROM moz_historyvisits v JOIN moz_places p ON v.place_id = p.id "
        "ORDER BY v.visit_date DESC LIMIT ?",
        (_MAX_ROWS,),
    ).fetchall()

    visits = []
    for r in rows:
        ts = _prtime_to_utc(r["visit_date"])
        if ts is None:
            continue
        url = r["url"] or ""
        visits.append({
            "url": url,
            "host": _host_of(url),
            "title": r["title"] or None,
            "visit_time": ts,
            "visit_count": r["visit_count"],
            "transition": _FIREFOX_VISIT_TYPES.get(r["visit_type"]),
        })

    # Firefox has no equivalent of Chromium's keyword_search_terms table
    # inside places.sqlite -- typed/form entries instead live in a separate
    # profile file, formhistory.sqlite (moz_formhistory table), which this
    # analyzer doesn't ingest (only one SQLite file is uploaded at a time).
    return {
        "schema_family": "firefox",
        "visits": visits,
        "search_terms": [],
        "downloads": _parse_firefox_downloads(conn),
        "truncated": len(rows) >= _MAX_ROWS,
    }


def _parse_firefox_downloads(conn: sqlite3.Connection) -> list[dict]:
    """Best-effort only. Firefox has changed how it records downloads across
    versions -- this reads the `moz_annos` "downloads/destinationFileURI"
    annotation still present in many profiles, giving url/target_path/
    start_time reliably. Size/end_time/state live in a version-dependent JSON
    blob (`downloads/metaData`) that isn't parsed here rather than guess at
    a schema that varies by Firefox version -- those fields come back None,
    not a wrong value.
    """
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    if "moz_annos" not in tables or "moz_anno_attributes" not in tables:
        return []
    try:
        rows = conn.execute(
            "SELECT p.url, a.content, a.dateAdded "
            "FROM moz_annos a "
            "JOIN moz_anno_attributes attr ON a.anno_attribute_id = attr.id "
            "JOIN moz_places p ON a.place_id = p.id "
            "WHERE attr.name = 'downloads/destinationFileURI' "
            "ORDER BY a.dateAdded DESC LIMIT ?",
            (_MAX_ROWS,),
        ).fetchall()
    except sqlite3.Error:
        return []

    downloads = []
    for r in rows:
        target = r["content"] or ""
        if target.startswith("file:"):
            from urllib.parse import unquote, urlparse
            target = unquote(urlparse(target).path) or target
        downloads.append({
            "url": r["url"] or None,
            "target_path": target or None,
            "start_time": _prtime_to_utc(r["dateAdded"]),
            "end_time": None, "received_bytes": None, "total_bytes": None,
            "state": None, "danger": None, "mime_type": None,
        })
    return downloads
