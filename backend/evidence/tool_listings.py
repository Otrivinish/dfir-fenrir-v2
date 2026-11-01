"""S6 (EG-4, HLD §3.5): the acquisition tool's own file listing, found inside a ZIP container, merged into its
manifest. Each parser is versioned and tolerant: a listing it can't read (not UTF-8, a missing column, a garbled line)
is not merged at all, the reason goes in the manifest's `listing` summary, and the manifest is still built.

v1 knows two listings. Neither format was checked against real tool output here (no tool, no internet): they follow
FENRIR's own Velociraptor reader (forensic/parser.py) and the tools' documented columns; docs/evidence-s6-container-
manifest-slice.md lists every assumption.

- kape_copylog v1: KAPE's `*_CopyLog.csv`. Needs the SourceFile and DestinationFile columns; uses SourceFileSha1,
  CreatedOnUtc, ModifiedOnUtc, LastAccessedOnUtc when present. A row's DestinationFile (where KAPE wrote the copy) is
  matched to the member with the longest common path suffix (case-insensitive, either slash); SourceFile becomes the
  entry's source_path, the three times its source times (UTC, as KAPE read them), SourceFileSha1 its tool hash.
- velociraptor_uploads v1: an offline collector's `uploads.json` (JSON lines). Each row's `_Components` (or its
  `vfs_path`, percent-decoded) after "uploads" = accessor + path components; the member is the one under uploads/
  whose percent-decoded components are the same. The path components rebuild source_path (a drive letter or device
  first: Windows separators; else POSIX). A row's sha256 / md5, if present, is its tool hash. Rows of Type "idx" (the
  sparse-file index) are skipped.
"""
from __future__ import annotations

import csv
import io
import json
import re
import zipfile
import zlib
import lzma
from datetime import datetime, timezone
from typing import Callable, Iterator, Optional
from urllib.parse import unquote

VERSION = 1
KAPE = "kape_copylog"
VELOCIRAPTOR = "velociraptor_uploads"
_HEX = {"md5": re.compile(r"[0-9a-f]{32}"), "sha1": re.compile(r"[0-9a-f]{40}"), "sha256": re.compile(r"[0-9a-f]{64}")}
_DRIVE = re.compile(r"[A-Za-z]:")
_MAX_LINE = 1024 * 1024                              # one listing line (uploads.json, CopyLog)


class Garbled(Exception):
    """The listing is not one this parser version reads: no merge (the message says why)."""


def listing_kind(path: str) -> Optional[str]:
    low = path.lower()
    if low.rsplit("/", 1)[-1].endswith("_copylog.csv"):
        return KAPE
    if low == "uploads.json":
        return VELOCIRAPTOR
    return None


def summary(kind: str, member: Optional[str], status: str, **kw) -> dict:
    return {"parser": kind, "version": VERSION, "member": member, "status": status, "rows": 0, "matched": 0,
            "unmatched": 0, "tool_hash_matches": 0, "tool_hash_mismatches": 0, "note": None, **kw}


def _text(s: str, line: int, caps) -> str:
    """Postgres text: no NUL and valid UTF-8 (no lone surrogates); within the path cap."""
    if "\x00" in s or len(s) > caps.max_path_chars:
        raise Garbled(f"line {line}: a path with a NUL byte or over {caps.max_path_chars} characters")
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        raise Garbled(f"line {line}: a path that is not valid Unicode") from None
    return s


def _kape_utc(v: str) -> Optional[str]:
    """A KAPE *OnUtc value as UTC ISO (more than 6 fraction digits cut), None if it doesn't parse."""
    t = v.strip().replace(" ", "T", 1).rstrip("Zz")
    t = re.sub(r"(\.\d{6})\d+", r"\1", t)
    try:
        dt = datetime.fromisoformat(t)
    except ValueError:
        return None
    dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _lines(text) -> Iterator[str]:
    """csv.reader takes whole lines from its iterator, before its field limit applies: bound each one (a deflated
    member can hold a gigabyte-long line in a few MiB)."""
    while raw := text.readline(_MAX_LINE):
        if len(raw) == _MAX_LINE and not raw.endswith(("\n", "\r")):
            raise Garbled(f"a line longer than {_MAX_LINE} characters")
        yield raw


def _kape(text, caps) -> Iterator[tuple[object, dict]]:
    """(DestinationFile, merge info) per row of a CopyLog (a text stream). Raises Garbled (UnicodeDecodeError and
    csv.Error, e.g. a field over csv's 128 KiB limit, included)."""
    try:
        reader = csv.reader(_lines(text))
        header = next(reader, None)
        if not header:
            raise Garbled("empty")
        cols = {name.strip(): i for i, name in enumerate(header)}
        missing = [c for c in ("SourceFile", "DestinationFile") if c not in cols]
        if missing:
            raise Garbled(f"no {' / '.join(missing)} column: not a KAPE CopyLog this parser (v{VERSION}) reads")
        for line, rec in enumerate(reader, 2):
            if not rec:
                continue
            if len(rec) != len(header):
                raise Garbled(f"line {line}: {len(rec)} fields, the header has {len(header)}")
            if line - 1 > caps.max_entries:
                raise Garbled(f"more than {caps.max_entries} rows")
            get = lambda c: rec[cols[c]] if c in cols else ""      # noqa: E731
            src, dst = _text(get("SourceFile"), line, caps), _text(get("DestinationFile"), line, caps)
            times = {slot: {"utc": _kape_utc(v), "as_recorded": v}
                     for col, slot in (("ModifiedOnUtc", "m"), ("LastAccessedOnUtc", "a"), ("CreatedOnUtc", "b"))
                     if (v := get(col).strip())}
            if times:
                times.update(basis="KAPE CopyLog ModifiedOnUtc / LastAccessedOnUtc / CreatedOnUtc (UTC, the source "
                                   "file's times as KAPE read them)", read_by="KAPE")
            sha1 = get("SourceFileSha1").strip()
            yield dst, {"source_path": src or None, "times": times or None,
                        "tool_hash": {"algorithm": "sha1", "value": sha1} if sha1 else None}
    except csv.Error as e:
        raise Garbled(f"not valid CSV: {e}") from None
    except UnicodeDecodeError:
        raise Garbled("not UTF-8 text") from None


def _velo_source_path(path: list[str]) -> str:
    if _DRIVE.fullmatch(path[0]):
        return path[0] + "\\" + "\\".join(path[1:])
    if path[0].startswith("\\\\"):                   # a device, e.g. \\.\C: (the ntfs accessor)
        return "\\".join(path)
    return "/" + "/".join(path)


def _velociraptor(text, caps) -> Iterator[tuple[object, dict]]:
    """(the upload's components, merge info) per row of uploads.json (a text stream, JSON lines). Raises Garbled."""
    line = rows = 0
    try:
        while raw := text.readline(_MAX_LINE):
            line += 1
            if len(raw) == _MAX_LINE and not raw.endswith("\n"):
                raise Garbled(f"line {line}: longer than {_MAX_LINE} characters")
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except ValueError:
                raise Garbled(f"line {line}: not JSON") from None
            if not isinstance(row, dict):
                raise Garbled(f"line {line}: not a JSON object")
            if row.get("Type") == "idx":
                continue
            comps = row.get("_Components")
            if comps is None and isinstance(row.get("vfs_path"), str):
                comps = [unquote(c) for c in row["vfs_path"].split("/") if c]
            if not (isinstance(comps, list) and comps and all(isinstance(c, str) and c for c in comps)):
                raise Garbled(f"line {line}: no _Components or vfs_path")
            if "uploads" in comps:
                comps = comps[comps.index("uploads") + 1:]
            if len(comps) < 2:
                raise Garbled(f"line {line}: no accessor and path after uploads/")
            rows += 1
            if rows > caps.max_entries:
                raise Garbled(f"more than {caps.max_entries} rows")
            src = _text(_velo_source_path([_text(c, line, caps) for c in comps[1:]]), line, caps)
            tool_hash = next(({"algorithm": algo, "value": v} for algo in ("sha256", "md5")
                              for v in (row.get(algo), row.get(algo.capitalize()))
                              if isinstance(v, str) and _HEX[algo].fullmatch(v.strip().lower())), None)
            yield tuple(comps), {"source_path": src, "times": None, "tool_hash": tool_hash}
    except UnicodeDecodeError:
        raise Garbled("not UTF-8 text") from None


_PARSERS = {KAPE: _kape, VELOCIRAPTOR: _velociraptor}


def _matcher(kind: str, paths: list[str]) -> Callable[[object], Optional[int]]:
    if kind == KAPE:
        index = {p.replace("\\", "/").strip("/").lower(): seq for seq, p in enumerate(paths, 1) if not p.endswith("/")}

        def match(dst):
            comps = [c for c in dst.replace("\\", "/").split("/") if c]
            return next((index[k] for i in range(len(comps)) if (k := "/".join(comps[i:]).lower()) in index), None)
        return match
    index = {tuple(unquote(c) for c in p.split("/")[1:] if c): seq
             for seq, p in enumerate(paths, 1) if p.startswith("uploads/") and not p.endswith("/")}
    return index.get


def merge_zip(paths: list[str], encrypted: list[bool], open_member: Callable[[int], object], caps,
              listing: list) -> dict[int, dict]:
    """Find the listings among a ZIP's members, parse them (streamed: never read whole) and return {seq: merge info}
    for the members they name. Appends one summary per listing member to `listing`. A listing is merged whole or not
    at all."""
    merged: dict[int, dict] = {}
    for seq, path in enumerate(paths, 1):
        kind = listing_kind(path)
        if not kind:
            continue
        s = summary(kind, path, "not_merged")
        listing.append(s)
        if encrypted[seq - 1]:
            s["note"] = "the listing member is encrypted: not read"
            continue
        match, found, rows = _matcher(kind, paths), {}, 0
        try:
            with open_member(seq) as f:
                text = io.TextIOWrapper(f, encoding="utf-8-sig" if kind == KAPE else "utf-8", newline="")
                for key, info in _PARSERS[kind](text, caps):
                    rows += 1
                    target = match(key)
                    if target is None or target in merged or target in found:
                        s["unmatched"] += 1
                    else:
                        found[target] = {**info, "summary": s}
        except Garbled as g:
            s.update(note=str(g)[:500], unmatched=0)
            continue
        except (zipfile.BadZipFile, NotImplementedError, zlib.error, lzma.LZMAError, EOFError, OSError) as e:
            s.update(note=f"could not read the listing: {type(e).__name__}: {e}"[:500], unmatched=0)
            continue
        merged.update(found)
        s.update(status="merged", rows=rows, matched=len(found))
    return merged


def apply(entry: dict, info: Optional[dict]) -> None:
    """Merge one listing row into its (hashed) entry and count the tool-hash comparison."""
    if not info:
        return
    s = info["summary"]
    entry["source_path"] = info["source_path"]
    if info["times"]:
        entry["times"] = {**entry["times"], "source": info["times"]}
    th = info["tool_hash"]
    if th:
        entry["tool_hash"] = th
        mine, value = entry.get(th["algorithm"]), th["value"].strip().lower()
        if mine and _HEX[th["algorithm"]].fullmatch(value):
            entry["tool_hash_match"] = mine == value
            s["tool_hash_matches" if mine == value else "tool_hash_mismatches"] += 1


def finish(listing: list) -> None:
    for s in listing:
        if s["status"] == "merged" and not s["matched"] and not s["note"]:
            s["note"] = "no row named a member of this container"
