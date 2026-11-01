"""S2 (EG-1/2/3/5) — an exhibit's source location record (docs/evidence-hld-2026-10-31.md §3.2–§3.4).

The one server-side check every intake route runs (source_columns), the search form norm_v1, and the
advisory provider-hash compare (EG-5). Pure: no DB, no I/O.

source_path and source_system are stored exactly as sent: never trimmed, case-folded or Unicode-normalised.
source_path_norm is derived here from the path and its style, and never accepted from a client. It is search
data only and can be recomputed from the verbatim path at any time, so a later norm_v2 needs no version column.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from typing import Mapping, Optional

from fastapi import status

from core.errors import ApiError
from schemas import SOURCE_PATH_MAX

# What a client may send (source_path_norm only to be refused), and what the collect / change audit rows carry.
SOURCE_INPUT_FIELDS = ("source_system", "source_path", "source_path_style", "source_path_norm",
                       "source_details", "source_unknown_reason")
SOURCE_AUDIT_FIELDS = ("make", "model", "serial", "source_system", "source_path", "source_path_style",
                       "source_details", "source_unknown_reason")
UNKNOWN_REASON_MIN = 10

# §3.4 shape rules, matched at the start of the path (re.match). cloud_uri also needs an allowed scheme.
_SHAPE = {
    "windows":    re.compile(r"[A-Za-z]:[\\/]|\\\\\?\\"),
    "unc":        re.compile(r"\\\\[^\\/]+[\\/][^\\/]+"),
    "posix":      re.compile(r"/"),
    "macos":      re.compile(r"/"),
    "android":    re.compile(r"/"),
    "ios":        re.compile(r"/|[A-Za-z][A-Za-z0-9]*Domain[^/]*-."),
    "cloud_uri":  re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*)://([^/?#]+)"),
    "mail_store": re.compile(r".", re.S),
    "device":     re.compile(r".", re.S),
    "other":      re.compile(r".", re.S),
}
_CLOUD_SCHEMES = {"https", "s3", "gs", "az", "abfss"}
_URI_AUTHORITY = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*)://([^/?#]*)")


def _refuse(code: str, detail: str) -> ApiError:
    return ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, code, detail)


def shape_ok(path: str, style: str) -> bool:
    m = _SHAPE[style].match(path)
    if style == "cloud_uri":
        return bool(m) and m.group(1).lower() in _CLOUD_SCHEMES
    return bool(m)


def norm_v1(path: str, style: str) -> str:
    """The search form: NFC; Windows styles drop \\\\?\\ (\\\\?\\UNC\\ becomes \\\\), turn / into \\, collapse
    repeated separators (keeping a UNC lead) and upper-case the drive letter; POSIX-like styles collapse //;
    a cloud URI lower-cases its scheme and host. Never resolves . or .. and never folds any other case."""
    p = unicodedata.normalize("NFC", path)
    if style in ("windows", "unc"):
        p = p.replace("/", "\\")
        if p[:8].upper() == "\\\\?\\UNC\\":
            p = "\\\\" + p[8:]
        elif p.startswith("\\\\?\\"):
            p = p[4:]
        lead = "\\\\" if p.startswith("\\\\") else ""
        p = lead + re.sub(r"\\{2,}", r"\\", p[len(lead):])
        if re.match(r"[a-z]:", p):
            p = p[0].upper() + p[1:]
    elif style in ("posix", "macos", "android", "ios"):
        p = re.sub(r"/{2,}", "/", p)
    elif style == "cloud_uri":
        m = _URI_AUTHORITY.match(p)
        if m:
            userinfo, at, hostport = m.group(2).rpartition("@")
            p = f"{m.group(1).lower()}://{userinfo}{at}{hostport.lower()}{p[m.end():]}"
    return p


def sent_source_fields(req) -> dict:
    """The source fields a Pydantic request body actually sent (an explicit null included)."""
    return {k: getattr(req, k) for k in SOURCE_INPUT_FIELDS if k in req.model_fields_set}


def source_columns(sent: Mapping, current: Optional[Mapping] = None) -> dict:
    """The evidence columns for the source fields a request sent (only those; null or "" clears one), checked.
    `current` = the row's stored source_path / source_path_style for an edit, None for a new exhibit. Returns the
    sent values as given (source_details, a SourceDetails, as its stored JSON) plus source_path_norm whenever
    the path or its style changes. Nothing is trimmed: the 10-character minimum of source_unknown_reason is
    counted without surrounding spaces, and the reason is stored as sent.
    422 source_path_norm_read_only, invalid_source_path (NUL or over 32,768 characters), invalid_source_text
    (a NUL in source_system / source_unknown_reason), source_unknown_reason_too_short,
    source_path_style_required, source_path_style_mismatch."""
    if "source_path_norm" in sent:
        raise _refuse("source_path_norm_read_only",
                      "source_path_norm is derived by the server from source_path and its style (norm_v1): "
                      "leave it out")
    cols: dict = {}
    for k, v in sent.items():
        if v == "":
            v = None
        if k == "source_details" and v is not None:
            v = v.model_dump(mode="json", exclude_none=True)
        cols[k] = v

    path = cols.get("source_path")
    if path is not None:
        if "\x00" in path:
            raise _refuse("invalid_source_path", "source_path contains a NUL character, which can't be stored: "
                          "put the path's raw bytes (base64) in source_details.path_raw_b64 and describe it here")
        if len(path) > SOURCE_PATH_MAX:
            raise _refuse("invalid_source_path", f"source_path is longer than {SOURCE_PATH_MAX:,} characters")
    for k in ("source_system", "source_unknown_reason"):
        if cols.get(k) is not None and "\x00" in cols[k]:
            raise _refuse("invalid_source_text", f"{k} contains a NUL character, which can't be stored")
    reason = cols.get("source_unknown_reason")
    if reason is not None and len(reason.strip()) < UNKNOWN_REASON_MIN:
        raise _refuse("source_unknown_reason_too_short",
                      f"source_unknown_reason must say why the source can't be stated (at least "
                      f"{UNKNOWN_REASON_MIN} characters)")

    if "source_path" in cols or "source_path_style" in cols:
        cur = current or {}
        path = cols["source_path"] if "source_path" in cols else cur.get("source_path")
        style = cols["source_path_style"] if "source_path_style" in cols else cur.get("source_path_style")
        if path is None:
            cols["source_path_norm"] = None
        elif not style:
            raise _refuse("source_path_style_required",
                          "source_path needs source_path_style (windows, unc, posix, macos, android, ios, "
                          "cloud_uri, mail_store, device or other)")
        elif not shape_ok(path, style):
            raise _refuse("source_path_style_mismatch",
                          f"source_path does not look like a {style} path (see source_path_style); pick the "
                          "style that matches, or other, and keep the path as recorded")
        else:
            cols["source_path_norm"] = norm_v1(path, style)
    return cols


def audit_values(ev) -> dict:
    """The source record of a row for its evidence_collect audit (fields with a value)."""
    return {k: getattr(ev, k) for k in SOURCE_AUDIT_FIELDS if getattr(ev, k) is not None}


# ── S3 (EG-12, HLD §3.3; owner Q1): the source a digital exhibit needs at seal ─────────────────────────────────
EXPORT_DEVICE_TYPES = frozenset({"email_export", "vendor_report", "network_capture"})


def _filled(v) -> bool:
    return bool((v or "").strip())


def seal_source_missing(ev) -> list[str]:
    """What the seal needs of a digital exhibit's source record and the exhibit lacks ([] = met), not counting
    source_unknown_reason, which meets all of it (the caller decides). One rule for the seal gate and the
    provenance check iso_27037_source_location:
      source_device      none of entity_id, source_system, serial (27037 §7.1.1.1 asks for the serial; make and
                         model alone do not identify a device);
      source_path        the path its handling needs: a full image needs a device path (style device); live or
                         volatile data (system_state live / live_critical) and exports (device type email_export,
                         vendor_report or network_capture) need none; anything else (logical, or no scope
                         recorded) needs the path and its style;
      source_path_style  a full image whose path is not of style device."""
    missing = [] if (ev.entity_id or _filled(ev.source_system) or _filled(ev.serial)) else ["source_device"]
    has_path = ev.source_path is not None and bool(ev.source_path_style)
    if ev.acquisition_scope == "full_image":
        if not has_path:
            missing.append("source_path")
        elif ev.source_path_style != "device":
            missing.append("source_path_style")
    elif not ((ev.system_state or "") in ("live", "live_critical")
              or EXPORT_DEVICE_TYPES & set(ev.device_types or [])) and not has_path:
        missing.append("source_path")
    return missing


# ── EG-5: the provider's own hash vs the stored file (advisory; provenance only) ─────────────────
_DIGEST_SIZE = {"md5": 16, "sha1": 20, "sha256": 32}
_HEX = re.compile(r"[0-9A-Fa-f]+")


def _digest(value: str, size: int) -> Optional[bytes]:
    v = value.strip()
    if len(v) == 2 * size and _HEX.fullmatch(v):
        return bytes.fromhex(v)
    try:
        raw = base64.b64decode(v, validate=True)      # Azure Content-MD5, S3 checksums
    except (binascii.Error, ValueError):
        return None
    return raw if len(raw) == size else None


def provider_hash_check(details: Optional[dict], *, md5: Optional[str], sha1: Optional[str],
                        sha256: Optional[str]) -> Optional[dict]:
    """None when the record has no provider hash. Otherwise {algorithm, comparable, match, reason}: only an
    MD5, SHA-1 or SHA-256 given as hex or base64 is compared with the stored file's hash of that algorithm.
    reason (when not comparable): algorithm (e.g. QuickXorHash), value (not hex or base64 of that length) or
    no_file (no stored hash)."""
    ph = ((details or {}).get("provider") or {}).get("provider_hash")
    if not ph:
        return None
    given = str(ph.get("algorithm") or "")
    algo = given.lower().replace("-", "").replace("_", "")
    if algo not in _DIGEST_SIZE:
        return {"algorithm": given, "comparable": False, "match": None, "reason": "algorithm"}
    digest = _digest(str(ph.get("value") or ""), _DIGEST_SIZE[algo])
    if digest is None:
        return {"algorithm": algo, "comparable": False, "match": None, "reason": "value"}
    stored = {"md5": md5, "sha1": sha1, "sha256": sha256}[algo]
    if not stored:
        return {"algorithm": algo, "comparable": False, "match": None, "reason": "no_file"}
    return {"algorithm": algo, "comparable": True, "match": digest.hex() == stored.lower(), "reason": None}
