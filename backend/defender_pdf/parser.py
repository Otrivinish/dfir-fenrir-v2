"""Microsoft Defender XDR incident PDF ("Evidence and response" export) parser.

Extracts candidate IOCs, Entities, and Timeline events from the incident PDF
an analyst downloads from the Defender portal, for review before committing.
Pure-Python text/word extraction via pdfplumber (wraps pdfminer.six, no
native PDF renderer) -- nothing in the file is executed.

Microsoft's report tables have no ruling lines, so plain text extraction
(`page.extract_text()`) reads columns in the wrong order wherever two
columns wrap onto the same rows -- verified against a real sample, where a
long free-text column next to another wrapping column came out with words
split and reordered at the character level (garbled beyond just "wrong
order"). To avoid ever using scrambled text as an IOC value or timeline
description, the three tables (Evidence, Devices, Alerts) are reconstructed
by clustering each word's x-position into columns derived from that table's
own header row -- and the one genuinely free-text column (Detection origin)
is never used as an extracted value, only ever as a description suffix.
"""
import io
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

import pdfplumber

MAX_PAGES = 50

_MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
           "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}
_DT_RE = re.compile(r'([A-Z][a-z]{2}) (\d{1,2}), (\d{4}) (\d{1,2}):(\d{2})(?::(\d{2}))? ([AP]M)')
_TZ_NOTE_RE = re.compile(r'Timestamps are generated in UTC([+-]\d+)')
_ACTIVITY_TS_RE = re.compile(r'^[A-Z][a-z]{2} \d{1,2}, \d{4} \d{1,2}:\d{2}(?::\d{2})? [AP]M$')
# Each Activity-log entry is preceded by an icon-font bullet glyph (Private
# Use Area codepoint), not a blank line -- there are no blank lines in the
# extracted text at all, verified against the real sample.
_PUA_ICON_RE = re.compile(r'[-]')

# Columns holding a single identifier/token (IP, URL, GUID fragment, rule
# name) that PDF line-wrapping can break with no hyphen and no real word
# boundary -- these join wrapped *lines* with no space. Everything else
# (dates, categorical labels, natural-language columns) joins wrapped lines
# with a space, same as words already on the same line always do. Verified
# against a real sample: without this split, an IP address wrapped across two
# lines (e.g. "203.0.113.1" as "203.0.113." + "1") extracted as literal text
# with a stray space in the middle instead of the real value.
_TIGHT_WRAP_COLUMNS = {"entity", "device_id", "detection_source"}

# Evidence-table "Entity type" values that are genuine indicators of
# compromise vs. ones that describe an asset/account/session (better
# suggested as an Entity than an IOC).
_IOC_ENTITY_TYPES = {"ip address", "ip addresses", "url", "urls", "domain", "domains",
                      "file", "files"}
_IOC_TYPE_MAP = {
    "ip address": "ip", "ip addresses": "ip",
    "url": "url", "urls": "url",
    "domain": "domain", "domains": "domain",
    "file": "hash_sha256", "files": "hash_sha256",
}
_RISK_TO_CRITICALITY = {"low": "low", "medium": "medium", "high": "high", "critical": "critical"}


def parse_defender_incident_pdf(content: bytes) -> dict:
    """Returns {"incident": {...display-only metadata...}, "candidates": [...]}.

    Raises ValueError if this doesn't look like a Defender incident PDF.
    """
    with pdfplumber.open(io.BytesIO(content)) as pdf:
        pages = pdf.pages[:MAX_PAGES]
        texts = [p.extract_text() or "" for p in pages]
        full_text = "\n".join(texts)

        if "Microsoft Security" not in (texts[0] if texts else "") or "Incident ID" not in full_text:
            raise ValueError("This doesn't look like a Microsoft Defender incident PDF export")

        tz_offset = _detect_tz_offset_hours(texts[0])
        incident = _extract_incident_meta(full_text)
        incident["title"] = _extract_title(texts[0])

        candidates: list[dict] = []
        candidates += _extract_evidence(pages, texts, tz_offset)
        candidates += _extract_devices(pages, texts)
        candidates += _extract_alerts(pages, texts, tz_offset)
        candidates += _extract_activity_log(full_text, tz_offset)

        created = _parse_defender_dt(incident.get("Time created", ""), tz_offset)
        if created and incident.get("title"):
            candidates.insert(0, {
                "kind": "incident_created",
                "suggested_destination": "timeline_event",
                "value": incident["title"],
                "event_time": created.isoformat(),
                "description": f"Defender incident created: {incident['title']} "
                                f"(ID {incident.get('Incident ID', '?')}, severity {incident.get('Severity', '?')})",
                "hostname": None,
                "source": "Microsoft Defender — Incident",
                "event_type": "incident_created",
                "ioc_type": None,
                "verdict": None,
                "raw_log": None,
                "low_confidence": False,
            })

    return {"incident": incident, "candidates": candidates}


# ─── Timezone / datetime helpers ────────────────────────────────────────────

def _detect_tz_offset_hours(first_page_text: str) -> int:
    m = _TZ_NOTE_RE.search(first_page_text)
    return int(m.group(1)) if m else 0


def _parse_defender_dt(s: str, tz_offset_hours: int) -> Optional[datetime]:
    m = _DT_RE.search(s or "")
    if not m:
        return None
    mon, day, year, hour, minute, sec, ampm = m.groups()
    if mon not in _MONTHS:
        return None
    hour = int(hour) % 12
    if ampm == "PM":
        hour += 12
    try:
        local = datetime(int(year), _MONTHS[mon], int(day), hour, int(minute), int(sec or 0))
    except ValueError:
        return None
    return (local - timedelta(hours=tz_offset_hours)).replace(tzinfo=timezone.utc)


# ─── Incident metadata (Overview page) — display-only, never committed ──────

_OVERVIEW_LABELS = [
    "Severity", "Status", "Assigned to", "Incident ID", "Classification",
    "Categories", "Time created", "First activity", "Last activity",
    "Description", "First log", "Last log", "Time closed",
]


def _extract_title(first_page_text: str) -> str:
    lines = first_page_text.splitlines()
    title_lines, started = [], False
    for line in lines:
        if line.strip() == "Microsoft Security":
            started = True
            continue
        if not started:
            continue
        if line.startswith("PDF file generated on"):
            break
        title_lines.append(line.strip())
    return " ".join(t for t in title_lines if t).strip()


def _extract_incident_meta(full_text: str) -> dict:
    m = re.search(r'\nOverview\n(.*?)(?:\nSecurity Copilot\n|\nAttack story\n|\nAnalysts involved|\Z)',
                   full_text, re.S)
    if not m:
        return {}
    lines = [l for l in m.group(1).splitlines() if l.strip()]
    meta: dict[str, str] = {}
    current: Optional[str] = None
    for line in lines:
        label = next((lbl for lbl in _OVERVIEW_LABELS if line == lbl or line.startswith(lbl + " ")), None)
        if label:
            current = label
            meta[label] = line[len(label):].strip()
        elif current:
            meta[current] = (meta[current] + " " + line.strip()).strip()
    return meta


# ─── Borderless table reconstruction (shared by Evidence/Devices/Alerts) ────

def _header_row_by_marker(words: list[dict], marker_text: str) -> list[dict]:
    marker = next((w for w in words if w["text"] == marker_text), None)
    if not marker:
        return []
    y = marker["top"]
    return sorted((w for w in words if abs(w["top"] - y) < 3), key=lambda w: w["x0"])


def _columns_from_header(header_words: list[dict], labels: list[str]) -> list[tuple[str, float]]:
    if len(header_words) != len(labels):
        return []
    return list(zip(labels, (w["x0"] for w in header_words)))


def _join_cell(tokens_with_lines: list[tuple[float, str]], tight_wrap: bool) -> str:
    """Join a cell's words back into text. Words sharing the same physical
    line always get a space (pdfplumber's word-tokenizer already only splits
    on real gaps). Words on a *new* wrapped line get a space too, unless
    `tight_wrap` -- for identifier columns (IP/URL/GUID fragments, rule
    names) that a line-wrap can break mid-token with no hyphen."""
    out, prev_line = "", None
    for line, tok in tokens_with_lines:
        if prev_line is None:
            out = tok
        elif abs(line - prev_line) < 3:          # same physical line
            out += " " + tok
        elif tight_wrap:                          # wrapped continuation of one token
            out += tok
        else:                                     # wrapped continuation of prose/dates
            out += " " + tok
        prev_line = line
    return out


def _table_rows(words: list[dict], columns: list[tuple[str, float]],
                 anchor_label: str, header_y: float) -> list[dict[str, str]]:
    """Reconstruct a borderless table's data rows below the header block.
    `anchor_label` must be a short, closed-vocabulary column that appears on
    exactly one line per row (e.g. Verdict, Severity, Risk level) -- never a
    field that can wrap -- since wrapped-cell line gaps are indistinguishable
    from genuine row breaks in this report. Headers in this report wrap
    across exactly two lines (~10.5pt apart); `header_y + 25` skips both with
    a safety margin, verified against every table in a real sample."""
    if not columns:
        return []
    below_y = header_y + 25

    def col_of(x0: float) -> str:
        best = columns[0][0]
        for label, start in columns:
            if x0 + 1 >= start:
                best = label
        return best

    data_words = [w for w in words if w["top"] > below_y]
    anchor_ys = sorted(w["top"] for w in data_words if col_of(w["x0"]) == anchor_label)
    if not anchor_ys:
        return []

    rows = []
    for i, y in enumerate(anchor_ys):
        y_hi = anchor_ys[i + 1] - 2 if i + 1 < len(anchor_ys) else float("inf")
        row_words = [w for w in data_words if y - 2 <= w["top"] < y_hi]
        cells: dict[str, list[tuple[float, str]]] = {label: [] for label, _ in columns}
        for w in sorted(row_words, key=lambda w: (w["top"], w["x0"])):
            cells[col_of(w["x0"])].append((w["top"], w["text"]))
        rows.append({label: _join_cell(toks, label in _TIGHT_WRAP_COLUMNS) for label, toks in cells.items()})
    return rows


def _find_page(pages, texts, *, starts_with: Optional[str] = None, contains: Optional[str] = None):
    for page, text in zip(pages, texts):
        if starts_with and not text.strip().startswith(starts_with):
            continue
        if contains and contains not in text:
            continue
        return page, text
    return None, None


# ─── Evidence table → IOC / Entity candidates ───────────────────────────────

_EVIDENCE_LABELS = ["first_seen", "entity", "entity_type", "verdict",
                     "remediation_status", "impacted_assets", "detection_origin"]


def _extract_evidence(pages, texts, tz_offset: int) -> list[dict]:
    page, text = _find_page(pages, texts, contains="Top evidence")
    if page is None:
        return []
    words = page.extract_words(use_text_flow=False, keep_blank_chars=False)
    header = _header_row_by_marker(words, "Verdict")
    columns = _columns_from_header(header, _EVIDENCE_LABELS)
    if not columns:
        return []
    rows = _table_rows(words, columns, "verdict", header[0]["top"])

    candidates = []
    for row in rows:
        entity = row.get("entity", "").strip()
        entity_type = row.get("entity_type", "").strip()
        verdict = row.get("verdict", "").strip()
        if not entity or not entity_type:
            continue
        event_time = _parse_defender_dt(row.get("first_seen", ""), tz_offset)
        et_key = entity_type.lower()
        is_ioc = et_key in _IOC_ENTITY_TYPES
        notes_bits = []
        if row.get("impacted_assets"):
            notes_bits.append(f"Impacted assets: {row['impacted_assets']}")
        if row.get("detection_origin"):
            notes_bits.append(f"Detection origin (best-effort extraction): {row['detection_origin']}")
        candidates.append({
            "kind": "evidence",
            "suggested_destination": "ioc" if is_ioc else "entity",
            "ioc_type": _IOC_TYPE_MAP.get(et_key, "other") if is_ioc else None,
            "entity_type_hint": "ip" if et_key in ("ip address", "ip addresses") else
                                 ("domain" if et_key in ("domain", "domains") else
                                  ("host" if et_key == "device" else "other")),
            "value": entity,
            "description": f"{entity_type}: {entity}" + (f" — {verdict}" if verdict else ""),
            "verdict": verdict or None,
            "event_time": event_time.isoformat() if event_time else None,
            "hostname": row.get("impacted_assets") or None,
            "source": "Microsoft Defender — Evidence",
            "event_type": entity_type,
            "raw_log": " | ".join(notes_bits) or None,
            "low_confidence": event_time is None,
        })
    return candidates


# ─── Devices table → Entity candidates ──────────────────────────────────────

_DEVICE_LABELS = ["device_name", "device_id", "risk_level", "exposure_level",
                   "os_platform", "tags", "first_activity", "last_activity", "related_alerts"]


def _extract_devices(pages, texts) -> list[dict]:
    page, text = _find_page(pages, texts, starts_with="Scope")
    if page is None:
        return []
    words = page.extract_words(use_text_flow=False, keep_blank_chars=False)
    header = _header_row_by_marker(words, "Risk")
    columns = _columns_from_header(header, _DEVICE_LABELS)
    if not columns:
        return []
    rows = _table_rows(words, columns, "risk_level", header[0]["top"])

    candidates = []
    for row in rows:
        name = row.get("device_name", "").strip()
        if not name:
            continue
        risk = row.get("risk_level", "").strip()
        candidates.append({
            "kind": "device",
            "suggested_destination": "entity",
            "ioc_type": None,
            "entity_type_hint": "host",
            "value": name,
            "description": f"Device: {name} (risk {risk or 'unknown'}, "
                            f"exposure {row.get('exposure_level', 'unknown')})",
            "verdict": None,
            "event_time": None,
            "hostname": name,
            "source": "Microsoft Defender — Devices",
            "event_type": "device",
            "raw_log": f"Device ID: {row.get('device_id', '')} · OS: {row.get('os_platform', '')} · "
                       f"Related alerts: {row.get('related_alerts', '')}",
            "criticality": _RISK_TO_CRITICALITY.get(risk.lower(), "medium"),
            "low_confidence": False,
        })
    return candidates


# ─── Alerts table → Timeline event candidates ───────────────────────────────

_ALERT_LABELS = ["alert_name", "severity", "status", "detection_source",
                  "impacted_assets", "first_activity", "last_activity"]


def _extract_alerts(pages, texts, tz_offset: int) -> list[dict]:
    page, text = _find_page(pages, texts, contains="All alerts")
    if page is None:
        return []
    words = page.extract_words(use_text_flow=False, keep_blank_chars=False)
    header = _header_row_by_marker(words, "Severity")
    columns = _columns_from_header(header, _ALERT_LABELS)
    if not columns:
        return []
    rows = _table_rows(words, columns, "severity", header[0]["top"])

    candidates = []
    for row in rows:
        name = row.get("alert_name", "").strip()
        if not name:
            continue
        event_time = _parse_defender_dt(row.get("first_activity", ""), tz_offset)
        candidates.append({
            "kind": "alert",
            "suggested_destination": "timeline_event",
            "ioc_type": None,
            "entity_type_hint": None,
            "value": name,
            "description": f"Alert: {name} — {row.get('severity', '')} severity, "
                            f"{row.get('status', '')} (detected via {row.get('detection_source', 'unknown')})",
            "verdict": None,
            "event_time": event_time.isoformat() if event_time else None,
            "hostname": row.get("impacted_assets") or None,
            "source": "Microsoft Defender — Alert",
            "event_type": "alert",
            "raw_log": None,
            "low_confidence": event_time is None,
        })
    return candidates


# ─── Activity log → Timeline event candidates ───────────────────────────────

def _extract_activity_log(full_text: str, tz_offset: int) -> list[dict]:
    m = re.search(r'\nActivity log\n(?:\d+ related activities\n)?(.*)\Z', full_text, re.S)
    if not m:
        return []
    blocks = [b.strip() for b in _PUA_ICON_RE.split(m.group(1)) if b.strip()]

    candidates = []
    for block in blocks:
        lines = [l for l in block.splitlines() if l.strip()]
        if len(lines) < 2:
            continue
        actor, ts_line = lines[0], lines[-1].strip()
        if not _ACTIVITY_TS_RE.match(ts_line):
            continue
        event_time = _parse_defender_dt(ts_line, tz_offset)
        description = " ".join(lines[1:-1]).strip()
        if not description:
            continue
        candidates.append({
            "kind": "activity",
            "suggested_destination": "timeline_event",
            "ioc_type": None,
            "entity_type_hint": None,
            "value": description,
            "description": f"{actor}: {description}",
            "verdict": None,
            "event_time": event_time.isoformat() if event_time else None,
            "hostname": None,
            "source": "Microsoft Defender — Activity log",
            "event_type": "activity_log",
            "raw_log": block[:2000],
            "low_confidence": event_time is None,
        })
    return candidates
