"""Timeline export (TX): six HTML layouts and the flat CSV, rendered from the same events the timeline list
returns (GET /api/incidents/{id}/timeline/export). Pure and synchronous — the route loads and filters the
events, then calls these in a worker thread. Design: docs/timeline-export-layouts-slice.md."""
import csv
import io

from core.csv_safe import csv_safe

from . import brief, horizon, ledger, rail, swimlanes, zigzag
from .common import LAYOUTS, RAW_LAYOUTS, Ctx

__all__ = ["CSV_COLUMNS", "LAYOUTS", "RAW_LAYOUTS", "Ctx", "render_csv", "render_html"]

_RENDER = {"rail": rail.render, "horizon": horizon.render, "swimlanes": swimlanes.render,
           "ledger": ledger.render, "brief": brief.render, "zigzag": zigzag.render}

# The original 12 columns, then provenance and clock offset (G4) — readers by position keep working.
CSV_COLUMNS = ("event_time", "description", "event_type", "ir_phase",
               "mitre_tactic_id", "mitre_tactic_name", "mitre_technique_id",
               "mitre_technique_name", "hostname", "source", "origin", "raw_log",
               "evidence_identifier", "parser_name", "parser_version", "time_basis",
               "recorded_event_time", "clock_offset_seconds")


def render_html(layout: str, ctx: Ctx) -> str:
    return _RENDER[layout](ctx)


def render_csv(rows: list, include_raw_logs: bool) -> str:
    """rows: TimelineEventOut.model_dump(mode="json") dicts (the API's own values). CRLF, formula-escaped
    cells (R129). Without include_raw_logs the raw_log column stays, empty."""
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\r\n")
    w.writerow(CSV_COLUMNS)
    for ev in rows:
        w.writerow([csv_safe(ev.get(c)) if c != "raw_log" or include_raw_logs else None for c in CSV_COLUMNS])
    return out.getvalue()
