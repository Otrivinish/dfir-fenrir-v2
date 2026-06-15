"""ReportLab PDF renderer for signed audit-log exports.

Two-part document:

    1. Cover page — provenance + chain anchors + signature recipe.
    2. Body — paginated tabular slice; hashes in mono, truncated to 12 chars.

Columns kept narrow so the table fits letter-portrait. Full hashes and full
`details` JSON live in audit.jsonl alongside this PDF.
"""
from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from models import AuditLog, Incident


# Mission Control palette — kept in sync with the SPA tokens. Mono for hashes.
_BG_HEADER   = colors.HexColor("#0E1B2C")
_BG_ROW_ALT  = colors.HexColor("#F5F7FA")
_BORDER      = colors.HexColor("#3E5469")
_BANNER_TLP  = {
    "white":  colors.HexColor("#FFFFFF"),
    "clear":  colors.HexColor("#FFFFFF"),
    "green":  colors.HexColor("#3FB950"),
    "amber":  colors.HexColor("#D29922"),
    "amber+strict": colors.HexColor("#D29922"),
    "red":    colors.HexColor("#F85149"),
}
_BANNER_FG_FOR = {
    "white": colors.black,
    "clear": colors.black,
    "green": colors.black,
    "amber": colors.black,
    "amber+strict": colors.black,
    "red":   colors.white,
}


def _h12(h: str | None) -> str:
    return (h[:12] + "…") if h and len(h) > 12 else (h or "")


def _utc_fmt(ts: datetime | None) -> str:
    if ts is None:
        return ""
    # ISO 8601 with seconds + Z. The verifier parses the JSONL — this is
    # purely the human-readable surface.
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _classification_text(manifest: dict[str, Any], incident: Incident | None) -> tuple[str, str]:
    """Return (label, tlp_key_for_color). Falls back to TLP:AMBER for safety."""
    if incident is not None:
        tlp = (incident.tlp or "amber").lower()
        return (f"TLP:{tlp.upper()} — INCIDENT {incident.ref or incident.id}", tlp)
    return ("TLP:AMBER — GLOBAL AUDIT EXPORT (HANDLE PER ORG POLICY)", "amber")


def _make_banner_drawer(label: str, tlp_key: str):
    bg = _BANNER_TLP.get(tlp_key, _BANNER_TLP["amber"])
    fg = _BANNER_FG_FOR.get(tlp_key, colors.black)

    def draw(canvas, doc):
        canvas.saveState()
        width, height = doc.pagesize
        # Top banner
        canvas.setFillColor(bg)
        canvas.rect(0, height - 0.35 * inch, width, 0.35 * inch, fill=1, stroke=0)
        canvas.setFillColor(fg)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawCentredString(width / 2, height - 0.23 * inch, label)
        # Bottom banner
        canvas.setFillColor(bg)
        canvas.rect(0, 0, width, 0.32 * inch, fill=1, stroke=0)
        canvas.setFillColor(fg)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawCentredString(width / 2, 0.10 * inch, label)
        # Page number, top-right of footer band
        canvas.setFont("Helvetica", 7)
        canvas.drawRightString(width - 0.4 * inch, 0.10 * inch, f"page {doc.page}")
        canvas.restoreState()

    return draw


# ── Cover page ───────────────────────────────────────────────────────────────

def _cover_flowables(manifest: dict[str, Any]) -> list[Any]:
    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        name="title",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=16,
        leading=20,
        spaceAfter=4,
    )
    sub = ParagraphStyle(
        name="sub",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        textColor=colors.HexColor("#3E5469"),
        spaceAfter=8,
    )
    h2 = ParagraphStyle(
        name="h2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        spaceBefore=10,
        spaceAfter=4,
    )
    body = ParagraphStyle(
        name="body",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
    )
    mono = ParagraphStyle(
        name="mono",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=8,
        leading=10,
    )

    export = manifest["export"]
    chain  = manifest["chain"]
    sign   = manifest["signing"]
    filt   = manifest.get("filters") or {}
    inc    = manifest.get("incident")

    flow: list[Any] = []
    flow.append(Paragraph("Signed Audit Log Export", title))
    flow.append(Paragraph(
        f"DFIR-FENRIR v2 — chain-anchored, Ed25519-signed extract", sub,
    ))

    # Provenance block
    provenance = [
        ["Export ID",     export["id"]],
        ["Generated at",  export["created_at"]],
        ["Generated by",  f'{export["created_by"]} ({export["created_by_id"]})'],
        ["Scope",         export["scope"]],
        ["Purpose",       export.get("purpose") or "—"],
    ]
    if inc:
        provenance.append(["Incident", f'{inc.get("ref") or "—"} — {inc.get("title") or ""}'])
        provenance.append(["TLP",      (inc.get("tlp") or "").upper()])

    flow.append(Paragraph("Provenance", h2))
    flow.append(_two_col_table(provenance))

    # Filter block — only show fields that are actually set. If nothing is
    # set the slice is the full chain over the retention window, which the
    # auditor needs to see stated explicitly.
    filter_rows = [
        (label, filt.get(key))
        for label, key in (
            ("date_from",     "date_from"),
            ("date_to",       "date_to"),
            ("action like",   "action"),
            ("username",      "username"),
            ("resource_type", "resource_type"),
            ("outcome",       "outcome"),
        )
        if filt.get(key)
    ]
    flow.append(Paragraph("Slice filters", h2))
    if filter_rows:
        flow.append(_two_col_table([[lbl, val] for lbl, val in filter_rows]))
    else:
        flow.append(Paragraph(
            "<i>No filters applied — full unfiltered slice of the audit chain.</i>",
            body,
        ))

    # Chain anchors
    flow.append(Paragraph("Chain anchors", h2))
    flow.append(_two_col_table([
        ["row_count",         str(manifest.get("row_count", 0))],
        ["first prev_hash",   chain.get("first_prev_hash")   or "—"],
        ["last row_hash",     chain.get("last_row_hash")     or "—"],
        ["chain head hash",   chain.get("chain_head_hash")   or "—"],
        ["chain head ts",     chain.get("chain_head_ts")     or "—"],
    ], mono_right=True))

    # Signature
    flow.append(Paragraph("Signature", h2))
    flow.append(_two_col_table([
        ["algorithm",       sign["algorithm"]],
        ["pubkey SHA-256",  sign["public_key_fpr"]],
        ["JSONL SHA-256",   sign["jsonl_sha256"]],
        ["signature file",  sign["signature_filename"]],
    ], mono_right=True))

    flow.append(Spacer(1, 0.10 * inch))
    flow.append(Paragraph(
        "Verify the SHA-256 of the encrypted bundle file you received against the "
        "value the sender published, then verify the Ed25519 signature in "
        "audit.jsonl.sig against public_key.pem (also exposed at GET /api/version). "
        "The README.txt inside this bundle has the canonical recipe.",
        body,
    ))
    flow.append(PageBreak())
    return flow


def _two_col_table(rows: list[list[str]], *, mono_right: bool = False) -> Table:
    t = Table(rows, colWidths=[1.4 * inch, 5.5 * inch])
    style = [
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
        ("FONT",       (0, 0), (0, -1), "Helvetica-Bold", 9),
        ("FONT",       (1, 0), (1, -1), "Courier" if mono_right else "Helvetica", 9),
        ("TEXTCOLOR",  (0, 0), (0, -1), _BG_HEADER),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, _BG_ROW_ALT]),
        ("BOX",        (0, 0), (-1, -1), 0.4, _BORDER),
        ("INNERGRID",  (0, 0), (-1, -1), 0.2, _BORDER),
    ]
    t.setStyle(TableStyle(style))
    return t


# ── Per-row blocks ───────────────────────────────────────────────────────────
# Replaces the narrow tabular body with one paragraph block per audit row so
# the actual `details` JSON and request context are visible — a regulator
# reading "who marked IOC X malicious" needs the substance, not just the
# action label.

_OUTCOME_COLOR = {
    "success": "#15803d",
    "failure": "#b91c1c",
    "denied":  "#b45309",
}


def _pesc(s: Any) -> str:
    """Escape for ReportLab Paragraph (which parses a small HTML subset)."""
    if s is None:
        return ""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))


def _format_details(details: Any) -> str:
    """Pretty-print details JSON with sorted keys and 2-space indent."""
    import json as _j
    if not details:
        return ""
    try:
        return _j.dumps(details, indent=2, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(details)


def _row_block(idx: int, row: AuditLog) -> KeepTogether:
    # Styles per-call so font config stays local + readable.
    header_style = ParagraphStyle(
        "rowhdr", fontName="Helvetica-Bold", fontSize=10, leading=13,
        textColor=_BG_HEADER, spaceAfter=2,
    )
    meta_style = ParagraphStyle(
        "rowmeta", fontName="Helvetica", fontSize=8.5, leading=11,
        textColor=colors.HexColor("#22303f"), spaceAfter=1,
    )
    hash_style = ParagraphStyle(
        "rowhash", fontName="Courier", fontSize=7, leading=9,
        textColor=colors.HexColor("#3E5469"), spaceBefore=2,
    )
    details_style = ParagraphStyle(
        "rowdet", fontName="Courier", fontSize=7.5, leading=9.5,
        leftIndent=10, textColor=colors.HexColor("#0E1B2C"),
    )

    parts: list[Any] = []

    outcome_color = _OUTCOME_COLOR.get((row.outcome or "").lower(), "#3E5469")
    parts.append(Paragraph(
        f"#{idx:03d} &middot; {_pesc(_utc_fmt(row.timestamp))} &middot; "
        f"<b>{_pesc(row.action or '—')}</b> &middot; "
        f"<font color=\"{outcome_color}\">{_pesc(row.outcome or '—')}</font>",
        header_style,
    ))

    user_cell = row.username or "—"
    if row.role_at_time:
        user_cell = f"{user_cell} ({row.role_at_time})"
    parts.append(Paragraph(f"<b>User</b> &nbsp; {_pesc(user_cell)}", meta_style))

    target = ""
    if row.resource_type:
        target = row.resource_type
        if row.resource_label:
            target = f"{row.resource_type}: {row.resource_label}"
        elif row.resource_id:
            target = f"{row.resource_type}: {row.resource_id}"
    if target:
        parts.append(Paragraph(f"<b>Target</b> &nbsp; {_pesc(target)}", meta_style))

    method_path = " ".join(filter(None, [row.request_method, row.request_path or ""]))
    if method_path:
        parts.append(Paragraph(
            f"<b>Request</b> &nbsp; <font face=\"Courier\">{_pesc(method_path)}</font>",
            meta_style,
        ))

    extras = []
    if row.ip_address:
        extras.append(f"<b>IP</b> {_pesc(row.ip_address)}")
    if row.request_id:
        extras.append(f"<b>req_id</b> <font face=\"Courier\">{_pesc(row.request_id)}</font>")
    if row.session_id:
        extras.append(f"<b>session</b> <font face=\"Courier\">{_pesc(str(row.session_id)[:8])}…</font>")
    if extras:
        parts.append(Paragraph(" &nbsp;·&nbsp; ".join(extras), meta_style))

    det = _format_details(row.details)
    if det:
        parts.append(Paragraph("<b>Details</b>", meta_style))
        parts.append(Preformatted(det, details_style))

    parts.append(Paragraph(
        f"prev={_pesc(_h12(row.prev_hash) or '—')} &nbsp;|&nbsp; "
        f"row={_pesc(_h12(row.row_hash) or '—')} &nbsp; "
        f"<i>(full hashes in audit.jsonl)</i>",
        hash_style,
    ))
    parts.append(Spacer(1, 8))

    # KeepTogether tries to keep the whole entry on one page; falls back to a
    # natural break only if a single block exceeds page height.
    return KeepTogether(parts)


def _section_separator() -> Table:
    """Thin horizontal rule between entries."""
    sep = Table([[" "]], colWidths=[7.0 * inch], rowHeights=[0.5])
    sep.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, _BORDER),
    ]))
    return sep


# ── Public entry ─────────────────────────────────────────────────────────────

def render_pdf(
    *,
    rows:     list[AuditLog],
    manifest: dict[str, Any],
    incident: Incident | None,
) -> bytes:
    """Render the full PDF and return its bytes."""
    label, tlp_key = _classification_text(manifest, incident)
    banner = _make_banner_drawer(label, tlp_key)

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=LETTER,
        leftMargin=0.5 * inch,
        rightMargin=0.5 * inch,
        topMargin=0.55 * inch,
        bottomMargin=0.5 * inch,
        title=f"DFIR-FENRIR Audit Export {manifest['export']['id']}",
        author="DFIR-FENRIR v2",
    )

    story: list[Any] = []
    story.extend(_cover_flowables(manifest))

    if rows:
        styles = getSampleStyleSheet()
        h2 = ParagraphStyle(
            name="bodyh2", parent=styles["Heading2"],
            fontName="Helvetica-Bold", fontSize=12, leading=15,
            textColor=_BG_HEADER, spaceAfter=8,
        )
        story.append(Paragraph(
            f"Audit Entries — {len(rows)} row(s)",
            h2,
        ))
        for i, r in enumerate(rows, start=1):
            story.append(_row_block(i, r))
            if i < len(rows):
                story.append(_section_separator())
                story.append(Spacer(1, 4))
    else:
        styles = getSampleStyleSheet()
        story.append(KeepTogether([
            Paragraph("No audit rows matched the filter.", styles["Normal"]),
        ]))

    doc.build(story, onFirstPage=banner, onLaterPages=banner)
    return buf.getvalue()
