"""Ledger — the forensic table. One row per event in time order, grouped by day: time, time since the previous
row, host / entity, event, ATT&CK, 800-61 phase, provenance (origin, source, exhibit, parser, time basis,
the device-recorded time and clock offset) and flags. The header block states what was exported and the
SHA-256 of the CSV export with the same options, so the rows can be checked against that file."""
from .common import (EMPTY, ENTITY_TYPE, ORIGIN, PHASES, Ctx, at, attack_label, day, delta, dur, esc, has_attack,
                     iso_z, legend, mal_iocs, offset_s, page, sev_style, tactic_color, utc_offset)

CSS = """
.lm{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:1px;background:var(--border);border:1px solid var(--border);
 border-radius:var(--radius);overflow:hidden;margin-bottom:var(--space-5)}
.lm div{background:var(--surface);padding:8px 10px;min-width:0}
.lm dt{font-family:var(--font-mono);font-size:9.5px;letter-spacing:.12em;text-transform:uppercase;color:var(--dim)}
.lm dd{font-size:12px;color:var(--text);word-break:break-all}
.lm .wide{grid-column:span 2}
.tbl{width:100%;border-collapse:collapse;font-size:11px;line-height:1.4}
.tbl th{position:sticky;top:0;background:var(--surface-2);text-align:left;font-family:var(--font-mono);font-size:9.5px;
 letter-spacing:.1em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border-strong);padding:6px 8px}
.tbl td{border-bottom:1px solid var(--border);padding:6px 8px;vertical-align:top;color:var(--text)}
.tbl td.n,.tbl td.t,.tbl td.dl{font-family:var(--font-mono);white-space:nowrap}
.tbl td.n,.tbl td.dl{color:var(--dim);text-align:right}
.tbl tr.dg td{background:var(--surface);font-family:var(--font-mono);font-size:10.5px;font-weight:700;letter-spacing:.08em;
 color:var(--text);border-bottom:1px solid var(--border-strong);padding-top:10px}
.tbl tr.dg td span{color:var(--dim);font-weight:400;margin-left:8px}
.tbl tr.rw td{padding-top:0;border-bottom:1px solid var(--border)}
.tbl .ty{font-weight:700}
.tbl .sm{font-size:10px;color:var(--muted)}
.tbl .pv{font-family:var(--font-mono);font-size:10px;color:var(--muted)}
.tbl .fls{display:flex;flex-direction:column;gap:3px;align-items:flex-start}
.tbl .att{white-space:normal}
.tbl tr.key td.n{color:var(--accent);font-weight:700}
@media print{.tbl th{position:static}.tbl tr{break-inside:avoid}}
"""


def _flags(ctx: Ctx, ev: dict) -> str:
    out = []
    if ev.get("key_event"):
        out.append('<span class="fl fl-key">KEY</span>')
    if mal_iocs(ev):
        vals = ", ".join(i.get("value") or "" for i in mal_iocs(ev))
        out.append(f'<span class="fl" style="{sev_style("critical")}" title="{esc(vals)}">MAL</span>')
    if ev["id"] in ctx.lolbin_ids:
        out.append('<span class="fl fl-lol">LOL</span>')
    if ev.get("clock_offset_seconds") is not None:
        out.append(f'<span class="fl fl-clk">CLK {esc(offset_s(ev["clock_offset_seconds"]))}</span>')
    return f'<div class="fls">{"".join(out)}</div>'


def _host(ev: dict) -> str:
    ent = ev.get("entity")
    h = ev.get("hostname") or ""
    out = esc(h) if h else ""
    if ent and ent.get("value"):
        typ = ENTITY_TYPE.get(ent.get("type"), ent.get("type"))
        label = f"linked {typ.lower()}" if ent["value"].lower() == h.lower() else f"{typ}: {ent['value']}"
        out += ("<br>" if out else "") + f'<span class="sm">→ {esc(label)}</span>'
    return out or '<span class="sm">—</span>'


def _prov(ctx: Ctx, ev: dict) -> str:
    lines = [ORIGIN.get(ev.get("origin"), ev.get("origin") or "")]
    if ev.get("source"):
        lines.append(ev["source"])
    if ev.get("evidence_identifier"):
        lines.append(f'exhibit {ev["evidence_identifier"]}')
    if ev.get("parser_name"):
        lines.append(" ".join(x for x in (ev["parser_name"], ev.get("parser_version")) if x))
    if ev.get("time_basis"):
        lines.append(f'time basis {ev["time_basis"]}')
    if ev.get("recorded_event_time"):
        lines.append(f'recorded {at(ctx, ev["recorded_event_time"]).strftime("%H:%M:%S")}'
                     + (f' ({offset_s(ev["clock_offset_seconds"])} corrected)'
                        if ev.get("clock_offset_seconds") is not None else ""))
    if ev.get("created_by_username"):
        lines.append(f'by {ev["created_by_username"]}')
    return "<br>".join(esc(x) for x in lines if x)


def _phase(ph) -> str:
    if ph not in PHASES:
        return ""
    _, short, glyph, var = PHASES[ph]
    return f'<span class="g" style="color:var({var})" aria-hidden="true">{glyph}</span> {esc(short)}'


def _time(ctx: Ctx, dt) -> str:
    loc = at(ctx, dt)
    s = loc.strftime("%H:%M:%S")
    if loc.microsecond:
        s += f".{loc.microsecond:06d}".rstrip("0")
    return s


def _meta(ctx: Ctx) -> str:
    evs = ctx.events
    n, k = len(evs), sum(1 for e in evs if e.get("key_event"))
    span = "—"
    if evs:
        a, b = evs[0]["event_time"], evs[-1]["event_time"]
        span = f"{iso_z(a)} → {iso_z(b)} ({dur((b - a).total_seconds())})"
    exhibits = sorted({e["evidence_identifier"] for e in evs if e.get("evidence_identifier")})
    origins = {}
    for e in evs:
        origins[e.get("origin")] = origins.get(e.get("origin"), 0) + 1
    origin_txt = " · ".join(f"{c} {ORIGIN.get(o, o).lower()}" for o, c in sorted(origins.items(), key=lambda x: -x[1]))
    cells = [
        ("Exported", iso_z(ctx.exported_at), ""), ("Exported by", ctx.exported_by or "—", ""),
        ("Time basis", f"{ctx.tz_name} (stored as UTC)", ""), ("Rows", f"{n} · {k} key", ""),
        ("Span", span, "wide"), ("Exhibits", ", ".join(exhibits) or "—", "wide"),
        ("Origin", origin_txt or "—", ""), ("Filters", " · ".join(ctx.filters) or "none", ""),
        ("Raw logs", "included" if ctx.include_raw_logs else "left out", ""),
        ("SHA-256 · CSV with the same options", ctx.csv_sha256 or "—", "wide"),
    ]
    return '<dl class="lm">' + "".join(
        f'<div class="{cls}"><dt>{esc(label)}</dt><dd class="{"mono" if "SHA" in label or label == "Span" else ""}">'
        f'{esc(val)}</dd></div>' for label, val, cls in cells) + "</dl>"


def render(ctx: Ctx) -> str:
    if not ctx.events:
        return page(ctx, "ledger", _meta(ctx) + EMPTY, CSS, 1280)
    rows, last_day, prev = [], None, None
    for i, ev in enumerate(ctx.events, 1):
        t = ev["event_time"]
        d = day(ctx, t)
        if d != last_day:
            rows.append(f'<tr class="dg"><td colspan="9">{esc(d)}<span>{esc(utc_offset(ctx, t))}</span></td></tr>')
            last_day = d
        dl = delta((t - prev).total_seconds()) if prev is not None else ""
        prev = t
        ph = ev.get("ir_phase")
        phase = _phase(ph)
        att = (f'<span class="att" style="--c:{tactic_color(ev)}">{esc(attack_label(ev))}</span>'
               if has_attack(ev) else "")
        event = (f'<div class="ty">{esc(ev.get("event_type") or "")}</div>' if ev.get("event_type") else "") + \
            f'<div>{esc(ev["description"])}</div>'
        cls = ' class="key"' if ev.get("key_event") else ""
        rows.append(f'<tr{cls}><td class="n">{i}</td><td class="t">{esc(_time(ctx, t))}</td><td class="dl">{esc(dl)}</td>'
                    f'<td>{_host(ev)}</td><td>{event}</td><td>{att}</td><td>{phase}</td>'
                    f'<td class="pv">{_prov(ctx, ev)}</td><td>{_flags(ctx, ev)}</td></tr>')
        if ctx.include_raw_logs and ev.get("raw_log"):
            rows.append(f'<tr class="rw"><td></td><td colspan="8"><pre class="raw">{esc(ev["raw_log"])}</pre></td></tr>')
    head = (f'<th>#</th><th>Time ({esc(ctx.tz_name)})</th><th>Δ prev</th><th>Host / entity</th><th>Event</th>'
            '<th>ATT&amp;CK</th><th>Phase</th><th>Provenance</th><th>Flags</th>')
    table = f'<table class="tbl"><thead><tr>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table>'
    key = legend([
        ('<span class="fl fl-key">KEY</span>', "key event (flagged, ATT&CK-tagged or recorded by FENRIR)"),
        (f'<span class="fl" style="{sev_style("critical")}">MAL</span>', "linked to a malicious IOC"),
        ('<span class="fl fl-lol">LOL</span>', "names a LOLBAS / GTFOBins binary"),
        ('<span class="fl fl-clk">CLK</span>', "time corrected for the exhibit's clock offset"),
        ("", "◉ Detect = Detection & Analysis · ⊘ C/E/R = Containment, Eradication & Recovery"),
    ])
    return page(ctx, "ledger", _meta(ctx) + table + key, CSS, 1280)
