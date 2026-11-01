"""Zig-zag — the original HTML export (frontend Timeline.jsx exportHtml until TX), kept as the sixth layout
(owner decision 2, 2026-10-31). Same markup and CSS; what changed: the times are in the export's time zone
(the browser's local time before), raw logs appear only with include_raw_logs, and the page carries the
same no-script CSP as the other layouts."""
from datetime import timedelta

from .common import Ctx, at, esc

IR_PHASE_LABELS = {
    "preparation": "Preparation",
    "detection_and_analysis": "Detection & Analysis",
    "containment_eradication_recovery": "Containment / Eradication / Recovery",
    "post_incident": "Post-Incident",
}

TACTIC_HEX = {
    "TA0043": "#10b981", "TA0042": "#a78bfa",
    "TA0001": "#f43f5e", "TA0002": "#f59e0b", "TA0003": "#a78bfa",
    "TA0004": "#f59e0b", "TA0005": "#22d3ee", "TA0006": "#f43f5e",
    "TA0007": "#10b981", "TA0008": "#f59e0b", "TA0009": "#a78bfa",
    "TA0010": "#f59e0b", "TA0011": "#22d3ee", "TA0040": "#f43f5e",
}

SEV_HEX = {
    "critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04",
    "low": "#2563eb", "informational": "#6b7280",
}

CSS = """*{box-sizing:border-box;margin:0;padding:0}
body{background:#07080b;color:#d9dde5;font-family:-apple-system,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;font-size:13px;line-height:1.6}
.mono{font-family:'JetBrains Mono','Fira Mono',Consolas,monospace}

.header{background:linear-gradient(135deg,#07070f,#140008);padding:32px 48px;border-bottom:3px solid %(sev)s}
.header-eyebrow{font-family:'JetBrains Mono','Fira Mono',Consolas,monospace;font-size:11px;color:#555570;letter-spacing:3px;margin-bottom:8px}
.header-title{font-size:24px;font-weight:700;color:#fff;margin-bottom:6px}
.header-badges{display:flex;gap:8px;margin-top:12px;flex-wrap:wrap}
.header-badge{padding:4px 12px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
.badge-sev{background:%(sev)s;color:#fff}
.badge-tlp{border:2px solid #dc2626;color:#dc2626}
.badge-count{background:#0e1015;border:1px solid #1f242d;color:#8888aa}
.header-meta{margin-top:14px;font-family:'JetBrains Mono','Fira Mono',Consolas,monospace;font-size:11px;color:#555570}

.timeline-container{max-width:1100px;margin:0 auto;padding:40px 24px;position:relative}
.timeline-container::before{content:'';position:absolute;left:50%%;top:0;bottom:0;width:2px;background:#1f242d;transform:translateX(-50%%)}

.date-divider{text-align:center;position:relative;margin:28px 0 16px;z-index:2}
.date-divider span{display:inline-block;background:#07080b;border:1px solid #1f242d;padding:4px 14px;border-radius:20px;font-family:'JetBrains Mono','Fira Mono',Consolas,monospace;font-size:11px;color:#8888aa;letter-spacing:.08em}

.event-item{display:flex;width:50%%;position:relative;margin-bottom:18px}
.event-item.left{padding-right:32px;justify-content:flex-end}
.event-item.right{padding-left:32px;margin-left:50%%}
.event-dot{position:absolute;width:12px;height:12px;border-radius:50%%;top:18px;z-index:3;border:2px solid #07080b}
.event-item.left .event-dot{right:-7px}
.event-item.right .event-dot{left:-7px}

.event-card{background:#0e1015;border:1px solid #1f242d;border-radius:6px;padding:12px 14px;width:100%%;max-width:460px}
.event-header{display:flex;flex-wrap:wrap;gap:6px 8px;align-items:center;margin-bottom:8px;row-gap:6px}
.event-time{font-family:'JetBrains Mono','Fira Mono',Consolas,monospace;font-size:11px;font-weight:600;color:#a8b0c0;flex-shrink:0}
.pill{font-size:10px;font-weight:700;padding:2px 8px;border-radius:3px;letter-spacing:.04em;white-space:nowrap;border:1px solid transparent}
.pill-muted{background:#1f242d33;color:#8888aa;border-color:#1f242d}
.event-host{font-family:'JetBrains Mono','Fira Mono',Consolas,monospace;font-size:10px;color:#555570;margin-left:auto;flex-shrink:0}
.event-desc{font-size:13px;color:#d9dde5;line-height:1.5;margin-bottom:6px;word-break:break-word}
.mitre-badge{display:inline-block;font-family:'JetBrains Mono','Fira Mono',Consolas,monospace;font-size:10px;font-weight:600;padding:2px 8px;border-radius:3px;border:1px solid;margin-top:4px}
.event-meta{font-size:10px;color:#8888aa;margin-top:6px}
.event-raw-wrap{margin-top:8px}
.event-raw-wrap summary{cursor:pointer;font-family:'JetBrains Mono','Fira Mono',Consolas,monospace;font-size:11px;color:#555570;list-style:'▶ '}
.event-raw-wrap[open] summary{list-style:'▼ ';color:#8888aa}
.event-raw{font-family:'JetBrains Mono','Fira Mono',Consolas,monospace;font-size:10px;color:#8888aa;background:#050508;padding:8px;border-radius:4px;margin-top:4px;white-space:pre-wrap;word-break:break-all;max-height:240px;overflow:auto;border:1px solid #1f242d}

.footer{padding:20px 48px;border-top:1px solid #1f242d;font-family:'JetBrains Mono','Fira Mono',Consolas,monospace;font-size:10px;color:#555570;display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}

@media (max-width:768px){
  .timeline-container::before{left:20px}
  .event-item,.event-item.right{width:100%%;margin-left:0;padding-left:40px;padding-right:0;justify-content:flex-start}
  .event-item.left .event-dot,.event-item.right .event-dot{left:13px;right:auto}
  .event-card{max-width:100%%}
}
@media print{
  body{background:#fff;color:#111}
  .header{background:#f5f5f5;color:#111}
  .header-title{color:#000}
  .timeline-container::before{background:#bbb}
  .date-divider span{background:#fff;border-color:#ccc;color:#555}
  .event-card{background:#fff;border-color:#ccc;color:#111}
  .event-desc{color:#000}
  .event-dot{border-color:#fff}
  .event-raw-wrap[open] .event-raw{display:block !important}
  .footer{background:#f5f5f5;color:#555;border-top-color:#ccc}
}"""


def _stamp(ctx: Ctx, dt) -> str:
    loc = at(ctx, dt)
    mins = int((loc.utcoffset() or timedelta(0)).total_seconds() // 60)
    sign = "+" if mins >= 0 else "-"
    return loc.strftime("%Y-%m-%d %H:%M:%S") + f" {sign}{abs(mins) // 60:02d}:{abs(mins) % 60:02d}"


def render(ctx: Ctx) -> str:
    inc, events = ctx.inc, ctx.events
    sev_hex = SEV_HEX.get((inc.get("severity") or "").lower(), "#6b7280")
    rows, prev_date = [], None
    # Alternation runs across all events regardless of date dividers, so the rhythm stays stable.
    for i, ev in enumerate(events):
        loc = at(ctx, ev["event_time"])
        date_label, time_label = loc.strftime("%Y-%m-%d"), loc.strftime("%H:%M:%S")
        if date_label != prev_date:
            rows.append(f'<div class="date-divider"><span>{esc(date_label)}</span></div>')
            prev_date = date_label
        side = "left" if i % 2 == 0 else "right"
        color = TACTIC_HEX.get(ev.get("mitre_tactic_id") or "", "#6b7280")
        phase = IR_PHASE_LABELS.get(ev.get("ir_phase") or "", "")
        bits = [f'<span class="event-time">{esc(time_label)}</span>']
        if ev.get("event_type"):
            bits.append(f'<span class="pill" style="background:{color}22;color:{color};border-color:{color}55">'
                        f'{esc(ev["event_type"])}</span>')
        if phase:
            bits.append(f'<span class="pill pill-muted">{esc(phase)}</span>')
        if ev.get("hostname"):
            bits.append(f'<span class="event-host">{esc(ev["hostname"])}</span>')
        mitre = " ".join(x for x in (ev.get("mitre_technique_id"), ev.get("mitre_technique_name")) if x) \
            or ev.get("mitre_tactic_name")
        badge = (f'<div class="mitre-badge" style="color:{color};border-color:{color}66;background:{color}1a">'
                 f'{esc(mitre)}</div>') if mitre else ""
        meta = [f"source: {esc(ev['source'])}"] if ev.get("source") else []
        if ev.get("origin"):
            meta.append(f"origin: {esc(ev['origin'])}")
        meta_line = f'<div class="event-meta">{" · ".join(meta)}</div>' if meta else ""
        raw = (f'<details class="event-raw-wrap"><summary>Raw log</summary><pre class="event-raw">'
               f'{esc(ev["raw_log"])}</pre></details>') if ctx.include_raw_logs and ev.get("raw_log") else ""
        rows.append(f"""
      <div class="event-item {side}">
        <div class="event-dot" style="background:{color};box-shadow:0 0 8px {color}66"></div>
        <div class="event-card" style="border-left:3px solid {color}">
          <div class="event-header">{"".join(bits)}</div>
          <div class="event-desc">{esc(ev["description"])}</div>
          {badge}
          {meta_line}
          {raw}
        </div>
      </div>""")
    generated = _stamp(ctx, ctx.exported_at)
    ref, title, tlp = inc.get("ref") or "", inc.get("title") or "", (inc.get("tlp") or "")
    n = len(events)
    empty = ('<div style="text-align:center;color:#555570;padding:60px;font-family:\'JetBrains Mono\',monospace;'
             'font-size:12px">No timeline events recorded.</div>')
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer">
<title>Timeline · {esc(ref)} {esc(title)}</title>
<style>
{CSS % {"sev": sev_hex}}
</style>
</head>
<body>

<div class="header">
  <div class="header-eyebrow">DFIR-FENRIR // INCIDENT TIMELINE</div>
  <div class="header-title">{esc(title)}</div>
  <div class="header-badges">
    {f'<span class="header-badge badge-count">{esc(ref)}</span>' if ref else ''}
    {f'<span class="header-badge badge-sev">{esc(str(inc.get("severity")).upper())}</span>' if inc.get("severity") else ''}
    {f'<span class="header-badge badge-tlp">TLP:{esc(tlp.upper())}</span>' if tlp else ''}
    <span class="header-badge badge-count">{n} event{"" if n == 1 else "s"}</span>
  </div>
  <div class="header-meta">Exported {esc(generated)} · times in {esc(ctx.tz_name)}</div>
</div>

<div class="timeline-container">
  {chr(10).join(rows) if events else empty}
</div>

<div class="footer">
  <span>DFIR-FENRIR v2 — {esc(title)}</span>
  {f'<span>TLP:{esc(tlp.upper())} — Handle accordingly</span>' if tlp else ''}
  <span>Generated {esc(generated)}</span>
</div>

</body>
</html>
"""
