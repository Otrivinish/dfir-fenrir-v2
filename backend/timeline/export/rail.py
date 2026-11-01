"""Rail — vertical, one-sided spine. Day rows, a row where the 800-61 phase changes, the incident milestones
inline (◆), the quiet time between rows over 10 minutes, and every event as a card with its flags,
provenance and (include_raw_logs) its raw log."""
from datetime import timedelta

from .common import (EMPTY, PHASES, Ctx, attack_chip, day, dur, esc, flags, has_attack, hms, host, legend,
                     milestone_strip, milestones, page, phase_label, provenance, tactic_color, utc_offset)

GAP_LABEL = timedelta(minutes=10)

CSS = """
.rl{position:relative}
.rl::before{content:'';position:absolute;left:105px;top:0;bottom:0;width:2px;background:var(--border)}
.rl-row{display:grid;grid-template-columns:86px 40px minmax(0,1fr);align-items:start;margin-bottom:var(--space-3)}
.rl-t{font-size:11px;font-weight:600;color:var(--muted);text-align:right;padding-top:9px}
.rl-m{display:flex;justify-content:center;padding-top:11px;position:relative;z-index:1}
.mk{display:inline-block;width:12px;height:12px;border-radius:50%}
.mk.dot{border:2px solid var(--bg)}
.mk.ring{border:2px solid var(--border-strong);background:var(--bg)}
.mk.sq{border-radius:var(--radius-sm);background:var(--muted);border:2px solid var(--bg)}
.mk.dm{width:11px;height:11px;border-radius:0;transform:rotate(45deg);background:var(--text);border:2px solid var(--bg)}
.rl-day{display:flex;gap:var(--space-3);align-items:baseline;margin:var(--space-5) 0 var(--space-3) 124px;
 font-family:var(--font-mono);font-size:12px;font-weight:700;letter-spacing:.08em;color:var(--text)}
.rl-off{font-size:10px;color:var(--dim);font-weight:400}
.rl-phase{margin:var(--space-4) 0 var(--space-3) 124px;font-family:var(--font-mono);font-size:10px;letter-spacing:.14em;
 text-transform:uppercase;color:var(--muted)}
.rl-gap{margin:0 0 var(--space-3) 124px;font-family:var(--font-mono);font-size:10px;color:var(--dim)}
.rl-gap span::before{content:'··· '}
.rl-gap span::after{content:' quiet ···'}
.rl-ms .rl-t{color:var(--text)}
.rl-msl{padding-top:7px;font-family:var(--font-mono);font-size:11px;font-weight:700;letter-spacing:.14em;color:var(--text)}
.card{background:var(--surface);border:1px solid var(--border);border-left:3px solid;border-radius:var(--radius);
 padding:10px 12px}
.c-top{display:flex;flex-wrap:wrap;align-items:center;gap:4px 8px;margin-bottom:4px}
.c-type{font-size:11px;font-weight:700;color:var(--text)}
.c-host{font-size:10px;color:var(--muted)}
.c-fl{display:flex;flex-wrap:wrap;gap:4px;margin-left:auto}
.c-desc{font-size:13px;color:var(--text);word-break:break-word}
.c-tags{margin-top:6px}
.c-prov{margin-top:6px;font-size:10px;color:var(--dim)}
"""


def _marker(ev: dict) -> str:
    if ev.get("server_generated"):
        return '<span class="mk sq" aria-hidden="true"></span>'
    if has_attack(ev):
        return f'<span class="mk dot" style="background:{tactic_color(ev)}" aria-hidden="true"></span>'
    return '<span class="mk ring" aria-hidden="true"></span>'


def _event(ctx: Ctx, ev: dict) -> str:
    top = []
    if ev.get("event_type"):
        top.append(f'<span class="c-type">{esc(ev["event_type"])}</span>')
    if host(ev):
        top.append(f'<span class="c-host mono">{esc(host(ev))}</span>')
    chip = attack_chip(ev)
    tags = f'<div class="c-tags">{chip}</div>' if chip else ""
    prov = provenance(ctx, ev)
    prov_html = f'<div class="c-prov mono">{esc(" · ".join(prov))}</div>' if prov else ""
    raw = (f'<pre class="raw">{esc(ev["raw_log"])}</pre>'
           if ctx.include_raw_logs and ev.get("raw_log") else "")
    return (f'<div class="rl-row"><div class="rl-t mono">{hms(ctx, ev["event_time"])}</div>'
            f'<div class="rl-m">{_marker(ev)}</div>'
            f'<div class="card" style="border-left-color:{tactic_color(ev)}">'
            f'<div class="c-top">{"".join(top)}<span class="c-fl">{flags(ctx, ev)}</span></div>'
            f'<div class="c-desc">{esc(ev["description"])}</div>{tags}{prov_html}{raw}</div></div>')


def render(ctx: Ctx) -> str:
    if not ctx.events:
        return page(ctx, "rail", milestone_strip(ctx) + EMPTY, CSS, 880)
    items = [(e["event_time"], 0, e) for e in ctx.events]
    items += [(t, 1, label) for _, label, t in milestones(ctx.inc)]
    items.sort(key=lambda x: (x[0], x[1]))
    rows, last_day, last_phase, prev_t = [], None, None, None
    for t, is_ms, obj in items:
        if prev_t is not None and t - prev_t > GAP_LABEL:
            rows.append(f'<div class="rl-gap"><span>{esc(dur((t - prev_t).total_seconds()))}</span></div>')
        prev_t = t
        d = day(ctx, t)
        if d != last_day:
            rows.append(f'<div class="rl-day"><span>{esc(d)}</span><span class="rl-off">{esc(utc_offset(ctx, t))}</span></div>')
            last_day = d
        if is_ms:
            rows.append(f'<div class="rl-row rl-ms"><div class="rl-t mono">{hms(ctx, t)}</div>'
                        f'<div class="rl-m"><span class="mk dm" aria-hidden="true"></span></div>'
                        f'<div class="rl-msl">{esc(obj.upper())}</div></div>')
            continue
        ph = obj.get("ir_phase")
        if ph in PHASES and ph != last_phase:
            rows.append(f'<div class="rl-phase">{phase_label(ph)}</div>')
            last_phase = ph
        rows.append(_event(ctx, obj))
    key = legend([
        ('<span class="mk dot" style="background:var(--crit)"></span>', "ATT&CK-tagged (tactic colour)"),
        ('<span class="mk ring"></span>', "no ATT&CK tag"),
        ('<span class="mk sq"></span>', "recorded by FENRIR"),
        ('<span class="mk dm"></span>', "incident milestone"),
        ("", "Quiet stretches over 10 min are labelled"),
    ])
    return page(ctx, "rail", milestone_strip(ctx) + f'<div class="rl">{"".join(rows)}</div>' + key, CSS, 880)
