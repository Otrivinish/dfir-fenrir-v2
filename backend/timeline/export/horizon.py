"""Horizon — horizontal and time-scaled (owner-approved rules, design 02 / 02b, 2026-10-31).

- One scale everywhere: 4 px per minute.
- Events less than 6 h apart form an active period (A, B, …). A longer quiet stretch folds into a fixed-width
  break labelled with its real length.
- Periods wrap onto new rows like text; a period longer than the rest of a row continues on the next.
- Events less than 10 min apart share one card (×N); every event still gets its own mark on the axis.
- The axis is coloured by incident phase: before detection, Detection & Analysis, then Containment,
  Eradication & Recovery (from the incident's detected / contained milestones).
- With more than one period, a true-scale overview (one column per day) sits on top, so the folding never
  hides the real dwell time; the dashed line is the C2 channel (first Command and Control event until
  containment).
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .common import (EMPTY, Ctx, at, attack_label, bursts, day_short, dur, esc, has_attack, hm, hms, host,
                     legend, mal_iocs, milestone_strip, milestones, page, periods, place_labels, tactic_color,
                     _PHRASE)

SCALE = 4 / 60            # px per second (4 px per minute)
ROW_W = 1360
BREAK_W = 72
MIN_PERIOD_W = 160
PAD = 10 * 60             # seconds of axis kept either side of a period's first and last event
MIN_SEG = 200             # wrap instead of starting a segment in less room than this
CARD_W, CARD_H = 172, 62
TRACK_H = CARD_H + 10
GAP_X = 8
HEAD = 24                 # period-label band at the top of a row
BAND = 18                 # tick band below the axis
UP_BAND = 32              # milestone labels above the axis, two levels
TICK = timedelta(minutes=15)

CSS = """
.hz-row{position:relative;width:1360px;margin-bottom:var(--space-4)}
.hz-ax{position:absolute;height:3px;border-radius:2px}
.hz-ph{position:absolute;top:0;height:20px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;
 font-family:var(--font-mono);font-size:10.5px;font-weight:700;letter-spacing:.06em;color:var(--text)}
.hz-ph b{display:inline-block;min-width:18px;padding:0 5px;margin-right:6px;border-radius:var(--radius-sm);
 background:var(--surface-2);border:1px solid var(--border-strong);text-align:center}
.hz-cont{position:absolute;font-family:var(--font-mono);font-size:10px;color:var(--dim);white-space:nowrap}
.hz-tk{position:absolute;width:1px;background:var(--border-strong)}
.hz-tl{position:absolute;font-family:var(--font-mono);font-size:9.5px;color:var(--dim);white-space:nowrap}
.hz-ev{position:absolute;width:9px;height:9px;margin:-3px 0 0 -4.5px;border-radius:50%}
.hz-ev.ring{border:2px solid var(--border-strong);background:var(--bg)}
.hz-ev.sq{border-radius:var(--radius-sm);background:var(--muted)}
.hz-ld{position:absolute;width:1px;background:var(--border-strong)}
.hz-ms{position:absolute;width:10px;height:10px;margin:-3.5px 0 0 -5px;transform:rotate(45deg);background:var(--text);
 border:2px solid var(--bg)}
.hz-msl{position:absolute;font-family:var(--font-mono);font-size:9.5px;font-weight:700;letter-spacing:.08em;
 color:var(--text);white-space:nowrap}
.hz-brk{position:absolute;width:72px;text-align:center;font-family:var(--font-mono);font-size:10px;line-height:1.3;
 color:var(--dim)}
.hz-brk .z{display:block;font-size:18px;line-height:1;color:var(--border-strong);letter-spacing:-2px}
.hc{position:absolute;width:172px;height:62px;overflow:hidden;background:var(--surface);border:1px solid var(--border);
 border-top:3px solid;border-radius:var(--radius);padding:4px 7px;font-size:11px;line-height:14px}
.hc-t{display:flex;gap:6px;font-size:10.5px;font-weight:700;color:var(--text);white-space:nowrap}
.hc-t .n{color:var(--accent)}
.hc-t .f{margin-left:auto;letter-spacing:2px}
.hc-h,.hc-d{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hc-h{font-size:10px;color:var(--muted)}
.hc-d{color:var(--text)}
.hc-d2{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;white-space:normal}
.ov{position:relative;width:1360px;height:160px;margin-bottom:var(--space-3);border:1px solid var(--border);
 border-radius:var(--radius);background:var(--surface);overflow:hidden}
.ov-d{position:absolute;top:0;bottom:0;border-left:1px solid var(--border)}
.ov-d.we{background:var(--surface-2)}
.ov-dl{position:absolute;top:4px;left:4px;font-family:var(--font-mono);font-size:9.5px;color:var(--dim);white-space:nowrap}
.ov-bar{position:absolute;top:46px;height:12px;border-radius:2px}
.ov-bl{position:absolute;top:30px;font-family:var(--font-mono);font-size:10px;font-weight:700;color:var(--text)}
.ov-c2{position:absolute;top:63px;height:0;border-top:2px dashed var(--accent)}
.ov-c2l{position:absolute;top:66px;font-family:var(--font-mono);font-size:9.5px;color:var(--accent);white-space:nowrap}
.ov-ms{position:absolute;top:47px;width:9px;height:9px;margin-left:-4.5px;transform:rotate(45deg);background:var(--text);
 border:2px solid var(--surface)}
.ov-br{position:absolute;height:8px;border:1px solid var(--muted);border-top:0}
.ov-brl{position:absolute;font-family:var(--font-mono);font-size:9.5px;color:var(--muted);white-space:nowrap}
.pt{width:100%;border-collapse:collapse;margin-bottom:var(--space-5);font-size:11px}
.pt th{text-align:left;font-family:var(--font-mono);font-size:9.5px;letter-spacing:.1em;text-transform:uppercase;
 color:var(--dim);border-bottom:1px solid var(--border-strong);padding:4px 8px}
.pt td{border-bottom:1px solid var(--border);padding:4px 8px;color:var(--text)}
.pt td.mono{font-size:10.5px}
"""


@dataclass
class _Seg:
    row: int
    x: float
    w: float
    t0: datetime
    t1: datetime
    pi: int
    cont_prev: bool
    cont_next: bool


@dataclass
class _Brk:
    row: int
    x: float
    gap: float
    notes: list = field(default_factory=list)


def letter(i: int) -> str:
    s = ""
    i += 1
    while i:
        i, r = divmod(i - 1, 26)
        s = chr(65 + r) + s
    return s


def _layout(pers: list):
    segs, brks, row, x = [], [], 0, 0.0
    for pi, p in enumerate(pers):
        a, b = p[0]["event_time"], p[-1]["event_time"]
        span = (b - a).total_seconds() + 2 * PAD
        extra = max(0.0, MIN_PERIOD_W / SCALE - span) / 2
        t0, t1 = a - timedelta(seconds=PAD + extra), b + timedelta(seconds=PAD + extra)
        width = (t1 - t0).total_seconds() * SCALE
        first_w = width if width <= ROW_W - BREAK_W else MIN_SEG   # whole, unless longer than a row
        lead = BREAK_W if pi else 0
        if x and x + lead + first_w > ROW_W:
            row, x = row + 1, 0.0
        if pi:
            brks.append(_Brk(row, x, (a - pers[pi - 1][-1]["event_time"]).total_seconds()))
            x += BREAK_W
        t, first = t0, True
        while t < t1:
            if ROW_W - x < MIN_SEG:
                row, x = row + 1, 0.0
            need = (t1 - t).total_seconds() * SCALE
            w = min(need, ROW_W - x)
            end = t1 if w >= need else t + timedelta(seconds=w / SCALE)
            segs.append(_Seg(row, x, w, t, end, pi, not first, end < t1))
            first, x, t = False, x + w, end
            if t < t1:
                row, x = row + 1, 0.0
    return segs, brks, row + 1


def _pos(segs: list, t: datetime):
    """The segment holding t (segs = one period's segments, in order) and t's x on its row."""
    for s in segs:
        if t <= s.t1:
            return s, s.x + max(0.0, (t - s.t0).total_seconds()) * SCALE
    s = segs[-1]
    return s, s.x + s.w


def _place(items: list):
    """Greedy card tracks above (up) and below (dn) the axis, nearest track first, sides alternating."""
    tracks, placed, pref = {"up": [], "dn": []}, [], "up"
    for x, b in sorted(items, key=lambda it: it[0]):
        cx = min(max(x - 12, 0), ROW_W - CARD_W)
        other = "dn" if pref == "up" else "up"
        spot = None
        for i in range(max(len(tracks["up"]), len(tracks["dn"]))):
            for side in (pref, other):
                if i < len(tracks[side]) and cx >= tracks[side][i] + GAP_X:
                    spot = (side, i)
                    break
            if spot:
                break
        if not spot:
            side = pref if len(tracks[pref]) <= len(tracks[other]) else other
            tracks[side].append(float("-inf"))
            spot = (side, len(tracks[side]) - 1)
        tracks[spot[0]][spot[1]] = cx + CARD_W
        placed.append((spot[0], spot[1], cx, x, b))
        pref = "dn" if spot[0] == "up" else "up"
    return placed, len(tracks["up"]), len(tracks["dn"])


def _axis_colour(inc: dict, t: datetime) -> str:
    if inc.get("contained_at") and t >= inc["contained_at"]:
        return "--phase-respond"
    if inc.get("detected_at") and t >= inc["detected_at"]:
        return "--phase-detect"
    return "--border-strong"


def _mark(ev: dict, x: float, y: float) -> str:
    if ev.get("server_generated"):
        cls, style = "hz-ev sq", ""
    elif has_attack(ev):
        cls, style = "hz-ev", f"background:{tactic_color(ev)};"
    else:
        cls, style = "hz-ev ring", ""
    return f'<span class="{cls}" style="{style}left:{x:.1f}px;top:{y:.1f}px" aria-hidden="true"></span>'


def _card(ctx: Ctx, b: list, cx: float, y: float) -> str:
    first = b[0]
    colour = next((tactic_color(e) for e in b if has_attack(e)), "var(--border-strong)")
    f = ("★" if any(e.get("key_event") for e in b) else "") + ("⌖" if any(mal_iocs(e) for e in b) else "") + \
        ("⏱" if any(e.get("clock_offset_seconds") is not None for e in b) else "")
    tip = "\n".join(f"{hms(ctx, e['event_time'])}  {e['description']}" for e in b)
    head = " · ".join(x for x in (first.get("event_type"), host(first)) if x) or attack_label(first)
    if len(b) == 1:
        body = f'<div class="hc-h">{esc(head)}</div><div class="hc-d hc-d2">{esc(first["description"])}</div>'
        n = ""
    else:
        body = (f'<div class="hc-d">{esc(first["description"])}</div>'
                f'<div class="hc-d">{esc(b[1]["description"])}</div>'
                + (f'<div class="hc-h">+{len(b) - 2} more</div>' if len(b) > 2 else ""))
        n = f'<span class="n">×{len(b)} to {hm(ctx, b[-1]["event_time"])}</span>'
    return (f'<div class="hc" style="left:{cx:.1f}px;top:{y:.1f}px;border-top-color:{colour}" title="{esc(tip)}">'
            f'<div class="hc-t mono"><span>{hms(ctx, first["event_time"])}</span>{n}'
            f'<span class="f" style="color:var(--accent)">{esc(f)}</span></div>{body}</div>')


def _ticks(ctx: Ctx, s: _Seg, axis_y: float) -> list:
    out = [f'<span class="hz-tl" style="left:{s.x + 2:.1f}px;top:{axis_y + 6:.1f}px">{esc(hm(ctx, s.t0))}</span>']
    # 15-minute steps in UTC hit every real zone's quarter hours; label the local full hours.
    u0 = s.t0.astimezone(timezone.utc)
    t = u0.replace(minute=(u0.minute // 15) * 15, second=0, microsecond=0) + TICK
    while t < s.t1:
        x = s.x + (t - s.t0).total_seconds() * SCALE
        major = at(ctx, t).minute == 0
        h = 7 if major else 4
        out.append(f'<span class="hz-tk" style="left:{x:.1f}px;top:{axis_y + 2:.1f}px;height:{h}px"></span>')
        if major and x - s.x > 44 and s.x + s.w - x > (90 if s.cont_next else 20):
            out.append(f'<span class="hz-tl" style="left:{x - 14:.1f}px;top:{axis_y + 6:.1f}px">{esc(hm(ctx, t))}</span>')
        t += TICK
    return out


def _overview(ctx: Ctx, pers: list) -> str:
    ms = milestones(ctx.inc)
    times = [pers[0][0]["event_time"], pers[-1][-1]["event_time"]] + [t for _, _, t in ms]
    start = at(ctx, min(times)).replace(hour=0, minute=0, second=0, microsecond=0)
    end = at(ctx, max(times)).replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    total = (end - start).total_seconds()

    def px(t):
        return (t - start).total_seconds() / total * ROW_W

    out, d, month = [], start, None
    while d < end:
        nxt = d + timedelta(days=1)
        x0, x1 = px(d), px(nxt)
        we = " we" if d.weekday() >= 5 else ""
        label = ""
        if x1 - x0 >= 28 or d.day == 1:
            label = d.strftime("%a %d") if x1 - x0 >= 44 else d.strftime("%d")
            if d.month != month:
                label += d.strftime(" %b")
                month = d.month
        out.append(f'<div class="ov-d{we}" style="left:{x0:.1f}px;width:{x1 - x0:.1f}px">'
                   + (f'<span class="ov-dl">{esc(label)}</span>' if label else "") + "</div>")
        d = nxt
    for pi, p in enumerate(pers):
        x0 = px(p[0]["event_time"])
        w = max(3.0, px(p[-1]["event_time"]) - x0)
        colour = "var(--crit)" if any(has_attack(e) for e in p) else "var(--dim)"
        out.append(f'<span class="ov-bl" style="left:{x0:.1f}px">{letter(pi)}</span>'
                   f'<span class="ov-bar" style="left:{x0:.1f}px;width:{w:.1f}px;background:{colour}"></span>')
    c2 = [e["event_time"] for p in pers for e in p if e.get("mitre_tactic_id") == "TA0011"]
    if c2:
        contained = ctx.inc.get("contained_at")
        if contained and contained > c2[0]:          # open from the first C2 event until containment
            c_end, label = contained, f"C2 open {dur((contained - c2[0]).total_seconds())}"
        elif c2[-1] > c2[0]:                         # not contained: first to last C2 event seen
            c_end, label = c2[-1], f"C2 active {dur((c2[-1] - c2[0]).total_seconds())}"
        else:
            c_end, label = c2[0], "C2 beacon"
        x0 = px(c2[0])
        out.append(f'<span class="ov-c2" style="left:{x0:.1f}px;width:{max(2.0, px(c_end) - x0):.1f}px"></span>'
                   f'<span class="ov-c2l" style="left:{x0:.1f}px">{esc(label)}</span>')
    for i, (k, label, t) in enumerate(ms):
        out.append(f'<span class="ov-ms" style="left:{px(t):.1f}px" title="{esc(label)} {esc(hms(ctx, t))}"></span>')
        if i:
            a = px(ms[i - 1][2])
            w = max(2.0, px(t) - a)
            y = 82 + ((i - 1) % 4) * 18
            text = f"{dur((t - ms[i - 1][2]).total_seconds())} {_PHRASE[k]}"
            if k == "detected_at":
                text = f"Dwell {text}"
            out.append(f'<span class="ov-br" style="left:{a:.1f}px;width:{w:.1f}px;top:{y:.1f}px"></span>'
                       f'<span class="ov-brl" style="left:{a:.1f}px;top:{y + 9:.1f}px">{esc(text)}</span>')
    return f'<div class="ov" aria-label="Overview at true scale, one column per day">{"".join(out)}</div>'


def _period_table(ctx: Ctx, pers: list) -> str:
    rows = []
    for pi, p in enumerate(pers):
        a, b = p[0]["event_time"], p[-1]["event_time"]
        quiet = dur((a - pers[pi - 1][-1]["event_time"]).total_seconds(), coarse=True) if pi else "—"
        keys = sum(1 for e in p if e.get("key_event"))
        rows.append(f'<tr><td class="mono"><b>{letter(pi)}</b></td><td class="mono">{esc(day_short(ctx, a))} '
                    f'{hms(ctx, a)}</td><td class="mono">{esc(day_short(ctx, b))} {hms(ctx, b)}</td>'
                    f'<td class="mono">{esc(dur((b - a).total_seconds()))}</td><td>{len(p)}</td><td>{keys}</td>'
                    f'<td class="mono">{esc(quiet)}</td></tr>')
    return ('<table class="pt"><thead><tr><th>Period</th><th>From</th><th>To</th><th>Length</th><th>Events</th>'
            f'<th>Key</th><th>Quiet before</th></tr></thead><tbody>{"".join(rows)}</tbody></table>')


def render(ctx: Ctx) -> str:
    if not ctx.events:
        return page(ctx, "horizon", milestone_strip(ctx) + EMPTY, CSS, 1440)
    pers = periods(ctx.events)
    segs, brks, nrows = _layout(pers)
    by_period = {}
    for s in segs:
        by_period.setdefault(s.pi, []).append(s)

    # Milestones on a segment are drawn on the axis; one inside a fold is noted on that break.
    ms_on_axis = []
    for _, label, t in milestones(ctx.inc):
        s = next((s for s in segs if s.t0 <= t <= s.t1), None)
        if s:
            ms_on_axis.append((s.row, s.x + (t - s.t0).total_seconds() * SCALE, label, t, s.x, s.x + s.w))
            continue
        for bi, brk in enumerate(brks):
            if pers[bi][-1]["event_time"] < t < pers[bi + 1][0]["event_time"]:
                brk.notes.append(label)

    marks, cards = {}, {}
    for pi, p in enumerate(pers):
        for b in bursts(p):
            s, x = _pos(by_period[pi], b[0]["event_time"])
            cards.setdefault(s.row, []).append((x, b))
            for e in b:
                s2, x2 = _pos(by_period[pi], e["event_time"])
                marks.setdefault(s2.row, []).append((x2, e))

    rows_html = []
    for r in range(nrows):
        placed, up, dn = _place(cards.get(r, []))
        axis_y = HEAD + up * TRACK_H + UP_BAND + 6
        height = axis_y + BAND + 8 + dn * TRACK_H
        out = []
        row_segs = [s for s in segs if s.row == r]
        for si, s in enumerate(row_segs):
            if not s.cont_prev:
                p = pers[s.pi]
                a, b = p[0]["event_time"], p[-1]["event_time"]
                text = f"{day_short(ctx, a)} · {hm(ctx, a)}–{hm(ctx, b)}"
                room = (row_segs[si + 1].x if si + 1 < len(row_segs) else ROW_W) - s.x - 8   # up to the next period
                out.append(f'<div class="hz-ph" style="left:{s.x:.1f}px;max-width:{room:.1f}px" '
                           f'title="{esc(text)} · {len(p)} event{"" if len(p) == 1 else "s"}"><b>{letter(s.pi)}</b>'
                           f'{esc(text)}</div>')
            else:
                out.append(f'<div class="hz-ph" style="left:{s.x:.1f}px"><b>{letter(s.pi)}</b>continued</div>')
            if s.cont_next:
                out.append(f'<span class="hz-cont" style="right:0;top:{axis_y + 6:.1f}px">continues ↓</span>')
            # the axis, cut where the incident's phase changes
            cuts = sorted({s.t0, s.t1, *(t for t in (ctx.inc.get("detected_at"), ctx.inc.get("contained_at"))
                                         if t and s.t0 < t < s.t1)})
            for c0, c1 in zip(cuts, cuts[1:]):
                x0 = s.x + (c0 - s.t0).total_seconds() * SCALE
                w = (c1 - c0).total_seconds() * SCALE
                out.append(f'<span class="hz-ax" style="left:{x0:.1f}px;width:{w:.1f}px;top:{axis_y:.1f}px;'
                           f'background:var({_axis_colour(ctx.inc, c0 + (c1 - c0) / 2)})"></span>')
            out += _ticks(ctx, s, axis_y)
        for brk in (b for b in brks if b.row == r):
            notes = "".join(f"<br>◆ {esc(n)}" for n in brk.notes)
            out.append(f'<div class="hz-brk" style="left:{brk.x:.1f}px;top:{axis_y - 34:.1f}px">'
                       f'<span class="z" aria-hidden="true">≈≈</span>{esc(dur(brk.gap, coarse=True))}<br>quiet{notes}</div>')
        for side, i, cx, x, b in placed:
            if side == "up":
                y = axis_y - UP_BAND - 6 - i * TRACK_H - CARD_H
                out.append(f'<span class="hz-ld" style="left:{x:.1f}px;top:{y + CARD_H:.1f}px;height:{axis_y - y - CARD_H:.1f}px"></span>')
            else:
                y = axis_y + BAND + 8 + i * TRACK_H
                out.append(f'<span class="hz-ld" style="left:{x:.1f}px;top:{axis_y:.1f}px;height:{y - axis_y:.1f}px"></span>')
            out.append(_card(ctx, b, cx, y))
        for x, e in marks.get(r, []):
            out.append(_mark(e, x, axis_y))
        mine = [m for m in ms_on_axis if m[0] == r]
        for x, *_ in mine:
            out.append(f'<span class="hz-ms" style="left:{x:.1f}px;top:{axis_y:.1f}px" aria-hidden="true"></span>')
        for x, text, lx, level in place_labels([(x, f"◆ {label.upper()} {hms(ctx, t)}", seg_x, seg_end)
                                                for _, x, label, t, seg_x, seg_end in mine]):
            out.append(f'<span class="hz-msl" style="left:{lx:.1f}px;top:{axis_y - 18 - level * 13:.1f}px">'
                       f'{esc(text)}</span>')
        rows_html.append(f'<div class="hz-row" style="height:{height:.0f}px">{"".join(out)}</div>')

    top = milestone_strip(ctx)
    if len(pers) > 1:
        top += ('<h2>Overview · true scale, one column per day</h2>' + _overview(ctx, pers)
                + _period_table(ctx, pers))
        top += '<h2>Active periods · one scale for all, 4 px per minute · quiet stretches over 6 h folded</h2>'
    key = legend([
        ('<span style="display:inline-block;width:22px;height:3px;background:var(--border-strong)"></span>', "before detection"),
        ('<span style="display:inline-block;width:22px;height:3px;background:var(--phase-detect)"></span>', "◉ Detection & Analysis"),
        ('<span style="display:inline-block;width:22px;height:3px;background:var(--phase-respond)"></span>', "⊘ Containment, Eradication & Recovery"),
        ('<span style="color:var(--border-strong);font-weight:700">≈≈</span>', "quiet stretch over 6 h, folded"),
        ('<span style="color:var(--accent)">×N</span>', "events under 10 min apart, one card"),
        ('<span style="display:inline-block;width:9px;height:9px;transform:rotate(45deg);background:var(--text)"></span>', "incident milestone"),
        ('<span style="color:var(--accent)">★ ⌖ ⏱</span>', "key · malicious IOC linked · clock corrected"),
    ] + ([('<span style="display:inline-block;width:22px;border-top:2px dashed var(--accent)"></span>', "C2 channel open"),
          ('<span style="display:inline-block;width:12px;height:8px;background:var(--crit)"></span>', "period with ATT&CK-tagged events")]
         if len(pers) > 1 else []))
    return page(ctx, "horizon", top + "".join(rows_html) + key, CSS, 1440)
