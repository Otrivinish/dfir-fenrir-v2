"""Swimlanes — one lane per linked entity (owner decision 3, 2026-10-31).

An event has one entity_id, so it sits in exactly one lane; events with no entity share a bottom "No linked
entity" lane. A malicious IOC linked to events is a target lane with no events of its own: each linking
event points an arrow at it, so nothing is counted twice. Lanes share one time axis: quiet stretches over
6 h fold into fixed breaks (as in Horizon) and the active periods are scaled to fit the page, at most 4 px
per minute. Events less than 10 min apart in a lane share one chip (×N). The incident milestones run
across every lane.
"""
from datetime import timedelta, timezone

from .common import (EMPTY, ENTITY_TYPE, Ctx, at, bursts, dur, esc, has_attack, hm, hms, legend, mal_iocs,
                     milestones, page, periods, place_labels, sev_style, tactic_color)
from .horizon import letter

LABEL_W = 230
PLOT_W = 1010              # the time axis; chips get CHIP_W more room on the right
BREAK_W = 44
EDGE = 18                  # px kept either side of a period's first and last event
MAX_SCALE = 4 / 60         # px per second
CHIP_W, CHIP_H = 138, 38
TRACK_H = CHIP_H + 6
AXIS_H = 64                # period row, tick row, two milestone-label rows
LANE_MIN = {"entity": 76, "ioc": 92, "none": 64}
STEPS = (5, 10, 15, 30, 60, 120, 180, 360, 720, 1440)   # tick steps, minutes

CSS = """
.sl-crumb{margin-bottom:var(--space-4);font-family:var(--font-mono);font-size:11px;color:var(--muted)}
.sl-crumb b{color:var(--text)}
.sl-scroll{overflow-x:auto}
.sl{position:relative}
.sl-axis{position:relative;height:64px;margin-left:230px;border-bottom:1px solid var(--border-strong)}
.sl-lane{display:flex;border-bottom:1px solid var(--border)}
.sl-lane.unl{background:var(--surface-2)}
.sl-lab{flex:0 0 230px;padding:8px 10px 8px 0;font-size:11px;line-height:1.4;overflow:hidden}
.sl-lab .v{font-family:var(--font-mono);font-weight:700;color:var(--text);word-break:break-all}
.sl-lab .s{color:var(--dim);font-size:10px}
.sl-lab .bd{display:flex;flex-wrap:wrap;gap:4px;margin-top:3px}
.sl-plot{position:relative;flex:0 0 auto}
.sl-chip{position:absolute;z-index:3;width:138px;height:38px;overflow:hidden;background:var(--surface);
 border:1px solid var(--border);border-left:3px solid;border-radius:var(--radius-sm);padding:2px 6px;font-size:10px;
 line-height:16px}
.sl-chip .t{font-family:var(--font-mono);font-weight:700;color:var(--text);white-space:nowrap}
.sl-chip .t .n{color:var(--accent);margin-left:4px}
.sl-chip .d{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--muted)}
.sl-tk{position:absolute;bottom:0;width:1px;height:5px;background:var(--border-strong)}
.sl-tl{position:absolute;top:16px;font-family:var(--font-mono);font-size:9.5px;color:var(--dim);white-space:nowrap}
.sl-ph{position:absolute;top:0;font-family:var(--font-mono);font-size:10px;font-weight:700;color:var(--text);white-space:nowrap}
.sl-brk{position:absolute;z-index:1;top:64px;bottom:0;width:44px;background:repeating-linear-gradient(135deg,
 var(--surface-2) 0 3px,transparent 3px 9px);border-left:1px dashed var(--border-strong);
 border-right:1px dashed var(--border-strong)}
.sl-brl{position:absolute;top:16px;width:44px;text-align:center;font-family:var(--font-mono);font-size:9px;color:var(--dim);
 white-space:nowrap}
.sl-ms{position:absolute;z-index:1;top:64px;bottom:0;width:0;border-left:1px dashed var(--c)}
.sl-msl{position:absolute;font-family:var(--font-mono);font-size:9px;font-weight:700;letter-spacing:.04em;
 color:var(--c);white-space:nowrap}
.sl-tgt{position:absolute;z-index:3;top:50%;margin:-8px 0 0 -8px;font-size:15px;line-height:16px;color:var(--sev-crit-text)}
.sl-svg{position:absolute;z-index:2;left:0;top:0;pointer-events:none;overflow:visible}
.sl-arrow{stroke:var(--crit);stroke-width:1.5;stroke-dasharray:4 3;fill:none}
.sl-head{fill:var(--crit)}
"""

_MS_COLOUR = {"occurred_at": "--muted", "detected_at": "--phase-detect", "contained_at": "--phase-respond",
              "eradicated_at": "--phase-respond", "recovered_at": "--phase-post"}


def _lanes(ctx: Ctx):
    """[(kind, key, events)] — entity lanes by first event, IOC target lanes, then the unlinked lane."""
    ent_lanes, ioc_lanes, unlinked = {}, {}, []
    for ev in ctx.events:
        if ev.get("entity_id"):
            ent_lanes.setdefault(ev["entity_id"], []).append(ev)
        else:
            unlinked.append(ev)
        for i in mal_iocs(ev):
            ioc_lanes.setdefault(i["id"], i)
    lanes = [("entity", eid, evs) for eid, evs in ent_lanes.items()]
    lanes += [("ioc", iid, []) for iid in ioc_lanes]
    if unlinked:
        lanes.append(("none", None, unlinked))
    return lanes, ioc_lanes


def _scale(pers: list):
    """[(x0, x1, t_first, t_last)] per period, the px-per-second scale (≤ 4 px/min, fit to PLOT_W) and
    the axis width."""
    spans = [(p[-1]["event_time"] - p[0]["event_time"]).total_seconds() for p in pers]
    room = PLOT_W - BREAK_W * (len(pers) - 1) - 2 * EDGE * len(pers)
    total = sum(spans)
    if total <= 0:
        scale = MAX_SCALE
    else:
        scale = min(MAX_SCALE, max(room, 0.0) / total)
    out, x = [], 0.0
    for p, span in zip(pers, spans):
        w = 2 * EDGE + span * scale
        out.append((x, x + w, p[0]["event_time"], p[-1]["event_time"]))
        x += w + BREAK_W
    return out, scale, x - BREAK_W


def _x(geo: list, scale: float, t):
    """x of time t on the folded axis (t inside a period, or the nearest period edge)."""
    for x0, x1, a, b in geo:
        if t <= b:
            return x0 + EDGE + max(0.0, (t - a).total_seconds()) * scale
    return geo[-1][1] - EDGE


def _inside(geo: list, t) -> bool:
    return any(a <= t <= b for _, _, a, b in geo)


def _pack(items: list):
    """Greedy chip tracks: [(track, cx, x, burst)], track count."""
    ends, out = [], []
    for x, b in sorted(items, key=lambda it: it[0]):
        cx = max(0.0, x - 6)
        for i, end in enumerate(ends):
            if cx >= end + 4:
                ends[i] = cx + CHIP_W
                out.append((i, cx, x, b))
                break
        else:
            ends.append(cx + CHIP_W)
            out.append((len(ends) - 1, cx, x, b))
    return out, max(1, len(ends))


def _label(ctx: Ctx, kind: str, key, evs: list, iocs: dict) -> str:
    if kind == "entity":
        ent = ctx.entities.get(key) or (evs[0].get("entity") or {})
        typ = ENTITY_TYPE.get(ent.get("type"), ent.get("type") or "Entity")
        name = ent.get("name")
        badges = []
        if ent.get("compromised"):
            badges.append(f'<span class="fl" style="{sev_style("critical")}">COMPROMISED</span>')
        crit = (ent.get("criticality") or "").lower()
        if crit in ("high", "critical"):
            badges.append(f'<span class="fl" style="{sev_style(crit)}">{esc(crit.upper())}</span>')
        sub = f"{typ}" + (f" · {name}" if name else "") + f" · {len(evs)} event{'' if len(evs) == 1 else 's'}"
        return (f'<div class="v" title="{esc(ent.get("value"))}">{esc(ent.get("value"))}</div>'
                f'<div class="s">{esc(sub)}</div>' + (f'<div class="bd">{"".join(badges)}</div>' if badges else ""))
    if kind == "ioc":
        i = iocs[key]
        return (f'<div class="v" title="{esc(i.get("value"))}">{esc(i.get("value"))}</div><div class="s">Linked IOC · '
                f'{esc(i.get("type"))} · target only, no events of its own</div><div class="bd"><span class="fl" '
                f'style="{sev_style("critical")}">MALICIOUS IOC</span></div>')
    return (f'<div class="v">No linked entity</div><div class="s">Events without an entity · {len(evs)} '
            f'event{"" if len(evs) == 1 else "s"}</div>')


def _chip(ctx: Ctx, b: list, cx: float, y: float) -> str:
    first = b[0]
    colour = next((tactic_color(e) for e in b if has_attack(e)), "var(--border-strong)")
    n = f'<span class="n">×{len(b)}</span>' if len(b) > 1 else ""
    mark = ("★" if any(e.get("key_event") for e in b) else "") + ("⌖" if any(mal_iocs(e) for e in b) else "")
    head = " ".join(x for x in (hms(ctx, first["event_time"]), first.get("event_type")) if x)
    tip = "\n".join(f"{hms(ctx, e['event_time'])}  {e['description']}" for e in b)
    return (f'<div class="sl-chip" style="left:{cx:.1f}px;top:{y:.1f}px;border-left-color:{colour}" title="{esc(tip)}">'
            f'<div class="t">{esc(head)}{n} <span style="color:var(--accent)">{esc(mark)}</span></div>'
            f'<div class="d">{esc(first["description"])}</div></div>')


def _axis(ctx: Ctx, geo: list, scale: float, plot_w: float) -> str:
    out = []
    step = next((s for s in STEPS if s * 60 * scale >= 70), None)
    for pi, (x0, x1, a, b) in enumerate(geo):
        out.append(f'<span class="sl-ph" style="left:{x0:.1f}px">{letter(pi)} · {esc(at(ctx, a).strftime("%a %d %b"))}</span>')
        out.append(f'<span class="sl-tl" style="left:{x0 + EDGE - 14:.1f}px">{esc(hm(ctx, a))}</span>')
        if not step or scale <= 0:
            continue
        u = a.astimezone(timezone.utc).replace(second=0, microsecond=0)
        t = u.replace(minute=(u.minute // 15) * 15)
        # 15-minute steps in UTC hit every real zone's quarter hours; keep the local multiples of the step.
        while t <= b:
            loc = at(ctx, t)
            if t > a and (loc.hour * 60 + loc.minute) % step == 0:
                x = x0 + EDGE + (t - a).total_seconds() * scale
                out.append(f'<span class="sl-tk" style="left:{x:.1f}px"></span>')
                if x - x0 - EDGE > 46:
                    out.append(f'<span class="sl-tl" style="left:{x - 14:.1f}px">{esc(hm(ctx, t))}</span>')
            t += timedelta(minutes=min(step, 15))
    for pi in range(1, len(geo)):
        gap = (geo[pi][2] - geo[pi - 1][3]).total_seconds()
        out.append(f'<span class="sl-brl" style="left:{geo[pi - 1][1]:.1f}px">{esc(dur(gap, coarse=True))}</span>')
    ms = [(k, label, t) for k, label, t in milestones(ctx.inc) if _inside(geo, t)]
    colour = {_x(geo, scale, t): _MS_COLOUR[k] for k, _, t in ms}
    for x, text, lx, level in place_labels(
            [(_x(geo, scale, t), f"◆ {label.upper()} {hm(ctx, t)}", 0, plot_w + CHIP_W) for _, label, t in ms],
            char_w=5.9):
        out.append(f'<span class="sl-msl" style="left:{lx:.1f}px;top:{48 - level * 14}px;--c:var({colour[x]})">'
                   f'{esc(text)}</span>')
    return "".join(out)


def render(ctx: Ctx) -> str:
    if not ctx.events:
        return page(ctx, "swimlanes", EMPTY, CSS, 1440)
    pers = periods(ctx.events)
    geo, scale, plot_w = _scale(pers)
    lanes, iocs = _lanes(ctx)

    lane_html, lane_box, arrows, y = [], {}, [], AXIS_H
    for kind, key, evs in lanes:
        items = [(_x(geo, scale, b[0]["event_time"]), b) for b in bursts(evs)]
        packed, ntracks = _pack(items)
        h = max(LANE_MIN[kind], ntracks * TRACK_H + 12)
        chips = []
        for track, cx, x, b in packed:
            cy = 6 + track * TRACK_H
            chips.append(_chip(ctx, b, cx, cy))
            for i in {i["id"] for e in b for i in mal_iocs(e)}:
                arrows.append((x, y + cy, y + cy + CHIP_H, i))
        if kind == "ioc":
            for e in ctx.events:
                if any(i["id"] == key for i in mal_iocs(e)):
                    chips.append(f'<span class="sl-tgt" style="left:{_x(geo, scale, e["event_time"]):.1f}px" '
                                 f'aria-hidden="true">⌖</span>')
        lane_box[(kind, key)] = (y, y + h)
        cls = " unl" if kind == "none" else ""
        lane_html.append(f'<div class="sl-lane{cls}" style="height:{h}px"><div class="sl-lab">'
                         f'{_label(ctx, kind, key, evs, iocs)}</div><div class="sl-plot" style="width:'
                         f'{plot_w + CHIP_W:.0f}px;height:{h}px">{"".join(chips)}</div></div>')
        y += h

    overlay = [f'<div class="sl-brk" style="left:{LABEL_W + geo[pi - 1][1]:.1f}px"></div>' for pi in range(1, len(geo))]
    for k, label, t in milestones(ctx.inc):
        if _inside(geo, t):
            overlay.append(f'<div class="sl-ms" style="left:{LABEL_W + _x(geo, scale, t):.1f}px;'
                           f'--c:var({_MS_COLOUR[k]})"></div>')
    svg = []
    for x, top, bottom, iid in arrows:
        box = lane_box.get(("ioc", iid))
        if box is None:
            continue
        ax = LABEL_W + x
        if box[0] >= bottom:                      # the IOC lane is below: from the chip's bottom edge, down
            y0, tip, base = bottom, box[0] + (box[1] - box[0]) / 2 - 9, -6
        else:                                     # above: from the top edge, up
            y0, tip, base = top, box[0] + (box[1] - box[0]) / 2 + 9, 6
        svg.append(f'<line class="sl-arrow" x1="{ax:.1f}" y1="{y0:.1f}" x2="{ax:.1f}" y2="{tip + base:.1f}"/>'
                   f'<polygon class="sl-head" points="{ax - 4:.1f},{tip + base:.1f} {ax + 4:.1f},{tip + base:.1f} '
                   f'{ax:.1f},{tip:.1f}"/>')
    total_w = LABEL_W + plot_w + CHIP_W
    svg_html = (f'<svg class="sl-svg" width="{total_w:.0f}" height="{y:.0f}" aria-hidden="true">{"".join(svg)}</svg>'
                if svg else "")

    order, seen = [], set()
    for ev in ctx.events:
        if has_attack(ev):
            lane = ev.get("entity") and ev["entity"].get("value")
            if lane and lane not in seen:
                seen.add(lane)
                order.append(lane)
            for i in mal_iocs(ev):
                if i["value"] not in seen:
                    seen.add(i["value"])
                    order.append(i["value"])
    crumb = ('<div class="sl-crumb">First seen, by ATT&amp;CK-tagged event: '
             + " → ".join(f"<b>{esc(v)}</b>" for v in order) + "</div>") if order else ""
    n_ent = sum(1 for k, _, _ in lanes if k == "entity")
    n_unl = next((len(evs) for k, _, evs in lanes if k == "none"), 0)
    stats = (f'<div class="sl-crumb">{n_ent} linked entit{"y" if n_ent == 1 else "ies"} · {len(iocs)} malicious IOC '
             f'target{"" if len(iocs) == 1 else "s"} · {n_unl} event{"" if n_unl == 1 else "s"} without an entity</div>')
    body = (stats + crumb + f'<div class="sl-scroll"><div class="sl" style="width:{total_w:.0f}px">'
            f'<div class="sl-axis" style="width:{plot_w + CHIP_W:.0f}px">{_axis(ctx, geo, scale, plot_w)}</div>'
            + "".join(lane_html) + "".join(overlay) + svg_html + "</div></div>")
    key = legend([
        ('<span style="display:inline-block;width:12px;height:12px;border-left:3px solid var(--crit);background:var(--surface)"></span>',
         "event chip, left edge = ATT&CK tactic colour"),
        ('<span style="color:var(--accent)">×N</span>', "events under 10 min apart in a lane"),
        ('<span style="color:var(--sev-crit-text)">⌖</span>', "event links a malicious IOC (arrow to its lane)"),
        ('<span style="display:inline-block;width:18px;height:10px;background:repeating-linear-gradient(135deg,var(--surface-2) 0 3px,transparent 3px 6px);border:1px dashed var(--border-strong)"></span>',
         "quiet stretch over 6 h, folded"),
        ('<span style="display:inline-block;height:12px;border-left:1px dashed var(--phase-detect)"></span>', "incident milestone"),
    ])
    return page(ctx, "swimlanes", body + key, CSS, 1440)
