"""Brief — the executive one-pager: the milestone track (how long undetected, to contain, to recover), the key
moments, impact counts and the ATT&CK stages seen. Everything is counted from the exported events and the
incident record; nothing is estimated or written for the reader."""
from .common import (EMPTY, PHASES, TACTICS, Ctx, day_short, esc, has_attack, hm, host, mal_iocs,
                     milestone_strip, page, phase_label, tactic_color)

MAX_MOMENTS = 12

CSS = """
.bf-st{margin:-8px 0 var(--space-4);font-size:12px;color:var(--muted)}
.bf{display:grid;grid-template-columns:minmax(0,3fr) minmax(0,2fr);gap:var(--space-5)}
.bf-m{list-style:none}
.bf-m li{display:grid;grid-template-columns:96px minmax(0,1fr);gap:var(--space-3);padding:8px 0;border-bottom:1px solid var(--border)}
.bf-m .w{font-family:var(--font-mono);font-size:11px;color:var(--muted);line-height:1.35}
.bf-m .w b{display:block;color:var(--text);font-size:12px}
.bf-m .d{font-size:13px;color:var(--text)}
.bf-m .x{margin-top:3px;font-size:10px;color:var(--dim)}
.bf-more{margin-top:var(--space-2);font-size:11px;color:var(--dim)}
.bf-t{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:var(--space-3)}
.bf-t div{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:var(--space-3)}
.bf-t b{display:block;font-family:var(--font-heading);font-size:26px;line-height:1.1;color:var(--text)}
.bf-t span{font-size:11px;color:var(--muted)}
.bf-s{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:4px}
.bf-s div{border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px;min-height:52px;font-size:10px;
 line-height:1.25;color:var(--dim);background:var(--bg)}
.bf-s div.on{color:var(--text);border-color:var(--c);border-top:3px solid var(--c);background:var(--surface)}
.bf-s div b{display:block;font-family:var(--font-mono);font-size:12px}
"""


def _moments(events: list):
    """The key events to show, oldest first: analyst-flagged first, then the first event of each ATT&CK
    tactic, then the rest; capped at MAX_MOMENTS. Returns (events, how many key events were left out)."""
    keys = [e for e in events if e.get("key_event")]
    if len(keys) <= MAX_MOMENTS:
        return keys, 0
    seen, ranked = set(), []
    for i, e in enumerate(keys):
        tac = e.get("mitre_tactic_id")
        if e.get("is_key"):
            rank = 0
        elif tac and tac not in seen:
            rank = 1
        else:
            rank = 2
        if tac:
            seen.add(tac)
        ranked.append((rank, i, e))
    picked = sorted(sorted(ranked, key=lambda r: (r[0], r[1]))[:MAX_MOMENTS], key=lambda r: r[1])
    return [e for _, _, e in picked], len(keys) - MAX_MOMENTS


def _impact(ctx: Ctx) -> list:
    hosts, users, compromised, iocs = set(), set(), set(), set()
    for e in ctx.events:
        ent = e.get("entity")
        if ent:
            if ent.get("type") == "host":
                hosts.add(ent.get("value", "").lower())
            if ent.get("type") == "user":
                users.add(ent.get("value", "").lower())
            if ent.get("compromised"):
                compromised.add(ent.get("id"))
        elif e.get("hostname"):
            hosts.add(e["hostname"].strip().lower())
        for i in mal_iocs(e):
            iocs.add(i.get("id"))
    def n(c, one, many):
        return (len(c), one if len(c) == 1 else many)
    return [n(hosts, "host involved", "hosts involved"), n(users, "account involved", "accounts involved"),
            n(compromised, "compromised entity", "compromised entities"),
            n(iocs, "malicious IOC linked", "malicious IOCs linked")]


def render(ctx: Ctx) -> str:
    inc = ctx.inc
    status = (inc.get("status") or "").capitalize()
    phase = phase_label(inc.get("phase")) if inc.get("phase") in PHASES else ""
    head = f'<p class="bf-st">Status: {esc(status)}' + (f" · Current phase: {phase}" if phase else "") + "</p>"
    if not ctx.events:
        return page(ctx, "brief", head + milestone_strip(ctx) + EMPTY, CSS, 1100)
    moments, more = _moments(ctx.events)
    multi_day = day_short(ctx, ctx.events[0]["event_time"]) != day_short(ctx, ctx.events[-1]["event_time"])
    items = []
    for e in moments:
        when = (f"<b>{esc(hm(ctx, e['event_time']))}</b>"
                + (esc(day_short(ctx, e["event_time"])) if multi_day else ""))
        extra = " · ".join(x for x in (host(e), e.get("mitre_tactic_name")) if x)
        items.append(f'<li><div class="w">{when}</div><div><div class="d">{esc(e["description"])}</div>'
                     + (f'<div class="x">{esc(extra)}</div>' if extra else "") + "</div></li>")
    more_html = (f'<p class="bf-more">+{more} more key event{"" if more == 1 else "s"} in the full timeline.</p>'
                 if more else "")
    if not items:
        items.append('<li><div class="w"></div><div class="d">No key events yet. Flag events as key, or tag them '
                     'with ATT&amp;CK, to list them here.</div></li>')
    tiles = "".join(f"<div><b>{c}</b><span>{esc(label)}</span></div>" for c, label in _impact(ctx))
    counts = {}
    for e in ctx.events:
        if e.get("mitre_tactic_id"):
            counts[e["mitre_tactic_id"]] = counts.get(e["mitre_tactic_id"], 0) + 1
    seen = sum(1 for t in TACTICS if t[0] in counts)
    stages = "".join(
        f'<div class="on" style="--c:{tactic_color({"mitre_tactic_id": tid})}"><b>{counts[tid]}</b>{esc(name)}</div>'
        if tid in counts else f"<div><b>—</b>{esc(name)}</div>"
        for tid, name, _ in TACTICS)
    attacked = sum(1 for e in ctx.events if has_attack(e))
    body = (head + milestone_strip(ctx)
            + f'<div class="bf"><section><h2>What happened</h2><ol class="bf-m">{"".join(items)}</ol>{more_html}</section>'
            + f'<section><h2>Impact</h2><div class="bf-t">{tiles}</div></section></div>'
            + f'<h2>Attack stages seen · {seen} of {len(TACTICS)} ATT&amp;CK tactics · {attacked} tagged '
            + f'event{"" if attacked == 1 else "s"}</h2><div class="bf-s">{stages}</div>')
    return page(ctx, "brief", body, CSS, 1100)
