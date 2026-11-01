"""Shared pieces of the timeline export layouts (TX): the context, vocabulary, formatting and the page shell.

Each layout is a pure function Ctx -> one complete HTML document; nothing here touches the DB. Every value
that comes from the incident or an event goes through esc() before it is written into the page. The page
has no script and carries a CSP that blocks scripts and outbound loads, so a missed escape still can't run
code or call home when the file is opened.

Colours are CSS custom properties only. The exported file can't load the app's stylesheet, so TOKENS copies
the mission-control values (screen) and the nordic-calm values (print) from frontend/src/styles/tokens.css;
keep them in step when those change. The one hex exception is SEV_PALETTE (CLAUDE.md, status badges).
"""
import html
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone, tzinfo

LAYOUTS = ("rail", "horizon", "swimlanes", "ledger", "brief", "zigzag")
LAYOUT_NAMES = {"rail": "Rail", "horizon": "Horizon", "swimlanes": "Swimlanes", "ledger": "Ledger",
                "brief": "Brief", "zigzag": "Zig-zag"}
# The layouts that print raw log lines when include_raw_logs is on (and the CSV's raw_log column).
RAW_LAYOUTS = ("rail", "ledger", "zigzag")

FOLD_GAP = timedelta(hours=6)       # a quiet stretch longer than this starts a new active period
BURST_GAP = timedelta(minutes=10)   # events closer together than this share one card (×N)


@dataclass
class Ctx:
    inc: dict                       # ref, title, severity, tlp, status, phase and the milestone times
    events: list                    # TimelineEventOut.model_dump() dicts, oldest first
    entities: dict                  # entity id -> {type, value, name, compromised, criticality}
    tz: tzinfo
    tz_name: str
    include_raw_logs: bool = False
    exported_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0))
    exported_by: str = ""
    filters: list = field(default_factory=list)    # labels of the filters applied, shown in the header
    lolbin_ids: set = field(default_factory=set)   # ids of events that name a LOLBAS / GTFOBins binary
    csv_sha256: str = ""                           # SHA-256 of the CSV export with the same options (Ledger)


# ─── Vocabulary (mirrors frontend lib/incidentVocab.js and lib/mitre.js) ─────────────────────────────

PHASES = {   # 800-61 R3 phase -> (label, short, glyph, colour token)
    "preparation":                      ("Preparation", "Prep", "◇", "--phase-prep"),
    "detection_and_analysis":           ("Detection & Analysis", "Detect", "◉", "--phase-detect"),
    "containment_eradication_recovery": ("Containment, Eradication & Recovery", "C/E/R", "⊘", "--phase-respond"),
    "post_incident":                    ("Post-Incident", "Post", "↺", "--phase-post"),
}

# The 14 ATT&CK Enterprise tactics in matrix order, with the token the app's tacticColor() uses.
TACTICS = (
    ("TA0043", "Reconnaissance", "--low"),
    ("TA0042", "Resource Development", "--med"),
    ("TA0001", "Initial Access", "--crit"),
    ("TA0002", "Execution", "--high"),
    ("TA0003", "Persistence", "--med"),
    ("TA0004", "Privilege Escalation", "--high"),
    ("TA0005", "Defense Evasion", "--accent"),
    ("TA0006", "Credential Access", "--crit"),
    ("TA0007", "Discovery", "--low"),
    ("TA0008", "Lateral Movement", "--high"),
    ("TA0009", "Collection", "--med"),
    ("TA0010", "Exfiltration", "--high"),
    ("TA0011", "Command and Control", "--accent"),
    ("TA0040", "Impact", "--crit"),
)
TACTIC_NAME = {t[0]: t[1] for t in TACTICS}
_TACTIC_VAR = {t[0]: t[2] for t in TACTICS}

ORIGIN = {"manual": "Manual", "forensic_import": "Imported", "system": "System"}
ENTITY_TYPE = {"host": "Host", "user": "User", "ip": "IP", "domain": "Domain", "email": "Email",
               "service": "Service", "network_range": "Network range", "group": "Group", "other": "Other"}
TLP = {"red": ("TLP:RED", "--crit"), "amber_strict": ("TLP:AMBER+STRICT", "--high"),
       "amber": ("TLP:AMBER", "--high"), "green": ("TLP:GREEN", "--ok"), "clear": ("TLP:CLEAR", "--muted")}

# SEV_PALETTE (frontend components/SevBadge.jsx) — canonical badge background and border; the text reads
# --sev-*-text so print (light) gets the darker nordic-calm text, as in the app.
_SEV = {"critical": ("#ff000022", "#ff000055", "--sev-crit-text"),
        "high":     ("#ff800022", "#ff800055", "--sev-high-text"),
        "medium":   ("#ffcc0022", "#ffcc0055", "--sev-med-text"),
        "low":      ("#00cc5522", "#00cc5555", "--sev-low-text")}

# Incident milestones in order; the phrase names the stretch that ends at that milestone.
MILESTONES = (("occurred_at", "Occurred", ""), ("detected_at", "Detected", "undetected"),
              ("contained_at", "Contained", "to contain"), ("eradicated_at", "Eradicated", "to eradicate"),
              ("recovered_at", "Recovered", "to recover"))
_PHRASE = {k: p for k, _, p in MILESTONES}


def sev_style(level: str) -> str:
    bg, border, text = _SEV.get(level, _SEV["medium"])
    return f"background:{bg};border-color:{border};color:var({text})"


def tactic_color(ev: dict) -> str:
    return f"var({_TACTIC_VAR.get(ev.get('mitre_tactic_id') or '', '--border-strong')})"


def has_attack(ev: dict) -> bool:
    return bool(ev.get("mitre_tactic_id") or ev.get("mitre_technique_id"))


def attack_label(ev: dict) -> str:
    tactic = ev.get("mitre_tactic_name") or TACTIC_NAME.get(ev.get("mitre_tactic_id") or "", "")
    tech = " ".join(x for x in (ev.get("mitre_technique_id"), ev.get("mitre_technique_name")) if x)
    return " · ".join(x for x in (tactic, tech) if x)


def host(ev: dict) -> str:
    """The linked entity's value, else the event's hostname."""
    ent = ev.get("entity")
    return (ent or {}).get("value") or ev.get("hostname") or ""


def mal_iocs(ev: dict) -> list:
    return [i for i in (ev.get("linked_iocs") or []) if i.get("malicious")]


def milestones(inc: dict) -> list:
    """[(key, label, time)] for the milestones the incident has, in time order."""
    return sorted(((k, label, inc[k]) for k, label, _ in MILESTONES if inc.get(k)), key=lambda m: m[2])


def periods(events: list, gap: timedelta = FOLD_GAP) -> list:
    """Split oldest-first events into runs; a quiet stretch longer than `gap` starts a new run."""
    out = []
    for ev in events:
        if out and ev["event_time"] - out[-1][-1]["event_time"] <= gap:
            out[-1].append(ev)
        else:
            out.append([ev])
    return out


def bursts(events: list) -> list:
    """Runs of events less than BURST_GAP apart (drawn as one card)."""
    out = []
    for ev in events:
        if out and ev["event_time"] - out[-1][-1]["event_time"] < BURST_GAP:
            out[-1].append(ev)
        else:
            out.append([ev])
    return out


# ─── Formatting ─────────────────────────────────────────────────────────────────────────────────────

def esc(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def at(ctx: Ctx, dt: datetime) -> datetime:
    return dt.astimezone(ctx.tz)


def hms(ctx: Ctx, dt: datetime) -> str:
    return at(ctx, dt).strftime("%H:%M:%S")


def hm(ctx: Ctx, dt: datetime) -> str:
    return at(ctx, dt).strftime("%H:%M")


def day(ctx: Ctx, dt: datetime) -> str:
    return at(ctx, dt).strftime("%a %d %b %Y")


def day_short(ctx: Ctx, dt: datetime) -> str:
    return at(ctx, dt).strftime("%a %d %b")


def utc_offset(ctx: Ctx, dt: datetime) -> str:
    if ctx.tz_name == "UTC":
        return "UTC"
    mins = int((at(ctx, dt).utcoffset() or timedelta(0)).total_seconds() // 60)
    return f"UTC{'+' if mins >= 0 else '−'}{abs(mins) // 60:02d}:{abs(mins) % 60:02d}"


def iso_z(dt: datetime) -> str:
    """UTC ISO 8601 with Z; sub-second precision kept when present."""
    u = dt.astimezone(timezone.utc)
    s = u.strftime("%Y-%m-%dT%H:%M:%S")
    if u.microsecond:
        s += f".{u.microsecond:06d}".rstrip("0")
    return s + "Z"


def dur(seconds: float, coarse: bool = False) -> str:
    """42s · 7m · 2h 53m · 5d 19h 10m, to the nearest minute. coarse drops the minutes from a day up
    (quiet stretches: 3d 11h)."""
    s = int(round(abs(seconds)))
    if s < 60:
        return f"{s}s"
    d, rem = divmod(int(round(s / 60)), 1440)
    h, m = divmod(rem, 60)
    if d:
        return f"{d}d {h}h" if coarse else f"{d}d {h}h {m}m"
    return f"{h}h {m:02d}m" if h else f"{m}m"


def delta(seconds: float) -> str:
    """Time since the previous row: +12s · +7m 05s · +2h 53m."""
    s = int(round(seconds))
    if s < 60:
        return f"+{s}s"
    if s < 3600:
        return f"+{s // 60}m {s % 60:02d}s"
    return "+" + dur(s)


def offset_s(n: int) -> str:
    return f"{'+' if n >= 0 else '−'}{abs(n)} s"


def clip(s, n: int) -> str:
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


# ─── Shared fragments ───────────────────────────────────────────────────────────────────────────────

def phase_label(ph) -> str:
    if ph not in PHASES:
        return ""
    label, _, glyph, var = PHASES[ph]
    return f'<span class="g" style="color:var({var})" aria-hidden="true">{glyph}</span> {esc(label)}'


def attack_chip(ev: dict) -> str:
    lab = attack_label(ev)
    return f'<span class="att" style="--c:{tactic_color(ev)}">{esc(lab)}</span>' if lab else ""


def flags(ctx: Ctx, ev: dict) -> str:
    out = []
    if ev.get("key_event"):
        out.append('<span class="fl fl-key">★ KEY</span>')
    for i in mal_iocs(ev):
        out.append(f'<span class="fl" style="{sev_style("critical")}" title="{esc(i.get("value"))}">'
                   f'⌖ MALICIOUS · {esc(clip(i.get("value"), 48))}</span>')
    if ev["id"] in ctx.lolbin_ids:
        out.append('<span class="fl fl-lol">⚑ LOLBAS</span>')
    if ev.get("clock_offset_seconds") is not None:
        out.append(f'<span class="fl fl-clk">⏱ CLOCK {esc(offset_s(ev["clock_offset_seconds"]))} · CORRECTED</span>')
    return "".join(out)


def provenance(ctx: Ctx, ev: dict) -> list:
    """Source, origin, exhibit, parser and the device-recorded time, as short strings."""
    bits = [ev.get("source"), ORIGIN.get(ev.get("origin"), ev.get("origin")), ev.get("evidence_identifier")]
    if ev.get("parser_name"):
        bits.append(" ".join(x for x in (ev["parser_name"], ev.get("parser_version")) if x))
    if ev.get("recorded_event_time"):
        bits.append(f"recorded {hms(ctx, ev['recorded_event_time'])}")
    return [b for b in bits if b]


def place_labels(items: list, levels: int = 2, char_w: float = 6.2) -> list:
    """items: [(x, text, x_min, x_max)] — one-line labels for marks at x. Each goes right of its mark if it
    fits inside [x_min, x_max] and clear of the labels already on that level, else left, on the first level
    that has room (level 0 first). Returns [(x, text, label_left, level)] in x order."""
    taken, out = [], []
    for x, text, x_min, x_max in sorted(items, key=lambda it: it[0]):
        w = len(text) * char_w + 6
        spot = None
        for level in range(levels):
            for lx in (x + 7, x - 7 - w):
                if lx >= x_min and lx + w <= x_max and all(
                        lx >= r + 6 or lx + w <= l - 6 for l, r, lv in taken if lv == level):
                    spot = (lx, level)
                    break
            if spot:
                break
        spot = spot or (x + 7, levels - 1)
        taken.append((spot[0], spot[0] + w, spot[1]))
        out.append((x, text, spot[0], spot[1]))
    return out


def milestone_strip(ctx: Ctx) -> str:
    ms = milestones(ctx.inc)
    if not ms:
        return ""
    parts = []
    for i, (k, label, t) in enumerate(ms):
        if i:
            gap = (t - ms[i - 1][2]).total_seconds()
            parts.append(f'<div class="ms-gap"><span>{esc(dur(gap))} {esc(_PHRASE[k])}</span></div>')
        parts.append(f'<div class="ms-step"><div class="ms-k">◆ {esc(label)}</div>'
                     f'<div class="ms-t mono">{hms(ctx, t)}</div><div class="ms-d">{esc(day_short(ctx, t))}</div></div>')
    return f'<div class="ms" aria-label="Incident milestones">{"".join(parts)}</div>'


def legend(items: list) -> str:
    """items: [(swatch html, label)]."""
    cells = "".join(f'<span class="lg-i">{sw}<span>{esc(label)}</span></span>' for sw, label in items)
    return f'<div class="lg" aria-label="Legend">{cells}</div>'


EMPTY = '<p class="empty">No timeline events match this export.</p>'

TOKENS = """
:root{--bg:#07080b;--surface:#0e1015;--surface-2:#14171e;--border:#1f242d;--border-strong:#2b323e;
--text:#d9dde5;--muted:#919cac;--dim:#808a99;--accent:#22d3ee;--accent-soft:rgba(34,211,238,0.12);
--crit:#f43f5e;--high:#f59e0b;--med:#a78bfa;--low:#22d3ee;--ok:#10b981;
--phase-prep:#c6a1d7;--phase-detect:#e1d695;--phase-respond:#d78f85;--phase-post:#8dc498;
--sev-crit-text:#ff4444;--sev-high-text:#ff8800;--sev-med-text:#ccaa00;--sev-low-text:#00aa44;
--font-body:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
--font-heading:"JetBrains Mono",ui-monospace,"SF Mono",Menlo,monospace;
--font-mono:"JetBrains Mono",ui-monospace,"SF Mono",Menlo,monospace;
--radius-sm:2px;--radius:4px;--radius-lg:8px;
--space-1:4px;--space-2:8px;--space-3:12px;--space-4:16px;--space-5:24px;--space-6:32px;
--shadow-sm:0 1px 0 rgba(0,0,0,0.4)}
@media print{:root{--bg:#ffffff;--surface:#ffffff;--surface-2:#f1f3f6;--border:#e5e7eb;--border-strong:#d1d5db;
--text:#111827;--muted:#505664;--dim:#5e646f;--accent:#145dce;--accent-soft:#dbeafe;
--crit:#c20212;--high:#ad3e01;--med:#975105;--low:#1a57de;--ok:#06714e;
--phase-prep:#6c4d8d;--phase-detect:#6e6110;--phase-respond:#93473b;--phase-post:#316c44;
--sev-crit-text:#bf081d;--sev-high-text:#9e5202;--sev-med-text:#7e6804;--sev-low-text:#06772f;
--shadow-sm:none}}
"""

BASE_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{background:var(--bg);color:var(--text);font-family:var(--font-body);font-size:13px;line-height:1.5}
.mono{font-family:var(--font-mono)}
.wrap{max-width:var(--page-w);margin:0 auto;padding:var(--space-5) var(--space-5) var(--space-6)}
.hd{border-bottom:2px solid var(--border-strong);padding-bottom:var(--space-4);margin-bottom:var(--space-5)}
.eyebrow{font-family:var(--font-mono);font-size:11px;letter-spacing:.2em;color:var(--dim);text-transform:uppercase}
h1{font-family:var(--font-heading);font-size:22px;line-height:1.3;color:var(--text);margin:6px 0 var(--space-3)}
h2{font-family:var(--font-heading);font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--muted);
 margin:var(--space-5) 0 var(--space-3)}
.badges{display:flex;flex-wrap:wrap;gap:var(--space-2)}
.badge{font-family:var(--font-mono);font-size:11px;font-weight:700;letter-spacing:.06em;padding:3px 10px;
 border-radius:var(--radius-sm);border:1px solid var(--border-strong);color:var(--muted);background:var(--surface)}
.badge-tlp{color:var(--c);border-color:var(--c)}
.meta{margin-top:var(--space-3);font-family:var(--font-mono);font-size:11px;color:var(--dim)}
.ft{margin-top:var(--space-6);padding-top:var(--space-4);border-top:1px solid var(--border);font-family:var(--font-mono);
 font-size:10px;color:var(--dim);display:flex;justify-content:space-between;flex-wrap:wrap;gap:var(--space-2)}
.empty{padding:60px 0;text-align:center;color:var(--dim);font-family:var(--font-mono)}
.g{font-weight:700}
.att{display:inline-block;font-family:var(--font-mono);font-size:10px;font-weight:600;padding:1px 7px;
 border-radius:var(--radius-sm);color:var(--c);border:1px solid var(--c);
 background:color-mix(in srgb,var(--c) 10%,transparent)}
.fl{display:inline-block;font-family:var(--font-mono);font-size:9.5px;font-weight:700;letter-spacing:.04em;
 padding:1px 6px;border-radius:var(--radius-sm);border:1px solid var(--border-strong);color:var(--muted);
 white-space:nowrap}
.fl-key{color:var(--accent);border-color:var(--accent)}
.fl-lol{color:var(--high);border-color:var(--high)}
.fl-clk{color:var(--high);border-color:var(--high)}
.ms{display:flex;align-items:stretch;flex-wrap:wrap;gap:var(--space-2);margin-bottom:var(--space-5)}
.ms-step{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:6px 12px}
.ms-k{font-family:var(--font-mono);font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.ms-t{font-size:13px;font-weight:700;color:var(--text)}
.ms-d{font-size:10px;color:var(--dim)}
.ms-gap{display:flex;align-items:center;font-family:var(--font-mono);font-size:10px;color:var(--dim)}
.ms-gap span{border-top:1px dashed var(--border-strong);padding-top:2px}
.lg{display:flex;flex-wrap:wrap;gap:var(--space-2) var(--space-4);margin-top:var(--space-5);padding:var(--space-3);
 border:1px solid var(--border);border-radius:var(--radius);font-size:11px;color:var(--muted)}
.lg-i{display:inline-flex;align-items:center;gap:6px}
.raw{font-family:var(--font-mono);font-size:10px;line-height:1.45;color:var(--muted);background:var(--bg);
 border:1px solid var(--border);border-radius:var(--radius-sm);padding:var(--space-2);margin-top:var(--space-2);
 white-space:pre-wrap;word-break:break-all;max-height:220px;overflow:auto}
@media print{.raw{max-height:none;overflow:visible}.wrap{max-width:none;padding:0}}
"""


def _tz_label(ctx: Ctx) -> str:
    """times in Europe/Stockholm (UTC+02:00), or (UTC+02:00 → UTC+01:00) when the export spans a DST change."""
    if ctx.tz_name == "UTC" or not ctx.events:
        return f"times in {ctx.tz_name}"
    a, b = (utc_offset(ctx, ctx.events[i]["event_time"]) for i in (0, -1))
    return f"times in {ctx.tz_name} ({a}{' → ' + b if b != a else ''})"


def page(ctx: Ctx, layout: str, body: str, css: str = "", width: int = 1100) -> str:
    """The complete document: header (incident, badges, export facts), the layout body, footer."""
    inc = ctx.inc
    ref, title = inc.get("ref") or "", inc.get("title") or ""
    n = len(ctx.events)
    k = sum(1 for e in ctx.events if e.get("key_event"))
    sev = (inc.get("severity") or "").lower()
    tlp_label, tlp_var = TLP.get((inc.get("tlp") or "").lower(), ("", ""))
    badges = [f'<span class="badge">{esc(ref)}</span>' if ref else ""]
    if sev:
        badges.append(f'<span class="badge" style="{sev_style(sev)}">{esc(sev.upper())}</span>')
    if tlp_label:
        badges.append(f'<span class="badge badge-tlp" style="--c:var({tlp_var})">{esc(tlp_label)}</span>')
    badges.append(f'<span class="badge">{n} event{"" if n == 1 else "s"} · {k} key</span>')
    meta = [f"Exported {iso_z(ctx.exported_at)}"]
    if ctx.exported_by:
        meta.append(f"by {ctx.exported_by}")
    meta.append(_tz_label(ctx))
    meta += ctx.filters
    tlp_foot = f"<span>{esc(tlp_label)} — handle accordingly</span>" if tlp_label else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer">
<title>Timeline · {esc(ref)} {esc(title)}</title>
<style>{TOKENS}{BASE_CSS}{css}</style>
</head>
<body style="--page-w:{width}px">
<div class="wrap">
<header class="hd">
  <div class="eyebrow">DFIR-FENRIR // Incident timeline · {esc(LAYOUT_NAMES[layout])}</div>
  <h1>{esc(title)}</h1>
  <div class="badges">{"".join(badges)}</div>
  <div class="meta">{esc(" · ".join(meta))}</div>
</header>
<main>
{body}
</main>
<footer class="ft"><span>DFIR-FENRIR v2 · {esc(ref)}</span>{tlp_foot}<span>Generated {esc(iso_z(ctx.exported_at))}</span></footer>
</div>
</body>
</html>
"""
