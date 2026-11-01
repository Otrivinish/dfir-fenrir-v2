"""TX — timeline export layouts (docs/timeline-export-layouts-slice.md): the pure renderers and the CSV.

stdlib unittest (the backend image has no pytest). No DB: the dummy DATABASE_URL only satisfies settings
at import. Run in a throwaway backend container with no network, from the repo root:

    docker run --rm --network none --read-only --tmpfs /tmp -v "$PWD/backend:/src:ro" \\
      -w /src -e PYTHONPATH=/src -e PYTHONDONTWRITEBYTECODE=1 \\
      -e DATABASE_URL=postgresql+asyncpg://x:y@127.0.0.1:1/z \\
      --entrypoint python dfir-fenrir-v2-backend:local -m unittest tests.test_timeline_export -v
"""
import csv
import io
import re
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from timeline.export import CSV_COLUMNS, LAYOUTS, RAW_LAYOUTS, Ctx, render_csv, render_html
from timeline.export import horizon, swimlanes
from timeline.export.brief import MAX_MOMENTS, _moments
from timeline.export.common import bursts, delta, dur, periods

UTC = timezone.utc
INC = uuid.UUID(int=42)


def T(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def ent(n, typ, value, compromised=False, **kw):
    return {"id": uuid.UUID(int=1000 + n), "type": typ, "value": value, "compromised": compromised, **kw}


WS = ent(1, "host", "WS-FIN-017", True, criticality="high")
SRV = ent(2, "host", "SRV-FS-02", True, criticality="critical")
EXCH = ent(3, "host", "EXCH-01")
IOC = {"id": uuid.UUID(int=2001), "type": "ip", "value": "185.220.101.47", "malicious": True}
ENTITIES = {e["id"]: {k: e.get(k) for k in ("type", "value", "name", "compromised", "criticality")}
            for e in (WS, SRV, EXCH)}


def ev(n, t, desc, entity=None, tactic=None, tech=None, **kw):
    base = dict(id=uuid.UUID(int=n), incident_id=INC, event_time=T(t), hostname=entity["value"] if entity else None,
                entity_id=entity["id"] if entity else None,
                entity={k: entity[k] for k in ("id", "type", "value", "compromised")} if entity else None,
                source=None, event_type=None, description=desc, raw_log=None, ir_phase="detection_and_analysis",
                mitre_tactic_id=tactic, mitre_tactic_name=None, mitre_technique_id=tech,
                mitre_technique_name=None, origin="manual", is_system=False, system_source=None,
                server_generated=False, is_key=False, linked_iocs=[], evidence_identifier=None, parser_name=None,
                parser_version=None, time_basis=None, recorded_event_time=None, clock_offset_seconds=None,
                created_by_username="irw-analyst")
    base.update(kw)
    base.setdefault("key_event", bool(base["is_key"] or base["mitre_tactic_id"] or base["mitre_technique_id"]
                                      or base["server_generated"]))
    return base


def phish_events():
    """The design sample INC-2026-00042 — invoice phish, one long day plus recovery the next day."""
    cer = "containment_eradication_recovery"
    return [
        ev(1, "2026-10-14T08:12:41Z", "Invoice_4471.docm delivered from billing@evil.example", EXCH, "TA0001",
           "T1566.001", event_type="Email delivered", mitre_tactic_name="Initial Access"),
        ev(2, "2026-10-14T08:19:02Z", "WINWORD spawned powershell -enc …", WS, "TA0002", "T1059.001",
           event_type="Process Execution", raw_log="EID 4104 ScriptBlock: $p='SECRET-RAW-TOKEN'", origin="forensic_import",
           evidence_identifier="EV-0003", parser_name="FENRIR timeline parser", parser_version="2.4"),
        ev(3, "2026-10-14T08:20:11Z", "Scheduled task OneDriveSync created", WS, "TA0003", "T1053.005"),
        ev(4, "2026-10-14T08:22:40Z", "rundll32 loaded C:\\Users\\Public\\x.dll", WS, "TA0005", "T1218.011"),
        ev(5, "2026-10-14T08:24:05Z", "Beacon to 185.220.101.47:443", WS, "TA0011", "T1071.001", linked_iocs=[IOC]),
        ev(6, "2026-10-14T09:31:10Z", "LSASS memory read by rundll32", WS, "TA0006", "T1003.001"),
        ev(7, "2026-10-14T10:15:28Z", "svc_backup logon over SMB (ADMIN$)", SRV, "TA0008", "T1021.002",
           recorded_event_time=T("2026-10-14T10:17:42Z"), clock_offset_seconds=134, origin="forensic_import",
           evidence_identifier="EV-0005", time_basis="explicit"),
        ev(8, "2026-10-14T10:52:00Z", "7z archive of \\\\SRV-FS-02\\Finance", SRV, "TA0009", "T1560.001"),
        ev(9, "2026-10-14T11:01:30Z", "3.8 GB uploaded to 185.220.101.47", SRV, "TA0010", "T1041", linked_iocs=[IOC]),
        ev(10, "2026-10-14T11:05:22Z", "Milestone: Detected", None, origin="system", is_system=True,
           system_source="milestone", server_generated=True, ir_phase=None),
        ev(11, "2026-10-14T11:20:00Z", "Alert triaged; incident declared", None),
        ev(12, "2026-10-14T12:03:00Z", "[Containment] Isolate host → WS-FIN-017", WS, source="Respond",
           ir_phase=cer, is_system=True, system_source="respond_action", server_generated=True, origin="system"),
        ev(13, "2026-10-14T12:10:00Z", "SRV-FS-02 isolated", SRV, ir_phase=cer),
        ev(14, "2026-10-14T12:20:00Z", "Firewall blocks 185.220.101.47", None, ir_phase=cer, linked_iocs=[IOC]),
        ev(15, "2026-10-15T09:30:00Z", "WS-FIN-017 reimaged", WS, ir_phase=cer, is_key=True),
        ev(16, "2026-10-15T14:00:00Z", "Finance share back in service", SRV, ir_phase=cer),
    ]


def multi_day_events():
    """The design sample INC-2026-00051 — dormant implant, five active periods over eight days."""
    out, n = [], 100
    plan = [("2026-10-01T14:00:00Z", 5, 18), ("2026-10-05T02:30:00Z", 4, 25), ("2026-10-07T01:50:00Z", 3, 30),
            ("2026-10-07T09:00:00Z", 6, 55), ("2026-10-09T08:00:00Z", 3, 25)]
    tactics = ["TA0011", "TA0007", "TA0006", "TA0009", "TA0010"]
    for pi, (start, count, step) in enumerate(plan):
        for i in range(count):
            n += 1
            t = T(start) + timedelta(minutes=i * step)
            out.append(ev(n, t.strftime("%Y-%m-%dT%H:%M:%SZ"), f"Period {pi} event {i}", WS, tactics[pi]))
    return out


def inc(**kw):
    base = dict(ref="INC-2026-00042", title="Finance workstation compromise via invoice phish", severity="high",
                tlp="amber", status="open", phase="containment_eradication_recovery",
                occurred_at=T("2026-10-14T08:12:41Z"), detected_at=T("2026-10-14T11:05:22Z"),
                contained_at=T("2026-10-14T12:03:00Z"), eradicated_at=None, recovered_at=T("2026-10-15T14:00:00Z"))
    base.update(kw)
    return base


def ctx(events=None, tz="UTC", raw=False, incident=None, **kw):
    zone = UTC if tz == "UTC" else ZoneInfo(tz)
    return Ctx(inc=incident or inc(), events=phish_events() if events is None else events, entities=ENTITIES,
               tz=zone, tz_name=tz, include_raw_logs=raw, exported_at=T("2026-10-31T20:00:00Z"),
               exported_by="irw-analyst", **kw)


class FormatTest(unittest.TestCase):
    def test_durations(self):
        self.assertEqual([dur(42), dur(7 * 60), dur(2 * 3600 + 53 * 60), dur(5 * 86400 + 19 * 3600 + 10 * 60)],
                         ["42s", "7m", "2h 53m", "5d 19h 10m"])
        self.assertEqual(dur(3 * 86400 + 11 * 3600 + 25 * 60, coarse=True), "3d 11h")
        self.assertEqual([delta(12), delta(7 * 60 + 5), delta(2 * 3600 + 53 * 60)], ["+12s", "+7m 05s", "+2h 53m"])

    def test_periods_fold_only_over_six_hours(self):
        evs = multi_day_events()
        self.assertEqual([len(p) for p in periods(evs)], [5, 4, 3, 6, 3])
        a = [ev(1, "2026-10-01T00:00:00Z", "a"), ev(2, "2026-10-01T06:00:00Z", "b"), ev(3, "2026-10-01T12:00:01Z", "c")]
        self.assertEqual([len(p) for p in periods(a)], [2, 1], "exactly 6 h stays in, 6 h 1 s folds")

    def test_bursts_under_ten_minutes(self):
        evs = phish_events()
        self.assertEqual([len(b) for b in bursts(evs[1:5])], [4], "08:19–08:24 is one burst")
        self.assertEqual(len(bursts([evs[0], evs[1]])), 1, "6 min 21 s apart: one card")
        gap = [ev(1, "2026-10-01T00:00:00Z", "a"), ev(2, "2026-10-01T00:10:00Z", "b")]
        self.assertEqual(len(bursts(gap)), 2, "exactly 10 min apart: two cards")


class EveryLayoutTest(unittest.TestCase):
    EVIL = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'

    def _all(self, c):
        return {layout: render_html(layout, c) for layout in LAYOUTS}

    def test_complete_documents_without_script(self):
        for evs in (phish_events(), multi_day_events(), [], phish_events()[:1]):
            for layout, doc in self._all(ctx(evs)).items():
                with self.subTest(layout=layout, n=len(evs)):
                    self.assertTrue(doc.startswith("<!DOCTYPE html>"))
                    self.assertTrue(doc.rstrip().endswith("</html>"))
                    self.assertIn("default-src 'none'", doc)
                    self.assertNotIn("<script", doc.lower())
                    self.assertIn("INC-2026-00042", doc)

    def test_every_value_is_escaped(self):
        bad_ent = ent(9, "host", self.EVIL, name=self.EVIL)
        evs = [ev(1, "2026-10-14T08:00:00Z", self.EVIL, bad_ent, "TA0002", event_type=self.EVIL, source=self.EVIL,
                  raw_log=self.EVIL, evidence_identifier=self.EVIL, parser_name=self.EVIL,
                  linked_iocs=[{"id": uuid.UUID(int=7), "type": "url", "value": self.EVIL, "malicious": True}],
                  mitre_tactic_name=self.EVIL, mitre_technique_name=self.EVIL, created_by_username=self.EVIL)]
        c = ctx(evs, raw=True, incident=inc(title=self.EVIL, ref=self.EVIL),
                filters=[self.EVIL])
        c.entities = {bad_ent["id"]: {"type": "host", "value": self.EVIL, "name": self.EVIL, "compromised": True}}
        c.exported_by = self.EVIL
        for layout, doc in self._all(c).items():
            with self.subTest(layout=layout):
                self.assertNotIn("<script>alert", doc)
                self.assertNotIn("<img src=x", doc)
                self.assertNotIn('"><img', doc)

    def test_raw_logs_only_where_asked(self):
        secret = "SECRET-RAW-TOKEN"
        off, on = self._all(ctx(raw=False)), self._all(ctx(raw=True))
        for layout in LAYOUTS:
            with self.subTest(layout=layout):
                self.assertNotIn(secret, off[layout])
                self.assertEqual(secret in on[layout], layout in RAW_LAYOUTS)

    def test_time_zone(self):
        utc, sto = ctx(tz="UTC"), ctx(tz="Europe/Stockholm")
        for layout in ("rail", "ledger"):
            with self.subTest(layout=layout):
                self.assertIn("08:12:41", render_html(layout, utc))
                doc = render_html(layout, sto)
                self.assertIn("10:12:41", doc)   # CEST, +02:00 in mid-October
                self.assertIn("UTC+02:00", doc)
                self.assertIn("times in Europe/Stockholm", doc)
        self.assertIn("2026-10-14T08:12:41Z", render_html("ledger", sto), "the span stays UTC ISO")
        for layout in LAYOUTS[:-1]:   # every layout but the original zig-zag names the offset in its header
            self.assertIn("times in Europe/Stockholm (UTC+02:00)", render_html(layout, sto))
        across = [ev(1, "2026-10-24T12:00:00Z", "before"), ev(2, "2026-10-26T12:00:00Z", "after")]   # DST ends 25 Oct
        self.assertIn("(UTC+02:00 → UTC+01:00)", render_html("brief", ctx(across, tz="Europe/Stockholm")))
        self.assertIn("times in UTC", render_html("brief", utc))

    def test_flags(self):
        doc = render_html("rail", ctx(lolbin_ids={uuid.UUID(int=2)}))
        self.assertIn("MALICIOUS · 185.220.101.47", doc)
        self.assertIn("⚑ LOLBAS", doc)
        self.assertIn("CLOCK +134 s · CORRECTED", doc)
        self.assertIn("recorded 10:17:42", doc)
        led = render_html("ledger", ctx(lolbin_ids={uuid.UUID(int=2)}, csv_sha256="ab" * 32))
        self.assertIn("ab" * 32, led)
        self.assertEqual(led.count('<td class="n">'), len(phish_events()))
        self.assertIn(">LOL<", led)

    def test_rail_milestones_phases_and_gaps(self):
        doc = render_html("rail", ctx())
        for label in ("OCCURRED", "DETECTED", "CONTAINED", "RECOVERED"):
            self.assertIn(f'class="rl-msl">{label}<', doc)
        self.assertIn("2h 53m undetected", doc)
        self.assertIn("58m to contain", doc)
        self.assertIn("Containment, Eradication &amp; Recovery", doc)
        self.assertIn('<div class="rl-gap"><span>1h 07m</span>', doc)   # 08:24:05 → 09:31:10


class HorizonTest(unittest.TestCase):
    def test_one_period_has_no_overview(self):
        evs = [e for e in phish_events() if e["event_time"] < T("2026-10-15T00:00:00Z")]
        doc = render_html("horizon", ctx(evs))
        self.assertNotIn('class="ov"', doc)
        self.assertNotIn("quiet<", doc)

    def test_multi_day_overview_breaks_and_wrap(self):
        evs = multi_day_events()
        doc = render_html("horizon", ctx(evs, incident=inc(
            occurred_at=T("2026-10-01T14:00:00Z"), detected_at=T("2026-10-07T11:05:00Z"),
            contained_at=T("2026-10-07T12:55:00Z"), recovered_at=T("2026-10-09T12:20:00Z"))))
        self.assertIn('class="ov"', doc)
        self.assertEqual(doc.count('class="ov-bar"'), 5)
        self.assertIn("3d 11h<br>quiet", doc)    # 01 Oct 15:12 → 05 Oct 02:30
        self.assertIn("Dwell 5d 21h 5m undetected", doc)
        self.assertIn("C2 open 5d 22h 55m", doc)   # first C2 event (01 Oct 14:00) until containment
        lone = [ev(1, "2026-10-01T08:00:00Z", "beacon", WS, "TA0011"), ev(2, "2026-10-02T08:00:00Z", "later", WS)]
        one = render_html("horizon", ctx(lone, incident=inc(contained_at=None, occurred_at=None, detected_at=None,
                                                             recovered_at=None)))
        self.assertIn(">C2 beacon<", one, "one C2 event, no containment: no made-up duration")
        self.assertIn("Fri 02 Oct · 08:00–08:00", one)
        self.assertIn("<b>E</b>", doc)

    def test_geometry(self):
        pers = periods(multi_day_events())
        segs, brks, nrows = horizon._layout(pers)
        self.assertGreater(nrows, 1, "five periods at 4 px/min wrap")
        for s in segs:
            self.assertLessEqual(s.x + s.w, horizon.ROW_W + 1e-6)
            self.assertAlmostEqual(s.w, (s.t1 - s.t0).total_seconds() * horizon.SCALE, places=3)
        self.assertEqual(len(brks), 4)
        long = [ev(i, (T("2026-10-01T00:00:00Z") + timedelta(minutes=50 * i)).strftime("%Y-%m-%dT%H:%M:%SZ"), "x")
                for i in range(20)]   # one 16 h period: 3840 px, so it continues over rows
        segs, _, nrows = horizon._layout(periods(long))
        self.assertGreaterEqual(nrows, 3)
        self.assertTrue(segs[0].cont_next and segs[1].cont_prev)
        placed, up, dn = horizon._place([(x, None) for x in range(0, 1200, 30)])
        tracks = {}
        for side, i, cx, _, _ in placed:
            tracks.setdefault((side, i), []).append(cx)
        for xs in tracks.values():
            xs.sort()
            self.assertTrue(all(b - a >= horizon.CARD_W + horizon.GAP_X for a, b in zip(xs, xs[1:])))


class SwimlanesTest(unittest.TestCase):
    def test_lanes(self):
        c = ctx()
        lanes, iocs = swimlanes._lanes(c)
        kinds = [k for k, _, _ in lanes]
        self.assertEqual(kinds, ["entity", "entity", "entity", "ioc", "none"])
        self.assertEqual([key for k, key, _ in lanes if k == "entity"], [EXCH["id"], WS["id"], SRV["id"]])
        self.assertEqual(sum(len(e) for _, _, e in lanes), len(phish_events()), "each event in exactly one lane")
        doc = render_html("swimlanes", c)
        self.assertIn("target only, no events of its own", doc)
        self.assertIn("No linked entity", doc)
        self.assertIn("COMPROMISED", doc)
        self.assertEqual(doc.count('class="sl-arrow"'), 3, "three events link the malicious IOC")
        self.assertIn("First seen, by ATT&amp;CK-tagged event: <b>EXCH-01</b> → <b>WS-FIN-017</b> → "
                      "<b>185.220.101.47</b> → <b>SRV-FS-02</b>", doc)

    def test_fits_the_page(self):
        geo, scale, w = swimlanes._scale(periods(multi_day_events()))
        self.assertLessEqual(w, swimlanes.PLOT_W + 1e-6)
        self.assertLessEqual(scale, swimlanes.MAX_SCALE)


class BriefTest(unittest.TestCase):
    def test_moments_capped_and_ranked(self):
        evs = [ev(i, (T("2026-10-01T00:00:00Z") + timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%SZ"), f"e{i}",
                  None, "TA0002") for i in range(30)]
        evs[25]["is_key"] = True
        evs[28]["mitre_tactic_id"] = "TA0040"
        picked, more = _moments(evs)
        self.assertEqual(len(picked), MAX_MOMENTS)
        self.assertEqual(more, 30 - MAX_MOMENTS)
        self.assertIn(evs[25], picked, "analyst-flagged first")
        self.assertIn(evs[28], picked, "first event of a tactic next")
        self.assertEqual(picked, sorted(picked, key=lambda e: e["event_time"]))

    def test_counts(self):
        doc = render_html("brief", ctx())
        self.assertIn("9 of 14 ATT&amp;CK tactics", doc)
        self.assertIn("<b>3</b><span>hosts involved</span>", doc)
        self.assertIn("<b>1</b><span>malicious IOC linked</span>", doc)


class CsvTest(unittest.TestCase):
    def rows(self, raw):
        evs = [dict(e, event_time=e["event_time"].strftime("%Y-%m-%dT%H:%M:%SZ")) for e in phish_events()]
        evs[0]["description"] = "=HYPERLINK(\"http://x\")"
        return list(csv.reader(io.StringIO(render_csv(evs, raw), newline="")))

    def test_columns_escape_and_raw(self):
        rows = self.rows(False)
        self.assertEqual(tuple(rows[0]), CSV_COLUMNS)
        self.assertEqual(len(CSV_COLUMNS), 18)
        self.assertEqual(len(rows), len(phish_events()) + 1)
        self.assertEqual(rows[1][1], "'=HYPERLINK(\"http://x\")")
        raw_col = CSV_COLUMNS.index("raw_log")
        self.assertEqual(rows[2][raw_col], "")
        self.assertIn("SECRET-RAW-TOKEN", self.rows(True)[2][raw_col])
        self.assertEqual(rows[7][CSV_COLUMNS.index("clock_offset_seconds")], "134")

    def test_crlf(self):
        text = render_csv([], False)
        self.assertTrue(text.endswith("\r\n") and re.fullmatch(r"[a-z_,]+\r\n", text))


class TimeZoneNameTest(unittest.TestCase):
    """The ?tz name check (timeline/routes.py _tz_name_ok) replaced a regex CodeQL flagged (py/polynomial-redos): same
    rule, no regex, plus a length cap."""
    OLD = re.compile(r"[A-Za-z0-9_+\-]+(?:/[A-Za-z0-9_+\-]+){0,2}")

    def test_same_rule_as_the_old_regex(self):
        import random
        from timeline.routes import _tz_name_ok
        rnd = random.Random(1101)
        alphabet = "Ab0_+-/.: \\%\x00é"
        names = ["UTC", "Europe/Stockholm", "America/Argentina/ComodRivadavia", "Etc/GMT+5", "a/b/c/d", "/Europe",
                 "Europe/", "Europe//Oslo", "", "../etc/passwd", "Europe/../../etc"]
        names += ["".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 20))) for _ in range(5000)]
        for n in names:
            self.assertEqual(_tz_name_ok(n), bool(self.OLD.fullmatch(n)), repr(n))

    def test_zone(self):
        import time
        from core.errors import ApiError
        from timeline.routes import _zone
        self.assertIs(_zone("UTC"), timezone.utc)
        self.assertEqual(str(_zone("Europe/Stockholm")), "Europe/Stockholm")
        for bad in ("../etc/passwd", "Europe/Nowhere", "x" * 65, "+" * 200_000 + "!"):
            t = time.perf_counter()
            with self.assertRaises(ApiError) as cm:
                _zone(bad)
            self.assertEqual(cm.exception.code, "invalid_timezone")
            self.assertLess(time.perf_counter() - t, 0.5, bad[:20])


if __name__ == "__main__":
    unittest.main()
