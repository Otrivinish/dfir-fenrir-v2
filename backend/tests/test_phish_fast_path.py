"""Phishing fast path (docs/phishing-fast-path-slices.md): pure parts. P1 candidates, P2 KQL, P3 plan.

stdlib unittest (the backend image has no pytest). No DB: the dummy DATABASE_URL only satisfies settings
at import. Run in a throwaway backend container with no network, from the repo root:

    docker run --rm --network none --read-only --tmpfs /tmp -v "$PWD/backend:/src:ro" \\
      -w /src -e PYTHONPATH=/src -e PYTHONDONTWRITEBYTECODE=1 \\
      -e DATABASE_URL=postgresql+asyncpg://x:y@127.0.0.1:1/z \\
      --entrypoint python dfir-fenrir-v2-backend:local -m unittest tests.test_phish_fast_path -v
"""
import random
import re
import unittest
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

from email_analyzer.containment import plan
from email_analyzer.hunting import hunting_queries, kql_literal
from email_analyzer.indicators import MAX_CANDIDATES, candidates


def analysis(**kw):
    base = dict(from_addr="Billing <billing@evil.example>", reply_to=None, return_path=None,
                headers={}, urls=[], attachments=[])
    base.update(kw)
    return SimpleNamespace(**base)


def full(**kw):
    a = analysis(**kw)
    a.id, a.subject, a.message_id = uuid.UUID(int=1), kw.get("subject", "Invoice 4471"), kw.get("message_id", "<m1@evil.example>")
    return a


def pairs(a):
    return [(c.source, c.ref, c.type, c.value) for c in candidates(a)]


class CandidatesTest(unittest.TestCase):
    def test_sender_reply_to_return_path(self):
        got = pairs(analysis(from_addr="billing@Evil.Example", reply_to="<pay@other.example>",
                             return_path="<bounce@evil.example>"))
        self.assertEqual(got, [
            ("sender", None, "email", "billing@evil.example"), ("sender", None, "domain", "evil.example"),
            ("reply_to", None, "email", "pay@other.example"), ("reply_to", None, "domain", "other.example"),
            ("return_path", None, "email", "bounce@evil.example")])   # same domain as the sender: once

    def test_only_public_origin_ips(self):
        got = pairs(analysis(from_addr=None, headers={"origin_ip": "10.0.0.5", "x_originating_ip": "45.33.32.156"}))
        self.assertEqual(got, [("x_originating_ip", None, "ip", "45.33.32.156")])

    def test_attachments_then_links(self):
        got = pairs(analysis(from_addr=None,
                             attachments=[{"sha256": "A" * 64, "md5": "b" * 32}],
                             urls=[{"url": "https://login.evil.example/x?a=1"},
                                   {"url": "https://eur01.safelinks.protection.outlook.com/?url=x",
                                    "safelink_target": "https://evil.example/"},
                                   {"url": "http://203.0.113.5/p"}]))
        self.assertEqual(got, [
            ("attachment", 0, "hash_sha256", "a" * 64), ("attachment", 0, "hash_md5", "b" * 32),
            ("url", 0, "url", "https://login.evil.example/x?a=1"),
            ("url_host", 0, "domain", "login.evil.example"), ("url_host", 0, "domain", "evil.example"),
            # The Safelink row is its target, a bare domain: listed for row 1 too, but once (not again as its host).
            ("url", 1, "domain", "evil.example"),
            ("url", 2, "url", "http://203.0.113.5/p"), ("url_host", 2, "ip", "203.0.113.5")])

    def test_each_row_keeps_its_entries(self):
        got = pairs(analysis(from_addr="a@evil.example", urls=[{"url": "https://evil.example/x"}]))
        self.assertIn(("sender", None, "domain", "evil.example"), got)
        self.assertIn(("url_host", 0, "domain", "evil.example"), got)   # the link row still gets its host

    def test_bounded(self):
        urls = [{"url": f"https://h{i}.example/p"} for i in range(500)]
        self.assertEqual(len(candidates(analysis(urls=urls))), MAX_CANDIDATES)
        self.assertEqual(candidates(analysis(urls=urls))[0].source, "sender")   # header indicators first

    def test_junk_skipped(self):
        self.assertEqual(pairs(analysis(from_addr="not an address", urls=[{"url": "https://"}])), [])


LITERAL = re.compile(r'^"(?:[^"\\\x00-\x1f\x7f]|\\.)*"$')


def decode(lit):
    """Decode a KQL regular string literal of the forms kql_literal writes."""
    body, out, i = lit[1:-1], [], 0
    while i < len(body):
        if body[i] == "\\":
            if body[i + 1] == "u":
                out.append(chr(int(body[i + 2:i + 6], 16)))
                i += 6
            else:
                out.append(body[i + 1])
                i += 2
        else:
            out.append(body[i])
            i += 1
    return "".join(out)


class KqlLiteralTest(unittest.TestCase):
    HOSTILE = ['x" | take 1 //', "a\\b", "line1\nline2\r\n", "\u202eexe.pdf", "tab\there", "\u2028sep",
               "emoji 🎣", "nul\x00", "\ufeffbom", '"; DeviceEvents | where 1==1 //']

    def check(self, v):
        lit = kql_literal(v)
        self.assertRegex(lit, LITERAL)
        self.assertEqual(decode(lit), v)
        self.assertFalse(any(ord(ch) < 32 or ch in "\u202e\u2028\u2029\ufeff" for ch in lit), repr(lit))

    def test_hostile_values_round_trip(self):
        for v in self.HOSTILE:
            self.check(v)

    def test_fuzz(self):
        rnd = random.Random(1015)
        alphabet = 'ab"\\|/;\n\r\t\x00\u202e\u2028é漢🎣\u200b'
        for _ in range(500):
            self.check("".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 40))))

    def test_refused(self):
        self.assertIsNone(kql_literal("x" * 2049))
        self.assertIsNone(kql_literal("tag\U000e0041"))       # invisible tag char outside the BMP


class HuntingQueriesTest(unittest.TestCase):
    NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)

    def run_q(self, a, days=30):
        return hunting_queries(a, incident_ref="INC-2026-00012", lookback_days=days, now=self.NOW)

    def test_full_email_has_all_six(self):
        out = self.run_q(full(return_path="<b@evil.example>", urls=[{"url": "https://evil.example/login?x=1"}],
                              attachments=[{"filename": "inv.html", "sha256": "a" * 64, "md5": "b" * 32}]))
        self.assertEqual([q["id"] for q in out["queries"]],
                         ["delivery", "similar", "url_recipients", "clicks", "attachments_mail", "attachments_endpoint"])
        self.assertEqual(out["skipped"], [])
        q = {x["id"]: x["kql"] for x in out["queries"]}
        self.assertIn('let message_ids = pack_array("<m1@evil.example>", "m1@evil.example");', q["delivery"])
        self.assertIn("let lookback = 30d;", q["delivery"])
        self.assertNotIn("let hosts", q["delivery"])                     # only the lets a query uses
        self.assertIn("NetworkMessageId in (msg)", q["clicks"])
        self.assertLess(q["clicks"].index("// Remove any legitimate host"), q["clicks"].index("let hosts"))
        self.assertIn("MD5 in~ (md5s)", q["attachments_endpoint"])
        self.assertNotIn("FileName", q["attachments_endpoint"].split("| project")[0])   # hashes only on devices

    def test_skips(self):
        out = self.run_q(full(from_addr=None, message_id=None, subject=None))
        self.assertEqual([s["id"] for s in out["skipped"]],
                         ["delivery", "similar", "url_recipients", "clicks", "attachments_mail", "attachments_endpoint"])

    def test_hostile_values_stay_in_their_lets(self):
        evil = 'Pay now"\n| take 0 //\u202e'
        out = self.run_q(full(subject=evil, urls=[{"url": 'https://evil.example/a"\nb'}],
                              attachments=[{"filename": 'x"\n.html', "sha256": "a" * 64, "md5": "b" * 32}]))
        for q in out["queries"]:
            lines = q["kql"].split("\n")
            self.assertTrue(lines[0].startswith("// FENRIR INC-2026-00012 · email analysis "))
            for ln in lines:
                self.assertFalse(any(ord(ch) < 32 or ch == "\u202e" for ch in ln), repr(ln))
                if ln.startswith("//"):
                    self.assertNotIn("Pay now", ln)                       # never attacker text in a comment
            subj = [ln for ln in lines if ln.startswith("let subject")]
            if subj:
                self.assertEqual(decode(subj[0][len("let subject = "):-1]), evil)


LIVE_OK = {"domain": "evil.example", "dmarc": {"found": True}, "ip_in_spf": True}


def planned(**kw):
    kw.setdefault("verdict", "red")
    kw.setdefault("findings", [])
    a = analysis(**{k: v for k, v in kw.items() if k not in ("verdict", "findings", "strong", "auth_verified")})
    a.verdict, a.findings, a.auth_verified = kw["verdict"], kw["findings"], kw.get("auth_verified")
    return {(i["kind"], i["ref"]): i for i in plan(a, kw.get("strong", frozenset()))}


class PlanTest(unittest.TestCase):
    def test_forged_sender_never_suggested(self):
        p = planned(from_addr="ceo@partner.example", headers={"auth": {"dmarc": "fail"}},
                    findings=[{"code": "dmarc_fail"}])
        self.assertFalse(p[("sender", None)]["suggested"])
        self.assertIn("forged", p[("sender", None)]["reason"])
        self.assertFalse(p[("sender_domain", None)]["suggested"])

    def test_authenticated_sender_on_red(self):
        p = planned(from_addr="billing@evil.example", headers={"auth": {"dmarc": "pass"}}, auth_verified=LIVE_OK)
        self.assertTrue(p[("sender", None)]["suggested"])
        self.assertEqual(p[("sender", None)]["template_id"], "block_sender")
        amber = planned(from_addr="b@evil.example", verdict="amber", headers={"auth": {"dmarc": "pass"}},
                        auth_verified=LIVE_OK)
        self.assertFalse(amber[("sender", None)]["suggested"])            # amber: the analyst decides

    def test_header_only_dmarc_pass_not_trusted(self):
        for av, codes in ((None, []), ({"skipped": "dark"}, []), (LIVE_OK, [{"code": "dmarc_claim_unverified"}]),
                          ({"error": "timeout"}, [])):
            p = planned(from_addr="ceo@partner.example", headers={"auth": {"dmarc": "pass"}}, auth_verified=av,
                        findings=codes)
            self.assertFalse(p[("sender", None)]["suggested"], av)
            self.assertIn("may be forged", p[("sender", None)]["reason"])

    def test_lookalike_domain_and_reply_to(self):
        p = planned(from_addr="a@xn--pple-43d.com", reply_to="pay@other.example",
                    findings=[{"code": "punycode_from"}, {"code": "replyto_mismatch"}])
        self.assertTrue(p[("sender_domain", None)]["suggested"])
        self.assertTrue(p[("reply_to", None)]["suggested"])

    def test_links_by_signal_and_seen_before(self):
        urls = [{"url": "https://evil.example/login", "host": "evil.example", "display_host": "bank.example"},
                {"url": "https://www.microsoft.com/privacy", "host": "www.microsoft.com"},
                {"url": "https://known.example/", "host": "known.example"}]
        p = planned(from_addr=None, urls=urls, strong=frozenset({("domain", "known.example")}))
        # A risk signal alone never pre-ticks a link: the attacker can point it at a legitimate site.
        self.assertEqual((p[("url", 0)]["template_id"], p[("url", 0)]["suggested"]), ("block_url", False))
        self.assertTrue(p[("url", 0)]["reason"].startswith("Link text hides its true destination. Check it isn't"))
        self.assertFalse(p[("url", 1)]["suggested"])                      # an unflagged legitimate link
        self.assertEqual((p[("url", 2)]["template_id"], p[("url", 2)]["suggested"]), ("block_domain", True))

    def test_attachment_origin_message(self):
        p = planned(from_addr=None, headers={"origin_ip": "45.33.32.156"}, verdict="green",
                    attachments=[{"filename": "inv.pdf.exe", "sha256": "A" * 64}])
        self.assertTrue(p[("attachment", 0)]["suggested"])
        self.assertEqual(p[("attachment", 0)]["value"], "a" * 64)
        self.assertFalse(p[("origin_ip", None)]["suggested"])
        self.assertFalse(p[("message", None)]["suggested"])              # green verdict

    def test_duplicates_keep_the_strongest_row(self):
        p = plan(SimpleNamespace(from_addr=None, reply_to=None, return_path=None, verdict="red", findings=[],
                                 headers={}, urls=[], auth_verified=None,
                                 attachments=[{"filename": "a.pdf", "sha256": "c" * 64},
                                              {"filename": "a.pdf.exe", "sha256": "c" * 64}]))
        att = [i for i in p if i["kind"] == "attachment"]
        self.assertEqual(len(att), 1)
        self.assertTrue(att[0]["suggested"])                                # from row 1's signal
        self.assertEqual(att[0]["ref"], 0)

    def test_over_long_value_left_out(self):
        p = planned(from_addr=None, urls=[{"url": "https://evil.example/" + "x" * 2100}],
                    strong=frozenset())
        self.assertNotIn(("url", 0), p)

    def test_same_value_two_templates(self):
        p = plan(SimpleNamespace(from_addr="x@evil.example", reply_to=None, return_path=None, verdict="red",
                                 findings=[], headers={}, attachments=[], auth_verified=None,
                                 urls=[{"url": "https://evil.example/"}]))
        self.assertEqual(sorted(i["template_id"] for i in p if i["value"] == "evil.example"),
                         ["block_domain", "block_sender"])                 # one IOC, two different actions


if __name__ == "__main__":
    unittest.main()
