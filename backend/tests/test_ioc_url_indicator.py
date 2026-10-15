"""URL/domain sorting (core/url_indicator.py), the Defender IOC export and the email analyser's
`urls[].ioc_type` (2026-10-15).

stdlib unittest (the backend image has no pytest). No DB: the dummy DATABASE_URL only satisfies
settings at import. Run in a throwaway backend container with no network, from the repo root:

    docker run --rm --network none --read-only --tmpfs /tmp -v "$PWD/backend:/src:ro" \
      -w /src -e PYTHONPATH=/src -e PYTHONDONTWRITEBYTECODE=1 \
      -e DATABASE_URL=postgresql+asyncpg://x:y@127.0.0.1:1/z \
      --entrypoint python dfir-fenrir-v2-backend:local -m unittest tests.test_ioc_url_indicator -v
"""
import csv
import inspect
import io
import json
import unittest
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

from core.url_indicator import classify_url_indicator
from iocs import exports
from schemas import EmailAnalysisOut


def _ioc(type_, value):
    return SimpleNamespace(type=type_, value=value, notes=None, tags=[])


def _csv_rows(iocs, action="Block", generate_alert=True, expiry_days=90):
    resp = exports._export_mde_csv(iocs, "abcd1234", action, "Medium", expiry_days, "", generate_alert)
    return list(csv.DictReader(io.StringIO(resp.body.decode("utf-8-sig"))))


def _json_items(iocs, action="Block", generate_alert=True):
    resp = exports._export_mde_json(iocs, "abcd1234", action, "Medium", 90, "", generate_alert)
    return json.loads(resp.body)


class ClassifyTest(unittest.TestCase):
    def test_bare_host_is_domain(self):
        for v in ("evil.example", "https://evil.example", "https://evil.example/", "http://Evil.Example.:8080/",
                  "hxxps://evil[.]example/", "https://user@evil.example/"):
            self.assertEqual(classify_url_indicator(v)[0], "domain", v)
        self.assertEqual(classify_url_indicator("https://Evil.Example/"), ("domain", "evil.example"))

    def test_path_or_query_is_full_url(self):
        self.assertEqual(classify_url_indicator("https://evil.example/page"), ("url", "https://evil.example/page"))
        self.assertEqual(classify_url_indicator("http://evil.example/?id=1"), ("url", "http://evil.example/?id=1"))
        self.assertEqual(classify_url_indicator("evil.example/page"), ("url", "https://evil.example/page"))
        self.assertEqual(classify_url_indicator("hxxp://evil[.]example/a.exe"), ("url", "http://evil.example/a.exe"))

    def test_ip_host(self):
        self.assertEqual(classify_url_indicator("http://203.0.113.5/"), ("ip", "203.0.113.5"))
        self.assertEqual(classify_url_indicator("http://203.0.113.5/x"), ("url", "http://203.0.113.5/x"))

    def test_no_host(self):
        for v in ("", "   ", "https://", "https:///path"):
            self.assertIsNone(classify_url_indicator(v), v)


class MdeExportTest(unittest.TestCase):
    def test_default_action_is_block(self):
        self.assertEqual(inspect.signature(exports.export_iocs).parameters["action"].default.default, "Block")

    def test_url_and_domain_sorted_by_value(self):
        rows = _csv_rows([_ioc("url", "https://evil.example/page"), _ioc("domain", "https://other.example/"),
                          _ioc("url", "phish.example"), _ioc("domain", "dl.example/a.exe"),
                          _ioc("url", "http://203.0.113.5/")])
        self.assertEqual([(r["IndicatorType"], r["IndicatorValue"]) for r in rows], [
            ("Url", "https://evil.example/page"), ("DomainName", "other.example"),
            ("DomainName", "phish.example"), ("Url", "https://dl.example/a.exe"), ("IpAddress", "203.0.113.5")])

    def test_same_indicator_once(self):
        rows = _csv_rows([_ioc("url", "https://evil.example/"), _ioc("domain", "evil.example")])
        self.assertEqual([(r["IndicatorType"], r["IndicatorValue"]) for r in rows], [("DomainName", "evil.example")])

    def test_csv_syntax(self):
        rows = _csv_rows([_ioc("hash_md5", "a" * 32), _ioc("hash_sha256", "b" * 64), _ioc("domain", "evil.example")])
        self.assertEqual([r["IndicatorType"] for r in rows], ["FileSha256", "DomainName"])   # no FileMd5 in the CSV import
        exp = rows[0]["ExpirationTime"]
        self.assertTrue(exp.endswith(".0Z"), exp)
        datetime.strptime(exp, "%Y-%m-%dT%H:%M:%S.0Z")
        self.assertEqual({r["Action"] for r in rows}, {"Block"})
        self.assertEqual({r["GenerateAlert"] for r in rows}, {"True"})
        self.assertEqual(_csv_rows([_ioc("ip", "203.0.113.5")], expiry_days=0)[0]["ExpirationTime"], "")

    def test_block_and_remediate_only_for_hashes(self):
        rows = _csv_rows([_ioc("hash_sha1", "c" * 40), _ioc("ip", "203.0.113.5"), _ioc("url", "https://e.example/x")],
                         action="BlockAndRemediate")
        self.assertEqual([r["Action"] for r in rows], ["BlockAndRemediate", "Block", "Block"])
        items = _json_items([_ioc("hash_sha1", "c" * 40), _ioc("domain", "e.example")], action="BlockAndRemediate")
        self.assertEqual([i["action"] for i in items["Indicators"]], ["BlockAndRemediate", "Block"])

    def test_audit_forces_generate_alert(self):
        self.assertEqual(_csv_rows([_ioc("ip", "203.0.113.5")], action="Audit", generate_alert=False)[0]["GenerateAlert"], "True")
        self.assertEqual(_csv_rows([_ioc("ip", "203.0.113.5")], action="Block", generate_alert=False)[0]["GenerateAlert"], "False")
        self.assertIs(_json_items([_ioc("ip", "203.0.113.5")], action="Audit", generate_alert=False)["Indicators"][0]["generateAlert"], True)

    def test_json_is_import_api_body(self):
        body = _json_items([_ioc("hash_md5", "a" * 32), _ioc("url", "https://evil.example/page")])
        self.assertEqual(list(body), ["Indicators"])
        self.assertEqual([(i["indicatorType"], i["indicatorValue"]) for i in body["Indicators"]],
                         [("FileMd5", "a" * 32), ("Url", "https://evil.example/page")])


class EmailUrlRowsTest(unittest.TestCase):
    def _out(self, urls):
        return EmailAnalysisOut(id=uuid.uuid4(), incident_id=uuid.uuid4(), verdict="green", score=0,
                                created_at=datetime.now(timezone.utc), urls=urls)

    def test_rows_carry_what_they_promote_as(self):
        out = self._out([
            {"url": "https://evil.example/login?x=1", "host": "evil.example"},
            {"url": "https://evil.example/", "host": "evil.example"},
            {"url": "https://eur01.safelinks.protection.outlook.com/?url=x", "host": "eur01.safelinks.protection.outlook.com",
             "safelink_target": "https://target.example/a", "safelink_host": "target.example"},
        ])
        self.assertEqual([(u["ioc_type"], u["ioc_value"]) for u in out.urls], [
            ("url", "https://evil.example/login?x=1"), ("domain", "evil.example"), ("url", "https://target.example/a")])
        self.assertEqual(out.urls[0]["host"], "evil.example")   # the stored row is kept


if __name__ == "__main__":
    unittest.main()
