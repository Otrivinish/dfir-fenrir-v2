"""S5 (EG-6, EG-7): a supporting document's capture record — the field checks every upload route and the PATCH run
(files/capture.py capture_columns), the audit values, and the Register-as-exhibit mapping onto a new draft
(exhibit_prefill, through evidence/source.py source_columns). Also the schemas: capture_sha256 read-only on the PATCH
body, the capture method enum, the link create body.

stdlib unittest; no DB, no network. From the repo root:

    docker run --rm --network none --read-only --tmpfs /tmp \
      --tmpfs /evidence:uid=1001,gid=1001 --tmpfs /asset_logs:uid=1001,gid=1001 \
      -v "$PWD/backend:/src:ro" -w /src -e PYTHONPATH=/src -e PYTHONDONTWRITEBYTECODE=1 \
      -e EVIDENCE_PATH=/evidence -e LOGS_PATH=/asset_logs \
      -e DATABASE_URL=postgresql+asyncpg://nobody:none@127.0.0.1:1/none \
      -e EVIDENCE_KEK=$(python3 -c "print('11'*32)") \
      --entrypoint python dfir-fenrir-v2-backend:local -m unittest tests.test_files_capture_s5 -v
"""
import types
import unittest
import uuid
from datetime import datetime, timedelta, timezone

from pydantic import ValidationError

from core.errors import ApiError
from files import capture
from schemas import IncidentFileUpdate, SOURCE_PATH_MAX, SupportingFileLinkCreate

UID = uuid.uuid4()
SHA = "ab" * 32


def code_of(fn, *a, **k):
    try:
        fn(*a, **k)
    except ApiError as e:
        return e.code
    return None


class CapturedAt(unittest.TestCase):
    def test_utc(self):
        for raw, want in (("2026-10-31T09:15:00Z", datetime(2026, 10, 31, 9, 15, tzinfo=timezone.utc)),
                          ("2026-10-31T10:15:00+01:00", datetime(2026, 10, 31, 9, 15, tzinfo=timezone.utc)),
                          ("2026-10-31T09:15:00.250Z", datetime(2026, 10, 31, 9, 15, 0, 250000, tzinfo=timezone.utc))):
            got = capture.captured_at_utc(raw)
            self.assertEqual(got, want, raw)
            self.assertEqual(got.utcoffset(), timedelta(0))
        self.assertIsNone(capture.captured_at_utc(None))
        self.assertIsNone(capture.captured_at_utc(""))

    def test_refused(self):
        for raw in ("2026-10-31T09:15:00", "2026-10-31", "yesterday", "31/10/2026 09:15", 1761902100,
                    " 2026-10-31T09:15:00Z"):
            self.assertEqual(code_of(capture.captured_at_utc, raw), "invalid_captured_at", raw)

    def test_future(self):
        now = datetime.now(timezone.utc)
        self.assertEqual(code_of(capture.captured_at_utc, (now + timedelta(minutes=10)).isoformat()),
                         "invalid_captured_at")
        self.assertIsNotNone(capture.captured_at_utc((now + timedelta(seconds=30)).isoformat()))   # within the skew


class Columns(unittest.TestCase):
    def test_only_the_sent_fields_verbatim(self):
        sent = {"capture_tool": "  Snagit ", "capture_source": "WS-01 ", "capture_url": " https://x.test/a b",
                "capture_method": "full_page", "capture_context": "Title: Inbox\nvisible: 3 mails"}
        self.assertEqual(capture.capture_columns(sent), sent)        # nothing trimmed or added

    def test_empty_clears(self):
        self.assertEqual(capture.capture_columns({"capture_tool": "", "captured_at": ""}),
                         {"capture_tool": None, "captured_at": None})

    def test_nul_refused(self):
        for k in ("captured_by_name", "capture_tool", "capture_tool_version", "capture_source", "capture_url",
                  "capture_context"):
            self.assertEqual(code_of(capture.capture_columns, {k: "a\x00b"}), "invalid_capture_text", k)

    def test_sha256(self):
        self.assertEqual(capture.capture_columns({"capture_sha256": " " + SHA.upper() + " "})["capture_sha256"], SHA)
        for bad in ("ab" * 16, "ab" * 20, "zz" * 32, "ab" * 33):
            self.assertEqual(code_of(capture.capture_columns, {"capture_sha256": bad}), "invalid_hash_format", bad)

    def test_capturer(self):
        self.assertEqual(code_of(capture.capture_columns, {"captured_by_id": UID, "captured_by_name": "PC Smith"}),
                         "captured_by_conflict")
        self.assertEqual(capture.capture_columns({"captured_by_id": UID}),
                         {"captured_by_id": UID, "captured_by_name": None})        # setting one clears the other
        self.assertEqual(capture.capture_columns({"captured_by_name": "PC Smith"}),
                         {"captured_by_name": "PC Smith", "captured_by_id": None})
        self.assertEqual(capture.capture_columns({"captured_by_id": None, "captured_by_name": "x"}),
                         {"captured_by_id": None, "captured_by_name": "x"})
        self.assertEqual(capture.capture_columns({}), {})                          # nobody by default

    def test_audit_values(self):
        row = types.SimpleNamespace(**{k: None for k in capture.FIELDS})
        row.captured_at = datetime(2026, 10, 31, 9, 15, 0, 500000, tzinfo=timezone.utc)
        row.captured_by_id, row.capture_sha256 = UID, SHA
        self.assertEqual(capture.audit_values(row), {"captured_at": "2026-10-31T09:15:00.500000Z",
                                                     "captured_by_id": str(UID), "capture_sha256": SHA})

    def test_editable(self):
        self.assertNotIn("capture_sha256", capture.EDITABLE)
        self.assertEqual(set(capture.EDITABLE) | {"capture_sha256"}, set(capture.FIELDS))


class Schemas(unittest.TestCase):
    def test_patch_body(self):
        self.assertIn("capture_sha256", IncidentFileUpdate(capture_sha256=None).model_fields_set)   # refused by the route
        self.assertTrue(IncidentFileUpdate.model_json_schema()["properties"]["capture_sha256"]["readOnly"])
        with self.assertRaises(ValidationError):
            IncidentFileUpdate(capture_method="screenshot")
        with self.assertRaises(ValidationError):
            IncidentFileUpdate(capture_tool="x" * 129)
        self.assertEqual(IncidentFileUpdate(capture_method="photo_of_screen").capture_method, "photo_of_screen")

    def test_link_body(self):
        with self.assertRaises(ValidationError):
            SupportingFileLinkCreate(target_type="entity", target_id=UID)
        self.assertEqual(SupportingFileLinkCreate(target_type="ioc", target_id=UID).note, None)


def file(**kw):
    base = {k: None for k in capture.FIELDS}
    return types.SimpleNamespace(**{**base, **kw})


class Prefill(unittest.TestCase):
    def test_full_mapping_https(self):
        at = datetime(2026, 10, 30, 22, 1, tzinfo=timezone.utc)
        cols, left = capture.exhibit_prefill(file(
            captured_at=at, capture_tool="Snagit", capture_tool_version="2024.1", capture_source="WS-01",
            capture_url="https://Phish.Example.COM/login?x=1", capture_context="Chrome window: fake O365 login",
            capture_method="full_page", captured_by_name="PC Smith", capture_sha256=SHA))
        self.assertEqual(left, [])
        self.assertEqual(cols, {"acquired_at": at, "acquisition_tool": "Snagit", "acquisition_tool_version": "2024.1",
                                "screen_state": "Chrome window: fake O365 login", "source_system": "WS-01",
                                "source_path": "https://Phish.Example.COM/login?x=1", "source_path_style": "cloud_uri",
                                "source_path_norm": "https://phish.example.com/login?x=1"})

    def test_http_and_app_urls_are_other(self):
        for url in ("http://phish.example/login", "ms-teams://chat/123", "about:blank", "file:///C:/x.html",
                    " https://leading-space.example/", "https:/broken"):
            cols, left = capture.exhibit_prefill(file(capture_url=url))
            self.assertEqual((cols["source_path"], cols["source_path_style"], left), (url, "other", []), url)

    def test_other_cloud_schemes(self):
        cols, _ = capture.exhibit_prefill(file(capture_url="s3://bucket/key"))
        self.assertEqual(cols["source_path_style"], "cloud_uri")

    def test_never_invents(self):
        self.assertEqual(capture.exhibit_prefill(file()), ({}, []))
        cols, _ = capture.exhibit_prefill(file(capture_tool="Greenshot"))
        self.assertEqual(cols, {"acquisition_tool": "Greenshot"})
        cols, _ = capture.exhibit_prefill(file(captured_by_name="x", capture_method="window"))
        self.assertEqual(cols, {})                     # capturer and method have no exhibit field here

    def test_capture_hash_is_the_target_hash(self):
        """Owner decision 2026-11-01: the hash at capture (compared with the bytes at upload) is the target hash."""
        cols, _ = capture.exhibit_prefill(file(capture_sha256=SHA, sha256=SHA))
        self.assertEqual(cols, {"acquisition_hash_target": SHA, "upload_hash_check": "match"})
        self.assertEqual(capture.exhibit_prefill(file(capture_sha256=SHA, sha256="0" * 64)), ({}, []))

    def test_refused_source_left_empty(self):
        long_url = "https://x.example/" + "a" * SOURCE_PATH_MAX
        cols, left = capture.exhibit_prefill(file(capture_url=long_url, capture_source="WS-01", capture_tool="T"))
        self.assertEqual(cols, {"acquisition_tool": "T", "source_system": "WS-01"})
        self.assertEqual([(x["field"], x["code"]) for x in left], [("source_path", "invalid_source_path")])
        cols, left = capture.exhibit_prefill(file(capture_source="WS\x00-01", capture_url="https://ok.example/"))
        self.assertNotIn("source_system", cols)
        self.assertEqual(cols["source_path_style"], "cloud_uri")
        self.assertEqual([(x["field"], x["code"]) for x in left], [("source_system", "invalid_source_text")])


if __name__ == "__main__":
    unittest.main()
