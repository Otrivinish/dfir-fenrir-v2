"""S4 (EG-8, EG-9, FP-2): an exhibit photo's record — taken_at validation and canonical UTC form, the photographer
rule, PATCH edits by photo id (evidence/photos.py); the output schema that never breaks on a legacy taken_at
(schemas.PhotoRef); what leaves the platform (records.photo_record) and the advisory provenance check.

stdlib unittest; no DB, no network. From the repo root:

    docker run --rm --network none --read-only --tmpfs /tmp \
      --tmpfs /evidence:uid=1001,gid=1001 --tmpfs /asset_logs:uid=1001,gid=1001 \
      -v "$PWD/backend:/src:ro" -w /src -e PYTHONPATH=/src -e PYTHONDONTWRITEBYTECODE=1 \
      -e EVIDENCE_PATH=/evidence -e LOGS_PATH=/asset_logs \
      -e DATABASE_URL=postgresql+asyncpg://nobody:none@127.0.0.1:1/none \
      -e EVIDENCE_KEK=$(python3 -c "print('11'*32)") \
      --entrypoint python dfir-fenrir-v2-backend:local -m unittest tests.test_evidence_photos_s4 -v
"""
import types
import unittest
import uuid
from datetime import datetime, timezone

from core.errors import ApiError
from evidence import photos, records
from evidence.provenance import score_evidence
from le_package.builder import _photo_ext
from schemas import PhotoRef

ME, OTHER = str(uuid.uuid4()), str(uuid.uuid4())


def code_of(fn, *a, **k):
    try:
        fn(*a, **k)
    except ApiError as e:
        return e.code
    return None


class TakenAt(unittest.TestCase):
    def test_canonical_utc(self):
        for raw, want in (("2026-10-31T09:15:00Z", "2026-10-31T09:15:00Z"),
                          ("2026-10-31T10:15:00+01:00", "2026-10-31T09:15:00Z"),
                          ("2026-10-31T10:15:00+0100", "2026-10-31T09:15:00Z"),
                          ("2026-10-31T09:15:00.250Z", "2026-10-31T09:15:00.250000Z"),     # sub-second kept
                          ("2026-10-31 04:15:00-05:00", "2026-10-31T09:15:00Z"),
                          ("20261031T091500Z", "2026-10-31T09:15:00Z")):                    # ISO 8601 basic
            self.assertEqual(photos.taken_at_utc(raw), want, raw)
        self.assertIsNone(photos.taken_at_utc(None))
        self.assertIsNone(photos.taken_at_utc(""))

    def test_refused(self):
        for raw in ("2026-10-31T09:15:00", "2026-10-31", "yesterday", "31/10/2026 09:15", "1761902100", 1761902100,
                    "2026-13-01T00:00:00Z", " 2026-10-31T09:15:00Z", "0001-01-01T00:00:00+01:00"):
            self.assertEqual(code_of(photos.taken_at_utc, raw), "invalid_taken_at", raw)


class Photographer(unittest.TestCase):
    def new(self, **kw):
        base = dict(taken_at=None, taken_by_id=None, taken_by_name=None, camera=None, context=None, uploader_id=ME)
        return photos.new_photo(**{**base, **kw})

    def test_default_is_the_uploader(self):
        self.assertEqual(self.new()["taken_by_id"], ME)
        self.assertEqual(self.new(taken_by_id=OTHER)["taken_by_id"], OTHER)
        r = self.new(taken_by_name="PC Smith", camera="Canon EOS R6 #0123", context="Laptop on desk, lid open",
                     taken_at="2026-10-31T10:15:00+01:00")
        self.assertEqual(r, {"taken_at": "2026-10-31T09:15:00Z", "taken_by_id": None, "taken_by_name": "PC Smith",
                             "camera": "Canon EOS R6 #0123", "context": "Laptop on desk, lid open"})

    def test_conflict_and_bad_time(self):
        self.assertEqual(code_of(self.new, taken_by_id=OTHER, taken_by_name="PC Smith"), "taken_by_conflict")
        self.assertEqual(code_of(self.new, taken_at="2026-10-31T09:15"), "invalid_taken_at")


class Edit(unittest.TestCase):
    STORED = {"id": "p1", "url": "/api/x", "caption": "in situ", "taken_at": "2026-10-31T09:00:00Z",
              "taken_by_id": ME, "taken_by_name": None, "camera": "iPhone 15", "context": "desk",
              "original_filename": "IMG_1.HEIC", "storage_path": "photos/e/p1.enc", "nonce_hex": "00" * 7,
              "sha256": "d" * 64, "size": 10, "mime_type": "image/heic"}

    def test_only_sent_fields_change(self):
        out = photos.edited(self.STORED, {"caption": "edited"})
        self.assertEqual(out, {**self.STORED, "caption": "edited"})
        out = photos.edited(self.STORED, {"taken_at": "2026-10-31T10:30:00+01:00", "camera": None})
        self.assertEqual((out["taken_at"], out["camera"], out["context"]), ("2026-10-31T09:30:00Z", None, "desk"))

    def test_setting_one_photographer_clears_the_other(self):
        out = photos.edited(self.STORED, {"taken_by_name": "PC Smith"})
        self.assertEqual((out["taken_by_id"], out["taken_by_name"]), (None, "PC Smith"))
        out = photos.edited(out, {"taken_by_id": OTHER})
        self.assertEqual((out["taken_by_id"], out["taken_by_name"]), (OTHER, None))
        self.assertEqual(code_of(photos.edited, self.STORED, {"taken_by_id": OTHER, "taken_by_name": "x"}),
                         "taken_by_conflict")
        self.assertEqual(code_of(photos.edited, self.STORED, {"taken_at": "today"}), "invalid_taken_at")

    def test_server_fields_are_not_editable(self):
        self.assertFalse({"sha256", "size", "storage_path", "nonce_hex", "mime_type", "original_filename", "url",
                          "id"} & set(photos.EDITABLE))

    def test_reference_entry(self):
        r = photos.reference({"url": "", "caption": "c", "taken_at": "2026-10-31T10:00:00+01:00"})
        self.assertEqual(r["taken_at"], "2026-10-31T09:00:00Z")
        self.assertEqual(code_of(photos.reference, {"url": "", "taken_at": "2026-10-31"}), "invalid_taken_at")


class OutputSchema(unittest.TestCase):
    """FP-2: a stored taken_at that isn't ISO 8601 with an offset never breaks a read, and is not lost."""

    def test_legacy_value_kept_unparsed(self):
        for raw in ("yesterday 3pm", "2026-06-14T10:00:00", 1761902100):
            p = PhotoRef.model_validate({"url": "", "taken_at": raw})
            self.assertIsNone(p.taken_at)
            self.assertEqual(p.taken_at_unparsed, str(raw))

    def test_valid_value(self):
        p = PhotoRef.model_validate({"url": "", "taken_at": "2026-10-31T10:15:00+01:00"})
        self.assertEqual(p.taken_at, datetime(2026, 10, 31, 9, 15, tzinfo=timezone.utc))
        self.assertIsNone(p.taken_at_unparsed)
        self.assertEqual(p.model_dump(mode="json")["taken_at"], "2026-10-31T09:15:00Z")
        self.assertIsNone(PhotoRef.model_validate({"url": "", "taken_at": ""}).taken_at_unparsed)

    def test_exposes_hash_and_record_never_internals(self):
        out = PhotoRef.model_validate(Edit.STORED).model_dump(mode="json")
        self.assertEqual((out["sha256"], out["size"], out["camera"], out["original_filename"]),
                         ("d" * 64, 10, "iPhone 15", "IMG_1.HEIC"))
        self.assertNotIn("storage_path", out)
        self.assertNotIn("nonce_hex", out)

    def test_leaving_record_has_no_internals(self):
        r = records.photo_record(Edit.STORED)
        self.assertEqual(set(r), set(records.PHOTO_FIELDS))
        self.assertFalse({"storage_path", "nonce_hex", "url"} & set(r))


def ev(**kw):
    base = dict(kind="physical_item", photos=[], collected_by_id=uuid.uuid4(), collected_location="x",
                lawful_basis="ir", status="active", current_custodian_id=uuid.uuid4(),
                current_custodian_external_name=None, collected_by_qualifications="q", collected_as_role="defr",
                coc_sealed=False, make="Dell", model="L", serial="S")
    return types.SimpleNamespace(**{**base, **kw})


def photo_check(e):
    return next((c for c in score_evidence(e)["checks"] if c["code"] == "iso_27037_photo_record"), None)


class PhotoRecordProvenance(unittest.TestCase):
    def test_absent_without_photos(self):
        self.assertIsNone(photo_check(ev()))

    def test_complete_and_incomplete(self):
        good = {"id": "a", "taken_by_name": "PC Smith", "taken_at": "2026-10-31T09:00:00Z", "camera": "EOS R6"}
        c = photo_check(ev(photos=[good, {**good, "taken_by_name": None, "taken_by_id": ME}]))
        self.assertEqual((c["status"], c["severity"], c["note"]), ("pass", "advisory", None))
        c = photo_check(ev(photos=[good, {"url": "", "caption": "legacy"},
                                   {**good, "taken_at": "2026-10-31T09:00:00", "camera": " "}]))
        self.assertEqual((c["status"], c["severity"]), ("fail", "advisory"))
        self.assertEqual(c["note"], "2 of 3 photo(s) lack: taken by, taken at, camera")
        c = photo_check(ev(kind="digital_file", photos=[{**good, "camera": None}], sha256=None, sha1=None, md5=None,
                           write_blocker_used=None, system_state=None, live_justification=None,
                           acquisition_tool=None, acquisition_tool_version=None, acquisition_hash_source=None,
                           acquisition_hash_target=None, acquisition_tool_validated=None, entity_id=None,
                           source_system=None, source_path=None, source_path_style=None, source_details=None,
                           source_unknown_reason=None, acquisition_scope=None, device_types=[]))
        self.assertEqual(c["note"], "1 of 1 photo(s) lack: camera")


class PackagePath(unittest.TestCase):
    def test_extension(self):
        self.assertEqual(_photo_ext({"mime_type": "image/jpeg"}), ".jpg")
        self.assertEqual(_photo_ext({"mime_type": "image/png; q=1"}), ".png")
        self.assertEqual(_photo_ext({"mime_type": "image/x-unknown", "original_filename": "IMG_7.HEIC"}), ".heic")
        self.assertEqual(_photo_ext({"mime_type": "image/x-unknown", "original_filename": "a.../../x"}), ".bin")
        self.assertEqual(_photo_ext({}), ".bin")


if __name__ == "__main__":
    unittest.main()
