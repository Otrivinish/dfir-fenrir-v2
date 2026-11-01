"""S2 (EG-1/2/3/5): the source location record. evidence/source.py (the one intake check, norm_v1, the provider-hash
compare), schemas.SourceDetails (Q11) and the two new advisory provenance checks.

stdlib unittest; no DB, no network. From the repo root:

    docker run --rm --network none --read-only --tmpfs /tmp \
      --tmpfs /evidence:uid=1001,gid=1001 --tmpfs /asset_logs:uid=1001,gid=1001 \
      -v "$PWD/backend:/src:ro" -w /src -e PYTHONPATH=/src -e PYTHONDONTWRITEBYTECODE=1 \
      -e EVIDENCE_PATH=/evidence -e LOGS_PATH=/asset_logs \
      -e DATABASE_URL=postgresql+asyncpg://nobody:none@127.0.0.1:1/none \
      -e EVIDENCE_KEK=$(python3 -c "print('11'*32)") \
      --entrypoint python dfir-fenrir-v2-backend:local -m unittest tests.test_evidence_source_s2 -v
"""
import base64
import hashlib
import types
import unicodedata
import unittest
import uuid
from typing import get_args

from pydantic import ValidationError

from core.errors import ApiError
from evidence import source
from evidence.provenance import score_evidence
from schemas import (EvidenceAcquisitionRecord, EvidenceUpdate, PhysicalEvidenceCreate, SourceDetails,
                     SourcePathStyle, UploadCompleteEvidence)


def cols(**sent):
    return source.source_columns(sent)


def code_of(fn, *a, **k):
    try:
        fn(*a, **k)
    except ApiError as e:
        return e.code
    return None


# §3.4 verbatim examples, by style.
EXAMPLES = {
    "windows":    ["C:\\Users\\jdoe\\Desktop\\Q3.xlsx", "\\\\?\\C:\\Users\\jdoe\\Q3.xlsx",
                   "C:\\Users\\jdoe\\file.txt:secret:$DATA", "C:/Users/jdoe/x.txt", "C:\\PROGRA~1\\x. "],
    "unc":        ["\\\\fs01\\finance$\\Q3.xlsx", "\\\\?\\UNC\\fs01\\share\\x"],
    "posix":      ["/home/jdoe/.bash_history"],
    "macos":      ["/Users/jdoe/Library/Mail/V10/x.emlx", "/Users/jdoe/f/..namedfork/rsrc"],
    "android":    ["/data/data/com.whatsapp/databases/msgstore.db", "/sdcard/DCIM/x.jpg"],
    "ios":        ["/private/var/mobile/Containers/Data/Application/0A1B/Library/x.db",
                   "HomeDomain-Library/SMS/sms.db", "AppDomain-net.whatsapp.WhatsApp-Documents/ChatStorage.sqlite"],
    "cloud_uri":  ["https://contoso.sharepoint.com/sites/fin/Shared Documents/Q3.xlsx", "s3://bkt/key",
                   "https://acct.blob.core.windows.net/c/b", "gs://b/o", "az://c/b",
                   "abfss://fs@acct.dfs.core.windows.net/dir/f", "https://h/a%20b"],
    "mail_store": ["jdoe@contoso.com/Inbox/Invoices", "Top of Personal Folders/Inbox"],
    "device":     ["\\\\.\\PhysicalDrive0", "/dev/sda", "\\\\.\\C:", "/dev/nvme0n1"],
    "other":      ["anything at all", "CON", "NUL"],
}
MISMATCHES = {
    "windows":   ["Users\\jdoe", "/home/x", "\\\\fs01\\share", " C:\\x"],
    "unc":       ["C:\\x", "\\\\fs01", "/x"],
    "posix":     ["C:\\x", "home/x", " /x"],
    "macos":     ["Users/x"],
    "android":   ["sdcard/x"],
    "ios":       ["Library/SMS/sms.db", "Home-Library"],
    "cloud_uri": ["http://h/x", "ftp://h/x", "contoso.sharepoint.com/x", "https:///x", " https://h/x"],
}


class Styles(unittest.TestCase):
    def test_style_list_matches_the_schema_and_shape_rules(self):
        self.assertEqual(set(get_args(SourcePathStyle)), set(source._SHAPE))
        self.assertEqual(len(get_args(SourcePathStyle)), 10)

    def test_every_hld_example_passes_its_style_and_is_stored_verbatim(self):
        for style, paths in EXAMPLES.items():
            for p in paths:
                with self.subTest(style=style, path=p):
                    out = cols(source_path=p, source_path_style=style)
                    self.assertEqual(out["source_path"], p)
                    self.assertEqual(out["source_path_style"], style)
                    self.assertIsInstance(out["source_path_norm"], str)

    def test_shape_mismatches_are_422(self):
        for style, paths in MISMATCHES.items():
            for p in paths:
                with self.subTest(style=style, path=p):
                    self.assertEqual(code_of(cols, source_path=p, source_path_style=style),
                                     "source_path_style_mismatch")


class Validation(unittest.TestCase):
    def test_nul_is_invalid_source_path(self):
        self.assertEqual(code_of(cols, source_path="/a\x00b", source_path_style="posix"), "invalid_source_path")

    def test_length_limit(self):
        ok = "C:\\" + "a" * (32_768 - 3)
        self.assertEqual(len(cols(source_path=ok, source_path_style="windows")["source_path"]), 32_768)
        self.assertEqual(code_of(cols, source_path=ok + "b", source_path_style="windows"), "invalid_source_path")

    def test_nul_in_system_or_reason_is_invalid_source_text(self):
        self.assertEqual(code_of(cols, source_system="WS\x0001"), "invalid_source_text")
        self.assertEqual(code_of(cols, source_unknown_reason="emailed by a user\x00"), "invalid_source_text")

    def test_style_required_with_a_path(self):
        self.assertEqual(code_of(cols, source_path="/x"), "source_path_style_required")
        self.assertEqual(code_of(cols, source_path="/x", source_path_style=None), "source_path_style_required")

    def test_norm_is_read_only_even_null(self):
        self.assertEqual(code_of(cols, source_path_norm="x"), "source_path_norm_read_only")
        self.assertEqual(code_of(cols, source_path_norm=None), "source_path_norm_read_only")

    def test_unknown_reason_min_length_counts_without_spaces_and_is_stored_verbatim(self):
        self.assertEqual(code_of(cols, source_unknown_reason="   too short   "), "source_unknown_reason_too_short")
        r = "  Emailed to the SOC by the user; source unknown  "
        self.assertEqual(cols(source_unknown_reason=r)["source_unknown_reason"], r)

    def test_leading_and_trailing_spaces_kept_in_path_norm_and_system(self):
        out = cols(source_path="  Inbox/Invoices  ", source_path_style="mail_store", source_system="  WS-01 ")
        self.assertEqual(out["source_path"], "  Inbox/Invoices  ")
        self.assertEqual(out["source_path_norm"], "  Inbox/Invoices  ")
        self.assertEqual(out["source_system"], "  WS-01 ")
        out = cols(source_path="/tmp/x ", source_path_style="posix")
        self.assertEqual((out["source_path"], out["source_path_norm"]), ("/tmp/x ", "/tmp/x "))

    def test_empty_string_clears(self):
        self.assertEqual(cols(source_path="", source_system=""),
                         {"source_path": None, "source_system": None, "source_path_norm": None})

    def test_edit_checks_against_the_stored_path(self):
        cur = {"source_path": "C:\\x", "source_path_style": "windows"}
        self.assertEqual(code_of(source.source_columns, {"source_path_style": "posix"}, cur),
                         "source_path_style_mismatch")
        self.assertEqual(source.source_columns({"source_path_style": "other"}, cur),
                         {"source_path_style": "other", "source_path_norm": "C:\\x"})
        self.assertEqual(source.source_columns({"source_path": None}, cur),
                         {"source_path": None, "source_path_norm": None})
        self.assertEqual(source.source_columns({"source_system": "WS-01"}, cur), {"source_system": "WS-01"})

    def test_details_are_stored_as_compact_json(self):
        d = SourceDetails(filename_on_source="Q3.xlsx", volume={"label": "OS", "serial": "1234-ABCD"})
        self.assertEqual(cols(source_details=d)["source_details"],
                         {"v": 1, "filename_on_source": "Q3.xlsx", "volume": {"label": "OS", "serial": "1234-ABCD"}})


class Norm(unittest.TestCase):
    def test_windows(self):
        n = source.norm_v1
        self.assertEqual(n("\\\\?\\C:\\Users\\JDoe\\Q3.XLSX", "windows"), "C:\\Users\\JDoe\\Q3.XLSX")
        self.assertEqual(n("c:/Users//jdoe\\\\x", "windows"), "C:\\Users\\jdoe\\x")
        self.assertEqual(n("C:\\Users\\jdoe\\file.txt:secret:$DATA", "windows"), "C:\\Users\\jdoe\\file.txt:secret:$DATA")
        self.assertEqual(n("C:\\a\\..\\b\\.\\c", "windows"), "C:\\a\\..\\b\\.\\c")      # never resolved

    def test_unc(self):
        n = source.norm_v1
        self.assertEqual(n("\\\\?\\UNC\\fs01\\share\\x", "unc"), "\\\\fs01\\share\\x")
        self.assertEqual(n("\\\\?\\unc\\fs01\\share", "unc"), "\\\\fs01\\share")
        self.assertEqual(n("\\\\fs01\\\\finance$\\\\Q3.xlsx", "unc"), "\\\\fs01\\finance$\\Q3.xlsx")
        self.assertEqual(n("//fs01/share/X", "unc"), "\\\\fs01\\share\\X")

    def test_posix_like_collapse_and_keep_case(self):
        n = source.norm_v1
        for style in ("posix", "macos", "android", "ios"):
            self.assertEqual(n("/Home//JDoe///X", style), "/Home/JDoe/X")
        self.assertEqual(n("HomeDomain-Library//SMS/sms.db", "ios"), "HomeDomain-Library/SMS/sms.db")

    def test_nfd_verbatim_nfc_norm(self):
        nfd = unicodedata.normalize("NFD", "/Users/jdoe/Café.txt")
        out = cols(source_path=nfd, source_path_style="macos")
        self.assertEqual(out["source_path"], nfd)
        self.assertNotEqual(out["source_path"], out["source_path_norm"])
        self.assertEqual(out["source_path_norm"], unicodedata.normalize("NFC", nfd))

    def test_cloud_scheme_and_host_lowered_only(self):
        n = source.norm_v1
        self.assertEqual(n("HTTPS://Contoso.SharePoint.com/Sites/Fin/Q3%20A.xlsx", "cloud_uri"),
                         "https://contoso.sharepoint.com/Sites/Fin/Q3%20A.xlsx")
        self.assertEqual(n("abfss://FS@Acct.dfs.core.windows.net/Dir", "cloud_uri"), "abfss://FS@acct.dfs.core.windows.net/Dir")
        self.assertEqual(n("s3://Bkt/Key", "cloud_uri"), "s3://bkt/Key")

    def test_other_styles_nfc_only(self):
        for style in ("mail_store", "device", "other"):
            self.assertEqual(source.norm_v1("\\\\.\\PhysicalDrive0//x", style), "\\\\.\\PhysicalDrive0//x")


class Details(unittest.TestCase):
    def test_q11_a_time_needs_basis_and_read_by(self):
        with self.assertRaises(ValidationError):
            SourceDetails(times={"m": {"utc": "2026-01-02T03:04:05Z"}})
        with self.assertRaises(ValidationError):
            SourceDetails(times={"b": {"as_recorded": "02/01/2026 03:04"}, "basis": "FAT local time"})
        t = SourceDetails(times={"m": {"utc": "2026-01-02T05:04:05+02:00", "as_recorded": "x"},
                                 "basis": "NTFS $STANDARD_INFORMATION", "read_by": "MFTECmd 1.2.2"})
        self.assertEqual(t.model_dump(mode="json", exclude_none=True)["times"]["m"]["utc"], "2026-01-02T03:04:05Z")
        SourceDetails(times={"basis": "none given", "tz_basis": "UTC"})          # no time: nothing required

    def test_unknown_key_and_bad_base64_refused(self):
        with self.assertRaises(ValidationError):
            SourceDetails(colour="red")
        with self.assertRaises(ValidationError):
            SourceDetails(path_raw_b64="not base64!")
        self.assertEqual(SourceDetails(path_raw_b64=base64.b64encode(b"/tmp/\xff").decode()).v, 1)

    def test_intake_schemas_carry_the_fields(self):
        for model in (EvidenceAcquisitionRecord, EvidenceUpdate, UploadCompleteEvidence):
            for f in (*source.SOURCE_INPUT_FIELDS, "make", "model", "serial"):
                self.assertIn(f, model.model_fields, (model.__name__, f))
        self.assertIn("source_system", PhysicalEvidenceCreate.model_fields)
        self.assertNotIn("source_path", PhysicalEvidenceCreate.model_fields)
        body = UploadCompleteEvidence(purpose="evidence", name="n", identifier="i", source_path_norm="x")
        self.assertEqual(code_of(source.source_columns, source.sent_source_fields(body)), "source_path_norm_read_only")


DATA = b"hello source"
H = {"md5": hashlib.md5(DATA).hexdigest(), "sha1": hashlib.sha1(DATA).hexdigest(),
     "sha256": hashlib.sha256(DATA).hexdigest()}


def ph(algorithm, value):
    return {"provider": {"provider_hash": {"algorithm": algorithm, "value": value}}}


class ProviderHash(unittest.TestCase):
    def check(self, details, **kw):
        return source.provider_hash_check(details, **{**H, **kw})

    def test_md5_hex_and_base64_content_md5(self):
        self.assertTrue(self.check(ph("MD5", H["md5"].upper()))["match"])
        b64 = base64.b64encode(hashlib.md5(DATA).digest()).decode()
        self.assertTrue(self.check(ph("MD5", b64))["match"])

    def test_sha256_and_sha1_names_and_mismatch(self):
        self.assertTrue(self.check(ph("SHA-256", H["sha256"]))["match"])
        self.assertTrue(self.check(ph("sha_1", base64.b64encode(hashlib.sha1(DATA).digest()).decode()))["match"])
        r = self.check(ph("sha256", "0" * 64))
        self.assertEqual((r["comparable"], r["match"]), (True, False))

    def test_not_comparable(self):
        self.assertEqual(self.check(ph("QuickXorHash", "AAAAAAAAAAAAAAAAAAAAAAAAAAA="))["reason"], "algorithm")
        self.assertEqual(self.check(ph("MD5", "zz"))["reason"], "value")
        self.assertEqual(self.check(ph("MD5", H["md5"]), md5=None)["reason"], "no_file")
        self.assertIsNone(self.check(None))
        self.assertIsNone(self.check({"provider": {"provider": "S3"}}))


def ev(**kw):
    base = dict(kind="digital_file", photos=[], collected_by_id=uuid.uuid4(), collected_location="x",
                lawful_basis="ir", sha256=H["sha256"], sha1=H["sha1"], md5=H["md5"], write_blocker_used=None,
                system_state=None, live_justification=None, acquisition_tool="t", acquisition_tool_version="1",
                coc_sealed=False, acquisition_hash_source=None, acquisition_hash_target=None, status="active",
                current_custodian_id=uuid.uuid4(), current_custodian_external_name=None,
                acquisition_tool_validated=True, collected_by_qualifications="q", collected_as_role="defr",
                entity_id=None, source_system=None, make=None, model=None, serial=None, source_path=None,
                source_path_style=None, source_details=None, source_unknown_reason=None,
                acquisition_scope=None, device_types=[], handling_mode="acquire")
    return types.SimpleNamespace(**{**base, **kw})


def check(e, code):
    return next((c for c in score_evidence(e)["checks"] if c["code"] == code), None)


class Provenance(unittest.TestCase):
    def status(self, **kw):
        c = check(ev(**kw), "iso_27037_source_location")
        return c and (c["status"], c["severity"])

    def test_logical_needs_device_and_path(self):
        self.assertEqual(self.status(acquisition_scope="logical"), ("fail", "advisory"))
        self.assertEqual(self.status(acquisition_scope="logical", source_system="WS-01"), ("fail", "advisory"))
        self.assertEqual(self.status(acquisition_scope="logical", source_system="WS-01", source_path="C:\\x",
                                     source_path_style="windows"), ("pass", "advisory"))
        self.assertEqual(self.status(entity_id=uuid.uuid4(), source_path="/x", source_path_style="posix"),
                         ("pass", "advisory"))
        self.assertEqual(self.status(serial="S123", source_path="/x", source_path_style="posix"), ("pass", "advisory"))

    def test_full_image_needs_a_device_path(self):
        kw = dict(acquisition_scope="full_image", serial="S4EWNX0R")      # S3: make / model alone are no device
        self.assertEqual(self.status(**kw, source_path="/home", source_path_style="posix"), ("fail", "advisory"))
        self.assertEqual(self.status(**kw, source_path="/dev/sda", source_path_style="device"), ("pass", "advisory"))
        self.assertEqual(self.status(acquisition_scope="full_image", make="Samsung", model="980 PRO",
                                     source_path="/dev/sda", source_path_style="device"), ("fail", "advisory"))

    def test_live_and_exports_need_no_path(self):
        self.assertEqual(self.status(system_state="live", source_system="WS-01"), ("pass", "advisory"))
        self.assertEqual(self.status(device_types=["email_export"], source_system="contoso tenant"), ("pass", "advisory"))
        self.assertEqual(self.status(system_state="live_critical"), ("fail", "advisory"))

    def test_unknown_reason_is_manual_never_pass(self):
        self.assertEqual(self.status(source_unknown_reason="Emailed to the SOC by a user"), ("manual", "advisory"))

    def test_physical_device_identifiers(self):
        c = check(ev(kind="physical_item", make="Dell", model="Latitude"), "iso_27037_device_identifiers")
        self.assertEqual((c["status"], c["severity"]), ("fail", "advisory"))
        self.assertIn("serial", c["note"])
        c = check(ev(kind="physical_item", make="Dell", model="Latitude", serial="ABC"), "iso_27037_device_identifiers")
        self.assertEqual(c["status"], "pass")
        self.assertIsNone(check(ev(kind="physical_item"), "iso_27037_source_location"))
        self.assertIsNone(check(ev(), "iso_27037_device_identifiers"))

    def test_provider_hash_check(self):
        self.assertIsNone(check(ev(), "source_provider_hash_match"))
        self.assertEqual(check(ev(source_details=ph("MD5", H["md5"])), "source_provider_hash_match")["status"], "pass")
        self.assertEqual(check(ev(source_details=ph("MD5", "0" * 32)), "source_provider_hash_match")["status"], "fail")
        self.assertEqual(check(ev(source_details=ph("QuickXorHash", "x")), "source_provider_hash_match")["status"], "n_a")


if __name__ == "__main__":
    unittest.main()
