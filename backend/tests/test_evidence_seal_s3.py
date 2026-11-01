"""S3 (EG-11, EG-12, FP-4, FP-8): the canonical record v1 the seal binds (evidence/records.py seal_record_v1, with a
test vector), its digest's stability, the source rule at seal (evidence/source.py seal_source_missing) across
handling modes and device types, and the provenance checks that share it.

stdlib unittest; no DB, no network. From the repo root:

    docker run --rm --network none --read-only --tmpfs /tmp \
      --tmpfs /evidence:uid=1001,gid=1001 --tmpfs /asset_logs:uid=1001,gid=1001 \
      -v "$PWD/backend:/src:ro" -w /src -e PYTHONPATH=/src -e PYTHONDONTWRITEBYTECODE=1 \
      -e EVIDENCE_PATH=/evidence -e LOGS_PATH=/asset_logs \
      -e DATABASE_URL=postgresql+asyncpg://nobody:none@127.0.0.1:1/none \
      -e EVIDENCE_KEK=$(python3 -c "print('11'*32)") \
      --entrypoint python dfir-fenrir-v2-backend:local -m unittest tests.test_evidence_seal_s3 -v
"""
import hashlib
import json
import types
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from unittest import mock

from evidence import records, source
from evidence.provenance import score_evidence

EID = uuid.UUID("0b6f2a52-3c1d-4e8f-9a7b-1c2d3e4f5a6b")
WIT = uuid.UUID("7d1e5c33-aaaa-4bbb-8ccc-0123456789ab")


def exhibit(**kw):
    """A sealed digital exhibit with every field of the record set to a fixed value."""
    base = dict(
        id=EID, identifier="EXH-2026-001", kind="digital_file", name="ignored: not in the record",
        md5="c" * 32, sha1="b" * 40, sha256="a" * 64,
        lawful_basis="warrant", lawful_basis_note=None, acquisition_tool="FTK Imager", acquisition_tool_version="4.7.1",
        acquisition_tool_sha256=None, acquisition_params="--e01", acquisition_hash_source="a" * 64,
        acquisition_hash_target="a" * 64,
        acquired_at=datetime(2026, 10, 20, 6, 0, 0, 120000, tzinfo=timezone.utc), upload_hash_check="match",
        write_blocker_used=True, write_blocker_serial="WB-9", system_state="powered_off", live_justification=None,
        network_isolated=None, witness_user_id=WIT, witness_name=None, collected_as_role="des",
        device_types=["computer", "storage"], handling_mode="acquire", decision_factors={"volatile": False, "a": 1},
        acquisition_scope="logical", logical_acquisition_rationale="profile only", system_time_offset="+3s",
        system_time_offset_seconds=3, screen_state=None, changes_made=None, device_details={"z": 1, "cabling": "P1"},
        acquisition_tool_validated=True, acquisition_tool_validation_ref="VR-14",
        acquisition_tool_validation_date="2026-01-01", collected_by_qualifications="GCFA",
        coc_sealed=True, coc_sealed_at=datetime(2026, 10, 31, 9, 0, tzinfo=timezone.utc), coc_sealed_by_id=WIT,
        seal_tst="MIIB…", seal_tst_time="2026-10-31T09:00:01Z", seal_tsa="https://tsa.example",
        source_system="WS-01.contoso.local", make="Dell", model=None, serial="SN-1",
        source_path="C:\\Users\\jdoé\\Q3 (final).xlsx ", source_path_style="windows",
        source_path_norm="C:\\Users\\jdoé\\Q3 (final).xlsx ", source_details={"v": 1, "os": "Windows 11"},
        source_unknown_reason=None, entity_id=None, seal_record_sha256=None,
        photos=[{"id": "ff01", "sha256": "e" * 64, "storage_path": "p/x.enc", "caption": "not bound"},
                {"url": "", "caption": "caption-only: no id, no bytes"},
                {"id": "0a02", "sha256": "d" * 64, "nonce_hex": "00" * 7}],
    )
    return types.SimpleNamespace(**{**base, **kw})


# The test vector: the exact bytes for exhibit() (UTF-8; é stays one 2-byte character, not \u00e9).
VECTOR = (
    '{"acquisition":{"acquired_at":"2026-10-20T06:00:00.120000Z","acquisition_hash_source":"' + "a" * 64 + '",'
    '"acquisition_hash_target":"' + "a" * 64 + '","acquisition_params":"--e01","acquisition_scope":"logical",'
    '"acquisition_tool":"FTK Imager","acquisition_tool_sha256":null,"acquisition_tool_validated":true,'
    '"acquisition_tool_validation_date":"2026-01-01","acquisition_tool_validation_ref":"VR-14",'
    '"acquisition_tool_version":"4.7.1","changes_made":null,"collected_as_role":"des",'
    '"collected_by_qualifications":"GCFA","decision_factors":{"a":1,"volatile":false},'
    '"device_details":{"cabling":"P1","z":1},"device_types":["computer","storage"],"handling_mode":"acquire",'
    '"lawful_basis":"warrant","lawful_basis_note":null,"live_justification":null,'
    '"logical_acquisition_rationale":"profile only","network_isolated":null,"screen_state":null,'
    '"system_state":"powered_off","system_time_offset":"+3s","system_time_offset_seconds":3,'
    '"upload_hash_check":"match","witness_name":null,"witness_user_id":"7d1e5c33-aaaa-4bbb-8ccc-0123456789ab",'
    '"write_blocker_serial":"WB-9","write_blocker_used":true},'
    '"hashes":{"md5":"' + "c" * 32 + '","sha1":"' + "b" * 40 + '","sha256":"' + "a" * 64 + '"},'
    '"id":"0b6f2a52-3c1d-4e8f-9a7b-1c2d3e4f5a6b","identifier":"EXH-2026-001","kind":"digital_file",'
    '"photos":[{"id":"0a02","sha256":"' + "d" * 64 + '"},{"id":"ff01","sha256":"' + "e" * 64 + '"}],'
    '"source":{"make":"Dell","model":null,"serial":"SN-1","source_details":{"os":"Windows 11","v":1},'
    '"source_path":"C:\\\\Users\\\\jdoé\\\\Q3 (final).xlsx ","source_path_norm":"C:\\\\Users\\\\jdoé\\\\Q3 (final).xlsx ",'
    '"source_path_style":"windows","source_system":"WS-01.contoso.local","source_unknown_reason":null},"v":1}'
).encode("utf-8")
VECTOR_SHA256 = "1e9287825a8d99aa050e751bf0c2abe98d9521aedb0408efd9f084b055f42965"


def digest(ev):
    return hashlib.sha256(records.seal_record_v1(ev)).hexdigest()


class CanonicalRecord(unittest.TestCase):
    def test_vector(self):
        self.assertEqual(records.seal_record_v1(exhibit()), VECTOR)
        self.assertEqual(digest(exhibit()), hashlib.sha256(VECTOR).hexdigest())
        self.assertEqual(hashlib.sha256(VECTOR).hexdigest(), VECTOR_SHA256)

    def test_shape(self):
        rec = json.loads(records.seal_record_v1(exhibit()))
        self.assertEqual(set(rec), {"v", "id", "identifier", "kind", "hashes", "acquisition", "source", "photos"})
        self.assertEqual(set(rec["acquisition"]), set(records.ACQUISITION_FIELDS) - set(records.SEAL_OUTPUT_FIELDS))
        self.assertEqual(set(rec["source"]), set(records.SOURCE_FIELDS))
        for f in records.SEAL_OUTPUT_FIELDS:                 # the seal's own outputs are not bound
            self.assertNotIn(f, rec["acquisition"])

    def test_null_keys_stay(self):
        rec = json.loads(records.seal_record_v1(exhibit(kind="physical_item", md5=None, sha1=None, sha256=None,
                                                        photos=[])))
        self.assertEqual(rec["hashes"], {"md5": None, "sha1": None, "sha256": None})
        self.assertIn("lawful_basis_note", rec["acquisition"])
        self.assertEqual(rec["photos"], [])

    def test_stable(self):
        a = exhibit()
        b = exhibit(photos=list(reversed(a.photos)), decision_factors={"a": 1, "volatile": False},
                    device_details={"cabling": "P1", "z": 1},
                    acquired_at=datetime(2026, 10, 20, 8, 0, 0, 120000, tzinfo=timezone(timedelta(hours=2))))
        self.assertEqual(digest(a), digest(b))              # photo order, key order, the same instant elsewhere
        # the seal's outputs and descriptive fields don't change it
        self.assertEqual(digest(a), digest(exhibit(coc_sealed_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
                                                   seal_tst=None, seal_tst_time=None, seal_tsa=None,
                                                   coc_sealed_by_id=uuid.uuid4(), name="renamed",
                                                   seal_record_sha256="f" * 64)))
        # a photo's caption is not bound; a caption-only photo is not either
        self.assertEqual(digest(a), digest(exhibit(photos=[{**a.photos[0], "caption": "edited"}, a.photos[2]])))

    def test_changes_change_it(self):
        base = digest(exhibit())
        for kw in ({"source_path": "C:\\Users\\jdoe\\Q3.xlsx"}, {"serial": None}, {"acquisition_tool_version": "4.7.2"},
                   {"sha256": "0" * 64}, {"identifier": "EXH-2"}, {"device_types": ["storage", "computer"]},
                   {"photos": exhibit().photos + [{"id": "1b03", "sha256": "1" * 64}]},
                   {"photos": [{"id": "ff01", "sha256": "2" * 64}]}, {"system_time_offset_seconds": 4}):
            self.assertNotEqual(digest(exhibit(**kw)), base, kw)

    def test_optional_key_only_when_set(self):
        """S6 adds manifest_sha256 to SEAL_RECORD_OPTIONAL_FIELDS: absent when null, so v1 stays byte-identical."""
        self.assertEqual(records.SEAL_RECORD_OPTIONAL_FIELDS, ("manifest_sha256",))
        self.assertEqual(records.seal_record_v1(exhibit()), VECTOR)               # S6 in place: same bytes
        with mock.patch.object(records, "SEAL_RECORD_OPTIONAL_FIELDS", ("manifest_sha256",)):
            self.assertEqual(records.seal_record_v1(exhibit(manifest_sha256=None)), VECTOR)
            rec = json.loads(records.seal_record_v1(exhibit(manifest_sha256="9" * 64)))
            self.assertEqual(rec["manifest_sha256"], "9" * 64)

    def test_non_ascii_is_utf8(self):
        raw = records.seal_record_v1(exhibit())
        self.assertIn("jdoé".encode("utf-8"), raw)
        self.assertNotIn(b"\\u00e9", raw)


def dig(**kw):
    """A digital exhibit with no source record; kw adds to it."""
    base = dict(kind="digital_file", entity_id=None, source_system=None, make=None, model=None, serial=None,
                source_path=None, source_path_style=None, source_unknown_reason=None, acquisition_scope=None,
                system_state=None, device_types=["computer"], handling_mode="acquire")
    return types.SimpleNamespace(**{**base, **kw})


DEV = dict(source_system="WS-01")
WIN = dict(source_path="C:\\x", source_path_style="windows")
DEVICE_PATH = dict(source_path="\\\\.\\PhysicalDrive0", source_path_style="device")


class SealSourceRule(unittest.TestCase):
    def m(self, **kw):
        return source.seal_source_missing(dig(**kw))

    def test_device_is_an_entity_a_system_or_a_serial(self):
        for kw in ({"entity_id": uuid.uuid4()}, {"source_system": "WS-01"}, {"serial": "SN-1"}):
            self.assertEqual(self.m(**kw, **WIN), [], kw)
        for kw in ({}, {"make": "Dell", "model": "Latitude"}, {"source_system": "   "}, {"serial": ""}):
            self.assertEqual(self.m(**kw, **WIN), ["source_device"], kw)

    def test_matrix(self):
        cases = [
            # (acquisition_scope, system_state, device_types, path fields, missing)
            ("logical", None, ["computer"], {}, ["source_path"]),
            ("logical", None, ["computer"], WIN, []),
            ("full_image", None, ["storage"], {}, ["source_path"]),
            ("full_image", None, ["storage"], WIN, ["source_path_style"]),
            ("full_image", None, ["storage"], DEVICE_PATH, []),
            ("full_image", "live", ["computer"], {}, ["source_path"]),     # a full image needs its device path
            (None, "live", ["computer"], {}, []),                            # live / volatile: path optional
            ("logical", "live_critical", ["computer"], {}, []),
            (None, None, ["email_export"], {}, []),                          # exports: path advisory
            (None, None, ["vendor_report"], {}, []),
            ("logical", None, ["network_capture"], {}, []),
            (None, None, ["computer"], {}, ["source_path"]),                 # no scope recorded: the path
            (None, None, ["computer"], {"source_path": "C:\\x"}, ["source_path"]),   # a path without its style
        ]
        for scope, state, types_, path, want in cases:
            with self.subTest(scope=scope, state=state, types=types_, path=path):
                self.assertEqual(self.m(acquisition_scope=scope, system_state=state, device_types=types_, **DEV,
                                        **path), want)
                self.assertEqual(self.m(acquisition_scope=scope, system_state=state, device_types=types_, **path),
                                 ["source_device"] + want)

    def test_unknown_reason_is_the_callers_escape(self):
        # the rule itself ignores the reason; the seal route and provenance accept it in place of everything
        self.assertEqual(self.m(source_unknown_reason="Emailed to the SOC by the user"), ["source_device", "source_path"])


def scored(**kw):
    base = dict(kind="digital_file", photos=[], collected_by_id=uuid.uuid4(), collected_location="x",
                lawful_basis="ir", sha256="a" * 64, sha1="b" * 40, md5="c" * 32, write_blocker_used=None,
                system_state=None, live_justification=None, acquisition_tool="t", acquisition_tool_version="1",
                coc_sealed=False, seal_record_sha256=None, acquisition_hash_source=None, acquisition_hash_target=None,
                status="active", current_custodian_id=uuid.uuid4(), current_custodian_external_name=None,
                acquisition_tool_validated=True, collected_by_qualifications="q", collected_as_role="defr",
                entity_id=None, source_system=None, make=None, model=None, serial=None, source_path=None,
                source_path_style=None, source_details=None, source_unknown_reason=None,
                acquisition_scope=None, device_types=[], handling_mode="acquire")
    return {c["code"]: c for c in score_evidence(types.SimpleNamespace(**{**base, **kw}))["checks"]}


class Provenance(unittest.TestCase):
    def loc(self, **kw):
        c = scored(**kw)["iso_27037_source_location"]
        return c["status"], c["severity"]

    def test_mandatory_for_record_v1_seals_only(self):
        self.assertEqual(self.loc(), ("fail", "advisory"))
        self.assertEqual(self.loc(coc_sealed=True), ("fail", "advisory"))                     # a legacy seal
        self.assertEqual(self.loc(coc_sealed=True, seal_record_sha256="f" * 64), ("fail", "mandatory"))
        self.assertEqual(self.loc(coc_sealed=True, seal_record_sha256="f" * 64, **DEV, **WIN), ("pass", "mandatory"))
        self.assertEqual(self.loc(coc_sealed=True, seal_record_sha256="f" * 64,
                                  source_unknown_reason="Emailed to the SOC by the user"), ("manual", "mandatory"))

    def test_same_rule_as_the_gate(self):
        c = scored(make="Dell", model="Latitude", **WIN)["iso_27037_source_location"]
        self.assertEqual(c["status"], "fail")
        self.assertIn("serial", c["note"])
        self.assertEqual(self.loc(serial="SN-1", acquisition_scope="full_image", **WIN), ("fail", "advisory"))
        self.assertEqual(self.loc(serial="SN-1", acquisition_scope="full_image", **DEVICE_PATH), ("pass", "advisory"))

    def test_fp4_live_critical_needs_a_justification(self):
        for state in ("live", "live_critical"):
            c = scored(system_state=state)["iso_27037_9_2_1_writeblocker"]
            self.assertEqual(c["status"], "fail", state)
            c = scored(system_state=state, live_justification="RAM first")["iso_27037_9_2_1_writeblocker"]
            self.assertEqual(c["status"], "pass", state)

    def test_fp8_codes_kept_labels_cite_27037_2012_clauses(self):
        checks = {**scored(acquisition_hash_source="c" * 32, acquisition_hash_target="c" * 32, system_state="live"),
                  **scored(kind="physical_item")}
        for code, clause in (("iso_27037_9_1_4", "§6.2.1"), ("iso_27037_9_2_3_sha256", "§5.4.4"),
                             ("iso_27037_9_2_1_writeblocker", "§5.4.4"), ("iso_27037_9_2_4_tool", "§5.4.4"),
                             ("iso_27037_9_2_5_hash_match", "§5.4.4")):
            self.assertIn(clause, checks[code]["label"], code)
            self.assertNotIn("§9", checks[code]["label"], code)

    def test_one_hash_alone_is_not_a_mismatch(self):
        """Owner decision 2026-11-01: a registered screenshot has a target hash (its hash at capture) and no source."""
        hm = lambda **kw: (lambda c: (c["status"], c["severity"]))(scored(**kw)["iso_27037_9_2_5_hash_match"])  # noqa: E731
        self.assertEqual(hm(acquisition_hash_target="e" * 64), ("manual", "advisory"))
        self.assertIn("Only the target hash", scored(acquisition_hash_target="e" * 64)["iso_27037_9_2_5_hash_match"]["note"])
        self.assertEqual(hm(acquisition_hash_source="e" * 64), ("manual", "advisory"))
        self.assertEqual(hm(acquisition_hash_source="c" * 32, acquisition_hash_target="d" * 32), ("fail", "mandatory"))
        self.assertEqual(hm(acquisition_hash_source="c" * 32, acquisition_hash_target="C" * 32), ("pass", "mandatory"))
        self.assertNotIn("iso_27037_9_2_5_hash_match", scored())


if __name__ == "__main__":
    unittest.main()
