"""S1 (EG-10, FP-5) + S2 sink: the disclosure package's Evidence_Inventory.csv keeps its old columns in order and
appends the acquisition record and the source location record; each file's .meta.json carries both as blocks; the
custody export's CoC JSON carries them too, and its photo list holds no storage internals.

stdlib unittest; no DB, no network (le_package.builder._section_evidence runs against a stub session). From the
repo root:

    docker run --rm --network none --read-only --tmpfs /tmp \
      --tmpfs /evidence:uid=1001,gid=1001 --tmpfs /asset_logs:uid=1001,gid=1001 \
      -v "$PWD/backend:/src:ro" -w /src -e PYTHONPATH=/src -e PYTHONDONTWRITEBYTECODE=1 \
      -e EVIDENCE_PATH=/evidence -e LOGS_PATH=/asset_logs \
      -e DATABASE_URL=postgresql+asyncpg://nobody:none@127.0.0.1:1/none \
      -e EVIDENCE_KEK=$(python3 -c "print('11'*32)") \
      --entrypoint python dfir-fenrir-v2-backend:local -m unittest tests.test_evidence_records_s1 -v
"""
import asyncio
import csv
import io
import json
import types
import unittest
import unittest.mock
import uuid
import zipfile
from datetime import datetime, timezone

from evidence import exports, records
from le_package import builder
from le_package.manifest import Manifest
from models import Evidence

# The inventory as it was before S1 (F4 and M11 appends included): readers that go by position rely on it.
OLD_COLUMNS = [
    "id", "kind", "identifier", "name", "description", "tlp", "status",
    "original_filename", "file_size_bytes", "mime_type", "sha256", "sha1", "md5",
    "make", "model", "serial", "physical_location", "condition",
    "collected_by_id", "collected_at_utc", "collected_location", "current_custodian_id", "disposed_at_utc",
    "final_hash_at_disposition", "legal_hold", "acquired_at_utc", "upload_hash_check",
    "coc_sealed", "coc_sealed_at_utc", "lawful_basis", "package_inclusion",
]
NEW_ACQUISITION = [
    "lawful_basis_note", "acquisition_tool", "acquisition_tool_version", "acquisition_tool_sha256",
    "acquisition_params", "acquisition_hash_source", "acquisition_hash_target",
    "write_blocker_used", "write_blocker_serial", "system_state", "live_justification", "network_isolated",
    "witness_user_id", "witness_name", "collected_as_role",
    "device_types", "handling_mode", "decision_factors", "acquisition_scope", "logical_acquisition_rationale",
    "system_time_offset", "system_time_offset_seconds", "screen_state", "changes_made", "device_details",
    "acquisition_tool_validated", "acquisition_tool_validation_ref", "acquisition_tool_validation_date",
    "collected_by_qualifications", "coc_sealed_by_id", "seal_tst_present", "seal_tst_time", "seal_tsa",
]
NEW_SOURCE = ["source_system", "source_path", "source_path_style", "source_path_norm", "source_details",
              "source_unknown_reason"]
NEW_MANIFEST = ["container_format", "manifest_status", "manifest_sha256", "manifest_entries", "manifest_builder",
                "manifest_error", "manifest_listing"]                                    # S6, appended after S2
T = datetime(2026, 10, 31, 9, 15, 0, 123000, tzinfo=timezone.utc)
SECRET_PATH = "inc/ev__internal.enc"
SECRET_NONCE = "abcdef0123456789abcdef01"


def _exhibit(**kw) -> Evidence:
    base = dict(
        id=uuid.uuid4(), incident_id=uuid.uuid4(), kind="digital_file", name="WS-01 Q3", identifier="EV-1",
        description=None, tlp="amber", status="active", original_filename="Q3.xlsx", storage_path=SECRET_PATH,
        nonce_hex=SECRET_NONCE, file_size_bytes=3, mime_type="application/octet-stream", sha256="a" * 64,
        sha1="b" * 40, md5="c" * 32, make="Dell", model="Latitude 7440", serial="SN-1", physical_location=None,
        condition=None, photos=[], collected_by_id=uuid.uuid4(), collected_at=T, collected_location="4F",
        current_custodian_id=uuid.uuid4(), disposed_at=None, final_hash_at_disposition=None, legal_hold=False,
        acquired_at=T, upload_hash_check="match", coc_sealed=True, coc_sealed_at=T, coc_sealed_by_id=uuid.uuid4(),
        lawful_basis="ir", lawful_basis_note="LIA ref 7", acquisition_tool="FTK Imager",
        acquisition_tool_version="4.7.1", acquisition_tool_sha256=None, acquisition_params="=cmd|' /C calc'!A0",
        acquisition_hash_source="c" * 32, acquisition_hash_target="c" * 32, write_blocker_used=True,
        write_blocker_serial="WB-9", system_state="powered_off", live_justification=None, network_isolated=True,
        witness_user_id=None, witness_name="Insp. Hansen", collected_as_role="des", device_types=["computer"],
        handling_mode="acquire", decision_factors={"volatile": False}, acquisition_scope="logical",
        logical_acquisition_rationale="profile only", system_time_offset="+3s", system_time_offset_seconds=3,
        screen_state=None, changes_made=None, device_details={"cabling_note": "P1-P6"},
        acquisition_tool_validated=True, acquisition_tool_validation_ref="VR-14",
        acquisition_tool_validation_date="2026-01-01", collected_by_qualifications="GCFA",
        # S3: valid base64 (the package now carries the token, decoded, as 04_Evidence/Seal/{id}__seal.tst); its
        # base64 text is still never in the inventory, a .meta.json or the CoC JSON.
        seal_tst="MIIBAA==", seal_tst_time="2026-10-31T09:16:00Z", seal_tsa="https://tsa.example",
        source_system="  WS-01.contoso.local", source_path="C:\\Users\\jdoe\\Q3.xlsx ", source_path_style="windows",
        source_path_norm="C:\\Users\\jdoe\\Q3.xlsx ", source_unknown_reason=None,
        source_details={"v": 1, "filename_on_source": "Q3.xlsx", "volume": {"label": "OS"}},
    )
    return Evidence(**{**base, **kw})


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return self._rows


class _Db:
    """First query: the exhibits; every later one (the custody audit rows): none."""
    def __init__(self, items):
        self.calls = 0
        self.items = items

    async def execute(self, _q):
        self.calls += 1
        return _Rows(self.items if self.calls == 1 else [])


def _build(items):
    buf = io.BytesIO()
    zf = zipfile.ZipFile(buf, "w")
    manifest = Manifest(incident_id="i", incident_ref=None, case_reference="c", platform_version="t")
    stub = lambda zf_, man, ev, path, mime, src: {"sha256": ev.sha256}          # noqa: E731
    with unittest.mock.patch.object(builder, "_stream_evidence_file", stub):
        asyncio.run(builder._section_evidence(_Db(items), uuid.uuid4(), legal_hold_only=False,
                                              include_unsealed_drafts=True, manifest=manifest, zf=zf))
    zf.close()
    return zipfile.ZipFile(io.BytesIO(buf.getvalue()))


class Inventory(unittest.TestCase):
    def setUp(self):
        self.ev = _exhibit()
        self.phys = _exhibit(kind="physical_item", storage_path=None, nonce_hex=None, original_filename=None,
                             source_path=None, source_path_style=None, source_path_norm=None, seal_tst=None,
                             seal_tst_time=None, source_details=None, device_types=None)
        self.z = _build([self.ev, self.phys])
        text = self.z.read("04_Evidence/Evidence_Inventory.csv").decode("utf-8-sig")
        self.rows = list(csv.reader(io.StringIO(text, newline="")))

    def test_old_columns_unchanged_new_ones_appended(self):
        header = self.rows[0]
        self.assertEqual(header[:len(OLD_COLUMNS)], OLD_COLUMNS)
        self.assertEqual(header[len(OLD_COLUMNS):], NEW_ACQUISITION + NEW_SOURCE + NEW_MANIFEST)
        self.assertEqual(list(records.INVENTORY_ACQUISITION_COLUMNS), NEW_ACQUISITION)
        self.assertEqual(list(records.INVENTORY_SOURCE_COLUMNS), NEW_SOURCE)

    def test_values(self):
        row = dict(zip(self.rows[0], self.rows[1]))
        self.assertEqual(row["identifier"], "EV-1")
        self.assertEqual(row["acquisition_tool"], "FTK Imager")
        self.assertEqual(row["acquisition_params"], "'=cmd|' /C calc'!A0")       # through csv_safe
        self.assertEqual(row["device_types"], '["computer"]')                    # compact JSON
        self.assertEqual(row["decision_factors"], '{"volatile":false}')
        self.assertEqual(row["seal_tst_present"], "True")
        self.assertEqual(row["seal_tst_time"], "2026-10-31T09:16:00Z")
        self.assertEqual(row["source_path"], "C:\\Users\\jdoe\\Q3.xlsx ")          # verbatim, trailing space kept
        self.assertEqual(row["source_system"], "  WS-01.contoso.local")
        self.assertEqual(json.loads(row["source_details"])["volume"], {"label": "OS"})
        phys = dict(zip(self.rows[0], self.rows[2]))
        self.assertEqual((phys["seal_tst_present"], phys["source_path"], phys["device_types"]), ("False", "", ""))

    def test_meta_json_blocks_and_no_internals(self):
        names = [n for n in self.z.namelist() if n.endswith(".meta.json")]
        self.assertEqual(len(names), 1)
        meta = json.loads(self.z.read(names[0]))
        self.assertEqual(set(meta["acquisition"]), set(records.ACQUISITION_FIELDS))     # _json_bytes sorts keys
        self.assertEqual(set(meta["source"]), set(records.SOURCE_FIELDS))
        self.assertEqual(meta["acquisition"]["acquisition_params"], "=cmd|' /C calc'!A0")   # raw in JSON
        self.assertEqual(meta["acquisition"]["acquired_at"], "2026-10-31T09:15:00.123000Z")
        self.assertIs(meta["acquisition"]["seal_tst_present"], True)
        self.assertEqual(meta["source"]["source_path"], "C:\\Users\\jdoe\\Q3.xlsx ")
        self.assertEqual(meta["source"]["make"], "Dell")
        everything = b"".join(self.z.read(n) for n in self.z.namelist())
        for secret in (SECRET_PATH, SECRET_NONCE, "MIIB"):
            self.assertNotIn(secret.encode(), everything)


class CustodyExport(unittest.TestCase):
    def test_coc_doc_blocks_and_sanitised_photos(self):
        photo = {"id": "p1", "url": "/api/incidents/x/evidence/y/photos/p1", "caption": "in situ",
                 "taken_at": "2026-10-31T09:00:00Z", "storage_path": SECRET_PATH, "nonce_hex": SECRET_NONCE,
                 "mime_type": "image/jpeg", "sha256": "d" * 64, "size": 10}
        ev = _exhibit(kind="physical_item", photos=[photo, {"url": "", "caption": "ref only"}])
        inc = types.SimpleNamespace(id=uuid.uuid4(), title="t", severity="high", tlp="amber", phase="p", status="open")
        doc = exports._build_coc_doc(inc, ev, [])
        none = dict.fromkeys(("taken_by_id", "taken_by_name", "camera", "original_filename", "context"))  # S4
        self.assertEqual(doc["item"]["physical"]["photos"], [
            {"id": "p1", "caption": "in situ", "taken_at": "2026-10-31T09:00:00Z", "mime_type": "image/jpeg",
             "sha256": "d" * 64, "size": 10, **none},
            {"id": None, "caption": "ref only", "taken_at": None, "mime_type": None, "sha256": None, "size": None,
             **none},
        ])
        self.assertEqual(doc["item"]["acquisition"], records.acquisition_record(ev))
        self.assertEqual(doc["item"]["source"]["serial"], "SN-1")
        blob = json.dumps(doc, default=str)
        for secret in (SECRET_PATH, SECRET_NONCE, "MIIB", "/photos/p1"):
            self.assertNotIn(secret, blob)


if __name__ == "__main__":
    unittest.main()
