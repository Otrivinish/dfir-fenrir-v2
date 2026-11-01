"""Report data: `evidence_items[]`, the exhibit list printed in § Evidence & Artifacts.

stdlib unittest (the backend image has no pytest). No DB: the dummy DATABASE_URL only satisfies settings
at import. Run in a throwaway backend container with no network, from the repo root:

    docker run --rm --network none --read-only --tmpfs /tmp -v "$PWD/backend:/src:ro" \\
      -w /src -e PYTHONPATH=/src -e PYTHONDONTWRITEBYTECODE=1 \\
      -e DATABASE_URL=postgresql+asyncpg://x:y@127.0.0.1:1/z \\
      --entrypoint python dfir-fenrir-v2-backend:local -m unittest tests.test_report_evidence_items -v
"""
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace

from reports.routes import _evidence_items

UTC = timezone.utc
SHA = "a" * 64


def exhibit(identifier, kind, collected_at, **kw):
    base = dict(identifier=identifier, name=f"name {identifier}", kind=kind, status="active",
                sha256=SHA if kind == "digital_file" else None, collected_at=collected_at,
                storage_path="/evidence/x.enc", nonce_hex="00" * 7, md5="b" * 32, sha1="c" * 40,
                current_custodian_external_contact="+46 70 000 00 00")
    base.update(kw)
    return SimpleNamespace(**base)


class EvidenceItems(unittest.TestCase):
    def test_fields_order_and_hash(self):
        t1 = datetime(2026, 11, 1, 9, 0, tzinfo=UTC)
        t2 = datetime(2026, 11, 1, 10, 0, tzinfo=UTC)
        rows = [
            exhibit("EX-003", "physical_item", t2),
            exhibit("EX-002", "digital_file", t1, status="verify_failed"),
            exhibit("EX-001", "digital_file", t1),
        ]
        out = _evidence_items(rows)
        self.assertEqual([i["identifier"] for i in out], ["EX-001", "EX-002", "EX-003"])
        self.assertEqual(out[0], {"identifier": "EX-001", "name": "name EX-001", "kind": "digital_file",
                                  "status": "active", "sha256": SHA})
        self.assertEqual(out[1]["status"], "verify_failed")
        self.assertIsNone(out[2]["sha256"])

    def test_physical_item_never_carries_a_hash(self):
        t = datetime(2026, 11, 1, tzinfo=UTC)
        out = _evidence_items([exhibit("EX-009", "physical_item", t, sha256=SHA)])
        self.assertIsNone(out[0]["sha256"])

    def test_no_internal_fields(self):
        out = _evidence_items([exhibit("EX-001", "digital_file", datetime(2026, 11, 1, tzinfo=UTC))])
        self.assertEqual(set(out[0]), {"identifier", "name", "kind", "status", "sha256"})

    def test_empty(self):
        self.assertEqual(_evidence_items([]), [])


if __name__ == "__main__":
    unittest.main()
