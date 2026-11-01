"""EI: automatic exhibit identifiers — the template rules (evidence/identifier.py template_error), expansion (legacy and
current incident references, padding past N, the UTC day), a blank identifier treated as left out, and the create
schemas that now take no identifier. The counter and the routes are covered by the DB-rollback harness
(ignore/evidence-verify/ei_db_rollback.py).

stdlib unittest; no DB, no network. From the repo root:

    docker run --rm --network none --read-only --tmpfs /tmp \
      --tmpfs /evidence:uid=1001,gid=1001 --tmpfs /asset_logs:uid=1001,gid=1001 \
      -v "$PWD/backend:/src:ro" -w /src -e PYTHONPATH=/src -e PYTHONDONTWRITEBYTECODE=1 \
      -e EVIDENCE_PATH=/evidence -e LOGS_PATH=/asset_logs \
      -e DATABASE_URL=postgresql+asyncpg://nobody:none@127.0.0.1:1/none \
      -e EVIDENCE_KEK=$(python3 -c "print('11'*32)") \
      --entrypoint python dfir-fenrir-v2-backend:local -m unittest tests.test_evidence_identifier_ei -v
"""
import unittest
from datetime import datetime, timedelta, timezone

from evidence import identifier as ei
from schemas import EvidenceIdentifierSettingsUpdate, PhysicalEvidenceCreate, UploadCompleteEvidence

AT = datetime(2026, 11, 1, 9, 30, 0, tzinfo=timezone.utc)


class TemplateRules(unittest.TestCase):
    def ok(self, t):
        self.assertIsNone(ei.template_error(t), t)

    def bad(self, t, needle):
        why = ei.template_error(t)
        self.assertIsNotNone(why, t)
        self.assertIn(needle, why, t)

    def test_default_and_valid_templates(self):
        for t in (ei.DEFAULT_TEMPLATE, "{seq}", "{seq:1}", "{seq:6}", "EXH-{seq:4}", "{incident}.{seq}",
                  "{date}_{incident}_{seq:2}", "Case-A.b_c-{seq}", "{incident}-{incident}-{seq}"):
            self.ok(t)

    def test_seq_exactly_once(self):
        self.bad("", "exactly once; it appears 0 times")
        self.bad("{incident}-{date}", "exactly once; it appears 0 times")
        self.bad("{seq}-{seq:2}", "exactly once; it appears 2 times")

    def test_unknown_tokens(self):
        for t, tok in (("{case}-{seq}", "{case}"), ("{SEQ}", "{SEQ}"), ("{seq:}", "{seq:}"),
                       ("{incident-{seq}", "{incident-{seq}"), ("{seq", "{seq"), ("{seq:x}", "{seq:x}")):
            self.bad(t, f"Unknown token {tok}")

    def test_seq_width(self):
        self.bad("{seq:0}", "N must be 1 to 6")
        self.bad("{seq:7}", "N must be 1 to 6")

    def test_literal_characters(self):
        for ch in (" ", "/", "\\", ":", "}", "é", "\x00", "#"):
            self.bad(f"A{ch}{{seq}}", "is not allowed")

    def test_template_length(self):
        self.ok("A" * 59 + "{seq}")                 # 64
        self.bad("A" * 60 + "{seq}", "65 characters long; at most 64")

    def test_worst_case_length(self):
        # 3 × {incident} (3 × 32) + 9-digit {seq} = 105: fits; 4 × = 137: refused, though the template is 45 characters
        self.ok("{incident}" * 3 + "{seq}")
        t = "{incident}" * 4 + "{seq}"
        self.assertLessEqual(len(t), ei.TEMPLATE_MAX)
        self.bad(t, "longest identifier it can give is 137 characters")
        # exactly 128: 3 × 32 + 23 literals + 9 = 128
        self.ok("{incident}{incident}{incident}" + "A" * 23 + "{seq}")
        self.bad("{incident}{incident}{incident}" + "A" * 24 + "{seq}", "129 characters")

    def test_length_is_checked_before_parsing(self):
        self.bad("/" * 1000, "1000 characters long")


class Expansion(unittest.TestCase):
    def test_default_with_a_current_reference(self):
        self.assertEqual(ei.expand(ei.DEFAULT_TEMPLATE, "INC-2026-00009", AT, 1), "INC-2026-00009-20261101-001")

    def test_legacy_reference_is_kept_as_stored(self):
        self.assertEqual(ei.expand(ei.DEFAULT_TEMPLATE, "INC-0002", AT, 42), "INC-0002-20261101-042")

    def test_padding_and_growing_past_n(self):
        self.assertEqual(ei.expand("{seq}", "X", AT, 7), "007")
        self.assertEqual(ei.expand("{seq:1}", "X", AT, 7), "7")
        self.assertEqual(ei.expand("{seq:3}", "X", AT, 1000), "1000")
        self.assertEqual(ei.expand("E{seq:2}", "X", AT, 123456), "E123456")
        self.assertEqual(ei.expand("{seq:6}", "X", AT, 12), "000012")

    def test_date_is_the_utc_day(self):
        late = datetime(2026, 11, 1, 23, 30, tzinfo=timezone(timedelta(hours=-5)))      # 2026-11-02 04:30 UTC
        self.assertEqual(ei.expand("{date}-{seq}", "X", late, 1), "20261102-001")

    def test_literals_and_order(self):
        self.assertEqual(ei.expand("EXH.{date}_{incident}-{seq:2}", "ACME-2026-00001", AT, 3),
                         "EXH.20261101_ACME-2026-00001-03")

    def test_worst_case_fits_the_column(self):
        t = "{incident}{incident}{incident}" + "A" * 23 + "{seq}"
        self.assertEqual(len(ei.expand(t, "R" * 32, AT, 999_999_999)), ei.IDENTIFIER_MAX)

    def test_distinct_numbers_give_distinct_identifiers(self):
        out = {ei.expand(ei.DEFAULT_TEMPLATE, "INC-2026-00009", AT, n) for n in range(1, 2001)}
        self.assertEqual(len(out), 2000)


class BlankMeansAutomatic(unittest.TestCase):
    def test_typed(self):
        for blank in (None, "", " ", "\t\n", " "):
            self.assertIsNone(ei.typed(blank), repr(blank))
        for kept in ("EXH-1", " EXH-1 ", "0"):
            self.assertEqual(ei.typed(kept), kept)          # a typed identifier is used exactly as sent

    def test_create_schemas_take_no_identifier(self):
        self.assertIsNone(PhysicalEvidenceCreate(name="Laptop").identifier)
        self.assertIsNone(PhysicalEvidenceCreate(name="Laptop", identifier=None).identifier)
        self.assertEqual(PhysicalEvidenceCreate(name="Laptop", identifier="  ").identifier, "  ")
        self.assertIsNone(UploadCompleteEvidence(purpose="evidence", name="disk").identifier)
        self.assertEqual(UploadCompleteEvidence(purpose="evidence", name="disk", identifier="EXH-1").identifier, "EXH-1")
        with self.assertRaises(Exception):
            PhysicalEvidenceCreate(name="Laptop", identifier="x" * 129)

    def test_the_update_schema_leaves_the_rules_to_the_route(self):
        # 422 invalid_identifier_template (with the rule) rather than a generic validation_error
        self.assertEqual(EvidenceIdentifierSettingsUpdate(template="A" * 200).template, "A" * 200)


if __name__ == "__main__":
    unittest.main()
