"""RD: deferred readiness checks — the summary counts (readiness/checks.py evaluate) with and without deferrals, the
admin-only reason, and the request schema. The routes, RBAC and audit rows are covered by the DB-rollback harness
(ignore/readiness-verify/rd_db_rollback.py).

stdlib unittest; no DB, no network. From the repo root:

    docker run --rm --network none --read-only --tmpfs /tmp \
      --tmpfs /evidence:uid=1001,gid=1001 --tmpfs /asset_logs:uid=1001,gid=1001 \
      -v "$PWD/backend:/src:ro" -w /src -e PYTHONPATH=/src -e PYTHONDONTWRITEBYTECODE=1 \
      -e EVIDENCE_PATH=/evidence -e LOGS_PATH=/asset_logs \
      -e DATABASE_URL=postgresql+asyncpg://nobody:none@127.0.0.1:1/none \
      -e EVIDENCE_KEK=$(python3 -c "print('11'*32)") \
      --entrypoint python dfir-fenrir-v2-backend:local -m unittest tests.test_readiness_defer_rd -v
"""
import asyncio
import contextlib
import unittest
import unittest.mock
from datetime import datetime, timezone
from types import SimpleNamespace

from pydantic import ValidationError

from readiness import checks
from readiness.routes import Readiness, ReadinessDeferIn

AT = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)


def fake_checks(results):
    """CHECKS-shaped list: (meta, fn) per (id, level, status[, level override for this evaluation])."""
    out = []
    for cid, level, st, *over in results:
        async def fn(db, now, st=st, over=over):
            return st, f"{st} detail", ({"level": over[0]} if over else {})
        out.append(({"id": cid, "title": cid.title(), "level": level, "csf": [], "fix_route": None}, fn))
    return out


class FakeDB:
    def __init__(self, deferrals):
        self.deferrals = deferrals

    def begin_nested(self):
        @contextlib.asynccontextmanager
        async def cm():
            yield
        return cm()

    async def execute(self, stmt):
        return SimpleNamespace(scalars=lambda: iter(self.deferrals))


def deferral(cid, reason="Two-person team", level="blocker"):
    return SimpleNamespace(check_id=cid, deferred_by_name="Ada Admin", deferred_at=AT, reason=reason, level=level)


CHECKS = [("admin_totp", "blocker", "fail"), ("on_call_14d", "blocker", "fail"), ("on_call_oob", "blocker", "fail"),
          ("backup_recent", "blocker", "pass"), ("smtp", "warning", "fail"), ("threat_intel", "warning", "unknown")]


def run(deferrals, is_admin=True, results=CHECKS):
    with unittest.mock.patch.object(checks, "CHECKS", fake_checks(results)):
        res = asyncio.run(checks.evaluate(FakeDB(deferrals), is_admin=is_admin))
    Readiness(**res)                                         # the response model accepts it
    return res


class SummaryCounts(unittest.TestCase):
    def test_no_deferrals_unchanged(self):
        s = run([])["summary"]
        self.assertEqual((s["blockers_failing"], s["warnings_failing"], s["unknown"]), (3, 1, 1))
        self.assertEqual((s["blockers_deferred"], s["warnings_deferred"]), (0, 0))

    def test_deferred_checks_leave_the_failing_counts(self):
        res = run([deferral("on_call_14d"), deferral("on_call_oob"), deferral("smtp")])
        s = res["summary"]
        self.assertEqual((s["blockers_failing"], s["blockers_deferred"]), (1, 2))   # admin_totp still counts
        self.assertEqual((s["warnings_failing"], s["warnings_deferred"]), (0, 1))
        by_id = {c["id"]: c for c in res["checks"]}
        self.assertEqual(by_id["on_call_14d"]["status"], "fail")                  # still reported failing
        self.assertEqual(by_id["on_call_14d"]["deferral"], {"by_name": "Ada Admin", "at": AT,
                                                            "reason": "Two-person team"})
        self.assertIsNone(by_id["admin_totp"]["deferral"])

    def test_every_failing_blocker_deferred_means_no_banner(self):
        s = run([deferral(c) for c in ("admin_totp", "on_call_14d", "on_call_oob")])["summary"]
        self.assertEqual((s["blockers_failing"], s["blockers_deferred"]), (0, 3))

    def test_deferred_check_that_passes_counts_nowhere(self):
        res = run([deferral("backup_recent")])
        s = res["summary"]
        self.assertEqual((s["blockers_failing"], s["blockers_deferred"]), (3, 0))
        self.assertIsNotNone(next(c for c in res["checks"] if c["id"] == "backup_recent")["deferral"])

    def test_unknown_counts_deferred_or_not(self):
        self.assertEqual(run([deferral("threat_intel")])["summary"]["unknown"], 1)

    def test_reason_is_admin_only_on_admin_only_checks(self):
        res = run([deferral("admin_totp"), deferral("on_call_14d")], is_admin=False)
        by_id = {c["id"]: c for c in res["checks"]}
        self.assertIsNone(by_id["admin_totp"]["deferral"]["reason"])
        self.assertEqual(by_id["admin_totp"]["deferral"]["by_name"], "Ada Admin")
        self.assertEqual(by_id["on_call_14d"]["deferral"]["reason"], "Two-person team")
        self.assertEqual(run([deferral("admin_totp")])["checks"][0]["deferral"]["reason"], "Two-person team")

    def test_a_warning_deferral_never_hides_the_blocker(self):
        # backup_recent / audit_anchor: a blocker by default, a warning for some failures (the check's override).
        as_warning = [("audit_anchor", "blocker", "fail", "warning")]
        res = run([deferral("audit_anchor", level="warning")], results=as_warning)
        self.assertEqual((res["summary"]["warnings_failing"], res["summary"]["warnings_deferred"]), (0, 1))
        res = run([deferral("audit_anchor", level="warning")], results=[("audit_anchor", "blocker", "fail")])
        self.assertEqual((res["summary"]["blockers_failing"], res["summary"]["blockers_deferred"]), (1, 0))
        self.assertIsNone(res["checks"][0]["deferral"])
        res = run([deferral("audit_anchor", level="blocker")], results=as_warning)    # a blocker deferral covers less
        self.assertEqual((res["summary"]["warnings_failing"], res["summary"]["warnings_deferred"]), (0, 1))


class Request(unittest.TestCase):
    def test_reason_optional(self):
        self.assertIsNone(ReadinessDeferIn(check_ids=["on_call_14d"]).reason)
        self.assertEqual(ReadinessDeferIn(check_ids=["on_call_14d"], reason="x" * 500).reason, "x" * 500)

    def test_limits(self):
        for bad in ({"check_ids": []}, {"check_ids": ["a"] * 33}, {"check_ids": ["a" * 65]},
                    {"check_ids": ["on_call_14d"], "reason": "x" * 501}):
            with self.assertRaises(ValidationError, msg=bad):
                ReadinessDeferIn(**bad)


if __name__ == "__main__":
    unittest.main()
