"""Regression test: a refused upload chunk ends its DB transaction before it drains the body
(evidence/uploads.py put_upload_chunk). Auth's last_seen_at UPDATE locks the user's session row, so
draining a slow body inside the transaction stalled every other request on that session.

stdlib unittest; no DB, no network. From the repo root:

    docker run --rm --network none --read-only --tmpfs /tmp \
      --tmpfs /evidence:uid=1001,gid=1001 --tmpfs /asset_logs:uid=1001,gid=1001 \
      -v "$PWD/backend:/src:ro" -w /src -e PYTHONPATH=/src -e PYTHONDONTWRITEBYTECODE=1 \
      -e EVIDENCE_PATH=/evidence -e LOGS_PATH=/asset_logs \
      -e DATABASE_URL=postgresql+asyncpg://nobody:none@127.0.0.1:1/none \
      -e EVIDENCE_KEK=$(python3 -c "print('11'*32)") \
      --entrypoint python dfir-fenrir-v2-backend:local -m unittest tests.test_upload_chunk_refusal -v
"""
import asyncio
import types
import unittest
import uuid
from unittest import mock

from core.errors import ApiError
from evidence import uploads


class _Db:
    def __init__(self, events):
        self.events = events

    async def commit(self):
        self.events.append("commit")

    async def rollback(self):
        self.events.append("rollback")


class _Request:
    headers = {"content-type": "application/octet-stream"}

    def __init__(self, events):
        self.events = events

    async def stream(self):
        for _ in range(3):
            self.events.append("read")
            yield b"x" * 1024


class RefusedChunkTest(unittest.TestCase):
    def test_unknown_upload_ends_transaction_before_draining(self):
        events = []

        async def refuse(db, *args, **kwargs):
            events.append("query")            # stands in for the flush that takes the session-row lock
            raise uploads._not_found()

        with mock.patch.object(uploads, "_session_for", refuse):
            with self.assertRaises(ApiError) as cm:
                asyncio.run(uploads.put_upload_chunk(uuid.uuid4(), uuid.uuid4(), _Request(events), index=0,
                                                     user=types.SimpleNamespace(id=uuid.uuid4()), db=_Db(events)))
        self.assertEqual(cm.exception.code, "upload_not_found")
        self.assertEqual(events, ["query", "rollback", "read", "read", "read"])


if __name__ == "__main__":
    unittest.main()
