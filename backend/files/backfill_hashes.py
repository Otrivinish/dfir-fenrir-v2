"""H4 (R10): record the server hashes of supporting documents uploaded before H4 (entity_files rows with no sha256).

    python -m files.backfill_hashes            DRY RUN (default, read-only): decrypt and hash every unhashed file,
                                               report what --apply would record
    python -m files.backfill_hashes --apply    record them

Runs in the backend container (EVIDENCE_KEK, the /asset_logs volume, the app's DML-only DB role) while the backend
serves. Read-only on the stored files in both modes. Per row with sha256 NULL, under a row lock (--apply):

  1. stream-decrypt the stored file (either format; bounded memory) and hash it in one pass (SHA-256 / SHA-1 / MD5);
     the stream must end cleanly (F-12) and give exactly the row's file_size bytes
  2. a report figure's stored report_sha256 must equal the SHA-256 — a mismatch is reported, nothing is recorded
  3. --apply: set sha256 / sha1 / md5 and write the audit row `file_hashes_backfilled` in one transaction

Idempotent: a row that has a sha256 is skipped (also when another writer set it meanwhile). Exit codes: 0 clean,
1 something needs attention (file missing / unreadable / failed authentication / size or report-hash mismatch).
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from collections import Counter

from sqlalchemy import select

from audit.service import write_audit
from core.config import settings
from core.database import SessionLocal
from evidence import crypto
from models import EntityFile

TOOL = "files.backfill_hashes"
BAD = {"file_missing", "integrity_failed", "read_error", "size_mismatch", "report_sha256_mismatch"}


def _hash_stored(rel: str, nonce_hex: str, size) -> tuple[str, str, str, int]:
    """(sha256, sha1, md5, byte count) of a stored file's plaintext, decrypted as a stream. Blocking."""
    hs = (hashlib.sha256(), hashlib.sha1(), hashlib.md5())
    n = 0
    for part in crypto.iter_decrypted(rel, nonce_hex, size, root=settings.logs_path):
        for h in hs:
            h.update(part)
        n += len(part)
    return hs[0].hexdigest(), hs[1].hexdigest(), hs[2].hexdigest(), n


async def backfill_one(fid, apply: bool) -> str:
    """One unhashed row. Returns the outcome (recorded | would_record | already | file_missing | integrity_failed |
    read_error | size_mismatch | report_sha256_mismatch)."""
    async with SessionLocal() as db:
        async with db.begin():
            q = select(EntityFile).where(EntityFile.id == fid).execution_options(populate_existing=True)
            ef = (await db.execute(q.with_for_update() if apply else q)).scalar_one_or_none()
            if ef is None or ef.sha256 is not None:
                return "already"
            try:
                sha256, sha1, md5, n = await asyncio.to_thread(_hash_stored, ef.file_path, ef.nonce_hex, ef.file_size)
            except crypto.EvidenceIntegrityError:
                return "integrity_failed"
            except crypto.EvidenceCryptoError as e:
                return "file_missing" if e.reason in ("file_missing", "invalid_path") else "read_error"
            if n != ef.file_size:
                return "size_mismatch"
            if ef.report_sha256 and ef.report_sha256.lower() != sha256:
                return "report_sha256_mismatch"
            if not apply:
                return "would_record"
            ef.sha256, ef.sha1, ef.md5 = sha256, sha1, md5
            kind = "entity_file" if (ef.file_path or "").startswith("entity-files/") else "incident_file"
            await write_audit(db, "file_hashes_backfilled", username=TOOL, role_at_time="offline-tool",
                              outcome="success", resource_type=kind, resource_id=str(ef.id),
                              request_method="CLI", request_path=f"{TOOL} --apply",
                              details={"incident_id": str(ef.incident_id), "filename": ef.original_name,
                                       "size": n, "sha256": sha256, "sha1": sha1, "md5": md5,
                                       "report_sha256_checked": bool(ef.report_sha256),
                                       "uploaded_at": ef.uploaded_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                       "note": "hashed after upload (row predates server hashing)", "tool": TOOL})
    return "recorded"


async def main_async(args) -> int:
    async with SessionLocal() as db:
        total = len((await db.execute(select(EntityFile.id))).all())
        todo = [r for (r,) in (await db.execute(select(EntityFile.id).where(EntityFile.sha256.is_(None))
                                                .order_by(EntityFile.uploaded_at, EntityFile.id))).all()]
    counts = Counter()
    for fid in todo:
        outcome = await backfill_one(fid, args.apply)
        counts[outcome] += 1
        if outcome in BAD:
            print(f"{outcome:24s} file {fid}", file=sys.stderr)
    print(json.dumps({"mode": "apply" if args.apply else "dry-run", "files": total, "unhashed": len(todo),
                      **counts}, sort_keys=True))
    return 1 if BAD & set(counts) else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog=f"python -m {TOOL}", description=__doc__.split("\n\n")[0])
    ap.add_argument("--apply", action="store_true", help="record the hashes (default: dry run, read-only)")
    return asyncio.run(main_async(ap.parse_args(argv)))


if __name__ == "__main__":
    sys.exit(main())
