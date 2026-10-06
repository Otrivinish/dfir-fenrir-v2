"""H1 (R06): encrypt the legacy plaintext quarantine files at rest (FENRGCM v2, docs/streaming-aes-gcm-format.md).

    python -m artifacts.encrypt_quarantine            DRY RUN (default, read-only): hash every plaintext file
                                                      against its row and report what --apply would do
    python -m artifacts.encrypt_quarantine --apply    migrate
    python -m artifacts.encrypt_quarantine --verify   read-only: every row reads back to its recorded SHA-256

Runs in the backend container (EVIDENCE_KEK, the quarantine volume, the app's DML-only DB role) while the
backend serves; each artifact row is locked (FOR UPDATE) while its file is migrated. Per plaintext row:

  1. read the file once: hash it (SHA-256 + size) while encrypting it into <quarantine>/.staging/*.partial;
     a hash or size that differs from the row stops here (nothing written, the plaintext kept, reported)
  2. rename the finished container to <stored name>.enc (never over an existing file), then decrypt it
     again and check the SHA-256 against the row; a failure removes the new file and keeps the plaintext
  3. in ONE transaction: the row's stored_filename + nonce_hex, and the audit row artifact_encrypted_at_rest
  4. only after that commit: delete the plaintext file (and fsync its directory)

Idempotent and resumable: an encrypted row is skipped; a `<name>.enc` that no row names (a crash between 2
and 3) is removed and redone; a plaintext file left behind by a crash between 3 and 4 is deleted once its
row's encrypted copy verifies. The plaintext is never deleted unless the encrypted copy verified.
Exit codes: 0 clean, 1 something needs attention (missing file, hash mismatch, failure), 2 bad usage.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
from collections import Counter
from pathlib import Path

from sqlalchemy import select

from artifacts import store
from audit.service import write_audit
from core.database import SessionLocal
from evidence import crypto
from models import Artifact

TOOL = "artifacts.encrypt_quarantine"
CHUNK = 1024 * 1024


def _path(incident_id, name: str) -> Path:
    return crypto._safe_target(store.rel_path(incident_id, name), store.root())


def _hash_plain(path: Path) -> tuple[str, int]:
    h, n = hashlib.sha256(), 0
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
            n += len(block)
    return h.hexdigest(), n


def _encrypt(path: Path):
    """Step 1 for one file: encrypt it into a finished staging file. Returns (StoredFile with the plaintext's
    hashes and size, the writer to commit or abort); nothing is left behind on an error."""
    w = crypto.EncryptedStagingWriter(store.root())
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as f:
            for block in iter(lambda: f.read(CHUNK), b""):
                w.write(block)
        return w.finish(), w
    except BaseException:
        w.abort()
        raise


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


async def _named(db, incident_id, name: str) -> bool:
    return (await db.execute(select(Artifact.id).where(Artifact.incident_id == incident_id,
                                                       Artifact.stored_filename == name))).first() is not None


async def migrate_one(aid, apply: bool) -> str:
    """One plaintext row. Returns the outcome (encrypted | would_encrypt | already | file_missing |
    hash_mismatch | size_mismatch | verify_failed | target_named | plaintext_left)."""
    async with SessionLocal() as db:
        async with db.begin():
            q = select(Artifact).where(Artifact.id == aid).execution_options(populate_existing=True)
            a = (await db.execute(q.with_for_update() if apply else q)).scalar_one_or_none()
            if a is None or a.nonce_hex is not None:
                return "already"
            src = _path(a.incident_id, a.stored_filename)
            if not src.is_file():
                return "file_missing"
            recorded = (a.sha256_hash or "").lower()
            if not apply:
                sha, n = await asyncio.to_thread(_hash_plain, src)
                if n != a.file_size:
                    return "size_mismatch"
                return "would_encrypt" if sha == recorded else "hash_mismatch"
            new_name = a.stored_filename + ".enc"
            rel_new = store.rel_path(a.incident_id, new_name)
            target = _path(a.incident_id, new_name)
            if os.path.lexists(target):
                if await _named(db, a.incident_id, new_name):
                    return "target_named"
                await asyncio.to_thread(os.unlink, target)            # left by a crash before step 3
            stored, w = await asyncio.to_thread(_encrypt, src)
            if stored.size != a.file_size or stored.sha256 != recorded:
                await asyncio.to_thread(w.abort)
                return "size_mismatch" if stored.size != a.file_size else "hash_mismatch"
            await asyncio.to_thread(w.commit, rel_new)                   # atomic rename, both dirs fsynced
            try:
                check = await asyncio.to_thread(crypto.sha256_decrypted, rel_new, stored.nonce_hex, stored.size,
                                                root=store.root())
            except crypto.EvidenceCryptoError:
                check = None
            if check != recorded:
                await asyncio.to_thread(os.unlink, target)
                return "verify_failed"
            before = a.stored_filename
            a.stored_filename, a.nonce_hex = new_name, stored.nonce_hex
            await write_audit(db, "artifact_encrypted_at_rest", username=TOOL, role_at_time="offline-tool",
                              outcome="success", resource_type="artifact", resource_id=str(a.id),
                              request_method="CLI", request_path=f"{TOOL} --apply",
                              details={"incident_id": str(a.incident_id), "artifact_id": str(a.id),
                                       "stored_filename_before": before, "stored_filename_after": new_name,
                                       "sha256": recorded, "size": stored.size, "nonce_hex": stored.nonce_hex,
                                       "format_before": "plain", "format_after": "v2",
                                       "sha256_verified_after_encrypt": True, "tool": TOOL})
        # committed: only now remove the plaintext
    try:
        await asyncio.to_thread(os.unlink, src)
        await asyncio.to_thread(_fsync_dir, src.parent)
    except OSError:
        return "plaintext_left"
    return "encrypted"


async def leftovers(apply: bool) -> Counter:
    """Plaintext files a crash left next to their row's encrypted copy (`<name>` beside a row naming
    `<name>.enc`, no row naming `<name>`): deleted with --apply once the encrypted copy verifies."""
    out = Counter()
    async with SessionLocal() as db:
        rows = (await db.execute(select(Artifact).where(Artifact.nonce_hex.isnot(None),
                                                        Artifact.stored_filename.like("%.enc")))).scalars().all()
        for a in rows:
            old = a.stored_filename[:-len(".enc")]
            p = _path(a.incident_id, old)
            if not p.is_file() or await _named(db, a.incident_id, old):
                continue
            try:
                ok = await asyncio.to_thread(crypto.sha256_decrypted, store.rel_path(a.incident_id, a.stored_filename),
                                             a.nonce_hex, a.file_size, root=store.root()) == (a.sha256_hash or "").lower()
            except crypto.EvidenceCryptoError:
                ok = False
            if not ok:
                out["leftover_kept_unverified"] += 1
            elif apply:
                await asyncio.to_thread(os.unlink, p)
                out["leftover_removed"] += 1
            else:
                out["leftover_would_remove"] += 1
    return out


async def verify() -> Counter:
    """Read-only: every row (either format) reads back to its recorded SHA-256."""
    out = Counter()
    async with SessionLocal() as db:
        rows = (await db.execute(select(Artifact))).scalars().all()
    def sha_of(a) -> str:
        h = hashlib.sha256()
        for part in store.iter_plaintext(a):
            h.update(part)
        return h.hexdigest()

    for a in rows:
        kind = "v2" if a.nonce_hex is not None else "plain"
        try:
            sha = await asyncio.to_thread(sha_of, a)
            out[f"{kind}_ok" if sha == (a.sha256_hash or "").lower() else f"{kind}_hash_mismatch"] += 1
        except crypto.EvidenceIntegrityError as e:
            out[f"{kind}_integrity_failed:{e.reason}"] += 1
        except crypto.EvidenceCryptoError as e:
            out[f"{kind}_unreadable:{e.reason}"] += 1
    return out


async def main_async(args) -> int:
    async with SessionLocal() as db:
        total = len((await db.execute(select(Artifact.id))).all())
        plain = [r for (r,) in (await db.execute(select(Artifact.id).where(Artifact.nonce_hex.is_(None))
                                                 .order_by(Artifact.uploaded_at))).all()]
    if args.verify:
        counts = await verify()
        print(json.dumps({"mode": "verify", "artifacts": total, **counts}, sort_keys=True))
        return 0 if all(k.endswith("_ok") for k in counts) else 1
    counts = Counter()
    for aid in plain:
        outcome = await migrate_one(aid, args.apply)
        counts[outcome] += 1
        if outcome not in ("encrypted", "would_encrypt", "already"):
            print(f"{outcome:15s} artifact {aid}", file=sys.stderr)
    counts.update(await leftovers(args.apply))
    print(json.dumps({"mode": "apply" if args.apply else "dry-run", "artifacts": total, "plain_rows": len(plain),
                      **counts}, sort_keys=True))
    bad = {"file_missing", "hash_mismatch", "size_mismatch", "verify_failed", "target_named", "plaintext_left",
           "leftover_kept_unverified"}
    return 1 if bad & set(counts) else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog=f"python -m {TOOL}", description=__doc__.split("\n\n")[0])
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--apply", action="store_true", help="encrypt (default: dry run, read-only)")
    g.add_argument("--verify", action="store_true", help="read-only check of every row against its SHA-256")
    args = ap.parse_args(argv)
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
