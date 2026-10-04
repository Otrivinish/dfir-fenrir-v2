"""G1 stage 4: the KEK rotation tool (evidence/rotation.py), spec §6.4 / §5.4.

Runs ONLY against the throwaway environment of ignore/irw-verify/g1s4_env.sh (its own internal
network, a throwaway Postgres built with the real role script + migrate, throwaway volumes, test
KEKs). The tool runs as the DML-only role fenrir_app; fixtures are made with the throwaway
superuser. stdlib unittest (the backend image has no pytest):

    sh ignore/irw-verify/g1s4_env.sh up
    sh ignore/irw-verify/g1s4_env.sh test            # or: test tests.test_rotation.Crash
    sh ignore/irw-verify/g1s4_env.sh down

Crash injection runs the tool in a child process (python -c 'from tests.test_rotation import
crash_child; crash_child()') that os._exit()s at the chosen protocol step: no finally blocks, no
flushes, exactly like a kill -9.
"""
import asyncio
import base64
import contextlib
import fcntl
import hashlib
import io
import json
import logging
import os
import shutil
import subprocess
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock

import asyncpg
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from core.config import settings
from evidence import codec
from evidence import crypto
from evidence import rotation as rot
from models import AuditLog, CollectionPackage, EntityFile, Evidence, Incident

logging.getLogger("fenrir.evidence.crypto").setLevel(logging.ERROR)   # expected wrong_kek alarms
EVID, LOGS = Path(settings.evidence_path), Path(settings.logs_path)
OLD, NEW, NEW2 = bytes.fromhex("a1" * 32), bytes.fromhex("b2" * 32), bytes.fromhex("c3" * 32)
KEYDIR = Path("/tmp/rt-keys")
MiB = 1024 * 1024
OPERATOR = "rt-tester"


def keyfile(name: str, key: bytes, mode: int = 0o600) -> str:
    KEYDIR.mkdir(mode=0o700, exist_ok=True)
    p = KEYDIR / name
    if p.is_symlink() or p.exists():
        p.unlink()
    p.write_text(key.hex() + "\n")
    os.chmod(p, mode)
    return str(p)


def K(old: bytes | None = OLD, new: bytes = NEW) -> list[str]:
    args = ["--new-kek-file", keyfile("new", new)]
    if old is not None:
        args = ["--old-kek-file", keyfile("old", old)] + args
    return args


APPLY = ["--apply", "--yes", "--operator", OPERATOR]


def tool(*argv: str) -> tuple[int, str, dict | None]:
    """Run the CLI in-process; returns (exit code, stdout, JSON report)."""
    rep = f"/tmp/rt-report-{uuid.uuid4().hex}.json"
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = rot.main(list(argv) + ["--report", rep])
    report = json.loads(Path(rep).read_text()) if Path(rep).exists() else None
    return code, out.getvalue(), report


# ─── DB helpers (throwaway superuser) ─────────────────────────────────────────────────────────

def adb():
    eng = create_async_engine(os.environ["ROT_ADMIN_URL"], poolclass=NullPool)
    return eng, async_sessionmaker(eng, expire_on_commit=False)


def arun(coro_fn, *a):
    async def wrapper():
        eng, S = adb()
        try:
            return await coro_fn(S, *a)
        finally:
            await eng.dispose()
    return asyncio.run(wrapper())


# ─── Corpus ───────────────────────────────────────────────────────────────────────────────────

def payload(n: int, seed: str) -> bytes:
    out, i = bytearray(), 0
    while len(out) < n:
        out += hashlib.sha256(f"{seed}:{i}".encode()).digest()
        i += 1
    return bytes(out[:n])


def write_v2(rel: str, data: bytes, root=None, kek: bytes = OLD) -> str:
    with mock.patch.object(settings, "evidence_kek", kek.hex()):
        return crypto.write_encrypted(data, rel, root=root).nonce_hex


def write_v0(rel: str, data: bytes, root=None, kek: bytes = OLD) -> str:
    """Exactly what the pre-3a writers did: one AES-GCM message under the raw KEK; evidence-store
    files also get a `.nonce` sidecar."""
    with mock.patch.object(settings, "evidence_kek", kek.hex()):
        ct, nonce_hex = crypto.encrypt_file_bytes(data)
    target = Path(root or settings.evidence_path) / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(ct)
    if root is None:
        target.with_name(target.name + ".nonce").write_text(nonce_hex)
    return nonce_hex


_COLLECTOR = []          # (wrapped under OLD, pem): generated once, RSA 4096 is slow


def collector_keys(n: int) -> list[tuple[str, bytes]]:
    from collectors.crypto import generate_keypair_and_cert
    while len(_COLLECTOR) < n:
        with mock.patch.object(settings, "evidence_kek", OLD.hex()):
            _cert, _fp, wrapped = generate_keypair_and_cert(f"rt-{len(_COLLECTOR)}.invalid")
            nonce_hex, b64 = wrapped.split(":", 1)
            pem = crypto.decrypt_file_bytes(base64.b64decode(b64), nonce_hex)
        _COLLECTOR.append((wrapped, pem))
    return _COLLECTOR[:n]


class Corpus:
    def __init__(self):
        self.incident = uuid.uuid4()
        self.tag = uuid.uuid4().hex[:8]
        self.items: list[dict] = []        # consumer, id, photo_id, rel, root, data, fmt
        self.keys: list[dict] = []         # id, pem
        self.evidence_rows: dict = {}      # id → dict of columns
        self.photo_rows: dict = {}         # evidence id → list of photo dicts
        self.file_rows: list = []

    def evidence(self, fmt: int, data: bytes, name: str, sha=True) -> dict:
        eid = uuid.uuid4()
        rel = f"rt-{self.tag}/{eid}/{name}"
        nonce = (write_v2 if fmt == 2 else write_v0)(rel, data)
        self.evidence_rows[eid] = dict(storage_path=rel, nonce_hex=nonce, file_size_bytes=len(data),
                                       sha256=hashlib.sha256(data).hexdigest() if sha else None)
        it = dict(consumer="evidence", id=str(eid), photo_id=None, rel=rel, root=None, data=data, fmt=fmt)
        self.items.append(it)
        return it

    def photo(self, fmt: int, data: bytes, eid=None) -> dict:
        eid = eid or uuid.uuid4()
        pid = uuid.uuid4().hex
        rel = f"photos/{eid}/{pid}.enc"
        nonce = (write_v2 if fmt == 2 else write_v0)(rel, data)
        self.photo_rows.setdefault(eid, []).append(
            {"id": pid, "url": f"/x/{pid}", "caption": None, "taken_at": None, "storage_path": rel,
             "nonce_hex": nonce, "mime_type": "image/png", "sha256": hashlib.sha256(data).hexdigest(),
             "size": len(data)})
        it = dict(consumer="photo", id=str(eid), photo_id=pid, rel=rel, root=None, data=data, fmt=fmt)
        self.items.append(it)
        return it

    def file(self, fmt: int, data: bytes, name: str, report_sha=False) -> dict:
        fid = uuid.uuid4()
        rel = f"rt-{self.tag}/files/{fid}_{name}"
        nonce = (write_v2 if fmt == 2 else write_v0)(rel, data, root=settings.logs_path)
        self.file_rows.append(dict(id=fid, file_path=rel, nonce_hex=nonce, file_size=len(data),
                                   report_sha256=hashlib.sha256(data).hexdigest() if report_sha else None))
        it = dict(consumer="file", id=str(fid), photo_id=None, rel=rel, root=settings.logs_path, data=data, fmt=fmt)
        self.items.append(it)
        return it

    def collector(self, n: int) -> None:
        for wrapped, pem in collector_keys(n):
            self.keys.append({"id": uuid.uuid4(), "wrapped": wrapped, "pem": pem})

    async def _save(self, S):
        async with S() as db, db.begin():
            db.add(Incident(id=self.incident, title="[RT] rotation test", ref=f"RT-{self.tag}"))
            await db.flush()
            for eid, cols in self.evidence_rows.items():
                db.add(Evidence(id=eid, incident_id=self.incident, kind="digital_file", name="rt", identifier=f"RT-{eid.hex[:12]}",
                                photos=self.photo_rows.pop(eid, []), **cols))
            for eid, photos in self.photo_rows.items():
                db.add(Evidence(id=eid, incident_id=self.incident, kind="physical_item", name="rt-photo",
                                identifier=f"RTP-{eid.hex[:12]}", photos=photos))
            for f in self.file_rows:
                db.add(EntityFile(incident_id=self.incident, original_name="f", **f))
            for k in self.keys:
                db.add(CollectionPackage(id=k["id"], incident_id=self.incident, name="rt", profile="triage",
                                         enc_private_key=k["wrapped"]))

    def save(self) -> "Corpus":
        arun(self._save)
        return self


def mixed_corpus(with_keys=True) -> Corpus:
    c = Corpus()
    c.evidence(2, b"", "empty.bin")
    c.evidence(2, payload(1, "a"), "one.bin")
    c.evidence(2, payload(MiB, "b"), "exact.bin")
    c.evidence(2, payload(2 * MiB + 5, "c"), "multi.bin")
    c.evidence(0, payload(1000, "d"), "legacy.bin")
    c.evidence(0, payload(70000, "e"), "legacy2.bin")
    ev = c.evidence(2, payload(300, "f"), "with-photos.bin")
    c.photo(0, payload(500, "g"), eid=uuid.UUID(ev["id"]))
    c.photo(2, payload(600, "h"), eid=uuid.UUID(ev["id"]))
    c.photo(2, payload(700, "i"))                          # physical item with a photo
    c.file(0, payload(800, "j"), "legacy.log")
    c.file(2, payload(900, "k"), "shot.png", report_sha=True)
    c.file(2, payload(MiB + 3, "l"), "big.log")
    if with_keys:
        c.collector(2)
    return c.save()


# ─── State inspection ─────────────────────────────────────────────────────────────────────────

def tree_state(skip_lock: bool = False) -> dict:
    """Every entry under both stores: content hash, mode, size, mtime. skip_lock leaves out the
    lock file, whose content (the current holder) a re-acquiring run rewrites."""
    out = {}
    for root in (EVID, LOGS):
        for dirpath, dirs, files in os.walk(root):
            for n in dirs + files:
                p = Path(dirpath) / n
                if skip_lock and p == EVID / rot.LOCK_NAME:
                    continue
                st = os.lstat(p)
                h = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() and not p.is_symlink() else None
                out[str(p)] = (h, st.st_mode, st.st_size, st.st_mtime_ns if p.is_file() else None)
    return out


async def _db_state(S, incident):
    async with S() as db:
        ev = sorted((str(r.id), r.nonce_hex, json.dumps(r.photos, sort_keys=True)) for r in
                    (await db.execute(select(Evidence).where(Evidence.incident_id == incident))).scalars())
        fl = sorted((str(r.id), r.nonce_hex) for r in
                    (await db.execute(select(EntityFile).where(EntityFile.incident_id == incident))).scalars())
        ks = sorted((str(r.id), r.enc_private_key) for r in
                    (await db.execute(select(CollectionPackage).where(CollectionPackage.incident_id == incident))).scalars())
        n = len((await db.execute(select(AuditLog.id))).all())
    return ev, fl, ks, n


def db_state(c: Corpus):
    return arun(_db_state, c.incident)


async def _row_nonce(S, it):
    async with S() as db:
        if it["consumer"] == "file":
            r = await db.get(EntityFile, uuid.UUID(it["id"]))
            return r.nonce_hex, r.file_size
        r = await db.get(Evidence, uuid.UUID(it["id"]))
        if it["consumer"] == "evidence":
            return r.nonce_hex, r.file_size_bytes
        p = next(p for p in r.photos if p["id"] == it["photo_id"])
        return p["nonce_hex"], p["size"]


def row_nonce(it):
    return arun(_row_nonce, it)


def read_with(it, kek: bytes) -> bytes:
    """The 3a dual-format reader (evidence/crypto.py), as the backend would read the row."""
    nonce_hex, size = row_nonce(it)
    with mock.patch.object(settings, "evidence_kek", kek.hex()):
        return crypto.read_decrypted(it["rel"], nonce_hex, size, root=it["root"])


async def _rekey_rows(S, run_ids=None, row_ids=None):
    async with S() as db:
        q = select(AuditLog).where(AuditLog.action.in_(sorted(set(rot.REKEY_ACTIONS.values()))))
        rows = (await db.execute(q)).scalars().all()
    out = []
    for r in rows:
        if run_ids is not None and r.request_id not in run_ids:
            continue
        if row_ids is not None and (r.details or {}).get("row_id") not in row_ids:
            continue
        out.append(r)
    return out


def rekey_rows(row_ids):
    return arun(_rekey_rows, None, set(row_ids))


async def _summary_rows(S, run_id):
    async with S() as db:
        return (await db.execute(select(AuditLog).where(AuditLog.request_id == run_id,
                                                        AuditLog.resource_type == "evidence_kek"))).scalars().all()


def path_of(it) -> Path:
    return Path(it["root"] or settings.evidence_path) / it["rel"]


def lock_path() -> Path:
    return EVID / rot.LOCK_NAME


def wipe_stores():
    for root in (EVID, LOGS):
        for p in list(root.iterdir()):
            if p.is_dir() and not p.is_symlink():
                shutil.rmtree(p)
            else:
                p.unlink()


async def _wipe_db(S):
    async with S() as db, db.begin():
        inc = select(Incident.id).where(Incident.ref.like("RT-%"))
        await db.execute(delete(CollectionPackage).where(CollectionPackage.incident_id.in_(inc)))
        await db.execute(delete(EntityFile).where(EntityFile.incident_id.in_(inc)))
        await db.execute(delete(Evidence).where(Evidence.incident_id.in_(inc)))
        await db.execute(delete(Incident).where(Incident.ref.like("RT-%")))


class Base(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        wipe_stores()
        arun(_wipe_db)

    def assertAllRead(self, c: Corpus, kek: bytes):
        for it in c.items:
            self.assertEqual(read_with(it, kek), it["data"], f"{it['consumer']} {it['rel']}")

    def assertNoneReadWithOld(self, c: Corpus):
        for it in c.items:
            with self.assertRaises(crypto.EvidenceCryptoError, msg=it["rel"]) as cm:
                read_with(it, OLD)
            self.assertNotIsInstance(cm.exception, crypto.EvidenceIntegrityError, it["rel"])
            self.assertEqual(cm.exception.reason, "wrong_kek", it["rel"])

    def assertKeysOpen(self, c: Corpus, kek: bytes):
        from collectors.crypto import _unwrap_private_key
        from cryptography.hazmat.primitives import serialization
        async def load(S):
            async with S() as db:
                return {str(r.id): r.enc_private_key for r in (await db.execute(
                    select(CollectionPackage).where(CollectionPackage.incident_id == c.incident))).scalars()}
        rows = arun(load)
        for k in c.keys:
            with mock.patch.object(settings, "evidence_kek", kek.hex()):
                key = _unwrap_private_key(rows[str(k["id"])])
            self.assertEqual(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()), k["pem"])

    def assertClean(self):
        j = rot.find_journals()
        # G-fix R3-1: "unrecognised" = stored files only named like journals (never a journal)
        self.assertEqual([p for k, v in j.items() if k != "unrecognised" for p in v], [],
                         "journals or staged copies left")
        self.assertFalse(os.path.lexists(lock_path()), "lock left behind")


# ─── 1. Dry run, full rotation, idempotency ───────────────────────────────────────────────────

class Rotation(Base):
    def test_dry_run_writes_nothing(self):
        c = mixed_corpus()
        before_tree, before_db = tree_state(), db_state(c)
        code, out, rep = tool("plan", *K())
        self.assertEqual(code, 0, out)
        acts = {(i["consumer"], i["action"]) for i in rep["items"]}
        self.assertIn(("evidence", "rewrap"), acts)
        self.assertIn(("evidence", "migrate"), acts)
        self.assertEqual({k["action"] for k in rep["collector_keys"]}, {"reencrypt"})
        code2, out2, _ = tool("rotate", *K())                 # rotate without --apply = plan
        self.assertEqual(code2, 0)
        self.assertIn("dry run", out2)
        code3, _, _ = tool("plan", "--breach", *K())
        self.assertEqual(code3, 0)
        code4, _, _ = tool("recover", *K())
        self.assertEqual(code4, 0)
        code5, _, _ = tool("verify", *K(old=None))            # before rotation: nothing opens with NEW
        self.assertEqual(code5, rot.EXIT_DO_NOT_SWAP)          # G-fix ROT-M2: v0 files are still under OLD
        self.assertEqual(tree_state(), before_tree, "a dry run changed the stores")
        self.assertEqual(db_state(c), before_db, "a dry run changed the database")

    def test_rotate_mixed_corpus(self):
        c = mixed_corpus()
        before = {str(path_of(i)): path_of(i).read_bytes() for i in c.items}
        nonces = {i["rel"]: row_nonce(i)[0] for i in c.items}
        code, out, rep = tool("rotate", *K(), *APPLY)
        self.assertEqual(code, 0, out)
        res = {(i["consumer"], i["path"]): i["result"] for i in rep["items"]}
        for it in c.items:
            self.assertEqual(res[(it["consumer"], it["rel"])], "rewrap" if it["fmt"] == 2 else "migrate", it["rel"])
            after = path_of(it).read_bytes()
            if it["fmt"] == 2:      # re-wrap: only the key slot changed, the row did not
                old_b = before[str(path_of(it))]
                self.assertEqual(after[:32], old_b[:32])
                self.assertEqual(after[80:], old_b[80:])
                self.assertNotEqual(after[32:80], old_b[32:80])
                self.assertEqual(row_nonce(it)[0], nonces[it["rel"]])
            else:                   # migrated: v2 under NEW, new prefix in the row, sidecar gone
                self.assertTrue(codec.is_streaming_format(after))
                self.assertEqual(row_nonce(it)[0], after[12:19].hex())
                self.assertFalse(path_of(it).with_name(path_of(it).name + ".nonce").exists())
        self.assertEqual({k["result"] for k in rep["collector_keys"]}, {"reencrypt"})
        self.assertAllRead(c, NEW)
        self.assertNoneReadWithOld(c)
        self.assertKeysOpen(c, NEW)
        self.assertClean()
        with self.assertRaises(Exception):
            self.assertKeysOpen(c, OLD)
        # custody: one row per item and per collector key, and one summary row
        rows = rekey_rows([i["id"] for i in c.items] + [str(k["id"]) for k in c.keys])
        self.assertEqual(len(rows), len(c.items) + len(c.keys))
        for r in rows:
            d = r.details
            self.assertEqual(r.request_id, rep["run_id"])
            self.assertEqual(d["kek_id_after"], NEW_ID)
            self.assertEqual(d["operator"], OPERATOR)
            self.assertNotIn(OLD.hex(), json.dumps(d))
            self.assertNotIn(NEW.hex(), json.dumps(d))
            if d["consumer"] in ("evidence", "photo"):
                self.assertEqual(r.action, "evidence_storage_rekeyed")
                self.assertEqual(d["incident_id"], str(c.incident))     # → shows in the custody log
        summary = arun(_summary_rows, rep["run_id"])
        self.assertEqual([s.action for s in summary], ["kek_rotation_run"])
        self.assertEqual(summary[0].outcome, "success")
        # verify: everything opens with NEW, nothing with OLD
        self.assertEqual(tool("verify", *K(old=None))[0], 0)
        self.assertEqual(tool("verify", *K())[0], 0)
        # the backend's gate is open again
        crypto.check_storage_gate((str(EVID), str(LOGS)))

    def test_idempotent_rerun(self):
        c = mixed_corpus()
        self.assertEqual(tool("rotate", *K(), *APPLY)[0], 0)
        tree, n_rows = tree_state(), len(rekey_rows([i["id"] for i in c.items] + [str(k["id"]) for k in c.keys]))
        code, out, rep = tool("rotate", *K(), *APPLY)
        self.assertEqual(code, 0, out)
        self.assertEqual({i["result"] for i in rep["items"]}, {"done"})
        self.assertEqual({k["result"] for k in rep["collector_keys"]}, {"done"})
        self.assertEqual(tree_state(), tree, "a re-run changed a file")
        self.assertEqual(len(rekey_rows([i["id"] for i in c.items] + [str(k["id"]) for k in c.keys])), n_rows)
        self.assertEqual(len(arun(_summary_rows, rep["run_id"])), 1)
        self.assertClean()

    def test_breach_reencrypts_under_fresh_data_keys(self):
        c = mixed_corpus()
        before = {i["rel"]: (path_of(i).read_bytes(), row_nonce(i)[0]) for i in c.items}
        old_deks = {}
        for it in c.items:
            if it["fmt"] == 2:
                h = codec.decode_header(before[it["rel"]][0][:80])
                old_deks[it["rel"]] = codec._open_key_slot(OLD, h)
        code, out, rep = tool("rotate", "--breach", *K(), *APPLY)
        self.assertEqual(code, 0, out)
        for it in c.items:
            data = path_of(it).read_bytes()
            nonce = row_nonce(it)[0]
            self.assertEqual(nonce, data[12:19].hex(), "row nonce_hex follows the new prefix")
            self.assertNotEqual(nonce, before[it["rel"]][1])
            if it["fmt"] == 2:
                new_dek = codec._open_key_slot(NEW, codec.decode_header(data[:80]))
                self.assertNotEqual(new_dek, old_deks[it["rel"]], "breach must not keep the data key")
                self.assertNotEqual(data[80:], before[it["rel"]][0][80:])
        self.assertEqual({i["result"] for i in rep["items"]}, {"reencrypt", "migrate"})
        self.assertAllRead(c, NEW)
        self.assertNoneReadWithOld(c)
        self.assertKeysOpen(c, NEW)
        self.assertClean()
        code, _, rep2 = tool("rotate", "--breach", *K(), *APPLY)            # idempotent
        self.assertEqual(code, 0)
        self.assertEqual({i["result"] for i in rep2["items"]}, {"done"})

    def test_breach_after_a_scheduled_rewrap_with_the_same_new_key(self):
        """A scheduled re-wrap keeps the data keys, so a later --breach run with the same NEW must
        still re-encrypt those files (decided by the custody ledger, not by 'opens with NEW')."""
        c = Corpus()
        a = c.evidence(2, payload(5000, "x"), "a.bin")
        c.evidence(2, payload(6000, "y"), "b.bin")
        c.save()
        self.assertEqual(tool("rotate", *K(), *APPLY)[0], 0)
        dek = codec._open_key_slot(NEW, codec.decode_header(path_of(a).read_bytes()[:80]))
        code, out, rep = tool("rotate", "--breach", *K(), *APPLY)
        self.assertEqual(code, 0, out)
        self.assertEqual({i["result"] for i in rep["items"]}, {"reencrypt"})
        self.assertNotEqual(codec._open_key_slot(NEW, codec.decode_header(path_of(a).read_bytes()[:80])), dek)
        self.assertAllRead(c, NEW)


NEW_ID = codec.kek_id(NEW).hex()


# ─── 2. Problem items are reported, never silently skipped or half-done ───────────────────────

class Reporting(Base):
    def test_failures_and_attention(self):
        c = Corpus()
        good = c.evidence(2, payload(4000, "ok"), "ok.bin")
        bad_v0 = c.evidence(0, payload(3000, "v0"), "bad-tag.bin")
        bad_v2 = c.evidence(2, payload(3000, "v2"), "bad-chunk.bin")
        gone = c.evidence(2, payload(100, "gone"), "gone.bin")
        alt_new = c.evidence(2, payload(100, "altnew"), "alt-new.bin")
        alt_old = c.evidence(2, payload(100, "altold"), "alt-old.bin")
        alt_to_new = c.evidence(2, payload(100, "alt2new"), "alt-to-new.bin")
        wrong_sha = c.evidence(0, payload(2000, "ws"), "wrong-sha.bin")
        c.evidence_rows[uuid.UUID(wrong_sha["id"])]["sha256"] = "0" * 64
        c.save()
        for it, off in ((bad_v0, 10), (bad_v2, 100)):
            b = bytearray(path_of(it).read_bytes()); b[off] ^= 1; path_of(it).write_bytes(bytes(b))
        path_of(gone).unlink()
        # alt_new: already under NEW but its advisory kek_id altered (R-6: report, never skip silently)
        b = bytearray(path_of(alt_new).read_bytes())
        b[:80] = codec.rewrap_header(bytes(b[:80]), OLD, NEW)
        b[33:40] = b"\x00" * 7
        path_of(alt_new).write_bytes(bytes(b))
        # alt_old: still under OLD with an altered id → re-wrapped (gets a correct id), flagged
        b = bytearray(path_of(alt_old).read_bytes()); b[33:40] = b"\xff" * 7; path_of(alt_old).write_bytes(bytes(b))
        # R-6: under OLD, but its advisory id altered to NEW's: must be re-wrapped, never skipped
        b = bytearray(path_of(alt_to_new).read_bytes()); b[33:40] = codec.kek_id(NEW); path_of(alt_to_new).write_bytes(bytes(b))
        snap = {k["rel"]: (k, path_of(k).read_bytes()) for k in (bad_v0, bad_v2, alt_new, wrong_sha)}
        code, out, rep = tool("rotate", *K(), *APPLY)
        # G-fix ROT-M2: wrong_sha is a v0 file still under OLD → 4 "do not swap" (bad_v0 opens with no key)
        self.assertEqual(code, rot.EXIT_DO_NOT_SWAP, out)
        self.assertEqual([i["path"] for i in rep["do_not_swap"]], [wrong_sha["rel"]])
        r = {i["path"]: i for i in rep["items"]}
        self.assertEqual(r[good["rel"]]["result"], "rewrap")
        self.assertEqual(r[bad_v0["rel"]]["result"], "failed")
        self.assertIn("tag", r[bad_v0["rel"]]["reason"])
        self.assertEqual(r[bad_v2["rel"]]["result"], "failed")
        self.assertIn("cannot_open", r[bad_v2["rel"]]["reason"])
        self.assertEqual(r[gone["rel"]]["result"], "attention")
        self.assertEqual(r[alt_new["rel"]]["result"], "attention")
        self.assertIn("kek_id_mismatch", r[alt_new["rel"]]["reason"])
        self.assertEqual(r[alt_old["rel"]]["result"], "rewrap")
        self.assertIn("kek_id_altered", r[alt_old["rel"]]["warnings"])
        self.assertEqual(r[alt_to_new["rel"]]["result"], "rewrap")
        self.assertEqual(read_with(alt_to_new, NEW), alt_to_new["data"])
        self.assertEqual(r[wrong_sha["rel"]]["result"], "failed")
        self.assertIn("hash_mismatch", r[wrong_sha["rel"]]["reason"])
        self.assertEqual(row_nonce(wrong_sha)[0], c.evidence_rows[uuid.UUID(wrong_sha["id"])]["nonce_hex"])
        for rel, (k, v) in snap.items():
            self.assertEqual(path_of(k).read_bytes(), v, f"{rel} was modified")
        self.assertTrue(path_of(bad_v0).with_name(path_of(bad_v0).name + ".nonce").exists())
        self.assertEqual(path_of(alt_old).read_bytes()[33:40], codec.kek_id(NEW))
        self.assertClean()          # the pass completed with no journal: the lock goes (§6.4)
        summary = arun(_summary_rows, rep["run_id"])
        self.assertEqual(summary[0].outcome, "failure")
        self.assertEqual(tool("verify", *K(old=None))[0], rot.EXIT_DO_NOT_SWAP)   # G-fix: v0 files left under OLD

    def test_a_bad_staged_copy_is_never_swapped_in(self):
        """§5.4 step 2: the staged copy is decrypted and checked before the swap. Simulate a
        write that lands wrong: the item fails, the original and its row stay as they were."""
        c = Corpus()
        it = c.evidence(0, payload(5000, "st"), "staged.bin")
        c.save()
        snap, nonce = path_of(it).read_bytes(), row_nonce(it)[0]
        real = rot._chunked_encrypt

        def corrupting(fd, enc, blocks, hasher):
            n = real(fd, enc, blocks, hasher)
            os.pwrite(fd, b"\x00", 100)              # one byte of chunk 0 written wrong
            return n
        with mock.patch.object(rot, "_chunked_encrypt", corrupting):
            code, out, rep = tool("rotate", *K(), *APPLY)
        self.assertEqual(code, rot.EXIT_DO_NOT_SWAP, out)          # G-fix ROT-M2: a v0 file left under OLD
        self.assertEqual(rep["items"][0]["result"], "failed")
        self.assertIn("staged copy did not verify", rep["items"][0]["reason"])
        self.assertEqual(path_of(it).read_bytes(), snap)
        self.assertEqual(row_nonce(it)[0], nonce)
        self.assertClean()

    def test_breach_refuses_to_rebind_a_swapped_file(self):
        """Q5: a v2 file whose prefix does not match its row is re-wrapped (key maintenance, row
        untouched) with a warning, but a re-encrypt would bind it to the row, so it is refused."""
        c = Corpus()
        it = c.evidence(2, payload(2000, "q5"), "q5.bin")
        c.evidence_rows[uuid.UUID(it["id"])]["nonce_hex"] = "00" * 7
        c.save()
        snap = path_of(it).read_bytes()
        code, _, rep = tool("rotate", "--breach", *K(), *APPLY)
        self.assertEqual(code, 1)
        self.assertEqual(rep["items"][0]["result"], "failed")
        self.assertEqual(path_of(it).read_bytes(), snap)
        code, _, rep = tool("rotate", *K(), *APPLY)
        self.assertEqual(code, 1)
        self.assertEqual(rep["items"][0]["result"], "rewrap")
        self.assertIn("nonce_mismatch", rep["items"][0]["warnings"])
        self.assertEqual(row_nonce(it)[0], "00" * 7)


# ─── 3. Preconditions ─────────────────────────────────────────────────────────────────────────

class Refusals(Base):
    def setUp(self):
        super().setUp()
        self.c = Corpus()
        self.it = self.c.evidence(2, payload(1000, "r"), "r.bin")
        self.c.save()
        self.snap = tree_state()

    def assertRefusedUntouched(self, code):
        self.assertEqual(code, rot.EXIT_REFUSED)
        self.assertEqual(tree_state(), self.snap)

    def test_lock_held_by_another_run(self):
        fd = os.open(lock_path(), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            code, _, _ = tool("rotate", *K(), *APPLY)
            self.assertEqual(code, rot.EXIT_REFUSED)
            self.assertIsNone(opens_with(self.it, NEW))
            self.assertIsNotNone(opens_with(self.it, OLD))
        finally:
            os.close(fd)
            os.unlink(lock_path())

    def _with_session(self, url):
        async def go():
            conn = await asyncpg.connect(url)
            try:
                return await asyncio.to_thread(tool, "rotate", *K(), *APPLY)
            finally:
                await conn.close()
        return asyncio.run(go())

    def test_backend_session_open(self):
        code, _, _ = self._with_session(os.environ["ROT_APP_URL"])
        self.assertRefusedUntouched(code)

    def test_backup_session_open(self):
        code, _, _ = self._with_session(os.environ["ROT_BACKUP_URL"])
        self.assertRefusedUntouched(code)

    def test_key_files(self):
        new = keyfile("new", NEW)
        old = keyfile("old", OLD, mode=0o620)                       # group-writable
        self.assertRefusedUntouched(tool("rotate", "--old-kek-file", old, "--new-kek-file", new, *APPLY)[0])
        old = keyfile("old", OLD)
        link = KEYDIR / "link"
        if link.is_symlink():
            link.unlink()
        link.symlink_to(old)
        self.assertRefusedUntouched(tool("rotate", "--old-kek-file", str(link), "--new-kek-file", new, *APPLY)[0])
        short = KEYDIR / "short"
        short.write_text("ab" * 31)
        os.chmod(short, 0o600)
        self.assertRefusedUntouched(tool("rotate", "--old-kek-file", str(short), "--new-kek-file", new, *APPLY)[0])
        self.assertRefusedUntouched(tool("rotate", *K(old=NEW, new=NEW), *APPLY)[0])
        _, out, _ = tool("rotate", *K(), *APPLY)                    # the real keys never appear in output
        self.assertNotIn(OLD.hex(), out)

    def test_apply_needs_operator_and_confirmation(self):
        self.assertRefusedUntouched(tool("rotate", *K(), "--apply", "--yes")[0])
        self.assertFalse(sys.stdin.isatty())
        self.assertRefusedUntouched(tool("rotate", *K(), "--apply", "--operator", OPERATOR)[0])
        self.assertFalse(os.path.lexists(lock_path()))


def opens_with(it, kek):
    b = path_of(it).read_bytes()
    return rot.opens(kek, b[:80], b[80:80 + codec.SEGMENT_LEN])


# ─── 4. Re-wrap recovery: torn slot at every byte split, R-1 key scenarios, bad journals ──────

def journalled_state(it, cut: int) -> tuple[Path, bytes]:
    """The state a crash leaves: journal written, slot torn after `cut` of 48 bytes."""
    p = path_of(it)
    data = p.read_bytes()
    header = data[:80]
    new_header = codec.rewrap_header(header, OLD, NEW)
    j = p.with_name(p.name + rot.KEYSLOT)
    j.write_bytes(rot.keyslot_journal(header, new_header))
    torn = new_header[32:32 + cut] + header[32 + cut:80]
    with open(p, "r+b") as f:
        f.seek(32)
        f.write(torn)
    return j, new_header


class KeyslotRecovery(Base):
    def setUp(self):
        super().setUp()
        self.c = Corpus()
        self.it = self.c.evidence(2, payload(3 * MiB + 7, "torn"), "torn.bin")
        self.c.save()
        self.orig = path_of(self.it).read_bytes()

    def reset(self):
        path_of(self.it).write_bytes(self.orig)
        for p in rot.find_journals()["keyslot"]:
            p.unlink()

    def test_torn_slot_every_split(self):
        results = {}
        for cut in range(0, 49):
            for old, new, label in ((NEW, NEW2, "next-rotation"), (OLD, NEW2, "mistyped-new")):
                self.reset()
                j, _ = journalled_state(self.it, cut)
                before = path_of(self.it).read_bytes()
                outcome, detail = rot.recover_keyslot(j, old, new, apply=True)
                self.assertEqual(outcome, "manual", f"cut {cut} {label}")
                self.assertEqual(path_of(self.it).read_bytes(), before, f"cut {cut} {label}: wrote bytes")
                self.assertTrue(j.exists())
            self.reset()
            j, new_header = journalled_state(self.it, cut)
            outcome, detail = rot.recover_keyslot(j, OLD, NEW, apply=True)
            results.setdefault(outcome, []).append(cut)
            self.assertFalse(j.exists(), f"cut {cut}")
            self.assertEqual(path_of(self.it).read_bytes()[:80], new_header, f"cut {cut}")
            self.assertEqual(read_with(self.it, NEW), self.it["data"], f"cut {cut}")
        self.assertEqual(results.get("finished"), [48])           # fully written: nothing to write
        self.assertEqual(results.get("rolled_forward"), list(range(0, 48)))

    def test_r1_scenarios_from_the_review(self):
        """recovery_sim.py: crash after step 6, before the journal unlink."""
        for old, new, expect, opens_new in ((OLD, NEW, "finished", True), (NEW, NEW2, "manual", True),
                                            (OLD, NEW2, "manual", True)):
            self.reset()
            j, new_header = journalled_state(self.it, 48)
            before = path_of(self.it).read_bytes()
            outcome, _ = rot.recover_keyslot(j, old, new, apply=True)
            self.assertEqual(outcome, expect, (old.hex()[:2], new.hex()[:2]))
            if expect == "manual":
                self.assertEqual(path_of(self.it).read_bytes(), before, "manual stop wrote bytes")
            self.assertIsNotNone(opens_with(self.it, NEW), "a completed rotation was reverted")
            self.assertIsNone(opens_with(self.it, NEW2))

    def test_bad_and_planted_journals(self):
        p = path_of(self.it)
        j = p.with_name(p.name + rot.KEYSLOT)
        header = self.orig[:80]
        good = rot.keyslot_journal(header, codec.rewrap_header(header, OLD, NEW))
        other = Corpus()
        o = other.evidence(2, payload(10, "other"), "o.bin")
        other_hdr = path_of(o).read_bytes()[:80]
        rnd = os.urandom(40)
        planted_garbage = (b"FENRKSJ1" + header[:32] + header[32:40] + rnd + bytes([1]) + codec.kek_id(NEW) + rnd)
        planted_garbage += hashlib.sha256(planted_garbage).digest()
        cases = {f"truncated-{n}": good[:n] for n in (0, 1, 8, 40, 100, 167)}
        cases.update({"extra-byte": good + b"\x00", "zeroed": bytes(168),
                      "other-file": rot.keyslot_journal(other_hdr, codec.rewrap_header(other_hdr, OLD, NEW)),
                      "planted-garbage-slots": planted_garbage})
        for pos in (0, 9, 45, 100, 140, 167):
            b = bytearray(good); b[pos] ^= 0x10; cases[f"bitflip-{pos}"] = bytes(b)
        for name, data in cases.items():
            self.reset()
            j.write_bytes(data)
            outcome, detail = rot.recover_keyslot(j, OLD, NEW, apply=True)
            self.assertEqual(outcome, "manual", f"{name}: {detail}")
            self.assertEqual(p.read_bytes(), self.orig, f"{name}: file modified")
            self.assertTrue(j.exists())
        # through the CLI: exit 3, lock and journal kept, backend gate closed, file untouched
        self.reset()
        j.write_bytes(bytes(168))
        code, out, rep = tool("rotate", *K(), *APPLY)
        self.assertEqual(code, rot.EXIT_MANUAL)
        self.assertTrue(lock_path().exists() and j.exists())
        self.assertEqual(p.read_bytes(), self.orig)
        with self.assertRaises(RuntimeError):
            crypto.check_storage_gate((str(EVID), str(LOGS)))
        os.unlink(j)
        code, out, _ = tool("rotate", *K(), *APPLY)              # once the operator removed it
        self.assertEqual(code, 0, out)
        self.assertClean()

    def test_planted_valid_slot_never_reverts_or_corrupts(self):
        p = path_of(self.it)
        j = p.with_name(p.name + rot.KEYSLOT)
        header = self.orig[:80]
        other = Corpus()
        o = other.evidence(2, payload(10, "other2"), "o.bin")
        other_new_slot = codec.rewrap_header(path_of(o).read_bytes()[:80], OLD, NEW)[32:80]
        # new_slot from another file (valid NEW slot, wrong DEK): only the verified OLD slot is written
        body = b"FENRKSJ1" + header[:32] + header[32:80] + other_new_slot
        j.write_bytes(body + hashlib.sha256(body).digest())
        outcome, _ = rot.recover_keyslot(j, OLD, NEW, apply=True)
        self.assertEqual(outcome, "rolled_back")
        self.assertEqual(p.read_bytes(), self.orig)
        # file already rotated; a journal planted from a pre-rotation copy must not revert it
        self.assertEqual(tool("rotate", *K(), *APPLY)[0], 0)
        rotated = p.read_bytes()
        j.write_bytes(rot.keyslot_journal(header, codec.rewrap_header(header, OLD, NEW)))
        outcome, _ = rot.recover_keyslot(j, OLD, NEW, apply=True)
        self.assertEqual(outcome, "finished")
        self.assertEqual(p.read_bytes(), rotated)

    def test_dry_runs_with_a_journal_write_nothing(self):
        j, _ = journalled_state(self.it, 20)
        snap = tree_state()
        for argv in (("plan", *K()), ("rotate", *K()), ("recover", *K()), ("verify", *K(old=None))):
            code, out, rep = tool(*argv)
            self.assertNotEqual(code, rot.EXIT_REFUSED, argv)
        self.assertEqual(tree_state(), snap)
        code, out, rep = tool("plan", *K())
        self.assertEqual(rep["recovery_preview"][0]["outcome"], "rolled_forward")

    def test_journal_of_another_file_is_never_consumed(self):
        """Step 2: even when this file already opens with NEW (step 4 would say 'finished'), a
        journal whose bytes 0-31 are another file's is a manual stop, and it is kept."""
        self.assertEqual(tool("rotate", *K(), *APPLY)[0], 0)
        other = Corpus()
        o = other.evidence(2, payload(10, "other3"), "o.bin")
        oh = path_of(o).read_bytes()[:80]
        p = path_of(self.it)
        j = p.with_name(p.name + rot.KEYSLOT)
        j.write_bytes(rot.keyslot_journal(oh, codec.rewrap_header(oh, OLD, NEW)))
        before = p.read_bytes()
        outcome, detail = rot.recover_keyslot(j, OLD, NEW, apply=True)
        self.assertEqual(outcome, "manual", detail)
        self.assertTrue(j.exists())
        self.assertEqual(p.read_bytes(), before)

    def test_step7_catches_a_write_that_did_not_land(self):
        """A lying or failing disk: the slot written is not the slot meant. Step 7 must stop the
        run with the journal kept (no DEK lost); recovery then restores the verified slot."""
        def faulty(fd, slot):
            bad = bytearray(slot)
            bad[20] ^= 0x01                         # inside the wrapped DEK
            os.pwrite(fd, bytes(bad), codec.KEY_SLOT_OFFSET)
            os.fsync(fd)
        with mock.patch.object(rot, "_pwrite_slot", faulty):
            code, out, rep = tool("rotate", *K(), *APPLY)
        self.assertEqual(code, rot.EXIT_MANUAL, out)
        self.assertEqual(len(rot.find_journals()["keyslot"]), 1)
        self.assertTrue(lock_path().exists())
        self.assertIsNone(opens_with(self.it, NEW))
        self.assertIsNone(opens_with(self.it, OLD))       # torn: only the journal can save it
        code, out, rep = tool("rotate", *K(), *APPLY)
        self.assertEqual(code, 0, out)
        self.assertEqual(rep["recovery"][0]["outcome"], "rolled_forward")
        self.assertAllRead(self.c, NEW)
        self.assertClean()

    def test_stray_tmp_journal_is_dropped(self):
        p = path_of(self.it)
        p.with_name(p.name + rot.KEYSLOT + rot.TMP).write_bytes(b"FENRKSJ1 torn")
        code, out, rep = tool("rotate", *K(), *APPLY)
        self.assertEqual(code, 0, out)
        self.assertEqual(rep["recovery"][0]["outcome"], "stray_tmp_removed")
        self.assertAllRead(self.c, NEW)
        self.assertClean()


# ─── 5. Crash injection (child process, os._exit at a protocol step) ──────────────────────────

def crash_child():
    """Entry point of the crashing child. ROT_CRASH = step, ROT_CRASH_NTH = which occurrence."""
    point, nth = os.environ["ROT_CRASH"], int(os.environ.get("ROT_CRASH_NTH", "1"))
    seen = [0]

    def hit() -> bool:
        seen[0] += 1
        return seen[0] == nth

    def die():
        os._exit(137)

    real_wd, real_pw, real_ul = rot._write_durable, rot._pwrite_slot, rot._unlink_durable
    real_rn, real_commit, real_audit = rot._rename_into_place, rot.commit_rewrite, rot._audit_item

    if point in ("ksj_tmp", "rwj_tmp", "ksj_renamed", "rwj_renamed", "staged"):
        suffix = rot.KEYSLOT if point.startswith("ksj") else rot.REWRITE

        def wd(path, data):
            if path.name.endswith(suffix) and hit():
                if point == "staged":
                    die()
                if point.endswith("_tmp"):
                    fd = os.open(path.with_name(path.name + rot.TMP), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    os.write(fd, data[:len(data) // 2])
                    os.fsync(fd)
                    die()
                real_wd(path, data)
                die()
            return real_wd(path, data)
        rot._write_durable = wd
    elif point.startswith("torn:") or point == "after_pwrite":
        def pw(fd, slot):
            if hit():
                if point == "after_pwrite":
                    real_pw(fd, slot)
                else:
                    os.pwrite(fd, slot[:int(point[5:])], codec.KEY_SLOT_OFFSET)
                    os.fsync(fd)
                die()
            return real_pw(fd, slot)
        rot._pwrite_slot = pw
    elif point in ("ksj_unlinked", "rwj_unlink"):
        suffix = rot.KEYSLOT if point == "ksj_unlinked" else rot.REWRITE

        def ul(path):
            if path.name.endswith(suffix) and hit():
                if point == "ksj_unlinked":
                    real_ul(path)
                die()
            return real_ul(path)
        rot._unlink_durable = ul
    elif point == "before_audit":
        async def au(db, details):
            if hit():
                die()
            return await real_audit(db, details)
        rot._audit_item = au
    elif point == "renamed":
        def rn(a, b):
            real_rn(a, b)
            if hit():
                die()
        rot._rename_into_place = rn
    elif point == "committed":
        async def cm(*a, **k):
            r = await real_commit(*a, **k)
            if hit():
                die()
            return r
        rot.commit_rewrite = cm
    else:
        raise SystemExit(f"unknown crash point {point}")
    with contextlib.redirect_stdout(io.StringIO()):
        code = rot.main(json.loads(os.environ["ROT_ARGS"]))
    os._exit(99 if code == 0 else 98)          # the crash point was never reached


def crash(point: str, argv: list[str], nth: int = 2) -> int:
    env = dict(os.environ, ROT_CRASH=point, ROT_CRASH_NTH=str(nth), ROT_ARGS=json.dumps(argv))
    p = subprocess.run([sys.executable, "-c", "from tests.test_rotation import crash_child; crash_child()"],
                       env=env, cwd="/src", capture_output=True, text=True, timeout=300)
    return p.returncode


class Crash(Base):
    def corpus_v2(self) -> Corpus:
        c = Corpus()
        for n in range(3):
            c.evidence(2, payload(MiB + 100 * n, f"cr{n}"), f"cr{n}.bin")
        c.collector(1)
        return c.save()

    def corpus_v0(self) -> Corpus:
        c = Corpus()
        c.evidence(0, payload(9000, "m0"), "m0.bin")
        c.evidence(0, payload(9100, "m1"), "m1.bin")
        c.photo(0, payload(9200, "m2"))
        c.file(0, payload(9300, "m3"), "m3.log")
        return c.save()

    def resume_and_check(self, c: Corpus, point: str, argv_extra=()):
        self.assertTrue(lock_path().exists(), f"{point}: the lock must survive a crash")
        with self.assertRaises(RuntimeError, msg=point):
            crypto.check_storage_gate((str(EVID), str(LOGS)))
        code, out, rep = tool("rotate", *argv_extra, *K(), *APPLY)
        self.assertEqual(code, 0, f"{point}: {out}")
        self.assertAllRead(c, NEW)
        self.assertNoneReadWithOld(c)
        self.assertClean()
        per = {}
        for r in rekey_rows([i["id"] for i in c.items]):      # fresh ids: rows of this test only
            k = (r.details["row_id"], r.details.get("photo_id"))
            per[k] = per.get(k, 0) + 1
        for it in c.items:
            self.assertEqual(per.get((it["id"], it["photo_id"])), 1, f"{point}: custody rows for {it['rel']}")
        for it in c.items:          # rows and headers agree (Q5)
            self.assertEqual(row_nonce(it)[0], path_of(it).read_bytes()[12:19].hex(), point)
        if c.keys:
            self.assertKeysOpen(c, NEW)
        return rep

    def test_rewrap_crash_matrix(self):
        points = ["ksj_tmp", "ksj_renamed", "torn:1", "torn:8", "torn:24", "torn:47", "after_pwrite",
                  "ksj_unlinked", "before_audit"]
        for point in points:
            with self.subTest(point=point):
                self.setUp()
                c = self.corpus_v2()
                code = crash(point, ["rotate", *K(), *APPLY])
                self.assertEqual(code, 137, f"{point}: the child did not crash")
                self.resume_and_check(c, point)

    def test_rewrite_crash_matrix(self):
        points = ["staged", "rwj_tmp", "rwj_renamed", "renamed", "before_audit", "committed", "rwj_unlink"]
        for breach in (False, True):
            for point in points:
                with self.subTest(point=point, breach=breach):
                    self.setUp()
                    c = self.corpus_v2() if breach else self.corpus_v0()
                    extra = ["--breach"] if breach else []
                    code = crash(point, ["rotate", *extra, *K(), *APPLY])
                    self.assertEqual(code, 137, f"{point}: the child did not crash")
                    self.resume_and_check(c, point, extra)

    def test_rewrite_recovery_with_wrong_keys_writes_nothing(self):
        c = self.corpus_v0()
        self.assertEqual(crash("renamed", ["rotate", *K(), *APPLY], nth=1), 137)
        before_tree, before_db = tree_state(skip_lock=True), db_state(c)
        code, out, rep = tool("recover", *K(old=OLD, new=NEW2), *APPLY)      # NEW mistyped
        self.assertEqual(code, rot.EXIT_MANUAL, out)
        self.assertIn("written for NEW id", json.dumps(rep["recovery"]))
        self.assertTrue(lock_path().exists())
        self.assertEqual(tree_state(skip_lock=True), before_tree)
        self.assertEqual(db_state(c)[:3], before_db[:3])
        code, out, rep = tool("recover", *K(), *APPLY)
        self.assertEqual(code, 0, out)
        self.assertEqual([r["outcome"] for r in rep["recovery"]], ["completed"])
        # R3-6: an interrupted `rotate` wrote the lock: recover keeps it until rotate finishes
        self.assertTrue(lock_path().exists())
        self.assertFalse(rep["lock_removed"])
        self.assertIsNotNone(rep["lock_kept_for_rotate"])
        with self.assertRaises(RuntimeError):
            crypto.check_storage_gate((str(EVID), str(LOGS)))
        self.assertEqual(tool("rotate", *K(), *APPLY)[0], 0)
        self.assertAllRead(c, NEW)
        self.assertClean()

    def test_rewrite_recovery_never_commits_an_unverified_file(self):
        c = self.corpus_v0()
        self.assertEqual(crash("renamed", ["rotate", *K(), *APPLY], nth=1), 137)
        target = rot.find_journals()["rewrite"][0].with_name(rot.find_journals()["rewrite"][0].name[:-len(rot.REWRITE)])
        b = bytearray(target.read_bytes()); b[100] ^= 1; target.write_bytes(bytes(b))      # chunk 0
        before_db = db_state(c)[:3]
        code, out, rep = tool("recover", *K(), *APPLY)
        self.assertEqual(code, rot.EXIT_MANUAL, out)
        self.assertIn("does not verify under NEW", json.dumps(rep["recovery"]))
        self.assertEqual(db_state(c)[:3], before_db, "the row was committed to an unverified file")
        self.assertTrue(lock_path().exists())

    def test_bad_rewrite_journal_stops(self):
        c = self.corpus_v0()
        self.assertEqual(crash("renamed", ["rotate", *K(), *APPLY], nth=1), 137)
        j = rot.find_journals()["rewrite"][0]
        good = j.read_bytes()
        for name, data in (("truncated", good[:-10]), ("zeroed", bytes(len(good))),
                           ("bitflip", good[:20] + bytes([good[20] ^ 1]) + good[21:])):
            j.write_bytes(data)
            snap = tree_state(skip_lock=True)
            code, _, rep = tool("recover", *K(), *APPLY)
            self.assertEqual(code, rot.EXIT_MANUAL, name)
            self.assertEqual(tree_state(skip_lock=True), snap, name)
        j.write_bytes(good)
        self.assertEqual(tool("rotate", *K(), *APPLY)[0], 0)
        self.assertAllRead(c, NEW)


if __name__ == "__main__":
    unittest.main()


# ─── 6. G-fix (2026-10-04): journals by content, destroyed photos, do-not-swap, lock and resume rules ──

class GfixA(Base):
    def file_named(self, name: str, data: bytes) -> dict:
        """An entity / incident file whose stored name ends like a journal (a legacy row: no .enc suffix)."""
        c = Corpus()
        it = c.file(2, data, name)
        c.save()
        return it

    def test_r3_1_stored_files_named_like_journals_are_rotated_never_touched_as_journals(self):
        c = Corpus()
        named = [c.file(2, payload(700 + n, f"j{n}"), name) for n, name in
                 enumerate(("x.keyslot", "x.rewrite", "x.keyslot.tmp", "x.rewrite.tmp"))]
        legacy = c.file(0, payload(900, "jv0"), "y.keyslot")          # v0: random-looking ciphertext
        c.save()
        snap = {it["rel"]: path_of(it).read_bytes() for it in named + [legacy]}
        crypto.check_storage_gate((str(EVID), str(LOGS)))              # the backend starts
        j = rot.find_journals()                                        # by content alone
        self.assertEqual([p for k in ("keyslot", "rewrite", "keyslot_tmp", "rewrite_tmp") for p in j[k]], [],
                         "a v2 container is never a journal, whatever its name")
        code, out, rep = tool("plan", *K())
        self.assertEqual(code, 0, out)
        self.assertEqual(rep["recovery_preview"], [])
        code, out, rep = tool("rotate", *K(), *APPLY)
        self.assertEqual(code, 0, out)
        res = {i["path"]: i["result"] for i in rep["items"]}
        for it in named:
            self.assertEqual(res[it["rel"]], "rewrap", it["rel"])
            self.assertTrue(path_of(it).exists(), f"{it['rel']} was deleted as a stray journal")
            self.assertEqual(read_with(it, NEW), it["data"])
            self.assertEqual(path_of(it).read_bytes()[80:], snap[it["rel"]][80:])
        self.assertEqual(res[legacy["rel"]], "migrate")
        self.assertEqual(read_with(legacy, NEW), legacy["data"])
        self.assertClean()
        self.assertEqual(tool("verify", *K(old=None))[0], 0)
        crypto.check_storage_gate((str(EVID), str(LOGS)))

    def test_r3_1_unreferenced_lookalikes(self):
        """A journal-named file no row references and without the magic: a temporary one is reported and
        never deleted; a non-temporary one stops the run (a corrupt journal or a foreign file)."""
        c = Corpus()
        it = c.evidence(2, payload(3000, "lk"), "lk.bin")
        c.save()
        d = LOGS / f"rt-{c.tag}" / "files"
        d.mkdir(parents=True, exist_ok=True)
        tmp = d / "orphan_x.keyslot.tmp"
        tmp.write_bytes(b"not a journal at all")
        torn = path_of(it).with_name(path_of(it).name + rot.REWRITE + rot.TMP)
        torn.write_bytes(rot.RWJ_MAGIC[:3])                          # a torn temporary journal
        code, out, rep = tool("rotate", *K(), *APPLY)
        self.assertEqual(code, 0, out)
        outcomes = {Path(r["journal"]).name: r["outcome"] for r in rep["recovery"]}
        self.assertEqual(outcomes[tmp.name], "unrecognised_tmp")
        self.assertEqual(outcomes[torn.name], "stray_tmp_removed")
        self.assertTrue(tmp.exists(), "a file that is not a journal was deleted")
        self.assertFalse(torn.exists())
        tmp.unlink()
        bogus = d / "orphan_y.rewrite"
        bogus.write_bytes(b"zz" * 50)
        snap = tree_state()
        code, out, rep = tool("rotate", *K(), *APPLY)
        self.assertEqual(code, rot.EXIT_MANUAL, out)
        self.assertTrue(bogus.exists())
        self.assertEqual(tree_state(skip_lock=True), snap, "a manual stop wrote something")
        bogus.unlink()
        os.unlink(lock_path())

    def test_rot_h2_destroyed_exhibit_photos_are_not_stored_files(self):
        """A destroyed exhibit whose photo entries still name their (deleted) files — rows destroyed before
        G-fix — no longer blocks rotate / verify / mirror-verify."""
        c = Corpus()
        ev = c.evidence(2, payload(500, "d0"), "d.bin")
        ph = c.photo(2, payload(600, "d1"), eid=uuid.UUID(ev["id"]))
        keep = c.evidence(2, payload(700, "d2"), "keep.bin")
        c.save()

        async def destroy(S):
            async with S() as db, db.begin():
                row = await db.get(Evidence, uuid.UUID(ev["id"]))
                row.status, row.storage_path, row.nonce_hex = "destroyed", None, None
        arun(destroy)
        path_of(ev).unlink()
        path_of(ph).unlink()                                         # photo row still names it
        code, out, rep = tool("rotate", *K(), *APPLY)
        self.assertEqual(code, 0, out)
        self.assertEqual({i["path"] for i in rep["items"]}, {keep["rel"]})
        self.assertEqual(tool("verify", *K(old=None))[0], 0)
        self.assertClean()

    def test_rot_m2_do_not_swap_while_a_v0_item_failed(self):
        c = Corpus()
        good = c.evidence(2, payload(4000, "ok"), "ok.bin")
        v0 = c.evidence(0, payload(5000, "st"), "stuck.bin")
        c.save()
        real = rot._chunked_encrypt

        def corrupting(fd, enc, blocks, hasher):
            n = real(fd, enc, blocks, hasher)
            os.pwrite(fd, b"\x00", 100)
            return n
        code, out, rep = tool("plan", *K())
        self.assertEqual(code, 0, out)
        with mock.patch.object(rot, "_chunked_encrypt", corrupting):
            code, out, rep = tool("rotate", *K(), *APPLY)
        self.assertEqual(code, rot.EXIT_DO_NOT_SWAP, out)
        self.assertEqual([i["path"] for i in rep["do_not_swap"]], [v0["rel"]])
        self.assertEqual(read_with(v0, OLD), v0["data"], "the v0 file is untouched, still under OLD")
        self.assertEqual(read_with(good, NEW), good["data"])
        code, out, rep = tool("verify", *K(old=None))                # after a (wrong) swap: verify says so
        self.assertEqual(code, rot.EXIT_DO_NOT_SWAP)
        self.assertEqual([i["path"] for i in rep["do_not_swap"]], [v0["rel"]])
        self.assertEqual(tool("rotate", *K(), *APPLY)[0], 0)          # fixed (no fault): migrated
        self.assertEqual(tool("verify", *K(old=None))[0], 0)

    def test_rot_l6_files_written_under_new_get_no_custody_row(self):
        c = mixed_corpus(with_keys=True)
        self.assertEqual(tool("rotate", *K(), *APPLY)[0], 0)
        later = Corpus()                                              # written by the backend after the swap
        n2 = later.evidence(2, payload(800, "new"), "new.bin")
        path_of(n2).unlink()
        later.evidence_rows[uuid.UUID(n2["id"])]["nonce_hex"] = write_v2(n2["rel"], n2["data"], kek=NEW)
        later.collector(1)
        later.save()

        async def rewrap_key(S):                                      # the collector key, created under NEW
            async with S() as db, db.begin():
                row = await db.get(CollectionPackage, later.keys[0]["id"])
                with mock.patch.object(settings, "evidence_kek", NEW.hex()):
                    ct, nonce = crypto.encrypt_file_bytes(later.keys[0]["pem"])
                row.enc_private_key = f"{nonce}:{base64.b64encode(ct).decode()}"
        arun(rewrap_key)
        before = len(rekey_rows([n2["id"], str(later.keys[0]["id"])]))
        code, out, rep = tool("rotate", *K(), *APPLY)                 # no lock: not a resumed run
        self.assertEqual(code, 0, out)
        r = {i["id"]: i for i in rep["items"]}
        self.assertEqual(r[n2["id"]]["result"], "done")
        self.assertIn("written under NEW", r[n2["id"]]["reason"])
        k = {x["id"]: x for x in rep["collector_keys"]}
        self.assertEqual(k[str(later.keys[0]["id"])]["result"], "done")
        self.assertEqual(len(rekey_rows([n2["id"], str(later.keys[0]["id"])])), before, "a false recorded_on_resume row")

    def test_rot_l8_recover_rechecks_sessions_after_taking_the_lock(self):
        c = Corpus()
        it = c.evidence(2, payload(3 * MiB + 7, "l8"), "l8.bin")
        c.save()
        journalled_state(it, 20)
        calls = []

        async def sessions_then_one(sessions):
            calls.append(1)
            return [] if len(calls) == 1 else [{"pid": 1, "role": "fenrir_app", "application_name": "x", "since": None}]
        snap = tree_state()
        with mock.patch.object(rot, "other_sessions", sessions_then_one):
            code, out, rep = tool("recover", *K(), *APPLY)
        self.assertEqual(code, rot.EXIT_REFUSED, out)
        self.assertEqual(len(calls), 2, "sessions checked again once the lock was taken")
        # nothing recovered; the lock stays only because a journal is still there (the gate holds anyway)
        self.assertEqual(tree_state(skip_lock=True), snap)
        self.assertEqual(len(rot.find_journals()["keyslot"]), 1)
        os.unlink(lock_path())

    def test_rot_m2_plan_says_do_not_swap_for_a_v0_file_it_can_not_migrate(self):
        c = Corpus()
        v0 = c.evidence(0, payload(2000, "sz"), "size.bin")
        c.evidence_rows[uuid.UUID(v0["id"])]["file_size_bytes"] = 1999      # the row's size is wrong
        c.save()
        code, out, rep = tool("plan", *K())
        self.assertEqual(code, rot.EXIT_DO_NOT_SWAP, out)
        self.assertEqual([i["path"] for i in rep["do_not_swap"]], [v0["rel"]])
        self.assertEqual(rep["items"][0]["reason"], "size_mismatch")
