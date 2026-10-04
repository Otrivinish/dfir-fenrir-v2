"""Unit tests for G2 (R04 part 2): bounded-RAM downloads, streamed export bundles and LE-package entries
(evidence/streaming.py, evidence/exports.py, le_package/builder.py; docs/streaming-aes-gcm-format.md §6.3 F-12).

stdlib unittest; no DB, no network (an in-process uvicorn on 127.0.0.1 serves the download tests, through a
BaseHTTPMiddleware like the app's). From the repo root:

    docker run --rm --network none --read-only --tmpfs /tmp \
      --tmpfs /evidence:uid=1001,gid=1001 --tmpfs /asset_logs:uid=1001,gid=1001 \
      -v "$PWD/backend:/src:ro" -w /src -e PYTHONPATH=/src -e PYTHONDONTWRITEBYTECODE=1 \
      -e EVIDENCE_PATH=/evidence -e LOGS_PATH=/asset_logs \
      -e DATABASE_URL=postgresql+asyncpg://nobody:none@127.0.0.1:1/none \
      -e EVIDENCE_KEK=$(python3 -c "print('11'*32)") \
      --entrypoint python dfir-fenrir-v2-backend:local -m unittest tests.test_g2_streaming -v

G2_BIG=1 adds the large cases (a > 4 GiB ZIP64 export entry and LE entry, a 2 GiB streamed download with its
peak RSS); give them a disk-backed /evidence instead of the tmpfs (-v <host dir>:/evidence) and ~10 GiB free.
"""
import asyncio
import contextlib
import hashlib
import io
import os
import shutil
import threading
import time
import types
import unittest
import uuid
import zipfile
from pathlib import Path
from unittest import mock

import httpx
import pyzipper
import uvicorn
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware

from core.config import settings
from core.errors import ApiError
from evidence import codec
from evidence import crypto as c
from evidence import exports
from evidence import streaming as st
from le_package import builder
from le_package.manifest import Manifest

C = codec.CHUNK_SIZE
EVID = Path(settings.evidence_path)
KEK = "11" * 32
BIG = os.environ.get("G2_BIG") == "1"


def rel(name="f.bin"):
    return f"ut-g2-{uuid.uuid4().hex[:8]}/{name}"


def v2_file(data: bytes, name="f.bin"):
    r = rel(name)
    s = c.write_encrypted(data, r)
    return r, s


def v0_file(data: bytes, name="old.bin"):
    r = rel(name)
    ct, nonce = c.encrypt_file_bytes(data)
    p = EVID / r
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(ct)
    return r, nonce


def flip(r: str, offset: int):
    p = EVID / r
    with open(p, "r+b") as f:
        f.seek(offset)
        b = f.read(1)
        f.seek(offset)
        f.write(bytes([b[0] ^ 1]))


def chunk_offset(i: int) -> int:
    """A byte inside chunk i's ciphertext."""
    return codec.HEADER_LEN + i * codec.SEGMENT_LEN + 100


def gcm_decrypt_stream(path: Path, key_hex: str, out) -> None:
    """The recipient recipe (README.txt): streamed AES-256-GCM, tag checked at the end."""
    key = bytes.fromhex(key_hex)
    size = path.stat().st_size
    with open(path, "rb") as f:
        nonce = f.read(12)
        f.seek(size - 16)
        tag = f.read(16)
        f.seek(12)
        dec = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        left = size - 28
        while left:
            block = f.read(min(left, 1 << 20))
            left -= len(block)
            out.write(dec.update(block))
        dec.finalize()


def staging_files() -> list:
    d = EVID / c.STAGING_DIR
    return sorted(os.listdir(d)) if d.exists() else []


class Base(unittest.TestCase):
    def setUp(self):
        self._kek = mock.patch.object(settings, "evidence_kek", KEK)
        self._kek.start()
        self.alarms = []
        c.set_read_alarm_sink(self.alarms.append)
        self.before_exports = set(os.listdir(EVID / "exports")) if (EVID / "exports").exists() else set()

    def tearDown(self):
        c.set_read_alarm_sink(None)
        self._kek.stop()
        for p in EVID.iterdir():
            if p.name.startswith("ut-g2-"):
                shutil.rmtree(p)
        ex = EVID / "exports"
        if ex.exists():
            for n in set(os.listdir(ex)) - self.before_exports:
                (ex / n).unlink()


# ─── Export bundle ──────────────────────────────────────────────────────────────────────────────

class ExportBundle(Base):
    def build(self, parts):
        rp = f"exports/ut-g2-{uuid.uuid4().hex}.enc"
        key, size, sha = exports._write_bundle(parts, rp)
        return EVID / rp, key, size, sha

    def test_roundtrip_mixed_v0_v2_byte_exact(self):
        a = os.urandom(3 * C + 12345)                      # v2, several chunks
        b = os.urandom(C)                                   # v2, exact multiple (empty final chunk)
        e = b""                                             # v2, empty
        o = os.urandom(70000)                               # v0 (legacy, decrypted whole)
        (ra, sa), (rb, sb), (re_, se) = v2_file(a), v2_file(b), v2_file(e)
        ro, no = v0_file(o)
        parts = [("README.txt", exports.README, None),
                 ("files/a", None, (ra, sa.nonce_hex, len(a))), ("files/b", None, (rb, sb.nonce_hex, len(b))),
                 ("files/e", None, (re_, se.nonce_hex, 0)), ("files/o", None, (ro, no, len(o))),
                 ("manifest.json", '{"x": 1}', None)]
        path, key, size, sha = self.build(parts)
        raw = path.read_bytes()
        self.assertEqual(size, len(raw))
        self.assertEqual(sha, hashlib.sha256(raw).hexdigest(), "bundle SHA-256 = the file as stored")
        out = io.BytesIO()
        gcm_decrypt_stream(path, key, out)
        # same wire format as the pre-G2 one-shot AESGCM.encrypt: the old recipe still opens small bundles
        self.assertEqual(AESGCM(bytes.fromhex(key)).decrypt(raw[:12], raw[12:], None), out.getvalue())
        with zipfile.ZipFile(io.BytesIO(out.getvalue())) as zf:
            self.assertIsNone(zf.testzip())
            got = {n: zf.read(n) for n in zf.namelist()}
            infos = {i.filename: i for i in zf.infolist()}
        self.assertEqual(got["files/a"], a)
        self.assertEqual(got["files/b"], b)
        self.assertEqual(got["files/e"], e)
        self.assertEqual(got["files/o"], o)
        self.assertEqual(got["README.txt"].decode(), exports.README)
        self.assertEqual(infos["files/a"].external_attr, 0o600 << 16)
        self.assertEqual(infos["files/a"].compress_type, zipfile.ZIP_DEFLATED)
        self.assertEqual(staging_files(), [], "nothing left in .staging")

    def test_mid_stream_tamper_discards_bundle(self):
        a = os.urandom(5 * C + 7)
        ra, sa = v2_file(a)
        flip(ra, chunk_offset(3))                             # chunks 0-2 decrypt, chunk 3 fails
        before = set(os.listdir(EVID / "exports")) if (EVID / "exports").exists() else set()
        with self.assertRaises(c.EvidenceIntegrityError) as cm:
            self.build([("README.txt", "x", None), ("files/a", None, (ra, sa.nonce_hex, len(a)))])
        self.assertEqual(cm.exception.reason, "chunk_auth")
        after = set(os.listdir(EVID / "exports")) if (EVID / "exports").exists() else set()
        self.assertEqual(after, before, "no bundle published")
        self.assertEqual(staging_files(), [], "the staged bundle was deleted")

    def test_truncated_and_missing_files_discard_bundle(self):
        a = os.urandom(2 * C + 1)
        ra, sa = v2_file(a)
        with open(EVID / ra, "r+b") as f:                    # cut at a chunk boundary: size check (step 3)
            f.truncate(codec.HEADER_LEN + codec.SEGMENT_LEN)
        with self.assertRaises(c.EvidenceIntegrityError):
            self.build([("files/a", None, (ra, sa.nonce_hex, len(a)))])
        with self.assertRaises(c.EvidenceCryptoError) as cm:
            self.build([("files/m", None, (rel(), sa.nonce_hex, 10))])
        self.assertNotIsInstance(cm.exception, c.EvidenceIntegrityError)
        self.assertEqual(cm.exception.reason, "file_missing")
        self.assertEqual([a_["reason"] for a_ in self.alarms], ["file_missing"], "cannot-read is still alarmed")
        self.assertEqual(staging_files(), [])

    def test_memory_is_bounded_while_bundling(self):
        """tracemalloc over a 64 MiB exhibit: the Python heap never holds the file (pre-G2: 3x)."""
        import tracemalloc
        a = os.urandom(64 * C)
        ra, sa = v2_file(a)
        del a
        tracemalloc.start()
        try:
            self.build([("files/a", None, (ra, sa.nonce_hex, 64 * C))])
            _cur, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 16 * C, f"peak Python allocations {peak / C:.1f} MiB for a 64 MiB exhibit")

    @unittest.skipUnless(BIG, "G2_BIG=1: > 4 GiB entry (ZIP64)")
    def test_zip64_entry_over_4_gib(self):
        n = 4 * 1024 ** 3 + C + 3                              # zeros: fast to deflate, still > ZIP64_LIMIT
        r = rel("big.bin")

        def zeros():
            left, block = n, bytes(8 * C)
            while left:
                k = min(left, len(block))
                yield block[:k]
                left -= k
        w = c.EncryptedStagingWriter()
        h = hashlib.sha256()
        for b in zeros():
            h.update(b)
            w.write(b)
        s = w.commit(r)
        self.assertEqual(s.sha256, h.hexdigest())
        path, key, size, sha = self.build([("README.txt", "x", None), ("files/big", None, (r, s.nonce_hex, n)),
                                           ("manifest.json", "{}", None)])
        plain = EVID / rel("bundle.zip")
        plain.parent.mkdir(parents=True, exist_ok=True)
        with open(plain, "wb") as out:
            gcm_decrypt_stream(path, key, out)
        with zipfile.ZipFile(plain) as zf:
            info = zf.getinfo("files/big")
            self.assertEqual(info.file_size, n)
            self.assertTrue(info.file_size > zipfile.ZIP64_LIMIT)
            hz = hashlib.sha256()
            with zf.open(info) as f:
                while blk := f.read(8 * C):
                    hz.update(blk)
            self.assertEqual(hz.hexdigest(), s.sha256, "the > 4 GiB entry is byte-exact")
            self.assertEqual(zf.read("manifest.json"), b"{}")


# ─── LE package: streamed evidence entries + the staged outer envelope ─────────────────────────

class LePackage(Base):
    def package(self, items, estimate=0, mutate=None):
        """Build an outer AE-2 envelope whose le_package.zip holds each item's streamed entry, the way
        build_le_package does. Returns (bundle path, entries, inner names->bytes, manifest)."""
        pw = "pw-" + uuid.uuid4().hex
        staged, oz, entry = builder._open_bundle(pw, estimate)
        man = Manifest(incident_id="x", incident_ref=None, case_reference="ut", platform_version="t")
        results = []
        try:
            with zipfile.ZipFile(entry, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("CASE_INFO.json", b"{}")
                for ev in items:
                    results.append(builder._stream_evidence_file(zf, man, ev, f"04_Evidence/Files/{ev.id}", "x/y",
                                                                 "test"))
            size, sha = builder._close_bundle(staged, oz, entry)
        except BaseException:
            builder._abandon_bundle(staged, oz, entry)
            raise
        self.raw = staged.path.read_bytes()
        self.assertEqual(sha, hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(size, staged.path.stat().st_size)
        with pyzipper.AESZipFile(staged.path) as oz2:
            oz2.setpassword(pw.encode())
            self.assertEqual(oz2.namelist(), ["le_package.zip"])
            inner = oz2.read("le_package.zip")                 # checks the AE-2 HMAC
        with zipfile.ZipFile(io.BytesIO(inner)) as zf:
            got = {n: zf.read(n) for n in zf.namelist()}
        staged.discard()
        return results, got, man

    @staticmethod
    def ev(r, nonce, size):
        return types.SimpleNamespace(id=uuid.uuid4(), storage_path=r, nonce_hex=nonce, file_size_bytes=size)

    def test_streamed_entries_byte_exact_and_manifest_hashes(self):
        a, o = os.urandom(3 * C + 99), os.urandom(5000)
        ra, sa = v2_file(a)
        ro, no = v0_file(o)
        ea, eo = self.ev(ra, sa.nonce_hex, len(a)), self.ev(ro, no, len(o))
        results, got, man = self.package([ea, eo])
        self.assertEqual(got[f"04_Evidence/Files/{ea.id}"], a)
        self.assertEqual(got[f"04_Evidence/Files/{eo.id}"], o)
        for data, res in ((a, results[0]), (o, results[1])):
            self.assertEqual((res["size"], res["sha256"], res["sha512"]),
                             (len(data), hashlib.sha256(data).hexdigest(), hashlib.sha512(data).hexdigest()))
        self.assertEqual(man.file_count, 2)

    def test_unopenable_exhibit_is_skipped_not_written(self):
        a = os.urandom(2 * C)
        ra, sa = v2_file(a)
        missing = self.ev(rel(), sa.nonce_hex, 10)
        wrong_size = self.ev(ra, sa.nonce_hex, len(a) + 1)
        results, got, man = self.package([missing, wrong_size])
        self.assertIsNone(results[0], "missing: recorded as absent, as before")
        # G-fix R3-2: a size that doesn't match the row is an integrity failure (the route freezes it)
        self.assertIsInstance(results[1], builder.IntegrityFailed)
        self.assertEqual(results[1].reason, "size_mismatch")
        self.assertEqual(sorted(got), ["CASE_INFO.json"], "nothing written for them")
        self.assertEqual(man.file_count, 0)

    def test_tampered_exhibit_is_skipped_as_before(self):
        """Pass 1 authenticates the whole file before anything is written: a tamper anywhere in it means
        'not included', exactly as before G2 (one bad exhibit never blocks the package). G-fix R3-2: it is
        reported as an integrity failure (IntegrityFailed, the crypto layer's reason), not as absent."""
        a, b = os.urandom(4 * C + 1), os.urandom(3000)
        ra, sa = v2_file(a)
        rb, sb = v2_file(b)
        flip(ra, chunk_offset(3))
        eb = self.ev(rb, sb.nonce_hex, len(b))
        results, got, man = self.package([self.ev(ra, sa.nonce_hex, len(a)), eb])
        self.assertIsInstance(results[0], builder.IntegrityFailed)
        self.assertEqual(results[0].reason, "chunk_auth")
        self.assertEqual(got[f"04_Evidence/Files/{eb.id}"], b)
        self.assertEqual(man.file_count, 1)

    def test_file_changing_during_the_build_abandons_package(self):
        """Pass 2 (the write) fails mid-entry: the file changed after pass 1 verified it. F-12: the whole
        package is abandoned and the staged bundle deleted."""
        a = os.urandom(4 * C + 1)
        ra, sa = v2_file(a)
        real, calls = builder.iter_decrypted, []

        def changing(*args, **kw):
            calls.append(args[0])
            if len(calls) == 2:
                flip(ra, chunk_offset(2))
            return real(*args, **kw)
        with mock.patch.object(builder, "iter_decrypted", changing):
            with self.assertRaises(c.EvidenceIntegrityError) as cm:
                self.package([self.ev(ra, sa.nonce_hex, len(a))])
        self.assertIn("chunk 2", str(cm.exception))
        self.assertEqual(len(calls), 2)
        self.assertEqual(staging_files(), [], "abandoned bundle deleted")

    def test_outer_entry_zip64_only_when_needed(self):
        a = os.urandom(1000)
        ra, sa = v2_file(a)
        for estimate, want in ((0, False), (5 * 1024 ** 3, True)):
            ev = self.ev(ra, sa.nonce_hex, len(a))
            _results, got, _ = self.package([ev], estimate=estimate)
            self.assertEqual(got[f"04_Evidence/Files/{ev.id}"], a)
            # local header of le_package.zip: 30 fixed bytes, name, extra (ZIP64 extra field id 0x0001)
            name_len, extra_len = int.from_bytes(self.raw[26:28], "little"), int.from_bytes(self.raw[28:30], "little")
            extra = self.raw[30 + name_len:30 + name_len + extra_len]
            ids, i = [], 0
            while i + 4 <= len(extra):
                ids.append(int.from_bytes(extra[i:i + 2], "little"))
                i += 4 + int.from_bytes(extra[i + 2:i + 4], "little")
            self.assertEqual(1 in ids, want, (estimate, ids))

    @unittest.skipUnless(BIG, "G2_BIG=1: > 4 GiB LE entry (ZIP64)")
    def test_zip64_le_entry_over_4_gib(self):
        n = 4 * 1024 ** 3 + 5
        r = rel("big.bin")
        w = c.EncryptedStagingWriter()
        block, left = bytes(8 * C), n
        while left:
            k = min(left, len(block))
            w.write(block[:k])
            left -= k
        s = w.commit(r)
        ev = self.ev(r, s.nonce_hex, n)
        pw = "pw-big"
        staged, oz, entry = builder._open_bundle(pw, n)
        man = Manifest(incident_id="x", incident_ref=None, case_reference="ut", platform_version="t")
        with zipfile.ZipFile(entry, "w", zipfile.ZIP_DEFLATED) as zf:
            res = builder._stream_evidence_file(zf, man, ev, "04_Evidence/Files/big", "x/y", "t")
        builder._close_bundle(staged, oz, entry)
        self.assertEqual((res["size"], res["sha256"]), (n, s.sha256))
        inner = EVID / rel("inner.zip")
        inner.parent.mkdir(parents=True, exist_ok=True)
        with pyzipper.AESZipFile(staged.path) as oz2, open(inner, "wb") as out:
            oz2.setpassword(pw.encode())
            with oz2.open("le_package.zip") as f:
                shutil.copyfileobj(f, out, 8 * C)
        with zipfile.ZipFile(inner) as zf:
            info = zf.getinfo("04_Evidence/Files/big")
            self.assertEqual(info.file_size, n)
            h = hashlib.sha256()
            with zf.open(info) as f:
                while blk := f.read(8 * C):
                    h.update(blk)
        self.assertEqual(h.hexdigest(), s.sha256)
        staged.discard()


# ─── Downloads: abort semantics through uvicorn + BaseHTTPMiddleware ──────────────────────────

class _Passthrough(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        return await call_next(request)


# The test registers each stored file here; requests carry only an opaque key, never a path.
_FILES: dict[str, tuple[str, str, int]] = {}


def _register(r: str, n: str, size: int) -> str:
    key = str(len(_FILES))
    _FILES[key] = (r, n, size)
    return key


def _app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(_Passthrough)

    @app.get("/f")
    async def get_file(k: str):
        if k not in _FILES:
            raise ApiError(404, "file_not_found", "unknown test file key")
        r, n, size = _FILES[k]
        try:
            return await st.decrypted_download(r, n, size, media_type="application/octet-stream",
                                               headers={"Content-Disposition": 'attachment; filename="x"'})
        except c.EvidenceIntegrityError as e:
            raise ApiError(409, "file_integrity_failed", str(e.reason))
    return app


@contextlib.asynccontextmanager
async def serve(app):
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="critical", lifespan="off"))
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await task


class Downloads(Base):
    async def fetch(self, base, r, n, size):
        """(status, headers, body bytes, error or None) — reads the body as a client would."""
        async with httpx.AsyncClient(base_url=base, timeout=120) as cli:
            async with cli.stream("GET", "/f", params={"k": _register(r, n, size)}) as resp:
                body = bytearray()
                try:
                    async for piece in resp.aiter_raw():
                        body += piece
                    err = None
                except httpx.HTTPError as e:
                    err = e
                return resp.status_code, resp.headers, bytes(body), err

    def run_async(self, coro):
        return asyncio.run(coro)

    def test_small_large_v0_and_tampered(self):
        small, large, old = os.urandom(3 * C + 5), os.urandom(20 * C + 77), os.urandom(4000)
        (rs, ss), (rl, sl) = v2_file(small), v2_file(large)
        ro, no = v0_file(old)
        rt, stt = v2_file(large)
        flip(rt, chunk_offset(17))                     # past the pre-flight: fails mid-stream
        rts, sts = v2_file(small)
        flip(rts, chunk_offset(2))                     # small: found before the response starts

        async def go():
            async with serve(_app()) as base:
                return [await self.fetch(base, *args) for args in (
                    (rs, ss.nonce_hex, len(small)), (rl, sl.nonce_hex, len(large)), (ro, no, len(old)),
                    (rt, stt.nonce_hex, len(large)), (rts, sts.nonce_hex, len(small)))]
        (s1, h1, b1, e1), (s2, h2, b2, e2), (s3, h3, b3, e3), (s4, h4, b4, e4), (s5, h5, b5, e5) = \
            self.run_async(go())
        self.assertEqual((s1, b1, e1, int(h1["content-length"])), (200, small, None, len(small)))
        self.assertEqual((s2, b2, e2, int(h2["content-length"])), (200, large, None, len(large)),
                         "large file streams completely, with Content-Length")
        self.assertEqual((s3, b3, e3), (200, old, None), "v0 file: decrypted whole, sent whole")
        self.assertEqual((s4, int(h4["content-length"])), (200, len(large)), "headers were already sent")
        self.assertIsInstance(e4, httpx.RemoteProtocolError, "mid-stream failure = aborted transfer, not EOF")
        self.assertLess(len(b4), len(large))
        self.assertEqual(b4, large[:len(b4)], "only authenticated chunks were sent before the abort")
        self.assertLessEqual(len(b4), 17 * C, "nothing from the failed chunk")
        self.assertEqual((s5, e5), (409, None), "small tampered file: error status, no partial body")
        self.assertNotIn(small[:4096], b5)

    def test_missing_file_fails_before_headers_and_alarms(self):
        r, s = v2_file(b"x" * 100)
        (EVID / r).unlink()

        async def go():
            async with serve(_app()) as base:
                return await self.fetch(base, r, s.nonce_hex, 100)
        status_, _h, _b, err = self.run_async(go())
        self.assertEqual(status_, 500)                   # this test app maps only integrity; routes map 404/503
        self.assertIsNone(err)
        self.assertEqual([a["reason"] for a in self.alarms], ["file_missing"])

    @unittest.skipUnless(BIG, "G2_BIG=1: 2 GiB streamed download, peak RSS")
    def test_2_gib_download_bounded_rss(self):
        n = 2 * 1024 ** 3
        r = rel("two.bin")
        w = c.EncryptedStagingWriter()
        h = hashlib.sha256()
        for _ in range(n // (8 * C)):
            b = os.urandom(8 * C)
            h.update(b)
            w.write(b)
        s = w.commit(r)
        del b

        def rss():
            with open("/proc/self/status") as f:
                return next(int(x.split()[1]) * 1024 for x in f if x.startswith("VmRSS"))
        base_rss, peak, stop = rss(), [0], threading.Event()

        def sample():
            while not stop.is_set():
                peak[0] = max(peak[0], rss())
                time.sleep(0.05)
        t = threading.Thread(target=sample)
        t.start()

        async def go():
            async with serve(_app()) as base:
                async with httpx.AsyncClient(base_url=base, timeout=600) as cli:
                    async with cli.stream("GET", "/f", params={"k": _register(r, s.nonce_hex, n)}) as resp:
                        hh, got = hashlib.sha256(), 0
                        async for piece in resp.aiter_raw():
                            hh.update(piece)
                            got += len(piece)
                        return got, hh.hexdigest()
        t0 = time.monotonic()
        got, digest = self.run_async(go())
        dur = time.monotonic() - t0
        stop.set()
        t.join()
        print(f"\n2 GiB download: {dur:.1f} s, baseline RSS {base_rss / C:.0f} MiB, peak {peak[0] / C:.0f} MiB, "
              f"delta {(peak[0] - base_rss) / C:.0f} MiB")
        self.assertEqual((got, digest), (n, h.hexdigest()))
        self.assertLess(peak[0] - base_rss, 300 * C)


# ─── Staging output + free space ─────────────────────────────────────────────────────────────

class Staging(Base):
    def test_commit_discard_no_overwrite(self):
        o = st.StagedOutput()
        o.file.write(b"abc")
        self.assertEqual(o.finish(), 3)
        r = rel("out.bin")
        o.commit(r)
        self.assertEqual((EVID / r).read_bytes(), b"abc")
        self.assertEqual(staging_files(), [])
        o2 = st.StagedOutput()
        o2.file.write(b"zzz")
        o2.finish()
        with self.assertRaises(c.EvidenceCryptoError):
            o2.commit(r)
        self.assertEqual((EVID / r).read_bytes(), b"abc")
        o2.discard()
        o2.discard()
        self.assertEqual(staging_files(), [])

    def test_require_free_space(self):
        fake = types.SimpleNamespace(f_bavail=10, f_frsize=1024 ** 3)            # 10 GiB free
        with mock.patch.object(st.os, "statvfs", return_value=fake):
            st.require_free_space(8 * 1024 ** 3, "x")                          # 8 + 1 reserve <= 10
            with self.assertRaises(ApiError) as cm:
                st.require_free_space(9 * 1024 ** 3 + 1, "this upload")
        self.assertEqual((cm.exception.status_code, cm.exception.code), (507, "insufficient_storage"))
        self.assertIn("this upload", cm.exception.detail)


if __name__ == "__main__":
    unittest.main()
