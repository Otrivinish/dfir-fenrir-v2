"""Unit tests for evidence/crypto.py G1 stage 3a (+ 3b: the incremental EncryptedStagingWriter): the v2 writer (staging protocol), the dual-format
reader with the spec §4.2 evaluation order and error mapping, read alarms, the startup gate and
the staging sweep (docs/streaming-aes-gcm-format.md §4.2–§4.4, §5.1, §6.3, §6.4).

stdlib unittest; no DB, no network. Files go to tmpfs mounts. From the repo root:

    docker run --rm --network none --read-only --tmpfs /tmp \
      --tmpfs /evidence:uid=1001,gid=1001 --tmpfs /asset_logs:uid=1001,gid=1001 \
      -v "$PWD/backend:/src:ro" -w /src -e PYTHONPATH=/src -e PYTHONDONTWRITEBYTECODE=1 \
      -e EVIDENCE_PATH=/evidence -e LOGS_PATH=/asset_logs \
      -e DATABASE_URL=postgresql+asyncpg://nobody:none@127.0.0.1:1/none \
      -e EVIDENCE_KEK=$(python3 -c "print('11'*32)") \
      --entrypoint python dfir-fenrir-v2-backend:local -m unittest tests.test_crypto_streaming -v
"""
import asyncio
import hashlib
import io
import os
import random
import shutil
import stat
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from core.config import settings
from evidence import codec
from evidence import crypto as c

C = codec.CHUNK_SIZE
EVID = Path(settings.evidence_path)
LOGS = Path(settings.logs_path)
KEK_A = "11" * 32
KEK_B = "22" * 32


def rel(name="f.bin"):
    return f"ut-{uuid.uuid4().hex[:8]}/{name}"


class Base(unittest.TestCase):
    def setUp(self):
        self.alarms = []
        c.set_read_alarm_sink(self.alarms.append)
        c._kek_id_warned.clear()
        self._kek = mock.patch.object(settings, "evidence_kek", KEK_A)
        self._kek.start()

    def tearDown(self):
        self._kek.stop()
        c.set_read_alarm_sink(None)
        for root in (EVID, LOGS):
            for p in root.iterdir():
                if p.name.startswith("ut-"):
                    shutil.rmtree(p)
                elif p.is_file():
                    p.unlink()
            staging = root / c.STAGING_DIR
            if staging.exists():
                for p in staging.iterdir():
                    p.unlink()

    def staged(self, root=EVID):
        d = root / c.STAGING_DIR
        return sorted(p.name for p in d.iterdir()) if d.exists() else []

    def write(self, pt, root=None, name="f.bin"):
        r = rel(name)
        return c.write_encrypted(pt, r, root=root), r

    def assert_integrity(self, reason, fn, *a, **k):
        with self.assertRaises(c.EvidenceIntegrityError) as cm:
            fn(*a, **k)
        self.assertEqual(cm.exception.reason, reason, str(cm.exception))
        return cm.exception

    def assert_cannot_read(self, reason, fn, *a, **k):
        with self.assertRaises(c.EvidenceCryptoError) as cm:
            fn(*a, **k)
        self.assertNotIsInstance(cm.exception, c.EvidenceIntegrityError, str(cm.exception))
        self.assertEqual(cm.exception.reason, reason, str(cm.exception))
        return cm.exception


class WriterTests(Base):
    def test_roundtrip_sizes(self):
        for n in (0, 1, C - 1, C, C + 1, 3 * C + 12345):
            pt = os.urandom(n)
            s, r = self.write(pt)
            disk = (EVID / r).read_bytes()
            self.assertEqual(disk[:7], codec.MAGIC, n)
            self.assertEqual(len(disk), codec.container_size(n), n)
            self.assertEqual(s.nonce_hex, disk[12:19].hex(), n)
            self.assertEqual(len(s.nonce_hex), 14)
            self.assertFalse((EVID / (r + ".nonce")).exists(), "v2 has no sidecar")
            self.assertEqual((s.size, s.sha256, s.sha1, s.md5),
                             (n, hashlib.sha256(pt).hexdigest(), hashlib.sha1(pt).hexdigest(),
                              hashlib.md5(pt).hexdigest()))
            self.assertEqual(c.read_decrypted(r, s.nonce_hex, n), pt, n)
            self.assertEqual(c.sha256_decrypted(r, s.nonce_hex, n), s.sha256, n)
            self.assertEqual(stat.S_IMODE((EVID / r).stat().st_mode), 0o644)
        self.assertEqual(self.staged(), [], "staging is empty after commits")
        self.assertEqual(stat.S_IMODE((EVID / c.STAGING_DIR).stat().st_mode), 0o700)

    def test_files_store_root(self):
        pt = os.urandom(C + 7)
        s, r = self.write(pt, root=settings.logs_path)
        self.assertTrue((LOGS / r).exists())
        self.assertFalse((EVID / r).exists())
        self.assertEqual(c.read_decrypted(r, s.nonce_hex, len(pt), root=settings.logs_path), pt)
        self.assertEqual(self.staged(LOGS), [])
        self.assert_cannot_read("invalid_path", c.read_decrypted, "../evidence/x", s.nonce_hex, 1,
                                root=settings.logs_path)
        with self.assertRaises(c.EvidenceCryptoError):
            c.write_encrypted(b"x", "../escape.bin", root=settings.logs_path)
        self.assertEqual(self.staged(LOGS), [], "a refused write leaves no staging file")

    def test_stream_sources(self):
        pt = os.urandom(2 * C + 999)
        want = hashlib.sha256(pt).hexdigest()

        class ShortReader(io.RawIOBase):          # a blocking source that returns short reads
            def __init__(self, data):
                self.data, self.pos = data, 0

            def readable(self):
                return True

            def read(self, n=-1):
                k = min(n if n >= 0 else len(self.data), random.randint(1, 70000))
                out = self.data[self.pos:self.pos + k]
                self.pos += len(out)
                return out

        async def parts():
            i = 0
            while i < len(pt):
                k = random.randint(1, 3 * C)
                yield pt[i:i + k]
                i += k
                await asyncio.sleep(0)

        for src in (pt, io.BytesIO(pt), ShortReader(pt), parts()):
            r = rel()
            s = asyncio.run(c.write_encrypted_stream(src, r))
            self.assertEqual((s.sha256, s.size), (want, len(pt)), type(src))
            self.assertEqual(c.read_decrypted(r, s.nonce_hex, s.size), pt, type(src))
        self.assertEqual(self.staged(), [])

    def test_accept_rejects_nothing_stored(self):
        class Nope(Exception):
            pass
        seen = []

        def accept(stored):
            seen.append((stored, self.staged()))
            raise Nope()
        r = rel()
        with self.assertRaises(Nope):
            asyncio.run(c.write_encrypted_stream(os.urandom(C + 5), r, accept=accept))
        self.assertEqual(len(seen[0][1]), 1, "accept runs while the staged file exists")
        self.assertTrue(seen[0][1][0].endswith(c.PARTIAL_SUFFIX))
        self.assertFalse((EVID / r).exists())
        self.assertFalse((EVID / r).parent.exists(), "no directory made for a refused file")
        self.assertEqual(self.staged(), [])
        # accept that passes: stored
        s = asyncio.run(c.write_encrypted_stream(b"ok", r, accept=lambda st: None))
        self.assertEqual(c.read_decrypted(r, s.nonce_hex, 2), b"ok")

    def test_cancelled_async_source_cleans_up(self):
        async def parts():
            yield os.urandom(C)
            raise asyncio.CancelledError()
        with self.assertRaises(asyncio.CancelledError):
            asyncio.run(c.write_encrypted_stream(parts(), rel()))
        self.assertEqual(self.staged(), [])

    def test_staging_o_excl(self):
        fixed = uuid.UUID(int=7)
        (EVID / c.STAGING_DIR).mkdir(mode=0o700, exist_ok=True)
        clash = EVID / c.STAGING_DIR / f"{fixed.hex}{c.PARTIAL_SUFFIX}"
        clash.write_bytes(b"someone else's")
        with mock.patch.object(c.uuid, "uuid4", return_value=fixed):
            with self.assertRaises(FileExistsError):
                c.write_encrypted(b"x", rel())
        self.assertEqual(clash.read_bytes(), b"someone else's", "O_EXCL never truncates an existing file")
        clash.unlink()

    def test_never_overwrites(self):
        s, r = self.write(b"first")
        before = (EVID / r).read_bytes()
        with self.assertRaises(c.EvidenceCryptoError):
            c.write_encrypted(b"second", r)
        self.assertEqual((EVID / r).read_bytes(), before)
        self.assertEqual(self.staged(), [])

    def test_fsync_and_rename_order(self):
        calls = []
        real_fsync, real_rename = os.fsync, os.rename

        def spy_fsync(fd):
            calls.append(("fsync", stat.S_ISDIR(os.fstat(fd).st_mode)))
            return real_fsync(fd)

        def spy_rename(a, b):
            calls.append(("rename", Path(a).parent.name, Path(b).name))
            return real_rename(a, b)
        with mock.patch.object(c.os, "fsync", spy_fsync), mock.patch.object(c.os, "rename", spy_rename):
            self.write(os.urandom(10))
        names = [x[0] for x in calls]
        i = names.index("rename")
        self.assertIn(("fsync", False), calls[:i], "file fsynced before the rename")
        self.assertEqual(calls[i][1], c.STAGING_DIR)
        self.assertEqual(calls[i + 1:][-2:], [("fsync", True), ("fsync", True)], "target + staging dirs fsynced")

    def test_writer_only_revert_switch(self):
        with mock.patch.object(c, "_WRITER_FORMAT", 0):
            pt = os.urandom(5000)
            s, r = self.write(pt)
            s2 = asyncio.run(c.write_encrypted_stream(io.BytesIO(pt), rel()))
            sl, rl = self.write(pt, root=settings.logs_path)
        self.assertEqual(len(s.nonce_hex), 24)
        self.assertEqual((EVID / (r + ".nonce")).read_text(), s.nonce_hex, "v0 evidence keeps its sidecar")
        self.assertFalse(codec.is_streaming_format((EVID / r).read_bytes()))
        self.assertFalse((LOGS / (rl + ".nonce")).exists(), "the Files store never had sidecars")
        self.assertEqual(c.read_decrypted(r, s.nonce_hex, len(pt)), pt)
        self.assertEqual(c.read_decrypted(rl, sl.nonce_hex, len(pt), root=settings.logs_path), pt)
        self.assertEqual((s2.sha256, len(s2.nonce_hex)), (s.sha256, 24))


class ReaderTests(Base):
    def v0(self, pt, root=EVID):
        ct, nonce = c.encrypt_file_bytes(pt)
        r = rel()
        (root / r).parent.mkdir(parents=True)
        (root / r).write_bytes(ct)
        return r, nonce

    def mutate(self, r, fn, root=EVID):
        b = bytearray((root / r).read_bytes())
        b = fn(b) or b
        (root / r).write_bytes(bytes(b))

    def test_v0_unchanged(self):
        pt = os.urandom(70000)
        r, nonce = self.v0(pt)
        self.assertEqual(c.read_decrypted(r, nonce), pt)
        self.assertEqual(c.read_decrypted(r, nonce, len(pt)), pt)
        self.assertEqual(c.read_decrypted(r, nonce, 12345), pt, "v0 has no size check (byte-compatible path)")
        self.assertEqual(c.sha256_decrypted(r, nonce, None), hashlib.sha256(pt).hexdigest())
        self.mutate(r, lambda b: b.__setitem__(-1, b[-1] ^ 1))
        self.assert_integrity("tag", c.read_decrypted, r, nonce)
        self.assertEqual(self.alarms, [])

    def test_v0_row_with_magic_file(self):
        r, nonce = self.v0(os.urandom(100))
        self.mutate(r, lambda b: b.__setitem__(slice(0, 7), codec.MAGIC))
        self.assert_integrity("format_mismatch", c.read_decrypted, r, nonce)

    def test_v2_row_without_magic(self):
        s, r = self.write(os.urandom(100))
        self.mutate(r, lambda b: b.__setitem__(0, b[0] ^ 1))
        self.assert_integrity("format_mismatch", c.read_decrypted, r, s.nonce_hex, 100)
        # a v0 file read through a v2 row (header stripped / swapped) is never handed to the v0 reader
        r0, _n = self.v0(os.urandom(100 + codec.container_size(100) - 116))
        self.assertEqual((EVID / r0).stat().st_size, codec.container_size(100))
        self.assert_integrity("format_mismatch", c.read_decrypted, r0, s.nonce_hex, 100)

    def test_malformed_row(self):
        s, r = self.write(b"abc")
        for bad in ("", "zz" * 7, s.nonce_hex[:-1], s.nonce_hex + "0", None, 12):
            self.assert_integrity("malformed_row", c.read_decrypted, r, bad, 3)
        for bad_size in (None, -1, "3", True, 2 ** 60):
            self.assert_integrity("malformed_row", c.read_decrypted, r, s.nonce_hex, bad_size)
        self.assertEqual(self.alarms, [])

    def test_size_check_before_decrypt(self):
        pt = os.urandom(C + 10)
        s, r = self.write(pt)
        self.assert_integrity("size_mismatch", c.read_decrypted, r, s.nonce_hex, len(pt) + 1)
        self.mutate(r, lambda b: b[:-16])
        self.assert_integrity("size_mismatch", c.read_decrypted, r, s.nonce_hex, len(pt))
        s, r = self.write(pt)
        self.mutate(r, lambda b: b + b"\x00")
        self.assert_integrity("size_mismatch", c.read_decrypted, r, s.nonce_hex, len(pt))
        # appended byte + a row size that matches: the final chunk's tag fails
        self.assert_integrity("chunk_auth", c.read_decrypted, r, s.nonce_hex, len(pt) + 1)
        s, r = self.write(pt)
        self.mutate(r, lambda b: b[:-1])
        self.assert_integrity("chunk_auth", c.read_decrypted, r, s.nonce_hex, len(pt) - 1)
        # a cut at a chunk boundary can never match any container size
        s, r = self.write(os.urandom(2 * C + 5))
        self.mutate(r, lambda b: b[:codec.HEADER_LEN + 2 * codec.SEGMENT_LEN])
        cut = (EVID / r).stat().st_size
        self.assertFalse(any(codec.container_size(p) == cut for p in range(2 * C - 100, 2 * C + 100)))

    def test_header_fields(self):
        for off, val, reason in ((7, 0x03, "bad_header"), (7, 0x01, "bad_header"), (11, 0x01, "bad_header"),
                                 (19, 0x01, "bad_header"), (31, 0x01, "bad_header"), (32, 0x02, "bad_header"),
                                 (32, 0x00, "bad_header")):
            s, r = self.write(os.urandom(50))
            self.mutate(r, lambda b: b.__setitem__(off, val))
            self.assert_integrity(reason, c.read_decrypted, r, s.nonce_hex, 50)
        self.assertEqual(self.alarms, [])

    def test_nonce_prefix_cross_check(self):
        s, r = self.write(os.urandom(50))
        other = os.urandom(7).hex()
        self.assert_integrity("nonce_mismatch", c.read_decrypted, r, other, 50)
        flipped = s.nonce_hex[:-1] + ("1" if s.nonce_hex[-1] != "1" else "2")
        self.assert_integrity("nonce_mismatch", c.read_decrypted, r, flipped, 50)
        self.assertEqual(c.read_decrypted(r, s.nonce_hex.upper(), 50), (c.read_decrypted(r, s.nonce_hex, 50)),
                         "hex case does not matter")
        self.mutate(r, lambda b: b.__setitem__(12, b[12] ^ 1))    # prefix in the header changed
        self.assert_integrity("nonce_mismatch", c.read_decrypted, r, s.nonce_hex, 50)
        # whole-file swap between rows: the other row's prefix does not match
        s1, r1 = self.write(b"one")
        s2, r2 = self.write(b"two")
        os.replace(EVID / r2, EVID / r1)
        self.assert_integrity("nonce_mismatch", c.read_decrypted, r1, s1.nonce_hex, 3)

    def test_unwrap_matching_kek_id_is_integrity(self):
        s, r = self.write(os.urandom(50))
        self.mutate(r, lambda b: b.__setitem__(60, b[60] ^ 1))   # wrapped DEK bit
        self.assert_integrity("slot_corrupt", c.read_decrypted, r, s.nonce_hex, 50)
        self.assertEqual(self.alarms, [], "integrity is not a cannot-read alarm")

    def test_unwrap_other_kek_is_cannot_read_and_alarms(self):
        with mock.patch.object(settings, "evidence_kek", KEK_B):
            s, r = self.write(os.urandom(50))
        self.assert_cannot_read("wrong_kek", c.read_decrypted, r, s.nonce_hex, 50)
        self.assertEqual(self.alarms, [{"event": "read_failed", "store": "evidence", "relative_path": r,
                                        "reason": "wrong_kek", "format": "v2"}])
        self.assertNotIn(KEK_A, repr(self.alarms))
        self.assertNotIn(KEK_B, repr(self.alarms))

    def test_kek_id_altered_reads_and_warns_once(self):
        pt = os.urandom(C + 3)
        s, r = self.write(pt)
        self.mutate(r, lambda b: b.__setitem__(34, b[34] ^ 0xFF))
        self.assertEqual(c.read_decrypted(r, s.nonce_hex, len(pt)), pt)
        self.assertEqual(c.read_decrypted(r, s.nonce_hex, len(pt)), pt)
        self.assertEqual(self.alarms, [{"event": "kek_id_mismatch", "store": "evidence", "relative_path": r,
                                        "reason": "kek_id_mismatch", "format": "v2"}])

    def test_chunk_tamper(self):
        pt = os.urandom(2 * C + 100)
        s, r = self.write(pt)
        self.mutate(r, lambda b: b.__setitem__(codec.HEADER_LEN + codec.SEGMENT_LEN + 5,
                                               b[codec.HEADER_LEN + codec.SEGMENT_LEN + 5] ^ 1))
        it = c.iter_decrypted(r, s.nonce_hex, len(pt))
        self.assertEqual(next(it), pt[:C], "chunk 0 is released (authentic) before chunk 1 fails")
        with self.assertRaises(c.EvidenceIntegrityError) as cm:
            next(it)
        self.assertEqual(cm.exception.reason, "chunk_auth")
        self.assert_integrity("chunk_auth", c.read_decrypted, r, s.nonce_hex, len(pt))

    def test_cannot_read_classes(self):
        s, r = self.write(b"x" * 10)
        self.assert_cannot_read("file_missing", c.read_decrypted, rel(), s.nonce_hex, 10)
        self.assert_cannot_read("invalid_path", c.read_decrypted, "../../etc/passwd", s.nonce_hex, 10)
        self.assert_cannot_read("io_error", c.read_decrypted, str(Path(r).parent), s.nonce_hex, 10)
        with mock.patch.object(settings, "evidence_kek", ""):
            self.assert_cannot_read("kek_unavailable", c.read_decrypted, r, s.nonce_hex, 10)
        self.assertEqual([a["reason"] for a in self.alarms],
                         ["file_missing", "invalid_path", "io_error", "kek_unavailable"])
        # step order: a missing file is "cannot read" even when the row is malformed (step 1 first)
        self.assert_cannot_read("file_missing", c.read_decrypted, rel(), "zz", None)

    def test_codec_value_error_is_internal(self):
        s, r = self.write(os.urandom(100))

        def boom(read, n):
            raise ValueError("read() returned None")
        with mock.patch.object(c.codec, "read_exactly", boom):
            with self.assertRaises(ValueError) as cm:
                c.read_decrypted(r, s.nonce_hex, 100)
        self.assertNotIsInstance(cm.exception, c.EvidenceCryptoError)
        self.assertEqual(self.alarms, [])

    def test_short_reads(self):
        pt = os.urandom(3 * C + 17)
        s, r = self.write(pt)
        real_open = open

        class Short:
            def __init__(self, f):
                self.f = f

            def read(self, n=-1):
                if n is None or n < 0:
                    return self.f.read()
                return self.f.read(random.randint(1, max(1, min(n, 50000))))

            def fileno(self):
                return self.f.fileno()

            def seek(self, *a):
                return self.f.seek(*a)

            def __enter__(self):
                return self

            def __exit__(self, *a):
                self.f.close()

        with mock.patch.object(c, "open", lambda p, m: Short(real_open(p, m)), create=True):
            self.assertEqual(c.read_decrypted(r, s.nonce_hex, len(pt)), pt)
            r0, n0 = self.v0(pt)
            self.assertEqual(c.read_decrypted(r0, n0), pt)

    def test_async_stream(self):
        pt = os.urandom(5 * C + 1)
        s, r = self.write(pt)

        async def collect(batch):
            return [p async for p in c.read_decrypted_stream(r, s.nonce_hex, len(pt), batch=batch)]
        parts = asyncio.run(collect(2))
        self.assertEqual(b"".join(parts), pt)
        self.assertEqual([len(p) for p in parts], [C] * 5 + [1])

        async def early():
            async for _p in c.read_decrypted_stream(r, s.nonce_hex, len(pt)):
                break
        asyncio.run(early())
        self.mutate(r, lambda b: b.__setitem__(-1, b[-1] ^ 1))

        async def bad():
            out = []
            async for p in c.read_decrypted_stream(r, s.nonce_hex, len(pt)):
                out.append(p)
            return out
        with self.assertRaises(c.EvidenceIntegrityError):
            asyncio.run(bad())

    def test_helpers(self):
        self.assertEqual(c.row_format("ab" * 7), 2)
        self.assertEqual(c.row_format("ab" * 12), 0)
        for bad in ("ab" * 8, "", None, "g" * 14):
            self.assertIsNone(c.row_format(bad))
        self.assertEqual(c.stored_size("ab" * 7, 10), codec.container_size(10))
        self.assertEqual(c.stored_size("ab" * 12, 10), 26)
        self.assertIsNone(c.stored_size("zz", 10))


class StagingWriterTests(Base):
    """G1 stage 3b: EncryptedStagingWriter (the chunked upload sessions' incremental writer)."""

    def pieces(self, pt, sizes):
        i, out = 0, []
        for k in sizes:
            out.append(pt[i:i + k])
            i += k
        out.append(pt[i:])
        return [p for p in out if p]

    def test_roundtrip_odd_boundaries_equals_stream_writer(self):
        n = 3 * C + 12345
        pt = os.urandom(n)
        splits = ([1, C - 1, 1, C, 7, 5 * C], [8 * C], [C // 3] * 12, [C] * 3, [n])
        for sizes in splits:
            w = c.EncryptedStagingWriter()
            partial = w.partial
            self.assertTrue(partial.name.endswith(c.PARTIAL_SUFFIX))
            self.assertEqual(partial.parent, EVID / c.STAGING_DIR)
            for p in self.pieces(pt, sizes):
                w.write(p)
                disk = partial.read_bytes()
                self.assertNotIn(pt[:64], disk, "plaintext never written to the partial")
                self.assertEqual((len(disk) - codec.HEADER_LEN) % codec.SEGMENT_LEN, 0,
                                 "only whole encrypted 1 MiB chunks reach the disk")
            self.assertEqual(w.size, n)
            r = rel()
            s = w.commit(r)
            self.assertIsNone(w.partial)
            self.assertFalse(partial.exists())
            self.assertEqual((s.relative_path, s.size, s.sha256, s.sha1, s.md5),
                             (r, n, hashlib.sha256(pt).hexdigest(), hashlib.sha1(pt).hexdigest(),
                              hashlib.md5(pt).hexdigest()), sizes)
            disk = (EVID / r).read_bytes()
            self.assertEqual(len(disk), codec.container_size(n))
            self.assertEqual(disk[12:19].hex(), s.nonce_hex)
            self.assertEqual(c.read_decrypted(r, s.nonce_hex, n), pt, sizes)
        # the whole-source writer of the same bytes: same hashes / size, both decrypt to the plaintext
        r2 = rel()
        s2 = asyncio.run(c.write_encrypted_stream(pt, r2))
        self.assertEqual((s2.sha256, s2.sha1, s2.md5, s2.size), (s.sha256, s.sha1, s.md5, s.size))
        self.assertEqual(len((EVID / r2).read_bytes()), len(disk))
        self.assertNotEqual(s2.nonce_hex, s.nonce_hex, "a fresh nonce prefix per file")
        self.assertEqual(self.staged(), [])

    def test_sizes_around_the_chunk(self):
        for n in (0, 1, C - 1, C, C + 1, 2 * C):
            pt = os.urandom(n)
            w = c.EncryptedStagingWriter()
            if pt:
                w.write(pt)
            r = rel()
            s = w.commit(r)
            self.assertEqual(c.read_decrypted(r, s.nonce_hex, n), pt, n)
        self.assertEqual(self.staged(), [])

    def test_finish_then_decide(self):
        pt = os.urandom(C + 3)
        w = c.EncryptedStagingWriter()
        w.write(pt)
        f = w.finish()
        self.assertEqual((f.relative_path, f.sha256, f.size), ("", hashlib.sha256(pt).hexdigest(), len(pt)))
        self.assertEqual(w.finish(), f, "finish is idempotent")
        self.assertTrue(w.partial.exists(), "finished, not yet moved into place")
        self.assertEqual(len(w.partial.read_bytes()), codec.container_size(len(pt)))
        with self.assertRaises(c.EvidenceCryptoError):
            w.write(b"more")                           # sealed: no more data
        r = rel()
        s = w.commit(r)
        self.assertEqual(c.read_decrypted(r, s.nonce_hex, len(pt)), pt)

    def test_abort_unlinks(self):
        w = c.EncryptedStagingWriter()
        w.write(os.urandom(2 * C + 5))
        p = w.partial
        self.assertTrue(p.exists())
        w.abort()
        self.assertFalse(p.exists())
        self.assertIsNone(w.partial)
        w.abort()                                      # idempotent
        with self.assertRaises(c.EvidenceCryptoError):
            w.write(b"x")
        with self.assertRaises(c.EvidenceCryptoError):
            w.finish()
        with self.assertRaises(c.EvidenceCryptoError):
            w.commit(rel())
        self.assertEqual(self.staged(), [])
        # aborted after finish (a refused upload): the complete partial is deleted too
        w = c.EncryptedStagingWriter()
        w.write(b"abc")
        w.finish()
        p = w.partial
        w.abort()
        self.assertFalse(p.exists())
        self.assertEqual(self.staged(), [])

    def test_accept_refuses_nothing_stored(self):
        class Nope(Exception):
            pass
        seen = []

        def accept(st):
            seen.append(st)
            raise Nope()
        pt = os.urandom(C + 9)
        w = c.EncryptedStagingWriter()
        w.write(pt)
        r = rel()
        with self.assertRaises(Nope):
            w.commit(r, accept=accept)
        self.assertEqual((seen[0].relative_path, seen[0].sha256), (r, hashlib.sha256(pt).hexdigest()))
        self.assertFalse((EVID / r).exists())
        self.assertIsNone(w.partial)
        self.assertEqual(self.staged(), [])

    def test_commit_failure_aborts_and_never_overwrites(self):
        s, r = self.write(b"first")
        before = (EVID / r).read_bytes()
        w = c.EncryptedStagingWriter()
        w.write(b"second")
        with self.assertRaises(c.EvidenceCryptoError):
            w.commit(r)
        self.assertEqual((EVID / r).read_bytes(), before)
        self.assertEqual(self.staged(), [])
        w = c.EncryptedStagingWriter()
        with self.assertRaises(c.EvidenceCryptoError):
            w.commit("../escape.bin")
        self.assertEqual(self.staged(), [])

    def test_files_root_and_async_methods(self):
        pt = os.urandom(2 * C + 1)

        async def go():
            w = await c.EncryptedStagingWriter.aopen(settings.logs_path)
            self.assertEqual(w.partial.parent, LOGS / c.STAGING_DIR)
            for p in self.pieces(pt, [C + 1, 5]):
                await w.awrite(p)
            f = await w.afinish()
            r = rel()
            s = await w.acommit(r)
            w2 = await c.EncryptedStagingWriter.aopen()
            await w2.awrite(b"x")
            p2 = w2.partial
            await w2.aabort()
            return f, s, r, p2
        f, s, r, p2 = asyncio.run(go())
        self.assertEqual(f.sha256, s.sha256)
        self.assertEqual(c.read_decrypted(r, s.nonce_hex, len(pt), root=settings.logs_path), pt)
        self.assertFalse(p2.exists())
        self.assertEqual(self.staged(LOGS), [])
        self.assertEqual(self.staged(), [])

    def test_abort_from_another_thread_during_writes(self):
        import threading
        w = c.EncryptedStagingWriter()
        p = w.partial
        errors = []

        def writer():
            try:
                for _ in range(64):
                    w.write(os.urandom(C))
            except c.EvidenceCryptoError as e:
                errors.append(e)
        t = threading.Thread(target=writer)
        t.start()
        time.sleep(0.02)
        w.abort()
        t.join()
        self.assertFalse(p.exists())
        self.assertEqual(len(errors), 1, "the next write after abort fails cleanly")
        self.assertEqual(self.staged(), [])


class StartupTests(Base):
    def test_gate(self):
        c.check_storage_gate((settings.evidence_path, settings.logs_path))
        lock = EVID / c.ROTATION_LOCK
        lock.write_text("")
        try:
            with self.assertRaises(RuntimeError) as cm:
                c.check_storage_gate((settings.evidence_path, settings.logs_path))
            self.assertIn(".kek-rotation.lock", str(cm.exception))
        finally:
            lock.unlink()
        for root, suffix in ((EVID, ".keyslot"), (LOGS, ".rewrite")):
            j = root / rel("x.enc" + suffix)
            j.parent.mkdir(parents=True)
            j.write_bytes(c.JOURNAL_MAGIC[suffix] + b"j")       # a journal = the name AND the magic (R3-1)
            with self.assertRaises(RuntimeError):
                c.check_storage_gate((settings.evidence_path, settings.logs_path))
            shutil.rmtree(j.parent)
        c.check_storage_gate((settings.evidence_path, settings.logs_path))

    def test_gate_ignores_files_only_named_like_journals(self):
        """R3-1: an uploaded "x.keyslot" / "x.rewrite" (stored as a v2 container, or anything without the
        journal magic) never blocks startup; nor does a temporary journal or a symlink to a journal."""
        made = []
        for root, name, data in ((LOGS, "x.keyslot", None), (LOGS, "x.rewrite", None), (EVID, "y.keyslot", b""),
                                 (LOGS, "z.keyslot.tmp", b"FENRKSJ1 torn"), (LOGS, "w.rewrite", b"FENRRWJ"),
                                 (EVID, "v.rewrite", b"FENRKSJ1 other magic")):
            p = root / rel(name)
            p.parent.mkdir(parents=True, exist_ok=True)
            if data is None:
                c.write_encrypted(b"user data", str(p.relative_to(root)), root=str(root))
            else:
                p.write_bytes(data)
            made.append(p)
        real = Path("/tmp") / f"rj-{uuid.uuid4().hex}.keyslot"       # a real journal outside the stores
        real.write_bytes(c.JOURNAL_MAGIC[".keyslot"] + bytes(160))
        link = LOGS / rel("link.keyslot")                               # never followed (O_NOFOLLOW)
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(real)
        c.check_storage_gate((settings.evidence_path, settings.logs_path))
        self.assertIsNone(c.journal_kind(link))
        self.assertEqual(c.journal_kind(real), ".keyslot")
        real.unlink()
        for p in made:
            self.assertIsNone(c.journal_kind(p), p.name)
        good = LOGS / rel("q.keyslot")
        good.parent.mkdir(parents=True, exist_ok=True)
        good.write_bytes(c.JOURNAL_MAGIC[".keyslot"])
        self.assertEqual(c.journal_kind(good), ".keyslot")
        with self.assertRaises(RuntimeError):
            c.check_storage_gate((settings.evidence_path, settings.logs_path))
        for root in (EVID, LOGS):
            for p in list(root.iterdir()):
                if p.name != c.STAGING_DIR:
                    shutil.rmtree(p) if p.is_dir() and not p.is_symlink() else p.unlink()
        c.check_storage_gate((settings.evidence_path, settings.logs_path))

    def test_sweep_keeps_partials_live_in_this_process(self):
        """ROT-L1: a staging file a writer of this process still has open is never swept, however long
        it has been idle; once committed or discarded it is no longer tracked."""
        w = c.EncryptedStagingWriter()
        w.write(b"x" * 10)
        t = time.time() - (c.STALE_PARTIAL_MINUTES + 5) * 60
        os.utime(w.partial, (t, t))
        self.assertEqual(c.sweep_staging(settings.evidence_path), 0)
        self.assertTrue(w.partial.exists())
        p = w.partial
        w.abort()
        self.assertFalse(p.exists())
        st = EVID / c.STAGING_DIR
        old = st / "dead.partial"
        old.write_bytes(b"x")
        os.utime(old, (t, t))
        self.assertEqual(c.sweep_staging(settings.evidence_path), 1)
        from evidence.streaming import StagedOutput
        so = StagedOutput()
        os.utime(so.path, (t, t))
        self.assertEqual(c.sweep_staging(settings.evidence_path), 0)
        so.discard()
        self.assertEqual(c._LIVE_PARTIALS, set())

    def test_sweep(self):
        st = EVID / c.STAGING_DIR
        if st.exists():
            st.rmdir()
        self.assertEqual(c.sweep_staging(settings.evidence_path), 0)
        self.assertEqual(stat.S_IMODE(st.stat().st_mode), 0o700)
        old, fresh, other = st / "a.partial", st / "b.partial", st / "c.keep"
        for p in (old, fresh, other):
            p.write_bytes(b"x")
        t = time.time() - (c.STALE_PARTIAL_MINUTES + 1) * 60
        os.utime(old, (t, t))
        os.utime(other, (t, t))
        self.assertEqual(c.sweep_staging(settings.evidence_path), 1)
        self.assertEqual(sorted(p.name for p in st.iterdir()), ["b.partial", "c.keep"])
        fresh.unlink()
        other.unlink()


if __name__ == "__main__":
    unittest.main()
