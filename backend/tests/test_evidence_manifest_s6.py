"""S6 (EG-4): the seekable view over FENRGCM v2 (random seeks, tampering, truncation, a dropped / forged final chunk,
swapped chunks, v0), the canonical JSONL with a test vector, the ZIP and TAR indexers (names, times, types, encrypted
and unreadable members, caps), the KAPE and Velociraptor listing merges (match / mismatch / garbled), the provenance
check and the container-format rules.

stdlib unittest; no DB, no network. Files are written encrypted to the /evidence tmpfs under a throwaway KEK. From the
repo root:

    docker run --rm --network none --read-only --tmpfs /tmp \
      --tmpfs /evidence:uid=1001,gid=1001 --tmpfs /asset_logs:uid=1001,gid=1001 \
      -v "$PWD/backend:/src:ro" -w /src -e PYTHONPATH=/src -e PYTHONDONTWRITEBYTECODE=1 \
      -e EVIDENCE_PATH=/evidence -e LOGS_PATH=/asset_logs \
      -e DATABASE_URL=postgresql+asyncpg://nobody:none@127.0.0.1:1/none \
      -e EVIDENCE_KEK=$(python3 -c "print('11'*32)") \
      --entrypoint python dfir-fenrir-v2-backend:local -m unittest tests.test_evidence_manifest_s6 -v
"""
import base64
import contextlib
import hashlib
import io
import json
import os
import random
import stat
import struct
import tarfile
import types
import unittest
import uuid
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

import pyzipper
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.config import settings
from core.errors import ApiError
from evidence import codec, crypto, manifest, records, seekable
from evidence.crypto import EvidenceIntegrityError
from evidence.manifest_index import Caps, IndexFailed, ManifestBuild, canonical_line, csv_bytes, manifest_sha256
from evidence.provenance import score_evidence

C = codec.CHUNK_SIZE
CAPS = Caps(max_entries=1000, max_uncompressed_bytes=64 * C, max_path_chars=32_768)


def store(data: bytes) -> tuple[str, str, int]:
    rel = f"s6test/{uuid.uuid4().hex}.enc"
    st = crypto.write_encrypted(data, rel)
    return rel, st.nonce_hex, st.size


def path_of(rel: str) -> Path:
    return Path(settings.evidence_path) / rel


def run(fmt: str, data: bytes, caps: Caps = CAPS):
    rel, nonce, size = store(data)
    mb = ManifestBuild(fmt, caps)
    src = seekable.open_view(rel, nonce, size) if fmt == "zip" else crypto.iter_decrypted(rel, nonce, size)
    with contextlib.closing(src):
        entries = list(mb.entries(src))
    return mb, entries


def by_path(entries) -> dict:
    return {e["entry_path"]: e for e in entries}


def h(data: bytes) -> tuple[str, str, str]:
    return hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest(), hashlib.sha256(data).hexdigest()


# ── 1. the seekable view ─────────────────────────────────────────────────────────────────────────────────────────

class SeekableView(unittest.TestCase):
    def setUp(self):
        rnd = random.Random(6)
        self.data = rnd.randbytes(3 * C + 12_345)                  # 4 chunks: 3 full + a short final one
        self.rel, self.nonce, self.size = store(self.data)

    def test_random_seeks_match_the_plaintext(self):
        rnd = random.Random(7)
        with seekable.open_view(self.rel, self.nonce, self.size) as v:
            self.assertTrue(v.seekable() and v.readable())
            for _ in range(400):
                off = rnd.randrange(0, self.size + 10)
                n = rnd.choice([0, 1, 7, 4096, C - 1, C, C + 1, 2 * C + 3, -1])
                v.seek(off)
                got = v.read(n)
                self.assertEqual(got, self.data[off:] if n == -1 else self.data[off:off + n], (off, n))
                self.assertEqual(v.tell(), off + len(got))
            self.assertEqual(v.seek(-10, os.SEEK_END), self.size - 10)
            self.assertEqual(v.read(), self.data[-10:])
            v.seek(5)
            self.assertEqual(v.seek(3, os.SEEK_CUR), 8)
            with self.assertRaises(OSError):
                v.seek(-1)
            self.assertLessEqual(len(v._lru), seekable.LRU_CHUNKS)      # bounded memory

    def test_exact_chunk_multiple_and_empty(self):
        for data in (os.urandom(2 * C), b""):
            rel, nonce, size = store(data)
            with seekable.open_view(rel, nonce, size) as v:
                self.assertEqual(v.read(), data)
                v.seek(size)
                self.assertEqual(v.read(10), b"")

    def _tampered(self, mutate) -> Path:
        p = path_of(self.rel)
        raw = bytearray(p.read_bytes())
        mutate(raw)
        os.chmod(p, 0o644)
        p.write_bytes(bytes(raw))
        return p

    def test_one_byte_in_a_middle_chunk(self):
        seg1 = codec.HEADER_LEN + codec.SEGMENT_LEN + 1000           # inside chunk 1
        self._tampered(lambda raw: raw.__setitem__(seg1, raw[seg1] ^ 0x01))
        with seekable.open_view(self.rel, self.nonce, self.size) as v:   # the final chunk is still authentic
            self.assertEqual(v.read(100), self.data[:100])                # chunk 0 is fine
            v.seek(C - 10)
            with self.assertRaises(EvidenceIntegrityError) as cm:          # spans 0 → 1: nothing returned
                v.read(20)
            self.assertEqual(cm.exception.reason, "chunk_auth")
            v.seek(2 * C)
            self.assertEqual(v.read(10), self.data[2 * C:2 * C + 10])     # chunk 2 still reads

    def test_truncated(self):
        self._tampered(lambda raw: raw.__delitem__(slice(-1, None)))
        with self.assertRaises(EvidenceIntegrityError) as cm:
            seekable.open_view(self.rel, self.nonce, self.size)
        self.assertEqual(cm.exception.reason, "size_mismatch")

    def test_final_chunk_dropped(self):
        final_len = self.size - 3 * C + codec.TAG_LEN
        self._tampered(lambda raw: raw.__delitem__(slice(-final_len, None)))
        with self.assertRaises(EvidenceIntegrityError) as cm:
            seekable.open_view(self.rel, self.nonce, self.size)
        self.assertEqual(cm.exception.reason, "size_mismatch")

    def test_extended(self):
        self._tampered(lambda raw: raw.extend(b"\x00" * 16))
        with self.assertRaises(EvidenceIntegrityError):
            seekable.open_view(self.rel, self.nonce, self.size)

    def test_final_chunk_without_the_final_flag(self):
        """A last chunk encrypted as NON-final (right length, right index): the view opens it as final and refuses."""
        p = path_of(self.rel)
        raw = bytearray(p.read_bytes())
        h_ = codec.decode_header(bytes(raw[:codec.HEADER_LEN]))
        dek = codec._open_key_slot(bytes.fromhex(settings.evidence_kek), h_)
        tail = self.data[3 * C:]
        forged = AESGCM(dek).encrypt(codec.chunk_nonce(h_.nonce_prefix, 3, False), tail, h_.aad)
        start = codec.HEADER_LEN + 3 * codec.SEGMENT_LEN
        self.assertEqual(len(forged), len(raw) - start)
        self._tampered(lambda r: r.__setitem__(slice(start, None), forged))
        with self.assertRaises(EvidenceIntegrityError) as cm:
            seekable.open_view(self.rel, self.nonce, self.size)
        self.assertEqual(cm.exception.reason, "chunk_auth")

    def test_two_chunks_swapped(self):
        a, b = codec.HEADER_LEN, codec.HEADER_LEN + codec.SEGMENT_LEN

        def swap(raw):
            s0, s1 = bytes(raw[a:b]), bytes(raw[b:b + codec.SEGMENT_LEN])
            raw[a:b], raw[b:b + codec.SEGMENT_LEN] = s1, s0
        self._tampered(swap)
        with seekable.open_view(self.rel, self.nonce, self.size) as v:
            with self.assertRaises(EvidenceIntegrityError):
                v.read(1)
            v.seek(C)
            with self.assertRaises(EvidenceIntegrityError):
                v.read(1)

    def test_v0_row_and_wrong_nonce(self):
        with self.assertRaises(seekable.LegacyFormat) as cm:
            seekable.open_view(self.rel, "00" * 12, self.size)
        self.assertEqual(cm.exception.reason, "legacy_format")
        with self.assertRaises(EvidenceIntegrityError) as cm:
            seekable.open_view(self.rel, "00" * 7, self.size)
        self.assertEqual(cm.exception.reason, "nonce_mismatch")


# ── 2. canonical JSONL ───────────────────────────────────────────────────────────────────────────────────────────

VECTOR_ENTRIES = [
    {"seq": 1, "entry_path": "dossier/", "entry_name_encoding": "utf8", "entry_path_raw_b64": None,
     "source_path": None, "entry_type": "dir", "size": 0, "compressed_size": 0,
     "times": {"m": {"utc": None, "as_recorded": "2024-02-29 13:14:16", "basis": "zip_dos_time_local_timezone_unknown"}},
     "md5": None, "sha1": None, "sha256": None, "tool_hash": None, "tool_hash_match": None, "encrypted": False,
     "notes": None},
    {"seq": 2, "entry_path": "dossier/résumé.txt", "entry_name_encoding": "cp437",
     "entry_path_raw_b64": "ZG9zc2llci9ygnN1bYIudHh0", "source_path": "C:\\Users\\jdoé\\résumé.txt",
     "entry_type": "file", "size": 3, "compressed_size": 3,
     "times": {"m": {"utc": "2024-01-02T03:04:05.123456Z", "as_recorded": "133486382451234567",
                     "basis": "zip_ntfs_extra_filetime"}},
     "md5": "900150983cd24fb0d6963f7d28e17f72", "sha1": "a9993e364706816aba3e25717850c26c9cd0d89d",
     "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
     "tool_hash": {"algorithm": "sha1", "value": "A9993E364706816ABA3E25717850C26C9CD0D89D"},
     "tool_hash_match": True, "encrypted": False, "notes": None},
]
# The exact manifest bytes for VECTOR_ENTRIES (UTF-8; é stays one 2-byte character). SHA-256 pinned below.
VECTOR = (
    '{"compressed_size":0,"encrypted":false,"entry_name_encoding":"utf8","entry_path":"dossier/",'
    '"entry_path_raw_b64":null,"entry_type":"dir","md5":null,"notes":null,"seq":1,"sha1":null,"sha256":null,'
    '"size":0,"source_path":null,"times":{"m":{"as_recorded":"2024-02-29 13:14:16",'
    '"basis":"zip_dos_time_local_timezone_unknown","utc":null}},"tool_hash":null,"tool_hash_match":null}\n'
    '{"compressed_size":3,"encrypted":false,"entry_name_encoding":"cp437","entry_path":"dossier/résumé.txt",'
    '"entry_path_raw_b64":"ZG9zc2llci9ygnN1bYIudHh0","entry_type":"file","md5":"900150983cd24fb0d6963f7d28e17f72",'
    '"notes":null,"seq":2,"sha1":"a9993e364706816aba3e25717850c26c9cd0d89d",'
    '"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","size":3,'
    '"source_path":"C:\\\\Users\\\\jdoé\\\\résumé.txt","times":{"m":{"as_recorded":"133486382451234567",'
    '"basis":"zip_ntfs_extra_filetime","utc":"2024-01-02T03:04:05.123456Z"}},'
    '"tool_hash":{"algorithm":"sha1","value":"A9993E364706816ABA3E25717850C26C9CD0D89D"},"tool_hash_match":true}\n'
).encode("utf-8")
VECTOR_SHA256 = "e995694c5e9e662245dc7fea3f5d3a412c7eab2b22079539621aabba7b93c976"


class CanonicalJsonl(unittest.TestCase):
    def test_vector(self):
        self.assertEqual(b"".join(canonical_line(e) for e in VECTOR_ENTRIES), VECTOR)
        self.assertEqual(hashlib.sha256(VECTOR).hexdigest(), VECTOR_SHA256)
        self.assertEqual(manifest_sha256(VECTOR_ENTRIES), VECTOR_SHA256)

    def test_stable_shape(self):
        sparse = canonical_line({"seq": 1, "entry_path": "x"})            # missing keys are null, never dropped
        self.assertEqual(set(json.loads(sparse)), set(VECTOR_ENTRIES[0]))
        reordered = {k: VECTOR_ENTRIES[1][k] for k in reversed(list(VECTOR_ENTRIES[1]))}
        self.assertEqual(canonical_line(reordered), canonical_line(VECTOR_ENTRIES[1]))
        self.assertIn("jdoé".encode(), VECTOR)
        self.assertNotIn(b"\\u00e9", VECTOR)

    def test_csv_through_csv_safe(self):
        e = {**VECTOR_ENTRIES[1], "entry_path": "=cmd|' /C calc'!A0"}
        text = csv_bytes([e], header=True).decode("utf-8-sig")
        self.assertIn("'=cmd|", text)
        self.assertTrue(text.startswith("seq,entry_path,"))


# ── 3. ZIP ───────────────────────────────────────────────────────────────────────────────────────────────────────

def _ntfs(m: int, a: int, b: int) -> bytes:
    return struct.pack("<HHI", 0x000A, 32, 0) + struct.pack("<HHQQQ", 1, 24, m, a, b)


def _ft(dt: datetime, ticks: int = 0) -> int:
    return int((dt - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds()) * 10_000_000 + ticks


class ZipIndex(unittest.TestCase):
    def setUp(self):
        T = datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("a/", b"")
            z.writestr("a/b/", b"")
            zi = zipfile.ZipInfo("a/b/ntfs.txt", date_time=(2024, 1, 2, 4, 4, 4))
            zi.extra = _ntfs(_ft(T, 1234567), _ft(T) + 10_000_000, _ft(T) - 10_000_000)
            z.writestr(zi, b"abc")
            zi = zipfile.ZipInfo("ut.txt")
            zi.extra = struct.pack("<HHBii", 0x5455, 9, 0x03, 1_700_000_000, 1_700_000_100)
            z.writestr(zi, b"unix times")
            z.writestr(zipfile.ZipInfo("dos.txt", date_time=(2024, 2, 29, 13, 14, 16)), b"dos only")
            z.writestr("dossier/résumé.txt", b"utf8 flag")
            zi = zipfile.ZipInfo("cafX.txt")                                     # becomes cp437 caf\x82.txt below
            raw = b"caf\x82.txt"
            z.writestr(zi, b"cp437 name")
            zi = zipfile.ZipInfo("upaX.txt")                                     # cp437 + Unicode Path extra
            zi.extra = struct.pack("<HHBL", 0x7075, 5 + len("upaé.txt".encode()), 1, zlib.crc32(b"upa\x82.txt")) \
                + "upaé.txt".encode()
            z.writestr(zi, b"unicode path field")
            zi = zipfile.ZipInfo("link")
            zi.create_system = 3
            zi.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(zi, b"a/b/ntfs.txt")
            z.writestr(zipfile.ZipInfo("stored.bin"), b"A" * 100, compress_type=zipfile.ZIP_STORED)
        data = buf.getvalue()
        for old, new in ((b"cafX.txt", raw), (b"upaX.txt", b"upa\x82.txt")):
            self.assertEqual(data.count(old), 2)
            data = data.replace(old, new)
        self.zip_data = data
        self.mb, self.entries = run("zip", data)
        self.e = by_path(self.entries)

    def test_order_types_and_hashes(self):
        self.assertEqual([e["seq"] for e in self.entries], list(range(1, 11)))
        self.assertEqual((self.e["a/"]["entry_type"], self.e["a/b/"]["entry_type"], self.e["link"]["entry_type"]),
                         ("dir", "dir", "symlink"))
        self.assertIsNone(self.e["a/"]["sha256"])
        self.assertEqual((self.e["a/b/ntfs.txt"]["md5"], self.e["a/b/ntfs.txt"]["sha1"],
                          self.e["a/b/ntfs.txt"]["sha256"]), h(b"abc"))
        self.assertEqual(self.e["link"]["sha256"], h(b"a/b/ntfs.txt")[2])        # the member holds the target
        self.assertEqual((self.e["a/b/ntfs.txt"]["size"], self.e["stored.bin"]["compressed_size"]), (3, 100))
        self.assertEqual(self.mb.count, 10)
        self.assertEqual(self.mb.manifest_sha256, manifest_sha256(self.entries))
        self.assertTrue(self.mb.builder.startswith("fenrir-manifest 1 (zip: CPython "))

    def test_names(self):
        self.assertEqual((self.e["dossier/résumé.txt"]["entry_name_encoding"],
                          self.e["dossier/résumé.txt"]["entry_path_raw_b64"]), ("utf8", None))
        cp = self.e["café.txt"]                                                     # 0x82 = é in cp437
        self.assertEqual((cp["entry_name_encoding"], base64.b64decode(cp["entry_path_raw_b64"])),
                         ("cp437", b"caf\x82.txt"))
        up = self.e["upaé.txt"]
        self.assertEqual((up["entry_name_encoding"], base64.b64decode(up["entry_path_raw_b64"])),
                         ("utf8", b"upa\x82.txt"))
        self.assertEqual(self.e["a/"]["entry_path_raw_b64"], None)                 # ASCII cp437: nothing raw

    def test_times(self):
        t = self.e["a/b/ntfs.txt"]["times"]
        self.assertEqual((t["m"]["utc"], t["m"]["basis"]), ("2024-01-02T03:04:05.123456Z", "zip_ntfs_extra_filetime"))
        self.assertEqual((t["a"]["utc"], t["b"]["utc"]), ("2024-01-02T03:04:06Z", "2024-01-02T03:04:04Z"))
        self.assertEqual(t["m"]["as_recorded"], str(_ft(datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc), 1234567)))
        u = self.e["ut.txt"]["times"]
        self.assertEqual((u["m"]["utc"], u["a"]["utc"], u["m"]["basis"]),
                         ("2023-11-14T22:13:20Z", "2023-11-14T22:15:00Z", "zip_extended_timestamp_unix"))
        d = self.e["dos.txt"]["times"]
        self.assertEqual(d, {"m": {"utc": None, "as_recorded": "2024-02-29 13:14:16",
                                   "basis": "zip_dos_time_local_timezone_unknown"}})

    def test_crc_error_and_unsupported_method_are_notes(self):
        bad = bytearray(self.zip_data)
        i = bad.find(b"A" * 100)
        bad[i] = ord("B")                                                            # stored member: CRC now wrong
        mb, entries = run("zip", bytes(bad))
        s = by_path(entries)["stored.bin"]
        self.assertIsNone(s["sha256"])
        self.assertIn("Bad CRC-32", s["notes"])
        self.assertEqual(mb.count, 10)                                               # the manifest is still built
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
            z.writestr("d64.bin", b"x" * 10)
        raw = bytearray(buf.getvalue())
        for sig, off in ((b"PK\x03\x04", 8), (b"PK\x01\x02", 10)):
            j = raw.find(sig) + off
            raw[j:j + 2] = struct.pack("<H", 9)                                      # Deflate64
        _, entries = run("zip", bytes(raw))
        self.assertIsNone(entries[0]["sha256"])
        self.assertIn("compression method 9", entries[0]["notes"])

    def test_encrypted_member(self):
        buf = io.BytesIO()
        with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
            z.setpassword(b"pw")
            z.writestr("secret.txt", b"top secret")
        _, entries = run("zip", buf.getvalue())
        e = entries[0]
        self.assertEqual((e["encrypted"], e["sha256"], e["md5"]), (True, None, None))
        self.assertEqual(e["notes"], "encrypted member: not hashed")

    def test_zip64_end_record(self):
        """More than 65,535 members: a ZIP64 end of central directory; the pre-count agrees with zipfile."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
            for i in range(65_540):
                z.writestr(f"d/{i}", b"")
        data = buf.getvalue()
        self.assertIn(b"PK\x06\x06", data)                                       # the ZIP64 end record is there
        mb, entries = run("zip", data, Caps(70_000, 64 * C, 1000))
        self.assertEqual((mb.count, entries[-1]["entry_path"], entries[-1]["sha256"]), (65_540, "d/65539", h(b"")[2]))
        with self.assertRaises(IndexFailed) as cm:
            run("zip", data, Caps(65_539, 64 * C, 1000))
        self.assertEqual(cm.exception.reason, "too_many_entries")

    def test_caps_and_not_a_zip(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for i in range(5):
                z.writestr(f"f{i}.txt", b"x")
            z.writestr("zeros.bin", b"\x00" * (3 * C))
            z.writestr("p/" + "a" * 40, b"long")
        for caps, reason in ((Caps(3, 64 * C, 1000), "too_many_entries"), (Caps(100, C, 1000), "uncompressed_cap"),
                             (Caps(100, 64 * C, 20), "path_too_long")):
            with self.assertRaises(IndexFailed) as cm:
                run("zip", buf.getvalue(), caps)
            self.assertEqual(cm.exception.reason, reason)
        with self.assertRaises(IndexFailed) as cm:
            run("zip", os.urandom(5000))
        self.assertEqual(cm.exception.reason, "not_a_zip")


# ── 4. TAR ───────────────────────────────────────────────────────────────────────────────────────────────────────

def tar_bytes(mode: str = "w", fmt=tarfile.PAX_FORMAT, extra=()) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode, format=fmt, encoding="utf-8", errors="surrogateescape") as t:
        d = tarfile.TarInfo("docs")
        d.type, d.mtime = tarfile.DIRTYPE, 1_700_000_000
        t.addfile(d)
        f = tarfile.TarInfo("docs/report.txt")
        f.size, f.mtime = 6, 1_700_000_002
        f.pax_headers = {"atime": "1700000000.5", "ctime": "1700000001.25"}
        t.addfile(f, io.BytesIO(b"report"))
        for name, kind, target in (("docs/link", tarfile.SYMTYPE, "report.txt"),
                                   ("docs/hard", tarfile.LNKTYPE, "docs/report.txt")):
            ln = tarfile.TarInfo(name)
            ln.type, ln.linkname = kind, target
            t.addfile(ln)
        p = tarfile.TarInfo("pipe")
        p.type = tarfile.FIFOTYPE
        t.addfile(p)
        for name, data in extra:
            x = tarfile.TarInfo(name)
            x.size = len(data)
            t.addfile(x, io.BytesIO(data))
    return buf.getvalue()


class TarIndex(unittest.TestCase):
    def test_types_times_hashes(self):
        mb, entries = run("tar", tar_bytes())
        e = by_path(entries)
        self.assertEqual([x["entry_type"] for x in entries], ["dir", "file", "symlink", "hardlink", "other"])
        r = e["docs/report.txt"]
        self.assertEqual((r["md5"], r["sha1"], r["sha256"]), h(b"report"))
        self.assertIsNone(r["compressed_size"])
        self.assertEqual(r["times"]["m"], {"utc": "2023-11-14T22:13:22Z", "as_recorded": "1700000002",
                                           "basis": "tar_header_mtime"})
        self.assertEqual((r["times"]["a"]["utc"], r["times"]["a"]["basis"]),
                         ("2023-11-14T22:13:20.500000Z", "tar_pax_atime"))
        self.assertEqual((r["times"]["c"]["utc"], r["times"]["c"]["as_recorded"]),
                         ("2023-11-14T22:13:21.250000Z", "1700000001.25"))
        self.assertEqual(e["docs/link"]["notes"], "link target: report.txt")
        self.assertEqual(e["pipe"]["notes"], "FIFO")
        self.assertEqual(mb.manifest_sha256, manifest_sha256(entries))

    def test_compressed_variants_are_the_same_manifest(self):
        plain = run("tar", tar_bytes())[1]
        for mode in ("w:gz", "w:bz2", "w:xz"):
            mb, entries = run("tar", tar_bytes(mode))
            self.assertEqual([(x["entry_path"], x["sha256"]) for x in entries],
                             [(x["entry_path"], x["sha256"]) for x in plain], mode)
            self.assertIn("tarfile", mb.builder)

    def test_non_utf8_name(self):
        _, entries = run("tar", tar_bytes(fmt=tarfile.GNU_FORMAT, extra=(("caf\udce9.txt", b"x"),)))
        e = entries[-1]
        self.assertEqual((e["entry_path"], e["entry_name_encoding"], base64.b64decode(e["entry_path_raw_b64"])),
                         ("caf\ufffd.txt", "other", b"caf\xe9.txt"))

    def test_truncated_caps_and_listing(self):
        gz = tar_bytes("w:gz", extra=(("big.bin", os.urandom(200_000)),))
        with self.assertRaises(IndexFailed) as cm:
            run("tar", gz[:len(gz) // 2])
        self.assertEqual(cm.exception.reason, "parse_error")
        with self.assertRaises(IndexFailed) as cm:
            run("tar", tar_bytes(), Caps(2, 64 * C, 1000))
        self.assertEqual(cm.exception.reason, "too_many_entries")
        with self.assertRaises(IndexFailed) as cm:
            run("tar", tar_bytes("w:gz", extra=(("zeros.bin", b"\x00" * (3 * C)),)), Caps(100, C, 1000))
        self.assertEqual(cm.exception.reason, "uncompressed_cap")
        mb, _ = run("tar", tar_bytes(extra=(("out/2024_CopyLog.csv", b"SourceFile,DestinationFile\r\n"),)))
        self.assertEqual([(s["parser"], s["status"]) for s in mb.listing], [("kape_copylog", "not_merged")])
        self.assertIn("ZIP containers only", mb.listing[0]["note"])

    def test_whole_stream_is_read(self):
        """Trailing bytes after the end-of-archive marker: the decrypting iterator still runs to its end (F-12)."""
        data = tar_bytes() + os.urandom(2 * C)
        rel, nonce, size = store(data)
        done = []

        def it():
            yield from crypto.iter_decrypted(rel, nonce, size)
            done.append(True)
        mb = ManifestBuild("tar", CAPS)
        self.assertEqual(len(list(mb.entries(it()))), 5)
        self.assertEqual(done, [True])

    def test_header_bombs_are_refused_before_tarfile_reads_them(self):
        """tarfile reads a pax / GNU long-name header whole, at the size it declares (1 GiB here, none of it present)."""
        for kind in (tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME):
            hdr = tarfile.TarInfo("././@Header")
            hdr.type, hdr.size = kind, 1 << 30
            with self.assertRaises(IndexFailed) as cm:
                run("tar", hdr.tobuf(format=tarfile.USTAR_FORMAT) + b"\0" * 1024)
            self.assertEqual(cm.exception.reason, "tar_header_too_large", kind)

        def with_global(comment: str) -> bytes:
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT, pax_headers={"comment": comment}) as t:
                t.addfile(tarfile.TarInfo("empty"))
            return buf.getvalue()
        with self.assertRaises(IndexFailed) as cm:
            run("tar", with_global("x" * (65 * 1024)))
        self.assertEqual(cm.exception.reason, "tar_header_too_large")
        self.assertEqual(len(run("tar", with_global("4f2c" * 10))[1]), 1)       # git archive's commit id: fine

    def test_long_names_still_build(self):
        long = "d/" * 9_000 + "f.txt"
        for fmt in (tarfile.PAX_FORMAT, tarfile.GNU_FORMAT):
            _, entries = run("tar", tar_bytes(fmt=fmt, extra=((long, b"x"),)))
            self.assertEqual((entries[-1]["entry_path"], entries[-1]["sha256"]), (long, h(b"x")[2]))

    def test_unknown_type_data_is_skipped_and_counted(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as t:
            u = tarfile.TarInfo("dumpdir")
            u.type, u.size = b"D", 3 * C
            t.addfile(u, io.BytesIO(b"\0" * (3 * C)))
            t.addfile(tarfile.TarInfo("after"))
        _, entries = run("tar", buf.getvalue())
        self.assertEqual([(e["entry_path"], e["entry_type"]) for e in entries], [("dumpdir", "other"), ("after", "file")])
        with self.assertRaises(IndexFailed) as cm:
            run("tar", buf.getvalue(), Caps(100, C, 1000))
        self.assertEqual(cm.exception.reason, "uncompressed_cap")


# ── 5. tool listings ─────────────────────────────────────────────────────────────────────────────────────────────

KAPE_HEADER = ("CopiedTimestamp,SourceFile,DestinationFile,FileSize,SourceFileSha1,DeferredCopy,CreatedOnUtc,"
               "ModifiedOnUtc,LastAccessedOnUtc,CopyDuration\r\n")


def kape_zip(copylog: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("C/Windows/System32/config/SAM", b"sam bytes")
        z.writestr("C/Users/jdoe/NTUSER.DAT", b"ntuser")
        z.writestr("C/Users/jdoe/Desktop/x.lnk", b"lnk")
        z.writestr("2024-01-02T030405_CopyLog.csv", copylog.encode("utf-8-sig"))
    return buf.getvalue()


class KapeCopyLog(unittest.TestCase):
    def test_merge_match_mismatch_unmatched(self):
        log = KAPE_HEADER + "\r\n".join([
            f"2024-01-02 03:04:05,C:\\Windows\\System32\\config\\SAM,D:\\kape\\out\\C\\Windows\\System32\\config\\SAM,9,"
            f"{hashlib.sha1(b'sam bytes').hexdigest().upper()},False,2019-12-07 09:10:11.1234567,"
            "2024-01-01 08:00:00.0000001,2024-01-02 01:02:03,0.1",
            "2024-01-02 03:04:05,C:\\Users\\jdoe\\NTUSER.DAT,D:\\kape\\out\\C\\Users\\jdoe\\NTUSER.DAT,6,"
            f"{'0' * 40},True,,,,0.2",
            "2024-01-02 03:04:05,C:\\Users\\jdoe\\gone.txt,D:\\kape\\out\\C\\Users\\jdoe\\gone.txt,1,,False,,,,0",
            "2024-01-02 03:04:05,C:\\Users\\jdoe\\Desktop\\x.lnk,D:\\kape\\out\\C\\Users\\jdoe\\Desktop\\x.lnk,3,,False,,,,0",
        ]) + "\r\n"
        mb, entries = run("zip", kape_zip(log))
        e = by_path(entries)
        sam = e["C/Windows/System32/config/SAM"]
        self.assertEqual(sam["source_path"], "C:\\Windows\\System32\\config\\SAM")
        self.assertEqual(sam["tool_hash"], {"algorithm": "sha1", "value": hashlib.sha1(b"sam bytes").hexdigest().upper()})
        self.assertIs(sam["tool_hash_match"], True)
        src = sam["times"]["source"]
        self.assertEqual((src["b"]["utc"], src["m"]["utc"], src["a"]["utc"], src["read_by"]),
                         ("2019-12-07T09:10:11.123456Z", "2024-01-01T08:00:00Z", "2024-01-02T01:02:03Z", "KAPE"))
        self.assertEqual(src["b"]["as_recorded"], "2019-12-07 09:10:11.1234567")
        self.assertIn("m", sam["times"])                                            # the container's own times stay
        nt = e["C/Users/jdoe/NTUSER.DAT"]
        self.assertIs(nt["tool_hash_match"], False)
        self.assertNotIn("source", nt["times"])
        lnk = e["C/Users/jdoe/Desktop/x.lnk"]
        self.assertEqual((lnk["source_path"], lnk["tool_hash"], lnk["tool_hash_match"]),
                         ("C:\\Users\\jdoe\\Desktop\\x.lnk", None, None))
        (s,) = mb.listing
        self.assertEqual({k: s[k] for k in ("parser", "version", "status", "rows", "matched", "unmatched",
                                            "tool_hash_matches", "tool_hash_mismatches")},
                         {"parser": "kape_copylog", "version": 1, "status": "merged", "rows": 4, "matched": 3,
                          "unmatched": 1, "tool_hash_matches": 1, "tool_hash_mismatches": 1})
        self.assertIsNone(e["2024-01-02T030405_CopyLog.csv"]["source_path"])

    def test_garbled_listing_is_not_merged(self):
        for log, why in ((("CopiedTimestamp,SourceFile,FileSize\r\n1,C:\\x,2\r\n"), "DestinationFile"),
                         (KAPE_HEADER + "1,C:\\x,D:\\o\\C\\x\r\n", "line 2: 3 fields"),
                         (KAPE_HEADER + "1," + "x" * 200_000 + ",D:\\o\\C\\x,1,,False,,,,0\r\n", "field larger"),
                         (KAPE_HEADER + "1," + "x" * (2 << 20), "longer than")):    # refused before csv reads it
            mb, entries = run("zip", kape_zip(log))
            (s,) = mb.listing
            self.assertEqual(s["status"], "not_merged")
            self.assertIn(why, s["note"])
            self.assertTrue(all(x["source_path"] is None and x["tool_hash"] is None for x in entries))
            self.assertEqual(mb.count, 4)                                            # still built


def velo_zip(uploads_json: str) -> tuple[bytes, dict]:
    files = {"uploads/auto/C%3A/Windows/System32/winevt/Logs/Security.evtx": b"evtx bytes",
             "uploads/ntfs/%5C%5C.%5CC%3A/$MFT": b"mft bytes",
             "uploads/auto/home/jdoe/.bash_history": b"ls\n"}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("collection_context.json", json.dumps({"Hostname": "WS-01"}))
        z.writestr("results/Windows.EventLogs.Evtx%2FAllEvents.json", b"{}\n")
        for name, data in files.items():
            z.writestr(name, data)
        z.writestr("uploads.json", uploads_json)
    return buf.getvalue(), files


class VelociraptorUploads(unittest.TestCase):
    def test_merge(self):
        evtx = hashlib.sha256(b"evtx bytes").hexdigest()
        rows = [
            {"Timestamp": 1700000000, "started": "2023-11-14 22:13:20 +0000 UTC",
             "vfs_path": "uploads/auto/C%3A/Windows/System32/winevt/Logs/Security.evtx",
             "_Components": ["uploads", "auto", "C:", "Windows", "System32", "winevt", "Logs", "Security.evtx"],
             "file_size": 10, "uploaded_size": 10, "sha256": evtx},
            {"vfs_path": "uploads/ntfs/%5C%5C.%5CC%3A/$MFT", "file_size": 9},
            {"_Components": ["uploads", "auto", "home", "jdoe", ".bash_history"], "md5": "0" * 32},
            {"_Components": ["uploads", "auto", "C:", "x.idx"], "Type": "idx"},
            {"_Components": ["uploads", "auto", "C:", "not", "here.txt"]},
        ]
        data, _ = velo_zip("\n".join(json.dumps(r) for r in rows) + "\n")
        mb, entries = run("zip", data)
        e = by_path(entries)
        sec = e["uploads/auto/C%3A/Windows/System32/winevt/Logs/Security.evtx"]
        self.assertEqual((sec["source_path"], sec["tool_hash"], sec["tool_hash_match"]),
                         ("C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", {"algorithm": "sha256", "value": evtx},
                          True))
        self.assertEqual(e["uploads/ntfs/%5C%5C.%5CC%3A/$MFT"]["source_path"], "\\\\.\\C:\\$MFT")
        bash = e["uploads/auto/home/jdoe/.bash_history"]
        self.assertEqual((bash["source_path"], bash["tool_hash_match"]), ("/home/jdoe/.bash_history", False))
        (s,) = mb.listing
        self.assertEqual((s["parser"], s["status"], s["rows"], s["matched"], s["unmatched"], s["tool_hash_matches"],
                          s["tool_hash_mismatches"]), ("velociraptor_uploads", "merged", 4, 3, 1, 1, 1))

    def test_garbled(self):
        good = '{"_Components": ["uploads", "auto", "C:", "Windows", "System32", "winevt", "Logs", "Security.evtx"]}\n'
        for text, note in ((good + "not json\n", "line 2: not JSON"),
                           (good + '{"x": "' + "a" * (2 * 1024 * 1024) + '"}\n', "line 2: longer than"),
                           (good + '["a list"]\n', "line 2: not a JSON object")):
            data, _ = velo_zip(text)
            mb, entries = run("zip", data)
            (s,) = mb.listing
            self.assertEqual((s["status"], s["matched"]), ("not_merged", 0))
            self.assertTrue(s["note"].startswith(note), s["note"])
            self.assertTrue(all(x["source_path"] is None for x in entries))       # all or nothing: line 1 not merged


# ── 6. provenance, format rules, the seal record ─────────────────────────────────────────────────────────────────

def _ev(**kw):
    base = dict(kind="digital_file", photos=[], collected_by_id=uuid.uuid4(), collected_location="x", lawful_basis="ir",
                sha256="a" * 64, write_blocker_used=True, system_state="powered_off", live_justification=None,
                acquisition_tool="t", acquisition_tool_version="1", acquisition_hash_source=None,
                acquisition_hash_target=None, status="active", coc_sealed=False, source_details=None,
                md5=None, sha1=None, entity_id=None, source_system="h", make=None, model=None, serial=None,
                source_path="C:\\x", source_path_style="windows", source_unknown_reason=None,
                acquisition_scope="logical", device_types=["computer"], handling_mode="acquire",
                seal_record_sha256=None, acquisition_tool_validated=None, collected_by_qualifications=None,
                collected_as_role=None, current_custodian_id=uuid.uuid4(), current_custodian_external_name=None,
                container_format=None, manifest_status=None, manifest_listing=None, manifest_error=None)
    return types.SimpleNamespace(**{**base, **kw})


def _check(ev):
    return {c["code"]: c for c in score_evidence(ev)["checks"]}["container_manifest"]


class ProvenanceAndRules(unittest.TestCase):
    def test_container_manifest_check(self):
        self.assertEqual(_check(_ev())["status"], "n_a")
        ok = _check(_ev(container_format="zip", manifest_status="built",
                        manifest_listing=[{"tool_hash_mismatches": 0}]))
        self.assertEqual((ok["status"], ok["severity"]), ("pass", "advisory"))
        bad = _check(_ev(container_format="zip", manifest_status="built",
                         manifest_listing=[{"tool_hash_mismatches": 2}, {"tool_hash_mismatches": 1}]))
        self.assertEqual((bad["status"], bad["note"]), ("fail", "3 member(s) differ from the tool listing's hash"))
        for st in ("failed", "not_indexed", "pending"):
            self.assertEqual(_check(_ev(container_format="tar" if st != "not_indexed" else "ad1", manifest_status=st,
                                        manifest_error="parse_error: x"))["status"], "manual", st)
        self.assertNotIn("container_manifest", {c["code"] for c in score_evidence(_ev(kind="physical_item"))["checks"]})

    def test_format_change(self):
        self.assertEqual(manifest.format_change(_ev(), "zip"),
                         {"container_format": "zip", "manifest_status": "pending", "manifest_error": None})
        self.assertEqual(manifest.format_change(_ev(), "ad1")["manifest_status"], "not_indexed")
        self.assertEqual(manifest.format_change(_ev(container_format="zip", manifest_status="failed",
                                                    manifest_error="x"), "tar")["manifest_status"], "pending")
        self.assertEqual(manifest.format_change(_ev(container_format="zip", manifest_status="built"), "zip"), {})
        with self.assertRaises(ApiError) as cm:
            manifest.format_change(_ev(container_format="zip", manifest_status="built"), None)
        self.assertEqual((cm.exception.status_code, cm.exception.code), (409, "manifest_built"))
        with self.assertRaises(ApiError) as cm:
            manifest.format_change(_ev(kind="physical_item"), "zip")
        self.assertEqual((cm.exception.status_code, cm.exception.code), (422, "container_format_not_applicable"))

    def test_seal_record_binds_manifest_sha256_only_when_set(self):
        self.assertEqual(records.SEAL_RECORD_OPTIONAL_FIELDS, ("manifest_sha256",))
        ev = types.SimpleNamespace(id=uuid.uuid4(), identifier="X", kind="digital_file", md5=None, sha1=None,
                                   sha256=None, photos=[], seal_tst=None, coc_sealed=False,
                                   **{f: None for f in records.ACQUISITION_FIELDS + records.SOURCE_FIELDS
                                      if f not in ("coc_sealed", "seal_tst_present")})
        self.assertNotIn(b"manifest_sha256", records.seal_record_v1(ev))
        ev.manifest_sha256 = "9" * 64
        self.assertEqual(json.loads(records.seal_record_v1(ev))["manifest_sha256"], "9" * 64)


if __name__ == "__main__":
    unittest.main()
