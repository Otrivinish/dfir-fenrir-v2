"""Unit tests for evidence/codec.py (FENRGCM v2, docs/streaming-aes-gcm-format.md §8.1).

stdlib unittest (the backend image has no pytest). Pure: no settings, no DB, no files.
Run in a throwaway backend container with no network, e.g. from the repo root:

    docker run --rm --network none --read-only --tmpfs /tmp -v "$PWD/backend:/src:ro" \
      -w /src -e PYTHONPATH=/src -e PYTHONDONTWRITEBYTECODE=1 \
      --entrypoint python dfir-fenrir-v2-backend:local -m unittest tests.test_codec -v

Private codec names are imported explicitly: they are test seams, not API (spec §4.1).
"""
import hashlib
import hmac
import io
import os
import random
import struct
import unittest
from unittest import mock

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap, aes_key_wrap

from evidence import codec
from evidence.codec import (AAD_LEN, CHUNK_SIZE, HEADER_LEN, KEY_SLOT_OFFSET, MAX_CHUNKS,
                            SEGMENT_LEN, TAG_LEN, CodecError, CodecFormatError,
                            CodecIntegrityError, CodecUnwrapError)
from evidence.codec import (_decrypt_chunk, _encode_header, _encrypt_chunk, _unwrap_dek,
                            _wrap_dek, _wrap_key)

KEK  = bytes(range(32))
KEK2 = bytes(range(100, 132))
CS   = CHUNK_SIZE


# ─── Drivers that mimic stage 3's file I/O over an in-memory file ────────────

def seal(kek: bytes, pt: bytes) -> bytes:
    enc = codec.StreamEncryptor(kek)
    out = [enc.header]
    full = len(pt) // CS
    for i in range(full):
        out.append(enc.update(pt[i * CS:(i + 1) * CS]))
    out.append(enc.finalize(pt[full * CS:]))
    return b"".join(out)


def open_read(kek: bytes, read) -> bytes:
    """The stage-3 read loop: header, then iter_segments, then finalize."""
    header = codec.read_exactly(read, HEADER_LEN)
    if not codec.is_streaming_format(header):
        raise AssertionError("not a FENRGCM container")
    dec = codec.StreamDecryptor(kek, header)
    out = [dec.update(seg) for seg in codec.iter_segments(read)]
    dec.finalize()
    return b"".join(out)


def open_(kek: bytes, blob: bytes) -> bytes:
    return open_read(kek, io.BytesIO(blob).read)


class ShortReader:
    """A file whose read(n) returns a random 1..n bytes, like a pipe or socket."""

    def __init__(self, data: bytes, seed: int, max_read: int):
        self._f, self._rng, self._max = io.BytesIO(data), random.Random(seed), max_read

    def read(self, n: int) -> bytes:
        return self._f.read(self._rng.randint(1, max(1, min(n, self._max))))


def segments(blob: bytes) -> list[bytes]:
    body = blob[HEADER_LEN:]
    return [body[i:i + SEGMENT_LEN] for i in range(0, len(body), SEGMENT_LEN)]


def join(header: bytes, segs: list[bytes]) -> bytes:
    return header + b"".join(segs)


def flip(blob: bytes, pos: int, mask: int = 0x01) -> bytes:
    b = bytearray(blob)
    b[pos] ^= mask
    return bytes(b)


# ─── Spec-only reference: rebuilds a container from the doc, not from codec ──

def hkdf_sha256(ikm: bytes, info: bytes, length: int, salt: bytes = b"") -> bytes:
    """RFC 5869 by hand (hmac + hashlib), independent of cryptography's HKDF."""
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out, i = out + t, i + 1
    return out[:length]


def spec_container(kek: bytes, dek: bytes, prefix: bytes, pt: bytes) -> bytes:
    immutable = b"FENRGCM" + bytes([2]) + struct.pack(">I", 1048576) + prefix + bytes(13)
    k_wrap = hkdf_sha256(kek, b"FENRGCM/v2/key-wrap", 32)
    kid = hkdf_sha256(kek, b"FENRGCM/v2/kek-id", 7)
    header = immutable + b"\x01" + kid + aes_key_wrap(k_wrap, dek)
    aes, out = AESGCM(dek), [header]
    n_full = len(pt) // 1048576
    for i in range(n_full + 1):
        final = i == n_full
        nonce = prefix + i.to_bytes(4, "big") + (b"\x01" if final else b"\x00")
        out.append(aes.encrypt(nonce, pt[i * 1048576:(i + 1) * 1048576], immutable))
    return b"".join(out)


class TestRoundTrip(unittest.TestCase):
    SIZES = {
        "0 B": 0,
        "1 B": 1,
        "chunk-1": CS - 1,
        "exactly 1 chunk": CS,
        "chunk+1": CS + 1,
        "multi-chunk non-aligned": 3 * CS + 12345,
        "~20 MiB": 20 * CS + 7,
    }

    def test_roundtrip_sizes(self):
        for label, n in self.SIZES.items():
            with self.subTest(label):
                pt = os.urandom(n)
                blob = seal(KEK, pt)
                self.assertEqual(len(blob), codec.container_size(n))
                segs = segments(blob)
                self.assertEqual(len(segs), n // CS + 1)                  # always one final chunk
                self.assertTrue(all(len(s) == SEGMENT_LEN for s in segs[:-1]))
                self.assertEqual(len(segs[-1]), n % CS + TAG_LEN)
                self.assertEqual(open_(KEK, blob), pt)

    def test_empty_plaintext_is_header_plus_one_tag(self):
        blob = seal(KEK, b"")
        self.assertEqual(len(blob), HEADER_LEN + TAG_LEN)

    def test_exact_multiple_ends_with_empty_final_chunk(self):
        segs = segments(seal(KEK, os.urandom(2 * CS)))
        self.assertEqual([len(s) for s in segs], [SEGMENT_LEN, SEGMENT_LEN, TAG_LEN])

    def test_encryptor_matches_spec_reference(self):
        pt = os.urandom(2 * CS + 99)
        blob = seal(KEK, pt)
        dek = aes_key_unwrap(hkdf_sha256(KEK, b"FENRGCM/v2/key-wrap", 32), blob[40:80])
        self.assertEqual(blob, spec_container(KEK, dek, blob[12:19], pt))


class TestShortReads(unittest.TestCase):
    """F-5: a short read must never be taken for the final chunk."""

    def test_random_short_reads_decrypt(self):
        pt = os.urandom(2 * CS + 777)
        blob = seal(KEK, pt)
        for seed in range(20):
            with self.subTest(seed=seed):
                max_read = random.Random(seed).choice(
                    [4096, 65536, SEGMENT_LEN - 1, SEGMENT_LEN, 3 * SEGMENT_LEN])
                self.assertEqual(open_read(KEK, ShortReader(blob, seed, max_read).read), pt)

    def test_one_byte_reads(self):
        pt = os.urandom(3000)
        blob = seal(KEK, pt)
        self.assertEqual(open_read(KEK, ShortReader(blob, 0, 1).read), pt)

    def test_read_exactly_stops_only_at_eof(self):
        r = ShortReader(b"x" * 100, 1, 7).read
        self.assertEqual(codec.read_exactly(r, 60), b"x" * 60)
        self.assertEqual(codec.read_exactly(r, 60), b"x" * 40)        # EOF
        self.assertEqual(codec.read_exactly(r, 60), b"")

    def test_non_blocking_read_is_a_caller_error(self):
        # A non-blocking source returns None when no data is ready; that is not EOF.
        parts = iter([b"abc", None, b"def"])
        with self.assertRaises(ValueError):
            codec.read_exactly(lambda n: next(parts), 6)

    def test_short_reads_do_not_hide_tampering(self):
        blob = flip(seal(KEK, os.urandom(2 * CS + 5)), HEADER_LEN + SEGMENT_LEN + 9)
        with self.assertRaises(CodecIntegrityError):
            open_read(KEK, ShortReader(blob, 3, 4096).read)

    def test_empty_update_is_a_caller_error(self):
        blob = seal(KEK, os.urandom(CS + 1))
        dec = codec.StreamDecryptor(KEK, blob[:HEADER_LEN])
        with self.assertRaises(ValueError):
            dec.update(b"")
        for s in segments(blob):
            dec.update(s)
        dec.finalize()
        with self.assertRaises(ValueError):
            dec.update(b"")


class TestTamper(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pt = os.urandom(3 * CS + 1000)                  # 4 chunks: 3 full + final
        cls.blob = seal(KEK, cls.pt)
        cls.other = seal(KEK, os.urandom(3 * CS + 1000))    # same KEK, same shape
        cls.hdr = cls.blob[:HEADER_LEN]
        cls.segs = segments(cls.blob)

    def assertRejects(self, blob, exc=CodecIntegrityError, msg=None):
        with self.assertRaises(exc) as cm:
            open_(KEK, blob)
        if msg:
            self.assertIn(msg, str(cm.exception))
        return cm.exception

    # chunk bytes
    def test_ciphertext_bit(self):
        self.assertRejects(flip(self.blob, HEADER_LEN + SEGMENT_LEN + 5), msg="chunk 1")

    def test_tag_byte(self):
        self.assertRejects(flip(self.blob, HEADER_LEN + 3 * SEGMENT_LEN - 1), msg="chunk 2")

    def test_final_chunk_tag(self):
        self.assertRejects(flip(self.blob, len(self.blob) - 1), msg="chunk 3")

    # header, immutable region
    def test_header_magic(self):
        bad = flip(self.blob, 0)
        self.assertFalse(codec.is_streaming_format(bad))
        with self.assertRaises(CodecFormatError):
            codec.StreamDecryptor(KEK, bad[:HEADER_LEN])

    def test_header_version(self):
        for v in (0x00, 0x01, 0x03, 0xFF):
            with self.subTest(version=v):
                bad = self.blob[:7] + bytes([v]) + self.blob[8:]
                self.assertTrue(codec.is_streaming_format(bad))
                self.assertRejects(bad, CodecFormatError, f"unsupported format version {v}")
                self.assertRejects(bad[:20], CodecFormatError, "unsupported format version")

    def test_header_chunk_size(self):
        bad = self.blob[:8] + struct.pack(">I", 65536) + self.blob[12:]
        self.assertRejects(bad, CodecFormatError, "unsupported chunk size")

    def test_header_prefix(self):
        self.assertRejects(flip(self.blob, 15), msg="chunk 0")

    def test_header_reserved(self):
        for pos in range(19, 32):
            with self.subTest(pos=pos):
                self.assertRejects(flip(self.blob, pos), CodecFormatError, "reserved")

    def test_aad_binds_every_immutable_byte(self):
        # Independent of decode_header's pre-checks: each of bytes 0..32 is in the tag.
        h = codec.decode_header(self.hdr)
        dek = _unwrap_dek(KEK, h.wrapped_dek)
        for pos in range(AAD_LEN):
            with self.subTest(pos=pos), self.assertRaises(CodecIntegrityError):
                _decrypt_chunk(dek, h.nonce_prefix, 0, False, flip(h.aad, pos), self.segs[0])

    def test_immutable_header_from_other_file(self):
        self.assertRejects(self.other[:AAD_LEN] + self.blob[AAD_LEN:], msg="chunk 0")

    # header, key slot
    def test_slot_type(self):
        for t in (0x00, 0x02, 0x81, 0xFF):
            with self.subTest(slot_type=t):
                bad = self.blob[:32] + bytes([t]) + self.blob[33:]
                self.assertRejects(bad, CodecFormatError, f"unsupported key slot type {t}")

    def test_wrapped_dek_swapped_from_other_file(self):
        bad = self.blob[:40] + self.other[40:80] + self.blob[80:]
        codec.StreamDecryptor(KEK, bad[:HEADER_LEN])               # unwraps: a valid key, wrong file
        self.assertRejects(bad, msg="chunk 0")

    def test_key_slot_swapped_from_other_file(self):
        bad = self.blob[:KEY_SLOT_OFFSET] + self.other[KEY_SLOT_OFFSET:HEADER_LEN] + self.blob[80:]
        self.assertRejects(bad, msg="chunk 0")

    def test_wrapped_dek_bit(self):
        e = self.assertRejects(flip(self.blob, 60), CodecUnwrapError, "key slot is corrupt")
        self.assertIs(e.kek_id_matches, True)

    def test_kek_id_altered_still_decrypts(self):
        # Advisory by design (§2.4): outside the AAD so rotation can rewrite it; the KW
        # integrity check, not the id, decides whether a KEK fits.
        bad = flip(self.blob, KEY_SLOT_OFFSET + 3)
        dec = codec.StreamDecryptor(KEK, bad[:HEADER_LEN])
        self.assertIs(dec.kek_id_matches, False)                     # F-10: stage 3 audits this
        self.assertEqual(open_(KEK, bad), self.pt)

    def test_kek_id_matches_on_a_clean_file(self):
        self.assertIs(codec.StreamDecryptor(KEK, self.hdr).kek_id_matches, True)

    def test_kek_id_compare_is_constant_time(self):
        with mock.patch.object(codec.hmac, "compare_digest", wraps=hmac.compare_digest) as spy:
            codec.StreamDecryptor(KEK, self.hdr)
        spy.assert_called()

    # chunk order / count
    def test_chunk_reorder(self):
        s = self.segs
        self.assertRejects(join(self.hdr, [s[1], s[0], s[2], s[3]]), msg="chunk 0")

    def test_chunk_duplicated(self):
        s = self.segs
        self.assertRejects(join(self.hdr, [s[0], s[0], s[1], s[2], s[3]]), msg="chunk 1")

    def test_chunk_removed_from_middle(self):
        s = self.segs
        self.assertRejects(join(self.hdr, [s[0], s[2], s[3]]), msg="chunk 1")

    def test_chunk_spliced_from_other_file(self):
        s = list(self.segs)
        s[1] = segments(self.other)[1]
        self.assertRejects(join(self.hdr, s), msg="chunk 1")

    def test_final_chunk_dropped_truncate_at_boundary(self):
        self.assertRejects(join(self.hdr, self.segs[:-1]), msg="no final chunk after 3 chunks")
        self.assertRejects(join(self.hdr, self.segs[:1]), msg="no final chunk after 1 chunks")

    def test_empty_final_chunk_dropped(self):
        blob = seal(KEK, os.urandom(2 * CS))
        self.assertRejects(blob[:-TAG_LEN], msg="no final chunk after 2 chunks")

    def test_header_only(self):
        self.assertRejects(self.hdr, msg="no final chunk after 0 chunks")

    def test_non_final_chunk_presented_as_final(self):
        # Cut inside the last full chunk so its remainder looks like a final chunk.
        self.assertRejects(self.blob[:HEADER_LEN + 3 * SEGMENT_LEN - 1], msg="chunk 2")

    def test_cut_leaving_exactly_one_tag_of_a_non_final_chunk(self):
        self.assertRejects(self.blob[:HEADER_LEN + SEGMENT_LEN + TAG_LEN], msg="chunk 1")

    def test_data_appended_after_final(self):
        for extra in (1, 16, SEGMENT_LEN, SEGMENT_LEN + 17):
            with self.subTest(extra=extra):
                self.assertRejects(self.blob + os.urandom(extra))

    def test_update_after_final_is_rejected(self):
        dec = codec.StreamDecryptor(KEK, self.hdr)
        for s in self.segs:
            dec.update(s)
        dec.finalize()
        with self.assertRaises(CodecIntegrityError) as cm:
            dec.update(self.segs[-1])
        self.assertIn("data after the final chunk", str(cm.exception))

    def test_truncate_mid_chunk(self):
        self.assertRejects(self.blob[:HEADER_LEN + SEGMENT_LEN + 500], msg="chunk 1")
        self.assertRejects(self.blob[:HEADER_LEN + SEGMENT_LEN + 5], msg="truncated (5 bytes)")

    def test_truncate_mid_header(self):
        for n in (7, 8, 31, 32, 33, 50, 79):
            with self.subTest(n=n):
                self.assertRejects(self.blob[:n], msg="truncated header")
        self.assertFalse(codec.is_streaming_format(self.blob[:6]))  # too short to carry the magic

    def test_all_errors_are_codec_errors(self):
        for bad in (flip(self.blob, 100), flip(self.blob, 60), self.blob[:50],
                    self.blob[:7] + b"\x03" + self.blob[8:], self.blob[:32] + b"\x02" + self.blob[33:]):
            with self.assertRaises(CodecError):
                open_(KEK, bad)


class TestKeys(unittest.TestCase):
    def setUp(self):
        self.pt = os.urandom(CS + 4321)
        self.blob = seal(KEK, self.pt)

    def test_wrong_kek(self):
        with self.assertRaises(CodecUnwrapError) as cm:
            open_(KEK2, self.blob)
        e = cm.exception
        self.assertIn("wrong KEK or corrupt header", str(e))
        self.assertIn(codec.kek_id(KEK).hex(), str(e))
        self.assertIn(codec.kek_id(KEK2).hex(), str(e))
        self.assertIs(e.kek_id_matches, False)
        self.assertNotIsInstance(e, InvalidUnwrap)
        self.assertIsNone(e.__cause__)
        self.assertTrue(e.__suppress_context__)

    def test_unwrap_wraps_library_error(self):
        with self.assertRaises(CodecUnwrapError):
            _unwrap_dek(KEK2, self.blob[40:80])

    def test_raw_kek_never_wraps(self):
        # F-8: the slot is wrapped under K_wrap = HKDF(KEK), not under the KEK itself.
        wrapped = self.blob[40:80]
        with self.assertRaises(InvalidUnwrap):
            aes_key_unwrap(KEK, wrapped)
        self.assertNotEqual(_wrap_key(KEK), KEK)
        self.assertEqual(_wrap_key(KEK), hkdf_sha256(KEK, b"FENRGCM/v2/key-wrap", 32))
        self.assertEqual(codec.kek_id(KEK), hkdf_sha256(KEK, b"FENRGCM/v2/kek-id", 7))
        self.assertNotEqual(codec.kek_id(KEK), _wrap_key(KEK)[:7])     # separate labels

    def test_bad_key_lengths(self):
        for bad in (b"", bytes(16), bytes(31), bytes(33)):
            with self.subTest(n=len(bad)), self.assertRaises(ValueError):
                codec.StreamEncryptor(bad)
            with self.assertRaises(ValueError):
                codec.StreamDecryptor(bad, self.blob[:HEADER_LEN])

    def test_rfc3394_vector_4_6(self):
        kek = bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
        key = bytes.fromhex("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
        self.assertEqual(aes_key_wrap(kek, key).hex().upper(),
                         "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326"
                         "CBC7F0E71A99F43BFB988B9B7A02DD21")

    def test_rfc5869_vectors(self):
        ikm = bytes([0x0B]) * 22
        a1 = ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
              "34007208d5b887185865")                                        # A.1
        a3 = ("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
              "9d201395faa4b61a96c8")                                        # A.3: empty salt
        self.assertEqual(hkdf_sha256(ikm, bytes(range(0xF0, 0xFA)), 42, bytes(range(13))).hex(), a1)
        self.assertEqual(hkdf_sha256(ikm, b"", 42).hex(), a3)
        self.assertEqual(codec._hkdf(bytes(32), b"", 42), hkdf_sha256(bytes(32), b"", 42))

    def test_rotation_rewrap_roundtrip(self):
        old_hdr = self.blob[:HEADER_LEN]
        new_hdr = codec.rewrap_header(old_hdr, KEK, KEK2)
        self.assertEqual(len(new_hdr), HEADER_LEN)
        self.assertEqual(new_hdr[:AAD_LEN], old_hdr[:AAD_LEN])          # immutable region kept
        self.assertEqual(new_hdr[32], codec.SLOT_TYPE_AES_KW)
        self.assertEqual(new_hdr[33:40], codec.kek_id(KEK2))
        rotated = new_hdr + self.blob[HEADER_LEN:]                     # chunks untouched
        diff = [i for i in range(HEADER_LEN) if rotated[i] != self.blob[i]]
        self.assertTrue(diff and all(KEY_SLOT_OFFSET <= i < HEADER_LEN for i in diff))
        self.assertEqual(open_(KEK2, rotated), self.pt)
        with self.assertRaises(CodecUnwrapError):
            open_(KEK, rotated)
        # Rotating back restores the original header byte for byte (KW is deterministic).
        self.assertEqual(codec.rewrap_header(new_hdr, KEK2, KEK), old_hdr)

    def test_rotation_with_wrong_old_kek(self):
        with self.assertRaises(CodecUnwrapError) as cm:
            codec.rewrap_header(self.blob[:HEADER_LEN], KEK2, KEK)
        self.assertIs(cm.exception.kek_id_matches, False)

    def test_rotation_rejects_bad_header(self):
        for pos in (20, 32):                                           # reserved byte, slot type
            with self.subTest(pos=pos), self.assertRaises(CodecFormatError):
                codec.rewrap_header(flip(self.blob[:HEADER_LEN], pos), KEK, KEK2)

    def test_torn_slot_write(self):
        # A torn in-place rewrite (new bytes before `cut`, old bytes after). While the
        # wrapped DEK is still all old, only the advisory kek_id differs and the old KEK opens
        # it; once the wrapped DEK is mixed, neither KEK does. The §6.4 journal repairs both.
        old = self.blob[:HEADER_LEN]
        new = codec.rewrap_header(old, KEK, KEK2)
        for cut in range(KEY_SLOT_OFFSET + 1, HEADER_LEN):
            torn = new[:cut] + old[cut:]
            with self.subTest(cut=cut):
                if cut <= 40:
                    self.assertIs(codec.StreamDecryptor(KEK, torn).kek_id_matches, torn == old)
                else:
                    for k in (KEK, KEK2):
                        with self.assertRaises(CodecUnwrapError):
                            codec.StreamDecryptor(k, torn)


class TestNonces(unittest.TestCase):
    PREFIX = bytes.fromhex("a0a1a2a3a4a5a6")

    def test_layout(self):
        self.assertEqual(codec.chunk_nonce(self.PREFIX, 0x01020304, True),
                         self.PREFIX + b"\x01\x02\x03\x04\x01")
        self.assertEqual(codec.chunk_nonce(self.PREFIX, 0, False), self.PREFIX + bytes(5))
        self.assertEqual(len(codec.chunk_nonce(self.PREFIX, MAX_CHUNKS - 1, True)), 12)

    def test_unique_over_many_chunks(self):
        n = 200_000
        seen = {codec.chunk_nonce(self.PREFIX, i, False) for i in range(n)}
        seen |= {codec.chunk_nonce(self.PREFIX, i, True) for i in range(n)}
        self.assertEqual(len(seen), 2 * n)                             # (index, final) is injective
        hi = {codec.chunk_nonce(self.PREFIX, MAX_CHUNKS - 1 - i, f) for i in range(1000)
              for f in (False, True)}
        self.assertEqual(len(hi | seen), 2 * n + 2000)

    def test_index_bounds(self):
        for bad in (-1, MAX_CHUNKS):
            with self.subTest(index=bad), self.assertRaises(ValueError):
                codec.chunk_nonce(self.PREFIX, bad, True)
        aad = bytes(AAD_LEN)
        with self.assertRaises(ValueError):                            # no index left for final
            _encrypt_chunk(bytes(32), self.PREFIX, MAX_CHUNKS - 1, False, aad, bytes(CS))
        _encrypt_chunk(bytes(32), self.PREFIX, MAX_CHUNKS - 1, True, aad, b"")

    def test_decryptor_index_overflow(self):
        blob = seal(KEK, os.urandom(CS))
        dec = codec.StreamDecryptor(KEK, blob[:HEADER_LEN])
        dec._index = MAX_CHUNKS - 1
        with self.assertRaises(CodecIntegrityError) as cm:
            dec.update(segments(blob)[0])
        self.assertIn("overflow", str(cm.exception))

    def test_fresh_key_and_prefix_per_file(self):
        hdrs = [codec.StreamEncryptor(KEK).header for _ in range(2000)]
        self.assertEqual(len({h[12:19] for h in hdrs}), 2000)          # nonce prefixes
        self.assertEqual(len({h[40:80] for h in hdrs}), 2000)          # wrapped data keys
        self.assertEqual({h[33:40] for h in hdrs}, {codec.kek_id(KEK)})

    def test_randomness_wiring(self):
        # F-7: the DEK is the first os.urandom draw (32 bytes), the prefix the second (7),
        # used verbatim, and nothing else is drawn.
        stream = bytes(range(1, 40))
        calls = []

        def fake_urandom(n):
            start = sum(calls)
            calls.append(n)
            return stream[start:start + n]

        with mock.patch.object(codec.os, "urandom", fake_urandom):
            enc = codec.StreamEncryptor(KEK)
        self.assertEqual(calls, [32, 7])
        self.assertEqual(_unwrap_dek(KEK, enc.header[40:80]), stream[:32])
        self.assertEqual(enc.header[12:19], stream[32:39])
        final = enc.finalize(b"abc")
        self.assertEqual(AESGCM(stream[:32]).decrypt(stream[32:39] + bytes(4) + b"\x01", final,
                                                     enc.header[:32]), b"abc")

    def test_encryptor_misuse(self):
        enc = codec.StreamEncryptor(KEK)
        for bad in (b"", bytes(CS - 1), bytes(CS + 1)):
            with self.assertRaises(ValueError):
                enc.update(bad)
        with self.assertRaises(ValueError):
            enc.finalize(bytes(CS))                                    # a full block is never final
        enc.finalize(b"x")
        for call in (lambda: enc.update(bytes(CS)), lambda: enc.finalize(b"")):
            with self.assertRaises(ValueError):
                call()

    def test_aad_must_be_immutable_region_only(self):
        with self.assertRaises(ValueError):                            # the full header is refused
            _encrypt_chunk(bytes(32), self.PREFIX, 0, True, bytes(HEADER_LEN), b"")

    def test_sealing_helpers_are_private(self):
        # F-6: only StreamEncryptor seals; callers cannot choose a DEK or a prefix.
        for name in ("encrypt_chunk", "decrypt_chunk", "wrap_dek", "unwrap_dek", "encode_header"):
            self.assertFalse(hasattr(codec, name), name)


class TestKnownAnswer(unittest.TestCase):
    """Pins the byte format. If one of these fails, the on-disk format changed."""
    DEK    = bytes(range(32, 64))
    PREFIX = bytes.fromhex("a0a1a2a3a4a5a6")
    PT     = bytes(i % 251 for i in range(CS + 5))
    PT2    = bytes(i % 251 for i in range(2 * CS))

    # Cross-checked 2026-10-04 against an independent Go build (stdlib AES-GCM, crypto/hkdf,
    # hand-written RFC 3394): /tmp/claude-1000/irw-scratch/g1review/kat/main.go.
    K_WRAP = "211d0bdf362e441712325ff5f3f397f91330d3797a6664c0adb5554a4c282df2"
    KEK_ID = "7e241ffc5344db"
    HEADER = ("46454e5247434d02" "00100000" "a0a1a2a3a4a5a6" "00000000000000000000000000"
              "01" "7e241ffc5344db"
              "5eac31166e3b247aacae542c9c03acc21763505f2071f03cc43a485c3e304117b44d5db8308a63fa")
    EMPTY_CONTAINER = HEADER + "f04c3589b42ec16b9d381130928eb5f9"
    PT_CONTAINER_SHA256 = "0211007817a85fec86d6972379423d2e93681a7189e3398cab000f8621b53227"
    EXACT_MULTIPLE_LEN = 80 + 2 * CS + 3 * 16
    EXACT_MULTIPLE_SHA256 = "6270e04c4c456b1b125bd4ade861c858b7056d6f097daf4ad6b00aed9bac39d6"
    EXACT_MULTIPLE_FINAL = "d5333739c90c3c0a6e7c1d42fe4822be"

    def build(self, pt: bytes) -> bytes:
        hdr = _encode_header(self.PREFIX, codec.kek_id(KEK), _wrap_dek(KEK, self.DEK))
        aad = codec.chunk_aad(hdr)
        n_full = len(pt) // CS
        segs = [_encrypt_chunk(self.DEK, self.PREFIX, i, i == n_full, aad,
                               pt[i * CS:(i + 1) * CS]) for i in range(n_full + 1)]
        return hdr + b"".join(segs)

    def test_constants(self):
        self.assertEqual((codec.MAGIC, codec.VERSION, CS, TAG_LEN, codec.PREFIX_LEN, AAD_LEN,
                          KEY_SLOT_OFFSET, codec.KEY_SLOT_LEN, codec.KEK_ID_LEN, HEADER_LEN,
                          MAX_CHUNKS, codec.SLOT_TYPE_AES_KW, codec.HKDF_INFO_KEY_WRAP,
                          codec.HKDF_INFO_KEK_ID),
                         (b"FENRGCM", 2, 1048576, 16, 7, 32, 32, 48, 7, 80, 2 ** 32, 1,
                          b"FENRGCM/v2/key-wrap", b"FENRGCM/v2/kek-id"))

    def test_derived_keys(self):
        self.assertEqual(_wrap_key(KEK).hex(), self.K_WRAP)
        self.assertEqual(codec.kek_id(KEK).hex(), self.KEK_ID)

    def test_empty_container(self):
        blob = self.build(b"")
        self.assertEqual(blob, spec_container(KEK, self.DEK, self.PREFIX, b""))
        self.assertEqual(blob[:HEADER_LEN].hex(), self.HEADER)
        self.assertEqual(blob.hex(), self.EMPTY_CONTAINER)
        self.assertEqual(open_(KEK, blob), b"")

    def test_two_chunk_container(self):
        blob = self.build(self.PT)
        self.assertEqual(blob, spec_container(KEK, self.DEK, self.PREFIX, self.PT))
        self.assertEqual(len(blob), codec.container_size(len(self.PT)))
        self.assertEqual(hashlib.sha256(blob).hexdigest(), self.PT_CONTAINER_SHA256)
        self.assertEqual(open_(KEK, blob), self.PT)

    def test_exact_multiple_container(self):
        blob = self.build(self.PT2)
        self.assertEqual(blob, spec_container(KEK, self.DEK, self.PREFIX, self.PT2))
        self.assertEqual(len(blob), self.EXACT_MULTIPLE_LEN)
        self.assertEqual(blob[-TAG_LEN:].hex(), self.EXACT_MULTIPLE_FINAL)
        self.assertEqual(hashlib.sha256(blob).hexdigest(), self.EXACT_MULTIPLE_SHA256)
        self.assertEqual(open_(KEK, blob), self.PT2)


class TestLegacyDetection(unittest.TestCase):
    def test_v0_ciphertext_is_not_streaming(self):
        # crypto.encrypt_file_bytes = AESGCM(KEK).encrypt(os.urandom(12), plaintext, None):
        # no header, uniformly random leading bytes.
        aes = AESGCM(KEK)
        for n in (0, 1, 7, 100, 4096):
            for _ in range(200):
                ct = aes.encrypt(os.urandom(12), os.urandom(n), None)
                self.assertFalse(codec.is_streaming_format(ct))

    def test_v0_plaintext_starting_with_magic_still_detected_as_v0(self):
        ct = AESGCM(KEK).encrypt(os.urandom(12), b"FENRGCM\x02" + bytes(100), None)
        self.assertFalse(codec.is_streaming_format(ct))

    def test_v2_is_streaming(self):
        self.assertTrue(codec.is_streaming_format(seal(KEK, b"abc")))


if __name__ == "__main__":
    unittest.main()
