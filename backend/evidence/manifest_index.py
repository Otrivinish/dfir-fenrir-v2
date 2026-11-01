"""S6 (EG-4, HLD §3.5): the per-file manifest of a container exhibit, built from the stored bytes. Pure: no DB, no
event loop; everything here blocks and runs in a worker thread (evidence/manifest.py drives it).

- ZIP: `zipfile` over the seekable view of the stored file (evidence/seekable.py). The central directory is counted
  first, without keeping it (caps below), so a hostile one never reaches zipfile's in-memory list.
- TAR (plain, .tar.gz / .tgz, .tar.bz2, .tar.xz): `tarfile` in stream mode ('r|*') over iter_decrypted, one forward
  pass, its headers bounded (_TarStream); then the rest of the stream is drained so the whole file is authenticated
  (F-12).
- Every member's bytes are hashed (MD5, SHA-1, SHA-256) as they are decompressed; nothing is extracted to disk.
  Encrypted ZIP members get no hashes. A member that can't be decompressed (unsupported method, CRC error,
  overlapping entries) is listed with a note and no hashes; a container that can't be parsed fails the build.
- Caps (settings.evidence_manifest_*): entries, total uncompressed bytes (the bomb guard: counted as bytes are
  decompressed, never trusted from the headers), path length. Hitting one fails the build: IndexFailed(reason).
- Tool listings found in a ZIP (evidence/tool_listings.py) fill source_path, the source times and tool_hash.

The manifest = canonical JSONL: canonical_line() of each entry in seq order. manifest_sha256 = its SHA-256.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import lzma
import platform
import stat
import struct
import tarfile
import zipfile
import zlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterator, Optional

from core.csv_safe import csv_safe
from evidence import tool_listings

BUILDER_NAME = "fenrir-manifest"
BUILDER_VERSION = "1"

# One canonical line per entry: these keys, always present (null included), sorted, compact, UTF-8.
ENTRY_FIELDS = ("seq", "entry_path", "entry_name_encoding", "entry_path_raw_b64", "source_path", "entry_type",
                "size", "compressed_size", "times", "md5", "sha1", "sha256", "tool_hash", "tool_hash_match",
                "encrypted", "notes")
ENTRY_TYPES = ("file", "dir", "symlink", "hardlink", "stream", "other")
NAME_ENCODINGS = ("utf8", "cp437", "other")
CONTAINER_FORMATS = ("zip", "tar", "ad1", "l01", "aff4l", "other")
INDEXED_FORMATS = ("zip", "tar")

_READ = 1024 * 1024
_CD_MAX_BYTES = 512 * 1024 * 1024     # zipfile reads the whole central directory into memory: bound it
_TAR_HEADERS_MAX = 4 * 1024 * 1024    # tarfile reads pax / GNU long-name / sparse headers whole into memory: bound them
_TAR_GLOBAL_MAX = 64 * 1024           # global pax headers: kept to the end, and copied into every extended header
_NOTE_MAX = 500


def canonical_line(entry: dict) -> bytes:
    """One manifest line: the entry's ENTRY_FIELDS (null kept), sorted keys, compact separators, non-ASCII as is."""
    return json.dumps({k: entry.get(k) for k in ENTRY_FIELDS}, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"


def manifest_sha256(entries) -> str:
    """SHA-256 of the canonical JSONL of `entries` (already in seq order)."""
    h = hashlib.sha256()
    for e in entries:
        h.update(canonical_line(e))
    return h.hexdigest()


# The CSV form (GET …/manifest?format=csv, the disclosure package): one row per entry, every cell through csv_safe;
# times as compact JSON. Hash the JSONL, never the CSV.
CSV_HEADER = ["seq", "entry_path", "entry_name_encoding", "entry_path_raw_b64", "source_path", "entry_type", "size",
              "compressed_size", "md5", "sha1", "sha256", "tool_hash_algorithm", "tool_hash_value", "tool_hash_match",
              "encrypted", "notes", "times"]


def csv_bytes(entries, *, header: bool) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    if header:
        w.writerow(CSV_HEADER)
    for e in entries:
        th = e.get("tool_hash") or {}
        cells = [e["seq"], e["entry_path"], e["entry_name_encoding"], e["entry_path_raw_b64"], e["source_path"],
                 e["entry_type"], e["size"], e["compressed_size"], e["md5"], e["sha1"], e["sha256"],
                 th.get("algorithm"), th.get("value"), e["tool_hash_match"], e["encrypted"], e["notes"],
                 json.dumps(e["times"], sort_keys=True, ensure_ascii=False, separators=(",", ":"))
                 if e["times"] is not None else None]
        w.writerow(["" if v is None else csv_safe(v) for v in cells])
    return (b"\xef\xbb\xbf" if header else b"") + buf.getvalue().encode("utf-8")


class IndexFailed(Exception):
    """The container could not be indexed (a cap, or it is not a ZIP / TAR FENRIR can read). `reason` is a code."""

    def __init__(self, reason: str, detail: str):
        super().__init__(f"{reason}: {detail}")
        self.reason, self.detail = reason, detail


@dataclass(frozen=True)
class Caps:
    max_entries: int
    max_uncompressed_bytes: int
    max_path_chars: int


class _Budget:
    """The bomb guard: every decompressed byte FENRIR reads (members and listings) counts."""

    def __init__(self, cap: int):
        self.cap, self.used = cap, 0

    def take(self, n: int) -> None:
        self.used += n
        if self.used > self.cap:
            raise IndexFailed("uncompressed_cap", f"more than {self.cap} bytes decompressed: stopped hashing")


def _hash_stream(f, budget: _Budget) -> tuple[str, str, str]:
    hs = (hashlib.md5(), hashlib.sha1(), hashlib.sha256())
    while block := f.read(_READ):
        budget.take(len(block))
        for h in hs:
            h.update(block)
    return tuple(h.hexdigest() for h in hs)


def _clean(s: str) -> str:
    """Postgres text can't hold NUL: shown as U+FFFD (the raw bytes are kept in entry_path_raw_b64)."""
    return s.replace("\x00", "�")


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _epoch(value) -> Optional[str]:
    """UTC ISO of seconds since 1970 (an int, float or decimal string, e.g. a pax time), else None."""
    try:
        text = str(value).strip()
        sign = -1 if text.startswith("-") else 1
        whole, _, frac = text.lstrip("+-").partition(".")
        if not whole.isdigit() or (frac and not frac.isdigit()):
            return None
        delta = timedelta(seconds=int(whole), microseconds=int((frac + "000000")[:6]))
        return _iso(datetime(1970, 1, 1, tzinfo=timezone.utc) + sign * delta)
    except (ValueError, OverflowError):
        return None


def _filetime(ft: int) -> Optional[str]:
    """UTC ISO of a Windows FILETIME (100 ns since 1601-01-01 UTC), cut to microseconds; None if out of range."""
    try:
        return _iso(datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft // 10))
    except OverflowError:
        return None


def _time(utc: Optional[str], as_recorded: str, basis: str) -> dict:
    return {"utc": utc, "as_recorded": as_recorded, "basis": basis}


def _note(*parts) -> Optional[str]:
    text = "; ".join(p for p in parts if p)
    return text[:_NOTE_MAX] if text else None


# ── ZIP ──────────────────────────────────────────────────────────────────────────────────────────────────────────

def _extras(extra: bytes) -> Iterator[tuple[int, bytes]]:
    while len(extra) >= 4:
        tag, size = struct.unpack("<HH", extra[:4])
        data = extra[4:4 + size]
        if len(data) < size:
            return
        yield tag, data
        extra = extra[4 + size:]


def _zip_times(zi: zipfile.ZipInfo, local_extra: bytes) -> dict:
    """m / a / b from the NTFS extra field (0x000a: FILETIMEs; its 'ctime' is the creation time), else the extended
    timestamp (0x5455: Unix seconds; the local header's copy can carry atime and creation time), else the DOS time,
    which is local time in an unknown timezone."""
    times: dict = {}
    for extra in (zi.extra, local_extra):
        for tag, data in _extras(extra):
            if tag == 0x000A and len(data) >= 4:
                rest = data[4:]
                while len(rest) >= 4:
                    atag, asize = struct.unpack("<HH", rest[:4])
                    if atag == 1 and asize >= 24 and len(rest) >= 28:
                        for slot, ft in zip(("m", "a", "b"), struct.unpack("<QQQ", rest[4:28])):
                            if ft and slot not in times:
                                times[slot] = _time(_filetime(ft), str(ft), "zip_ntfs_extra_filetime")
                    rest = rest[4 + asize:]
    for extra in (local_extra, zi.extra):
        for tag, data in _extras(extra):
            if tag == 0x5455 and data:
                flags, pos = data[0], 1
                for bit, slot in ((1, "m"), (2, "a"), (4, "b")):
                    if flags & bit and pos + 4 <= len(data):
                        (secs,) = struct.unpack("<i", data[pos:pos + 4])
                        pos += 4
                        if slot not in times:
                            times[slot] = _time(_epoch(secs), str(secs), "zip_extended_timestamp_unix")
    if "m" not in times:
        y, mo, d, h, mi, s = zi.date_time
        times["m"] = _time(None, f"{y:04d}-{mo:02d}-{d:02d} {h:02d}:{mi:02d}:{s:02d}",
                           "zip_dos_time_local_timezone_unknown")
    return times


def _zip_name(zi: zipfile.ZipInfo) -> tuple[str, str, bytes]:
    """(entry_path, encoding, raw header bytes): the UTF-8 flag, else cp437 (zipfile's reading), and the Info-ZIP
    Unicode Path extra field (0x7075) when its CRC matches the header name."""
    utf8 = bool(zi.flag_bits & 0x800)
    raw = zi.orig_filename.encode("utf-8" if utf8 else "cp437")
    name, enc = zi.orig_filename, "utf8" if utf8 else "cp437"
    if not utf8:
        for tag, data in _extras(zi.extra):
            if tag == 0x7075 and len(data) > 5 and data[0] == 1 and struct.unpack("<L", data[1:5])[0] == zlib.crc32(raw):
                try:
                    name, enc = data[5:].decode("utf-8"), "utf8"
                except UnicodeDecodeError:
                    pass                                   # not UTF-8 after all: keep the cp437 header name
    return _clean(name), enc, raw


def _zip_local_extra(view, zi: zipfile.ZipInfo) -> bytes:
    view.seek(zi.header_offset)
    head = view.read(30)
    if len(head) != 30 or head[:4] != b"PK\x03\x04":
        return b""
    n, m = struct.unpack("<HH", head[26:30])
    view.seek(n, 1)
    return view.read(m)


def _zip_precheck(view, caps: Caps) -> None:
    """Count the central directory's records (as zipfile will walk them) without keeping them."""
    try:
        endrec = zipfile._EndRecData(view)
    except OSError:
        endrec = None
    if not endrec:
        raise IndexFailed("not_a_zip", "no end-of-central-directory record")
    size_cd, offset_cd = endrec[zipfile._ECD_SIZE], endrec[zipfile._ECD_OFFSET]
    if endrec[zipfile._ECD_ENTRIES_TOTAL] > caps.max_entries:
        raise IndexFailed("too_many_entries", f"the ZIP declares {endrec[zipfile._ECD_ENTRIES_TOTAL]} entries "
                                              f"(cap {caps.max_entries})")
    if size_cd > _CD_MAX_BYTES:
        raise IndexFailed("central_directory_too_large", f"{size_cd} bytes (cap {_CD_MAX_BYTES})")
    start = endrec[zipfile._ECD_LOCATION] - size_cd
    if start < 0:
        raise IndexFailed("not_a_zip", "bad central directory offset")
    view.seek(start)
    count = total = 0
    while total < size_cd:
        rec = view.read(zipfile.sizeCentralDir)
        if len(rec) != zipfile.sizeCentralDir or rec[:4] != zipfile.stringCentralDir:
            return                                        # zipfile reports the corruption itself
        n, m, k = struct.unpack("<HHH", rec[28:34])
        count += 1
        if count > caps.max_entries:
            raise IndexFailed("too_many_entries", f"more than {caps.max_entries} entries in the central directory")
        if n > 4 * caps.max_path_chars:
            raise IndexFailed("path_too_long", f"entry {count}: a {n}-byte name (cap {caps.max_path_chars} characters)")
        view.seek(n + m + k, 1)
        total += zipfile.sizeCentralDir + n + m + k


def _zip_entries(view, caps: Caps, budget: _Budget, listing: list) -> Iterator[dict]:
    _zip_precheck(view, caps)
    try:
        zf = zipfile.ZipFile(view)
    except (zipfile.BadZipFile, NotImplementedError, UnicodeDecodeError, ValueError, struct.error) as e:
        raise IndexFailed("not_a_zip", f"{type(e).__name__}: {e}") from None
    infos = zf.infolist()
    declared = sum(zi.file_size for zi in infos)
    if declared > caps.max_uncompressed_bytes:
        raise IndexFailed("uncompressed_cap", f"the members declare {declared} bytes (cap {caps.max_uncompressed_bytes})")
    names = []
    for zi in infos:
        name = _zip_name(zi)
        if len(name[0]) > caps.max_path_chars:
            raise IndexFailed("path_too_long", f"{name[0][:80]}…: {len(name[0])} characters (cap {caps.max_path_chars})")
        names.append(name)

    def open_member(seq: int):
        """A listing member, streamed (zipfile never yields more than its declared size, which is counted here)."""
        budget.take(infos[seq - 1].file_size)
        return zf.open(infos[seq - 1])

    merged = tool_listings.merge_zip([n[0] for n in names], [bool(zi.flag_bits & 0x1) for zi in infos], open_member,
                                     caps, listing)
    for seq, (zi, (path, enc, raw)) in enumerate(zip(infos, names), 1):
        mode = zi.external_attr >> 16
        etype = ("dir" if zi.is_dir() else "symlink" if zi.create_system == 3 and stat.S_ISLNK(mode) else "file")
        encrypted = bool(zi.flag_bits & 0x1)
        md5 = sha1 = sha256 = None
        note = None
        if etype != "dir" and encrypted:
            note = "encrypted member: not hashed"
        elif etype != "dir":
            try:
                with zf.open(zi) as f:
                    md5, sha1, sha256 = _hash_stream(f, budget)
            except NotImplementedError as e:
                note = f"not hashed: {e} (compression method {zi.compress_type})"
            except (zipfile.BadZipFile, zlib.error, lzma.LZMAError, EOFError, OSError) as e:
                note = f"not hashed: {type(e).__name__}: {e}"
        entry = {
            "seq": seq, "entry_path": path, "entry_name_encoding": enc,
            "entry_path_raw_b64": None if raw == path.encode("utf-8") else base64.b64encode(raw).decode(),
            "source_path": None, "entry_type": etype, "size": zi.file_size, "compressed_size": zi.compress_size,
            "times": _zip_times(zi, _zip_local_extra(view, zi)), "md5": md5, "sha1": sha1, "sha256": sha256,
            "tool_hash": None, "tool_hash_match": None, "encrypted": encrypted, "notes": _note(note),
        }
        tool_listings.apply(entry, merged.get(seq))
        yield entry


# ── TAR ──────────────────────────────────────────────────────────────────────────────────────────────────────────

class _IterReader:
    """read(n) over an iterator of byte blocks (iter_decrypted), for tarfile's stream mode."""

    def __init__(self, it):
        self._it, self._cur, self._off, self._eof = it, b"", 0, False

    def read(self, n: int = -1) -> bytes:
        out = bytearray()
        while n < 0 or len(out) < n:
            if self._off >= len(self._cur):
                if self._eof:
                    break
                nxt = next(self._it, None)
                if nxt is None:
                    self._eof = True
                    break
                self._cur, self._off = nxt, 0
                continue
            take = len(self._cur) - self._off if n < 0 else min(n - len(out), len(self._cur) - self._off)
            out += self._cur[self._off:self._off + take]
            self._off += take
        return bytes(out)

    def drain(self) -> None:
        while self.read(_READ):
            pass


class _TarStream:
    """tarfile's decompressed stream, bounded while tarfile reads headers. tarfile (CPython 3.12 _proc_pax,
    _proc_gnulong, _proc_sparse, _proc_gnusparse_10) reads a header whole into memory at the size the archive
    declares, so a few MiB of .tar.gz can declare gigabytes. Between members (tf.next()), a read or skip past
    _TAR_HEADERS_MAX fails the build before tarfile reads it; a member's data (data()) is counted by the budget."""

    def __init__(self, stream):
        self._s, self._left, self.global_bytes = stream, _TAR_HEADERS_MAX, 0

    def headers(self) -> None:
        self._left = _TAR_HEADERS_MAX

    def data(self) -> None:
        self._left = None

    def _spend(self, n: int) -> None:
        if self._left is not None:
            self._left -= n
            if self._left < 0:
                raise IndexFailed("tar_header_too_large",
                                  f"more than {_TAR_HEADERS_MAX} bytes of tar headers before one member")

    def read(self, n: int) -> bytes:
        self._spend(n)
        return self._s.read(n)

    def seek(self, pos: int) -> int:
        self._spend(pos - self._s.tell())
        return self._s.seek(pos)

    def tell(self) -> int:
        return self._s.tell()


class _TarInfo(tarfile.TarInfo):
    def _proc_member(self, tf):
        if self.type == tarfile.XGLTYPE:          # checked at the size it declares, before tarfile reads it
            tf.fileobj.global_bytes += self.size
            if tf.fileobj.global_bytes > _TAR_GLOBAL_MAX:
                raise IndexFailed("tar_header_too_large", f"more than {_TAR_GLOBAL_MAX} bytes of global pax headers")
        return super()._proc_member(tf)


def _tar_name(name: str) -> tuple[str, str, Optional[bytes]]:
    raw = name.encode("utf-8", "surrogateescape")
    try:
        text = raw.decode("utf-8")
        if "\x00" not in text:
            return text, "utf8", None
    except UnicodeDecodeError:
        pass                                               # not UTF-8: fall through to the replaced name + raw bytes
    return _clean(raw.decode("utf-8", "replace")), "other", raw


def _tar_times(ti: tarfile.TarInfo) -> dict:
    pax = ti.pax_headers or {}
    times = {"m": (_time(_epoch(pax["mtime"]), pax["mtime"], "tar_pax_mtime") if "mtime" in pax
                   else _time(_epoch(ti.mtime), str(ti.mtime), "tar_header_mtime"))}
    for key, slot, basis in (("atime", "a", "tar_pax_atime"), ("ctime", "c", "tar_pax_ctime"),
                             ("LIBARCHIVE.creationtime", "b", "tar_pax_libarchive_creationtime")):
        if key in pax:
            times[slot] = _time(_epoch(pax[key]), pax[key], basis)
    return times


def _tar_entries(reader: _IterReader, caps: Caps, budget: _Budget, listing: list) -> Iterator[dict]:
    try:                                          # = tarfile.open(fileobj=reader, mode="r|*"), with _TarStream between
        ts = _TarStream(tarfile._Stream(None, "r", "*", reader, tarfile.RECORDSIZE, 9))
        tf = tarfile.TarFile(None, "r", ts, tarinfo=_TarInfo)
    except (tarfile.TarError, zlib.error, lzma.LZMAError, EOFError, OSError) as e:
        raise IndexFailed("not_a_tar", f"{type(e).__name__}: {e}") from None
    seq = 0
    found: set[str] = set()
    while True:
        try:
            ti = tf.next()
        except (tarfile.TarError, zlib.error, lzma.LZMAError, EOFError, OSError) as e:
            raise IndexFailed("parse_error", f"after entry {seq}: {type(e).__name__}: {e}") from None
        if ti is None:
            break
        ts.data()
        tf.members.clear()                        # stream mode keeps every TarInfo otherwise: bounded memory
        seq += 1
        if seq > caps.max_entries:
            raise IndexFailed("too_many_entries", f"more than {caps.max_entries} entries")
        path, enc, raw = _tar_name(ti.name)
        if len(path) > caps.max_path_chars:
            raise IndexFailed("path_too_long", f"{path[:80]}…: {len(path)} characters (cap {caps.max_path_chars})")
        etype = ("file" if ti.isreg() else "dir" if ti.isdir() else "symlink" if ti.issym()
                 else "hardlink" if ti.islnk() else "other")
        md5 = sha1 = sha256 = None
        note = f"link target: {_tar_name(ti.linkname)[0]}" if etype in ("symlink", "hardlink") else None
        if etype == "other":
            note = {tarfile.CHRTYPE: "character device", tarfile.BLKTYPE: "block device",
                    tarfile.FIFOTYPE: "FIFO"}.get(ti.type, f"tar type {ti.type!r}")
        if etype == "file":
            try:
                md5, sha1, sha256 = _hash_stream(tf.extractfile(ti), budget)
            except (tarfile.TarError, zlib.error, lzma.LZMAError, EOFError, OSError) as e:
                raise IndexFailed("parse_error", f"entry {seq}: {type(e).__name__}: {e}") from None
        kind = tool_listings.listing_kind(path)
        if kind:
            found.add(kind)
        yield {
            "seq": seq, "entry_path": path, "entry_name_encoding": enc,
            "entry_path_raw_b64": base64.b64encode(raw).decode() if raw is not None else None,
            "source_path": None, "entry_type": etype, "size": ti.size, "compressed_size": None,
            "times": _tar_times(ti), "md5": md5, "sha1": sha1, "sha256": sha256,
            "tool_hash": None, "tool_hash_match": None, "encrypted": False, "notes": _note(note),
        }
        budget.take(tf.offset - ts.tell())        # the member's padding, or an unknown type's data: skipped, counted
        ts.seek(tf.offset)
        ts.headers()
    tf.close()
    reader.drain()                                # the rest of the file, so iter_decrypted authenticates its end
    for kind in sorted(found):
        listing.append(tool_listings.summary(kind, None, "not_merged",
                                             note="found in a TAR container: v1 merges tool listings from ZIP "
                                                  "containers only (a TAR is read in one forward pass)"))


# ── The build ────────────────────────────────────────────────────────────────────────────────────────────────────

class ManifestBuild:
    """entries(source) yields the manifest entries in seq order (source = the seekable view for zip, an iterator of
    decrypted blocks for tar) and hashes their canonical lines; when it is exhausted without raising, `count`,
    `manifest_sha256` and `listing` (what each tool listing found did) are final."""

    def __init__(self, fmt: str, caps: Caps):
        if fmt not in INDEXED_FORMATS:
            raise ValueError(f"{fmt} is not indexed by FENRIR")
        self.fmt, self.caps = fmt, caps
        self.count = 0
        self.listing: list[dict] = []
        self._sha = hashlib.sha256()
        self._budget = _Budget(caps.max_uncompressed_bytes)

    @property
    def builder(self) -> str:
        return (f"{BUILDER_NAME} {BUILDER_VERSION} ({self.fmt}: CPython {platform.python_version()} "
                f"{'zipfile' if self.fmt == 'zip' else 'tarfile'})")

    @property
    def manifest_sha256(self) -> str:
        return self._sha.hexdigest()

    def entries(self, source) -> Iterator[dict]:
        walk = (_zip_entries(source, self.caps, self._budget, self.listing) if self.fmt == "zip"
                else _tar_entries(_IterReader(source), self.caps, self._budget, self.listing))
        for entry in walk:
            self._sha.update(canonical_line(entry))
            self.count += 1
            yield entry
        tool_listings.finish(self.listing)
