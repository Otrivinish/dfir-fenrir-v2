"""LE-package builder.

Single entry point: `build_le_package`. Reads the source-of-truth tables for
an incident (plain READ COMMITTED queries in the caller's session; the builder
itself writes nothing to the DB), streams a ZIP that follows the LE-package
layout (see README in this module's `readme.py`) straight into the one entry of
an AES-256 password-protected outer ZIP (WinZip AE-2) under a fresh one-time
password.

G2 (R04): nothing is assembled in memory. The outer ZIP is written to a staging
file (evidence/streaming.StagedOutput, /evidence/.staging/*.partial), each
exhibit is decrypted chunk by chunk into its own entry, and the plaintext never
touches a disk. The route moves the staged bundle into place
(`BuildResult.staged.commit`) or discards it; a failed build discards it here.

Returns the staged bundle plus the metadata the route layer needs to persist
`CustodyExport` + `LePackage` rows and emit the audit anchor row. This module
does **not** write to the DB and does **not** commit.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import csv
import hashlib
import io
import itertools
import json
import secrets
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pyzipper
# Outer envelope is now an AES-256 password-protected ZIP (pyzipper, WinZip
# AE-2) rather than raw AES-256-GCM — see `bundle_password` / `_hmac_key`
# below. pyzipper is already imported at top of file for the inner evidence
# ZIP, so no new dependency.
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import verify_row_hash
from artifacts import store as artifact_store
from evidence.crypto import EvidenceCryptoError, EvidenceIntegrityError, iter_decrypted
from evidence.streaming import StagedOutput
from evidence.timestamping import timestamp_sha256
from le_package.manifest import Manifest, hmac_manifest
from le_package.readme import render_readme
from le_package.sop import CHAIN_OF_CUSTODY_SOP
from case_notes.hashing import LINK_FIELDS, content_sha256, created_at_text
from models import (Artifact, AuditLog, BrowserHistoryUpload, CaseNote, Comment, CustodyExport, DefenderPdfImport,
                    EmailAnalysis, Evidence, ForensicImport, IOC, Incident, IncidentStakeholder, LessonsLearned,
                    OOBLog, PCAPAnalysis, TimelineEvent, User, YaraMatch,
                    ClosureChecklistItem)


PLATFORM_VERSION = "v2.0.0"


def _iso_z(dt: datetime | None) -> str | None:
    """UTC ISO 8601 with a Z suffix; sub-second precision is kept where present (L5, CLAUDE.md:
    don't truncate). A naive value is UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _csv_bytes(header: list[str], rows: list[list[Any]]) -> bytes:
    """CSV with UTF-8 BOM (Excel-friendly) and CRLF line endings."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(header)
    for r in rows:
        w.writerow(["" if v is None else v for v in r])
    return buf.getvalue().encode("utf-8-sig")


def _json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, indent=2, default=str).encode("utf-8")


def _safe_filename(s: str, max_len: int = 60) -> str:
    out = []
    for ch in s:
        if ch.isalnum() or ch in "-_.":
            out.append(ch)
        elif ch.isspace():
            out.append("_")
    return ("".join(out) or "file")[:max_len].strip("._-") or "file"


# ── Blocking helpers (run via asyncio.to_thread, one call at a time per ZipFile) ──
# The backend runs one event loop: zipping, hashing and encrypting evidence-sized blobs inline
# froze every request for the whole build. Big blobs also go into a ZIP in slices, because
# zlib's output join and BytesIO.write copy a whole blob while holding the GIL, so a single
# writestr() of a 300 MB file stalls the loop even from a worker thread.

_ZIP_CHUNK = 8 * 1024 * 1024


def _zip_add_chunked(zf: zipfile.ZipFile, arcname: str, data) -> None:
    """`zf.writestr(arcname, data)`, written in 8 MiB slices: same entry metadata (time,
    compression, mode 0600, ZIP64 decided from the size up front)."""
    zinfo = getattr(zf, "zipinfo_cls", zipfile.ZipInfo)(arcname, date_time=time.localtime(time.time())[:6])
    zinfo.compress_type = zf.compression
    zinfo.external_attr = 0o600 << 16
    with memoryview(data) as view:
        zinfo.file_size = len(view)
        with zf.open(zinfo, "w") as dest:
            for i in range(0, len(view), _ZIP_CHUNK):
                dest.write(view[i:i + _ZIP_CHUNK])


def _add_file(zf: zipfile.ZipFile, manifest: Manifest, path: str, data: bytes, mime: str, source: str) -> dict:
    """Write one (large) file into the bundle and record it in the manifest (hashes it)."""
    _zip_add_chunked(zf, path, data)
    return manifest.add(path=path, data=data, mime=mime, source=source)


class IntegrityFailed:
    """R3-2: the first pass of _stream_evidence_file found the stored exhibit tampered or corrupt (an
    EvidenceIntegrityError, not a file that can't be read). `reason` = the crypto layer's check."""
    __slots__ = ("reason",)

    def __init__(self, reason: str | None):
        self.reason = reason or "integrity"


def _stream_evidence_file(zf: zipfile.ZipFile, manifest: Manifest, ev: Evidence, path: str, mime: str,
                          source: str) -> dict | IntegrityFailed | None:
    """Blocking (G2): decrypt an exhibit chunk by chunk into its own entry, hashing it on the way, and record
    it in the manifest. Two bounded-memory passes: the first decrypts the whole stored file and writes
    nothing, so a file that fails an integrity check (anywhere in it) returns IntegrityFailed (R3-2: the
    caller records integrity_failed:<reason> and the route freezes the exhibit) and one that is missing or
    can't be read returns None (recorded as absent) — one bad exhibit never blocks the package. The
    second pass writes the entry; a failure there means the file changed during the build, and it raises
    (F-12): the entry is half written, so the whole package is abandoned (build_le_package discards it)."""
    try:
        for _part in iter_decrypted(ev.storage_path, ev.nonce_hex, ev.file_size_bytes):
            pass
    except EvidenceIntegrityError as e:
        return IntegrityFailed(e.reason)
    except Exception:
        return None
    stream = iter_decrypted(ev.storage_path, ev.nonce_hex, ev.file_size_bytes)
    first = next(stream)
    sha256, sha512, size = hashlib.sha256(), hashlib.sha512(), 0
    zinfo = getattr(zf, "zipinfo_cls", zipfile.ZipInfo)(path, date_time=time.localtime(time.time())[:6])
    zinfo.compress_type = zf.compression
    zinfo.external_attr = 0o600 << 16
    zinfo.file_size = ev.file_size_bytes or len(first)      # sizes the ZIP64 decision
    with contextlib.closing(stream), zf.open(zinfo, "w") as dest:
        for part in itertools.chain((first,), stream):
            with memoryview(part) as view:
                for i in range(0, len(view), _ZIP_CHUNK):     # a v0 file arrives whole: write it in slices
                    piece = view[i:i + _ZIP_CHUNK]
                    sha256.update(piece)
                    sha512.update(piece)
                    dest.write(piece)
            size += len(part)
    return manifest.add_hashed(path=path, size=size, sha256=sha256.hexdigest(), sha512=sha512.hexdigest(),
                               mime=mime, source=source)


def _artifacts_zip(arts: list) -> tuple[bytes, dict[str, str]]:
    """The quarantined files in an `infected`-password AES ZIP (arcname = original name), each read through
    the quarantine's dual-format reader (H1: encrypted at rest, or a legacy plaintext row) in two bounded
    passes: the first authenticates the whole stored file and checks its SHA-256 against the row, the second
    writes it. A file that is missing, can't be read or fails a check is left out; its status — included,
    missing, unreadable:<reason>, integrity_failed:<reason> — goes in the inventory. A failure in the second
    pass (the file changed during the build) raises: the whole package is abandoned (F-12).
    Returns (ZIP bytes or b"" when nothing was included, {artifact id: status})."""
    statuses: dict[str, str] = {}
    inner = io.BytesIO()
    with pyzipper.AESZipFile(inner, "w",
                             compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as iz:
        iz.setpassword(b"infected")
        for a in arts:
            try:
                h = hashlib.sha256()
                for part in artifact_store.iter_plaintext(a):
                    h.update(part)
            except EvidenceIntegrityError as e:
                statuses[str(a.id)] = f"integrity_failed:{e.reason or 'integrity'}"
                continue
            except EvidenceCryptoError as e:
                statuses[str(a.id)] = "missing" if e.reason == "file_missing" else f"unreadable:{e.reason or 'error'}"
                continue
            if a.sha256_hash and h.hexdigest() != a.sha256_hash.lower():
                statuses[str(a.id)] = "integrity_failed:hash_mismatch"
                continue
            zinfo = getattr(iz, "zipinfo_cls", zipfile.ZipInfo)(a.original_filename or a.stored_filename,
                                                               date_time=time.localtime(time.time())[:6])
            zinfo.compress_type = iz.compression
            zinfo.external_attr = 0o600 << 16
            zinfo.file_size = a.file_size or 0
            with iz.open(zinfo, "w") as dest:
                for part in artifact_store.iter_plaintext(a):
                    dest.write(part)
            statuses[str(a.id)] = "included"
    return (inner.getvalue() if "included" in statuses.values() else b""), statuses


# ── The outer envelope (G2: streamed into a staging file) ──
# The outer entry is opened before its size is known. Force ZIP64 when the package could pass 4 GiB:
# the stored files (exhibits, quarantined artifacts) plus a 1 GiB allowance for the records.
_RECORDS_ALLOWANCE = 1024 ** 3


def _open_bundle(bundle_password: str, size_estimate: int) -> tuple[StagedOutput, Any, Any]:
    """Blocking: the staged outer AES-256 ZIP (WinZip AE-2) with its one entry, le_package.zip, open for
    streaming writes (same entry metadata as before). Returns (staged output, outer ZIP, entry)."""
    out = StagedOutput()
    try:
        oz = pyzipper.AESZipFile(out.file, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES)
        oz.setpassword(bundle_password.encode("utf-8"))
        zinfo = getattr(oz, "zipinfo_cls", zipfile.ZipInfo)("le_package.zip",
                                                             date_time=time.localtime(time.time())[:6])
        zinfo.compress_type = oz.compression
        zinfo.external_attr = 0o600 << 16
        zip64 = (size_estimate + _RECORDS_ALLOWANCE) * 1.05 > zipfile.ZIP64_LIMIT
        entry = oz.open(zinfo, "w", force_zip64=zip64)
    except BaseException:
        out.discard()
        raise
    return out, oz, entry


def _close_bundle(out: StagedOutput, oz, entry) -> tuple[int, str]:
    """Blocking: finish the entry and the outer ZIP, fsync, then hash the staged bundle by reading it back
    (the ZIP writer seeks back to rewrite the local header, so it can't be hashed on the way).
    Returns (size, SHA-256)."""
    entry.close()
    oz.close()
    size = out.finish()
    h = hashlib.sha256()
    with open(out.path, "rb") as f:
        while block := f.read(1024 * 1024):
            h.update(block)
    return size, h.hexdigest()


def _abandon_bundle(out: StagedOutput, oz, entry) -> None:
    """Blocking: a failed build — close what is open (best effort) and delete the staged file."""
    for close in (entry.close, oz.close):
        try:
            close()
        except Exception:
            pass
    out.discard()


async def estimate_package_bytes(db: AsyncSession, inc_id: uuid.UUID, *, legal_hold_only: bool,
                                 include_artifacts: bool, include_unsealed_drafts: bool = False) -> int:
    """The stored bytes a package of this incident would embed: its exhibits' plaintext (with the
    legal-hold filter; M11: sealed ones only unless drafts are included) and, when included, its
    quarantined artifacts. For the free-space check and the ZIP64 decision; the records (timeline,
    audit, ...) come on top."""
    q = select(func.coalesce(func.sum(Evidence.file_size_bytes), 0)).where(
        Evidence.incident_id == inc_id, Evidence.kind == "digital_file",
        Evidence.storage_path.isnot(None), Evidence.nonce_hex.isnot(None))
    if legal_hold_only:
        q = q.where(Evidence.legal_hold.is_(True))
    if not include_unsealed_drafts:
        q = q.where(Evidence.coc_sealed.is_(True))
    total = int((await db.execute(q)).scalar() or 0)
    if include_artifacts:
        total += int((await db.execute(select(func.coalesce(func.sum(Artifact.file_size), 0))
                                       .where(Artifact.incident_id == inc_id))).scalar() or 0)
    return total


# ── Section builders ───────────────────────────────────────────────────────


_FETCH_PARTITION = 1_000


async def _fetch_all(db: AsyncSession, stmt, *, scalars: bool = False) -> list:
    """Every row of `stmt`, read through a server-side cursor in partitions so the event loop runs
    between them: one execute().all() turns tens of thousands of rows into ORM objects in a single
    stall of over a second."""
    result = await db.stream(stmt.execution_options(yield_per=_FETCH_PARTITION))
    if scalars:
        result = result.scalars()
    rows: list = []
    async for part in result.partitions():
        rows.extend(part)
    return rows


async def _section_incident(db: AsyncSession, inc: Incident, manifest: Manifest, zf: zipfile.ZipFile) -> None:
    summary = {
        "id":            str(inc.id),
        "ref":           inc.ref,
        "title":         inc.title,
        "description":   inc.description,
        "severity":      inc.severity,
        "phase":         inc.phase,
        "tlp":           inc.tlp,
        "status":        inc.status,
        "triage_state":  inc.triage_state,
        "incident_type": inc.incident_type,
        "dark_operation": inc.dark_operation,
        "reporter":       inc.reporter,
        "occurred_at":    _iso_z(inc.occurred_at),
        "detected_at":    _iso_z(inc.detected_at),
        "contained_at":   _iso_z(inc.contained_at),
        "eradicated_at":  _iso_z(inc.eradicated_at),
        "recovered_at":   _iso_z(inc.recovered_at),
        "created_at":     _iso_z(inc.created_at),
        "updated_at":     _iso_z(inc.updated_at),
        "closed_at":      _iso_z(inc.closed_at),
        "detection_method": inc.detection_method,
    }
    data = _json_bytes(summary)
    zf.writestr("01_Incident/Incident_Summary.json", data)
    manifest.add(path="01_Incident/Incident_Summary.json", data=data,
                 mime="application/json", source="incidents table")

    # Closure checklist (if any)
    cc = (await db.execute(
        select(ClosureChecklistItem).where(ClosureChecklistItem.incident_id == inc.id)
        .order_by(ClosureChecklistItem.sort_order)
    )).scalars().all()
    if cc:
        rows = [{
            "id":            str(c.id),
            "item_key":      c.item_key,
            "label":         c.label,
            "checked":       bool(c.checked),
            "checked_by_id": str(c.checked_by_id) if c.checked_by_id else None,
            "checked_by":    c.checked_by,
            "checked_at":    _iso_z(c.checked_at),
            "assigned_to_id": str(c.assigned_to_id) if c.assigned_to_id else None,
            "assigned_to":   c.assigned_to,
            "notes":         c.notes,
            "sort_order":    c.sort_order,
        } for c in cc]
        data = _json_bytes(rows)
        zf.writestr("01_Incident/Closure_Checklist.json", data)
        manifest.add(path="01_Incident/Closure_Checklist.json", data=data,
                     mime="application/json", source="closure_checklist_items table")

    # Lessons learned (if any)
    ll = (await db.execute(
        select(LessonsLearned).where(LessonsLearned.incident_id == inc.id)
    )).scalar_one_or_none()
    if ll:
        ll_obj = {c.name: getattr(ll, c.name) for c in LessonsLearned.__table__.columns}
        data = _json_bytes(ll_obj)
        zf.writestr("01_Incident/Lessons_Learned.json", data)
        manifest.add(path="01_Incident/Lessons_Learned.json", data=data,
                     mime="application/json", source="lessons_learned table")


async def _section_timeline(db: AsyncSession, inc_id: uuid.UUID, manifest: Manifest, zf: zipfile.ZipFile) -> None:
    # C5 provenance, appended after the original columns (readers that go by position keep
    # working): the exhibit an imported event came from (its identifier), the SHA-256 of the bytes
    # it was parsed from (G-fix B L25: the run's input, else the exhibit's), the parser version, and how
    # its time was worked out (explicit | assumed_tz | inferred_year; empty = analyst-entered / legacy).
    # G4, appended after those: the parser's name and the import run (Timeline Import or Defender
    # import id), the time as the device recorded it and the clock offset that corrected it (both
    # empty when no offset was applied). Defender-promoted rows fill the C5 columns from their run.
    # G3: PCAP- and browser-history-promoted rows fill the same columns from their run (no new
    # columns: parser_name / parser_version = the analyser, import_run_id = the analysis / upload).
    # G-fix B: L26 — email relay hops with a run (email_analysis_id) fill them from their analysis.
    # L25 — source_sha256 is the SHA-256 of the bytes the run PARSED (the run's input hash, else the
    # exhibit's): for Logs & triage of a Velociraptor collection that is the decrypted collection ZIP, not
    # the container exhibit. The exhibit's own SHA-256, when it differs (the container), goes in a new
    # last column, container_sha256 (empty otherwise).
    events = await _fetch_all(db,
        select(TimelineEvent, Evidence.identifier, Evidence.sha256,
               ForensicImport.parser_version, ForensicImport.sha256_hash,
               func.coalesce(DefenderPdfImport.parser_name, PCAPAnalysis.analyser_name,
                             BrowserHistoryUpload.parser_name, EmailAnalysis.analyser_name),
               func.coalesce(DefenderPdfImport.parser_version, PCAPAnalysis.analyser_version,
                             BrowserHistoryUpload.parser_version, EmailAnalysis.analyser_version),
               func.coalesce(DefenderPdfImport.sha256_hash, PCAPAnalysis.input_sha256,
                             BrowserHistoryUpload.sha256_hash, EmailAnalysis.input_sha256))
        .outerjoin(Evidence, Evidence.id == TimelineEvent.evidence_id)
        .outerjoin(ForensicImport, ForensicImport.id == TimelineEvent.forensic_import_id)
        .outerjoin(DefenderPdfImport, DefenderPdfImport.id == TimelineEvent.defender_import_id)
        .outerjoin(PCAPAnalysis, PCAPAnalysis.id == TimelineEvent.pcap_analysis_id)
        .outerjoin(BrowserHistoryUpload, BrowserHistoryUpload.id == TimelineEvent.browser_history_upload_id)
        .outerjoin(EmailAnalysis, EmailAnalysis.id == TimelineEvent.email_analysis_id)
        .where(TimelineEvent.incident_id == inc_id)
        .order_by(TimelineEvent.event_time.asc(), TimelineEvent.id.asc())
    )
    await asyncio.to_thread(_timeline_files, zf, manifest, events)


def _timeline_files(zf: zipfile.ZipFile, manifest: Manifest, events: list) -> None:
    """Blocking (rows, CSV/JSON encoding, deflate, hashes): run via asyncio.to_thread."""
    header = ["event_time_utc", "hostname", "source", "event_type", "description",
              "ir_phase", "mitre_tactic_id", "mitre_tactic_name",
              "mitre_technique_id", "mitre_technique_name", "origin",
              "is_system", "external_safe", "raw_log",
              "source_exhibit", "source_sha256", "parser_version", "time_basis",
              "parser_name", "import_run_id", "recorded_time_utc", "clock_offset_seconds",
              "container_sha256"]

    def _parsed_sha(ev_sha, imp_sha, run_sha):
        return imp_sha or run_sha or ev_sha or ""

    rows = [[
        _iso_z(e.event_time), e.hostname or "", e.source or "", e.event_type or "",
        e.description or "", e.ir_phase or "",
        e.mitre_tactic_id or "", e.mitre_tactic_name or "",
        e.mitre_technique_id or "", e.mitre_technique_name or "",
        e.origin, e.is_system, e.external_safe,
        (e.raw_log or "")[:4000],
        ev_ident or "", _parsed_sha(ev_sha, imp_sha, def_sha), parser_version or def_version or "",
        e.time_basis or "",
        def_name or ("FENRIR timeline parser" if e.forensic_import_id and parser_version else ""),
        str(e.forensic_import_id or e.defender_import_id or e.pcap_analysis_id or e.browser_history_upload_id
            or e.email_analysis_id or ""),
        _iso_z(e.recorded_event_time) if e.recorded_event_time else "",
        "" if e.clock_offset_seconds is None else e.clock_offset_seconds,
        ev_sha if ev_sha and ev_sha != _parsed_sha(ev_sha, imp_sha, def_sha) else "",
    ] for e, ev_ident, ev_sha, parser_version, imp_sha, def_name, def_version, def_sha in events]
    _add_file(zf, manifest, "02_Timeline/Timeline.csv", _csv_bytes(header, rows),
              "text/csv", "timeline_events table")

    json_rows = [{h: r[i] for i, h in enumerate(header)} for r in rows]
    _add_file(zf, manifest, "02_Timeline/Timeline.json",
              _json_bytes({"event_count": len(json_rows), "events": json_rows}),
              "application/json", "timeline_events table")


async def _section_iocs(db: AsyncSession, inc_id: uuid.UUID, manifest: Manifest, zf: zipfile.ZipFile) -> None:
    iocs = await _fetch_all(db,
        select(IOC).where(IOC.incident_id == inc_id)
        .order_by(IOC.added_at.asc(), IOC.id.asc()),
        scalars=True)
    await asyncio.to_thread(_ioc_files, zf, manifest, iocs)


def _ioc_files(zf: zipfile.ZipFile, manifest: Manifest, iocs: list) -> None:
    """Blocking (rows, CSV/JSON encoding, deflate, hashes): run via asyncio.to_thread."""
    header = ["type", "value", "malicious", "confidence", "source", "tags",
              "notes", "added_by_id", "added_at_utc"]
    rows = [[
        i.type, i.value, i.malicious, i.confidence, i.source or "",
        ",".join(i.tags or []), i.notes or "",
        str(i.added_by_id) if i.added_by_id else "",
        _iso_z(i.added_at),
    ] for i in iocs]
    _add_file(zf, manifest, "03_IOCs/IOCs.csv", _csv_bytes(header, rows), "text/csv", "iocs table")

    json_rows = [{h: r[i] for i, h in enumerate(header)} for r in rows]
    _add_file(zf, manifest, "03_IOCs/IOCs.json", _json_bytes({"ioc_count": len(json_rows), "iocs": json_rows}),
              "application/json", "iocs table")


EXCLUDED_DRAFT = "excluded: unsealed draft"


async def _section_evidence(
    db: AsyncSession, inc_id: uuid.UUID,
    *, legal_hold_only: bool, include_unsealed_drafts: bool = False,
    manifest: Manifest, zf: zipfile.ZipFile,
) -> tuple[int, list[dict], int]:
    """Returns (exhibits included, integrity failures to freeze, unsealed drafts excluded). M11 (owner,
    2026-10-04): an exhibit whose chain of custody is not sealed is listed in the inventory as "excluded:
    unsealed draft" with no custody log and no file, unless the lead opted in."""
    q = select(Evidence).where(Evidence.incident_id == inc_id)
    if legal_hold_only:
        q = q.where(Evidence.legal_hold.is_(True))
    listed = (await db.execute(q.order_by(Evidence.collected_at.asc(), Evidence.id.asc()))).scalars().all()
    excluded = {e.id for e in listed if not e.coc_sealed and not include_unsealed_drafts}
    items = [e for e in listed if e.id not in excluded]
    failures: list[dict] = []

    header = ["id", "kind", "identifier", "name", "description", "tlp", "status",
              "original_filename", "file_size_bytes", "mime_type",
              "sha256", "sha1", "md5",
              "make", "model", "serial", "physical_location", "condition",
              "collected_by_id", "collected_at_utc", "collected_location",
              "current_custodian_id", "disposed_at_utc",
              "final_hash_at_disposition", "legal_hold",
              # F4 (R12), appended so readers that go by position keep working: when the image
              # was taken / item seized (operator-stated; empty = not recorded) and how the
              # imaging tool's target hash compared with the uploaded bytes.
              "acquired_at_utc", "upload_hash_check",
              # M11, appended: the sealed state, the lawful basis, and whether the item is in this package.
              "coc_sealed", "coc_sealed_at_utc", "lawful_basis", "package_inclusion"]
    rows = [[
        str(e.id), e.kind, e.identifier, e.name, e.description or "",
        e.tlp, e.status,
        e.original_filename or "", e.file_size_bytes or "", e.mime_type or "",
        e.sha256 or "", e.sha1 or "", e.md5 or "",
        e.make or "", e.model or "", e.serial or "", e.physical_location or "", e.condition or "",
        str(e.collected_by_id) if e.collected_by_id else "",
        _iso_z(e.collected_at), e.collected_location or "",
        str(e.current_custodian_id) if e.current_custodian_id else "",
        _iso_z(e.disposed_at),
        e.final_hash_at_disposition or "",
        e.legal_hold,
        _iso_z(e.acquired_at), e.upload_hash_check or "",
        bool(e.coc_sealed), _iso_z(e.coc_sealed_at), e.lawful_basis or "",
        EXCLUDED_DRAFT if e.id in excluded else "included",
    ] for e in listed]
    data = _csv_bytes(header, rows)
    zf.writestr("04_Evidence/Evidence_Inventory.csv", data)
    manifest.add(path="04_Evidence/Evidence_Inventory.csv", data=data,
                 mime="text/csv", source="evidence table")

    # Per-item custody log (events from audit_logs scoped to resource_type='evidence').
    for ev in items:
        events = (await db.execute(
            select(AuditLog)
            .where(AuditLog.resource_type == "evidence",
                   AuditLog.resource_id   == str(ev.id))
            .order_by(AuditLog.timestamp.asc(), AuditLog.id.asc())
        )).scalars().all()
        if not events:
            continue
        e_header = ["timestamp_utc", "actor_user_id", "actor_username", "action", "outcome",
                    "details_json", "ip_address", "row_hash", "prev_hash"]
        e_rows = [[
            _iso_z(a.timestamp),
            str(a.user_id) if a.user_id else "",
            a.username or "", a.action, a.outcome or "",
            json.dumps(a.details or {}, default=str),
            a.ip_address or "",
            a.row_hash, a.prev_hash,
        ] for a in events]
        cust_bytes = _csv_bytes(e_header, e_rows)
        path = f"04_Evidence/Custody/{ev.id}_custody.csv"
        zf.writestr(path, cust_bytes)
        manifest.add(path=path, data=cust_bytes, mime="text/csv",
                     source=f"audit_logs (resource_type=evidence, resource_id={ev.id})")

    # Embed decrypted file bytes for digital_file items, streamed (G2: bounded memory per exhibit).
    for ev in items:
        if ev.kind != "digital_file" or not ev.storage_path or not ev.nonce_hex:
            continue
        fname_safe = _safe_filename(ev.original_filename or f"evidence_{ev.id}.bin", max_len=80)
        in_zip = f"04_Evidence/Files/{ev.id}__{fname_safe}"

        entry = await asyncio.to_thread(
            _stream_evidence_file, zf, manifest, ev, in_zip,
            ev.mime_type or "application/octet-stream", f"evidence.storage_path={ev.storage_path}")
        if isinstance(entry, IntegrityFailed):
            # R3-2: the stored file failed an integrity check (tampered or corrupt) before a byte was
            # written: no file in the package, recorded below; the route freezes the exhibit.
            sha256_now = None
            integrity_note = f"integrity_failed:{entry.reason}"
            failures.append({"evidence_id": ev.id, "identifier": ev.identifier, "reason": entry.reason,
                             "integrity": integrity_note, "sha256_recomputed": None})
        elif entry is not None:
            sha256_now = entry["sha256"]
            integrity_note = "hash_at_export_matches_recorded" if sha256_now == ev.sha256 else "HASH_MISMATCH_AT_EXPORT"
            if integrity_note == "HASH_MISMATCH_AT_EXPORT":
                failures.append({"evidence_id": ev.id, "identifier": ev.identifier, "reason": "hash_mismatch",
                                 "integrity": integrity_note, "sha256_recomputed": sha256_now})
        else:
            # Source file missing or unreadable (wrong KEK, storage error): it failed before a byte was
            # written; not an integrity failure (not frozen; the read was audited and admins notified).
            sha256_now = None
            integrity_note = "source_file_missing_or_undecryptable"

        meta = {
            "evidence_id":           str(ev.id),
            "identifier":            ev.identifier,
            "name":                  ev.name,
            "original_filename":     ev.original_filename,
            "size_bytes":            ev.file_size_bytes,
            "mime_type":             ev.mime_type,
            "sha256_recorded_at_collection": ev.sha256,
            "sha1_recorded":         ev.sha1,
            "md5_recorded":          ev.md5,
            "sha256_at_export":      sha256_now,
            "integrity":             integrity_note,
            "collected_at_utc":      _iso_z(ev.collected_at),
            "collected_by_id":       str(ev.collected_by_id) if ev.collected_by_id else None,
            "collected_location":    ev.collected_location,
            "acquired_at_utc":       _iso_z(ev.acquired_at),
            "upload_hash_check":     ev.upload_hash_check,
            "coc_sealed":            bool(ev.coc_sealed),
            "coc_sealed_at_utc":     _iso_z(ev.coc_sealed_at),
            "lawful_basis":          ev.lawful_basis,
        }
        meta_bytes = _json_bytes(meta)
        meta_path = f"04_Evidence/Files/{ev.id}__{fname_safe}.meta.json"
        zf.writestr(meta_path, meta_bytes)
        manifest.add(path=meta_path, data=meta_bytes, mime="application/json",
                     source="evidence table + computed at export")

    return len(items), failures, len(excluded)


async def _section_artifacts(
    db: AsyncSession, inc_id: uuid.UUID,
    *, manifest: Manifest, zf: zipfile.ZipFile, settings_quarantine_path: str,
) -> None:
    arts = (await db.execute(
        select(Artifact).where(Artifact.incident_id == inc_id)
    )).scalars().all()

    # The artifact files themselves — wrapped in an `infected`-password ZIP per
    # malware-analyst convention. Skipped if there is no quarantine volume.
    quar = Path(settings_quarantine_path)
    blob, statuses = b"", {}
    if quar.exists() and arts:
        blob, statuses = await asyncio.to_thread(_artifacts_zip, arts)

    # H1: file_status (appended last) — whether the file is in Files.zip, or why not.
    header = ["id", "original_filename", "stored_filename", "file_size",
              "mime_type", "md5", "sha256", "sha512", "description",
              "analysis_status", "file_status"]
    rows = [[
        str(a.id), a.original_filename, a.stored_filename, a.file_size,
        a.mime_type or "", a.md5_hash or "", a.sha256_hash or "", a.sha512_hash or "",
        a.description or "", a.analysis_status, statuses.get(str(a.id), "not_packaged"),
    ] for a in arts]
    data = _csv_bytes(header, rows)
    zf.writestr("05_Artifacts/Artifacts_Inventory.csv", data)
    manifest.add(path="05_Artifacts/Artifacts_Inventory.csv", data=data,
                 mime="text/csv", source="artifacts table")
    if blob:
        await asyncio.to_thread(
            _add_file, zf, manifest, "05_Artifacts/Files.zip", blob,
            "application/zip", f"quarantine volume @ {settings_quarantine_path} (decrypted)")


async def _section_forensic(db: AsyncSession, inc_id: uuid.UUID, manifest: Manifest, zf: zipfile.ZipFile) -> None:
    pcaps = (await db.execute(
        select(PCAPAnalysis).where(PCAPAnalysis.incident_id == inc_id)
        .order_by(PCAPAnalysis.created_at.asc())
    )).scalars().all()
    if pcaps:
        idents = dict((await db.execute(
            select(Evidence.id, Evidence.identifier)
            .where(Evidence.id.in_({p.evidence_id for p in pcaps if p.evidence_id})))).all())
        rows = [{
            "id": str(p.id), "filename": p.filename, "file_size": p.file_size,
            "uploaded_by": p.uploaded_by, "created_at_utc": _iso_z(p.created_at),
            "result": p.result_json,
            # G3 run record, appended (null on analyses made before G3)
            "evidence_id": str(p.evidence_id) if p.evidence_id else None,
            "evidence_identifier": idents.get(p.evidence_id),
            "input_sha256": p.input_sha256, "analyser_name": p.analyser_name,
            "analyser_version": p.analyser_version, "exhibit_link": p.exhibit_link,
            "clock_offset_seconds": p.clock_offset_seconds,
        } for p in pcaps]
        data = _json_bytes(rows)
        zf.writestr("06_Forensic/PCAP_Analyses.json", data)
        manifest.add(path="06_Forensic/PCAP_Analyses.json", data=data,
                     mime="application/json", source="pcap_analyses table")

    yara = (await db.execute(
        select(YaraMatch).where(YaraMatch.incident_id == inc_id)
    )).scalars().all()
    if yara:
        header = [c.name for c in YaraMatch.__table__.columns]
        rows = [[getattr(m, h) for h in header] for m in yara]
        data = _csv_bytes(header, rows)
        zf.writestr("06_Forensic/YARA_Matches.csv", data)
        manifest.add(path="06_Forensic/YARA_Matches.csv", data=data,
                     mime="text/csv", source="yara_matches table")


async def _section_comms(db: AsyncSession, inc_id: uuid.UUID, manifest: Manifest, zf: zipfile.ZipFile) -> None:
    comments = (await db.execute(
        select(Comment).where(Comment.incident_id == inc_id).order_by(Comment.created_at.asc())
    )).scalars().all()
    if comments:
        header = ["id", "author_id", "body", "created_at_utc", "edited_at_utc"]
        rows = [[str(c.id), str(c.author_id) if c.author_id else "",
                 c.body, _iso_z(c.created_at), _iso_z(c.edited_at)] for c in comments]
        data = _csv_bytes(header, rows)
        zf.writestr("07_Communications/Comments.csv", data)
        manifest.add(path="07_Communications/Comments.csv", data=data,
                     mime="text/csv", source="comments table")

    oobs = (await db.execute(
        select(OOBLog).where(OOBLog.incident_id == inc_id).order_by(OOBLog.created_at.asc())
    )).scalars().all()
    if oobs:
        header = ["id", "stakeholder_name", "channel", "direction", "summary",
                  "verified", "verification_method", "created_by_id", "created_at_utc"]
        rows = [[str(o.id), o.stakeholder_name, o.channel, o.direction, o.summary,
                 o.verified, o.verification_method or "",
                 str(o.created_by_id) if o.created_by_id else "",
                 _iso_z(o.created_at)] for o in oobs]
        data = _csv_bytes(header, rows)
        zf.writestr("07_Communications/OOB_Log.csv", data)
        manifest.add(path="07_Communications/OOB_Log.csv", data=data,
                     mime="text/csv", source="oob_logs table")

    stk = (await db.execute(
        select(IncidentStakeholder).where(IncidentStakeholder.incident_id == inc_id)
        .order_by(IncidentStakeholder.created_at.asc())
    )).scalars().all()
    if stk:
        header = ["id", "name", "title", "organization", "type",
                  "contact_methods_json", "notes", "available_hours",
                  "created_at_utc"]
        rows = [[str(s.id), s.name, s.title or "", s.organization or "", s.type,
                 json.dumps(s.contact_methods or [], default=str),
                 s.notes or "", s.available_hours or "",
                 _iso_z(s.created_at)] for s in stk]
        data = _csv_bytes(header, rows)
        zf.writestr("07_Communications/Stakeholders.csv", data)
        manifest.add(path="07_Communications/Stakeholders.csv", data=data,
                     mime="text/csv", source="incident_stakeholders table")


async def _section_case_notes(db: AsyncSession, inc_id: uuid.UUID, manifest: Manifest, zf: zipfile.ZipFile) -> None:
    """H2: the incident's append-only case notes, oldest first, each with its stored content hash and
    whether it still matches the entry (recomputed now; recipe in case_notes/hashing.py and README)."""
    notes = (await db.execute(
        select(CaseNote).where(CaseNote.incident_id == inc_id).order_by(CaseNote.created_at.asc(), CaseNote.id.asc())
    )).scalars().all()
    if not notes:
        return
    names = dict((await db.execute(
        select(User.id, User.username).where(User.id.in_({n.author_id for n in notes}))
    )).all())
    fixed_by = {n.corrects_id: n.id for n in notes if n.corrects_id}
    header = ["id", "incident_id", "created_at_utc", "author_id", "author_username", "body", "corrects_id", "corrected_by_id",
              "source_scratchpad_id", *LINK_FIELDS, "content_sha256", "content_sha256_verified"]
    rows = [[str(n.id), str(n.incident_id), created_at_text(n), str(n.author_id), names.get(n.author_id, ""), n.body,
             str(n.corrects_id) if n.corrects_id else "", str(fixed_by[n.id]) if n.id in fixed_by else "",
             str(n.source_scratchpad_id) if n.source_scratchpad_id else "",
             *[";".join(sorted(str(x) for x in getattr(n, f) or [])) for f in LINK_FIELDS],
             n.content_sha256, "yes" if content_sha256(n) == n.content_sha256 else "NO"] for n in notes]
    _add_file(zf, manifest, "10_Case_Notes/Case_Notes.csv", _csv_bytes(header, rows), "text/csv", "case_notes table")


async def _section_audit(db: AsyncSession, inc_id: uuid.UUID, manifest: Manifest,
                          zf: zipfile.ZipFile) -> tuple[int, bytes]:
    """Per-incident audit trail (incl. hash chain) + verifier output.

    Returns (row_count, verifier_text_bytes). The verifier text is also
    written to the bundle.
    """
    rows = await _fetch_all(db,
        select(AuditLog)
        .where(AuditLog.request_path.like(f"/api/incidents/{inc_id}%"))
        .order_by(AuditLog.timestamp.asc(), AuditLog.id.asc()),
        scalars=True)
    # Also include any audit rows that reference resources owned by this incident
    # (evidence rows logged before LE-package generate). We intersect by resource_id
    # collisions later if needed; for v1 scope keep request_path filter.
    return await asyncio.to_thread(_audit_files, zf, manifest, rows)


def _audit_files(zf: zipfile.ZipFile, manifest: Manifest, rows: list) -> tuple[int, bytes]:
    """Blocking (rows, CSV/JSON encoding, per-row hash-chain check, deflate, hashes): run via
    asyncio.to_thread. Returns (row_count, verifier_text_bytes)."""
    header = ["timestamp_utc", "user_id", "username", "role_at_time", "action",
              "outcome", "resource_type", "resource_id", "resource_label",
              "request_method", "request_path", "request_id", "ip_address",
              "details_json", "hash_version", "row_hash", "prev_hash"]
    csv_rows = [[
        _iso_z(r.timestamp),
        str(r.user_id) if r.user_id else "",
        r.username or "", r.role_at_time or "",
        r.action, r.outcome or "",
        r.resource_type or "", r.resource_id or "", r.resource_label or "",
        r.request_method or "", r.request_path or "", r.request_id or "",
        r.ip_address or "",
        json.dumps(r.details or {}, default=str),
        r.hash_version or "v1",
        r.row_hash, r.prev_hash,
    ] for r in rows]
    _add_file(zf, manifest, "08_Audit/Audit_Trail.csv", _csv_bytes(header, csv_rows),
              "text/csv", "audit_logs (request_path LIKE /api/incidents/{id}%)")

    # JSON form (preserves full row + hashes)
    json_rows = [{h: cr[i] for i, h in enumerate(header)} for cr in csv_rows]
    _add_file(zf, manifest, "08_Audit/Audit_Trail.json",
              _json_bytes({"row_count": len(json_rows), "rows": json_rows}), "application/json", "audit_logs")

    # Run the verifier and write a human-readable report.
    verifier_lines = [
        "DFIR-FENRIR — Hash-Chain Verification",
        f"Generated:       {_iso_z(datetime.now(timezone.utc))}",
        f"Rows verified:   {len(rows)}",
        "",
        "Per-row check (row_hash == sha256(prev_hash || canonical_payload)):",
    ]
    failures = 0
    for r in rows:
        ok = verify_row_hash(r)
        if not ok:
            failures += 1
            verifier_lines.append(f"  FAIL  {_iso_z(r.timestamp)}  row_id={r.id}  action={r.action}")
    if failures == 0:
        verifier_lines += ["  (every row verified)", "", "RESULT: VERIFIED ✓"]
    else:
        verifier_lines += ["", f"RESULT: FAIL — {failures} row(s) failed verification"]
    verifier_bytes = ("\n".join(verifier_lines) + "\n").encode("utf-8")
    zf.writestr("08_Audit/Hash_Chain_Verification.txt", verifier_bytes)
    manifest.add(path="08_Audit/Hash_Chain_Verification.txt", data=verifier_bytes,
                 mime="text/plain", source="audit/service.verify_row_hash() output")

    return len(rows), verifier_bytes


def _section_legal(manifest: Manifest, zf: zipfile.ZipFile, *, tlp: str) -> None:
    sop_bytes = CHAIN_OF_CUSTODY_SOP.encode("utf-8")
    zf.writestr("09_Legal/Chain_of_Custody_SOP.md", sop_bytes)
    manifest.add(path="09_Legal/Chain_of_Custody_SOP.md", data=sop_bytes,
                 mime="text/markdown", source="le_package/sop.py (embedded constant)")

    tlp_text = (
        f"# TLP Handling Statement\n\n"
        f"This package is classified **TLP:{tlp.upper()}** per FIRST TLP 2.0.\n\n"
        "Handling rules:\n\n"
        "- **TLP:RED**        — for named recipients only. No further sharing.\n"
        "- **TLP:AMBER+STRICT** — share only within the recipient organisation, "
        "and only with those who *need to know*.\n"
        "- **TLP:AMBER**      — share within the recipient organisation and with its clients.\n"
        "- **TLP:GREEN**      — share within the trust community.\n"
        "- **TLP:CLEAR**      — unrestricted, subject to standard copyright rules.\n\n"
        "Unauthorised disclosure may compromise the investigation, the victim, or third parties.\n"
    ).encode("utf-8")
    zf.writestr("09_Legal/TLP_Statement.md", tlp_text)
    manifest.add(path="09_Legal/TLP_Statement.md", data=tlp_text,
                 mime="text/markdown", source="le_package/builder.py (rendered)")

    provenance = {
        "platform":               f"DFIR-FENRIR {PLATFORM_VERSION}",
        "package_builder":        "backend/le_package/builder.py",
        "hash_algorithms":        ["sha256", "sha512"],
        "manifest_signature":     "HMAC-SHA-256 over MANIFEST.json (INTEGRITY.sig); key = SHA-256 of the "
                                  "bundle password. A shared-secret MAC, not a public-key signature",
        "bundle_encryption":      "Outer envelope: AES-256 password-protected ZIP (WinZip AE-2: AES-256 in CTR "
                                  "mode, key derived from the password with PBKDF2-HMAC-SHA1 (1,000 iterations), "
                                  "10-byte HMAC-SHA1 authentication code per entry), holding le_package.zip; one-time 24-character "
                                  "password shown once at generation. The inner le_package.zip itself is not "
                                  "encrypted; 05_Artifacts/Files.zip (when present) is an AE-2 ZIP with the "
                                  "password 'infected'",
        "evidence_at_rest":       ("FENRGCM v2 (items stored since 2026-10-04): AES-256-GCM in 1 MiB chunks under "
                                   "a random 256-bit data key per file; the data key is wrapped with AES-KW (RFC "
                                   "3394) under K_wrap = HKDF-SHA256(EVIDENCE_KEK, info \"FENRGCM/v2/key-wrap\") "
                                   "and kept in the file header; chunk nonce = 56-bit random per-file prefix || "
                                   "32-bit chunk index || final-chunk flag; the header's fixed bytes are the "
                                   "associated data of every chunk. Legacy v0 (items stored before): one "
                                   "AES-256-GCM message per file under EVIDENCE_KEK with a random 96-bit nonce. "
                                   "Spec: docs/streaming-aes-gcm-format.md"),
        "audit_chain":            "SHA-256 chain (row_hash = sha256(prev_hash || canonical_json(payload)))",
        "audit_chain_version":    "v2",
        "time_source":            "container clock (NTP-disciplined host); recorded UTC",
        "standards_alignment":    ["NIST SP 800-86", "ISO/IEC 27037", "ACPO Good Practice Guide", "SWGDE Best Practices"],
    }
    data = _json_bytes(provenance)
    zf.writestr("09_Legal/Tool_Provenance.json", data)
    manifest.add(path="09_Legal/Tool_Provenance.json", data=data,
                 mime="application/json", source="le_package/builder.py (constant)")


# ── Main entry point ───────────────────────────────────────────────────────


class BuildResult:
    """Return value of `build_le_package`. Plain object, no DB state. `staged` = the finished bundle in
    /evidence/.staging/ (StagedOutput): the caller commits it into place or discards it."""
    __slots__ = ("staged", "bundle_size", "bundle_sha256", "manifest_sha256",
                 "hmac_sha256", "bundle_password", "file_count", "total_bytes",
                 "evidence_count", "audit_row_count", "manifest_json_bytes",
                 "generated_at_iso", "integrity_failures", "excluded_drafts")

    def __init__(self, **kw: Any) -> None:
        for k in self.__slots__:
            setattr(self, k, kw.get(k))


async def build_le_package(
    *,
    db:                 AsyncSession,
    inc:                Incident,
    user:               User,
    case_reference:     str,
    requesting_authority: str,
    legal_basis:        str,
    retention_until:    datetime | None,
    legal_hold_only:    bool,
    include_artifacts:  bool,
    quarantine_path:    str,
    size_estimate:      int | None = None,
    include_unsealed_drafts: bool = False,
) -> BuildResult:
    """Build the encrypted bundle, streamed into a staging file (G2). Does not touch DB write state.
    `size_estimate` = estimate_package_bytes() when the caller already has it. A stored exhibit that
    fails part-way (F-12) raises its EvidenceIntegrityError / EvidenceCryptoError after the staged
    bundle is discarded.

    Integrity model:
      • In-bundle proof:  per-file SHA-256 (INTEGRITY.sha256) + manifest SHA-256
                          + HMAC-SHA-256(MANIFEST.json, bundle_kek). Anyone with
                          the bundle alone can prove every file matches the
                          manifest; anyone with bundle + KEK can prove the
                          bundle was assembled by a holder of that KEK.
      • Platform proof:   the *route layer* writes one `le_package_generate`
                          audit row AFTER this builder returns, carrying
                          `details.manifest_sha256` and `details.bundle_sha256`.
                          That row's `row_hash` is the tamper-evident anchor —
                          stored on the LePackage DB row, surfaced in the API
                          response. Receivers can re-query the platform via
                          authenticated API to obtain it.

    The audit anchor is NOT in the bundle (and MANIFEST.json has no anchor key):
    the audit row's payload contains the manifest hash, so it can only be written
    after the manifest exists — a circular dependency. README/SOP say so.
    """
    generated_at_iso = _iso_z(datetime.now(timezone.utc))
    # Single secret: a 24-char URL-safe base64 password. The pyzipper outer envelope consumes the
    # password directly (WinZip AE-2 derives the AES-256 key via PBKDF2); the HMAC key is derived
    # deterministically as SHA-256(password) so a recipient who can open the ZIP can also recompute
    # the manifest HMAC. Drawn first: the envelope is written while the package is built.
    bundle_password = secrets.token_urlsafe(18)
    if size_estimate is None:
        size_estimate = await estimate_package_bytes(db, inc.id, legal_hold_only=legal_hold_only,
                                                     include_artifacts=include_artifacts,
                                                     include_unsealed_drafts=include_unsealed_drafts)
    staged, oz, entry = await asyncio.to_thread(_open_bundle, bundle_password, size_estimate)
    try:
        return await _build_into(entry, staged, oz, db=db, inc=inc, user=user, case_reference=case_reference,
                                 requesting_authority=requesting_authority, legal_basis=legal_basis,
                                 retention_until=retention_until, legal_hold_only=legal_hold_only,
                                 include_artifacts=include_artifacts, quarantine_path=quarantine_path,
                                 bundle_password=bundle_password, generated_at_iso=generated_at_iso,
                                 include_unsealed_drafts=include_unsealed_drafts)
    except BaseException:
        await asyncio.to_thread(_abandon_bundle, staged, oz, entry)
        raise


async def _build_into(entry, staged: StagedOutput, oz, *, db: AsyncSession, inc: Incident, user: User,
                      case_reference: str, requesting_authority: str, legal_basis: str,
                      retention_until: datetime | None, legal_hold_only: bool, include_artifacts: bool,
                      quarantine_path: str, bundle_password: str, generated_at_iso: str,
                      include_unsealed_drafts: bool = False) -> BuildResult:
    """The package itself, written as a ZIP into the outer envelope's entry (an unseekable stream: the
    inner entries use data descriptors, ZIP64 where one needs it)."""
    with zipfile.ZipFile(entry, "w", zipfile.ZIP_DEFLATED) as zf:
        manifest = Manifest(
            incident_id=str(inc.id), incident_ref=inc.ref,
            case_reference=case_reference, platform_version=PLATFORM_VERSION,
        )

        # CASE_INFO.json — added first, hashed into manifest.
        case_info = {
            "case_reference":       case_reference,
            "requesting_authority": requesting_authority,
            "legal_basis":          legal_basis,
            "retention_until":      _iso_z(retention_until),
            "build_options": {
                "legal_hold_only":   legal_hold_only,
                "include_artifacts": include_artifacts,
                "include_unsealed_drafts": include_unsealed_drafts,
            },
            "incident": {
                "id":  str(inc.id),
                "ref": inc.ref,
                "tlp": inc.tlp,
            },
            "generated_at_utc":   generated_at_iso,
            "generated_by_user_id": str(user.id),
            "generated_by_username": user.username,
        }
        ci_bytes = _json_bytes(case_info)
        zf.writestr("CASE_INFO.json", ci_bytes)
        manifest.add(path="CASE_INFO.json", data=ci_bytes,
                     mime="application/json", source="LE-package request payload")

        # Content sections
        await _section_incident(db, inc, manifest, zf)
        await _section_timeline(db, inc.id, manifest, zf)
        await _section_iocs(db, inc.id, manifest, zf)
        evidence_count, integrity_failures, excluded_drafts = await _section_evidence(
            db, inc.id, legal_hold_only=legal_hold_only, include_unsealed_drafts=include_unsealed_drafts,
            manifest=manifest, zf=zf,
        )
        if include_artifacts:
            await _section_artifacts(
                db, inc.id, manifest=manifest, zf=zf,
                settings_quarantine_path=quarantine_path,
            )
        await _section_forensic(db, inc.id, manifest, zf)
        await _section_comms(db, inc.id, manifest, zf)
        audit_row_count, _ = await _section_audit(db, inc.id, manifest, zf)
        _section_legal(manifest, zf, tlp=inc.tlp)
        await _section_case_notes(db, inc.id, manifest, zf)

        # Manifest, integrity, README — written LAST so all sections are accounted for.
        manifest_json = _json_bytes(manifest.to_json())
        manifest_sha256 = hashlib.sha256(manifest_json).hexdigest()
        zf.writestr("MANIFEST.json", manifest_json)
        zf.writestr("MANIFEST.txt",  manifest.to_text().encode("utf-8"))
        zf.writestr("INTEGRITY.sha256", manifest.to_integrity_sha256().encode("utf-8"))

        # GS-4 — RFC 3161 trusted timestamp over sha256(MANIFEST.json), best-effort.
        # Written as a raw DER token so a recipient can `openssl ts -verify
        # -data MANIFEST.json -in MANIFEST.tst` independently of FENRIR's clock.
        manifest_tst = await timestamp_sha256(manifest_sha256)
        if manifest_tst:
            zf.writestr("MANIFEST.tst", base64.b64decode(manifest_tst["tst_b64"]))

        # HMAC will be computed against the ephemeral key below; reserve filename.
        # README contains the final hashes — render after we know bundle hash placeholder.
        # NOTE: bundle_sha256 isn't known until *after* we encrypt; we use a
        # canonical "computed at finalize" placeholder model: the README gets
        # the manifest_sha256 + hmac (the latter computed below) + anchor; the
        # bundle SHA-256 is also exposed in the X-Bundle-SHA256 download
        # header and in the LePackage row.
        # → Compute HMAC now (key = SHA-256 of the bundle password, drawn in build_le_package).
        hmac_key   = hashlib.sha256(bundle_password.encode("utf-8")).digest()
        hmac_hex   = hmac_manifest(manifest_json, hmac_key)
        zf.writestr("INTEGRITY.sig", hmac_hex.encode("ascii"))

        readme = render_readme(
            case_reference=case_reference,
            requesting_authority=requesting_authority,
            legal_basis=legal_basis,
            retention_until=retention_until,
            incident_ref=inc.ref,
            incident_title=inc.title,
            incident_id=str(inc.id),
            severity=inc.severity, tlp=inc.tlp, phase=inc.phase, status=inc.status,
            occurred_at_utc=_iso_z(inc.occurred_at),
            detected_at_utc=_iso_z(inc.detected_at),
            contained_at_utc=_iso_z(inc.contained_at),
            eradicated_at_utc=_iso_z(inc.eradicated_at),
            recovered_at_utc=_iso_z(inc.recovered_at),
            generated_at_utc=generated_at_iso,
            generator_username=user.username,
            generator_role=user.role,
            generator_user_id=str(user.id),
            platform_version=PLATFORM_VERSION,
            bundle_sha256="(see X-Bundle-SHA256 download header / LePackage.bundle_sha256)",
            manifest_sha256=manifest_sha256,
            hmac_sha256=hmac_hex,
            audit_anchor_row_id="(written post-build; see LePackage.audit_anchor_row_id in platform API)",
            audit_anchor_row_hash="(written post-build; see LePackage.audit_anchor_row_hash in platform API)",
            trusted_timestamp=({"time": manifest_tst.get("time"), "tsa": manifest_tst.get("tsa")}
                               if manifest_tst else None),
            legal_hold_only=legal_hold_only,
            include_artifacts=include_artifacts,
            file_count=manifest.file_count,
            total_bytes=manifest.total_bytes,
            evidence_count=evidence_count,
            audit_row_count=audit_row_count,
        )
        zf.writestr("README.md", readme.encode("utf-8"))

    # Outer envelope — AES-256 password-protected ZIP (WinZip AE-2 via pyzipper).
    # Operators open with any standard archive tool — macOS Finder, 7-Zip,
    # WinRAR, `unzip -P` — no Python or `cryptography` library required.
    bundle_size, bundle_sha256 = await asyncio.to_thread(_close_bundle, staged, oz, entry)

    return BuildResult(
        staged=staged,
        bundle_size=bundle_size,
        bundle_sha256=bundle_sha256,
        manifest_sha256=manifest_sha256,
        hmac_sha256=hmac_hex,
        bundle_password=bundle_password,
        file_count=manifest.file_count,
        total_bytes=manifest.total_bytes,
        evidence_count=evidence_count,
        audit_row_count=audit_row_count,
        manifest_json_bytes=manifest_json,
        generated_at_iso=generated_at_iso,
        integrity_failures=integrity_failures,
        excluded_drafts=excluded_drafts,
    )
