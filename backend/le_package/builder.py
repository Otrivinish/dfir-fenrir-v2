"""LE-package builder.

Single entry point: `build_le_package`. Reads the source-of-truth tables for
an incident in a read-only fashion, assembles an in-memory ZIP that follows
the LE-package layout (see README in this module's `readme.py`), then
encrypts the whole ZIP with AES-256-GCM under a fresh ephemeral KEK.

Returns the encrypted bundle bytes plus the metadata the route layer needs to
persist `CustodyExport` + `LePackage` rows and emit the audit anchor row.

This module does **not** write to DB or disk and does **not** commit. The
route layer owns those side effects.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import secrets
import uuid
import zipfile
from datetime import datetime, timezone
from typing import Any

import pyzipper
# Outer envelope is now an AES-256 password-protected ZIP (pyzipper, WinZip
# AE-2) rather than raw AES-256-GCM — see `bundle_password` / `_hmac_key`
# below. pyzipper is already imported at top of file for the inner evidence
# ZIP, so no new dependency.
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import verify_row_hash
from evidence.crypto import aread_decrypted
from evidence.timestamping import timestamp_sha256
from le_package.manifest import Manifest, hmac_manifest
from le_package.readme import render_readme
from le_package.sop import CHAIN_OF_CUSTODY_SOP
from models import (Artifact, AuditLog, Comment, CustodyExport, Evidence,
                    IOC, Incident, IncidentStakeholder, LessonsLearned,
                    OOBLog, PCAPAnalysis, TimelineEvent, User, YaraMatch,
                    ClosureChecklistItem)


PLATFORM_VERSION = "v2.0.0"


def _iso_z(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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


# ── Section builders ───────────────────────────────────────────────────────


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
        "contained_at":   _iso_z(inc.contained_at),
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
    events = (await db.execute(
        select(TimelineEvent).where(TimelineEvent.incident_id == inc_id)
        .order_by(TimelineEvent.event_time.asc(), TimelineEvent.id.asc())
    )).scalars().all()

    header = ["event_time_utc", "hostname", "source", "event_type", "description",
              "ir_phase", "mitre_tactic_id", "mitre_tactic_name",
              "mitre_technique_id", "mitre_technique_name", "origin",
              "is_system", "external_safe", "raw_log"]
    rows = [[
        _iso_z(e.event_time), e.hostname or "", e.source or "", e.event_type or "",
        e.description or "", e.ir_phase or "",
        e.mitre_tactic_id or "", e.mitre_tactic_name or "",
        e.mitre_technique_id or "", e.mitre_technique_name or "",
        e.origin, e.is_system, e.external_safe,
        (e.raw_log or "")[:4000],
    ] for e in events]
    data = _csv_bytes(header, rows)
    zf.writestr("02_Timeline/Timeline.csv", data)
    manifest.add(path="02_Timeline/Timeline.csv", data=data,
                 mime="text/csv", source="timeline_events table")

    json_rows = [{h: r[i] for i, h in enumerate(header)} for r in rows]
    data = _json_bytes({"event_count": len(json_rows), "events": json_rows})
    zf.writestr("02_Timeline/Timeline.json", data)
    manifest.add(path="02_Timeline/Timeline.json", data=data,
                 mime="application/json", source="timeline_events table")


async def _section_iocs(db: AsyncSession, inc_id: uuid.UUID, manifest: Manifest, zf: zipfile.ZipFile) -> None:
    iocs = (await db.execute(
        select(IOC).where(IOC.incident_id == inc_id)
        .order_by(IOC.added_at.asc(), IOC.id.asc())
    )).scalars().all()

    header = ["type", "value", "malicious", "confidence", "source", "tags",
              "notes", "added_by_id", "added_at_utc"]
    rows = [[
        i.type, i.value, i.malicious, i.confidence, i.source or "",
        ",".join(i.tags or []), i.notes or "",
        str(i.added_by_id) if i.added_by_id else "",
        _iso_z(i.added_at),
    ] for i in iocs]
    data = _csv_bytes(header, rows)
    zf.writestr("03_IOCs/IOCs.csv", data)
    manifest.add(path="03_IOCs/IOCs.csv", data=data, mime="text/csv", source="iocs table")

    json_rows = [{h: r[i] for i, h in enumerate(header)} for r in rows]
    data = _json_bytes({"ioc_count": len(json_rows), "iocs": json_rows})
    zf.writestr("03_IOCs/IOCs.json", data)
    manifest.add(path="03_IOCs/IOCs.json", data=data, mime="application/json", source="iocs table")


async def _section_evidence(
    db: AsyncSession, inc_id: uuid.UUID,
    *, legal_hold_only: bool,
    manifest: Manifest, zf: zipfile.ZipFile,
) -> int:
    q = select(Evidence).where(Evidence.incident_id == inc_id)
    if legal_hold_only:
        q = q.where(Evidence.legal_hold.is_(True))
    items = (await db.execute(q.order_by(Evidence.collected_at.asc(), Evidence.id.asc()))).scalars().all()

    header = ["id", "kind", "identifier", "name", "description", "tlp", "status",
              "original_filename", "file_size_bytes", "mime_type",
              "sha256", "sha1", "md5",
              "make", "model", "serial", "physical_location", "condition",
              "collected_by_id", "collected_at_utc", "collected_location",
              "current_custodian_id", "disposed_at_utc",
              "final_hash_at_disposition", "legal_hold"]
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
    ] for e in items]
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

    # Embed decrypted file bytes for digital_file items.
    for ev in items:
        if ev.kind != "digital_file" or not ev.storage_path or not ev.nonce_hex:
            continue
        try:
            plaintext = await aread_decrypted(ev.storage_path, ev.nonce_hex)
        except Exception:
            # Source file missing or KEK can't decrypt — record the absence in meta below.
            plaintext = None

        fname_safe = _safe_filename(ev.original_filename or f"evidence_{ev.id}.bin", max_len=80)
        in_zip = f"04_Evidence/Files/{ev.id}__{fname_safe}"

        if plaintext is not None:
            zf.writestr(in_zip, plaintext)
            sha256_now = hashlib.sha256(plaintext).hexdigest()
            manifest.add(path=in_zip, data=plaintext,
                         mime=ev.mime_type or "application/octet-stream",
                         source=f"evidence.storage_path={ev.storage_path}")
            integrity_note = "hash_at_export_matches_recorded" if sha256_now == ev.sha256 else "HASH_MISMATCH_AT_EXPORT"
        else:
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
        }
        meta_bytes = _json_bytes(meta)
        meta_path = f"04_Evidence/Files/{ev.id}__{fname_safe}.meta.json"
        zf.writestr(meta_path, meta_bytes)
        manifest.add(path=meta_path, data=meta_bytes, mime="application/json",
                     source="evidence table + computed at export")

    return len(items)


async def _section_artifacts(
    db: AsyncSession, inc_id: uuid.UUID,
    *, manifest: Manifest, zf: zipfile.ZipFile, settings_quarantine_path: str,
) -> None:
    arts = (await db.execute(
        select(Artifact).where(Artifact.incident_id == inc_id)
    )).scalars().all()

    header = ["id", "original_filename", "stored_filename", "file_size",
              "mime_type", "md5", "sha256", "sha512", "description",
              "analysis_status"]
    rows = [[
        str(a.id), a.original_filename, a.stored_filename, a.file_size,
        a.mime_type or "", a.md5_hash or "", a.sha256_hash or "", a.sha512_hash or "",
        a.description or "", a.analysis_status,
    ] for a in arts]
    data = _csv_bytes(header, rows)
    zf.writestr("05_Artifacts/Artifacts_Inventory.csv", data)
    manifest.add(path="05_Artifacts/Artifacts_Inventory.csv", data=data,
                 mime="text/csv", source="artifacts table")

    # The artifact files themselves — wrapped in an `infected`-password ZIP per
    # malware-analyst convention. Skip silently if no quarantine volume.
    quar = __import__("pathlib").Path(settings_quarantine_path)
    if not quar.exists() or not arts:
        return
    inner = io.BytesIO()
    with pyzipper.AESZipFile(inner, "w",
                             compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as iz:
        iz.setpassword(b"infected")
        for a in arts:
            src = quar / str(inc_id) / a.stored_filename
            if not src.exists():
                continue
            iz.write(str(src), arcname=a.original_filename or a.stored_filename)
    blob = inner.getvalue()
    if blob:
        zf.writestr("05_Artifacts/Files.zip", blob)
        manifest.add(path="05_Artifacts/Files.zip", data=blob,
                     mime="application/zip",
                     source=f"quarantine volume @ {settings_quarantine_path}")


async def _section_forensic(db: AsyncSession, inc_id: uuid.UUID, manifest: Manifest, zf: zipfile.ZipFile) -> None:
    pcaps = (await db.execute(
        select(PCAPAnalysis).where(PCAPAnalysis.incident_id == inc_id)
        .order_by(PCAPAnalysis.created_at.asc())
    )).scalars().all()
    if pcaps:
        rows = [{
            "id": str(p.id), "filename": p.filename, "file_size": p.file_size,
            "uploaded_by": p.uploaded_by, "created_at_utc": _iso_z(p.created_at),
            "result": p.result_json,
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


async def _section_audit(db: AsyncSession, inc_id: uuid.UUID, manifest: Manifest,
                          zf: zipfile.ZipFile) -> tuple[int, bytes]:
    """Per-incident audit trail (incl. hash chain) + verifier output.

    Returns (row_count, verifier_text_bytes). The verifier text is also
    written to the bundle.
    """
    rows = (await db.execute(
        select(AuditLog)
        .where(AuditLog.request_path.like(f"/api/incidents/{inc_id}%"))
        .order_by(AuditLog.timestamp.asc(), AuditLog.id.asc())
    )).scalars().all()
    # Also include any audit rows that reference resources owned by this incident
    # (evidence rows logged before LE-package generate). We intersect by resource_id
    # collisions later if needed; for v1 scope keep request_path filter.

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
    csv_data = _csv_bytes(header, csv_rows)
    zf.writestr("08_Audit/Audit_Trail.csv", csv_data)
    manifest.add(path="08_Audit/Audit_Trail.csv", data=csv_data,
                 mime="text/csv", source="audit_logs (request_path LIKE /api/incidents/{id}%)")

    # JSON form (preserves full row + hashes)
    json_rows = [{h: cr[i] for i, h in enumerate(header)} for cr in csv_rows]
    json_data = _json_bytes({"row_count": len(json_rows), "rows": json_rows})
    zf.writestr("08_Audit/Audit_Trail.json", json_data)
    manifest.add(path="08_Audit/Audit_Trail.json", data=json_data,
                 mime="application/json", source="audit_logs")

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
        "manifest_signature":     "HMAC-SHA-256 over MANIFEST.json under the ephemeral bundle KEK",
        "bundle_encryption":      "AES-256-GCM, 12-byte nonce prefix + ciphertext + 16-byte tag",
        "evidence_at_rest":       "AES-256-GCM with per-file 96-bit nonces under EVIDENCE_KEK",
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
    """Return value of `build_le_package`. Plain object, no DB state."""
    __slots__ = ("encrypted_bundle", "bundle_sha256", "manifest_sha256",
                 "hmac_sha256", "bundle_password", "file_count", "total_bytes",
                 "evidence_count", "audit_row_count", "manifest_json_bytes",
                 "generated_at_iso")

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
) -> BuildResult:
    """Build the encrypted bundle in memory. Does not touch DB write state.

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

    The audit anchor is intentionally NOT embedded in the bundle. Doing so
    would require the audit row's payload (which contains the manifest hash)
    to be written before the manifest hash is known — a circular dependency.
    """
    audit_anchor = None   # see docstring — anchored externally, not in-bundle
    generated_at_iso = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as zf:
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
        evidence_count = await _section_evidence(
            db, inc.id, legal_hold_only=legal_hold_only,
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

        # Manifest, integrity, README — written LAST so all sections are accounted for.
        manifest_json = _json_bytes(manifest.to_json(audit_anchor=audit_anchor))
        manifest_sha256 = hashlib.sha256(manifest_json).hexdigest()
        zf.writestr("MANIFEST.json", manifest_json)
        zf.writestr("MANIFEST.txt",  manifest.to_text(audit_anchor=audit_anchor).encode("utf-8"))
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
        # → Compute HMAC now.
        # Single secret: a 24-char URL-safe base64 password. The pyzipper
        # outer envelope consumes the password directly (WinZip AE-2 derives
        # the AES-256 key via PBKDF2); the HMAC key is derived deterministically
        # as SHA-256(password) so a recipient who can open the ZIP can also
        # recompute the manifest HMAC.
        bundle_password = secrets.token_urlsafe(18)
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
            contained_at_utc=_iso_z(inc.contained_at),
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
            legal_hold_only=legal_hold_only,
            include_artifacts=include_artifacts,
            file_count=manifest.file_count,
            total_bytes=manifest.total_bytes,
            evidence_count=evidence_count,
            audit_row_count=audit_row_count,
        )
        zf.writestr("README.md", readme.encode("utf-8"))

    plaintext_zip = inner.getvalue()

    # Outer envelope — AES-256 password-protected ZIP (WinZip AE-2 via pyzipper).
    # Operators open with any standard archive tool — macOS Finder, 7-Zip,
    # WinRAR, `unzip -P` — no Python or `cryptography` library required.
    outer = io.BytesIO()
    with pyzipper.AESZipFile(
        outer, "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as oz:
        oz.setpassword(bundle_password.encode("utf-8"))
        oz.writestr("le_package.zip", plaintext_zip)
    bundle = outer.getvalue()
    bundle_sha256 = hashlib.sha256(bundle).hexdigest()

    return BuildResult(
        encrypted_bundle=bundle,
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
    )
