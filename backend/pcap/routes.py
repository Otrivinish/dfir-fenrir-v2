"""Per-incident PCAP analysis endpoints.

Mounted at prefix="/api/incidents". Proxies captures to the air-gapped
analysis worker, persists results per-incident, and supports IOC extraction
directly into the incident's IOC list.

G3 (R02) register-first: the raw capture IS an exhibit, kept encrypted at rest and
hashed. An upload is registered as an unsealed draft exhibit first (or linked to
the one active exhibit with the same SHA-256) and that exhibit is analysed;
`from-evidence/{evidence_id}` analyses a registered exhibit (hash re-verified).
Each analysis carries its run record (exhibit, input SHA-256, the analyser name +
version the worker reports, the exhibit's clock offset) and timeline candidates
(conversation first/last seen, DNS queries, HTTP requests, TLS ClientHello SNI,
capture window — pcap epoch times, UTC, offset applied); `promote` copies chosen
candidates onto the Timeline server-side. Analyses before G3 kept no capture.

Route ordering: literal sub-paths (import-iocs) come before parametric ones.
"""
import json
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.worker_client import WORKER_URL, worker_client, worker_headers
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from evidence.register import (EXAMINED_MASTER, EXAMINED_MATCH, EXAMINED_UPLOAD, UPLOAD_ID_DOC, ExhibitInput,
                               examine_audit, exhibit_brief, link_error_extra, read_exhibit_for_analysis,
                               recheck_exhibit, register_or_link_upload, upload_link_for)
from evidence.routes import _check_acquired_at
from forensic.parser import apply_clock_offset
from forensic.routes import clock_offset_fields, exhibit_info
from incidents.access import get_accessible_incident
from models import IOC, Incident, PCAPAnalysis, TimelineEvent, User, utcnow
from pcap.dns_recon import DnsReconResponse, build_recon
from schemas import ForensicImportPromoteResult, PcapAnalysisOut, PcapPromote

router = APIRouter()


# Cap PCAP uploads. Unlike artifacts/evidence this endpoint had no limit, so a
# single large upload (or Content-Length-spoofed chunked body) was an easy OOM.
_MAX_PCAP_BYTES = 500 * 1024 * 1024  # 500 MiB


async def _read_capped(file: UploadFile, cap: int) -> bytes:
    """Read the upload, aborting as soon as it exceeds `cap` — never trusts
    Content-Length and never buffers more than the limit."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > cap:
            raise HTTPException(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                f"PCAP exceeds the {cap // (1024 * 1024)} MiB limit",
            )
        chunks.append(chunk)
    return b"".join(chunks)

# IOC types this endpoint can produce — subset of IocType literal in schemas.py
_ALLOWED_IOC_TYPES = {"ip", "domain", "url"}


class _IocItem(BaseModel):
    type:  str
    value: str
    notes: Optional[str] = None


class _IocImportBody(BaseModel):
    iocs: list[_IocItem]
    # Auto-source tag stamped on every imported IOC. Defaults to ["pcap"]
    # for the standard PCAP "Import IOCs" flow; the DNS Recon view passes
    # ["dns-recon"] so DNS-derived indicators are filterable separately.
    tags_override: Optional[list[str]] = None


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


def _ensure_open(inc: Incident) -> None:
    """409 incident_closed: a closed incident's record is frozen (re-open it first)."""
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")


_CLOSED_409 = {409: {"model": ApiErrorBody, "description": "incident_closed"}}

# ─── G3 run record + timeline candidates ─────────────────────────────────────

# pcap (µs / ns, both byte orders) and pcapng section-header magic: anything else is refused before it
# is registered (nothing stored).
_CAPTURE_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
                  b"\x0a\x0d\x0d\x0a"}
_ANALYSER = "FENRIR PCAP analyser"
_PROMOTE_CHUNK = 900           # timeline rows per INSERT (≈33 binds/row; asyncpg caps a statement at 32767)
_KIND_LABEL = {
    "capture_start": "Capture start", "capture_end": "Capture end",
    "conversation_start": "Conversation first seen", "conversation_end": "Conversation last seen",
    "dns_query": "DNS query", "http_request": "HTTP request", "tls_client_hello": "TLS ClientHello (SNI)",
}


def _is_capture(content: bytes) -> bool:
    return len(content) >= 24 and content[:4] in _CAPTURE_MAGIC


def _epoch_to_utc(epoch) -> Optional[datetime]:
    """A pcap timestamp (epoch seconds as tshark prints frame.time_epoch, up to ns) → UTC datetime,
    microseconds kept (ns truncated). None when absent or not a sane epoch."""
    try:
        d = Decimal(str(epoch))
    except (InvalidOperation, ValueError, TypeError):
        return None
    if not d.is_finite() or d < 0 or d >= 253402300800:      # before 1970 / after 9999
        return None
    sec = int(d)
    return datetime.fromtimestamp(sec, tz=timezone.utc) + timedelta(microseconds=int((d - sec) * 1_000_000))


def _candidates(result: dict, filename: str, offset: Optional[int]) -> list[dict]:
    """The worker's timeline entries → stored timeline candidates. pcap times are UTC epochs as the
    capturing host's clock wrote them (time_basis explicit); the exhibit's clock offset (G4) corrects
    them here, at analysis time, and each keeps `recorded_time`. No epoch → time_basis missing (never
    promoted)."""
    out = []
    for t in result.get("timeline") or []:
        if not isinstance(t, dict):
            continue
        when = _epoch_to_utc(t.get("epoch"))
        kind = str(t.get("kind") or "")
        out.append({
            "event_time": when.isoformat() if when else None,
            "time_basis": "explicit" if when else "missing",
            "kind": kind,
            "event_type": _KIND_LABEL.get(kind, kind or "Network event"),
            "description": str(t.get("summary") or kind or "network event")[:2000],
            "hostname": str(t["src"])[:256] if t.get("src") else None,
            "source": f"PCAP: {filename}"[:128],
            "raw_log": json.dumps(t, default=str)[:4000],
        })
    return apply_clock_offset(out, offset)


async def _run_worker(filename: str, content: bytes) -> dict:
    """Send the capture to the air-gapped analysis worker. ApiError 503 analysis_worker_unavailable,
    502 analysis_worker_error, 422 parse_failed (the worker could not read it)."""
    try:
        async with worker_client(timeout=300) as client:
            resp = await client.post(
                f"{WORKER_URL}/analyze/pcap", headers=worker_headers(),
                files={"file": (filename or "capture.pcap", content, "application/octet-stream")})
    except httpx.ConnectError:
        raise ApiError(status.HTTP_503_SERVICE_UNAVAILABLE, "analysis_worker_unavailable",
                       "Analysis worker unavailable — check fenrir-analysis container")
    except httpx.HTTPError as e:
        raise ApiError(status.HTTP_502_BAD_GATEWAY, "analysis_worker_error",
                       f"Analysis worker error ({type(e).__name__})")
    if not resp.is_success:
        try:
            err = resp.json().get("detail", "Analysis failed")
        except Exception:
            err = f"Analysis worker error ({resp.status_code})"
        raise ApiError(status.HTTP_502_BAD_GATEWAY, "analysis_worker_error", str(err))
    data = resp.json()
    if data.get("error"):
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "parse_failed", str(data["error"]))
    return data


async def _analyse_and_store(db: AsyncSession, inc: Incident, x: ExhibitInput, filename: str, user: User,
                             ip: Optional[str], chunked: tuple = (None, None)) -> PCAPAnalysis:
    """Analyse the exhibit's capture in the worker, store the result with its run record and
    timeline candidates, and write the examination to the exhibit's custody log. `chunked` =
    (upload_id, its link) of the chunked upload the exhibit came from (R93; from-evidence only)."""
    upload_id, upload_link = chunked
    offset = x.evidence.system_time_offset_seconds
    base = {"incident_id": str(inc.id), "tool": _ANALYSER, "version": None,
            "params": {"clock_offset_seconds": offset}}
    try:
        data = await _run_worker(filename, x.data)
    except ApiError as exc:
        await examine_audit(db, user=user, ip=ip, evidence_id=x.evidence.id, outcome="failure",
                            details={**base, "result": exc.code, "error": str(exc.detail)[:500]})
        await db.commit()
        raise ApiError(exc.status_code, exc.code,
                       f"{exc.detail}. The capture is registered as exhibit {x.evidence.identifier}; "
                       "nothing was analysed.", extra=link_error_extra(x)) from exc
    analyser = data.get("analyser") if isinstance(data.get("analyser"), dict) else {}
    name = str(analyser.get("name") or _ANALYSER)[:64]
    version = str(analyser.get("version") or "unversioned")[:32]
    candidates = _candidates(data, filename, offset)
    base = {**base, "tool": name, "version": version}
    if x.link == "from_evidence":       # the decrypt + analysis took a while: re-check under a row lock
        await recheck_exhibit(db, incident_id=inc.id, evidence_id=x.evidence.id, user=user, ip=ip, base=base)

    record = PCAPAnalysis(
        id=uuid.uuid4(), incident_id=inc.id,
        filename=(filename or "capture.pcap")[:512], file_size=len(x.data),
        uploaded_by_id=user.id, uploaded_by=user.username,
        result_json=data,
        evidence_id=x.evidence.id, input_sha256=x.sha256,
        analyser_name=name, analyser_version=version, exhibit_link=upload_link or x.link,
        clock_offset_seconds=offset, timeline_candidates=candidates,
    )
    db.add(record)
    await db.flush()
    await examine_audit(db, user=user, ip=ip, evidence_id=x.evidence.id, details={
        **base, "result": "pcap_analysis", "pcap_analysis_id": str(record.id),
        "engine": analyser.get("engine"),
        "method": {"registered": "upload_registered", "sha256_match": "upload_sha256_match"}.get(x.link, "from_evidence"),
        "examined_on": {"registered": EXAMINED_UPLOAD, "sha256_match": EXAMINED_MATCH}.get(x.link, EXAMINED_MASTER),
        "sha256_verified": x.sha256, "timeline_candidates": len(candidates),
        "untimestamped": sum(1 for c in candidates if c["time_basis"] == "missing")})
    await write_audit(
        db, "pcap_upload",
        user_id=user.id, username=user.username,
        resource_type="pcap_analysis", resource_id=str(record.id),
        details={
            "incident_id": str(inc.id), "filename": record.filename, "file_size": record.file_size,
            "evidence_id": str(x.evidence.id), "evidence_identifier": x.evidence.identifier,
            "exhibit_link": record.exhibit_link, "input_sha256": x.sha256,
            "analyser": name, "analyser_version": version, "clock_offset_seconds": offset,
            "timeline_candidates": len(candidates),
            **({"upload_id": str(upload_id)} if upload_id else {}),
        },
        ip_address=ip,
    )
    await db.commit()
    return record


async def _promoted_indices(db: AsyncSession, analysis_id) -> set:
    return set((await db.execute(select(TimelineEvent.import_event_index)
                                 .where(TimelineEvent.pcap_analysis_id == analysis_id))).scalars().all())


async def _pcap_out(db: AsyncSession, r: PCAPAnalysis) -> dict:
    """The stored worker result plus `result_id` / `filename` / `saved_at` and (G3) the run record and
    the timeline candidates, each with its `idx` and whether it is already on the Timeline."""
    data = dict(r.result_json or {})
    data["result_id"] = str(r.id)
    data["filename"]  = r.filename
    data["saved_at"]  = r.created_at.isoformat()
    brief = await exhibit_brief(db, [r.evidence_id])
    ident, sealed = brief.get(r.evidence_id, (None, None))
    data.update({
        "evidence_id": str(r.evidence_id) if r.evidence_id else None,
        "evidence_identifier": ident, "evidence_sealed": sealed,
        "input_sha256": r.input_sha256, "analyser_name": r.analyser_name,
        "analyser_version": r.analyser_version, "exhibit_link": r.exhibit_link,
    })
    if r.analyser_version:
        data.update(clock_offset_fields(r.evidence_id, r.clock_offset_seconds,
                                        await exhibit_info(db, [r.evidence_id])))
    else:
        data.update({"clock_offset_seconds": None, "clock_offset_status": None,
                     "exhibit_time_offset": None, "exhibit_time_offset_seconds": None})
    if r.timeline_candidates is None:
        data["timeline_candidates"] = None           # analysed before G3: none stored (re-analyse)
    else:
        done = await _promoted_indices(db, r.id)
        data["timeline_candidates"] = [{**c, "idx": i, "promoted": i in done}
                                       for i, c in enumerate(r.timeline_candidates)]
    return data


# ─── List ────────────────────────────────────────────────────────────────────

@router.get("/{incident_id}/pcap", summary="List PCAP analyses")
async def list_pcap(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
):
    """List the incident's saved PCAP analyses (up to 50, newest first).
    Requires access to the incident. Returns a list of summaries (id, filename,
    size, uploader, created_at) plus the run record (G3: exhibit + identifier + draft
    state, input SHA-256, analyser + version, how the exhibit was linked; null before G3)."""
    await _get_incident(db, incident_id, user)
    rows = (
        await db.execute(
            select(PCAPAnalysis)
            .where(PCAPAnalysis.incident_id == incident_id)
            .order_by(PCAPAnalysis.created_at.desc())
            .limit(50)
        )
    ).scalars().all()
    brief = await exhibit_brief(db, [r.evidence_id for r in rows])
    return [
        {
            "id":          str(r.id),
            "filename":    r.filename,
            "file_size":   r.file_size,
            "uploaded_by": r.uploaded_by,
            "created_at":  r.created_at.isoformat(),
            "evidence_id": str(r.evidence_id) if r.evidence_id else None,
            "evidence_identifier": brief.get(r.evidence_id, (None, None))[0],
            "evidence_sealed":     brief.get(r.evidence_id, (None, None))[1],
            "input_sha256":     r.input_sha256,
            "analyser_name":    r.analyser_name,
            "analyser_version": r.analyser_version,
            "exhibit_link":     r.exhibit_link,
            "timeline_candidate_count": len(r.timeline_candidates) if r.timeline_candidates is not None else None,
        }
        for r in rows
    ]


# ─── Upload + Analyze ────────────────────────────────────────────────────────

_ANALYZE_RESPONSES = {
    **_CLOSED_409,
    413: {"description": "larger than 500 MiB"},
    422: {"model": ApiErrorBody, "description": "not_a_capture (not pcap/pcapng: nothing stored), "
          "acquired_in_future, or parse_failed (the capture stays registered: `evidence_id` in the body)"},
    502: {"model": ApiErrorBody, "description": "analysis_worker_error (the capture stays registered)"},
    503: {"model": ApiErrorBody, "description": "analysis_worker_unavailable (the capture stays registered)"},
    507: {"model": ApiErrorBody, "description": "insufficient_storage (the evidence volume or the upload scratch space is full; nothing stored)"},
}


@router.post("/{incident_id}/pcap", status_code=201, response_model=PcapAnalysisOut,
             summary="Register a capture as a draft exhibit and analyze it (multipart; deprecated: use the upload "
                     "session API)",
             responses=_ANALYZE_RESPONSES, deprecated=True)
async def upload_pcap(
    incident_id: uuid.UUID,
    file: UploadFile = File(...),
    acquired_at: Optional[datetime] = Form(default=None, description="When the capture was acquired (UTC; "
                                           "optional, unknown if omitted). Not in the future."),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Deprecated (G1 stage 3b, R80): the whole multipart body is held by the server in its memory-only
    scratch space (tmpfs, 1 GiB shared by every upload and parse; 507 insufficient_storage when full)
    before this route sees it. Use the upload session API instead — POST
    …/uploads (purpose=pcap), PUT the chunks, POST …/uploads/{upload_id}/complete (registers or links
    the exhibit, encrypted as it arrived), then POST …/pcap/from-evidence/{evidence_id}. Kept for API
    compatibility.

    Register-first (G3): a packet capture (pcap / pcapng, max 500 MiB; anything else is 422
    not_a_capture and nothing is stored) is FIRST kept as an exhibit — a new unsealed draft
    (identifier `PCAP-…`, the caller as collector and custodian, `acquired_at` as supplied or
    unknown, lawful basis pending; hashed SHA-256 / SHA-1 / MD5, encrypted at rest, audited
    `evidence_collect`) or the one active exhibit with the same SHA-256 — and then that exhibit is
    analysed by the air-gapped worker. The result is persisted with its run record (`evidence_id`,
    `input_sha256`, `analyser_name` / `analyser_version`, `exhibit_link`, the exhibit's clock offset)
    and `timeline_candidates` (pcap epoch times, UTC, offset applied); the analysis is in the
    exhibit's custody log (`evidence_examine`). If the worker fails the capture stays registered
    (503 / 502 / 422 with `evidence_id`). Requires the analyst role and an open incident (409
    incident_closed). Returns the analysis result JSON with the saved `result_id` and the run record."""
    inc = await _get_incident(db, incident_id, user)
    _ensure_open(inc)
    acquired_at = _check_acquired_at(acquired_at)

    content = await _read_capped(file, _MAX_PCAP_BYTES)
    if not _is_capture(content):
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "not_a_capture",
                       "Not a valid PCAP or PCAPNG file; nothing was stored")
    filename = Path(file.filename or "capture.pcap").name or "capture.pcap"
    ip = request.client.host if request and request.client else None
    x = await register_or_link_upload(
        db, incident_id=incident_id, user=user, data=content, filename=filename,
        mime_type="application/vnd.tcpdump.pcap", prefix="PCAP", name=f"Network capture: {filename}",
        method="pcap_upload", analyser_label="PCAP analyser", acquired_at=acquired_at, ip=ip)
    del content
    await db.commit()                     # registered first: the capture stands even if the analysis fails
    return await _pcap_out(db, await _analyse_and_store(db, inc, x, filename, user, ip))


@router.post("/{incident_id}/pcap/from-evidence/{evidence_id}", status_code=201, response_model=PcapAnalysisOut,
             summary="Analyze a registered exhibit (hash re-verified) as a packet capture",
             responses={
                 404: {"model": ApiErrorBody, "description": "evidence_not_found"},
                 409: {"model": ApiErrorBody, "description": "incident_closed, evidence_not_active, "
                       "evidence_not_in_internal_custody, transfer_pending, evidence_storage_missing or "
                       "evidence_hash_mismatch (the item is frozen: verify_failed)"},
                 413: {"model": ApiErrorBody, "description": "exhibit_too_large_for_analyser (over the 500 MiB "
                       "PCAP limit; checked before anything is decrypted)"},
                 422: {"model": ApiErrorBody, "description": "evidence_not_digital, not_a_capture, parse_failed or "
                       "upload_link_not_found (upload_id)"},
                 502: {"model": ApiErrorBody, "description": "analysis_worker_error"},
                 503: {"model": ApiErrorBody, "description": "evidence_read_error (not frozen) or "
                       "analysis_worker_unavailable"},
             })
async def analyze_pcap_from_evidence(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    request: Request,
    upload_id: Optional[uuid.UUID] = Query(default=None, description=UPLOAD_ID_DOC),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Analyse an exhibit already registered in Evidence (a pcap / pcapng up to 500 MiB) instead of
    re-uploading it — the C5/G4 rules: active, in internal custody, no pending transfer (409
    otherwise; re-checked under a row lock before anything is stored); decrypted and re-hashed off
    the event loop — a mismatch (or a failed AES-GCM tag) freezes the exhibit (409
    evidence_hash_mismatch), an unreadable copy is 503 evidence_read_error. The exhibit's clock
    offset corrects the timeline candidates (each keeps its recorded time). The analysis is in the
    exhibit's custody log (`evidence_examine`). After a chunked upload, pass its `upload_id` so the
    run record keeps the upload's exhibit link (R93). Requires the analyst role and an open incident.
    Returns the analysis (201) as the upload does."""
    inc = await _get_incident(db, incident_id, user)
    _ensure_open(inc)
    upload_link = await upload_link_for(db, upload_id=upload_id, incident_id=incident_id, evidence_id=evidence_id,
                                        purpose="pcap", user=user)
    ip = request.client.host if request.client else None
    base = {"incident_id": str(incident_id), "tool": _ANALYSER, "version": None, "params": {}}
    x = await read_exhibit_for_analysis(db, incident_id=incident_id, evidence_id=evidence_id, user=user, ip=ip,
                                        max_bytes=_MAX_PCAP_BYTES, limit_label="500 MiB PCAP",
                                        phase="pcap_analysis", base=base)
    if not _is_capture(x.data):
        await examine_audit(db, user=user, ip=ip, evidence_id=evidence_id, outcome="failure",
                            details={**base, "result": "not_a_capture", "error": "not pcap / pcapng"})
        await db.commit()
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "not_a_capture",
                       f"Exhibit {x.evidence.identifier} is not a PCAP or PCAPNG file; nothing was analysed")
    await db.commit()                     # end the read transaction before the (long) worker call
    filename = Path(x.evidence.original_filename or "capture.pcap").name or "capture.pcap"
    return await _pcap_out(db, await _analyse_and_store(db, inc, x, filename, user, ip,
                                                        chunked=(upload_id, upload_link)))


# ─── Promote timeline candidates (G3) ─────────────────────────────────────────

@router.post("/{incident_id}/pcap/{result_id}/promote", response_model=ForensicImportPromoteResult,
             summary="Put timeline candidates of a PCAP analysis on the Timeline (server-side copy)",
             responses={404: {"model": ApiErrorBody, "description": "pcap_analysis_not_found"},
                        409: {"model": ApiErrorBody, "description": "incident_closed or reparse_required "
                              "(an analysis made before G3 has no candidates)"},
                        422: {"model": ApiErrorBody, "description": "index_out_of_range"}})
async def promote_pcap_candidates(
    incident_id: uuid.UUID,
    result_id: uuid.UUID,
    req: PcapPromote,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Copy chosen timeline candidates of a stored PCAP analysis (by `idx`) onto the Timeline. The
    server copies them from the run, so every event carries the exhibit (`evidence_id`), the run
    (`pcap_analysis_id`) and the candidate index, `time_basis` explicit and — when the exhibit's clock
    offset corrected it — the recorded time and the offset. Promoted facts are immutable (timeline
    edits → 409 imported_fact_immutable); events are internal-only (`external_safe` false) until
    marked otherwise. A candidate without a time is never placed on the timeline
    (`skipped_untimestamped`); one already promoted from this run is skipped (`already_promoted`,
    re-promoting is a no-op). 409 reparse_required for an analysis made before G3 (no candidates):
    analyse its capture again. Requires the analyst role and an open incident; audited
    `pcap_promote`."""
    _ensure_open(await _get_incident(db, incident_id, user))
    r = (await db.execute(select(PCAPAnalysis).where(          # L28: serialised with delete (row lock)
        PCAPAnalysis.id == result_id, PCAPAnalysis.incident_id == incident_id)
        .with_for_update(of=PCAPAnalysis).execution_options(populate_existing=True))).scalar_one_or_none()
    if not r:
        raise ApiError(status.HTTP_404_NOT_FOUND, "pcap_analysis_not_found", "PCAP analysis not found")
    if r.timeline_candidates is None or r.evidence_id is None:
        raise ApiError(status.HTTP_409_CONFLICT, "reparse_required",
                       "This analysis was made before run records (G3): it has no timeline candidates and "
                       "its capture was not kept. Upload the capture again (it becomes an exhibit).")
    cands = r.timeline_candidates
    bad = sorted({i for i in req.indices if i < 0 or i >= len(cands)})
    if bad:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "index_out_of_range",
                       f"{len(bad)} index(es) are not candidates of this analysis (0..{len(cands) - 1})",
                       extra={"indices": bad[:50]})
    wanted = sorted(set(req.indices))
    already = await _promoted_indices(db, r.id)
    now = utcnow()
    rows, untimed, again = [], [], []
    for i in wanted:
        c = cands[i]
        if i in already:
            again.append(i)
            continue
        if not c.get("event_time") or c.get("time_basis") == "missing":
            untimed.append(i)
            continue
        rows.append({
            "id": uuid.uuid4(), "incident_id": incident_id,
            "event_time": datetime.fromisoformat(c["event_time"]),
            "hostname": c.get("hostname"), "entity_id": None,
            "source": (c.get("source") or "PCAP")[:128], "event_type": (c.get("event_type") or "")[:128] or None,
            "description": (c.get("description") or "").strip() or "network event",
            "raw_log": (c.get("raw_log") or None) and c["raw_log"][:4000],
            "ir_phase": req.ir_phase,
            "mitre_tactic_id": None, "mitre_tactic_name": None,
            "mitre_technique_id": None, "mitre_technique_name": None,
            "origin": "forensic_import", "is_system": False, "system_source": None,
            "external_safe": False, "created_by_id": user.id,
            "evidence_id": r.evidence_id, "forensic_import_id": None, "defender_import_id": None,
            "pcap_analysis_id": r.id, "browser_history_upload_id": None, "source_record_id": None,
            "import_event_index": i, "time_basis": "explicit",
            "recorded_event_time": datetime.fromisoformat(c["recorded_time"]) if c.get("recorded_time") else None,
            "clock_offset_seconds": r.clock_offset_seconds if c.get("recorded_time") else None,
            "created_at": now, "updated_at": now,
        })
    made: list[int] = []
    for start in range(0, len(rows), _PROMOTE_CHUNK):
        res = await db.execute(
            pg_insert(TimelineEvent).values(rows[start:start + _PROMOTE_CHUNK])
            .on_conflict_do_nothing(index_elements=[TimelineEvent.pcap_analysis_id, TimelineEvent.import_event_index],
                                    index_where=TimelineEvent.pcap_analysis_id.isnot(None))
            .returning(TimelineEvent.import_event_index))
        made.extend(res.scalars().all())
    again = sorted(set(again) | ({e["import_event_index"] for e in rows} - set(made)))
    await write_audit(
        db, "pcap_promote",
        user_id=user.id, username=user.username,
        resource_type="pcap_analysis", resource_id=str(r.id),
        details={"incident_id": str(incident_id), "evidence_id": str(r.evidence_id),
                 "analyser_version": r.analyser_version, "clock_offset_seconds": r.clock_offset_seconds,
                 "requested": len(wanted), "created_events": len(made),
                 "skipped_untimestamped": len(untimed), "already_promoted": len(again), "ir_phase": req.ir_phase},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return ForensicImportPromoteResult(created=len(made), created_indices=sorted(made),
                                       skipped_untimestamped=untimed, already_promoted=again)


# ─── Import IOCs (literal before parametric) ─────────────────────────────────

@router.post("/{incident_id}/pcap/{result_id}/import-iocs", status_code=201,
             summary="Import IOCs from a PCAP analysis", responses=_CLOSED_409)
async def import_pcap_iocs(
    incident_id: uuid.UUID,
    result_id: uuid.UUID,
    body: _IocImportBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Import selected indicators (ip, domain, url only) from a saved PCAP
    analysis into the incident's IOC list, deduplicating against existing
    values and tagging them (`pcap` by default, or `tags_override`). IOCs from an
    analysis with a run record (G3) record its exhibit (`evidence_id`). Requires
    the analyst role and an open incident (409 incident_closed otherwise). Returns
    `{imported, skipped_duplicates}`."""
    _ensure_open(await _get_incident(db, incident_id, user))

    r = (
        await db.execute(
            select(PCAPAnalysis).where(
                PCAPAnalysis.id == result_id,
                PCAPAnalysis.incident_id == incident_id,
            )
        )
    ).scalar_one_or_none()
    if not r:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Result not found")

    if not body.iocs:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No IOCs to import")

    # Pre-load existing values for fast dedup
    existing = set(
        row[0]
        for row in (
            await db.execute(select(IOC.value).where(IOC.incident_id == incident_id))
        ).fetchall()
    )

    imported = 0
    skipped  = 0
    auto_tags = body.tags_override if body.tags_override else ["pcap"]
    audit_source = "pcap-analysis" if auto_tags == ["pcap"] else f"pcap-analysis:{auto_tags[0]}"
    exhibit = r.evidence_id if r.input_sha256 else None
    for item in body.iocs:
        ioc_type = (item.type or "").strip()
        value    = (item.value or "").strip()
        notes    = (item.notes or "").strip() or None

        if not value or ioc_type not in _ALLOWED_IOC_TYPES or value in existing:
            skipped += 1
            continue

        # Per-row savepoint (same pattern as iocs/routes.py batch create): a
        # row that loses a race to a concurrent import is skipped without
        # discarding the rows already imported in this request.
        sp = await db.begin_nested()
        try:
            db.add(IOC(
                id=uuid.uuid4(),
                incident_id=incident_id,
                type=ioc_type,
                value=value,
                notes=notes,
                source=audit_source,
                tags=auto_tags,
                added_by_id=user.id,
                evidence_id=exhibit,
            ))
            await db.flush()
            await sp.commit()
            existing.add(value)
            imported += 1
        except IntegrityError:
            await sp.rollback()
            skipped += 1

    await write_audit(
        db,
        "pcap_import_iocs",
        user_id=user.id,
        username=user.username,
        resource_type="pcap_analysis",
        resource_id=str(result_id),
        details={
            "incident_id": str(incident_id),
            "imported": imported,
            "skipped": skipped,
            "evidence_id": str(exhibit) if exhibit else None,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return {"imported": imported, "skipped_duplicates": skipped}


# ─── DNS recon (literal sub-path before parametric /{result_id}) ────────────

@router.get(
    "/{incident_id}/pcap/{result_id}/dns-recon",
    response_model=DnsReconResponse,
    summary="Get DNS recon for a PCAP analysis",
)
async def get_pcap_dns_recon(
    incident_id: uuid.UUID,
    result_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
):
    """Aggregate the saved PCAP's raw DNS queries into a per-domain analyst
    view (query chains, suspicious flags, DGA candidates, top resolvers).
    Pure derivation — no worker round-trip, no extra storage."""
    await _get_incident(db, incident_id, user)
    r = (
        await db.execute(
            select(PCAPAnalysis).where(
                PCAPAnalysis.id == result_id,
                PCAPAnalysis.incident_id == incident_id,
            )
        )
    ).scalar_one_or_none()
    if not r:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Result not found")
    queries = (r.result_json or {}).get("dns_queries", []) or []
    return build_recon(str(r.id), queries)


# ─── Get one ─────────────────────────────────────────────────────────────────

@router.get("/{incident_id}/pcap/{result_id}", summary="Get a PCAP analysis", response_model=PcapAnalysisOut)
async def get_pcap(
    incident_id: uuid.UUID,
    result_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
):
    """Fetch a single saved PCAP analysis by id within the incident, returning
    the full stored result JSON plus `result_id`, `filename`, and `saved_at`, the
    run record (G3) and `timeline_candidates` (each with `idx` and `promoted`;
    null for an analysis made before G3). Requires access to the incident. 404 if
    not found."""
    await _get_incident(db, incident_id, user)
    r = (
        await db.execute(
            select(PCAPAnalysis).where(
                PCAPAnalysis.id == result_id,
                PCAPAnalysis.incident_id == incident_id,
            )
        )
    ).scalar_one_or_none()
    if not r:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Result not found")
    return await _pcap_out(db, r)


# ─── Delete ──────────────────────────────────────────────────────────────────

@router.delete("/{incident_id}/pcap/{result_id}", summary="Delete a PCAP analysis",
               responses={409: {"model": ApiErrorBody, "description": "incident_closed or import_has_promoted_events"}})
async def delete_pcap(
    incident_id: uuid.UUID,
    result_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Delete a saved PCAP analysis by id from the incident (its exhibit stays in
    Evidence). Requires the analyst role and an open incident (409 incident_closed
    otherwise); 409 `import_has_promoted_events` while timeline events promoted from
    it exist (it is their provenance record). Returns `{status: "ok"}`; 404 if not
    found."""
    _ensure_open(await _get_incident(db, incident_id, user))

    r = (
        await db.execute(
            select(PCAPAnalysis).where(
                PCAPAnalysis.id == result_id,
                PCAPAnalysis.incident_id == incident_id,
            ).with_for_update(of=PCAPAnalysis).execution_options(populate_existing=True)   # L28
        )
    ).scalar_one_or_none()
    if not r:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Result not found")
    promoted = (await db.execute(select(func.count()).select_from(TimelineEvent)
                                 .where(TimelineEvent.pcap_analysis_id == r.id))).scalar_one()
    if promoted:
        raise ApiError(status.HTTP_409_CONFLICT, "import_has_promoted_events",
                       f"{promoted} timeline event(s) were promoted from this analysis; it is their "
                       "provenance record and can't be deleted while they exist")

    await write_audit(
        db,
        "pcap_delete",
        user_id=user.id,
        username=user.username,
        resource_type="pcap_analysis",
        resource_id=str(r.id),
        details={"incident_id": str(incident_id), "filename": r.filename,
                 "evidence_id": str(r.evidence_id) if r.evidence_id else None,
                 "input_sha256": r.input_sha256, "analyser_version": r.analyser_version},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(r)
    await db.commit()
    return {"status": "ok"}
