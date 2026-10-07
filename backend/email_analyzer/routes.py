"""U8.1 — Email analyzer routes (offline phishing triage).

Parse + score an email, then route its content into existing subsystems:
  attachments → quarantine Artifact · URLs/IPs/hashes → IOC · hops → Timeline.
Mounted under /api/incidents.

G3 (R02) register-first: the message analysed IS an exhibit. An upload (or pasted source) is
registered as an unsealed draft exhibit first — or linked to the one active exhibit with the same
SHA-256 — and that exhibit is analysed; `from-evidence/{evidence_id}` analyses a registered exhibit
(hash re-verified). No quarantine copy is made; attachment extraction re-reads the exhibit. Each
analysis carries its run record (exhibit, input SHA-256, analyser + version) and is written to the
exhibit's custody log (`evidence_examine`). Analyses made before G3 keep their quarantine copy and
the legacy "Register as exhibit" (mint-evidence).
"""
from __future__ import annotations

import asyncio
import io
import logging
import re
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
import magic
from fastapi import (APIRouter, Depends, File, Form, HTTPException, Query, Request,
                     UploadFile, status)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.config import settings
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from core.outbound_policy import outbound_allowed, require_outbound_confirmation, siem_redaction
from email_analyzer.domain_check import check_dkim, check_spf_dmarc, evaluate_source_ip, fetch_domain_auth
from email_analyzer.parser import (PARSER_NAME, PARSER_VERSION, attachment_bytes, is_msg, msg_to_eml_bytes,
                                   parse_email, repair_wrapped_export)
from email_analyzer.scoring import score as score_email
from artifacts import store as artifact_store
from evidence.crypto import EvidenceCryptoError, awrite_encrypted
from evidence.hashing import ahashes_of, asha256_of
from evidence.streaming import require_free_space
from evidence.register import (EXAMINED_MASTER, EXAMINED_MATCH, EXAMINED_UPLOAD, UPLOAD_ID_DOC, ExhibitInput,
                               examine_audit, exhibit_brief, link_error_extra, read_exhibit_for_analysis,
                               recheck_exhibit, register_or_link_upload, upload_link_for)
from evidence.routes import _check_acquired_at
from incidents.access import get_accessible_incident
from models import Artifact, EmailAnalysis, Evidence, IOC, User, utcnow
from schemas import (DomainCheckOut, EmailAnalysisList, EmailAnalysisOut, EmailBulkAnalyzeOut,
                     HopImportStatus, PromoteIocsRequest)

router = APIRouter()
log = logging.getLogger(__name__)

MAX_EMAIL_BYTES = 25 * 1024 * 1024
MAX_BULK_FILES = 200
MAX_BULK_TOTAL_BYTES = 250 * 1024 * 1024
AUTH_VALIDATE_TIMEOUT = 8.0     # per distinct domain -- a slow/unreachable DNS
                                # server must never block or fail the analysis
_AUTH_CONCURRENCY = 5           # cap concurrent live-DNS lookups within a batch


async def _read_capped(file: UploadFile, cap: int) -> bytes:
    """Read an upload, aborting as soon as it exceeds `cap` -- never trusts
    Content-Length and never buffers more than the limit (mirrors pcap's
    upload guard)."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > cap:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                f"Upload exceeds the {cap // (1024 * 1024)} MiB limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _read_zip_member_capped(zf: zipfile.ZipFile, info: zipfile.ZipInfo, cap: int) -> bytes | None:
    """Stream-decompress one zip member, aborting past `cap` regardless of what
    the archive's own (attacker-controlled) size metadata claims -- the only
    safe way to bound a decompression bomb, since `ZipInfo.file_size` is just
    a declared value in the archive, not a check on the decompressed stream."""
    buf = bytearray()
    with zf.open(info) as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            buf += chunk
            if len(buf) > cap:
                return None
    return bytes(buf)


def _extract_zip_members(data: bytes) -> tuple[list[tuple[str, bytes]], list[str]]:
    """Safely pull .eml/.msg members out of an uploaded zip for bulk import.

    Rejects zip-slip (absolute paths / `..` components), silently-nested
    archives (only .eml/.msg extensions are read at all, so a nested .zip is
    just skipped, never recursed into), and enforces a per-member decompressed
    size cap (via streamed reads, not trusting declared sizes) plus a total
    batch size cap and a member-count cap. Nothing dropped is silent -- every
    exclusion is returned as a human-readable reason.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Not a valid zip file")

    members: list[tuple[str, bytes]] = []
    skipped: list[str] = []
    max_skip_notes = 500   # a hostile zip with millions of junk entries must not

    def note(msg: str) -> None:
        # inflate the response payload one skip-string per entry
        if len(skipped) < max_skip_notes:
            skipped.append(msg)
        elif len(skipped) == max_skip_notes:
            skipped.append(f"... additional skipped entries omitted (over {max_skip_notes})")

    total = 0
    for info in zf.infolist():
        name = info.filename
        if info.is_dir():
            continue
        if len(members) >= MAX_BULK_FILES:
            note(f"stopped after {MAX_BULK_FILES} files -- remaining zip entries not processed")
            break
        if total >= MAX_BULK_TOTAL_BYTES:
            note("stopped -- batch exceeds total size limit; remaining zip entries not processed")
            break
        norm = Path(name.replace("\\", "/"))
        if norm.is_absolute() or ".." in norm.parts:
            note(f"{name}: rejected (path traversal)")
            continue
        if not name.lower().endswith((".eml", ".msg")):
            note(f"{name}: skipped (not .eml/.msg)")
            continue
        payload = _read_zip_member_capped(zf, info, min(MAX_EMAIL_BYTES, MAX_BULK_TOTAL_BYTES - total))
        if payload is None:
            note(f"{name}: skipped (exceeds size limit during extraction)")
            continue
        total += len(payload)
        members.append((name, payload))
    return members, skipped


def _auth_check_domain(parsed: dict) -> str | None:
    """Which domain the automatic SPF/DMARC/DKIM cross-check should target --
    the same domain SPF itself is evaluated against (smtp.mailfrom from
    Authentication-Results), falling back to the envelope/header From when
    that header is missing."""
    auth = parsed.get("auth") or {}
    for candidate in (auth.get("spf_domain"), parsed.get("return_path"), parsed.get("from_addr")):
        if not candidate:
            continue
        domain = candidate.rsplit("@", 1)[-1] if "@" in candidate else candidate
        domain = domain.strip().lower().rstrip(".")
        if domain:
            return domain
    return None


async def _auto_verify_auth(parsed: dict) -> Optional[dict]:
    """Best-effort automatic auth cross-check for a single analyze() call.
    Never raises -- a DNS timeout/error degrades to an 'unavailable' marker
    rather than failing or stalling the analysis."""
    domain = _auth_check_domain(parsed)
    if not domain:
        return None
    try:
        result = await asyncio.wait_for(
            fetch_domain_auth(domain, (parsed.get("auth") or {}).get("dkim_selector")),
            timeout=AUTH_VALIDATE_TIMEOUT,
        )
    except Exception:
        return {"domain": domain, "error": "Live DNS validation timed out or failed."}
    result["ip_in_spf"] = evaluate_source_ip(result["spf"], parsed.get("origin_ip"))
    return result


_SKIP_LABEL = {"dark_operation": "Dark Operation", "tlp_red": "TLP:RED"}


def _lookup_skipped(domain: str, reason: str) -> dict:
    """`auth_verified` for an automatic lookup skipped by the outbound policy (H3:
    Dark Operation or TLP:RED). `error` makes the scorer and the live badges treat
    it as unavailable, like a DNS timeout; `skipped` says why."""
    return {"domain": domain, "skipped": reason,
            "error": f"Live DNS checks skipped — {_SKIP_LABEL.get(reason, reason)}."}


async def _audit_lookups_suppressed(db: AsyncSession, inc, user: User, request: Request, n: int,
                                    reason: str) -> None:
    """One `outbound_lookup_suppressed` audit row per automatic lookup skipped by
    the outbound policy: {kind, reason} only -- never the domain or message
    content. Never raises; a failed write is logged and the lookup stays skipped."""
    try:
        # Savepoint: a failed audit write must not poison the request's transaction.
        async with db.begin_nested():
            for _ in range(n):
                await write_audit(
                    db, "outbound_lookup_suppressed", user_id=user.id, username=user.username,
                    resource_type="incident", resource_id=str(inc.id), resource_label=inc.ref,
                    outcome="success", details={"kind": "email_auth_dns", "reason": reason},
                    ip_address=request.client.host if request.client else None,
                )
    except Exception as exc:  # noqa: BLE001 -- never raise
        log.warning("Outbound policy: email DNS lookups skipped for incident %s; audit row not written (%s)",
                    getattr(inc, "id", "?"), type(exc).__name__)


async def _incident(db, incident_id, user, *, writable=True):
    inc = await get_accessible_incident(db, incident_id, user)
    if writable and inc.status == "closed":
        # R66: every Email Analyzer write changes investigative facts (analyses, IOCs, timeline,
        # quarantine, exhibits), so a closed incident refuses them.
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")
    return inc


_CLOSED_409 = {409: {"model": ApiErrorBody, "description": "incident_closed"}}


async def _get_analysis(db, incident_id, aid, *, for_update=False) -> EmailAnalysis:
    q = select(EmailAnalysis).where(EmailAnalysis.id == aid, EmailAnalysis.incident_id == incident_id)
    if for_update:
        q = q.with_for_update()
    a = (await db.execute(q)).scalar_one_or_none()
    if not a:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Email analysis not found")
    return a


def _hop_time(h: dict):
    """A hop's timestamp when it parses -- only such hops go to the Timeline."""
    from datetime import datetime
    if not h.get("timestamp"):
        return None
    try:
        return datetime.fromisoformat(h["timestamp"])
    except Exception:
        return None


def _event_id(h: dict) -> uuid.UUID | None:
    """The Timeline event an imported hop is marked with, if any."""
    try:
        return uuid.UUID(str(h.get("timeline_event_id")))
    except ValueError:
        return None


async def _live_hop_events(db: AsyncSession, incident_id: uuid.UUID, hops: list) -> set:
    """Ids of the hops' marked Timeline events that still exist."""
    from models import TimelineEvent
    marked = {e for e in map(_event_id, hops) if e}
    if not marked:
        return set()
    return set((await db.execute(
        select(TimelineEvent.id).where(TimelineEvent.incident_id == incident_id,
                                       TimelineEvent.id.in_(marked))
    )).scalars().all())


async def _analysis_out(db: AsyncSession, analysis: EmailAnalysis) -> EmailAnalysisOut:
    """A single analysis plus `hop_import`, the hop counts import_hops itself uses,
    so a client can tell "all on the Timeline" from "some events deleted"."""
    hops = [h for h in (analysis.headers or {}).get("hops") or [] if _hop_time(h)]
    live = await _live_hop_events(db, analysis.incident_id, hops)
    out = _with_exhibit(EmailAnalysisOut.model_validate(analysis), await exhibit_brief(db, [analysis.evidence_id]))
    out.hop_import = HopImportStatus(importable=len(hops),
                                     already_imported=sum(_event_id(h) in live for h in hops))
    return out


def _with_exhibit(out: EmailAnalysisOut, brief: dict) -> EmailAnalysisOut:
    """G3 — the exhibit's identifier and whether it is still an unsealed draft."""
    if out.evidence_id in brief:
        out.evidence_identifier, out.evidence_sealed = brief[out.evidence_id]
    return out


def _prepare(data: bytes, src_name: str) -> tuple[bytes, bool]:
    """The exhibit's bytes → the RFC-822 bytes the analyser reads (the exhibit itself is never
    changed): a JSON-string export is unwrapped, an Outlook .msg converted. ValueError when a .msg
    can't be read. CPU-bound: call via asyncio.to_thread."""
    data = repair_wrapped_export(data)
    if is_msg(data) or (src_name or "").lower().endswith(".msg"):
        try:
            return msg_to_eml_bytes(data), True
        except Exception as e:
            raise ValueError(f"Could not parse .msg file: {e}") from e
    return data, False


def _parse_exhibit(data: bytes, src_name: str) -> tuple[dict, bool]:
    """(parsed, from_msg). CPU-bound over up to 25 MB: call via asyncio.to_thread (never on the loop)."""
    eml, from_msg = _prepare(data, src_name)
    return parse_email(eml), from_msg


def _examine_base(incident_id, **params) -> dict:
    return {"incident_id": str(incident_id), "tool": PARSER_NAME, "version": PARSER_VERSION,
            "params": params}


async def _parse_or_fail(db, x: ExhibitInput, src_name: str, base: dict, user, ip) -> tuple[dict, bool]:
    """Parse the exhibit; on failure record the failed examination in its custody log and return
    422 parse_failed naming the exhibit (an upload stays registered even when its analysis fails)."""
    try:
        return await asyncio.to_thread(_parse_exhibit, x.data, src_name)
    except Exception as exc:  # noqa: BLE001 -- hostile input: any parser error is a parse failure
        msg = str(exc) if isinstance(exc, ValueError) else f"Could not parse the message: {type(exc).__name__}"
        await examine_audit(db, user=user, ip=ip, evidence_id=x.evidence.id, outcome="failure",
                            details={**base, "result": "parse_failed", "error": msg[:500]})
        await db.commit()
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "parse_failed",
                       f"{msg}. The input is registered as exhibit {x.evidence.identifier}; nothing was analysed.",
                       extra=link_error_extra(x)) from exc


def _new_analysis(incident_id, x: ExhibitInput, parsed: dict, verdict: dict, auth_verified, user,
                  batch_id=None, upload_link: Optional[str] = None) -> EmailAnalysis:
    return EmailAnalysis(
        incident_id=incident_id, source_artifact_id=None, batch_id=batch_id,
        evidence_id=x.evidence.id, input_sha256=x.sha256,
        analyser_name=PARSER_NAME, analyser_version=PARSER_VERSION, exhibit_link=upload_link or x.link,
        subject=parsed.get("subject"), from_display=parsed.get("from_display"),
        from_addr=parsed.get("from_addr"), reply_to=parsed.get("reply_to"),
        return_path=parsed.get("return_path"), message_id=parsed.get("message_id"),
        date_hdr=parsed.get("date_hdr"),
        verdict=verdict["verdict"], score=verdict["score"], findings=verdict["findings"],
        headers={
            "hops": parsed.get("hops"), "auth": parsed.get("auth"),
            "notable": parsed.get("notable_headers"),
            "origin_ip": parsed.get("origin_ip"), "x_originating_ip": parsed.get("x_originating_ip"),
        },
        raw_headers=parsed.get("raw_headers"), auth_verified=auth_verified,
        body_text=parsed.get("body_text"), body_html=parsed.get("body_html"),
        urls=parsed.get("urls"), attachments=parsed.get("attachments"),
        created_by_id=user.id, created_by=user.username,
    )


def _examined_on(link: str) -> str:
    return {"registered": EXAMINED_UPLOAD, "sha256_match": EXAMINED_MATCH}.get(link, EXAMINED_MASTER)


async def _audit_examined(db, x: ExhibitInput, analysis: EmailAnalysis, base: dict, from_msg: bool, user, ip) -> None:
    await examine_audit(db, user=user, ip=ip, evidence_id=x.evidence.id, details={
        **base, "result": "email_analysis", "email_analysis_id": str(analysis.id),
        "method": {"registered": "upload_registered", "sha256_match": "upload_sha256_match"}.get(x.link, "from_evidence"),
        "examined_on": _examined_on(x.link), "sha256_verified": x.sha256,
        "verdict": analysis.verdict, "score": analysis.score, "from_msg": from_msg,
    })


def _read_quarantine(src: Artifact) -> bytes:
    """A pre-G3 analysis's quarantined message (H1: either row format, ≤ the 25 MB email cap). 410 when
    the file is gone, 409 artifact_integrity_failed / 503 artifact_read_error (artifacts/store.py)."""
    try:
        return artifact_store.read_all(src, MAX_EMAIL_BYTES)
    except EvidenceCryptoError as e:
        raise artifact_store.read_error(e, missing_status=status.HTTP_410_GONE,
                                        missing_detail="Source message no longer in quarantine") from None


_ANALYZE_RESPONSES = {
    **_CLOSED_409,
    413: {"description": "the message is larger than 25 MB"},
    422: {"model": ApiErrorBody,
          "description": "parse_failed (the input stays registered as a draft exhibit: `evidence_id` + "
                         "`evidence_identifier` in the body), or acquired_in_future"},
    507: {"model": ApiErrorBody, "description": "insufficient_storage (the evidence volume or the upload scratch space is full; nothing stored)"},
}


async def _verify_auth_single(db, inc, parsed: dict, user, request) -> Optional[dict]:
    allowed, reason = outbound_allowed(inc)
    if not allowed:
        domain = _auth_check_domain(parsed)
        auth_verified = _lookup_skipped(domain, reason) if domain else None
        if auth_verified:
            await _audit_lookups_suppressed(db, inc, user, request, 1, reason)
        return auth_verified
    return await _auto_verify_auth(parsed)


async def _analyse_one(db, inc, x: ExhibitInput, src_name: str, user, request,
                       chunked: tuple = (None, None)) -> EmailAnalysis:
    """Analyse one exhibit (already registered / linked / re-verified): parse in a thread, the live
    SPF/DMARC/DKIM cross-check (skipped + audited under Dark Operation or TLP:RED), score, store the analysis
    with its run record and write the examination to the exhibit's custody log. `chunked` = (upload_id,
    its link) of the chunked upload the exhibit came from (R93; from-evidence only)."""
    upload_id, upload_link = chunked
    ip = request.client.host if request.client else None
    base = _examine_base(inc.id, source=src_name)
    parsed, from_msg = await _parse_or_fail(db, x, src_name, base, user, ip)
    auth_verified = await _verify_auth_single(db, inc, parsed, user, request)
    verdict = score_email(parsed, auth_verified)
    if x.link == "from_evidence":
        # the decrypt + parse + DNS took a while: a transfer / dispose / freeze meanwhile wins
        await recheck_exhibit(db, incident_id=inc.id, evidence_id=x.evidence.id, user=user, ip=ip, base=base)
    analysis = _new_analysis(inc.id, x, parsed, verdict, auth_verified, user, upload_link=upload_link)
    db.add(analysis)
    await db.flush()
    await _audit_examined(db, x, analysis, base, from_msg, user, ip)
    await write_audit(
        db, "email_analyze", user_id=user.id, username=user.username,
        resource_type="email_analysis", resource_id=str(analysis.id), outcome="success",
        details={"incident_id": str(inc.id), "verdict": verdict["verdict"],
                 "score": verdict["score"], "from": parsed.get("from_addr"), "from_msg": from_msg,
                 "urls": len(parsed.get("urls") or []), "attachments": len(parsed.get("attachments") or []),
                 "evidence_id": str(x.evidence.id), "evidence_identifier": x.evidence.identifier,
                 "exhibit_link": analysis.exhibit_link, "input_sha256": x.sha256,
                 "analyser": PARSER_NAME, "analyser_version": PARSER_VERSION,
                 **({"upload_id": str(upload_id)} if upload_id else {})},
        ip_address=ip,
    )
    await db.commit()
    return analysis


@router.post("/{incident_id}/email/analyze", response_model=EmailAnalysisOut,
             status_code=status.HTTP_201_CREATED, responses=_ANALYZE_RESPONSES,
             summary="Register an email as a draft exhibit and analyze it for phishing")
async def analyze_email(
    incident_id: uuid.UUID,
    request: Request,
    raw:  Optional[str]        = Form(default=None),
    file: Optional[UploadFile] = File(default=None, deprecated=True,
                                      description="Deprecated (R80: the multipart body is held in the server's memory-only scratch space): "
                                                  "upload a file through the upload session API (purpose=email)"),
    acquired_at: Optional[datetime] = Form(default=None, description="When the message was acquired "
                                           "(UTC; optional, unknown if omitted). Not in the future."),
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> EmailAnalysisOut:
    """Register-first phishing triage (G3). The input — an uploaded .eml/.msg (capped at 25 MB) or
    pasted raw source (form field `raw`) — is FIRST registered as an exhibit, then that exhibit is
    analysed. The `file` part is deprecated (G1 stage 3b, R80: a multipart file is held whole in the
    server's memory-only scratch space first): upload a message with the upload session API (POST
    …/uploads purpose=email, PUT the chunks, POST …/complete), then POST
    …/email/from-evidence/{evidence_id}. Pasted source (`raw`) stays here.

    - a new **unsealed draft exhibit** (identifier `EMAIL-…`, the caller as collector and custodian,
      `acquired_at` as supplied or unknown, lawful basis pending), hashed (SHA-256 / SHA-1 / MD5),
      encrypted at rest and audited `evidence_collect` (method email_upload / email_paste) — complete
      and seal it later in Evidence; or
    - when its SHA-256 equals exactly one active exhibit of the incident, that exhibit (no second copy).

    No quarantine copy is made. Outlook .msg is converted to RFC-822 in memory (the exhibit keeps the
    original bytes). The analysis extracts headers, hops, auth results, URLs and attachments and scores
    them; under Dark Operation or TLP:RED the automatic live SPF/DMARC/DKIM lookup is skipped
    (`auth_verified.skipped`) and audited. The run record (`evidence_id`, `input_sha256`,
    `analyser_name` / `analyser_version`, `exhibit_link`) is on the analysis and the examination is
    in the exhibit's custody log (`evidence_examine`). A message that can't be parsed stays registered:
    422 parse_failed with `evidence_id`. Requires the analyst role and an open incident (409
    incident_closed). Returns the created analysis.
    """
    inc = await _incident(db, incident_id, user)
    acquired_at = _check_acquired_at(acquired_at)
    if file is not None:
        data = await _read_capped(file, MAX_EMAIL_BYTES)
        src_name = Path(file.filename or "message.eml").name or "message.eml"
        method = "email_upload"
    elif raw and raw.strip():
        data = raw.encode("utf-8", "replace")
        src_name = "pasted.eml"
        method = "email_paste"
    else:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Provide raw header text or an .eml file")
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty input")
    if len(data) > MAX_EMAIL_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            f"Message exceeds {MAX_EMAIL_BYTES} bytes")
    ip = request.client.host if request.client else None
    x = await register_or_link_upload(
        db, incident_id=incident_id, user=user, data=data, filename=src_name,
        mime_type="application/vnd.ms-outlook" if is_msg(data) else "message/rfc822",
        prefix="EMAIL", name=("Email message (pasted source)" if method == "email_paste"
                              else f"Email message: {src_name}"),
        method=method, analyser_label="Email analyser", acquired_at=acquired_at, ip=ip)
    await db.commit()                     # registered first: the exhibit stands even if the analysis fails
    return await _analysis_out(db, await _analyse_one(db, inc, x, src_name, user, request))


@router.post("/{incident_id}/email/from-evidence/{evidence_id}", response_model=EmailAnalysisOut,
             status_code=status.HTTP_201_CREATED,
             summary="Analyze a registered exhibit (hash re-verified) as an email",
             responses={
                 404: {"model": ApiErrorBody, "description": "evidence_not_found"},
                 409: {"model": ApiErrorBody, "description": "incident_closed, evidence_not_active, "
                       "evidence_not_in_internal_custody, transfer_pending, evidence_storage_missing or "
                       "evidence_hash_mismatch (the item is frozen: verify_failed)"},
                 413: {"model": ApiErrorBody, "description": "exhibit_too_large_for_analyser (over the 25 MB "
                       "email limit; checked before anything is decrypted)"},
                 422: {"model": ApiErrorBody, "description": "evidence_not_digital, evidence_is_archive, "
                       "parse_failed or upload_link_not_found (upload_id)"},
                 503: {"model": ApiErrorBody, "description": "evidence_read_error (stored copy unreadable; not frozen)"},
             })
async def analyze_email_from_evidence(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    request: Request,
    upload_id: Optional[uuid.UUID] = Query(default=None, description=UPLOAD_ID_DOC),
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> EmailAnalysisOut:
    """Analyse an exhibit already registered in Evidence (an .eml or Outlook .msg, up to 25 MB)
    instead of re-uploading it — the C5/G4 rules: the exhibit must be an active digital file of this
    incident, held by an internal custodian, with no custody transfer pending (409 otherwise; checked
    again under a row lock before anything is stored). Its encrypted master is decrypted into memory
    and re-hashed off the event loop; a SHA-256 mismatch (or a failed AES-GCM tag) freezes it
    (`verify_failed`, audited `evidence_verify_failed`) → 409 evidence_hash_mismatch; an unreadable
    copy is 503 evidence_read_error (not frozen). The analysis is recorded in the exhibit's custody
    log (`evidence_examine`, tool = the analyser + version). Dark Operation and scoring as the upload.
    After a chunked upload, pass its `upload_id` so the run record keeps the upload's exhibit link
    (R93). The read transaction ends before the parse and the DNS cross-check (L24).
    Requires the analyst role and an open incident. Returns the analysis (201) with its run record.
    """
    inc = await _incident(db, incident_id, user)
    upload_link = await upload_link_for(db, upload_id=upload_id, incident_id=incident_id, evidence_id=evidence_id,
                                        purpose="email", user=user)
    ip = request.client.host if request.client else None
    base = _examine_base(incident_id)
    x = await read_exhibit_for_analysis(db, incident_id=incident_id, evidence_id=evidence_id, user=user, ip=ip,
                                        max_bytes=MAX_EMAIL_BYTES, limit_label="25 MB email",
                                        phase="email_analysis", base=base)
    src_name = Path(x.evidence.original_filename or "message.eml").name or "message.eml"
    if x.data[:4] == b"PK\x03\x04":
        await examine_audit(db, user=user, ip=ip, evidence_id=evidence_id, outcome="failure",
                            details={**base, "result": "evidence_is_archive", "error": "a ZIP archive"})
        await db.commit()
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "evidence_is_archive",
                       "The exhibit is a ZIP archive, not a message. Analyse each .eml/.msg it holds: "
                       "upload them (each becomes its own exhibit).")
    await db.commit()                     # L24: end the read transaction before the parse + DNS cross-check
    return await _analysis_out(db, await _analyse_one(db, inc, x, src_name, user, request,
                                                      chunked=(upload_id, upload_link)))


@router.post("/{incident_id}/email/analyze-bulk", response_model=EmailBulkAnalyzeOut,
             status_code=status.HTTP_201_CREATED, responses=_CLOSED_409,
             summary="Register and bulk-analyze multiple emails")
async def analyze_email_bulk(
    incident_id: uuid.UUID,
    request: Request,
    files: list[UploadFile] = File(...),
    acquired_at: Optional[datetime] = Form(default=None, description="When the messages were acquired "
                                           "(UTC; optional). Not in the future."),
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> EmailBulkAnalyzeOut:
    """Analyze many emails in one batch: either multiple .eml/.msg uploads, or a single .zip
    containing them. (R80: like every multipart upload the batch is held whole in the server's
    memory-only scratch space before this route sees it, never on a disk; single messages can use the
    upload session API instead.)

    Register-first (G3): every message is FIRST registered as its own unsealed draft exhibit (or
    linked to the one active exhibit with the same SHA-256), then analysed — one exhibit per message,
    no quarantine copies. A .zip is a container only: its members are registered (each exhibit's
    `evidence_collect` audit records the archive name and SHA-256); the archive itself is not stored.
    Each message runs through the same offline parse+score pipeline as a single analyze, tagged with
    a shared batch_id so the history view can be filtered to this run. Live SPF/DMARC/DKIM validation
    is looked up once per distinct sender domain in the batch, concurrently with a capped timeout.
    Nothing is silently dropped -- oversized/invalid members are reported back as `skipped`/`errors`
    (a message that fails to parse stays registered; its error names the exhibit). Requires the
    analyst role and an open incident. Under Dark Operation the live lookups are skipped and audited.
    """
    inc = await _incident(db, incident_id, user)
    acquired_at = _check_acquired_at(acquired_at)
    if len(files) > MAX_BULK_FILES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            f"Batch exceeds {MAX_BULK_FILES} files")

    items: list[tuple[str, bytes]] = []
    skipped: list[str] = []
    container: dict = {}
    if len(files) == 1 and (files[0].filename or "").lower().endswith(".zip"):
        zdata = await _read_capped(files[0], MAX_BULK_TOTAL_BYTES)
        container = {"container": Path(files[0].filename or "batch.zip").name,
                     "container_sha256": await asha256_of(zdata)}
        items, skipped = await asyncio.to_thread(_extract_zip_members, zdata)
        del zdata
    else:
        total = 0
        for f in files:
            name = f.filename or "message.eml"
            if not name.lower().endswith((".eml", ".msg")):
                skipped.append(f"{name}: skipped (not .eml/.msg)")
                continue
            remaining = MAX_BULK_TOTAL_BYTES - total
            if remaining <= 0:
                skipped.append(f"{name}: skipped (batch exceeds total size limit)")
                continue
            try:
                data = await _read_capped(f, min(MAX_EMAIL_BYTES, remaining))
            except HTTPException:
                skipped.append(f"{name}: skipped (exceeds size limit)")
                continue
            if not data:
                skipped.append(f"{name}: skipped (empty file)")
                continue
            total += len(data)
            items.append((name, data))

    if not items:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No valid .eml/.msg files in the upload")

    ip = request.client.host if request.client else None
    batch_id = uuid.uuid4()
    # Register first: every message becomes (or links to) an exhibit before anything is analysed. Each
    # registration commits on its own (review H1): its evidence_collect audit row takes the audit-chain
    # lock, which must not be held while the next message is hashed and encrypted.
    registered: list[tuple[str, ExhibitInput]] = []
    for name, data in items:
        src_name = Path(name.replace("\\", "/")).name or "message.eml"
        extra = {**container, "member": name, "batch_id": str(batch_id)} if container else {"batch_id": str(batch_id)}
        x = await register_or_link_upload(
            db, incident_id=incident_id, user=user, data=data, filename=src_name,
            mime_type="application/vnd.ms-outlook" if is_msg(data) else "message/rfc822",
            prefix="EMAIL", name=f"Email message: {src_name}", method="email_upload",
            analyser_label="Email analyser (bulk)", acquired_at=acquired_at, ip=ip, extra=extra)
        await db.commit()
        registered.append((src_name, x))
    del items

    parsed_items: list[tuple[str, dict, ExhibitInput, bool, dict]] = []
    errors: list[str] = []
    for src_name, x in registered:
        base = _examine_base(incident_id, source=src_name, batch_id=str(batch_id))
        try:
            parsed, from_msg = await asyncio.to_thread(_parse_exhibit, x.data, src_name)
        except Exception as e:  # noqa: BLE001 -- hostile input
            msg = str(e) if isinstance(e, ValueError) else f"parse failed ({type(e).__name__})"
            await examine_audit(db, user=user, ip=ip, evidence_id=x.evidence.id, outcome="failure",
                                details={**base, "result": "parse_failed", "error": msg[:500]})
            errors.append(f"{src_name}: {msg} (registered as {x.evidence.identifier})")
            continue
        parsed_items.append((src_name, parsed, x, from_msg, base))
    if errors:
        await db.commit()       # H1: release the audit-chain lock (parse-failure rows) before the DNS phase

    # One live-DNS fetch per distinct claimed domain across the whole batch.
    domains = {d for d in (_auth_check_domain(p) for _, p, _, _, _ in parsed_items) if d}
    sem = asyncio.Semaphore(_AUTH_CONCURRENCY)

    async def _fetch(domain: str) -> tuple[str, dict]:
        async with sem:
            try:
                result = await asyncio.wait_for(fetch_domain_auth(domain, None), timeout=AUTH_VALIDATE_TIMEOUT)
            except Exception:
                result = {"domain": domain, "error": "Live DNS validation timed out or failed."}
            return domain, result

    allowed, reason = outbound_allowed(inc)
    dark = not allowed
    if dark:
        domain_cache = {d: _lookup_skipped(d, reason) for d in domains}
    else:
        domain_cache = dict(await asyncio.gather(*(_fetch(d) for d in domains))) if domains else {}

    created: list[EmailAnalysis] = []
    for src_name, parsed, x, from_msg, base in parsed_items:
        domain = _auth_check_domain(parsed)
        cached = domain_cache.get(domain) if domain else None
        auth_verified = None
        if cached is not None:
            auth_verified = cached if cached.get("error") else {
                **cached, "ip_in_spf": evaluate_source_ip(cached["spf"], parsed.get("origin_ip")),
            }
        verdict = score_email(parsed, auth_verified)
        analysis = _new_analysis(incident_id, x, parsed, verdict, auth_verified, user, batch_id=batch_id)
        db.add(analysis)
        await db.flush()
        await _audit_examined(db, x, analysis, base, from_msg, user, ip)
        created.append(analysis)

    if dark and domains:
        await _audit_lookups_suppressed(db, inc, user, request, len(domains), reason)
    await write_audit(
        db, "email_analyze_bulk", user_id=user.id, username=user.username,
        resource_type="email_analysis", resource_id=str(batch_id), outcome="success",
        details={"incident_id": str(incident_id), "batch_id": str(batch_id),
                 "analyzed": len(created), "skipped": len(skipped), "errors": len(errors),
                 "from_msg_count": sum(1 for *_, fm, _b in parsed_items if fm),
                 "exhibits_registered": sum(1 for _, x in registered if x.link == "registered"),
                 "exhibits_linked": sum(1 for _, x in registered if x.link == "sha256_match"),
                 "analyser": PARSER_NAME, "analyser_version": PARSER_VERSION, **container},
        ip_address=ip,
    )
    await db.commit()

    return EmailBulkAnalyzeOut(
        batch_id=str(batch_id),
        analyzed=[await _analysis_out(db, a) for a in created],
        skipped=skipped, errors=errors,
    )


@router.get("/{incident_id}/email", response_model=EmailAnalysisList,
            summary="List email analyses for an incident")
async def list_email_analyses(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db:   AsyncSession = Depends(get_db),
) -> EmailAnalysisList:
    """List all email analyses for an incident, newest first.

    Requires access to the incident. Returns each analysis with its verdict, score,
    headers, URLs, and attachments, plus its run record (G3: exhibit, input SHA-256, analyser).
    """
    await _incident(db, incident_id, user, writable=False)
    rows = (await db.execute(
        select(EmailAnalysis).where(EmailAnalysis.incident_id == incident_id)
        .order_by(EmailAnalysis.created_at.desc())
    )).scalars().all()
    brief = await exhibit_brief(db, [r.evidence_id for r in rows])
    return EmailAnalysisList(items=[_with_exhibit(EmailAnalysisOut.model_validate(r), brief) for r in rows])


# ─── Domain auth check (manual mode) ─────────────────────────────────────────
# Registered before the parametric GET /{incident_id}/email/{aid} below --
# {aid} is typed as a UUID path param, but Starlette matches routes in
# registration order regardless of type converters, so a literal path
# segment sharing this shape must come first or it gets swallowed by {aid}
# and 422s on UUID parsing. Same class of ordering bug the correlations
# router already has a comment about, for the same underlying reason.

@router.get("/{incident_id}/email/domain-check", response_model=DomainCheckOut,
            summary="Live SPF/DMARC check for a domain, optional DKIM selector",
            responses={409: {"model": ApiErrorBody, "description": "outbound_confirmation_required "
                             "(Dark Operation or TLP:RED incident; body has `reason`)"}})
async def domain_check(
    incident_id: uuid.UUID,
    request: Request,
    domain: str = Query(..., min_length=1, max_length=253),
    selector: Optional[str] = Query(default=None, max_length=63),
    confirm_outbound: bool = Query(default=False, description="Required (true) on a Dark Operation "
                                   "or TLP:RED incident: the lookup leaves the platform. Audited."),
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> DomainCheckOut:
    """Live-check a domain's SPF and DMARC records via DNS (no key required).
    DKIM is only checked if a `selector` is supplied -- it cannot be
    discovered from a bare domain, so manual mode requires one rather than
    guessing. Read-only: works on a closed incident. Audited (domain +
    whether a selector was checked, not the DNS response content).
    On a Dark Operation or TLP:RED incident: 409 outbound_confirmation_required
    unless `confirm_outbound=true`; a confirmed check is also audited as
    `outbound_manual_lookup` (no domain in that row).
    """
    inc = await _incident(db, incident_id, user, writable=False)
    domain = domain.strip().lower().lstrip("*.")
    await require_outbound_confirmation(db, inc, confirm=confirm_outbound, kind="email_domain_check",
                                        user=user, request=request, providers=["dns.google"], ioc_type="domain")

    try:
        result = await check_spf_dmarc(domain)
    except httpx.HTTPStatusError as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"DNS lookup failed: HTTP {e.response.status_code}")
    except httpx.TimeoutException:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "DNS lookup timed out")

    dkim = None
    if selector:
        try:
            dkim = await check_dkim(domain, selector.strip())
        except (httpx.HTTPStatusError, httpx.TimeoutException):
            dkim = {"found": False, "selector": selector, "verdict": "DKIM lookup failed (DNS error)."}

    await write_audit(
        db, "email_domain_check",
        user_id=user.id, username=user.username,
        resource_type="domain", resource_id=domain,
        details={"incident_id": str(incident_id), "selector_checked": bool(selector)},
        ip_address=request.client.host if request.client else None,
        siem_redact=siem_redaction(inc),
    )
    await db.commit()

    return DomainCheckOut(domain=domain, spf=result["spf"], dmarc=result["dmarc"], dkim=dkim)


@router.get("/{incident_id}/email/{aid}", response_model=EmailAnalysisOut,
            summary="Get a single email analysis")
async def get_email_analysis(
    incident_id: uuid.UUID, aid: uuid.UUID,
    user: User = Depends(current_user), db: AsyncSession = Depends(get_db),
) -> EmailAnalysisOut:
    """Retrieve a single email analysis by id.

    Requires access to the incident. Returns 404 if the analysis does not belong to that
    incident, otherwise the full analysis record.
    """
    await _incident(db, incident_id, user, writable=False)
    return await _analysis_out(db, await _get_analysis(db, incident_id, aid))


@router.post("/{incident_id}/email/{aid}/promote-iocs", response_model=EmailAnalysisOut,
             summary="Promote email indicators to IOCs", responses=_CLOSED_409)
async def promote_iocs(
    incident_id: uuid.UUID, aid: uuid.UUID, req: PromoteIocsRequest, request: Request,
    user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db),
) -> EmailAnalysisOut:
    """Promote selected indicators from an email analysis into incident IOCs.

    Takes a list of typed indicators (ip, domain, url, hash_*, email, registry_key,
    file_path, other); unknown types and existing duplicates are skipped. IOCs from an analysis with a
    run record (G3) record its exhibit (`evidence_id`). Each `urls[]` row whose URL (its Safelink
    target when it has one) is now a URL IOC of the incident, new or existing, gets
    `promoted_ioc_id`. Requires the analyst role and an open incident. Returns the email analysis.
    """
    await _incident(db, incident_id, user)
    analysis = await _get_analysis(db, incident_id, aid)
    valid = {"ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256",
             "email", "registry_key", "file_path", "other"}
    created = 0
    url_iocs: dict[str, str] = {}      # K5 (R49): URL value -> its IOC id, for urls[].promoted_ioc_id
    for item in req.iocs:
        if item.type not in valid:
            continue
        exists = (await db.execute(select(IOC).where(
            IOC.incident_id == incident_id, IOC.type == item.type, IOC.value == item.value,
        ))).scalar_one_or_none()
        if exists:
            if item.type == "url":
                url_iocs[item.value] = str(exists.id)
            continue
        ioc = IOC(id=uuid.uuid4(), incident_id=incident_id, type=item.type, value=item.value,
                  notes=item.notes or f"From email analysis {aid}", source="email-analysis",
                  tags=["email"], added_by_id=user.id,
                  # G3 — found in the exhibit this run analysed (none for a pre-G3 analysis)
                  evidence_id=analysis.evidence_id if analysis.input_sha256 else None)
        db.add(ioc)
        if item.type == "url":
            url_iocs[item.value] = str(ioc.id)
        created += 1
    # A URL row is promoted when its value (the Safelink target when there is one, as the UI
    # sends) is a URL IOC of this incident. A new list, so the JSON column is written.
    if url_iocs:
        analysis.urls = [({**u, "promoted_ioc_id": url_iocs[k]}
                          if (k := (u.get("safelink_target") or u.get("url"))) in url_iocs else u)
                         for u in (analysis.urls or [])]
    await write_audit(db, "email_promote_iocs", user_id=user.id, username=user.username,
                      resource_type="email_analysis", resource_id=str(aid), outcome="success",
                      details={"incident_id": str(incident_id), "created": created},
                      ip_address=request.client.host if request.client else None)
    await db.commit()
    return await _analysis_out(db, analysis)


@router.post("/{incident_id}/email/{aid}/attachments/{idx}/extract", response_model=EmailAnalysisOut,
             summary="Extract an email attachment to quarantine",
             responses={**_CLOSED_409,
                        409: {"model": ApiErrorBody, "description": "incident_closed, or (G3, the analysed "
                              "exhibit) evidence_not_active, evidence_not_in_internal_custody, transfer_pending "
                              "or evidence_hash_mismatch (frozen)"},
                        503: {"model": ApiErrorBody, "description": "evidence_read_error"}})
async def extract_attachment(
    incident_id: uuid.UUID, aid: uuid.UUID, idx: int, request: Request,
    user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db),
) -> EmailAnalysisOut:
    """Extract one attachment (by index) from the analyzed email into a quarantine artifact.

    The message is read from the exhibit the analysis ran on (G3: decrypted and re-hashed first, the
    same rules as from-evidence — a mismatch freezes the exhibit, 409; the extraction is written to
    its custody log as `evidence_examine`), or, for an analysis made before G3, from its quarantine
    copy. Writes the attachment as a new artifact with detected MIME type and hashes, and
    auto-creates dedup SHA-256/MD5 IOCs (recording the exhibit when there is one). Fails if the index
    is out of range, the attachment was already extracted, or the source message is gone. Requires
    the analyst role and an open incident. Returns the email analysis.
    """
    await _incident(db, incident_id, user)
    analysis = await _get_analysis(db, incident_id, aid)
    atts = list(analysis.attachments or [])
    if idx < 0 or idx >= len(atts):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Attachment index out of range")
    if atts[idx].get("artifact_id"):
        raise HTTPException(status.HTTP_409_CONFLICT, "Attachment already extracted")
    ip = request.client.host if request.client else None
    run = bool(analysis.input_sha256 and analysis.evidence_id)
    x = None
    if run:
        # G3 — no quarantine copy: re-read (and re-verify) the exhibit this analysis ran on.
        base = _examine_base(incident_id, attachment_index=idx, email_analysis_id=str(aid))
        x = await read_exhibit_for_analysis(db, incident_id=incident_id, evidence_id=analysis.evidence_id,
                                            user=user, ip=ip, max_bytes=MAX_EMAIL_BYTES,
                                            limit_label="25 MB email", phase="email_attachment_extract", base=base)
        src_name = x.evidence.original_filename or "message.eml"
        raw, _from_msg = await asyncio.to_thread(_prepare, x.data, src_name)
    else:
        if not analysis.source_artifact_id:
            raise HTTPException(status.HTTP_410_GONE, "Source message unavailable")
        src = (await db.execute(select(Artifact).where(Artifact.id == analysis.source_artifact_id))).scalar_one_or_none()
        if not src:
            raise HTTPException(status.HTTP_410_GONE, "Source message artifact missing")
        raw = await asyncio.to_thread(_read_quarantine, src)
    try:
        filename, _declared, data = await asyncio.to_thread(attachment_bytes, raw, idx)
    except IndexError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Attachment not found in the message")
    del raw
    if run:
        await recheck_exhibit(db, incident_id=incident_id, evidence_id=analysis.evidence_id, user=user,
                              ip=ip, base=base)

    art_id = uuid.uuid4()
    stored = artifact_store.stored_name(art_id, filename)
    require_free_space(len(data), "this attachment", root=settings.quarantine_path)   # 507, nothing stored
    sf, tap = await artifact_store.awrite(data, incident_id, stored)    # H1: encrypted at rest
    md5, sha256, sha512 = sf.md5, sf.sha256, tap.sha512.hexdigest()
    db.add(Artifact(
        id=art_id, incident_id=incident_id, original_filename=filename, stored_filename=stored,
        file_size=sf.size, mime_type=magic.from_buffer(tap.head, mime=True), nonce_hex=sf.nonce_hex,
        md5_hash=md5, sha256_hash=sha256, sha512_hash=sha512,
        description=f"Email attachment from analysis {aid}",
        analysis_status="pending", analysis_results={},
        uploaded_by_id=user.id, uploaded_by=user.username,
    ))
    # Auto-create hash IOCs (dedup), mirroring artifact upload.
    for value, t in [(sha256, "hash_sha256"), (md5, "hash_md5")]:
        exists = (await db.execute(select(IOC).where(
            IOC.incident_id == incident_id, IOC.type == t, IOC.value == value))).scalar_one_or_none()
        if not exists:
            db.add(IOC(incident_id=incident_id, type=t, value=value,
                       notes=f"Auto-extracted from email attachment: {filename}",
                       source="email-analysis", tags=["email", "attachment"], added_by_id=user.id,
                       evidence_id=analysis.evidence_id if run else None))

    atts[idx] = {**atts[idx], "artifact_id": str(art_id)}
    analysis.attachments = atts
    if run:
        await db.flush()
        await examine_audit(db, user=user, ip=ip, evidence_id=analysis.evidence_id, details={
            **base, "result": "email_attachment_extracted", "examined_on": EXAMINED_MASTER,
            "sha256_verified": x.sha256, "artifact_id": str(art_id), "filename": filename,
            "attachment_sha256": sha256})
    await write_audit(db, "email_extract_attachment", user_id=user.id, username=user.username,
                      resource_type="email_analysis", resource_id=str(aid), outcome="success",
                      details={"incident_id": str(incident_id), "artifact_id": str(art_id),
                               "filename": filename, "sha256": sha256,
                               "evidence_id": str(analysis.evidence_id) if run else None},
                      ip_address=ip)
    await db.commit()
    return await _analysis_out(db, analysis)


@router.post("/{incident_id}/email/{aid}/import-hops", response_model=EmailAnalysisOut,
             summary="Import mail relay hops to the timeline", responses=_CLOSED_409)
async def import_hops(
    incident_id: uuid.UUID, aid: uuid.UUID, request: Request,
    user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db),
) -> EmailAnalysisOut:
    """Import the email's Received (relay hop) chain as timeline events.

    Each parsed hop with a valid timestamp becomes a Detection & Analysis phase event
    sourced from "email"; hops without a usable timestamp are skipped. Idempotent: each
    imported hop records its `timeline_event_id`, and hops whose event still exists are
    skipped, so a repeat call adds only hops whose event was deleted. For an analysis with a
    run record (G3) each event records the exhibit, the analysis (`email_analysis_id`, its run) and a
    `time_basis` (explicit; assumed_tz for a zone-less date, read as UTC), so its facts are immutable;
    no clock offset is applied (relay
    times come from the mail servers). Requires the analyst role and an open incident. Returns the
    email analysis; its `hop_import` counts importable hops and those already on the Timeline.
    """
    from models import TimelineEvent
    await _incident(db, incident_id, user)
    # Row lock: two concurrent imports of the same analysis serialise here, so the
    # second sees the first one's markers instead of importing the hops again.
    analysis = await _get_analysis(db, incident_id, aid, for_update=True)

    headers = analysis.headers or {}
    hops = [dict(h) for h in headers.get("hops") or []]
    live = await _live_hop_events(db, incident_id, hops)
    run = bool(analysis.input_sha256 and analysis.evidence_id)
    n = 0
    already = 0
    for h in hops:
        et = _hop_time(h)
        if et is None:
            continue
        if _event_id(h) in live:
            already += 1
            continue
        desc = f"Mail hop: {h.get('from') or '?'} → {h.get('by') or '?'}"
        if h.get("ip"):
            desc += f" [{h['ip']}]"
        ev_id = uuid.uuid4()
        # raw_log keeps the parsed hop exactly as before (without the new marker)
        raw = {k: v for k, v in h.items() if k != "timeline_event_id"}
        prov = {}
        if run:
            # G3 — a run-record analysis: the event carries its exhibit and how its time was worked
            # out, so its facts are immutable like other imports. Received-header times are written
            # by the mail servers, so the exhibit's device clock offset does not apply.
            prov = {"evidence_id": analysis.evidence_id, "email_analysis_id": analysis.id,      # L26: the run
                    "time_basis": "explicit" if et.tzinfo is not None else "assumed_tz"}
            if et.tzinfo is None:
                et = et.replace(tzinfo=timezone.utc)
        db.add(TimelineEvent(
            id=ev_id, incident_id=incident_id, event_time=et, source="email",
            event_type="Mail relay hop", hostname=h.get("by"),
            description=desc, raw_log=str(raw)[:4000], ir_phase="detection_and_analysis",
            origin="forensic_import", external_safe=False, created_by_id=user.id, **prov,
        ))
        h["timeline_event_id"] = str(ev_id)
        n += 1
    if n:
        # New list of new dicts, reassigned: the JSON column change is detected.
        analysis.headers = {**headers, "hops": hops}
    await write_audit(db, "email_import_hops", user_id=user.id, username=user.username,
                      resource_type="email_analysis", resource_id=str(aid), outcome="success",
                      details={"incident_id": str(incident_id), "events": n,
                               "already_imported": already,
                               "evidence_id": str(analysis.evidence_id) if run else None},
                      ip_address=request.client.host if request.client else None)
    await db.commit()
    return await _analysis_out(db, analysis)


@router.post("/{incident_id}/email/{aid}/mint-evidence", response_model=EmailAnalysisOut,
             operation_id="mint_email_evidence",
             summary="Register a pre-G3 analysis's email as an exhibit (legacy)",
             responses={409: {"model": ApiErrorBody,
                              "description": "artifact_hash_mismatch (or already minted), or "
                                             "incident_closed"},
                        507: {"model": ApiErrorBody, "description": "insufficient_storage (the evidence volume is full; nothing stored)"}})
async def mint_evidence(
    incident_id: uuid.UUID, aid: uuid.UUID, request: Request,
    user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db),
) -> EmailAnalysisOut:
    """Register the analyzed email's raw message as an encrypted chain-of-custody exhibit — for an
    analysis made BEFORE G3 only (it analysed a quarantine copy first). A G3 analysis already is
    of an exhibit (`evidence_id` set): 409.

    Reads the source message from quarantine and re-hashes it: if its SHA-256 no longer
    matches the hash recorded at upload, nothing is minted (409 `artifact_hash_mismatch`,
    audited as `evidence_collect_rejected`). Otherwise writes it AES-encrypted to evidence
    storage, records hashes, custody (collector/custodian = caller) and `acquired_at` = the
    upload time, audits `evidence_collect` (details.method = email_mint), and links the
    evidence to the analysis. Fails if already minted or the source message is unavailable.
    Requires the analyst role and an open incident. Returns the email analysis.
    """
    await _incident(db, incident_id, user)
    analysis = await _get_analysis(db, incident_id, aid)
    if analysis.evidence_id:
        raise ApiError(status.HTTP_409_CONFLICT, "already_minted", "Already minted as evidence")
    if not analysis.source_artifact_id:
        raise HTTPException(status.HTTP_410_GONE, "Source message unavailable")
    src = (await db.execute(select(Artifact).where(Artifact.id == analysis.source_artifact_id))).scalar_one_or_none()
    if not src:
        raise HTTPException(status.HTTP_410_GONE, "Source message artifact missing")
    raw = await asyncio.to_thread(_read_quarantine, src)
    sha256, sha1, md5 = await ahashes_of(raw)
    # C3 — the quarantined copy must still be the bytes hashed at upload.
    if sha256 != (src.sha256_hash or "").lower():
        await write_audit(db, "evidence_collect_rejected", user_id=user.id, username=user.username,
                          resource_type="evidence", outcome="failure",
                          details={"incident_id": str(incident_id), "method": "email_mint",
                                   "email_analysis_id": str(aid), "artifact_id": str(src.id),
                                   "reason": "artifact_hash_mismatch",
                                   "recorded_sha256": src.sha256_hash, "computed_sha256": sha256},
                          ip_address=request.client.host if request.client else None)
        await db.commit()
        raise ApiError(status.HTTP_409_CONFLICT, "artifact_hash_mismatch",
                       "The stored message no longer matches the SHA-256 recorded when it was "
                       "uploaded; it was not minted as evidence.")

    require_free_space(len(raw), "this exhibit")                           # L2
    ev_id = uuid.uuid4()
    rel = f"emails/{ev_id}.eml.enc"
    stored = await awrite_encrypted(raw, rel)
    short = str(aid)[:8]
    ev = Evidence(
        id=ev_id, incident_id=incident_id, kind="digital_file", status="active",
        name=f"Email: {(analysis.subject or '(no subject)')[:200]}",
        identifier=f"EMAIL-{short}",
        original_filename="message.eml", storage_path=rel, nonce_hex=stored.nonce_hex,
        file_size_bytes=len(raw), mime_type="message/rfc822",
        sha256=sha256, sha1=sha1, md5=md5,
        current_custodian_id=user.id, collected_by_id=user.id, collected_at=utcnow(),
        acquired_at=src.uploaded_at, upload_hash_check="not_checked",
    )
    db.add(ev)
    await db.flush()          # persist evidence before linking it, so the FK on
    analysis.evidence_id = ev_id   # email_analysis can't reference a not-yet-inserted row
    await write_audit(db, "evidence_collect", user_id=user.id, username=user.username,
                      resource_type="evidence", resource_id=str(ev_id), outcome="success",
                      details={"incident_id": str(incident_id), "method": "email_mint",
                               "email_analysis_id": str(aid), "artifact_id": str(src.id),
                               "kind": "digital_file", "identifier": ev.identifier, "name": ev.name,
                               "sha256": ev.sha256, "file_size_bytes": ev.file_size_bytes,
                               "acquired_at": ev.acquired_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                                               if ev.acquired_at else None,
                               "artifact_hash_verified": True},
                      ip_address=request.client.host if request.client else None)
    await db.commit()
    return await _analysis_out(db, analysis)
