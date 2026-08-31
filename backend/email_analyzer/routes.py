"""U8.1 — Email analyzer routes (offline phishing triage).

Parse + score an email, then route its content into existing subsystems:
  attachments → quarantine Artifact · URLs/IPs/hashes → IOC · hops → Timeline ·
  raw message → Evidence. Mounted under /api/incidents.
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import re
import uuid
import zipfile
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
from email_analyzer.domain_check import check_dkim, check_spf_dmarc, evaluate_source_ip, fetch_domain_auth
from email_analyzer.parser import (attachment_bytes, is_msg, msg_to_eml_bytes, parse_email,
                                   repair_wrapped_export)
from email_analyzer.scoring import score as score_email
from evidence.crypto import awrite_encrypted
from incidents.access import get_accessible_incident
from models import Artifact, EmailAnalysis, Evidence, IOC, User, utcnow
from schemas import (DomainCheckOut, EmailAnalysisList, EmailAnalysisOut, EmailBulkAnalyzeOut,
                     PromoteIocsRequest)

router = APIRouter()

MAX_EMAIL_BYTES = 25 * 1024 * 1024
MAX_BULK_FILES = 200
MAX_BULK_TOTAL_BYTES = 250 * 1024 * 1024
AUTH_VALIDATE_TIMEOUT = 8.0     # per distinct domain -- a slow/unreachable DNS
                                # server must never block or fail the analysis
_AUTH_CONCURRENCY = 5           # cap concurrent live-DNS lookups within a batch


def _quarantine_dir(incident_id: uuid.UUID) -> Path:
    return Path(settings.quarantine_path) / str(incident_id)


def _safe_filename(name: str) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]", "_", (name or "file").strip()) or "file"
    return base[:200]


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


async def _incident(db, incident_id, user, *, writable=True):
    inc = await get_accessible_incident(db, incident_id, user)
    if writable and inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")
    return inc


async def _get_analysis(db, incident_id, aid) -> EmailAnalysis:
    a = (await db.execute(
        select(EmailAnalysis).where(EmailAnalysis.id == aid, EmailAnalysis.incident_id == incident_id)
    )).scalar_one_or_none()
    if not a:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Email analysis not found")
    return a


def _store_quarantine(incident_id: uuid.UUID, filename: str, data: bytes) -> tuple[uuid.UUID, str]:
    aid = uuid.uuid4()
    stored = f"{aid}_{_safe_filename(filename)}"
    out_dir = _quarantine_dir(incident_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / stored).write_bytes(data)
    return aid, stored


def _read_quarantine(incident_id: uuid.UUID, stored_filename: str) -> bytes:
    p = (_quarantine_dir(incident_id) / stored_filename).resolve()
    root = Path(settings.quarantine_path).resolve()
    if root not in p.parents:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid path")
    if not p.exists():
        raise HTTPException(status.HTTP_410_GONE, "Source message no longer in quarantine")
    return p.read_bytes()


@router.post("/{incident_id}/email/analyze", response_model=EmailAnalysisOut,
             status_code=status.HTTP_201_CREATED,
             summary="Analyze an email for phishing")
async def analyze_email(
    incident_id: uuid.UUID,
    request: Request,
    raw:  Optional[str]        = Form(default=None),
    file: Optional[UploadFile] = File(default=None),
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> EmailAnalysisOut:
    """Parse and score an email for phishing offline, persisting the result.

    Accepts either pasted raw header text (form field) or an uploaded .eml/.msg file
    (capped at 25 MB); Outlook .msg is converted to RFC-822 first. Extracts headers,
    hops, auth results, URLs, and attachments, computes a verdict and score, and stores
    the raw message as a quarantine artifact. Requires the analyst role and an open
    incident. Returns the created email analysis.
    """
    inc = await _incident(db, incident_id, user)

    if file is not None:
        data = await file.read()
        src_name = file.filename or "message.eml"
    elif raw and raw.strip():
        data = raw.encode("utf-8", "replace")
        src_name = "pasted.eml"
    else:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Provide raw header text or an .eml file")
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty input")
    data = repair_wrapped_export(data)
    if len(data) > MAX_EMAIL_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            f"Message exceeds {MAX_EMAIL_BYTES} bytes")

    # Outlook .msg → RFC-822 (phase d.1). Everything downstream operates on the .eml.
    from_msg = False
    if is_msg(data) or (src_name or "").lower().endswith(".msg"):
        try:
            data = msg_to_eml_bytes(data)
        except Exception as e:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"Could not parse .msg file: {e}")
        from_msg = True
        if src_name.lower().endswith(".msg"):
            src_name = src_name[:-4] + ".eml"

    parsed = parse_email(data)
    auth_verified = await _auto_verify_auth(parsed)
    verdict = score_email(parsed, auth_verified)

    # Persist the raw message as a quarantine Artifact (re-readable for extraction / evidence).
    art_id, stored = _store_quarantine(incident_id, src_name, data)
    db.add(Artifact(
        id=art_id, incident_id=incident_id,
        original_filename=src_name, stored_filename=stored,
        file_size=len(data), mime_type="message/rfc822",
        md5_hash=hashlib.md5(data).hexdigest(),
        sha256_hash=hashlib.sha256(data).hexdigest(),
        sha512_hash=hashlib.sha512(data).hexdigest(),
        description=f"Source email: {parsed.get('subject') or '(no subject)'}",
        analysis_status="pending", analysis_results={},
        uploaded_by_id=user.id, uploaded_by=user.username,
    ))

    analysis = EmailAnalysis(
        incident_id=incident_id, source_artifact_id=art_id,
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
    db.add(analysis)
    await db.flush()

    await write_audit(
        db, "email_analyze", user_id=user.id, username=user.username,
        resource_type="email_analysis", resource_id=str(analysis.id), outcome="success",
        details={"incident_id": str(incident_id), "verdict": verdict["verdict"],
                 "score": verdict["score"], "from": parsed.get("from_addr"), "from_msg": from_msg,
                 "urls": len(parsed.get("urls") or []), "attachments": len(parsed.get("attachments") or [])},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return EmailAnalysisOut.model_validate(analysis)


@router.post("/{incident_id}/email/analyze-bulk", response_model=EmailBulkAnalyzeOut,
             status_code=status.HTTP_201_CREATED,
             summary="Bulk-analyze multiple emails")
async def analyze_email_bulk(
    incident_id: uuid.UUID,
    request: Request,
    files: list[UploadFile] = File(...),
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> EmailBulkAnalyzeOut:
    """Analyze many emails in one batch: either multiple .eml/.msg uploads, or
    a single .zip containing them.

    Each message runs through the same offline parse+score pipeline as a
    single analyze, tagged with a shared batch_id so the history view can be
    filtered to this run. Live SPF/DMARC/DKIM validation is looked up once per
    distinct sender domain in the batch (phishing runs typically reuse one
    spoofed domain across many messages) and run concurrently with a capped
    timeout, so one slow or unreachable domain can't stall the whole batch.
    Nothing is silently dropped -- oversized/invalid members are reported back
    as `skipped`/`errors`. Requires the analyst role and an open incident.
    """
    await _incident(db, incident_id, user)
    if len(files) > MAX_BULK_FILES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            f"Batch exceeds {MAX_BULK_FILES} files")

    items: list[tuple[str, bytes]] = []
    skipped: list[str] = []
    if len(files) == 1 and (files[0].filename or "").lower().endswith(".zip"):
        zdata = await _read_capped(files[0], MAX_BULK_TOTAL_BYTES)
        items, skipped = _extract_zip_members(zdata)
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

    batch_id = uuid.uuid4()
    parsed_items: list[tuple[str, dict, bytes, bool]] = []
    errors: list[str] = []
    for name, data in items:
        data = repair_wrapped_export(data)
        from_msg = False
        if is_msg(data) or name.lower().endswith(".msg"):
            try:
                data = msg_to_eml_bytes(data)
                from_msg = True
                if name.lower().endswith(".msg"):
                    name = name[:-4] + ".eml"
            except Exception as e:
                errors.append(f"{name}: could not parse .msg file ({e})")
                continue
        try:
            parsed = parse_email(data)
        except Exception as e:
            errors.append(f"{name}: parse failed ({e})")
            continue
        parsed_items.append((name, parsed, data, from_msg))

    # One live-DNS fetch per distinct claimed domain across the whole batch.
    domains = {d for d in (_auth_check_domain(p) for _, p, _, _ in parsed_items) if d}
    sem = asyncio.Semaphore(_AUTH_CONCURRENCY)

    async def _fetch(domain: str) -> tuple[str, dict]:
        async with sem:
            try:
                result = await asyncio.wait_for(fetch_domain_auth(domain, None), timeout=AUTH_VALIDATE_TIMEOUT)
            except Exception:
                result = {"domain": domain, "error": "Live DNS validation timed out or failed."}
            return domain, result

    domain_cache = dict(await asyncio.gather(*(_fetch(d) for d in domains))) if domains else {}

    created: list[EmailAnalysis] = []
    for name, parsed, data, from_msg in parsed_items:
        domain = _auth_check_domain(parsed)
        base = domain_cache.get(domain) if domain else None
        auth_verified = None
        if base is not None:
            auth_verified = base if base.get("error") else {
                **base, "ip_in_spf": evaluate_source_ip(base["spf"], parsed.get("origin_ip")),
            }
        verdict = score_email(parsed, auth_verified)

        art_id, stored = _store_quarantine(incident_id, name, data)
        db.add(Artifact(
            id=art_id, incident_id=incident_id,
            original_filename=name, stored_filename=stored,
            file_size=len(data), mime_type="message/rfc822",
            md5_hash=hashlib.md5(data).hexdigest(),
            sha256_hash=hashlib.sha256(data).hexdigest(),
            sha512_hash=hashlib.sha512(data).hexdigest(),
            description=f"Source email: {parsed.get('subject') or '(no subject)'}",
            analysis_status="pending", analysis_results={},
            uploaded_by_id=user.id, uploaded_by=user.username,
        ))
        analysis = EmailAnalysis(
            incident_id=incident_id, source_artifact_id=art_id, batch_id=batch_id,
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
        db.add(analysis)
        await db.flush()
        created.append(analysis)

    await write_audit(
        db, "email_analyze_bulk", user_id=user.id, username=user.username,
        resource_type="email_analysis", resource_id=str(batch_id), outcome="success",
        details={"incident_id": str(incident_id), "batch_id": str(batch_id),
                 "analyzed": len(created), "skipped": len(skipped), "errors": len(errors),
                 "from_msg_count": sum(1 for *_, fm in parsed_items if fm)},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    return EmailBulkAnalyzeOut(
        batch_id=str(batch_id),
        analyzed=[EmailAnalysisOut.model_validate(a) for a in created],
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
    headers, URLs, and attachments.
    """
    await _incident(db, incident_id, user, writable=False)
    rows = (await db.execute(
        select(EmailAnalysis).where(EmailAnalysis.incident_id == incident_id)
        .order_by(EmailAnalysis.created_at.desc())
    )).scalars().all()
    return EmailAnalysisList(items=[EmailAnalysisOut.model_validate(r) for r in rows])


# ─── Domain auth check (manual mode) ─────────────────────────────────────────
# Registered before the parametric GET /{incident_id}/email/{aid} below --
# {aid} is typed as a UUID path param, but Starlette matches routes in
# registration order regardless of type converters, so a literal path
# segment sharing this shape must come first or it gets swallowed by {aid}
# and 422s on UUID parsing. Same class of ordering bug the correlations
# router already has a comment about, for the same underlying reason.

@router.get("/{incident_id}/email/domain-check", response_model=DomainCheckOut,
            summary="Live SPF/DMARC check for a domain, optional DKIM selector")
async def domain_check(
    incident_id: uuid.UUID,
    request: Request,
    domain: str = Query(..., min_length=1, max_length=253),
    selector: Optional[str] = Query(default=None, max_length=63),
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> DomainCheckOut:
    """Live-check a domain's SPF and DMARC records via DNS (no key required).
    DKIM is only checked if a `selector` is supplied -- it cannot be
    discovered from a bare domain, so manual mode requires one rather than
    guessing. Read-only: works on a closed incident. Audited (domain +
    whether a selector was checked, not the DNS response content).
    """
    await _incident(db, incident_id, user, writable=False)
    domain = domain.strip().lower().lstrip("*.")

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
    return EmailAnalysisOut.model_validate(await _get_analysis(db, incident_id, aid))


@router.post("/{incident_id}/email/{aid}/promote-iocs", response_model=EmailAnalysisOut,
             summary="Promote email indicators to IOCs")
async def promote_iocs(
    incident_id: uuid.UUID, aid: uuid.UUID, req: PromoteIocsRequest, request: Request,
    user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db),
) -> EmailAnalysisOut:
    """Promote selected indicators from an email analysis into incident IOCs.

    Takes a list of typed indicators (ip, domain, url, hash_*, email, registry_key,
    file_path, other); unknown types and existing duplicates are skipped. Requires the
    analyst role and an open incident. Returns the email analysis.
    """
    await _incident(db, incident_id, user)
    analysis = await _get_analysis(db, incident_id, aid)
    valid = {"ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256",
             "email", "registry_key", "file_path", "other"}
    created = 0
    for item in req.iocs:
        if item.type not in valid:
            continue
        exists = (await db.execute(select(IOC).where(
            IOC.incident_id == incident_id, IOC.type == item.type, IOC.value == item.value,
        ))).scalar_one_or_none()
        if exists:
            continue
        db.add(IOC(incident_id=incident_id, type=item.type, value=item.value,
                   notes=item.notes or f"From email analysis {aid}", source="email-analysis",
                   tags=["email"], added_by_id=user.id))
        created += 1
    await write_audit(db, "email_promote_iocs", user_id=user.id, username=user.username,
                      resource_type="email_analysis", resource_id=str(aid), outcome="success",
                      details={"incident_id": str(incident_id), "created": created},
                      ip_address=request.client.host if request.client else None)
    await db.commit()
    return EmailAnalysisOut.model_validate(analysis)


@router.post("/{incident_id}/email/{aid}/attachments/{idx}/extract", response_model=EmailAnalysisOut,
             summary="Extract an email attachment to quarantine")
async def extract_attachment(
    incident_id: uuid.UUID, aid: uuid.UUID, idx: int, request: Request,
    user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db),
) -> EmailAnalysisOut:
    """Extract one attachment (by index) from the analyzed email into a quarantine artifact.

    Reads the source message from quarantine, writes the attachment as a new artifact with
    detected MIME type and hashes, and auto-creates dedup SHA-256/MD5 IOCs. Fails if the
    index is out of range, the attachment was already extracted, or the source message is
    gone. Requires the analyst role and an open incident. Returns the email analysis.
    """
    await _incident(db, incident_id, user)
    analysis = await _get_analysis(db, incident_id, aid)
    atts = list(analysis.attachments or [])
    if idx < 0 or idx >= len(atts):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Attachment index out of range")
    if atts[idx].get("artifact_id"):
        raise HTTPException(status.HTTP_409_CONFLICT, "Attachment already extracted")
    if not analysis.source_artifact_id:
        raise HTTPException(status.HTTP_410_GONE, "Source message unavailable")

    src = (await db.execute(select(Artifact).where(Artifact.id == analysis.source_artifact_id))).scalar_one_or_none()
    if not src:
        raise HTTPException(status.HTTP_410_GONE, "Source message artifact missing")
    raw = _read_quarantine(incident_id, src.stored_filename)
    filename, _declared, data = attachment_bytes(raw, idx)

    art_id, stored = _store_quarantine(incident_id, filename, data)
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    db.add(Artifact(
        id=art_id, incident_id=incident_id, original_filename=filename, stored_filename=stored,
        file_size=len(data), mime_type=magic.from_buffer(data[:2048], mime=True),
        md5_hash=md5, sha256_hash=sha256, sha512_hash=hashlib.sha512(data).hexdigest(),
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
                       source="email-analysis", tags=["email", "attachment"], added_by_id=user.id))

    atts[idx] = {**atts[idx], "artifact_id": str(art_id)}
    analysis.attachments = atts
    await write_audit(db, "email_extract_attachment", user_id=user.id, username=user.username,
                      resource_type="email_analysis", resource_id=str(aid), outcome="success",
                      details={"incident_id": str(incident_id), "artifact_id": str(art_id),
                               "filename": filename, "sha256": sha256},
                      ip_address=request.client.host if request.client else None)
    await db.commit()
    return EmailAnalysisOut.model_validate(analysis)


@router.post("/{incident_id}/email/{aid}/import-hops", response_model=EmailAnalysisOut,
             summary="Import mail relay hops to the timeline")
async def import_hops(
    incident_id: uuid.UUID, aid: uuid.UUID, request: Request,
    user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db),
) -> EmailAnalysisOut:
    """Import the email's Received (relay hop) chain as timeline events.

    Each parsed hop with a valid timestamp becomes a Detection & Analysis phase event
    sourced from "email"; hops without a usable timestamp are skipped. Requires the
    analyst role and an open incident. Returns the email analysis.
    """
    from datetime import datetime
    from models import TimelineEvent
    await _incident(db, incident_id, user)
    analysis = await _get_analysis(db, incident_id, aid)
    n = 0
    for h in (analysis.headers or {}).get("hops") or []:
        if not h.get("timestamp"):
            continue
        try:
            et = datetime.fromisoformat(h["timestamp"])
        except Exception:
            continue
        desc = f"Mail hop: {h.get('from') or '?'} → {h.get('by') or '?'}"
        if h.get("ip"):
            desc += f" [{h['ip']}]"
        db.add(TimelineEvent(
            incident_id=incident_id, event_time=et, source="email",
            event_type="Mail relay hop", hostname=h.get("by"),
            description=desc, raw_log=str(h)[:4000], ir_phase="detection_and_analysis",
            origin="forensic_import", external_safe=False, created_by_id=user.id,
        ))
        n += 1
    await write_audit(db, "email_import_hops", user_id=user.id, username=user.username,
                      resource_type="email_analysis", resource_id=str(aid), outcome="success",
                      details={"incident_id": str(incident_id), "events": n},
                      ip_address=request.client.host if request.client else None)
    await db.commit()
    return EmailAnalysisOut.model_validate(analysis)


@router.post("/{incident_id}/email/{aid}/mint-evidence", response_model=EmailAnalysisOut,
             summary="Mint the email as chain-of-custody evidence")
async def mint_evidence(
    incident_id: uuid.UUID, aid: uuid.UUID, request: Request,
    user: User = Depends(require_analyst), db: AsyncSession = Depends(get_db),
) -> EmailAnalysisOut:
    """Mint the analyzed email's raw message as an encrypted chain-of-custody evidence item.

    Reads the source message from quarantine, writes it AES-encrypted to evidence storage,
    records hashes and custody (collector/custodian = caller), and links the evidence to the
    analysis. Fails if already minted or the source message is unavailable. Requires the
    analyst role and an open incident. Returns the email analysis.
    """
    await _incident(db, incident_id, user)
    analysis = await _get_analysis(db, incident_id, aid)
    if analysis.evidence_id:
        raise HTTPException(status.HTTP_409_CONFLICT, "Already minted as evidence")
    if not analysis.source_artifact_id:
        raise HTTPException(status.HTTP_410_GONE, "Source message unavailable")
    src = (await db.execute(select(Artifact).where(Artifact.id == analysis.source_artifact_id))).scalar_one_or_none()
    if not src:
        raise HTTPException(status.HTTP_410_GONE, "Source message artifact missing")
    raw = _read_quarantine(incident_id, src.stored_filename)

    ev_id = uuid.uuid4()
    rel = f"emails/{ev_id}.eml.enc"
    await awrite_encrypted(raw, rel)
    nonce = (Path(settings.evidence_path) / (rel + ".nonce")).read_text().strip()
    short = str(aid)[:8]
    ev = Evidence(
        id=ev_id, incident_id=incident_id, kind="digital_file", status="active",
        name=f"Email: {(analysis.subject or '(no subject)')[:200]}",
        identifier=f"EMAIL-{short}",
        original_filename="message.eml", storage_path=rel, nonce_hex=nonce,
        file_size_bytes=len(raw), mime_type="message/rfc822",
        sha256=hashlib.sha256(raw).hexdigest(), sha1=hashlib.sha1(raw).hexdigest(),
        md5=hashlib.md5(raw).hexdigest(),
        current_custodian_id=user.id, collected_by_id=user.id, collected_at=utcnow(),
    )
    db.add(ev)
    await db.flush()          # persist evidence before linking it, so the FK on
    analysis.evidence_id = ev_id   # email_analysis can't reference a not-yet-inserted row
    await write_audit(db, "email_mint_evidence", user_id=user.id, username=user.username,
                      resource_type="evidence", resource_id=str(ev_id), outcome="success",
                      details={"incident_id": str(incident_id), "email_analysis_id": str(aid),
                               "sha256": ev.sha256},
                      ip_address=request.client.host if request.client else None)
    await db.commit()
    return EmailAnalysisOut.model_validate(analysis)
