"""U8.1 — Email analyzer routes (offline phishing triage).

Parse + score an email, then route its content into existing subsystems:
  attachments → quarantine Artifact · URLs/IPs/hashes → IOC · hops → Timeline ·
  raw message → Evidence. Mounted under /api/incidents.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from pathlib import Path
from typing import Optional

import magic
from fastapi import (APIRouter, Depends, File, Form, HTTPException, Request,
                     UploadFile, status)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.config import settings
from core.database import get_db
from email_analyzer.parser import attachment_bytes, is_msg, msg_to_eml_bytes, parse_email
from email_analyzer.scoring import score as score_email
from evidence.crypto import awrite_encrypted
from incidents.access import get_accessible_incident
from models import Artifact, EmailAnalysis, Evidence, IOC, User, utcnow
from schemas import (EmailAnalysisList, EmailAnalysisOut, PromoteIocsRequest)

router = APIRouter()

MAX_EMAIL_BYTES = 25 * 1024 * 1024


def _quarantine_dir(incident_id: uuid.UUID) -> Path:
    return Path(settings.quarantine_path) / str(incident_id)


def _safe_filename(name: str) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]", "_", (name or "file").strip()) or "file"
    return base[:200]


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
    verdict = score_email(parsed)

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
    analysis.evidence_id = ev_id
    await write_audit(db, "email_mint_evidence", user_id=user.id, username=user.username,
                      resource_type="evidence", resource_id=str(ev_id), outcome="success",
                      details={"incident_id": str(incident_id), "email_analysis_id": str(aid),
                               "sha256": ev.sha256},
                      ip_address=request.client.host if request.client else None)
    await db.commit()
    return EmailAnalysisOut.model_validate(analysis)
