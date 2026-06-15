"""YARA rule library (global) + per-incident scan/match endpoints.

Global rules: mounted at prefix="/api/yara".
Incident scan: mounted at prefix="/api/incidents".
"""
import asyncio
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, Form, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.config import settings
from core.database import get_db
from incidents.access import get_accessible_incident
from models import Artifact, Incident, TimelineEvent, IOC, User, YaraMatch, YaraRule
from schemas import (
    YaraMatchList,
    YaraMatchOut,
    YaraRuleCreate,
    YaraRuleList,
    YaraRuleOut,
    YaraRuleUpdate,
    YaraScanResult,
)

logger = logging.getLogger("fenrir.yara")

WORKER_URL      = "http://analysis-worker:8001"
YARA_MAX_BYTES  = 512 * 1024   # 512 KB per rule file

global_router   = APIRouter()
incident_router = APIRouter()


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _parse_meta(content: str) -> dict:
    """Best-effort extraction of name/description/author from YARA rule text."""
    name = ""
    description = ""
    author = ""
    tags: list[str] = []

    m = re.search(r'\brule\s+(\w+)', content)
    if m:
        name = m.group(1)

    for key in ("description", "author"):
        mv = re.search(rf'{key}\s*=\s*"([^"]+)"', content, re.IGNORECASE)
        if mv:
            if key == "description":
                description = mv.group(1)
            else:
                author = mv.group(1)

    tm = re.search(r'tags\s*=\s*\[([^\]]+)\]', content, re.IGNORECASE)
    if tm:
        tags = [t.strip().strip('"\'') for t in tm.group(1).split(',') if t.strip()]

    return {"name": name, "description": description, "author": author, "tags": tags}


async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


# ─── Global YARA rule library ─────────────────────────────────────────────────

@global_router.get("", response_model=YaraRuleList, summary="List YARA rules")
async def list_rules(
    _: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> YaraRuleList:
    """List all YARA rules in the global library, ordered by name. Any
    authenticated user may read. Returns the full rule set as a list."""
    rows = (await db.execute(
        select(YaraRule).order_by(YaraRule.name)
    )).scalars().all()
    return YaraRuleList(items=[YaraRuleOut.model_validate(r) for r in rows])


@global_router.post("", response_model=YaraRuleOut, status_code=status.HTTP_201_CREATED,
                    summary="Create a YARA rule")
async def create_rule(
    req: YaraRuleCreate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> YaraRuleOut:
    """Create a YARA rule in the global library from inline rule content.
    Name, description, author, and tags are taken from the request or parsed
    from the rule text when omitted. Requires the analyst role. Returns the
    created rule."""
    meta = _parse_meta(req.rule_content)
    rule = YaraRule(
        id=uuid.uuid4(),
        name=req.name or meta["name"] or "Unnamed Rule",
        description=req.description or meta["description"] or None,
        author=req.author or meta["author"] or None,
        tags=req.tags or meta["tags"],
        rule_content=req.rule_content,
        created_by_id=user.id,
    )
    db.add(rule)
    await write_audit(
        db, "yara_rule_create",
        user_id=user.id, username=user.username,
        resource_type="yara_rule", resource_id=str(rule.id),
        details={"name": rule.name},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return YaraRuleOut.model_validate(rule)


@global_router.post("/upload", response_model=YaraRuleOut, status_code=status.HTTP_201_CREATED,
                    summary="Upload a YARA rule file")
async def upload_rule(
    request: Request,
    file: UploadFile = File(...),
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> YaraRuleOut:
    """Create a YARA rule by uploading a .yar file (max 512 KB). Name,
    description, author, and tags are parsed from the rule text, falling back
    to the filename for the name. Requires the analyst role. Returns the
    created rule."""
    raw = await file.read()
    if len(raw) > YARA_MAX_BYTES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Rule file too large (max 512 KB)")
    content = raw.decode("utf-8", errors="replace").strip()
    if not content:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty rule file")

    meta = _parse_meta(content)
    rule = YaraRule(
        id=uuid.uuid4(),
        name=meta["name"] or (file.filename or "Uploaded Rule"),
        description=meta["description"] or None,
        author=meta["author"] or None,
        tags=meta["tags"],
        rule_content=content,
        created_by_id=user.id,
    )
    db.add(rule)
    await write_audit(
        db, "yara_rule_upload",
        user_id=user.id, username=user.username,
        resource_type="yara_rule", resource_id=str(rule.id),
        details={"name": rule.name, "filename": file.filename},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return YaraRuleOut.model_validate(rule)


@global_router.patch("/{rule_id}", response_model=YaraRuleOut,
                     summary="Update a YARA rule")
async def update_rule(
    rule_id: uuid.UUID,
    req: YaraRuleUpdate,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> YaraRuleOut:
    """Update a YARA rule's name and/or active flag; only those two fields are
    mutable. Requires the analyst role. Returns the updated rule, or 404 if the
    rule does not exist."""
    rule = (await db.execute(
        select(YaraRule).where(YaraRule.id == rule_id)
    )).scalar_one_or_none()
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")

    if req.name      is not None: rule.name      = req.name
    if req.is_active is not None: rule.is_active = req.is_active

    await write_audit(
        db, "yara_rule_update",
        user_id=user.id, username=user.username,
        resource_type="yara_rule", resource_id=str(rule.id),
        details={"name": rule.name, "is_active": rule.is_active},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return YaraRuleOut.model_validate(rule)


@global_router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT,
                      summary="Delete a YARA rule")
async def delete_rule(
    rule_id: uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a YARA rule from the global library. Requires the analyst role.
    Returns 204 No Content, or 404 if the rule does not exist."""
    rule = (await db.execute(
        select(YaraRule).where(YaraRule.id == rule_id)
    )).scalar_one_or_none()
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")

    await write_audit(
        db, "yara_rule_delete",
        user_id=user.id, username=user.username,
        resource_type="yara_rule", resource_id=str(rule_id),
        details={"name": rule.name},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(rule)
    await db.commit()


# ─── Per-incident YARA scan ───────────────────────────────────────────────────

async def _run_scan(incident_id: uuid.UUID) -> YaraScanResult:
    """Run all active rules against all artifacts for an incident. Idempotent (deduped by rule+artifact)."""
    from core.database import SessionLocal

    async with SessionLocal() as db:
        rules = (await db.execute(
            select(YaraRule).where(YaraRule.is_active == True)
        )).scalars().all()

        if not rules:
            return YaraScanResult(artifacts_scanned=0, matches_found=0,
                                  errors=["No active YARA rules in library"])

        artifacts = (await db.execute(
            select(Artifact).where(Artifact.incident_id == incident_id)
        )).scalars().all()

        if not artifacts:
            return YaraScanResult(artifacts_scanned=0, matches_found=0,
                                  errors=["No artifacts for this incident"])

        inline_rules = [{"name": r.name, "content": r.rule_content} for r in rules]
        rule_map     = {r.name: r for r in rules}
        quarantine   = Path(settings.quarantine_path)

        matches_found = 0
        errors:  list[str] = []
        now = datetime.now(timezone.utc)

        async with httpx.AsyncClient(timeout=60) as client:
            for artifact in artifacts:
                art_path = str(quarantine / str(incident_id) / artifact.stored_filename)
                try:
                    resp = await client.post(
                        f"{WORKER_URL}/analyze/yara-inline",
                        json={"path": art_path, "rules": inline_rules},
                    )
                    resp.raise_for_status()
                    result = resp.json()
                except Exception as e:
                    errors.append(f"[{artifact.original_filename}] worker error: {e}")
                    continue

                for err in result.get("errors", []):
                    errors.append(f"[{artifact.original_filename}] {err}")

                for match in result.get("matches", []):
                    rule_name = match["rule_name"]
                    rule_obj  = rule_map.get(rule_name)

                    # Dedup: skip if already recorded
                    if rule_obj:
                        existing = (await db.execute(
                            select(YaraMatch).where(
                                YaraMatch.rule_id    == rule_obj.id,
                                YaraMatch.artifact_id == artifact.id,
                            )
                        )).scalar_one_or_none()
                        if existing:
                            continue

                    ym = YaraMatch(
                        id=uuid.uuid4(),
                        rule_id=rule_obj.id if rule_obj else None,
                        rule_name=rule_name,
                        incident_id=incident_id,
                        artifact_id=artifact.id,
                        artifact_name=artifact.original_filename,
                        matched_strings=match.get("strings", [])[:50],
                    )
                    db.add(ym)
                    if rule_obj:
                        rule_obj.match_count     = (rule_obj.match_count or 0) + 1
                        rule_obj.last_matched_at = now
                    matches_found += 1

        await db.commit()
        return YaraScanResult(
            artifacts_scanned=len(artifacts),
            matches_found=matches_found,
            errors=errors,
        )


@incident_router.post("/{incident_id}/yara/scan", response_model=YaraScanResult,
                      summary="Scan an incident's artifacts with YARA")
async def scan_incident(
    incident_id: uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> YaraScanResult:
    """Run all active library rules against every artifact for the incident via
    the analysis worker. Idempotent — matches are deduped by rule and artifact.
    Requires the analyst role and access to the incident. Returns counts of
    artifacts scanned, matches found, and any errors."""
    await _get_incident(db, incident_id, user)
    await write_audit(
        db, "yara_scan_trigger",
        user_id=user.id, username=user.username,
        resource_type="incident", resource_id=str(incident_id),
        details={"incident_id": str(incident_id)},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return await _run_scan(incident_id)


@incident_router.get("/{incident_id}/yara/matches", response_model=YaraMatchList,
                     summary="List YARA matches for an incident")
async def list_matches(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> YaraMatchList:
    """List all recorded YARA matches for the incident, newest first. Any
    authenticated user with access to the incident may read. Returns the list
    of matches."""
    await _get_incident(db, incident_id, user)
    rows = (await db.execute(
        select(YaraMatch)
        .where(YaraMatch.incident_id == incident_id)
        .order_by(YaraMatch.created_at.desc())
    )).scalars().all()
    return YaraMatchList(items=[YaraMatchOut.model_validate(r) for r in rows])


@incident_router.delete("/{incident_id}/yara/matches", status_code=status.HTTP_204_NO_CONTENT,
                        summary="Clear all YARA matches for an incident")
async def clear_matches(
    incident_id: uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete all recorded YARA matches for the incident. Requires the analyst
    role and access to the incident. Returns 204 No Content."""
    await _get_incident(db, incident_id, user)
    rows = (await db.execute(
        select(YaraMatch).where(YaraMatch.incident_id == incident_id)
    )).scalars().all()
    for r in rows:
        await db.delete(r)
    await write_audit(
        db, "yara_matches_clear",
        user_id=user.id, username=user.username,
        resource_type="incident", resource_id=str(incident_id),
        details={"count": len(rows)},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()


@incident_router.post("/{incident_id}/yara/matches/{match_id}/to-timeline",
                      status_code=status.HTTP_201_CREATED,
                      summary="Add a YARA match to the timeline")
async def match_to_timeline(
    incident_id: uuid.UUID,
    match_id:    uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Create a timeline event from a YARA match, summarising the rule, matched
    artifact, and matched strings. Requires the analyst role. Returns the new
    event id, or 404 if the match does not exist for this incident."""
    match = (await db.execute(
        select(YaraMatch).where(
            YaraMatch.id == match_id,
            YaraMatch.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not match:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Match not found")

    strings_summary = ", ".join(
        s["identifier"] for s in (match.matched_strings or [])[:5] if "identifier" in s
    )
    desc = f"[YARA] {match.rule_name}"
    if match.artifact_name:
        desc += f" — {match.artifact_name}"
    if strings_summary:
        desc += f" — matched: {strings_summary}"

    raw = "\n".join(
        f"{s.get('identifier', '?')} @ 0x{s.get('offset', 0):x}: {s.get('data', '')}"
        for s in (match.matched_strings or [])[:20]
    )

    ev = TimelineEvent(
        id=uuid.uuid4(),
        incident_id=incident_id,
        event_time=datetime.now(timezone.utc),
        event_type="yara_detection",
        source="YARA",
        description=desc,
        raw_log=raw,
        origin="manual",
        created_by_id=user.id,
    )
    db.add(ev)
    await write_audit(
        db, "yara_match_to_timeline",
        user_id=user.id, username=user.username,
        resource_type="timeline_event", resource_id=str(ev.id),
        details={"match_id": str(match_id), "rule": match.rule_name},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return {"event_id": str(ev.id)}


@incident_router.post("/{incident_id}/yara/matches/{match_id}/to-ioc",
                      status_code=status.HTTP_201_CREATED,
                      summary="Promote a YARA match to an IOC")
async def match_to_ioc(
    incident_id: uuid.UUID,
    match_id:    uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Add the matched artifact's SHA-256 hash as a sha256 IOC on the incident.
    Deduplicates against existing IOCs. Requires the analyst role. Returns the
    IOC id and whether it was newly created; 404 if the match is missing, 422
    if the artifact has no SHA-256."""
    match = (await db.execute(
        select(YaraMatch).where(
            YaraMatch.id == match_id,
            YaraMatch.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not match:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Match not found")

    # Fetch SHA-256 from the artifact row.
    sha256 = None
    if match.artifact_id:
        art = (await db.execute(
            select(Artifact).where(Artifact.id == match.artifact_id)
        )).scalar_one_or_none()
        if art:
            sha256 = art.sha256_hash

    if not sha256:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "Artifact SHA-256 not available")

    # Dedup check.
    existing = (await db.execute(
        select(IOC).where(
            IOC.incident_id == incident_id,
            IOC.type == "hash_sha256",
            IOC.value == sha256,
        )
    )).scalar_one_or_none()
    if existing:
        return {"ioc_id": str(existing.id), "created": False}

    ioc = IOC(
        id=uuid.uuid4(),
        incident_id=incident_id,
        type="hash_sha256",
        value=sha256,
        notes=f"YARA match: {match.rule_name} on {match.artifact_name or 'artifact'}",
        source="yara-match",
        tags=["yara"],
        added_by_id=user.id,
    )
    db.add(ioc)
    await write_audit(
        db, "yara_match_to_ioc",
        user_id=user.id, username=user.username,
        resource_type="ioc", resource_id=str(ioc.id),
        details={"match_id": str(match_id), "rule": match.rule_name, "sha256": sha256},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return {"ioc_id": str(ioc.id), "created": True}
