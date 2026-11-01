"""Admin-only platform settings — API key management.

Keys are stored Fernet-encrypted in platform_settings (one row per service).
The raw value is never returned; only configured/source status is exposed.

DB key format: "api_key.{service_id}" e.g. "api_key.virustotal"
"""
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import require_admin
from core.database import get_db
from core.security import decrypt_secret, encrypt_secret
from core.config import settings as env_settings
from core.errors import ApiError, ApiErrorBody
from models import Incident, PlatformSetting, User, utcnow
from incidents import reference as incident_ref
from evidence import identifier as exhibit_ids
from schemas import (ApiKeyServiceOut, ApiKeySet, ApiKeysResponse, ENRICHMENT_SERVICES,
                     EvidenceIdentifierSettings, EvidenceIdentifierSettingsUpdate, EvidenceIdentifierToken,
                     IncidentRefSettings, IncidentRefSettingsUpdate)

router = APIRouter()

# Maps service id → human label (mirrors SOURCES in osint/service.py, but kept
# independent so settings_api has no import cycle with osint).
_SERVICE_LABELS: dict[str, str] = {
    "virustotal": "VirusTotal",
    "abuseipdb":  "AbuseIPDB",
    "shodan":     "Shodan",
    "greynoise":  "GreyNoise",
    "urlscan":    "URLScan.io",
}

# Maps service id → env var attribute on Settings
_ENV_ATTRS: dict[str, str] = {
    "virustotal": "virustotal_api_key",
    "abuseipdb":  "abuseipdb_api_key",
    "shodan":     "shodan_api_key",
    "greynoise":  "greynoise_api_key",
    "urlscan":    "urlscan_api_key",
}


def _db_key(service: str) -> str:
    return f"api_key.{service}"


async def _get_row(db: AsyncSession, service: str) -> Optional[PlatformSetting]:
    return (await db.execute(
        select(PlatformSetting).where(PlatformSetting.key == _db_key(service))
    )).scalar_one_or_none()


def _env_value(service: str) -> Optional[str]:
    attr = _ENV_ATTRS.get(service)
    if attr is None:
        return None
    return getattr(env_settings, attr, None) or None


@router.get("/api-keys", response_model=ApiKeysResponse, summary="List API key status")
async def list_api_keys(
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ApiKeysResponse:
    """List the configuration status of each enrichment service's API key. For every
    known service it reports whether a key is configured and its source (db, env, or
    none); the raw key value is never returned. Admin only."""
    rows = {
        r.key: r
        for r in (await db.execute(
            select(PlatformSetting).where(
                PlatformSetting.key.in_([_db_key(s) for s in ENRICHMENT_SERVICES])
            )
        )).scalars().all()
    }

    out: list[ApiKeyServiceOut] = []
    for svc in ENRICHMENT_SERVICES:
        row = rows.get(_db_key(svc))
        if row:
            out.append(ApiKeyServiceOut(
                service=svc,
                label=_SERVICE_LABELS.get(svc, svc),
                configured=True,
                source="db",
            ))
        elif _env_value(svc):
            out.append(ApiKeyServiceOut(
                service=svc,
                label=_SERVICE_LABELS.get(svc, svc),
                configured=True,
                source="env",
            ))
        else:
            out.append(ApiKeyServiceOut(
                service=svc,
                label=_SERVICE_LABELS.get(svc, svc),
                configured=False,
                source=None,
            ))
    return ApiKeysResponse(services=out)


@router.put("/api-keys/{service}", status_code=status.HTTP_204_NO_CONTENT,
            summary="Set an API key")
async def set_api_key(
    service: str,
    req: ApiKeySet,
    request: Request,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Store or replace the API key for an enrichment service. The value is
    Fernet-encrypted at rest (one row per service). Returns 400 for an unknown
    service and 204 on success. Admin only."""
    if service not in ENRICHMENT_SERVICES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown service: {service}")

    encrypted = encrypt_secret(req.value.strip())

    stmt = (
        pg_insert(PlatformSetting)
        .values(
            key=_db_key(service),
            encrypted_value=encrypted,
            updated_by_id=user.id,
        )
        .on_conflict_do_update(
            index_elements=["key"],
            set_={"encrypted_value": encrypted, "updated_by_id": user.id},
        )
    )
    await db.execute(stmt)

    await write_audit(
        db, "api_key_set",
        user_id=user.id, username=user.username,
        resource_type="platform_setting", resource_id=_db_key(service),
        details={"service": service},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()


@router.delete("/api-keys/{service}", status_code=status.HTTP_204_NO_CONTENT,
               summary="Delete an API key")
async def delete_api_key(
    service: str,
    request: Request,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete the stored (DB) API key for an enrichment service; any env-provided key
    is unaffected. Returns 400 for an unknown service, 404 if no DB key is set, and
    204 on success. Admin only."""
    if service not in ENRICHMENT_SERVICES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown service: {service}")

    row = await _get_row(db, service)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No DB key set for this service")

    await db.delete(row)

    await write_audit(
        db, "api_key_delete",
        user_id=user.id, username=user.username,
        resource_type="platform_setting", resource_id=_db_key(service),
        details={"service": service},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()


# ─── Incident reference prefix ───────────────────────────────────────────────

@router.get("/incident-ref", response_model=IncidentRefSettings,
            summary="Get incident-reference settings")
async def get_incident_ref_settings(
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> IncidentRefSettings:
    """Current prefix for new incident references and a preview of the next
    reference (PREFIX-YYYY-NNNNN). Admin only."""
    prefix = await incident_ref.get_prefix(db)
    return IncidentRefSettings(prefix=prefix, next_ref_preview=await incident_ref.preview_next(db, prefix))


@router.patch("/incident-ref", response_model=IncidentRefSettings,
              summary="Set the incident-reference prefix")
async def update_incident_ref_settings(
    req: IncidentRefSettingsUpdate,
    request: Request,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> IncidentRefSettings:
    """Change the prefix used for **new** incidents (2-10 chars, A-Z then A-Z/0-9).
    Existing incident references never change. Audit-logged. Admin only."""
    old = await incident_ref.get_prefix(db)
    await incident_ref.set_prefix(db, req.prefix, user.id)
    await write_audit(
        db, "incident_ref_prefix_changed",
        outcome="success", resource_type="platform_setting",
        resource_id=incident_ref.PREFIX_KEY, resource_label="Incident reference prefix",
        details={"old": old, "new": req.prefix},
    )
    await db.commit()
    return IncidentRefSettings(prefix=req.prefix, next_ref_preview=await incident_ref.preview_next(db, req.prefix))


# ─── Exhibit identifier convention (EI) ──────────────────────────────────────

async def _evidence_identifier_settings(db: AsyncSession, template: str) -> EvidenceIdentifierSettings:
    """The template, its tokens and an example for the most recent incident (or the next incident's reference)."""
    inc = (await db.execute(select(Incident.id, Incident.ref)
                            .order_by(Incident.created_at.desc(), Incident.id).limit(1))).first()
    if inc is not None:
        ref, example = inc.ref, await exhibit_ids.preview(db, inc.id, inc.ref, template)
    else:
        ref = await incident_ref.preview_next(db)
        example = exhibit_ids.expand(template, ref, utcnow(), 1)
    return EvidenceIdentifierSettings(
        template=template, tokens=[EvidenceIdentifierToken(token=t, description=d) for t, d in exhibit_ids.TOKENS],
        example=example, example_incident_ref=ref)


@router.get("/evidence-identifier", response_model=EvidenceIdentifierSettings,
            summary="Get the exhibit-identifier naming convention")
async def get_evidence_identifier_settings(
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> EvidenceIdentifierSettings:
    """The template FENRIR fills in when an exhibit is registered without an identifier (and for every draft it
    registers itself: supporting documents, the Email, PCAP and Browser history uploads), its tokens, and an example
    for the most recent incident. Default {incident}-{date}-{seq:3}. Admin only."""
    return await _evidence_identifier_settings(db, await exhibit_ids.get_template(db))


@router.patch("/evidence-identifier", response_model=EvidenceIdentifierSettings,
              summary="Set the exhibit-identifier naming convention",
              responses={422: {"model": ApiErrorBody,
                               "description": "invalid_identifier_template (the detail names the rule it breaks)"}})
async def update_evidence_identifier_settings(
    req: EvidenceIdentifierSettingsUpdate,
    request: Request,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> EvidenceIdentifierSettings:
    """Change the template for identifiers assigned **from now on**; identifiers already assigned never change.
    Rules (422 invalid_identifier_template, naming the rule): tokens {incident}, {date}, {seq} / {seq:N} only;
    literal text A–Z a–z 0–9 . _ -; {seq} exactly once; at most 64 characters; the longest result (a 32-character
    reference, a 9-digit number) at most 128. Audit-logged (old / new). Admin only."""
    if (why := exhibit_ids.template_error(req.template)) is not None:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_identifier_template", why)
    old = await exhibit_ids.get_template(db)
    await exhibit_ids.set_template(db, req.template, user.id)
    await write_audit(
        db, "evidence_identifier_template_changed",
        outcome="success", resource_type="platform_setting",
        resource_id=exhibit_ids.TEMPLATE_KEY, resource_label="Exhibit identifier convention",
        details={"old": old, "new": req.template},
    )
    await db.commit()
    return await _evidence_identifier_settings(db, req.template)

