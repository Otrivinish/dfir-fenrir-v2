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
from models import PlatformSetting, User
from schemas import ApiKeyServiceOut, ApiKeySet, ApiKeysResponse, ENRICHMENT_SERVICES

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
