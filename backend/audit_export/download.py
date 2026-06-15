"""Token-gated download for signed audit-export bundles.

Mounted at `/api/audit-exports`. No auth — the token IS the authorisation,
mirroring `evidence/download.py`. Tokens are 32-byte URL-safe random,
single-use, 24-hour expiry.

Failure modes (all return 410 Gone — don't leak which case applied):
  - Unknown token
  - Already consumed
  - Past expires_at
  - Bundle file missing (e.g., 30d retention cron already ran)
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from audit_export.bundle import is_expired, open_bundle_for_download
from core.database import get_db
from models import AuditExport


router = APIRouter()


@router.get("/{token}", summary="Download a signed audit-log export bundle")
async def download_audit_export(
    token:   str,
    request: Request,
    db:      AsyncSession = Depends(get_db),
) -> Response:
    """Download a signed audit-log export bundle by its one-time token — the
    token IS the authorisation (no login). Tokens are single-use and expire after
    24 hours; unknown, consumed, expired or purged tokens all return 410 Gone
    without leaking which case applied. The token is atomically claimed before
    streaming to prevent double-download. Returns the AES-256-encrypted ZIP as an
    attachment with the bundle SHA-256 and Ed25519 public-key fingerprint in
    response headers."""
    exp = (await db.execute(
        select(AuditExport).where(AuditExport.token == token)
    )).scalar_one_or_none()

    if (
        not exp
        or exp.status in ("consumed", "purged")
        or is_expired(exp)
    ):
        if exp is not None:
            await write_audit(
                db, "audit_export_download_denied",
                username="token:anonymous",
                resource_type="audit_export", resource_id=str(exp.id),
                outcome="denied",
                details={
                    "incident_id": str(exp.incident_id) if exp.incident_id else None,
                    "reason": exp.status if exp.status in ("consumed", "purged") else "expired",
                },
                ip_address=request.client.host if request.client else None,
            )
            await db.commit()
        raise HTTPException(
            status.HTTP_410_GONE,
            "This export is no longer available (expired, consumed, or unknown).",
        )

    # Atomically claim the token BEFORE streaming — closes the TOCTOU race where
    # two concurrent requests both pass the status check above and both serve the
    # one-time bundle. Exactly one UPDATE flips status→consumed; the loser 410s.
    client_ip = request.client.host if request.client else None
    claimed = await db.execute(
        update(AuditExport)
        .where(
            AuditExport.id == exp.id,
            AuditExport.status.not_in(("consumed", "purged")),
        )
        .values(status="consumed", consumed_at=datetime.now(timezone.utc), consumed_ip=client_ip)
    )
    await db.commit()
    if claimed.rowcount == 0:
        raise HTTPException(
            status.HTTP_410_GONE,
            "This export is no longer available (expired, consumed, or unknown).",
        )

    try:
        body, suggested = open_bundle_for_download(exp)
    except FileNotFoundError:
        # Bundle file purged (or never written) — record + 410.
        exp.status = "purged"
        await write_audit(
            db, "audit_export_download_denied",
            username="token:anonymous",
            resource_type="audit_export", resource_id=str(exp.id),
            outcome="failure",
            details={
                "incident_id": str(exp.incident_id) if exp.incident_id else None,
                "reason": "bundle_missing",
            },
            ip_address=client_ip,
        )
        await db.commit()
        raise HTTPException(status.HTTP_410_GONE, "Bundle file is no longer available.")

    await write_audit(
        db, "audit_export_download",
        username="token:anonymous",
        resource_type="audit_export", resource_id=str(exp.id),
        outcome="success",
        details={
            "incident_id":   str(exp.incident_id) if exp.incident_id else None,
            "bundle_sha256": exp.bundle_sha256,
            "row_count":     exp.row_count,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    return Response(
        content=body,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{suggested}"',
            "X-Bundle-SHA256":     exp.bundle_sha256 or "",
            "X-Pubkey-Fpr":        exp.pubkey_fpr   or "",
            "Cache-Control":       "no-store",
        },
    )
