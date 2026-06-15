"""Public token-gated download for custody export bundles.

Mounted at `/api/exports`. No auth — the token IS the authorisation.
Tokens are 32-byte URL-safe random, single-use, 24-hour expiry. The bundle
itself is AES-256-GCM-encrypted with an ephemeral key delivered out-of-band
to the recipient; this endpoint just streams ciphertext.

Failure modes (all return 410 Gone to avoid leaking which case applied):
  - Unknown token
  - Already consumed
  - Past expires_at
  - Revoked (phase 3)
"""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from core.database import get_db
from models import CustodyExport

from evidence.exports import is_expired, open_bundle_for_download

router = APIRouter()


@router.get("/{token}", summary="Download a custody export bundle")
async def download_export(
    token:   str,
    request: Request,
    db:      AsyncSession = Depends(get_db),
) -> Response:
    """Download a custody export bundle by its one-time token — the token IS the
    authorisation (no login). Tokens are single-use and expire after 24 hours;
    unknown, consumed, expired or revoked tokens all return 410 Gone without
    leaking which case applied. The token is atomically claimed before streaming
    to prevent double-download. Returns the AES-256-GCM ciphertext as an
    octet-stream attachment with the bundle SHA-256 in `X-Bundle-SHA256`."""
    exp = (await db.execute(
        select(CustodyExport).where(CustodyExport.token == token)
    )).scalar_one_or_none()

    # Single response shape for unknown / consumed / expired / revoked — don't
    # leak which case applied.
    if (
        not exp
        or exp.status in ("consumed", "revoked")
        or is_expired(exp)
    ):
        # Best-effort audit even on failure (no actor for token auth).
        if exp is not None:
            await write_audit(
                db, "evidence_export_download_denied",
                username=f"token:{exp.recipient}" if exp.recipient else "token:anonymous",
                resource_type="custody_export", resource_id=str(exp.id),
                outcome="denied",
                details={
                    "incident_id": str(exp.incident_id),
                    "reason": exp.status if exp.status in ("consumed", "revoked") else "expired",
                },
                ip_address=request.client.host if request.client else None,
            )
            await db.commit()
        raise HTTPException(
            status.HTTP_410_GONE,
            "This export is no longer available (expired, consumed, or unknown).",
        )

    # Atomically claim the token BEFORE streaming. A plain read-check-then-write
    # is a TOCTOU race: two concurrent requests both pass the status check above
    # and both serve the one-time bundle. The guarded UPDATE lets exactly one
    # request flip status→consumed; the loser sees rowcount 0 and gets 410.
    client_ip = request.client.host if request.client else None
    claimed = await db.execute(
        update(CustodyExport)
        .where(
            CustodyExport.id == exp.id,
            CustodyExport.status.not_in(("consumed", "revoked")),
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
        await write_audit(
            db, "evidence_export_download_denied",
            username=f"token:{exp.recipient}" if exp.recipient else "token:anonymous",
            resource_type="custody_export", resource_id=str(exp.id),
            outcome="failure",
            details={"incident_id": str(exp.incident_id), "reason": "bundle_missing"},
            ip_address=client_ip,
        )
        await db.commit()
        raise HTTPException(status.HTTP_410_GONE, "Bundle file is no longer available.")

    # No authenticated user here — the token IS the authorisation. Surface a
    # synthetic actor that identifies the recipient so the audit log shows
    # context instead of an empty "—" column.
    actor_label = f"token:{exp.recipient}" if exp.recipient else "token:anonymous"
    await write_audit(
        db, "evidence_export_download",
        username=actor_label,
        resource_type="custody_export", resource_id=str(exp.id),
        outcome="success",
        details={
            "incident_id":   str(exp.incident_id),
            "recipient":     exp.recipient,
            "bundle_sha256": exp.bundle_sha256,
            "item_count":    len(exp.item_ids or []),
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    return Response(
        content=body,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{suggested}"',
            "X-Bundle-SHA256":     exp.bundle_sha256 or "",
            "Cache-Control":       "no-store",
        },
    )
