"""Collection packages (U1.1) — generate / list / one-time download / delete.

Routers:
  - router          (/api/incidents)  : profiles, generate, list, get, delete
  - download_router (/api/collections) : auth-free one-time token download
  - admin_router    (/api/admin)       : manual retention sweep

Generation is offline + air-gap-safe (bundled Velociraptor binaries, no inbound
path). Disk hygiene is built in: every generate + list runs the retention sweep,
generation is capped per incident, and the one-time download deletes the ~60 MB
ZIP on consume.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

from fastapi import (APIRouter, Depends, File, HTTPException, Request,
                     Response, UploadFile, status)
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_admin, require_analyst
from core.config import settings
from core.database import get_db
from incidents.access import get_accessible_incident
from models import CollectionPackage, User

from collectors.builder import (
    CollectorBuildError,
    binaries_present,
    build_package,
    package_path,
)
from collectors.ingest import register_collection_output
from collectors.profiles import get_profile, list_profiles
from collectors.retention import (
    effective_status,
    enforce_active_cap,
    is_stale,
    sweep,
)

router          = APIRouter()
download_router = APIRouter()
admin_router    = APIRouter()


class GenerateRequest(BaseModel):
    name:     str = Field(min_length=1, max_length=200)
    profile:  str = Field(min_length=1, max_length=32)
    platform: str = Field(default="windows", max_length=16)


def _pkg_out(pkg: CollectionPackage) -> dict:
    """Serialiser. Never exposes the one-time token (shown once at generation)."""
    return {
        "id":                  str(pkg.id),
        "incident_id":         str(pkg.incident_id),
        "name":                pkg.name,
        "platform":            pkg.platform,
        "profile":             pkg.profile,
        "artifact_selection":  pkg.artifact_selection or [],
        "velociraptor_version": pkg.velociraptor_version,
        "status":              effective_status(pkg),
        "is_stale":            is_stale(pkg),
        "package_sha256":      pkg.package_sha256,
        "manifest_sha256":     pkg.manifest_sha256,
        "signing_fingerprint": pkg.signing_fingerprint,
        "cert_fingerprint":    pkg.cert_fingerprint,
        "encrypted":           bool(pkg.enc_private_key),
        "file_size":           pkg.file_size,
        "created_by":          pkg.created_by,
        "created_at":          pkg.created_at.isoformat() if pkg.created_at else None,
        "token_expires_at":    pkg.token_expires_at.isoformat() if pkg.token_expires_at else None,
        "consumed_at":         pkg.consumed_at.isoformat() if pkg.consumed_at else None,
        "ingested_at":         pkg.ingested_at.isoformat() if pkg.ingested_at else None,
        "result_artifact_id":  str(pkg.result_artifact_id) if pkg.result_artifact_id else None,
    }


# ─── Profiles (literal route — MUST precede /{cid}) ──────────────────────────

@router.get("/{incident_id}/collections/profiles", summary="List collection profiles")
async def collection_profiles(
    incident_id: uuid.UUID,
    db:   AsyncSession = Depends(get_db),
    user: User         = Depends(current_user),
):
    """List the available collection profiles (per-platform artifact bundles)
    that can be used to generate a collector for this incident. Requires access
    to the incident. Returns `{items: [...]}` of profile descriptors."""
    await get_accessible_incident(db, incident_id, user)
    return {"items": list_profiles()}


# ─── Generate ────────────────────────────────────────────────────────────────

@router.post("/{incident_id}/collections", status_code=status.HTTP_201_CREATED,
             summary="Generate a collection package")
async def generate_collection(
    incident_id: uuid.UUID,
    body:    GenerateRequest,
    request: Request,
    user: User         = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
):
    """Build a signed, air-gap-safe Velociraptor collector ZIP for the incident
    from the named platform/profile. Requires the analyst role and an open
    incident; enforces a per-incident active-package cap. Returns the package
    metadata plus a one-time `download_url` and its expiry, shown only once."""
    inc = await get_accessible_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    prof = get_profile(body.platform, body.profile)
    if not prof:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Unknown profile '{body.platform}/{body.profile}'",
        )

    # Disk hygiene: reclaim stale/expired first, then enforce the per-incident cap.
    await sweep(db)
    try:
        await enforce_active_cap(db, incident_id)
    except ValueError as e:
        await db.commit()   # persist any sweep changes
        raise HTTPException(status.HTTP_409_CONFLICT, str(e))

    if not binaries_present(body.platform):
        await db.commit()
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Velociraptor binaries are not bundled for this platform — collection "
            "generation is unavailable. See docs/u1-collector-spike.md.",
        )

    package_id = uuid.uuid4()
    loop = asyncio.get_event_loop()
    try:
        meta = await loop.run_in_executor(None, lambda: build_package(
            incident_id=incident_id,
            incident_ref=inc.ref,
            incident_title=inc.title,
            package_id=package_id,
            name=body.name,
            platform=body.platform,
            profile=body.profile,
            artifacts=prof["artifacts"],
            created_by=user.username,
        ))
    except CollectorBuildError as e:
        await db.commit()
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(e))

    pkg = CollectionPackage(
        id=package_id,
        incident_id=incident_id,
        name=body.name,
        platform=body.platform,
        profile=body.profile,
        artifact_selection=prof["artifacts"],
        velociraptor_version=meta["velociraptor_version"],
        manifest_sha256=meta["manifest_sha256"],
        package_sha256=meta["package_sha256"],
        signature_b64=meta["signature_b64"],
        signing_fingerprint=meta["signing_fingerprint"],
        enc_private_key=meta["enc_private_key"],
        cert_fingerprint=meta["cert_fingerprint"],
        token=meta["token"],
        token_expires_at=meta["token_expires_at"],
        file_path=meta["file_path"],
        file_size=meta["file_size"],
        status="generated",
        created_by_id=user.id,
        created_by=user.username,
        created_at=meta["created_at"],
    )
    db.add(pkg)
    await db.flush()

    # Anchor provenance (manifest + package hashes + signature) in the audit chain.
    await write_audit(
        db, "collection_package_generate",
        user_id=user.id, username=user.username,
        resource_type="collection_package", resource_id=str(pkg.id),
        outcome="success",
        details={
            "incident_id":     str(incident_id),
            "profile":         f"{body.platform}/{body.profile}",
            "artifact_count":  len(prof["artifacts"]),
            "manifest_sha256": meta["manifest_sha256"],
            "package_sha256":  meta["package_sha256"],
            "fingerprint":     meta["signing_fingerprint"],
            "file_size":       meta["file_size"],
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    await db.refresh(pkg)

    out = _pkg_out(pkg)
    # The one-time download URL is shown ONCE, here, like an evidence export.
    out["download_url"]        = f"/api/collections/{meta['token']}"
    out["download_expires_at"] = meta["token_expires_at"].isoformat()
    out["shown_once"]          = True
    return out


# ─── List ────────────────────────────────────────────────────────────────────

@router.get("/{incident_id}/collections", summary="List collection packages")
async def list_collections(
    incident_id: uuid.UUID,
    db:   AsyncSession = Depends(get_db),
    user: User         = Depends(current_user),
):
    """List all collection packages generated for this incident, newest first.
    Runs a lazy retention sweep on each call. Requires access to the incident.
    Returns `{items: [...], cap: {...}}`; never exposes the one-time tokens."""
    await get_accessible_incident(db, incident_id, user)
    await sweep(db)          # lazy GC on every list
    await db.commit()
    rows = (await db.execute(
        select(CollectionPackage)
        .where(CollectionPackage.incident_id == incident_id)
        .order_by(CollectionPackage.created_at.desc())
    )).scalars().all()
    return {
        "items": [_pkg_out(r) for r in rows],
        "cap":   {"max_active_per_incident": settings.collection_max_active_per_incident},
    }


# ─── Get one ─────────────────────────────────────────────────────────────────

@router.get("/{incident_id}/collections/{cid}", summary="Get a collection package")
async def get_collection(
    incident_id: uuid.UUID,
    cid:  uuid.UUID,
    db:   AsyncSession = Depends(get_db),
    user: User         = Depends(current_user),
):
    """Fetch metadata for a single collection package by id within the incident.
    Requires access to the incident. Returns the package descriptor (status,
    hashes, signing fingerprint, sizes); never exposes the one-time token. 404
    if not found."""
    await get_accessible_incident(db, incident_id, user)
    pkg = (await db.execute(
        select(CollectionPackage).where(
            CollectionPackage.id == cid,
            CollectionPackage.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not pkg:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Collection package not found")
    return _pkg_out(pkg)


# ─── Delete (reclaims the ZIP; row kept for audit) ───────────────────────────

@router.delete("/{incident_id}/collections/{cid}", status_code=status.HTTP_204_NO_CONTENT,
               summary="Delete a collection package")
async def delete_collection(
    incident_id: uuid.UUID,
    cid:     uuid.UUID,
    request: Request,
    user: User         = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
):
    """Delete a collection package: reclaims its ZIP from disk and marks the row
    `deleted` (the row is retained for audit). Requires the analyst role and
    access to the incident. Returns 204; 404 if not found."""
    await get_accessible_incident(db, incident_id, user)
    pkg = (await db.execute(
        select(CollectionPackage).where(
            CollectionPackage.id == cid,
            CollectionPackage.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not pkg:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Collection package not found")

    # Reclaim the ZIP and mark deleted (sweep also reclaims on its next pass).
    if pkg.file_path:
        try:
            p = package_path(pkg.incident_id, pkg.id)
            if p.is_file():
                p.unlink()
        except (OSError, CollectorBuildError):
            pass
        pkg.file_path = None
    pkg.status = "deleted"

    await write_audit(
        db, "collection_package_delete",
        user_id=user.id, username=user.username,
        resource_type="collection_package", resource_id=str(pkg.id),
        outcome="success",
        details={"incident_id": str(incident_id)},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ─── Ingest (U1.2 — upload the collector's output, register as Artifact) ─────

@router.post("/{incident_id}/collections/{cid}/ingest", status_code=status.HTTP_201_CREATED,
             summary="Ingest collection output")
async def ingest_collection(
    incident_id: uuid.UUID,
    cid:     uuid.UUID,
    request: Request,
    file: UploadFile   = File(...),
    user: User         = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
):
    """Upload the collector's output file for a generated package and register it
    as a first-class quarantine Artifact for downstream analysis. Requires the
    analyst role and an open incident; rejects already-ingested or deleted
    packages and oversize uploads. Returns the updated package plus the created
    artifact summary."""
    inc = await get_accessible_incident(db, incident_id, user)
    if inc.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is closed")

    pkg = (await db.execute(
        select(CollectionPackage).where(
            CollectionPackage.id == cid,
            CollectionPackage.incident_id == incident_id,
        )
    )).scalar_one_or_none()
    if not pkg:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Collection package not found")
    if pkg.status == "ingested":
        raise HTTPException(status.HTTP_409_CONFLICT, "This package's output was already ingested")
    if pkg.status == "deleted":
        raise HTTPException(status.HTTP_409_CONFLICT, "This package was deleted")

    cl = request.headers.get("content-length")
    if cl and int(cl) > settings.collection_output_max_bytes:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"Collection output exceeds {settings.collection_output_max_bytes} bytes",
        )

    # Stream to quarantine + register as a first-class Artifact (existing
    # analysis tools + U1.3 timeline import operate on it). X.509 decrypt of an
    # encrypted container would happen inside this call once keys are bundled.
    artifact = await register_collection_output(
        db, incident_id, pkg.name, file, user, pkg.enc_private_key
    )

    pkg.status            = "ingested"
    pkg.ingested_at       = datetime.now(timezone.utc)
    pkg.ingested_by_id    = user.id
    pkg.output_sha256     = artifact.sha256_hash
    pkg.result_artifact_id = artifact.id

    await write_audit(
        db, "collection_ingest",
        user_id=user.id, username=user.username,
        resource_type="collection_package", resource_id=str(pkg.id),
        outcome="success",
        details={
            "incident_id":   str(incident_id),
            "artifact_id":   str(artifact.id),
            "output_sha256": artifact.sha256_hash,
            "output_size":   artifact.file_size,
            "filename":      artifact.original_filename,
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    await db.refresh(pkg)

    return {
        **_pkg_out(pkg),
        "artifact": {
            "id":                str(artifact.id),
            "original_filename": artifact.original_filename,
            "file_size":         artifact.file_size,
            "sha256":            artifact.sha256_hash,
            "mime_type":         artifact.mime_type,
        },
    }


# ─── One-time token download (auth-free — the token IS the authorisation) ────

@download_router.get("/{token}", summary="Download a collection package (one-time)")
async def download_collection(
    token:   str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """One-time, auth-free download of a generated collector ZIP — the opaque
    token is the authorisation. Marks the package consumed and deletes the ZIP
    from disk before returning the bytes. Returns the ZIP with its SHA-256 in a
    header; 410 Gone if the token is unknown, expired, consumed, superseded, or
    the file is missing."""
    pkg = (await db.execute(
        select(CollectionPackage).where(CollectionPackage.token == token)
    )).scalar_one_or_none()

    # Single shape for unknown / consumed / expired / superseded / deleted.
    if not pkg or effective_status(pkg) != "generated":
        if pkg is not None:
            await write_audit(
                db, "collection_package_download_denied",
                username=f"token:{pkg.created_by or 'anonymous'}",
                resource_type="collection_package", resource_id=str(pkg.id),
                outcome="denied",
                details={"incident_id": str(pkg.incident_id), "reason": effective_status(pkg)},
                ip_address=request.client.host if request.client else None,
            )
            await db.commit()
        raise HTTPException(
            status.HTTP_410_GONE,
            "This collection package is no longer available (expired, consumed, "
            "superseded, or unknown).",
        )

    try:
        path = package_path(pkg.incident_id, pkg.id)
        body = path.read_bytes() if path.is_file() else None
    except (OSError, CollectorBuildError):
        body = None
    if body is None:
        pkg.status = "expired"
        pkg.file_path = None
        await write_audit(
            db, "collection_package_download_denied",
            username=f"token:{pkg.created_by or 'anonymous'}",
            resource_type="collection_package", resource_id=str(pkg.id),
            outcome="failure",
            details={"incident_id": str(pkg.incident_id), "reason": "file_missing"},
            ip_address=request.client.host if request.client else None,
        )
        await db.commit()
        raise HTTPException(status.HTTP_410_GONE, "Package file is no longer available.")

    # Single use: mark consumed and delete the ZIP BEFORE returning the bytes.
    try:
        path.unlink()
    except OSError:
        pass
    pkg.status      = "consumed"
    pkg.file_path   = None
    pkg.consumed_at = datetime.now(timezone.utc)
    pkg.consumed_ip = request.client.host if request.client else None

    await write_audit(
        db, "collection_package_download",
        username=f"token:{pkg.created_by or 'anonymous'}",
        resource_type="collection_package", resource_id=str(pkg.id),
        outcome="success",
        details={
            "incident_id":    str(pkg.incident_id),
            "package_sha256": pkg.package_sha256,
            "profile":        f"{pkg.platform}/{pkg.profile}",
        },
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    return Response(
        content=body,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="fenrir-collector-{pkg.id}.zip"',
            "X-Package-SHA256":    pkg.package_sha256 or "",
            "Cache-Control":       "no-store",
        },
    )


# ─── Admin manual sweep ──────────────────────────────────────────────────────

@admin_router.post("/collections/cleanup", summary="Run collection retention sweep")
async def cleanup_collections(
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Manually run the collection-package retention sweep, reclaiming stale and
    expired package files across all incidents. Admin only. Returns the counts
    of packages affected by the sweep."""
    counts = await sweep(db)
    await db.commit()
    return counts
