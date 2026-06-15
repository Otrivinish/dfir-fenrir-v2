"""Retention + disk hygiene for collection packages.

A repacked Velociraptor collector is ~60 MB, so unbounded generation fills the
quarantine volume and stale binaries (built against a since-patched Velociraptor)
are a security liability a responder must never run. This module reclaims them.

Three mechanisms:
  1. consume-deletes        — the ZIP is removed the moment its one-time token
                              is used (single use is the whole point).
  2. sweep()                — lazy GC (called on generate + list, and on the
                              admin cleanup endpoint): expires past-TTL packages,
                              SUPERSEDES packages built with an outdated/insecure
                              Velociraptor version, and reclaims the on-disk ZIP
                              for any non-active package.
  3. enforce_active_cap()   — bounds the number of un-downloaded packages per
                              incident so generation can't run away.

Rows are never hard-deleted (audit trail) — only the ~60 MB ZIP is reclaimed;
the row's status records why.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from models import CollectionPackage

from collectors.builder import package_path

# Statuses whose on-disk ZIP should NOT exist (reclaimable).
_RECLAIMABLE = ("consumed", "expired", "superseded", "deleted")
# The only status whose ZIP is meant to be on disk.
_ACTIVE = "generated"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _unlink(pkg: CollectionPackage) -> int:
    """Best-effort delete of the package ZIP. Returns bytes reclaimed."""
    if not pkg.file_path:
        return 0
    try:
        p = package_path(pkg.incident_id, pkg.id)
    except Exception:
        return 0
    reclaimed = 0
    try:
        if p.is_file():
            reclaimed = p.stat().st_size
            p.unlink()
    except OSError:
        return 0
    pkg.file_path = None
    return reclaimed


def is_stale(pkg: CollectionPackage) -> bool:
    """Built against a Velociraptor version other than the one bundled now.

    Empty `velociraptor_version` config disables stale detection (dev).
    """
    current = settings.velociraptor_version
    if not current:
        return False
    return (pkg.velociraptor_version or "") != current


def effective_status(pkg: CollectionPackage) -> str:
    """Status with TTL + staleness applied, without mutating the row.

    Use anywhere the UI/serialiser reports status so a not-yet-swept row still
    reads correctly.
    """
    if pkg.status == _ACTIVE:
        if pkg.token_expires_at and _now() >= pkg.token_expires_at:
            return "expired"
        if is_stale(pkg):
            return "superseded"
    return pkg.status


async def sweep(db: AsyncSession) -> dict:
    """Reclaim disk for expired/stale/already-terminal packages. Idempotent.

    Caller commits. Returns counts for the admin cleanup endpoint.
    """
    rows = (await db.execute(select(CollectionPackage))).scalars().all()
    expired = superseded = reclaimed_files = 0
    reclaimed_bytes = 0

    for pkg in rows:
        if pkg.status == _ACTIVE:
            # Expire past-TTL packages.
            if pkg.token_expires_at and _now() >= pkg.token_expires_at:
                pkg.status = "expired"
                expired += 1
            # Supersede packages built with an outdated/insecure version.
            elif is_stale(pkg):
                pkg.status = "superseded"
                superseded += 1

        # Any non-active package must not keep its ZIP around.
        if pkg.status in _RECLAIMABLE and pkg.file_path:
            freed = _unlink(pkg)
            if freed or pkg.file_path is None:
                reclaimed_files += 1
                reclaimed_bytes += freed

    return {
        "expired":         expired,
        "superseded":      superseded,
        "reclaimed_files": reclaimed_files,
        "reclaimed_bytes": reclaimed_bytes,
    }


async def active_count(db: AsyncSession, incident_id: uuid.UUID) -> int:
    rows = (await db.execute(
        select(CollectionPackage).where(
            CollectionPackage.incident_id == incident_id,
            CollectionPackage.status == _ACTIVE,
        )
    )).scalars().all()
    # Exclude rows that are effectively expired/stale (sweep may not have run).
    return sum(1 for p in rows if effective_status(p) == _ACTIVE)


async def enforce_active_cap(db: AsyncSession, incident_id: uuid.UUID) -> None:
    """Raise ValueError if the incident already has the max un-downloaded packages."""
    cap = settings.collection_max_active_per_incident
    if await active_count(db, incident_id) >= cap:
        raise ValueError(
            f"This incident already has {cap} active collection packages "
            "(the per-incident cap). Download or delete an existing package "
            "before generating another."
        )
