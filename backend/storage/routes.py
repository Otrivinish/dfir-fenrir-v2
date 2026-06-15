"""Storage admin — disk usage per Docker volume."""
import os
import shutil
from pathlib import Path

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import require_admin
from core.config import settings
from core.database import get_db
from models import CollectionPackage, User

from collectors.builder import collections_root
from collectors.retention import effective_status, is_stale

router = APIRouter(prefix="/api/admin/storage", tags=["Admin"])

# Ordered list of volumes to report on.
_VOLUMES = [
    ("Evidence",  "evidence_path"),
    ("Quarantine","quarantine_path"),
    ("Backups",   "backup_path"),
    ("Reports",   "reports_path"),
    ("Branding",  "branding_path"),
    ("Logs",      "logs_path"),
]


class VolumeStats(BaseModel):
    label:           str
    path:            str
    exists:          bool
    # Filesystem totals for the mount point (may be shared across volumes).
    fs_total_bytes:  int
    fs_used_bytes:   int
    fs_free_bytes:   int
    # Content within this directory.
    content_bytes:   int
    file_count:      int
    # True when content scan was capped (very large volume).
    scan_capped:     bool


class CollectionsStorage(BaseModel):
    """Velociraptor collection packages (U1) — these live on the quarantine
    volume but are broken out so admins see what generation consumes and how
    much the retention sweep can reclaim."""
    on_disk_bytes:     int   # actual bytes of package ZIPs on disk
    file_count:        int
    active_bytes:      int   # bytes held by still-downloadable packages
    active_count:      int
    stale_count:       int   # active-but-superseded (outdated Velociraptor version)
    reclaimable_bytes: int   # on_disk - active → freed by the next sweep


class StorageResponse(BaseModel):
    volumes:     list[VolumeStats]
    collections: CollectionsStorage


_FILE_CAP = 50_000   # max files to enumerate per volume before capping


def _scan(path: Path) -> tuple[int, int, bool]:
    """Return (total_bytes, file_count, capped) for the directory tree."""
    total = 0
    count = 0
    capped = False
    try:
        for root, _dirs, files in os.walk(path, followlinks=False):
            for name in files:
                if count >= _FILE_CAP:
                    capped = True
                    return total, count, capped
                try:
                    total += os.path.getsize(os.path.join(root, name))
                except OSError:
                    pass
                count += 1
    except PermissionError:
        pass
    return total, count, capped


def _volume_stats(label: str, path_str: str) -> VolumeStats:
    p = Path(path_str)
    if not p.exists():
        return VolumeStats(
            label=label, path=path_str, exists=False,
            fs_total_bytes=0, fs_used_bytes=0, fs_free_bytes=0,
            content_bytes=0, file_count=0, scan_capped=False,
        )

    try:
        du = shutil.disk_usage(p)
        fs_total = du.total
        fs_used  = du.used
        fs_free  = du.free
    except OSError:
        fs_total = fs_used = fs_free = 0

    content_bytes, file_count, capped = _scan(p)

    return VolumeStats(
        label=label, path=path_str, exists=True,
        fs_total_bytes=fs_total, fs_used_bytes=fs_used, fs_free_bytes=fs_free,
        content_bytes=content_bytes, file_count=file_count, scan_capped=capped,
    )


async def _collections_storage(db: AsyncSession) -> CollectionsStorage:
    on_disk_bytes, file_count, _capped = _scan(collections_root())
    rows = (await db.execute(select(CollectionPackage))).scalars().all()
    active_bytes = active_count = stale_count = 0
    for pkg in rows:
        if effective_status(pkg) == "generated":
            active_bytes += pkg.file_size or 0
            active_count += 1
            if is_stale(pkg):
                stale_count += 1
    return CollectionsStorage(
        on_disk_bytes=on_disk_bytes,
        file_count=file_count,
        active_bytes=active_bytes,
        active_count=active_count,
        stale_count=stale_count,
        # Anything on disk beyond what active packages legitimately hold is
        # reclaimable by the retention sweep (consumed/expired/superseded/orphan).
        reclaimable_bytes=max(0, on_disk_bytes - active_bytes),
    )


@router.get("", response_model=StorageResponse, summary="Get storage usage")
async def storage_status(
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> StorageResponse:
    """Report disk usage per Docker volume (evidence, quarantine, backups,
    reports, branding, logs) — filesystem totals plus a per-directory content
    scan (capped at 50,000 files) — and a Velociraptor collections breakdown
    showing on-disk, active, stale and reclaimable bytes. Admin access
    required."""
    volumes = [
        _volume_stats(label, getattr(settings, attr))
        for label, attr in _VOLUMES
    ]
    return StorageResponse(volumes=volumes, collections=await _collections_storage(db))
