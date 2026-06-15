"""Backup status + manual trigger endpoints.

Lists .sql.gz backup files from BACKUP_PATH and allows admins to trigger
a pg_dump via POST /api/admin/backups/run (returns 202, runs in background).
"""
import asyncio
import gzip
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel

from auth.deps import require_admin
from models import User
from core.config import settings

router = APIRouter(prefix="/api/admin/backups", tags=["admin"])

_BACKUP_RE = re.compile(r"^fenrir_backup_(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})\.sql\.gz$")

_running = False  # simple in-process guard; single worker per CLAUDE.md


class BackupFile(BaseModel):
    filename:    str
    size_bytes:  int
    created_at:  str   # ISO 8601 UTC


class BackupListResponse(BaseModel):
    backups:    list[BackupFile]
    is_running: bool


class BackupRunResponse(BaseModel):
    status:  str
    message: str


def _list_backups() -> list[BackupFile]:
    path = Path(settings.backup_path)
    if not path.exists():
        return []
    files = []
    for f in path.iterdir():
        if _BACKUP_RE.match(f.name):
            stat = f.stat()
            files.append(BackupFile(
                filename=f.name,
                size_bytes=stat.st_size,
                created_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            ))
    files.sort(key=lambda x: x.created_at, reverse=True)
    return files


def _pg_creds() -> tuple[str, str, str, str]:
    """Return (host, user, password, dbname) parsed from settings."""
    parsed = urlparse(settings.database_url)
    host   = parsed.hostname or "postgres"
    user   = parsed.username or "fenrir"
    pw     = settings.pg_password
    db     = (parsed.path or "/fenrir").lstrip("/") or "fenrir"
    return host, user, pw, db


async def _run_backup() -> None:
    global _running
    _running = True
    try:
        host, user, pw, db = _pg_creds()
        ts       = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
        out_path = Path(settings.backup_path) / f"fenrir_backup_{ts}.sql.gz"
        out_path.parent.mkdir(parents=True, exist_ok=True)

        env = {**os.environ, "PGPASSWORD": pw}
        proc = await asyncio.create_subprocess_exec(
            "pg_dump",
            "-h", host,
            "-U", user,
            "-d", db,
            "--clean", "--if-exists", "--no-owner",
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"pg_dump failed: {stderr.decode()[:500]}")

        # Write gzipped
        with gzip.open(str(out_path), "wb") as gz:
            gz.write(stdout)

        # Prune backups older than 14 days (match backup.sh behaviour)
        cutoff = datetime.now(timezone.utc).timestamp() - 14 * 86400
        for f in Path(settings.backup_path).iterdir():
            if _BACKUP_RE.match(f.name) and f.stat().st_mtime < cutoff:
                f.unlink(missing_ok=True)

    finally:
        _running = False


@router.get("", response_model=BackupListResponse, summary="List database backups")
async def list_backups(_: User = Depends(require_admin)):
    """List the available .sql.gz database backup files (filename, size,
    UTC creation time), newest first, plus whether a backup is currently
    running. Admin access required."""
    return BackupListResponse(backups=_list_backups(), is_running=_running)


@router.post("/run", response_model=BackupRunResponse, status_code=status.HTTP_202_ACCEPTED,
             summary="Trigger a database backup")
async def run_backup(background_tasks: BackgroundTasks, _: User = Depends(require_admin)):
    """Trigger a pg_dump backup that runs in the background (returns 202
    immediately). Single-flight: returns 409 if a backup is already running.
    Backups older than 14 days are pruned after a successful dump. Admin access
    required. Returns an accepted status message."""
    global _running
    if _running:
        raise HTTPException(status.HTTP_409_CONFLICT, "A backup is already running")
    background_tasks.add_task(_run_backup)
    return BackupRunResponse(status="accepted", message="Backup started in background")
