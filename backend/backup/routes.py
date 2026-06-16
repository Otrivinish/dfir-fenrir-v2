"""Backup status + manual trigger endpoints.

Lists .sql.gz backup files from BACKUP_PATH and allows admins to trigger
a pg_dump via POST /api/admin/backups/run (returns 202, runs in background).
"""
import asyncio
import gzip
import logging
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

logger = logging.getLogger("backup")

_BACKUP_RE = re.compile(r"^fenrir_backup_(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})\.sql\.gz$")

# Process-local state (single worker per CLAUDE.md; resets on restart).
_running = False                  # single-flight guard
_last_run: Optional[dict] = None  # last run outcome — see _last_run_model()


class BackupFile(BaseModel):
    filename:    str
    size_bytes:  int
    created_at:  str   # ISO 8601 UTC


class BackupLastRun(BaseModel):
    state:       str                   # 'idle' | 'running' | 'success' | 'error'
    started_at:  Optional[str] = None  # ISO 8601 UTC
    finished_at: Optional[str] = None  # ISO 8601 UTC
    filename:    Optional[str] = None  # set on success
    error:       Optional[str] = None  # sanitized reason, set on error


class BackupListResponse(BaseModel):
    backups:    list[BackupFile]
    is_running: bool                   # == (last_run.state == 'running'); kept for back-compat
    last_run:   BackupLastRun


class BackupRunResponse(BaseModel):
    status:     str
    message:    str
    started_at: Optional[str] = None   # ISO 8601 UTC of this run, for client correlation


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


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_reason(e: Exception) -> str:
    """Map a backup failure to a fixed, non-sensitive reason for the UI. Full
    detail is logged server-side — pg_dump stderr can carry host/user/db."""
    msg = str(e).lower()
    if isinstance(e, FileNotFoundError):
        return "Backup tool unavailable (pg_dump not found)."
    if isinstance(e, PermissionError) or "permission denied" in msg:
        return "Could not write backup file (permissions)."
    if "pg_dump failed" in msg or "connect" in msg or "connection" in msg:
        return "Database dump failed (pg_dump error)."
    return "Backup failed (see server logs)."


def _last_run_model() -> BackupLastRun:
    if _last_run is None:
        return BackupLastRun(state="idle")
    return BackupLastRun(**_last_run)


async def _run_backup(started: Optional[datetime] = None) -> None:
    global _running, _last_run
    _running = True
    started = started or datetime.now(timezone.utc)
    _last_run = {"state": "running", "started_at": _iso(started),
                 "finished_at": None, "filename": None, "error": None}
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

        # Prune backups older than 14 days (match backup.sh behaviour).
        # /backups carries a sticky bit, so dumps written by the root sidecar
        # aren't deletable from here — skip those (the sidecar's own daily prune
        # reaps them as root); only our own manual dumps are pruned here.
        cutoff = datetime.now(timezone.utc).timestamp() - 14 * 86400
        for f in Path(settings.backup_path).iterdir():
            if _BACKUP_RE.match(f.name) and f.stat().st_mtime < cutoff:
                try:
                    f.unlink(missing_ok=True)
                except OSError:
                    pass

        _last_run = {"state": "success", "started_at": _iso(started),
                     "finished_at": _iso(datetime.now(timezone.utc)),
                     "filename": out_path.name, "error": None}
    except Exception as e:                       # noqa: BLE001 — record every failure
        logger.exception("manual backup failed")
        _last_run = {"state": "error", "started_at": _iso(started),
                     "finished_at": _iso(datetime.now(timezone.utc)),
                     "filename": None, "error": _safe_reason(e)}
    finally:
        _running = False


@router.get("", response_model=BackupListResponse, summary="List database backups")
async def list_backups(_: User = Depends(require_admin)):
    """List the available .sql.gz database backup files (filename, size,
    UTC creation time), newest first, plus whether a backup is currently
    running. Admin access required."""
    return BackupListResponse(backups=_list_backups(), is_running=_running,
                              last_run=_last_run_model())


@router.post("/run", response_model=BackupRunResponse, status_code=status.HTTP_202_ACCEPTED,
             summary="Trigger a database backup")
async def run_backup(background_tasks: BackgroundTasks, _: User = Depends(require_admin)):
    """Trigger a pg_dump backup that runs in the background (returns 202
    immediately). Single-flight: returns 409 if a backup is already running.
    Backups older than 14 days are pruned after a successful dump. Admin access
    required. Returns an accepted status message."""
    global _running, _last_run
    if _running:
        raise HTTPException(status.HTTP_409_CONFLICT, "A backup is already running")
    _running = True   # claim synchronously to close the double-submit race
    started = datetime.now(timezone.utc)
    _last_run = {"state": "running", "started_at": _iso(started),
                 "finished_at": None, "filename": None, "error": None}
    background_tasks.add_task(_run_backup, started)
    return BackupRunResponse(status="accepted", message="Backup started in background",
                             started_at=_iso(started))
