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
from core.errors import ApiError, ApiErrorBody

router = APIRouter(prefix="/api/admin/backups", tags=["admin"])

logger = logging.getLogger("backup")

# .sql.gz = legacy/plaintext dump; .sql.gz.age = age-encrypted (BACKUP_AGE_RECIPIENT).
_BACKUP_RE = re.compile(r"^fenrir_backup_(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})\.sql\.gz(\.age)?$")

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
    if "backup_age_recipient" in msg:
        return "No age recipient configured (BACKUP_AGE_RECIPIENT): no unencrypted dump was written."
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
        recipient = settings.backup_age_recipient
        if not recipient:          # R106: never an unencrypted dump (run_backup refuses up front too)
            raise RuntimeError("BACKUP_AGE_RECIPIENT is not set: refusing to write an unencrypted dump")
        host, user, pw, db = _pg_creds()
        ts       = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
        out_path = Path(settings.backup_path) / f"fenrir_backup_{ts}.sql.gz"
        out_path.parent.mkdir(parents=True, exist_ok=True)

        # Minimal child environment: pg_dump gets its password and PATH, nothing else.
        env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "PGPASSWORD": pw}
        if settings.db_ssl_ca:   # same verify-full TLS as the app's own connections
            env.update(PGSSLMODE="verify-full", PGSSLROOTCERT=settings.db_ssl_ca)
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

        # Compress and encrypt OFF the event loop (single uvicorn worker), then write
        # atomically via a .tmp that the listing regex never matches. Fails CLOSED: a
        # failed age run → no file.
        data = await asyncio.to_thread(gzip.compress, stdout)
        age = await asyncio.create_subprocess_exec(
            "age", "-r", recipient,
            env={"PATH": env["PATH"]},
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        data, age_err = await age.communicate(data)
        if age.returncode != 0:
            raise RuntimeError(f"age encryption failed: {age_err.decode()[:300]}")
        out_path = out_path.with_name(out_path.name + ".age")
        tmp_path = out_path.with_name(out_path.name + ".tmp")
        try:
            await asyncio.to_thread(tmp_path.write_bytes, data)
            tmp_path.replace(out_path)
        finally:
            tmp_path.unlink(missing_ok=True)

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
             summary="Trigger a database backup",
             responses={409: {"description": "A backup is already running"},
                        503: {"model": ApiErrorBody,
                              "description": "backup_encryption_not_configured (no BACKUP_AGE_RECIPIENT: the "
                                             "server never writes an unencrypted dump; nothing was started)"}})
async def run_backup(background_tasks: BackgroundTasks, _: User = Depends(require_admin)):
    """Trigger a pg_dump backup that runs in the background (returns 202
    immediately). The dump is gzip-compressed and age-encrypted to the server's
    BACKUP_AGE_RECIPIENT (public key): without one, nothing is started (503
    backup_encryption_not_configured; R106, as the backup sidecar's backup.sh) —
    a database dump holds every incident's data and is never written in plaintext.
    Single-flight: returns 409 if a backup is already running.
    Backups older than 14 days are pruned after a successful dump. Admin access
    required. Returns an accepted status message."""
    global _running, _last_run
    if not settings.backup_age_recipient:
        logger.error("manual backup refused: BACKUP_AGE_RECIPIENT is not set (no unencrypted dumps)")
        raise ApiError(status.HTTP_503_SERVICE_UNAVAILABLE, "backup_encryption_not_configured",
                       "No age recipient is configured (BACKUP_AGE_RECIPIENT), so the backup was not started: "
                       "the server never writes an unencrypted database dump. Set the age public key in .env "
                       "(the same one the backup sidecar uses) and restart the backend.")
    if _running:
        raise HTTPException(status.HTTP_409_CONFLICT, "A backup is already running")
    _running = True   # claim synchronously to close the double-submit race
    started = datetime.now(timezone.utc)
    _last_run = {"state": "running", "started_at": _iso(started),
                 "finished_at": None, "filename": None, "error": None}
    background_tasks.add_task(_run_backup, started)
    return BackupRunResponse(status="accepted", message="Backup started in background",
                             started_at=_iso(started))
