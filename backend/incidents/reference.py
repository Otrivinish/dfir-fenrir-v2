"""Incident reference — assigned once at creation, never recomputed.

Format ``{PREFIX}-{YYYY}-{NNNNN}`` (e.g. ``INC-2026-00009``):
  PREFIX  operator setting ``incident_ref.prefix`` (default ``INC``), ``^[A-Z][A-Z0-9]{1,9}$``
  YYYY    UTC creation year — informational, never used for uniqueness
  NNNNN   global, non-resetting ``incident_seq`` value, zero-padded to 5 (grows past 99999)

Incidents created before this format keep their original ``INC-NNNN`` reference
(backfilled once in ``core/database.py``), so references already printed in reports,
LE packages and audit exports stay valid. A database trigger rejects any change to
``incidents.ref`` after insert.
"""
import re
from datetime import datetime

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from core.security import decrypt_secret, encrypt_secret
from models import PlatformSetting, utcnow

PREFIX_KEY     = "incident_ref.prefix"
DEFAULT_PREFIX = "INC"
PREFIX_RE      = re.compile(r"^[A-Z][A-Z0-9]{1,9}$")
# Accepts both the legacy (INC-0002) and current (INC-2026-00009) forms.
REF_RE         = re.compile(r"^[A-Z][A-Z0-9]{1,9}-(\d{4}-)?\d{4,}$")


def format_ref(prefix: str, year: int, number: int) -> str:
    return f"{prefix}-{year:04d}-{number:05d}"


async def get_prefix(db: AsyncSession) -> str:
    row = (await db.execute(
        select(PlatformSetting).where(PlatformSetting.key == PREFIX_KEY)
    )).scalar_one_or_none()
    if not row:
        return DEFAULT_PREFIX
    try:
        value = decrypt_secret(row.encrypted_value)
    except Exception:
        return DEFAULT_PREFIX
    return value if PREFIX_RE.fullmatch(value) else DEFAULT_PREFIX


async def set_prefix(db: AsyncSession, prefix: str, user_id) -> None:
    if not PREFIX_RE.fullmatch(prefix):
        raise ValueError("prefix must match ^[A-Z][A-Z0-9]{1,9}$")
    enc = encrypt_secret(prefix)
    await db.execute(
        pg_insert(PlatformSetting)
        .values(key=PREFIX_KEY, encrypted_value=enc, updated_by_id=user_id)
        .on_conflict_do_update(index_elements=["key"],
                               set_={"encrypted_value": enc, "updated_by_id": user_id})
    )


async def assign(db: AsyncSession) -> tuple[int, str, datetime]:
    """Allocate (incident_number, ref, created_at) for a new incident.

    The creation time is returned so the caller stores the same instant the
    reference's year was taken from.
    """
    number = (await db.execute(text("SELECT nextval('incident_seq')"))).scalar()
    now = utcnow()
    return number, format_ref(await get_prefix(db), now.year, number), now


async def preview_next(db: AsyncSession, prefix: str | None = None) -> str:
    """The reference the next incident would get (without consuming the sequence)."""
    last_value, is_called = (await db.execute(
        text("SELECT last_value, is_called FROM incident_seq")
    )).one()
    number = last_value + 1 if is_called else last_value
    return format_ref(prefix or await get_prefix(db), utcnow().year, number)
