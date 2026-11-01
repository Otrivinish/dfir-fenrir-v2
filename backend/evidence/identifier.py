"""EI — automatic exhibit identifiers (docs/evidence-auto-identifier-slice.md).

An exhibit registered without an identifier (left out, null or blank), and every draft FENRIR registers itself (D4),
gets one from the admin's template, filled in inside the registering transaction:

  {incident}  the incident's reference as stored (a legacy INC-0002 stays as it is)
  {date}      YYYYMMDD, the UTC day of registration: the same instant as the row's collected_at (D1)
  {seq}       the exhibit's number in the incident, zero-padded to 3 digits; {seq:N} pads to N (1–6); grows past it

Literal text: A–Z a–z 0–9 . _ - (an identifier stays safe in a file name and in "<identifier>-WC-n"). Checked when
saved: {seq} exactly once (it keeps identifiers unique within an incident), known tokens only, at most 64 characters,
and the longest possible result (a 32-character reference, a 9-digit number) fits evidence.identifier (128). Stored in
platform_settings `evidence_identifier.template`, encrypted as incidents/reference.py stores the prefix; no row (or one
that no longer decrypts or passes the rules) = DEFAULT_TEMPLATE.

The number: evidence_identifier_counters, one row per incident, bumped with INSERT … ON CONFLICT DO UPDATE …
RETURNING in the caller's transaction. A concurrent registration in the same incident waits on that row until the
first one ends, so the two get different numbers, and a rolled-back registration gives its number back (D2: per
incident, never reset). Only automatic identifiers use numbers (D3); one already typed by hand is skipped and the next
number taken, so an automatic identifier never ends in 409 (the unique constraint stays the backstop).
"""
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from core.security import decrypt_secret, encrypt_secret
from models import Evidence, EvidenceIdentifierCounter, PlatformSetting, utcnow

TEMPLATE_KEY     = "evidence_identifier.template"
DEFAULT_TEMPLATE = "{incident}-{date}-{seq:3}"
TEMPLATE_MAX     = 64
IDENTIFIER_MAX   = 128          # evidence.identifier
WORST_REF        = 32           # incidents.ref
WORST_SEQ        = 9            # digits
DEFAULT_WIDTH    = 3
TOKENS = [
    ("{incident}", "The incident's reference, as stored (an older INC-0002 stays as it is)."),
    ("{date}", "The UTC day the exhibit is registered, as YYYYMMDD."),
    ("{seq}", "The exhibit's number in the incident, zero-padded to 3 digits; it grows past them. Required, exactly "
              "once. Only automatically assigned identifiers use a number."),
    ("{seq:N}", "The same number, zero-padded to N digits (N = 1 to 6)."),
]

_PART = re.compile(r"\{(incident|date|seq(?::([0-9]+))?)\}|[A-Za-z0-9._-]+")


def _parse(template: str) -> list[tuple[str, object]]:
    """[("text", s) | ("incident", None) | ("date", None) | ("seq", width)], or ValueError(the rule it breaks)."""
    parts, pos = [], 0
    while pos < len(template):
        m = _PART.match(template, pos)
        if m is None:
            if template[pos] == "{":
                end = template.find("}", pos)
                token = template[pos:end + 1] if end != -1 else template[pos:]
                raise ValueError(f"Unknown token {token}: use {{incident}}, {{date}}, {{seq}} or {{seq:N}}.")
            raise ValueError(f"The character {template[pos]!r} is not allowed: literal text may use A–Z, a–z, 0–9, "
                             "'.', '_' and '-'.")
        if m.group(1) is None:
            parts.append(("text", m.group(0)))
        elif m.group(1).startswith("seq"):
            width = int(m.group(2)) if m.group(2) is not None else DEFAULT_WIDTH
            if not 1 <= width <= 6:
                raise ValueError(f"{m.group(0)}: N must be 1 to 6.")
            parts.append(("seq", width))
        else:
            parts.append((m.group(1), None))
        pos = m.end()
    return parts


def template_error(template: str) -> Optional[str]:
    """Why the template breaks a rule (the first one it breaks), or None."""
    if len(template) > TEMPLATE_MAX:
        return f"The template is {len(template)} characters long; at most {TEMPLATE_MAX}."
    try:
        parts = _parse(template)
    except ValueError as e:
        return str(e)
    seqs = sum(1 for kind, _ in parts if kind == "seq")
    if seqs != 1:
        return f"{{seq}} (or {{seq:N}}) must appear exactly once; it appears {seqs} times."
    worst = sum(len(v) if kind == "text" else WORST_REF if kind == "incident" else 8 if kind == "date"
                else max(v, WORST_SEQ) for kind, v in parts)
    if worst > IDENTIFIER_MAX:
        return (f"The longest identifier it can give is {worst} characters (with a {WORST_REF}-character incident "
                f"reference and a {WORST_SEQ}-digit number); at most {IDENTIFIER_MAX}.")
    return None


def expand(template: str, incident_ref: str, at: datetime, seq: int) -> str:
    out = []
    for kind, v in _parse(template):
        out.append(v if kind == "text" else incident_ref if kind == "incident"
                   else at.astimezone(timezone.utc).strftime("%Y%m%d") if kind == "date" else f"{seq:0{v}d}")
    return "".join(out)


def typed(identifier: Optional[str]) -> Optional[str]:
    """The identifier as typed, or None when it is blank (left out, null or whitespace only): assign one."""
    return identifier if identifier is not None and identifier.strip() else None


async def get_template(db: AsyncSession) -> str:
    row = (await db.execute(
        select(PlatformSetting).where(PlatformSetting.key == TEMPLATE_KEY)
    )).scalar_one_or_none()
    if not row:
        return DEFAULT_TEMPLATE
    try:
        value = decrypt_secret(row.encrypted_value)
    except Exception:
        return DEFAULT_TEMPLATE
    return value if template_error(value) is None else DEFAULT_TEMPLATE


async def set_template(db: AsyncSession, template: str, user_id) -> None:
    if (why := template_error(template)) is not None:
        raise ValueError(why)
    enc = encrypt_secret(template)
    await db.execute(
        pg_insert(PlatformSetting)
        .values(key=TEMPLATE_KEY, encrypted_value=enc, updated_by_id=user_id)
        .on_conflict_do_update(index_elements=["key"],
                               set_={"encrypted_value": enc, "updated_by_id": user_id})
    )


async def _taken(db: AsyncSession, incident_id: uuid.UUID, identifier: str) -> bool:
    return (await db.execute(select(Evidence.id).where(
        Evidence.incident_id == incident_id, Evidence.identifier == identifier).limit(1))).first() is not None


async def assign(db: AsyncSession, incident_id: uuid.UUID, incident_ref: str, at: datetime) -> tuple[str, str]:
    """(identifier, template) for a new exhibit registered at `at` (also its collected_at). Uses up the incident's
    next number in the caller's transaction (the counter row stays locked until it ends); a number whose identifier
    was already typed by hand is skipped."""
    template = await get_template(db)
    bump = (pg_insert(EvidenceIdentifierCounter).values(incident_id=incident_id, last_seq=1)
            .on_conflict_do_update(index_elements=["incident_id"],
                                   set_={"last_seq": EvidenceIdentifierCounter.last_seq + 1})
            .returning(EvidenceIdentifierCounter.last_seq))
    while True:
        seq = (await db.execute(bump)).scalar_one()
        identifier = expand(template, incident_ref, at, seq)
        if not await _taken(db, incident_id, identifier):
            return identifier, template


async def preview(db: AsyncSession, incident_id: uuid.UUID, incident_ref: str,
                  template: Optional[str] = None) -> str:
    """The identifier the incident's next automatic exhibit would get now, without using up a number (an example:
    a concurrent registration can take it first)."""
    template = template or await get_template(db)
    at = utcnow()
    seq = (await db.execute(select(EvidenceIdentifierCounter.last_seq).where(
        EvidenceIdentifierCounter.incident_id == incident_id))).scalar_one_or_none() or 0
    while True:
        seq += 1
        identifier = expand(template, incident_ref, at, seq)
        if not await _taken(db, incident_id, identifier):
            return identifier
