"""Contacts directory (E2): the organisation's prepared external contacts.

Supervisory authority, national CSIRT, police cyber unit, insurer, IR retainer, PR, and any other
party worth having before an incident starts. Analysts and admins read it; only admins write it.
An incident gets its own COPY of an entry (POST /api/incidents/{id}/stakeholders with
contact_id), so editing or deleting a directory entry never rewrites a case record.

Verification is a server-side stamp: PATCH {"verified": true} sets last_verified_at to the
server's time and verified_by to the caller; neither can be supplied. Readiness check
`contacts_directory` warns when one of the six key types is missing or older than 90 days.
"""
import base64
import json
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import require_admin, require_analyst
from core.database import get_db
from core.errors import ApiError
from models import OrgContact, User, utcnow
from schemas import (OrgContactCreate, OrgContactList, OrgContactOut, OrgContactUpdate,
                     StakeholderType)

router = APIRouter()

# A directory holds tens of entries; a cursor past this offset is not one we issued (L9).
_MAX_OFFSET = 100_000


# L11, accepted: a row deleted between two page reads makes an offset cursor skip one row; the war room pages by keyset.
def _encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"o": offset}).encode()).decode().rstrip("=")


def _decode_cursor(cursor: Optional[str]) -> int:
    if not cursor:
        return 0
    try:
        data = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode())
        offset = max(0, int(data.get("o", 0)))
    except Exception:
        raise ApiError(status.HTTP_400_BAD_REQUEST, "invalid_cursor", "Invalid cursor")
    if offset > _MAX_OFFSET:
        raise ApiError(status.HTTP_400_BAD_REQUEST, "invalid_cursor", "Invalid cursor")
    return offset


def _label(contact_type: str) -> str:
    """Audit resource_label: the type, never the person's name (audit rows are hash-chained and can't
    be erased; the name stays findable through resource_id while the entry exists) (L13)."""
    return f"{contact_type} contact"


def _like(q: str) -> str:
    """Substring pattern with LIKE wildcards in the user's text escaped (ESCAPE '\\')."""
    return "%" + q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _out(c: OrgContact, verified_by_username: Optional[str]) -> OrgContactOut:
    return OrgContactOut(
        id=c.id, name=c.name, title=c.title, organization=c.organization, type=c.type,
        contact_methods=c.contact_methods or [], notes=c.notes, available_hours=c.available_hours,
        last_verified_at=c.last_verified_at, verified_by_id=c.verified_by_id,
        verified_by_username=verified_by_username, created_at=c.created_at, updated_at=c.updated_at,
    )


async def _get(db: AsyncSession, contact_id: uuid.UUID) -> tuple[OrgContact, Optional[str]]:
    row = (await db.execute(
        select(OrgContact, User.username)
        .outerjoin(User, User.id == OrgContact.verified_by_id)
        .where(OrgContact.id == contact_id)
    )).first()
    if row is None:
        raise ApiError(status.HTTP_404_NOT_FOUND, "contact_not_found", "Contact not found")
    return row[0], row[1]


@router.get("", response_model=OrgContactList, summary="List directory contacts")
async def list_contacts(
    type:   Optional[StakeholderType] = Query(None, description="Only this stakeholder type."),
    q:      Optional[str] = Query(None, max_length=200,
                                  description="Case-insensitive substring of name, organization or title."),
    limit:  int           = Query(100, ge=1, le=200),
    cursor: Optional[str] = Query(None, description="Opaque next_cursor from the previous page."),
    _: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> OrgContactList:
    """List the organisation's Contacts directory, ordered by name. Analysts and admins; viewers
    get 403. Filter by `type` and free-text `q`; page with `limit` (1-200) and `cursor` (400
    invalid_cursor if malformed or past offset 100000). Each entry
    shows when it was last verified (`last_verified_at`, server time) and by whom."""
    offset = _decode_cursor(cursor)
    stmt = (select(OrgContact, User.username)
            .outerjoin(User, User.id == OrgContact.verified_by_id))
    if type:
        stmt = stmt.where(OrgContact.type == type)
    if q and q.strip():
        pat = _like(q.strip())
        stmt = stmt.where(or_(func.lower(OrgContact.name).like(pat, escape="\\"),
                              func.lower(func.coalesce(OrgContact.organization, "")).like(pat, escape="\\"),
                              func.lower(func.coalesce(OrgContact.title, "")).like(pat, escape="\\")))
    rows = (await db.execute(stmt.order_by(func.lower(OrgContact.name), OrgContact.id)
                             .offset(offset).limit(limit + 1))).all()
    page = rows[:limit]
    return OrgContactList(items=[_out(c, u) for c, u in page],
                          next_cursor=_encode_cursor(offset + limit) if len(rows) > limit else None)


@router.get("/{contact_id}", response_model=OrgContactOut, summary="Get a directory contact")
async def get_contact(
    contact_id: uuid.UUID,
    _: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
) -> OrgContactOut:
    """One Contacts-directory entry. Analysts and admins; 404 contact_not_found if absent."""
    return _out(*await _get(db, contact_id))


@router.post("", response_model=OrgContactOut, status_code=status.HTTP_201_CREATED,
             summary="Add a directory contact")
async def create_contact(
    req: OrgContactCreate,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> OrgContactOut:
    """Add an entry to the Contacts directory. Admins only (analysts and viewers get 403). A new
    entry is unverified until an admin PATCHes it with {"verified": true}. Audited
    (org_contact_create)."""
    c = OrgContact(
        id=uuid.uuid4(), name=req.name, title=req.title, organization=req.organization, type=req.type,
        contact_methods=[m.model_dump() for m in req.contact_methods], notes=req.notes,
        available_hours=req.available_hours, created_by_id=admin.id,
    )
    db.add(c)
    await db.flush()
    await write_audit(db, "org_contact_create", resource_type="org_contact", resource_id=str(c.id),
                      resource_label=_label(c.type), details={"type": c.type})
    await db.commit()
    return _out(*await _get(db, c.id))


@router.patch("/{contact_id}", response_model=OrgContactOut, summary="Update or verify a directory contact")
async def update_contact(
    contact_id: uuid.UUID,
    req: OrgContactUpdate,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> OrgContactOut:
    """Change fields of a directory entry (only the fields sent), and/or mark it verified with
    {"verified": true}: that stamps `last_verified_at` with the server's current time and
    `verified_by` with you. Admins only. Incidents that already copied this entry keep their copy.
    Audited (org_contact_update, or org_contact_verify for a verification alone)."""
    c, _ = await _get(db, contact_id)
    changed = []
    for f in ("name", "title", "organization", "type", "notes", "available_hours"):
        v = getattr(req, f)
        if v is not None and v != getattr(c, f):
            setattr(c, f, v)
            changed.append(f)
    if req.contact_methods is not None:
        methods = [m.model_dump() for m in req.contact_methods]
        if methods != (c.contact_methods or []):
            c.contact_methods = methods
            changed.append("contact_methods")
    if req.verified:
        c.last_verified_at = utcnow()
        c.verified_by_id = admin.id
    if changed or req.verified:
        await write_audit(db, "org_contact_update" if changed else "org_contact_verify",
                          resource_type="org_contact", resource_id=str(c.id), resource_label=_label(c.type),
                          details={"fields": changed, "verified": bool(req.verified)})
    await db.commit()
    return _out(*await _get(db, c.id))


@router.delete("/{contact_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a directory contact")
async def delete_contact(
    contact_id: uuid.UUID,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Remove an entry from the Contacts directory. Admins only. Copies already added to incidents
    are kept. Audited (org_contact_delete). Returns 204."""
    c, _ = await _get(db, contact_id)
    await write_audit(db, "org_contact_delete", resource_type="org_contact", resource_id=str(c.id),
                      resource_label=_label(c.type), details={"type": c.type})
    await db.delete(c)
    await db.commit()
