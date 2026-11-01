"""S6 (EG-4, HLD §3.5, §3.10): a container exhibit's manifest.

- GET  /{id}/evidence/{eid}/manifest          — its entries, cursor-paginated, `q` = path search; `format=csv` streams
                                                every matching entry as CSV
- POST /{id}/evidence/{eid}/manifest/rebuild  — queue the build again (failed or pending only; a built one is fixed)

The build itself runs in the background (evidence/manifest.py); its state is on the exhibit (EvidenceOut
container_format, manifest_status, manifest_sha256, manifest_entries, manifest_builder, manifest_error,
manifest_listing).
"""
from __future__ import annotations

import base64
import json
import re
import uuid
from typing import Literal, Optional

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user, require_analyst
from core.database import get_db
from core.errors import ApiError, ApiErrorBody
from evidence import manifest as container_manifest
from evidence.manifest_index import INDEXED_FORMATS, csv_bytes
from evidence.routes import _get_evidence, _get_incident, _to_out
from models import EvidenceManifestEntry, User
from schemas import EvidenceOut, ManifestEntryList, ManifestEntryOut

router = APIRouter()
_E = lambda d: {"model": ApiErrorBody, "description": d}          # noqa: E731


def _cursor(seq: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"s": seq}).encode()).decode().rstrip("=")


def _after(cursor: Optional[str]) -> int:
    if not cursor:
        return 0
    try:
        return max(0, int(json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))["s"]))
    except Exception:
        raise ApiError(status.HTTP_400_BAD_REQUEST, "invalid_cursor", "Invalid cursor") from None


def _path_filter(q: Optional[str]) -> list:
    """Case-insensitive substring of entry_path or source_path (LIKE wildcards in q are literal)."""
    if not q:
        return []
    like = "%" + re.sub(r"([\\%_])", r"\\\1", q) + "%"
    return [or_(EvidenceManifestEntry.entry_path.ilike(like, escape="\\"),
                EvidenceManifestEntry.source_path.ilike(like, escape="\\"))]


@router.get(
    "/{incident_id}/evidence/{evidence_id}/manifest",
    response_model=ManifestEntryList,
    summary="List a container exhibit's manifest entries (or stream them as CSV)",
    responses={200: {"content": {"text/csv": {"schema": {"type": "string"}}},
                     "description": "JSON {items, next_cursor}; with format=csv every matching entry as CSV "
                                    "(UTF-8 with BOM; cells formula-escaped; hash the JSONL, never the CSV)"},
               400: _E("invalid_cursor"),
               404: _E("the incident or the item"),
               409: _E("manifest_not_built (the body's manifest_status says why: pending, failed, not_indexed or "
                       "null for an exhibit that is not a container)")},
)
async def get_evidence_manifest(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    limit:  int = Query(100, ge=1, le=1000),
    cursor: Optional[str] = Query(None, description="Opaque; next_cursor of the previous page"),
    q:      Optional[str] = Query(None, max_length=1024, description="Case-insensitive substring of the entry path "
                                                                     "or the source path"),
    format: Literal["json", "csv"] = Query("json", description="csv: stream every matching entry (ignores limit "
                                                               "and cursor)"),
    user: User = Depends(current_user),
    db:   AsyncSession = Depends(get_db),
):
    """S6 (ISO/IEC 27037 §7.1.3.4): the members of a container exhibit as FENRIR read them from the stored bytes, in
    container order (`seq`): the verbatim entry path (and its raw bytes when they are not that path's UTF-8), the
    tool listing's source path, type, sizes, times with their basis, FENRIR's MD5 / SHA-1 / SHA-256 of the member,
    the tool's hash and whether it matched. `q` filters by a case-insensitive substring of the entry or source path.
    Entry paths follow the exhibit's TLP. Requires access to the incident. 409 manifest_not_built unless the
    exhibit's manifest_status is built."""
    await _get_incident(db, incident_id, user)
    ev = await _get_evidence(db, incident_id, evidence_id)
    if ev.manifest_status != "built":
        raise ApiError(status.HTTP_409_CONFLICT, "manifest_not_built",
                       f"The exhibit has no built manifest (manifest_status {ev.manifest_status or 'null'})",
                       extra={"manifest_status": ev.manifest_status})
    where = _path_filter(q)
    if format == "csv":
        async def body():
            yield csv_bytes([], header=True)
            async for batch in container_manifest.entry_batches(db, ev.id, *where):
                yield csv_bytes(batch, header=False)
        name = re.sub(r"[^A-Za-z0-9._-]+", "_", ev.identifier)[:80] or "exhibit"
        return StreamingResponse(body(), media_type="text/csv; charset=utf-8",
                                 headers={"Content-Disposition": f'attachment; filename="{name}__manifest.csv"'})
    rows = (await db.execute(
        select(EvidenceManifestEntry)
        .where(EvidenceManifestEntry.evidence_id == ev.id, EvidenceManifestEntry.seq > _after(cursor), *where)
        .order_by(EvidenceManifestEntry.seq).limit(limit + 1)
    )).scalars().all()
    more = len(rows) > limit
    rows = rows[:limit]
    return ManifestEntryList(items=[ManifestEntryOut.model_validate(r) for r in rows],
                             next_cursor=_cursor(rows[-1].seq) if more else None)


@router.post(
    "/{incident_id}/evidence/{evidence_id}/manifest/rebuild",
    response_model=EvidenceOut,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue a container exhibit's manifest build again (failed or pending only)",
    responses={404: _E("the incident or the item"),
               409: _E("incident_closed, manifest_built (a built manifest is fixed), manifest_not_indexed (not a "
                       "zip / tar container)")},
)
async def rebuild_evidence_manifest(
    incident_id: uuid.UUID,
    evidence_id: uuid.UUID,
    request: Request,
    user: User = Depends(require_analyst),
    db:   AsyncSession = Depends(get_db),
) -> EvidenceOut:
    """S6: build the manifest of a zip / tar container exhibit again after a failure (manifest_error says why), or
    queue a pending one that is not progressing. manifest_status becomes pending and the build runs in the
    background; poll the exhibit. A built manifest never changes (409 manifest_built). Allowed after the seal: a
    manifest built then is reported by GET …/seal-record as a change since the seal. Requires the analyst role and an
    open incident. Audited `evidence_manifest_rebuild`. 202 with the exhibit."""
    inc = await _get_incident(db, incident_id, user)
    if inc.status == "closed":
        raise ApiError(status.HTTP_409_CONFLICT, "incident_closed", "Incident is closed")
    ev = await _get_evidence(db, incident_id, evidence_id, for_update=True)
    if ev.container_format not in INDEXED_FORMATS:
        raise ApiError(status.HTTP_409_CONFLICT, "manifest_not_indexed",
                       "FENRIR builds manifests for zip and tar containers only")
    if ev.manifest_status == "built":
        raise ApiError(status.HTTP_409_CONFLICT, "manifest_built", "The manifest is built and can't be rebuilt")
    before, error_before = ev.manifest_status, ev.manifest_error
    ev.manifest_status, ev.manifest_error = "pending", None
    await write_audit(
        db, "evidence_manifest_rebuild",
        user_id=user.id, username=user.username,
        resource_type="evidence", resource_id=str(ev.id), outcome="success",
        details={"incident_id": str(incident_id), "identifier": ev.identifier, "container_format": ev.container_format,
                 "manifest_status_before": before, "manifest_error_before": error_before},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    container_manifest.enqueue(ev.id, (user.id, user.username))
    return _to_out(ev)
