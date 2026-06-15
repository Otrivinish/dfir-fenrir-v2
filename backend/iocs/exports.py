"""IOC export endpoints — one per supported security platform.

Mounted at prefix="/api/incidents". Route pattern: GET /{incident_id}/iocs/export/{fmt}

IMPORTANT: This router MUST be included in main.py BEFORE iocs_router so FastAPI
matches the literal 'export' segment before the parametric {ioc_id} in iocs/{ioc_id}.
"""
import csv
import io
import json
import re
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Literal
from xml.etree import ElementTree as ET

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.service import write_audit
from auth.deps import current_user
from core.database import get_db
from models import IOC, Incident, User

router = APIRouter()

ExportFormat = Literal[
    "mde-csv", "mde-json",
    "crowdstrike", "sentinelone", "cortex-xdr",
    "fortigate", "panos",
]

# ── Type maps ─────────────────────────────────────────────────────────────────

_MDE_TYPE = {
    "ip":          "IpAddress",
    "domain":      "DomainName",
    "url":         "Url",
    "hash_md5":    "FileMd5",
    "hash_sha1":   "FileSha1",
    "hash_sha256": "FileSha256",
}

_CROWDSTRIKE_TYPE = {
    "ip":          "ip_address",
    "domain":      "domain",
    "url":         "url",
    "hash_md5":    "md5",
    "hash_sha256": "sha256",
}

_SENTINELONE_TYPE = {
    "ip":          "IPV4",
    "domain":      "DOMAIN",
    "url":         "URL",
    "hash_md5":    "MD5",
    "hash_sha1":   "SHA1",
    "hash_sha256": "SHA256",
}

_CORTEX_TYPE = {
    "ip":          "IP",
    "domain":      "DOMAIN_NAME",
    "hash_md5":    "HASH",
    "hash_sha1":   "HASH",
    "hash_sha256": "HASH",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _load_iocs(db: AsyncSession, incident_id: uuid.UUID) -> list[IOC]:
    inc = (await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )).scalar_one_or_none()
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    rows = (await db.execute(
        select(IOC)
        .where(IOC.incident_id == incident_id)
        .order_by(IOC.added_at)
    )).scalars().all()
    return rows


def _utc_expiry(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_name(value: str, max_len: int = 63) -> str:
    """Strip characters not allowed in FortiGate / PAN-OS address names."""
    return re.sub(r"[^A-Za-z0-9._\-]", "-", value)[:max_len]


# ── Single export endpoint ────────────────────────────────────────────────────

@router.get("/{incident_id}/iocs/export/{fmt}", summary="Export incident IOCs for a security platform")
async def export_iocs(
    incident_id: uuid.UUID,
    fmt: ExportFormat,
    request: Request,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
    action:      str = Query(default="Alert"),
    severity:    str = Query(default="Medium"),
    expiry_days: int = Query(default=90, ge=1, le=3650),
    prefix:      str = Query(default=""),
) -> Response:
    """Export all of an incident's IOCs as a downloadable file formatted for a
    security platform. The `fmt` path param selects the target: mde-csv,
    mde-json, crowdstrike, sentinelone, cortex-xdr, fortigate, or panos. Query
    params `action`, `severity`, and `expiry_days` apply to the MDE formats;
    `prefix` names objects in the FortiGate and PAN-OS outputs. Returns 404 if
    the incident does not exist, writes an audit record, and requires an
    authenticated user. Returns a file Response (CSV, JSON, FortiGate CLI script,
    or a PAN-OS XML + EDL ZIP) with an attachment Content-Disposition.
    """
    iocs = await _load_iocs(db, incident_id)
    short = str(incident_id)[:8]

    await write_audit(
        db, "ioc_export",
        user_id=user.id, username=user.username,
        resource_type="incident", resource_id=str(incident_id),
        details={"format": fmt, "count": len(iocs)},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    if fmt == "mde-csv":
        return _export_mde_csv(iocs, short, action, severity, expiry_days)
    if fmt == "mde-json":
        return _export_mde_json(iocs, short, action, severity, expiry_days)
    if fmt == "crowdstrike":
        return _export_crowdstrike(iocs, short)
    if fmt == "sentinelone":
        return _export_sentinelone(iocs, short)
    if fmt == "cortex-xdr":
        return _export_cortex(iocs, short)
    if fmt == "fortigate":
        return _export_fortigate(iocs, short, prefix)
    # panos
    return _export_panos(iocs, short, prefix)


# ── MDE CSV ───────────────────────────────────────────────────────────────────

def _export_mde_csv(iocs: list, short: str, action: str, severity: str, expiry_days: int) -> Response:
    expiry = _utc_expiry(expiry_days)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=[
        "IndicatorType", "IndicatorValue", "ExpirationTime",
        "Action", "Severity", "Title", "Description",
        "RecommendedActions", "RbacGroups", "Tags",
    ])
    w.writeheader()
    for ioc in iocs:
        itype = _MDE_TYPE.get(ioc.type)
        if not itype:
            continue
        w.writerow({
            "IndicatorType":      itype,
            "IndicatorValue":     ioc.value,
            "ExpirationTime":     expiry,
            "Action":             action,
            "Severity":           severity,
            "Title":              f"DFIR-FENRIR incident {short}",
            "Description":        (ioc.notes or f"Exported from incident {short}")[:500],
            "RecommendedActions": "Investigate and isolate if confirmed.",
            "RbacGroups":         "",
            # MDE doesn't have a native tags field — we emit `;`-joined so the
            # column round-trips cleanly through Excel and stays grep-able.
            "Tags":               ";".join(ioc.tags or []),
        })
    # utf-8-sig BOM for Excel compatibility
    content = buf.getvalue().encode("utf-8-sig")
    return Response(
        content=content,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="mde-iocs-{short}.csv"',
            "Content-Length": str(len(content)),
        },
    )


# ── MDE JSON ──────────────────────────────────────────────────────────────────

def _export_mde_json(iocs: list, short: str, action: str, severity: str, expiry_days: int) -> Response:
    expiry = _utc_expiry(expiry_days)
    items = []
    for ioc in iocs:
        itype = _MDE_TYPE.get(ioc.type)
        if not itype:
            continue
        items.append({
            "indicatorType":      itype,
            "indicatorValue":     ioc.value,
            "expirationTime":     expiry,
            "action":             action,
            "severity":           severity,
            "title":              f"DFIR-FENRIR incident {short}",
            "description":        (ioc.notes or f"Exported from incident {short}")[:500],
            "recommendedActions": "Investigate and isolate if confirmed.",
            "rbacGroupNames":     [],
            "tags":               list(ioc.tags or []),
        })
    content = json.dumps({"value": items}, indent=2).encode()
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="mde-iocs-{short}.json"',
            "Content-Length": str(len(content)),
        },
    )


# ── CrowdStrike ───────────────────────────────────────────────────────────────

def _export_crowdstrike(iocs: list, short: str) -> Response:
    items = []
    for ioc in iocs:
        itype = _CROWDSTRIKE_TYPE.get(ioc.type)
        if not itype:
            continue
        items.append({
            "type":        itype,
            "value":       ioc.value,
            "action":      "detect",
            "severity":    "MEDIUM",
            "description": (ioc.notes or f"Exported from DFIR-FENRIR incident {short}")[:500],
            # Existing `fenrir-{short}` provenance tag preserved; analyst-supplied
            # tags now pre-pended so they survive the round-trip into CrowdStrike.
            "tags":        list(ioc.tags or []) + [f"fenrir-{short}"],
        })
    content = json.dumps({"resources": items}, indent=2).encode()
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="crowdstrike-iocs-{short}.json"',
            "Content-Length": str(len(content)),
        },
    )


# ── SentinelOne ───────────────────────────────────────────────────────────────

def _export_sentinelone(iocs: list, short: str) -> Response:
    items = []
    for ioc in iocs:
        itype = _SENTINELONE_TYPE.get(ioc.type)
        if not itype:
            continue
        items.append({
            "type":        itype,
            "value":       ioc.value,
            "source":      f"DFIR-FENRIR incident {short}",
            "description": (ioc.notes or "")[:500],
            "name":        f"fenrir-{short}-{ioc.value[:30]}",
            "tags":        list(ioc.tags or []),
        })
    content = json.dumps({"data": items}, indent=2).encode()
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="sentinelone-iocs-{short}.json"',
            "Content-Length": str(len(content)),
        },
    )


# ── Cortex XDR ────────────────────────────────────────────────────────────────

def _export_cortex(iocs: list, short: str) -> Response:
    items = []
    for ioc in iocs:
        itype = _CORTEX_TYPE.get(ioc.type)
        if not itype:
            continue
        items.append({
            "indicator":   ioc.value,
            "type":        itype,
            "severity":    "MEDIUM",
            "comment":     (ioc.notes or f"DFIR-FENRIR incident {short}")[:500],
            "vendors":     [],
            "class":       "MALICIOUS",
            # Cortex XDR's indicator schema doesn't define a `tags` field, but
            # the platform ignores unknown keys on upload — preserving them lets
            # downstream tooling keep the analyst provenance.
            "tags":        list(ioc.tags or []),
        })
    content = json.dumps({"reply": {"indicators": items}}, indent=2).encode()
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="cortex-xdr-iocs-{short}.json"',
            "Content-Length": str(len(content)),
        },
    )


# ── FortiGate CLI script ───────────────────────────────────────────────────────

def _export_fortigate(iocs: list, short: str, prefix: str) -> Response:
    # No tags column: FortiGate address objects only carry a free-text `comment`
    # already used for ioc.notes; smuggling tags into it would pollute the only
    # human-readable field. Analysts who need tag provenance should pair this
    # export with a JSON export (MDE/CrowdStrike/etc) that has a native tags slot.
    pfx = (prefix or f"fenrir-{short}").replace(" ", "-")[:20]
    grp_name = f"{pfx}-ioc-grp"[:63]
    lines = [
        f"# DFIR-FENRIR — FortiGate IOC block script",
        f"# Incident : {short}",
        f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"# Import   : paste into CLI or System > Config > Restore (script mode)",
        "",
        "config firewall address",
    ]
    names: list[str] = []
    for ioc in iocs:
        if ioc.type not in ("ip", "domain"):
            continue
        name = f"{pfx}-{_safe_name(ioc.value)}"[:63]
        names.append(name)
        comment = (ioc.notes or "")[:255].replace('"', "'")
        lines.append(f'  edit "{name}"')
        if ioc.type == "ip":
            lines.append(f"    set type ipmask")
            lines.append(f"    set subnet {ioc.value} 255.255.255.255")
        else:
            lines.append(f"    set type fqdn")
            lines.append(f'    set fqdn "{ioc.value}"')
        if comment:
            lines.append(f'    set comment "{comment}"')
        lines.append("  next")
    lines.append("end")
    if names:
        members = " ".join(f'"{n}"' for n in names)
        lines += [
            "",
            "config firewall addrgrp",
            f'  edit "{grp_name}"',
            f"    set member {members}",
            "  next",
            "end",
        ]
    content = "\n".join(lines).encode()
    return Response(
        content=content,
        media_type="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="fortigate-iocs-{short}.conf"',
            "Content-Length": str(len(content)),
        },
    )


# ── Palo Alto PAN-OS XML + EDL ZIP ────────────────────────────────────────────

def _export_panos(iocs: list, short: str, prefix: str) -> Response:
    # No tags column: PAN-OS address objects + EDL plaintext files have no
    # native tags field — the XML `<description>` already carries ioc.notes and
    # EDLs are pure value-per-line. See `_export_fortigate` for the same rationale.
    pfx = (prefix or f"fenrir-{short}").replace(" ", "-")[:20]
    ip_edl:     list[str] = []
    domain_edl: list[str] = []
    url_edl:    list[str] = []

    addr_root = ET.Element("config")
    devices   = ET.SubElement(addr_root, "devices")
    dev_entry = ET.SubElement(devices, "entry", name="localhost.localdomain")
    vsys_root = ET.SubElement(dev_entry, "vsys")
    vsys_ent  = ET.SubElement(vsys_root, "entry", name="vsys1")
    address   = ET.SubElement(vsys_ent, "address")

    for ioc in iocs:
        if ioc.type == "ip":
            ip_edl.append(ioc.value)
            ent = ET.SubElement(address, "entry", name=f"{pfx}-{_safe_name(ioc.value)}"[:63])
            ET.SubElement(ent, "ip-netmask").text = f"{ioc.value}/32"
            if ioc.notes:
                ET.SubElement(ent, "description").text = ioc.notes[:255]
        elif ioc.type == "domain":
            domain_edl.append(ioc.value)
            ent = ET.SubElement(address, "entry", name=f"{pfx}-{_safe_name(ioc.value)}"[:63])
            ET.SubElement(ent, "fqdn").text = ioc.value
            if ioc.notes:
                ET.SubElement(ent, "description").text = ioc.notes[:255]
        elif ioc.type == "url":
            url_edl.append(ioc.value)

    xml_str   = ET.tostring(addr_root, encoding="unicode")
    xml_bytes = ('<?xml version="1.0" encoding="UTF-8"?>\n' + xml_str).encode()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"panos-addresses-{short}.xml", xml_bytes)
        if ip_edl:
            z.writestr(f"edl-ip-{short}.txt",     "\n".join(ip_edl))
        if domain_edl:
            z.writestr(f"edl-domain-{short}.txt", "\n".join(domain_edl))
        if url_edl:
            z.writestr(f"edl-url-{short}.txt",    "\n".join(url_edl))
    content = buf.getvalue()
    return Response(
        content=content,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="panos-iocs-{short}.zip"',
            "Content-Length": str(len(content)),
        },
    )
