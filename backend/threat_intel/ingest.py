"""Feed download, parsing, and upsert logic.

SSRF protection: feed URLs are validated at creation time against RFC-1918 /
loopback ranges. DNS-resolved hostnames are trusted (feeds are admin-configured).
"""
import csv
import io
import ipaddress
import json
import logging
import re
import socket
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from sqlalchemy import select, func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from models import ThreatFeed, ThreatIntelIOC

logger = logging.getLogger(__name__)

_FEED_MAX_BYTES = 50 * 1024 * 1024   # 50 MB hard cap per feed download
_BATCH_SIZE     = 1000

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_non_routable(addr) -> bool:
    """True for any address (IPv4Address/IPv6Address) an external feed has no
    business resolving to."""
    if (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
        return True
    return any(addr in net for net in _PRIVATE_NETS)


def _host_resolves_non_routable(host: str) -> bool:
    """Resolve host (A + AAAA) and report whether ANY address is non-routable.

    Returns False if the name simply doesn't resolve — let the real request
    surface that error rather than masking it as an SSRF rejection.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        try:
            if _is_non_routable(ipaddress.ip_address(info[4][0])):
                return True
        except ValueError:
            continue
    return False


def assert_safe_feed_url(url: str) -> None:
    """SSRF guard applied at FETCH time (and per redirect hop). Unlike the
    creation-time check this resolves hostnames, so a name pointing at an
    internal address — or a DNS record flipped after creation — is rejected.

    Residual: a determined DNS-rebinding attacker controlling the feed's
    authoritative DNS could still race the resolution between this check and
    httpx's own connect. Acceptable for an admin-only feature; full closure
    needs IP-pinned transport (breaks TLS SNI for https feeds).
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Feed URL must use http or https")
    host = parsed.hostname or ""
    if not host:
        raise ValueError("Feed URL has no host")
    try:
        if _is_non_routable(ipaddress.ip_address(host)):
            raise ValueError(f"Feed URL targets a non-routable address ({host})")
    except ValueError as exc:
        if "non-routable" in str(exc):
            raise
        # Not a bare IP literal — fall through to DNS resolution.
    if _host_resolves_non_routable(host):
        raise ValueError(f"Feed URL host '{host}' resolves to a non-routable address")


def validate_feed_url(url: str) -> None:
    """Raise ValueError if the URL targets a private/loopback address.

    Creation-time check — resolves hostnames too so an obviously-internal feed
    is rejected up front. The authoritative guard is assert_safe_feed_url at
    fetch time (DNS can change between create and pull).
    """
    assert_safe_feed_url(url)


# ─── Parsers ─────────────────────────────────────────────────────────────────

def _parse_txt(content: str, cfg: dict) -> list[str]:
    comment_chars = cfg.get("txt_comment_chars", "#;")
    values = []
    for line in content.splitlines():
        line = line.strip()
        if line and line[0] not in comment_chars:
            values.append(line)
    return values


def _parse_csv(content: str, cfg: dict) -> list[str]:
    delimiter  = cfg.get("csv_delimiter", ",")
    field_name = cfg.get("csv_field")          # column header name
    field_idx  = cfg.get("csv_index", 0)       # 0-based column index (no-header mode)
    strip_port = cfg.get("csv_value_strip_port", False)

    # Strip comment/blank lines from the top
    lines = [l for l in content.splitlines() if l.strip() and not l.strip().startswith(("#", ";"))]
    if not lines:
        return []

    values = []
    if field_name:
        # First non-comment line is the header row
        reader = csv.DictReader(io.StringIO("\n".join(lines)), delimiter=delimiter)
        for row in reader:
            v = (row.get(field_name) or "").strip()
            if v:
                if strip_port:
                    v = re.sub(r":\d+$", "", v)
                values.append(v)
    else:
        # Index-based; no header assumed
        reader = csv.reader(io.StringIO("\n".join(lines)), delimiter=delimiter)
        for row in reader:
            if len(row) > field_idx:
                v = row[field_idx].strip()
                if v:
                    if strip_port:
                        v = re.sub(r":\d+$", "", v)
                    values.append(v)
    return values


def _parse_json(content: str, cfg: dict) -> list[str]:
    data        = json.loads(content)
    array_path  = cfg.get("json_array_path", "")
    value_field = cfg.get("json_value_field", "value")

    obj = data
    if array_path:
        for key in array_path.split("."):
            obj = obj.get(key, []) if isinstance(obj, dict) else []

    if not isinstance(obj, list):
        return []

    values = []
    for item in obj:
        if isinstance(item, dict):
            v = str(item.get(value_field, "")).strip()
        else:
            v = str(item).strip()
        if v:
            values.append(v)
    return values


def parse_feed(content: str, feed_type: str, parser_config: dict) -> list[str]:
    if feed_type == "txt":
        raw = _parse_txt(content, parser_config)
    elif feed_type == "csv":
        raw = _parse_csv(content, parser_config)
    elif feed_type == "json":
        raw = _parse_json(content, parser_config)
    else:
        return []

    # Deduplicate, drop oversized values
    seen: set[str] = set()
    result = []
    for v in raw:
        if v and v not in seen and len(v) <= 2048:
            seen.add(v)
            result.append(v)
    return result


# ─── Ingest ──────────────────────────────────────────────────────────────────

async def ingest_feed(db: AsyncSession, feed: ThreatFeed) -> int:
    """Download, parse, and upsert a feed. Returns the count of values ingested."""
    # Manual redirect-following so each hop's target is SSRF-validated. With
    # follow_redirects=True httpx would silently chase a 302 → http://169.254…
    # past the guard. Cap at 5 hops to bound redirect loops.
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(connect=10, read=60, write=10, pool=5),
        follow_redirects=False,
        headers={"User-Agent": "DFIR-FENRIR-v2/2.0 threat-intel-puller"},
    ) as client:
        url = feed.url
        resp = None
        for _ in range(6):
            assert_safe_feed_url(url)
            resp = await client.get(url)
            if resp.is_redirect and resp.headers.get("location"):
                url = str(httpx.URL(url).join(resp.headers["location"]))
                continue
            break
        else:
            raise ValueError("Feed URL exceeded the maximum number of redirects")
        resp.raise_for_status()
        raw = resp.content
        if len(raw) > _FEED_MAX_BYTES:
            raise ValueError(f"Feed response too large ({len(raw):,} bytes > {_FEED_MAX_BYTES:,})")
        content = raw.decode("utf-8", errors="replace")

    values = parse_feed(content, feed.feed_type, feed.parser_config)
    if not values:
        return 0

    now = datetime.now(timezone.utc)

    for i in range(0, len(values), _BATCH_SIZE):
        batch = values[i : i + _BATCH_SIZE]
        rows = [
            {
                "id":           uuid.uuid4(),
                "feed_id":      feed.id,
                "feed_name":    feed.name,
                "type":         feed.ioc_type,
                "value":        v,
                "tags":         [],
                "first_seen_at": now,
                "last_seen_at":  now,
            }
            for v in batch
        ]
        stmt = pg_insert(ThreatIntelIOC).values(rows)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_ti_ioc_type_value",
            set_={"last_seen_at": now, "feed_name": stmt.excluded.feed_name},
        )
        await db.execute(stmt)

    # Update feed stats
    feed.last_pulled_at      = now
    feed.last_ioc_count      = len(values)
    feed.total_iocs_ingested = (feed.total_iocs_ingested or 0) + len(values)
    await db.commit()

    logger.info("TI feed pulled: %s — %d values", feed.name, len(values))
    return len(values)


async def ingest_feed_bg(feed_id: uuid.UUID) -> None:
    """Background-task wrapper that opens its own DB session."""
    from core.database import SessionLocal
    async with SessionLocal() as db:
        feed = (await db.execute(
            select(ThreatFeed).where(ThreatFeed.id == feed_id)
        )).scalar_one_or_none()
        if not feed or not feed.enabled:
            return
        try:
            await ingest_feed(db, feed)
        except Exception as exc:
            logger.error("TI feed pull failed [%s]: %s", feed.name, exc)
