"""OSINT enrichment service.

Cache-aside pattern: check EnrichmentCache first; call external API on miss
or TTL expiry; upsert result back to cache.

API key resolution order: DB (platform_settings, Fernet-encrypted) → env var fallback.
All sources are opt-in — the caller selects which sources to query.
"""
import ipaddress
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings as env_settings
from core.security import decrypt_secret
from models import EnrichmentCache, PlatformSetting

log = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(10.0)

# ─── Source registry ─────────────────────────────────────────────────────────

SOURCES: dict[str, dict] = {
    "geoip": {
        "label":           "GeoIP",
        "description":     "Location, ISP, ASN via ip-api.com — no API key required",
        "public":          False,
        "ttl":             7 * 86_400,   # 7 days
        "supported_types": ["ip"],
        "key_attr":        None,         # no key required
    },
    "greynoise": {
        "label":           "GreyNoise",
        "description":     "Internet noise classification (community tier)",
        "public":          False,
        "ttl":             12 * 3_600,   # 12 h
        "supported_types": ["ip"],
        "key_attr":        "greynoise_api_key",
    },
    "abuseipdb": {
        "label":           "AbuseIPDB",
        "description":     "Crowdsourced IP abuse reports and confidence score",
        "public":          False,
        "ttl":             12 * 3_600,
        "supported_types": ["ip"],
        "key_attr":        "abuseipdb_api_key",
    },
    "virustotal": {
        "label":           "VirusTotal",
        "description":     "Multi-engine malware analysis — queries are PUBLIC to third parties",
        "public":          True,
        "ttl":             24 * 3_600,
        "supported_types": ["ip", "domain", "hash_md5", "hash_sha1", "hash_sha256"],
        "key_attr":        "virustotal_api_key",
    },
    "shodan": {
        "label":           "Shodan",
        "description":     "Internet-connected device scan data (ports, services, banners)",
        "public":          False,
        "ttl":             24 * 3_600,
        "supported_types": ["ip"],
        "key_attr":        "shodan_api_key",
    },
    "urlscan": {
        "label":           "URLScan.io",
        "description":     "Search historical URL and domain scans",
        "public":          False,
        "ttl":             6 * 3_600,    # 6 h
        "supported_types": ["url", "domain"],
        "key_attr":        "urlscan_api_key",
    },
    "asn": {
        "label":           "ASN lookup",
        "description":     "ASN, prefix, and holder for an IP — RIPE stat (free, no API key)",
        "public":          False,
        "ttl":             7 * 86_400,   # 7 days — ASN allocations are stable
        "supported_types": ["ip"],
        "key_attr":        None,
    },
    "crt_sh": {
        "label":           "Cert Transparency (crt.sh)",
        "description":     "Recent TLS certificates and subdomains seen in CT logs",
        "public":          False,
        "ttl":             6 * 3_600,    # 6 h — domains acquire new certs frequently
        "supported_types": ["domain"],
        "key_attr":        None,
    },
    "whois": {
        "label":           "WHOIS / RDAP",
        "description":     "Registrar, registrant, dates and nameservers via RDAP (no key)",
        "public":          False,
        "ttl":             24 * 3_600,
        "supported_types": ["domain", "ip"],
        "key_attr":        None,
    },
    "dns": {
        "label":           "DNS records",
        "description":     "A / AAAA / MX / NS / TXT / CNAME / SOA via Google DoH",
        "public":          False,
        "ttl":             3_600,        # 1 h — DNS is highly volatile
        "supported_types": ["domain"],
        "key_attr":        None,
    },
    "dnsbl": {
        "label":           "DNSBL",
        "description":     "Spamhaus / SpamCop / SORBS / Barracuda blocklists (DoH-based)",
        "public":          False,
        "ttl":             6 * 3_600,
        "supported_types": ["ip"],
        "key_attr":        None,
    },
    "passivedns": {
        "label":           "PassiveDNS (Mnemonic)",
        "description":     "Historical resolutions from Mnemonic's free public PDNS",
        "public":          False,
        "ttl":             12 * 3_600,
        "supported_types": ["domain", "ip"],
        "key_attr":        None,
    },
}

# ─── API key resolution ───────────────────────────────────────────────────────

def _db_setting_key(service: str) -> str:
    return f"api_key.{service}"


async def get_api_key(db: AsyncSession, service: str) -> Optional[str]:
    """DB row (Fernet-decrypted) → env var fallback → None."""
    row = (await db.execute(
        select(PlatformSetting).where(PlatformSetting.key == _db_setting_key(service))
    )).scalar_one_or_none()
    if row is not None:
        try:
            return decrypt_secret(row.encrypted_value)
        except Exception:
            log.warning("Failed to decrypt API key for service '%s'", service)

    key_attr = SOURCES.get(service, {}).get("key_attr")
    if key_attr:
        return getattr(env_settings, key_attr, None) or None
    return None


async def source_available(source_id: str, db: Optional[AsyncSession] = None) -> bool:
    meta = SOURCES.get(source_id)
    if meta is None:
        return False
    if meta["key_attr"] is None:
        return True
    if db is not None:
        return bool(await get_api_key(db, source_id))
    # Fast path without DB: check env only
    return bool(getattr(env_settings, meta["key_attr"], None))


# ─── Private IP helper ────────────────────────────────────────────────────────

def _is_private_ip(indicator: str) -> bool:
    try:
        return ipaddress.ip_address(indicator).is_private
    except ValueError:
        return False


# ─── Cache helpers ────────────────────────────────────────────────────────────

async def _cache_get(db: AsyncSession, tool: str, indicator: str) -> dict | None:
    row = (await db.execute(
        select(EnrichmentCache).where(
            EnrichmentCache.tool == tool,
            EnrichmentCache.indicator == indicator,
        )
    )).scalar_one_or_none()
    if row is None:
        return None
    age = (datetime.now(timezone.utc) - row.fetched_at).total_seconds()
    if age > row.ttl_seconds:
        return None     # expired — treat as miss
    return row.result


async def _cache_set(db: AsyncSession, tool: str, indicator: str, result: dict, ttl: int) -> None:
    stmt = (
        pg_insert(EnrichmentCache)
        .values(
            id=uuid.uuid4(),
            tool=tool,
            indicator=indicator,
            result=result,
            fetched_at=datetime.now(timezone.utc),
            ttl_seconds=ttl,
        )
        .on_conflict_do_update(
            index_elements=["tool", "indicator"],
            set_={"result": result, "fetched_at": datetime.now(timezone.utc), "ttl_seconds": ttl},
        )
    )
    await db.execute(stmt)
    await db.commit()


# ─── Per-source fetch functions ───────────────────────────────────────────────

async def _fetch_geoip(indicator: str) -> dict:
    if _is_private_ip(indicator):
        return {"private": True, "message": "Private address — GeoIP not applicable"}
    fields = "status,message,country,countryCode,regionName,city,isp,org,as,reverse,proxy,hosting,mobile"
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        r = await c.get(f"http://ip-api.com/json/{indicator}?fields={fields}")
        r.raise_for_status()
        return r.json()


async def _fetch_greynoise(indicator: str, key: str) -> dict:
    if _is_private_ip(indicator):
        return {"message": "Private address — GreyNoise not applicable"}
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        r = await c.get(
            f"https://api.greynoise.io/v3/community/{indicator}",
            headers={"key": key},
        )
        if r.status_code == 404:
            return {"noise": False, "riot": False, "message": "No information available"}
        r.raise_for_status()
        return r.json()


async def _fetch_abuseipdb(indicator: str, key: str) -> dict:
    if _is_private_ip(indicator):
        return {"message": "Private address — AbuseIPDB not applicable"}
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        r = await c.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": indicator, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": key, "Accept": "application/json"},
        )
        r.raise_for_status()
        return r.json()


async def _fetch_virustotal(indicator: str, ioc_type: str, key: str) -> dict:
    headers = {"x-apikey": key}
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        if ioc_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
        elif ioc_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
        elif ioc_type in ("hash_md5", "hash_sha1", "hash_sha256"):
            url = f"https://www.virustotal.com/api/v3/files/{indicator}"
        else:
            raise ValueError(f"VirusTotal does not support ioc_type '{ioc_type}'")
        r = await c.get(url, headers=headers)
        if r.status_code == 404:
            return {"found": False}
        r.raise_for_status()
        return r.json()


async def _fetch_shodan(indicator: str, key: str) -> dict:
    if _is_private_ip(indicator):
        return {"message": "Private address — Shodan not applicable"}
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        r = await c.get(
            f"https://api.shodan.io/shodan/host/{indicator}",
            params={"key": key},
        )
        if r.status_code == 404:
            return {"found": False, "message": "No information available"}
        r.raise_for_status()
        return r.json()


async def _fetch_asn(indicator: str) -> dict:
    """RIPE stat — ASN + prefix from network-info, holder from as-overview.

    Returns the first ASN announcing the prefix. Multi-homed IPs are rare in
    practice; if multiple ASNs are returned we include them all but only fetch
    the holder for the first.
    """
    if _is_private_ip(indicator):
        return {"private": True, "message": "Private address — ASN lookup not applicable"}

    base = "https://stat.ripe.net/data"
    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as c:
        ni = await c.get(f"{base}/network-info/data.json", params={"resource": indicator})
        ni.raise_for_status()
        ni_data = (ni.json() or {}).get("data") or {}
        asns   = ni_data.get("asns") or []
        prefix = ni_data.get("prefix")

        holder = None
        if asns:
            try:
                ov = await c.get(
                    f"{base}/as-overview/data.json",
                    params={"resource": f"AS{asns[0]}"},
                )
                ov.raise_for_status()
                holder = ((ov.json() or {}).get("data") or {}).get("holder")
            except Exception:
                # Holder is nice-to-have; don't fail the whole lookup if it 5xxs.
                pass

    return {
        "asn":    asns[0] if asns else None,
        "asns":   asns,
        "prefix": prefix,
        "holder": holder,
    }


async def _fetch_crt_sh(indicator: str) -> dict:
    """crt.sh JSON feed — recent certificates for a domain.

    Returns: {total, certs[], subdomains[]}.
      - certs: up to 10 most-recent {common_name, names, issuer, not_before, not_after, id}
      - subdomains: deduplicated subjects covering the domain (CT-derived enum)
    """
    domain = indicator.strip().lstrip("*.").lower()
    url = "https://crt.sh/"
    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as c:
        r = await c.get(url, params={"q": f"%.{domain}", "output": "json"})
        if r.status_code == 404:
            return {"total": 0, "certs": [], "subdomains": []}
        r.raise_for_status()
        rows = r.json() or []

    # Deduplicate subdomains: name_value can be a multiline list of SAN subjects.
    subs: set[str] = set()
    for row in rows:
        nv = (row.get("name_value") or "")
        for line in nv.splitlines():
            n = line.strip().lower()
            if n and (n == domain or n.endswith(f".{domain}")):
                subs.add(n)

    # 10 most-recent by entry_timestamp.
    def _key(r):
        return r.get("entry_timestamp") or r.get("not_before") or ""

    top = sorted(rows, key=_key, reverse=True)[:10]
    certs = [{
        "id":          r.get("id"),
        "common_name": r.get("common_name"),
        "names":       (r.get("name_value") or "").splitlines()[:8],
        "issuer":      r.get("issuer_name"),
        "not_before":  r.get("not_before"),
        "not_after":   r.get("not_after"),
        "entry_ts":    r.get("entry_timestamp"),
    } for r in top]

    return {
        "total":      len(rows),
        "certs":      certs,
        "subdomains": sorted(subs),
    }


async def _fetch_whois(indicator: str, ioc_type: str) -> dict:
    """RDAP via rdap.org — modern WHOIS replacement, free, JSON, no key."""
    if ioc_type == "ip" and _is_private_ip(indicator):
        return {"private": True, "message": "Private address — WHOIS not applicable"}
    target = indicator.strip().lstrip("*.").lower()
    path = "ip" if ioc_type == "ip" else "domain"
    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0), follow_redirects=True) as c:
        r = await c.get(f"https://rdap.org/{path}/{target}")
        if r.status_code == 404:
            return {"found": False, "message": "No RDAP record"}
        r.raise_for_status()
        raw = r.json() or {}

    def _entities(role: str) -> list[str]:
        out: list[str] = []
        for ent in raw.get("entities") or []:
            if role in (ent.get("roles") or []):
                v = ent.get("vcardArray") or []
                # vcard: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "<name>"], ...]]
                if len(v) >= 2 and isinstance(v[1], list):
                    for item in v[1]:
                        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                            out.append(str(item[3]))
        return out

    def _dates() -> dict:
        d: dict = {}
        for ev in raw.get("events") or []:
            action = ev.get("eventAction")
            ts     = ev.get("eventDate")
            if action and ts:
                d[action] = ts
        return d

    nameservers = [ns.get("ldhName") for ns in (raw.get("nameservers") or []) if ns.get("ldhName")]
    return {
        "handle":      raw.get("handle"),
        "name":        raw.get("ldhName") or raw.get("name"),
        "status":      raw.get("status") or [],
        "registrar":   _entities("registrar"),
        "registrant":  _entities("registrant"),
        "tech":        _entities("technical"),
        "abuse":       _entities("abuse"),
        "events":      _dates(),
        "nameservers": nameservers,
    }


async def _fetch_dns(indicator: str) -> dict:
    """A / AAAA / MX / NS / TXT / CNAME / SOA via Google DoH. No key."""
    domain = indicator.strip().lstrip("*.").lower()
    types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    async def _q(c: httpx.AsyncClient, t: str) -> tuple[str, list[str]]:
        try:
            r = await c.get(
                "https://dns.google/resolve",
                params={"name": domain, "type": t},
                headers={"Accept": "application/dns-json"},
            )
            r.raise_for_status()
            j = r.json() or {}
            answers = [a.get("data", "") for a in (j.get("Answer") or []) if a.get("data")]
            return t, answers
        except Exception:
            return t, []

    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as c:
        import asyncio as _aio
        pairs = await _aio.gather(*[_q(c, t) for t in types])

    records = {t: ans for t, ans in pairs}
    total = sum(len(v) for v in records.values())
    return {"domain": domain, "records": records, "total": total}


async def _fetch_dnsbl(indicator: str) -> dict:
    """DNSBL via Google DoH against several common zones. No key."""
    if _is_private_ip(indicator):
        return {"private": True, "message": "Private address — DNSBL not applicable"}
    try:
        ip = ipaddress.ip_address(indicator)
    except ValueError:
        return {"error": "Not a valid IP address"}
    if isinstance(ip, ipaddress.IPv6Address):
        # IPv6 DNSBL queries use nibble-reversed addresses — skip for now.
        return {"message": "IPv6 DNSBL queries not supported", "checked": [], "listed": []}

    reversed_ip = ".".join(reversed(indicator.split(".")))
    zones = [
        ("zen.spamhaus.org",       "Spamhaus ZEN"),
        ("bl.spamcop.net",         "SpamCop"),
        ("dnsbl.sorbs.net",        "SORBS"),
        ("b.barracudacentral.org", "Barracuda"),
    ]

    async def _check(c: httpx.AsyncClient, zone: str, label: str) -> dict:
        host = f"{reversed_ip}.{zone}"
        try:
            r = await c.get(
                "https://dns.google/resolve",
                params={"name": host, "type": "A"},
                headers={"Accept": "application/dns-json"},
            )
            r.raise_for_status()
            j = r.json() or {}
            answers = [a.get("data", "") for a in (j.get("Answer") or []) if a.get("data")]
            # Status 0 = NOERROR, 3 = NXDOMAIN
            return {"zone": zone, "label": label, "listed": bool(answers), "codes": answers}
        except Exception as exc:
            return {"zone": zone, "label": label, "listed": False, "error": str(exc)[:80]}

    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as c:
        import asyncio as _aio
        results = await _aio.gather(*[_check(c, z, lbl) for z, lbl in zones])

    listed = [r for r in results if r.get("listed")]
    return {"ip": indicator, "checked": results, "listed_count": len(listed)}


async def _fetch_passivedns(indicator: str, ioc_type: str) -> dict:
    """PassiveDNS via Mnemonic's free public PDNS API (v3)."""
    target = indicator.strip().lstrip("*.").lower()
    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as c:
        r = await c.get(f"https://api.mnemonic.no/pdns/v3/{target}",
                        params={"limit": 50})
        if r.status_code in (401, 403):
            return {"available": False, "message": "Public endpoint unauthorised — try later or configure an API key"}
        if r.status_code == 404:
            return {"total": 0, "records": []}
        r.raise_for_status()
        j = r.json() or {}

    raw = j.get("data") or []
    records = [{
        "query":      it.get("query"),
        "answer":     it.get("answer"),
        "rrtype":     it.get("rrtype"),
        "count":      it.get("count"),
        "first_seen": it.get("firstSeenTimestamp"),
        "last_seen":  it.get("lastSeenTimestamp"),
    } for it in raw[:50]]
    return {
        "indicator": target,
        "total":     j.get("metaData", {}).get("size") or len(records),
        "records":   records,
    }


async def _fetch_urlscan(indicator: str, ioc_type: str, key: Optional[str]) -> dict:
    headers: dict[str, str] = {}
    if key:
        headers["API-Key"] = key

    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        if ioc_type == "url":
            q = f'page.url:"{indicator}"'
        else:  # domain
            q = f"domain:{indicator}"

        r = await c.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": q, "size": 5},
            headers=headers,
        )
        if r.status_code == 429:
            raise httpx.HTTPStatusError("Rate limited", request=r.request, response=r)
        r.raise_for_status()
        data = r.json()
        results = data.get("results", [])
        if not results:
            return {"found": False, "total": 0}
        # Return condensed summary of top results
        hits = []
        for item in results[:5]:
            page = item.get("page", {})
            task = item.get("task", {})
            stats = item.get("stats", {})
            hits.append({
                "url":        page.get("url"),
                "domain":     page.get("domain"),
                "country":    page.get("country"),
                "server":     page.get("server"),
                "ip":         page.get("ip"),
                "status":     page.get("status"),
                "malicious":  stats.get("malicious", 0),
                "scan_date":  task.get("time"),
                "report_url": f"https://urlscan.io/result/{item.get('_id', '')}",
            })
        return {"found": True, "total": data.get("total", len(results)), "hits": hits}


# ─── Public interface ─────────────────────────────────────────────────────────

async def enrich_one(
    db: AsyncSession,
    indicator: str,
    ioc_type: str,
    source: str,
) -> dict:
    """Enrich a single indicator with one source.

    Returns:
        {available, from_cache, data, error}
    """
    meta = SOURCES.get(source)
    if meta is None:
        return {"available": False, "from_cache": False, "data": None, "error": "Unknown source"}

    if ioc_type not in meta["supported_types"]:
        return {
            "available": True,
            "from_cache": False,
            "data": None,
            "error": f"{meta['label']} does not support type '{ioc_type}'",
        }

    # Resolve API key (DB first, then env var)
    key: Optional[str] = None
    if meta["key_attr"] is not None:
        key = await get_api_key(db, source)
        if not key:
            return {"available": False, "from_cache": False, "data": None, "error": "API key not configured"}

    # Check cache
    cached = await _cache_get(db, source, indicator)
    if cached is not None:
        return {"available": True, "from_cache": True, "data": cached, "error": None}

    # Fetch from API
    try:
        if source == "geoip":
            data = await _fetch_geoip(indicator)
        elif source == "greynoise":
            data = await _fetch_greynoise(indicator, key)
        elif source == "abuseipdb":
            data = await _fetch_abuseipdb(indicator, key)
        elif source == "virustotal":
            data = await _fetch_virustotal(indicator, ioc_type, key)
        elif source == "shodan":
            data = await _fetch_shodan(indicator, key)
        elif source == "urlscan":
            data = await _fetch_urlscan(indicator, ioc_type, key)
        elif source == "asn":
            data = await _fetch_asn(indicator)
        elif source == "crt_sh":
            data = await _fetch_crt_sh(indicator)
        elif source == "whois":
            data = await _fetch_whois(indicator, ioc_type)
        elif source == "dns":
            data = await _fetch_dns(indicator)
        elif source == "dnsbl":
            data = await _fetch_dnsbl(indicator)
        elif source == "passivedns":
            data = await _fetch_passivedns(indicator, ioc_type)
        else:
            return {"available": False, "from_cache": False, "data": None, "error": "Unknown source"}

        await _cache_set(db, source, indicator, data, meta["ttl"])
        return {"available": True, "from_cache": False, "data": data, "error": None}

    except httpx.HTTPStatusError as e:
        msg = f"HTTP {e.response.status_code}"
        if e.response.status_code == 401:
            msg = "Invalid API key"
        elif e.response.status_code == 429:
            msg = "Rate limited — try again later"
        log.warning("OSINT %s %s → %s", source, indicator, msg)
        return {"available": True, "from_cache": False, "data": None, "error": msg}
    except httpx.TimeoutException:
        return {"available": True, "from_cache": False, "data": None, "error": "Request timed out"}
    except Exception as exc:
        log.warning("OSINT %s %s → %s", source, indicator, exc)
        return {"available": True, "from_cache": False, "data": None, "error": str(exc)}
