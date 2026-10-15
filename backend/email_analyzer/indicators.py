"""The indicators an email analysis carries -- sender, links, attachments, origin IP -- derived from the
stored analysis (never re-parsed, so old analyses work too). One list for seen-before (P1), the hunting
queries (P2) and the containment plan (P3), so all three agree on what an email's indicators are
(docs/phishing-fast-path-slices.md). Pure: no I/O.
"""
import ipaddress
from dataclasses import dataclass
from email.utils import parseaddr
from urllib.parse import urlsplit

from core.url_indicator import classify_url_indicator

MAX_CANDIDATES = 200


@dataclass(frozen=True)
class Candidate:
    source: str        # sender | reply_to | return_path | origin_ip | x_originating_ip | attachment | url | url_host
    ref: int | None    # the urls[] / attachments[] index for url, url_host and attachment; else None
    type: str          # an IOC type
    value: str


def address(v: str | None) -> str | None:
    """The lower-cased mailbox address of a header value ("Name <a@b>", "<a@b>" or "a@b"), or None."""
    addr = parseaddr(v or "")[1].strip().lower()
    return addr if "@" in addr and " " not in addr else None


def domain_of(addr: str | None) -> str | None:
    return (addr.rsplit("@", 1)[1].rstrip(".") or None) if addr else None


def public_ip(v: str | None) -> str | None:
    try:
        ip = ipaddress.ip_address((v or "").strip())
    except ValueError:
        return None
    return str(ip) if ip.is_global else None


def link_target(u: dict) -> str:
    """What a urls[] row points at: its Safelink target when wrapped, else its URL."""
    return u.get("safelink_target") or u.get("url") or ""


def link_host(u: dict) -> str | None:
    kind = classify_url_indicator(link_target(u))
    if not kind:
        return None
    if kind[0] != "url":
        return kind[1]
    try:
        return (urlsplit(kind[1]).hostname or "").rstrip(".") or None
    except ValueError:
        return None


def _parents(host: str) -> list[str]:
    """The host and its parent domains down to the last two labels (the naive registrable domain
    scoring uses): a.b.evil.example -> a.b.evil.example, b.evil.example, evil.example."""
    labels = host.split(".")
    return [".".join(labels[i:]) for i in range(max(1, len(labels) - 1))]


def candidates(a) -> list[Candidate]:
    """Header indicators and attachments first (few, and the most telling), then each link in message
    order: what it is promoted as (core.url_indicator), then its host and parent domains. A value is
    listed once per place it occurs (a link's host can also be the sender's domain), so each row keeps
    its own entries; callers that need distinct values de-duplicate on (type, value). At most
    MAX_CANDIDATES, so a message with thousands of links stays bounded."""
    out: list[Candidate] = []
    seen: set[tuple] = set()

    def add(source, ref, type_, value):
        key = ("url" if source == "url_host" else source, ref, type_, value)   # a link and its hosts: one place
        if value and key not in seen and len(out) < MAX_CANDIDATES:
            seen.add(key)
            out.append(Candidate(source, ref, type_, value))

    sender = address(a.from_addr)
    sender_domain = domain_of(sender)
    add("sender", None, "email", sender)
    add("sender", None, "domain", sender_domain)
    for source, raw in (("reply_to", a.reply_to), ("return_path", a.return_path)):
        addr = address(raw)
        add(source, None, "email", addr)
        if domain_of(addr) != sender_domain:
            add(source, None, "domain", domain_of(addr))
    headers = a.headers or {}
    for source in ("origin_ip", "x_originating_ip"):
        add(source, None, "ip", public_ip(headers.get(source)))
    for i, att in enumerate(a.attachments or []):
        add("attachment", i, "hash_sha256", (att.get("sha256") or "").lower())
        add("attachment", i, "hash_md5", (att.get("md5") or "").lower())
    for i, u in enumerate(a.urls or []):
        kind = classify_url_indicator(link_target(u))
        if not kind:
            continue
        add("url", i, kind[0], kind[1])
        host = link_host(u)
        if not host:
            continue
        if _is_ip(host):
            add("url_host", i, "ip", host)
        else:
            for parent in _parents(host):
                add("url_host", i, "domain", parent)
    return out


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False
