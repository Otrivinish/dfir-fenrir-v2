"""What a URL/domain indicator really is: a bare domain (or IP) or a full request URL.

Microsoft Defender (learn.microsoft.com/defender-endpoint/indicators-overview): a domain
indicator is the bare name (`contoso.com`, which also matches its subdomains); a URL indicator
is the full path with its scheme (`https://contoso.com/block`); an IP is the bare address.
Shared by the email analyser (what a link is promoted as) and the Defender IOC export (which
indicatorType a row gets), so both sort a link the same way.
"""
import ipaddress
import re
from urllib.parse import urlsplit

_HXXP_RE = re.compile(r"^hxxp", re.I)


def classify_url_indicator(value: str) -> tuple[str, str] | None:
    """("domain", host), ("ip", host) or ("url", full URL), or None when there is no host.

    Defanged input is refanged (hxxp, [.], (.), [:]). A link with no path beyond "/" and no
    query is the domain (or IP) it points at. Anything else is a full request URL, kept as
    written; a URL written without a scheme gets https:// (Microsoft's own example form).
    """
    v = (value or "").strip().replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    v = _HXXP_RE.sub("http", v)
    full = v if "://" in v else f"https://{v}"
    try:
        parts = urlsplit(full)
        host = (parts.hostname or "").rstrip(".")
    except ValueError:
        return None
    if not host:
        return None
    if parts.path not in ("", "/") or parts.query:
        return "url", full
    try:
        ipaddress.ip_address(host)
        return "ip", host
    except ValueError:
        return "domain", host
