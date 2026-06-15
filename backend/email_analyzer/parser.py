"""U8.1 — offline email parsing. Pure-stdlib `email` + `magic` + `hashlib` + regex.

Parse-only: no HTML rendering, no network, no execution. Everything below the first trusted
`Received` hop is attacker-supplied — callers/UI mark the trust boundary.
"""
from __future__ import annotations

import hashlib
import math
import re
from datetime import datetime
from email import message_from_bytes, policy
from email.utils import parseaddr, parsedate_to_datetime

import magic

URL_RE  = re.compile(r'https?://[^\s<>"\'\)\]}]+', re.I)
HREF_RE = re.compile(r'<a\b[^>]*?href\s*=\s*["\']?(https?://[^"\'>\s]+)["\']?[^>]*>(.*?)</a>', re.I | re.S)
IP_RE   = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
TAG_RE  = re.compile(r'<[^>]+>')


def parse_email(raw: bytes) -> dict:
    msg = message_from_bytes(raw, policy=policy.default)
    hops = _received(msg)
    return {
        "subject":    _hdr(msg, "Subject"),
        "message_id": _hdr(msg, "Message-ID"),
        "date_hdr":   _hdr(msg, "Date"),
        **_addresses(msg),
        "auth":       _auth(msg),
        "hops":       hops,
        "origin_ip":  _origin_ip(hops),
        "x_originating_ip": _first_public_ip(
            " ".join(filter(None, [msg.get("X-Originating-IP"), msg.get("X-Sender-IP"), msg.get("X-Source-IP")]))
        ),
        "urls":         _urls(msg),
        "attachments":  _attachments(msg),
        "notable_headers": _notable(msg),
    }


def attachment_bytes(raw: bytes, index: int) -> tuple[str, str | None, bytes]:
    """Return (filename, declared_type, data) for the Nth attachment of a raw message."""
    msg = message_from_bytes(raw, policy=policy.default)
    i = -1
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        fn = part.get_filename()
        if part.get_content_disposition() != "attachment" and not fn:
            continue
        data = part.get_payload(decode=True) or b""
        if not data:
            continue
        i += 1
        if i == index:
            return (fn or "attachment.bin", part.get_content_type(), data)
    raise IndexError(f"attachment {index} not found")


# ─── Outlook .msg → RFC-822 (U8.1 phase d.1; offline, lazy-imported) ───────────

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"   # OLE2 compound-file signature


def is_msg(data: bytes) -> bool:
    return data[:8] == OLE_MAGIC


def msg_to_eml_bytes(data: bytes) -> bytes:
    """Convert an Outlook `.msg` (OLE compound file) to RFC-822 bytes so the rest of the
    analyzer works unchanged. Lazy-imports `extract_msg`; fully offline."""
    import io
    import extract_msg
    m = extract_msg.openMsg(io.BytesIO(data))
    try:
        return m.asEmailMessage().as_bytes()
    except Exception:
        return _msg_manual_eml(m)


def _msg_manual_eml(m) -> bytes:
    """Fallback builder: preserve original transport headers (Received / Authentication-Results
    / DKIM / From …) and reattach body + attachments as a clean MIME message."""
    from email.message import EmailMessage
    msg = EmailMessage()
    structural = {"content-type", "content-transfer-encoding", "mime-version"}
    hdr = getattr(m, "header", None)
    if hdr is not None:
        for k, v in hdr.items():
            if k.lower() in structural:
                continue
            try:
                msg[k] = v
            except Exception:
                pass

    def ensure(name, val):
        if val and name not in msg:
            try:
                msg[name] = str(val)
            except Exception:
                pass
    ensure("From", getattr(m, "sender", None))
    ensure("To", getattr(m, "to", None))
    ensure("Subject", getattr(m, "subject", None))
    ensure("Date", getattr(m, "date", None))

    body = getattr(m, "body", None) or ""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    msg.set_content(body)
    html = getattr(m, "htmlBody", None)
    if html:
        if isinstance(html, bytes):
            html = html.decode("utf-8", "replace")
        try:
            msg.add_alternative(html, subtype="html")
        except Exception:
            pass

    for att in getattr(m, "attachments", []) or []:
        adata = getattr(att, "data", None)
        if not isinstance(adata, (bytes, bytearray)) or not adata:
            continue
        fn = (getattr(att, "longFilename", None) or getattr(att, "shortFilename", None)
              or "attachment.bin")
        try:
            msg.add_attachment(bytes(adata), maintype="application", subtype="octet-stream", filename=fn)
        except Exception:
            pass
    return msg.as_bytes()


# ─── helpers ──────────────────────────────────────────────────────────────────

def _hdr(msg, name):
    v = msg.get(name)
    return str(v) if v is not None else None


def _addresses(msg):
    fdisp, faddr = parseaddr(_hdr(msg, "From") or "")
    _, rto    = parseaddr(_hdr(msg, "Reply-To") or "")
    _, rpath  = parseaddr(_hdr(msg, "Return-Path") or "")
    _, sender = parseaddr(_hdr(msg, "Sender") or "")
    return {
        "from_display": fdisp or None, "from_addr": faddr or None,
        "reply_to": rto or None, "return_path": rpath or None, "sender": sender or None,
    }


def _re1(s, pat):
    m = re.search(pat, s or "", re.I)
    return m.group(1) if m else None


def _auth(msg):
    ar = " ".join(msg.get_all("Authentication-Results", []) or [])
    def grab(mech):
        m = re.search(rf'\b{mech}=(\w+)', ar, re.I)
        return m.group(1).lower() if m else None
    sig = msg.get("DKIM-Signature")
    rspf = msg.get("Received-SPF")
    return {
        "spf": grab("spf"), "dkim": grab("dkim"), "dmarc": grab("dmarc"),
        "spf_domain":   _re1(ar, r'smtp\.mailfrom=([^\s;]+)'),
        "dkim_domain":  _re1(str(sig), r'd=([^;\s]+)') if sig else None,
        "dkim_selector": _re1(str(sig), r's=([^;\s]+)') if sig else None,
        "received_spf": (str(rspf).split()[0].lower() if rspf else None),
        "raw": ar or None,
    }


def _received(msg):
    raws = msg.get_all("Received", []) or []
    hops = []
    for raw in reversed(raws):   # email gives newest-first → reverse to chronological
        s = " ".join(str(raw).split())
        ts = None
        head = s
        if ";" in s:
            head, _, tail = s.rpartition(";")
            try:
                ts = parsedate_to_datetime(tail.strip())
            except Exception:
                ts = None
        hops.append({
            "from": _re1(head, r'\bfrom\s+([^\s;]+)'),
            "by":   _re1(head, r'\bby\s+([^\s;]+)'),
            "with": _re1(head, r'\bwith\s+([^\s;]+)'),
            "ip":   _first_public_ip(head) or (IP_RE.search(head).group(0) if IP_RE.search(head) else None),
            "timestamp": ts.isoformat() if ts else None,
        })
    prev = None
    for h in hops:
        delay = None
        if h["timestamp"] and prev:
            try:
                delay = (datetime.fromisoformat(h["timestamp"]) - datetime.fromisoformat(prev)).total_seconds()
            except Exception:
                delay = None
        h["delay_seconds"] = delay
        if h["timestamp"]:
            prev = h["timestamp"]
    return hops


def _is_public(ip):
    try:
        a, b, *_ = (int(x) for x in ip.split("."))
    except Exception:
        return False
    if a in (10, 127, 0):            return False
    if a == 192 and b == 168:        return False
    if a == 172 and 16 <= b <= 31:   return False
    if a == 169 and b == 254:        return False
    return True


def _first_public_ip(s):
    for ip in IP_RE.findall(s or ""):
        if _is_public(ip):
            return ip
    return None


def _origin_ip(hops):
    for h in hops:   # chronological → first public IP is the true origin
        if h.get("ip") and _is_public(h["ip"]):
            return h["ip"]
    return None


def _url_host(url):
    if not url or not url.lower().startswith("http"):
        return None
    authority = url.split("//", 1)[-1].split("/", 1)[0]
    authority = authority.split("@")[-1]          # drop userinfo
    return authority.split(":")[0].lower() or None


def _defang(url):
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def _urls(msg):
    seen = {}
    def add(url, display=None):
        url = url.rstrip('.,);]\'">')
        key = url.lower()
        if key in seen:
            return
        dhost = _url_host(display) if display and display.lower().startswith("http") else None
        seen[key] = {
            "url": url, "defanged": _defang(url), "host": _url_host(url),
            "display_text": display or None, "display_host": dhost,
        }
    for part in msg.walk():
        if part.get_content_maintype() != "text" or part.get_content_disposition() == "attachment":
            continue
        try:
            text = part.get_content()
        except Exception:
            try:
                text = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
            except Exception:
                continue
        if part.get_content_subtype() == "html":
            for m in HREF_RE.finditer(text):
                inner = TAG_RE.sub("", m.group(2)).strip()
                add(m.group(1), inner or None)
        for m in URL_RE.finditer(text):
            add(m.group(0))
    return list(seen.values())


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _attachments(msg):
    out = []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        fn = part.get_filename()
        if part.get_content_disposition() != "attachment" and not fn:
            continue
        data = part.get_payload(decode=True) or b""
        if not data:
            continue
        out.append({
            "filename":      fn or "(unnamed)",
            "declared_type": part.get_content_type(),
            "true_type":     magic.from_buffer(data[:2048], mime=True),
            "size":          len(data),
            "md5":           hashlib.md5(data).hexdigest(),
            "sha256":        hashlib.sha256(data).hexdigest(),
            "entropy":       round(_entropy(data), 2),
        })
    return out


_NOTABLE = ("From", "To", "Reply-To", "Return-Path", "Sender", "Subject", "Date",
            "Message-ID", "X-Mailer", "User-Agent", "X-Originating-IP",
            "Content-Type", "List-Unsubscribe", "X-Forefront-Antispam-Report")


def _notable(msg):
    return {k: str(msg.get(k)) for k in _NOTABLE if msg.get(k) is not None}
