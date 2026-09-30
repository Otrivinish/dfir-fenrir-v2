"""U8.1 — offline email parsing. Pure-stdlib `email` + `magic` + `hashlib` + regex.

Parse-only: no HTML rendering, no network, no execution. Everything below the first trusted
`Received` hop is attacker-supplied — callers/UI mark the trust boundary.
"""
from __future__ import annotations

import base64
import hashlib
import math
import re
from datetime import datetime
from email import message_from_bytes, policy
from email.utils import parseaddr, parsedate_to_datetime
from urllib.parse import parse_qs, urlsplit

import magic
import nh3

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
        "raw_headers":  _raw_header_block(raw),
        **_body(msg),
    }


def attachment_bytes(raw: bytes, index: int) -> tuple[str, str | None, bytes]:
    """Return (filename, declared_type, data) for the Nth attachment of a raw message."""
    msg = message_from_bytes(raw, policy=policy.default)
    for i, (ctype, fn, data) in enumerate(_iter_attachment_parts(msg)):
        if i == index:
            return (fn, ctype, data)
    raise IndexError(f"attachment {index} not found")


# ─── JSON-string-export repair ─────────────────────────────────────────────

def repair_wrapped_export(raw: bytes) -> bytes:
    """Repair a common "download original message" export mistake: some
    portals/tools expose the raw message as a JSON string field, and whatever
    saved it wrote that STRING value -- quotes and all -- straight to a .eml
    file instead of JSON-decoding it first. The result opens with a literal
    `"` (often after a UTF-8 BOM) and closes with one too.
    `email.message_from_bytes` can't find a single valid header in that
    shape and silently degrades to "no headers, one giant text/plain body" --
    a parse that *looks* like it succeeded but drops everything, attachments
    included, without raising anything the caller would notice.

    Detected narrowly (BOM-stripped content starts AND ends with `"`, and
    what's inside the quotes actually starts with something that looks like
    a real header field name) so a message that legitimately starts/ends
    with a quote character for some unrelated reason is left untouched."""
    stripped = raw.lstrip(b"\xef\xbb\xbf")
    if len(stripped) < 2 or stripped[:1] != b'"' or stripped[-1:] != b'"':
        return raw
    inner = stripped[1:-1]
    name = inner.split(b"\n", 1)[0].split(b"\r", 1)[0].split(b":", 1)[0]
    if not name or not name[:1].isalpha() or b" " in name:
        return raw
    return inner.replace(b'\\"', b'"')


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


def _raw_header_block(raw: bytes) -> str | None:
    """Full raw header block, verbatim -- not just the fixed `_NOTABLE` subset.
    Message = headers, blank line, body (RFC 5322); split on the first blank
    line and tolerate bare LF for messages that don't use CRLF."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx].decode("utf-8", "replace")
    return raw.decode("utf-8", "replace") or None


def _unwrap_safelink(url: str) -> str | None:
    """Decode a Microsoft Defender Safelink (*.safelinks.protection.outlook.com)
    back to its real destination. String parsing only -- the wrapped URL is
    never fetched, so this stays inside the parser's offline guarantee.

    `parse_qs` already fully percent-decodes each value (it calls `unquote`
    internally) -- an extra `unquote()` on top double-decodes it. Harmless
    when the real destination has no `%XX`-shaped substring of its own, but
    for a destination that is itself another redirector with an embedded
    percent-encoded sub-URL (common in multi-hop phishing kits: Safelink ->
    tracker.example/click?url=<encoded-final-target>), the second decode
    prematurely flattens that inner encoding, corrupting the extracted URL.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    # `.hostname` (not a manual `.split(":")` on netloc) so userinfo/port/IPv6
    # brackets are stripped correctly, and an exact-or-subdomain check (not
    # `.endswith(domain)`) so a host like "evilsafelinks.protection.outlook.com"
    # -- which ends with the same substring but isn't a subdomain of it --
    # can't be mistaken for the real thing (CodeQL: incomplete substring sanitization).
    host = (parts.hostname or "").lower()
    domain = "safelinks.protection.outlook.com"
    if not (host == domain or host.endswith("." + domain)):
        return None
    return parse_qs(parts.query).get("url", [None])[0] or None


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
        safelink_target = _unwrap_safelink(url)
        seen[key] = {
            "url": url, "defanged": _defang(url), "host": _url_host(url),
            "display_text": display or None, "display_host": dhost,
            "safelink_target": safelink_target,
            "safelink_host": _url_host(safelink_target) if safelink_target else None,
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


def _attachment_data(part) -> bytes:
    """`get_payload(decode=True)` only decodes leaf parts with a transfer
    encoding -- an attached full email (Content-Type: message/rfc822, e.g. a
    forwarded phishing sample) is a *container* part instead: its payload is
    a one-element list holding the sub-Message, not raw bytes. Without this,
    such attachments silently vanish (`get_payload(decode=True)` returns None
    -> empty data -> filtered out below)."""
    if part.get_content_maintype() == "message":
        sub = part.get_payload()
        if isinstance(sub, list) and sub:
            try:
                return sub[0].as_bytes()
            except Exception:
                return b""
        return b""
    return part.get_payload(decode=True) or b""


TNEF_MAGIC = b"\x78\x9f\x3e\x22"   # little-endian 0x223e9f78 -- checked on bytes, not
                                    # declared Content-Type, so a mislabeled blob is still caught


def is_tnef(data: bytes) -> bool:
    return data[:4] == TNEF_MAGIC


def _tnef_attachments(data: bytes):
    """Decode a winmail.dat (TNEF) blob's real attachments.

    Outlook "Rich Text" format bundles real attachments inside a single
    opaque TNEF container instead of normal MIME parts -- to a plain MIME
    walk this looks like one oddly-named attachment (winmail.dat,
    application/ms-tnef), with the analyst's actual file invisible inside
    it. Best-effort: a malformed/unsupported TNEF blob just yields nothing
    extra here; the raw winmail.dat container is still listed by the caller
    either way, so nothing is silently dropped."""
    try:
        import tnefparse
        parsed = tnefparse.TNEF(data)
    except Exception:
        return
    for att in parsed.attachments:
        try:
            fn = att.long_filename() or "(unnamed)"
            adata = bytes(att.data or b"")
        except Exception:
            continue
        if not adata:
            continue
        yield "application/octet-stream", fn, adata


def _iter_attachment_parts(msg):
    """Single source of truth for "what counts as an attachment" -- yields
    (content_type, filename, data), shared by `_attachments()` (listing) and
    `attachment_bytes()` (extraction by index) so the two can never disagree
    on ordering/inclusion. A TNEF container's real attachments are expanded
    and yielded alongside (not instead of) the raw container itself."""
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        fn = part.get_filename()
        if part.get_content_disposition() != "attachment" and not fn:
            continue
        data = _attachment_data(part)
        if not data:
            continue
        yield part.get_content_type(), (fn or "(unnamed)"), data
        if is_tnef(data):
            yield from _tnef_attachments(data)


def _attachments(msg):
    out = []
    for ctype, fn, data in _iter_attachment_parts(msg):
        out.append({
            "filename":      fn,
            "declared_type": ctype,
            "true_type":     magic.from_buffer(data[:2048], mime=True),
            "size":          len(data),
            "md5":           hashlib.md5(data).hexdigest(),
            "sha256":        hashlib.sha256(data).hexdigest(),
            "entropy":       round(_entropy(data), 2),
        })
    return out


# ─── Body preview (render-safe, for "what does this look like") ────────────
#
# This is a DISPLAY convenience only, never a forensic copy -- the untouched
# raw message is already preserved as the quarantine Artifact/Evidence. The
# sanitized HTML is deliberately much more restrictive than a real mail
# client: no script/style/on*-handler survives, and the only network-style
# resource allowed is an inline `cid:` image already fully contained in the
# message (resolved to a `data:` URI) -- never a remote http(s) fetch, so
# nothing here can beacon to whoever sent the email. The frontend additionally
# renders this inside a fully sandboxed, script-and-navigation-blocked iframe
# on top of this -- defense in depth, this sanitization must not be the only
# thing standing between attacker HTML and the analyst's browser.
#
# Residual, accepted risk: a `data:` URI image is still decoded by the
# browser's image codec like any other image, so this doesn't eliminate an
# image-parser exploit -- only network beaconing. Worth knowing, not a gap
# this pass is meant to close.

_PREVIEW_ALLOWED_TAGS = {
    "p", "br", "b", "i", "u", "strong", "em", "span", "div",
    "table", "thead", "tbody", "tr", "td", "th",
    "ul", "ol", "li", "h1", "h2", "h3", "h4", "h5", "h6",
    "blockquote", "hr", "pre", "code", "a", "img",
}
_PREVIEW_ATTRIBUTES = {"img": {"src", "alt"}}   # every other tag: no attributes at all
_PREVIEW_STRIP_WITH_CONTENT = {"script", "style", "head", "title", "noscript",
                               "svg", "iframe", "object", "embed"}
_MAX_PREVIEW_CHARS = 200_000

_MAX_INLINE_IMAGES = 20
_MAX_INLINE_IMAGE_BYTES = 2 * 1024 * 1024
_MAX_INLINE_TOTAL_BYTES = 8 * 1024 * 1024
_CID_RE = re.compile(r'cid:([^"\'>\s]+)', re.I)


def _sanitize_preview_html(html: str) -> str:
    try:
        return nh3.clean(
            html[:_MAX_PREVIEW_CHARS],
            tags=_PREVIEW_ALLOWED_TAGS,
            attributes=_PREVIEW_ATTRIBUTES,
            clean_content_tags=_PREVIEW_STRIP_WITH_CONTENT,
            url_schemes={"data"},   # backstop: strips src/href even if it slipped past pre-processing
        )
    except Exception:
        return ""


def _inline_images(msg) -> dict:
    """Map Content-ID -> data: URI for inline images (`cid:` references).
    These bytes are already fully contained in the message -- resolving them
    is not a network fetch. Bounded so a hostile message can't bloat storage
    via dozens of huge "inline" images."""
    out = {}
    total = 0
    for part in msg.walk():
        if len(out) >= _MAX_INLINE_IMAGES or total >= _MAX_INLINE_TOTAL_BYTES:
            break
        if part.get_content_maintype() != "image":
            continue
        cid = part.get("Content-ID")
        if not cid:
            continue
        cid = cid.strip().strip("<>")
        data = part.get_payload(decode=True)
        if not data or len(data) > _MAX_INLINE_IMAGE_BYTES:
            continue
        total += len(data)
        out[cid] = f"data:{part.get_content_type() or 'image/png'};base64,{base64.b64encode(data).decode('ascii')}"
    return out


def _resolve_cids(html: str, images: dict) -> str:
    return _CID_RE.sub(lambda m: images.get(m.group(1), ""), html)


def _body(msg) -> dict:
    """Best-effort plain-text and sanitized-HTML body for the UI preview."""
    text_part = html_part = None
    for part in msg.walk():
        if part.get_content_maintype() != "text" or part.get_content_disposition() == "attachment":
            continue
        subtype = part.get_content_subtype()
        if subtype == "plain" and text_part is None:
            text_part = part
        elif subtype == "html" and html_part is None:
            html_part = part

    def text_of(part):
        if part is None:
            return None
        try:
            return part.get_content()
        except Exception:
            try:
                return (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
            except Exception:
                return None

    raw_html = text_of(html_part)
    body_html = _sanitize_preview_html(_resolve_cids(raw_html, _inline_images(msg))) if raw_html else None

    body_text = text_of(text_part)
    if not body_text and raw_html:
        body_text = TAG_RE.sub(" ", raw_html)
    if body_text:
        body_text = body_text[:_MAX_PREVIEW_CHARS]

    return {"body_text": body_text, "body_html": body_html}


_NOTABLE = ("From", "To", "Reply-To", "Return-Path", "Sender", "Subject", "Date",
            "Message-ID", "X-Mailer", "User-Agent", "X-Originating-IP",
            "Content-Type", "List-Unsubscribe", "X-Forefront-Antispam-Report")


def _notable(msg):
    return {k: str(msg.get(k)) for k in _NOTABLE if msg.get(k) is not None}
