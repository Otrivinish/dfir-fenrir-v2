"""Defender XDR Advanced Hunting queries that scope a phish (P2, docs/phishing-fast-path-slices.md).

Pure text generation: FENRIR runs nothing and sends nothing; the analyst pastes a query into Defender XDR
-> Hunting -> Advanced hunting. Columns are the MS Learn schema pages' (EmailEvents, EmailUrlInfo,
UrlClickEvents, EmailAttachmentInfo, DeviceFileEvents; checked 2026-10-15).

Every value comes from the attacker's message, so every value goes through kql_literal() and appears only
inside a `let` at the top of a query -- never in a comment (a newline there would end the comment).
"""
import re
import unicodedata
from datetime import datetime, timezone

from email_analyzer.indicators import address, link_host, link_target

MAX_VALUE_LEN = 2048
MAX_LIST = 50
_ESCAPE_CATEGORIES = {"Cc", "Cf", "Zl", "Zp", "Co", "Cn", "Cs"}


def kql_literal(v: str) -> str | None:
    """A regular double-quoted KQL string literal for `v`, or None when it can't be written safely (too
    long, or an invisible character outside the BMP that \\uXXXX can't express). `\\` and `"` are
    backslash-escaped; every control, format, line/paragraph-separator, private-use or unassigned
    character (incl. the right-to-left override) becomes \\uXXXX, so the value can't end its string and
    no invisible bidi control can reorder the query text -- KQL decodes it back to the exact value. (Plain
    right-to-left letters, Hebrew or Arabic, are kept: adjacent RTL values may display in swapped order,
    but the query is unchanged.)"""
    if len(v) > MAX_VALUE_LEN:
        return None
    out = []
    for ch in v:
        if ch in '\\"':
            out.append("\\" + ch)
        elif unicodedata.category(ch) in _ESCAPE_CATEGORIES:
            if ord(ch) > 0xFFFF:
                return None
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _values(a) -> tuple[dict, int]:
    """name -> literal (scalar) or list of literals; plus how many values were left out."""
    omitted = 0
    vals: dict = {}

    def scalar(name, v):
        nonlocal omitted
        if v:
            lit = kql_literal(v)
            vals[name] = lit if lit else None
            omitted += lit is None

    def listed(name, items):
        nonlocal omitted
        lits = []
        for v in dict.fromkeys(x for x in items if x):
            lit = kql_literal(v)
            if lit is None or len(lits) >= MAX_LIST:
                omitted += 1
            else:
                lits.append(lit)
        if lits:
            vals[name] = lits

    mid = (a.message_id or "").strip()
    bare = mid.strip("<>").strip()
    listed("message_ids", [f"<{bare}>", bare] if bare else [])
    scalar("sender", address(a.from_addr))
    scalar("envelope_sender", address(a.return_path))
    scalar("subject", (a.subject or "").strip())
    urls = a.urls or []
    listed("urls", [link_target(u) for u in urls])
    listed("hosts", [link_host(u) for u in urls])
    atts = a.attachments or []
    listed("names", [x.get("filename") for x in atts])
    listed("sha256s", [(x.get("sha256") or "").lower() for x in atts])
    listed("md5s", [(x.get("md5") or "").lower() for x in atts])
    return {k: v for k, v in vals.items() if v}, omitted


def _let(name, v) -> str:
    return f"let {name} = {v};" if isinstance(v, str) else f"let {name} = pack_array({', '.join(v)});"


_HOSTS_NOTE = "// Remove any legitimate host (a real vendor's or Microsoft's own link) from `hosts` before running."
_MSG = """let msg = EmailEvents
    | where Timestamp > ago(lookback) and InternetMessageId in (message_ids)
    | distinct NetworkMessageId;"""
_SEED = """let seed = EmailEvents
    | where Timestamp > ago(lookback) and InternetMessageId in (message_ids)
    | where isnotnull(EmailClusterId)
    | distinct EmailClusterId;"""


def _delivery(v):
    conds = []
    if "message_ids" in v:
        conds.append("InternetMessageId in (message_ids)")
    if "sender" in v and "subject" in v:
        conds.append("(SenderFromAddress =~ sender and Subject == subject)")
    if not conds:
        return None, "no Message-ID, and no sender and subject"
    return ([], f"""EmailEvents
| where Timestamp > ago(lookback)
| where {" or ".join(conds)}
| summarize arg_max(Timestamp, *) by NetworkMessageId, RecipientEmailAddress
| project Timestamp, RecipientEmailAddress, DeliveryAction, DeliveryLocation,
          LatestDeliveryAction, LatestDeliveryLocation, ThreatTypes, NetworkMessageId, EmailClusterId
| order by Timestamp desc"""), None


def _similar(v):
    pre, conds = [], []
    if "message_ids" in v:
        pre.append(_SEED)
        conds.append("EmailClusterId in (seed)")
    if "sender" in v:
        conds.append("SenderFromAddress =~ sender")
    if "envelope_sender" in v:
        conds.append("SenderMailFromAddress =~ envelope_sender")
    if not conds:
        return None, "no Message-ID or sender"
    return (pre, f"""EmailEvents
| where Timestamp > ago(lookback)
| where {" or ".join(conds)}
| summarize Recipients = dcount(RecipientEmailAddress), Messages = dcount(NetworkMessageId),
            Subjects = make_set(Subject, 20), First = min(Timestamp), Last = max(Timestamp)
          by SenderFromAddress, SenderMailFromAddress
| order by Last desc"""), None


def _url_recipients(v):
    conds = (["Url in (urls)"] if "urls" in v else []) + (["UrlDomain in~ (hosts)"] if "hosts" in v else [])
    if not conds:
        return None, "no links"
    return ([], f"""EmailUrlInfo
| where Timestamp > ago(lookback)
| where {" or ".join(conds)}
| join kind=inner (EmailEvents
    | where Timestamp > ago(lookback)
    | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, Subject, DeliveryAction, LatestDeliveryLocation)
    on NetworkMessageId
| summarize Urls = make_set(Url, 20)
          by RecipientEmailAddress, SenderFromAddress, Subject, DeliveryAction, LatestDeliveryLocation"""), None


def _clicks(v):
    if "urls" not in v and "hosts" not in v:
        return None, "no links"
    pre, conds = [], []
    if "message_ids" in v:
        pre.append(_MSG)
        conds.append("NetworkMessageId in (msg)")
    if "urls" in v:
        conds.append("Url in (urls)")
    if "hosts" in v:
        conds.append("Host in~ (hosts)")
    return (pre, f"""UrlClickEvents
| where Timestamp > ago(lookback)
| extend Host = tostring(parse_url(Url).Host)
| where {" or ".join(conds)}
| project Timestamp, AccountUpn, ActionType, IsClickedThrough, Url, Workload, IPAddress, NetworkMessageId
| order by Timestamp desc"""), None


def _attachments_mail(v):
    conds = (["FileName in~ (names)"] if "names" in v else []) + (["SHA256 in~ (sha256s)"] if "sha256s" in v else [])
    if not conds:
        return None, "no attachments"
    return ([], f"""EmailAttachmentInfo
| where Timestamp > ago(lookback)
| where {" or ".join(conds)}
| project Timestamp, RecipientEmailAddress, SenderFromAddress, FileName, FileType, SHA256, ThreatTypes, NetworkMessageId
| order by Timestamp desc"""), None


def _attachments_endpoint(v):
    conds = (["MD5 in~ (md5s)"] if "md5s" in v else []) + (["SHA256 in~ (sha256s)"] if "sha256s" in v else [])
    if not conds:
        return None, "no attachments"
    return ([], f"""DeviceFileEvents
| where Timestamp > ago(lookback)
| where {" or ".join(conds)}
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, MD5,
          InitiatingProcessAccountUpn, InitiatingProcessFileName, FileOriginUrl
| order by Timestamp desc"""), None


MDO, MDE = "Defender for Office 365", "Defender for Endpoint"
QUERIES = [
    ("delivery", "Who received it, and where it is now", "Every recipient of this message, its delivery "
     "action and its latest location (after ZAP or a manual remediation).", MDO, ["EmailEvents"], _delivery),
    ("similar", "The same campaign", "Mail in Microsoft's similarity cluster of this message, or from the "
     "same sender: recipients, message count, subjects and first/last seen.", MDO, ["EmailEvents"], _similar),
    ("url_recipients", "Every mail carrying these links", "Recipients of any mail with the same links or "
     "link hosts, and where those mails are now.", MDO, ["EmailUrlInfo", "EmailEvents"], _url_recipients),
    ("clicks", "Who clicked", "Safe Links clicks on this message's links (or the same links and hosts "
     "anywhere): who, when, allowed or blocked, clicked through a warning.", MDO, ["UrlClickEvents"], _clicks),
    ("attachments_mail", "Who received the attachment", "Mail carrying an attachment with the same name or "
     "SHA-256 (Microsoft notes SHA256 is usually empty in this table, so the name is the main key).",
     MDO, ["EmailAttachmentInfo"], _attachments_mail),
    ("attachments_endpoint", "Where the file landed on devices", "File events on devices for the "
     "attachment's MD5 or SHA-256 (hashes only: file names are too common on endpoints).",
     MDE, ["DeviceFileEvents"], _attachments_endpoint),
]


def hunting_queries(a, *, incident_ref: str, lookback_days: int, now: datetime | None = None) -> dict:
    """{queries: [{id, title, purpose, requires, tables, kql}], skipped: [{id, reason}], omitted_values}.
    Each query is standalone: a FENRIR-only comment header, the `let`s it uses, then its body."""
    now = now or datetime.now(timezone.utc)
    v, omitted = _values(a)
    header = (f"// FENRIR {incident_ref} · email analysis {a.id} · generated {now.strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
              f"let lookback = {int(lookback_days)}d;")
    queries, skipped = [], []
    for qid, title, purpose, requires, tables, build in QUERIES:
        built, reason = build(v)
        if built is None:
            skipped.append({"id": qid, "reason": reason})
            continue
        pre, text = built
        body = "\n".join([*pre, text])
        used = [name for name in v if re.search(rf"\b{name}\b", body)]
        notes = [_HOSTS_NOTE] if "hosts" in used else []
        kql = "\n".join([header, *notes, *(_let(name, v[name]) for name in used), body])
        queries.append({"id": qid, "title": title, "purpose": purpose, "requires": requires,
                        "tables": tables, "kql": kql})
    return {"queries": queries, "skipped": skipped, "omitted_values": omitted}
