"""
Stateless forensic artifact parser.

Supported formats:
  - EVTX             (Windows Event Log binary)
  - XML              (wevtutil / PowerShell XML export; same schema as EVTX records)
  - SQLite           (Chrome or Firefox browsing history)
  - CSV / TSV
  - JSON / JSONL
  - syslog / auth.log (RFC 3164 BSD timestamps or ISO 8601 prefix)
  - journald JSON    (journalctl -o json or -o json-pretty)
  - macOS Unified Log (log show --style json)

Returns a list of normalized dicts; nothing is written to the database.

python-evtx is imported lazily; the rest of the module works without it.
EVTX uploads fail with a clear error message if the package is absent.
"""
import csv
import io
import json
import os
import re
import sqlite3
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from typing import Optional, Union
from urllib.parse import unquote

try:
    import Evtx.Evtx as evtx_lib
    HAS_EVTX = True
except ImportError:  # pragma: no cover
    HAS_EVTX = False

MAX_EVENTS    = 2_000
MAX_RAW_CHARS = 2_000

EVTX_MAGIC   = b"ElfFile\x00"
SQLITE_MAGIC  = b"SQLite format 3\x00"
_EVTX_NS     = "http://schemas.microsoft.com/win/2004/08/events/event"

# ─── MITRE ATT&CK lookup tables ───────────────────────────────────────────────
# Each entry: event_type, mitre_tactic_id, mitre_tactic_name,
#             mitre_technique_id, mitre_technique_name

_WIN_MITRE: dict[int, dict] = {
    # Logon / authentication
    4624: {"event_type": "Logon",                     "mitre_tactic_id": "TA0001", "mitre_tactic_name": "Initial Access",       "mitre_technique_id": "T1078", "mitre_technique_name": "Valid Accounts"},
    4625: {"event_type": "Logon Failure",              "mitre_tactic_id": "TA0006", "mitre_tactic_name": "Credential Access",    "mitre_technique_id": "T1110", "mitre_technique_name": "Brute Force"},
    4648: {"event_type": "Logon (Explicit Creds)",    "mitre_tactic_id": "TA0008", "mitre_tactic_name": "Lateral Movement",     "mitre_technique_id": "T1550", "mitre_technique_name": "Use Alternate Authentication Material"},
    4672: {"event_type": "Special Privileges Logon",  "mitre_tactic_id": "TA0004", "mitre_tactic_name": "Privilege Escalation", "mitre_technique_id": "T1134", "mitre_technique_name": "Access Token Manipulation"},
    4768: {"event_type": "Kerberos TGT",               "mitre_tactic_id": "TA0006", "mitre_tactic_name": "Credential Access",    "mitre_technique_id": "T1558", "mitre_technique_name": "Steal or Forge Kerberos Tickets"},
    4769: {"event_type": "Kerberos Service Ticket",   "mitre_tactic_id": "TA0006", "mitre_tactic_name": "Credential Access",    "mitre_technique_id": "T1558", "mitre_technique_name": "Steal or Forge Kerberos Tickets"},
    4771: {"event_type": "Kerberos Pre-auth Failed",  "mitre_tactic_id": "TA0006", "mitre_tactic_name": "Credential Access",    "mitre_technique_id": "T1110", "mitre_technique_name": "Brute Force"},
    4776: {"event_type": "NTLM Auth",                 "mitre_tactic_id": "TA0006", "mitre_tactic_name": "Credential Access",    "mitre_technique_id": "T1110", "mitre_technique_name": "Brute Force"},
    # Process / execution
    4688: {"event_type": "Process Creation",           "mitre_tactic_id": "TA0002", "mitre_tactic_name": "Execution",            "mitre_technique_id": "T1059", "mitre_technique_name": "Command and Scripting Interpreter"},
    4104: {"event_type": "PowerShell Script Block",   "mitre_tactic_id": "TA0002", "mitre_tactic_name": "Execution",            "mitre_technique_id": "T1059", "mitre_technique_name": "Command and Scripting Interpreter"},
    # Persistence / services / tasks
    4697: {"event_type": "Service Installed",          "mitre_tactic_id": "TA0003", "mitre_tactic_name": "Persistence",          "mitre_technique_id": "T1543", "mitre_technique_name": "Create or Modify System Process"},
    7045: {"event_type": "Service Installed",          "mitre_tactic_id": "TA0003", "mitre_tactic_name": "Persistence",          "mitre_technique_id": "T1543", "mitre_technique_name": "Create or Modify System Process"},
    4698: {"event_type": "Scheduled Task Created",    "mitre_tactic_id": "TA0003", "mitre_tactic_name": "Persistence",          "mitre_technique_id": "T1053", "mitre_technique_name": "Scheduled Task/Job"},
    4702: {"event_type": "Scheduled Task Updated",    "mitre_tactic_id": "TA0003", "mitre_tactic_name": "Persistence",          "mitre_technique_id": "T1053", "mitre_technique_name": "Scheduled Task/Job"},
    # Account / group manipulation
    4720: {"event_type": "Account Created",            "mitre_tactic_id": "TA0003", "mitre_tactic_name": "Persistence",          "mitre_technique_id": "T1136", "mitre_technique_name": "Create Account"},
    4728: {"event_type": "Group Membership Added",    "mitre_tactic_id": "TA0004", "mitre_tactic_name": "Privilege Escalation", "mitre_technique_id": "T1098", "mitre_technique_name": "Account Manipulation"},
    4732: {"event_type": "Group Membership Added",    "mitre_tactic_id": "TA0004", "mitre_tactic_name": "Privilege Escalation", "mitre_technique_id": "T1098", "mitre_technique_name": "Account Manipulation"},
    4756: {"event_type": "Group Membership Added",    "mitre_tactic_id": "TA0004", "mitre_tactic_name": "Privilege Escalation", "mitre_technique_id": "T1098", "mitre_technique_name": "Account Manipulation"},
    # Object access / collection
    4663: {"event_type": "Object Access",              "mitre_tactic_id": "TA0009", "mitre_tactic_name": "Collection",           "mitre_technique_id": "T1005", "mitre_technique_name": "Data from Local System"},
    # Defense evasion
    1102: {"event_type": "Audit Log Cleared",          "mitre_tactic_id": "TA0005", "mitre_tactic_name": "Defense Evasion",      "mitre_technique_id": "T1070", "mitre_technique_name": "Indicator Removal"},
    4719: {"event_type": "Audit Policy Changed",       "mitre_tactic_id": "TA0005", "mitre_tactic_name": "Defense Evasion",      "mitre_technique_id": "T1562", "mitre_technique_name": "Impair Defenses"},
}

_SYS_MITRE: dict[int, dict] = {
    1:  {"event_type": "Process Creation",             "mitre_tactic_id": "TA0002", "mitre_tactic_name": "Execution",            "mitre_technique_id": "T1059", "mitre_technique_name": "Command and Scripting Interpreter"},
    2:  {"event_type": "File Timestamp Changed",       "mitre_tactic_id": "TA0005", "mitre_tactic_name": "Defense Evasion",      "mitre_technique_id": "T1070", "mitre_technique_name": "Indicator Removal"},
    3:  {"event_type": "Network Connection",           "mitre_tactic_id": "TA0011", "mitre_tactic_name": "Command and Control",  "mitre_technique_id": "T1071", "mitre_technique_name": "Application Layer Protocol"},
    6:  {"event_type": "Driver Loaded",                "mitre_tactic_id": "TA0005", "mitre_tactic_name": "Defense Evasion",      "mitre_technique_id": "T1014", "mitre_technique_name": "Rootkit"},
    7:  {"event_type": "Image Loaded",                 "mitre_tactic_id": "TA0005", "mitre_tactic_name": "Defense Evasion",      "mitre_technique_id": "T1574", "mitre_technique_name": "Hijack Execution Flow"},
    8:  {"event_type": "Remote Thread Created",        "mitre_tactic_id": "TA0004", "mitre_tactic_name": "Privilege Escalation", "mitre_technique_id": "T1055", "mitre_technique_name": "Process Injection"},
    10: {"event_type": "Process Access",               "mitre_tactic_id": "TA0006", "mitre_tactic_name": "Credential Access",    "mitre_technique_id": "T1003", "mitre_technique_name": "OS Credential Dumping"},
    11: {"event_type": "File Created",                 "mitre_tactic_id": "TA0002", "mitre_tactic_name": "Execution",            "mitre_technique_id": "T1105", "mitre_technique_name": "Ingress Tool Transfer"},
    12: {"event_type": "Registry Create/Delete",       "mitre_tactic_id": "TA0003", "mitre_tactic_name": "Persistence",          "mitre_technique_id": "T1547", "mitre_technique_name": "Boot or Logon Autostart Execution"},
    13: {"event_type": "Registry Value Set",           "mitre_tactic_id": "TA0003", "mitre_tactic_name": "Persistence",          "mitre_technique_id": "T1547", "mitre_technique_name": "Boot or Logon Autostart Execution"},
    14: {"event_type": "Registry Renamed",             "mitre_tactic_id": "TA0005", "mitre_tactic_name": "Defense Evasion",      "mitre_technique_id": "T1036", "mitre_technique_name": "Masquerading"},
    15: {"event_type": "File Stream Created",          "mitre_tactic_id": "TA0005", "mitre_tactic_name": "Defense Evasion",      "mitre_technique_id": "T1553", "mitre_technique_name": "Subvert Trust Controls"},
    22: {"event_type": "DNS Query",                    "mitre_tactic_id": "TA0011", "mitre_tactic_name": "Command and Control",  "mitre_technique_id": "T1071", "mitre_technique_name": "Application Layer Protocol"},
    23: {"event_type": "File Deleted",                 "mitre_tactic_id": "TA0005", "mitre_tactic_name": "Defense Evasion",      "mitre_technique_id": "T1070", "mitre_technique_name": "Indicator Removal"},
    25: {"event_type": "Process Tampering",            "mitre_tactic_id": "TA0005", "mitre_tactic_name": "Defense Evasion",      "mitre_technique_id": "T1055", "mitre_technique_name": "Process Injection"},
}

# EIDs whose presence alone warrants suspicious=True, regardless of tactic.
_SUSPICIOUS_WIN = {4625, 4648, 4671, 4776, 1102, 4719, 7045, 4720, 4728, 4732, 4756, 4697}
_SUSPICIOUS_SYS = {8, 10, 25}
# Tactics where presence → suspicious=True.
_HIGH_RISK_TACTICS = {"TA0001", "TA0006", "TA0008", "TA0040"}

# ─── Linux / macOS syslog MITRE rules ─────────────────────────────────────────

# RFC 3164 syslog line: timestamp host process[pid]: message
# Also handles ISO 8601 / RFC 5424 prefix ("2024-01-01T12:00:00Z host proc[pid]: msg")
_SYSLOG_LINE_RE = re.compile(
    r'^(?:'
    r'(?P<iso_ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'
    r'|(?P<bsd_ts>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2})'
    r')\s+(?P<host>\S+)\s+(?P<proc>[^\[\s:]+)(?:\[(?P<pid>\d+)\])?\s*:\s*(?P<msg>.*)',
    re.MULTILINE,
)

_BSD_MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12,
}

# Each rule: (message_re, event_type, tactic_id, tactic_name, tech_id, tech_name, suspicious)
# Search target for each rule is "{proc}: {msg}" so process context is included.
_SYSLOG_RULES: list[tuple] = [
    # SSH auth failures
    (re.compile(r'Failed (?:password|publickey|keyboard|gssapi)|authentication failure|Invalid user|illegal user', re.I),
     "Auth Failure", "TA0006", "Credential Access", "T1110", "Brute Force", True),
    # SSH successful login
    (re.compile(r'Accepted (?:password|publickey|keyboard|hostbased)|session opened for user', re.I),
     "SSH Login", "TA0001", "Initial Access", "T1078", "Valid Accounts", False),
    # sudo execution (proc=sudo; message contains COMMAND=)
    (re.compile(r'\bsudo\b.*COMMAND=|sudo:.*authentication failure', re.I),
     "Sudo Execution", "TA0004", "Privilege Escalation", "T1548", "Abuse Elevation Control Mechanism", True),
    # su to root
    (re.compile(r'\bsu\b.*root|pam.*su.*fail|su:\s+FAILED', re.I),
     "Su to Root", "TA0004", "Privilege Escalation", "T1548", "Abuse Elevation Control Mechanism", True),
    # Account created
    (re.compile(r'useradd|adduser.*new user|new user:|new account added', re.I),
     "Account Created", "TA0003", "Persistence", "T1136", "Create Account", True),
    # Account removed / locked
    (re.compile(r'userdel|deluser|account.*locked|pam_tally.*locked|pam_faillock.*locked', re.I),
     "Account Removed/Locked", "TA0040", "Impact", "T1531", "Account Access Removal", True),
    # Password change
    (re.compile(r'password changed|chpasswd|passwd.*changed|password.*updated', re.I),
     "Password Change", "TA0003", "Persistence", "T1098", "Account Manipulation", False),
    # Cron / scheduled task
    (re.compile(r'CMD\s*\(|CRON.*COMMAND|crond.*run|anacron.*job', re.I),
     "Scheduled Task Run", "TA0003", "Persistence", "T1053", "Scheduled Task/Job", False),
    # Service start / install
    (re.compile(r'systemd.*Started .+\.service|service.*started|daemon\s+(?:started|running)', re.I),
     "Service Started", "TA0003", "Persistence", "T1543", "Create or Modify System Process", False),
    # Firewall changes
    (re.compile(r'iptables|nftables|firewalld|ufw .+(?:allow|deny|rule)', re.I),
     "Firewall Modified", "TA0005", "Defense Evasion", "T1562", "Impair Defenses", True),
    # Package install
    (re.compile(r'(?:apt|dpkg|yum|dnf|rpm|brew)\b.+install', re.I),
     "Package Installed", "TA0002", "Execution", "T1072", "Software Deployment Tools", False),
    # Log tampering
    (re.compile(r'log.*cleared|journal.*vacuum|logrotate.*removed|log.*deleted', re.I),
     "Log Tamper", "TA0005", "Defense Evasion", "T1070", "Indicator Removal", True),
    # Kernel error (informational, no MITRE)
    (re.compile(r'segfault|kernel.*oops|Out of memory.*process', re.I),
     "Kernel Error", None, None, None, None, False),
]

# CSV/JSON heuristic column names (lowercased).
_TS_COL   = {"timestamp", "time", "datetime", "date", "event_time", "@timestamp",
             "date_time", "eventtime", "created", "created_at",
             "timegenerated", "time_generated"}  # Defender / Azure / KQL exports
_DESC_COL = {"message", "description", "event", "log", "details", "summary",
             "command", "cmdline", "commandline", "msg", "processcommandline"}
_HOST_COL = {"hostname", "host", "computer", "device", "source_host", "computername",
             "machine", "workstation", "devicename"}
_TYPE_COL = {"type", "event_type", "category", "action", "eventtype", "event_category",
             "filename"}
_SRC_COL  = {"source", "log_source", "channel", "provider", "logsource", "source_name"}

# ─── Public entry point ────────────────────────────────────────────────────────

def parse_artifact(filename: str, content: bytes) -> tuple[str, list[dict]]:
    """
    Detect format and parse *content* into a list of normalized event dicts.
    Returns (detected_format, events).
    Raises ValueError with a human-readable message on failure.
    """
    ext = os.path.splitext(filename.lower())[1]

    # Magic-byte detection takes priority over extension.
    if content[:8] == EVTX_MAGIC:
        return "evtx", _parse_evtx(content)
    if content[:16] == SQLITE_MAGIC:
        return "sqlite", _parse_sqlite(content, filename)
    # ZIP — a Velociraptor offline-collector output bundle (U1.3).
    if content[:4] == b"PK\x03\x04":
        return "velociraptor", parse_velociraptor_collection(io.BytesIO(content))

    if ext in (".evtx",):
        return "evtx", _parse_evtx(content)
    if ext in (".xml",):
        return "xml", _parse_xml(content)
    if ext in (".db", ".sqlite", ".sqlite3"):
        return "sqlite", _parse_sqlite(content, filename)
    if ext in (".csv",):
        return "csv", _parse_csv(content)
    if ext in (".tsv",):
        return "csv", _parse_csv(content, dialect="tsv")
    if ext in (".log",):
        try:
            events = _parse_syslog(content)
            return "syslog", events
        except ValueError:
            pass
        return "csv", _parse_csv(content)
    if ext in (".json", ".jsonl"):
        return _dispatch_json(content)

    # Last-resort content sniff.
    snippet = content[:512]
    if b"<Events>" in snippet or b"<Event xmlns" in snippet:
        return "xml", _parse_xml(content)

    # Syslog content sniff: RFC 3164 "Mon DD HH:MM:SS" at line start.
    snippet_text = snippet.decode("utf-8-sig", errors="replace")
    if re.search(r'^[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} ', snippet_text, re.MULTILINE):
        try:
            events = _parse_syslog(content)
            if events:
                return "syslog", events
        except ValueError:
            pass

    if snippet.lstrip().startswith(b"{") or snippet.lstrip().startswith(b"["):
        return _dispatch_json(content)
    try:
        return "csv", _parse_csv(content)
    except Exception:
        raise ValueError(f"Unsupported file format: {filename!r}")


# ─── EVTX ─────────────────────────────────────────────────────────────────────

def _parse_evtx(content: bytes) -> list[dict]:
    if not HAS_EVTX:
        raise ValueError(
            "EVTX parsing requires the python-evtx package. "
            "Rebuild the backend image to include it."
        )
    results: list[dict] = []
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as f:
            f.write(content)
            tmp_path = f.name
        with evtx_lib.Evtx(tmp_path) as log:
            for record in log.records():
                if len(results) >= MAX_EVENTS:
                    break
                try:
                    xml_str = record.xml()
                    root = ET.fromstring(xml_str)
                    ev = _extract_win_xml(root)
                    if ev:
                        results.append(ev)
                except Exception:
                    continue
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    return results


# ─── Windows / Sysmon XML ─────────────────────────────────────────────────────

def _ns(tag: str) -> str:
    return f"{{{_EVTX_NS}}}{tag}"


def _find(el: ET.Element, tag: str) -> "ET.Element | None":
    """Find child by namespaced tag, fall back to plain tag.
    Using 'is not None' avoids the Python <3.12 bug where a leaf Element
    (0 children) is falsy, causing 'el.find(ns) or el.find(plain)' to
    incorrectly return None even when the namespaced element exists."""
    result = el.find(_ns(tag))
    if result is not None:
        return result
    return el.find(tag)


def _parse_xml(content: bytes) -> list[dict]:
    """Parse wevtutil / PowerShell XML export (root = <Events> or bare <Event>)."""
    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        raise ValueError(f"XML parse error: {e}")

    # Normalise: if root IS an <Event>, wrap it.
    tag_local = root.tag.split("}")[-1] if "}" in root.tag else root.tag
    if tag_local == "Event":
        events_el = [root]
    else:
        events_el = list(root.iter(_ns("Event"))) or list(root.iter("Event"))

    results: list[dict] = []
    for el in events_el:
        if len(results) >= MAX_EVENTS:
            break
        try:
            ev = _extract_win_xml(el)
            if ev:
                results.append(ev)
        except Exception:
            continue
    return results


def _extract_win_xml(root: ET.Element) -> Optional[dict]:
    """Extract one event from a Windows XML <Event> element."""
    sys_el = _find(root, "System")
    if sys_el is None:
        return None

    eid_el = _find(sys_el, "EventID")
    if eid_el is None:
        return None
    try:
        eid = int(eid_el.text or "0")
    except (ValueError, TypeError):
        return None

    ts_el      = _find(sys_el, "TimeCreated")
    ts_str     = ts_el.get("SystemTime") if ts_el is not None else None
    event_time = _parse_win_ts(ts_str)

    channel_el  = _find(sys_el, "Channel")
    computer_el = _find(sys_el, "Computer")
    channel  = (channel_el.text  or "").strip() if channel_el  is not None else ""
    hostname = (computer_el.text or "").strip() if computer_el is not None else None

    # Determine whether this is a Sysmon record by channel name.
    is_sysmon = "sysmon" in channel.lower()
    mitre_map = _SYS_MITRE if is_sysmon else _WIN_MITRE
    mitre_info = mitre_map.get(eid, {})

    # Collect EventData fields.
    data: dict[str, str] = {}
    data_el = _find(root, "EventData")
    if data_el is not None:
        for d in list(data_el):
            name = d.get("Name")
            if name and d.text:
                data[name] = d.text.strip()

    description = _build_description(eid, data, mitre_info, is_sysmon)
    event_type  = mitre_info.get("event_type") or f"Event {eid}"
    source      = channel or ("Sysmon" if is_sysmon else "Windows Event Log")

    raw_payload = {"EventID": eid, **data}
    raw_log = json.dumps(raw_payload, ensure_ascii=False)[:MAX_RAW_CHARS]

    suspicious, reasons = _flag_suspicious(
        eid, mitre_info, is_sysmon,
        base_reason=f"{'Sysmon' if is_sysmon else 'Windows'} Event {eid}: {event_type}"
    )

    return _make_event(
        event_time=event_time,
        hostname=hostname or None,
        source=source,
        event_type=event_type,
        description=description,
        raw_log=raw_log,
        suspicious=suspicious,
        suspicious_reasons=reasons,
        **{k: v for k, v in mitre_info.items() if k != "event_type"},
    )


def _build_description(eid: int, data: dict, mitre_info: dict, is_sysmon: bool) -> str:
    """Human-readable one-liner for the most common event IDs."""
    g = data.get

    if is_sysmon:
        if eid == 1:
            img = g("Image", "?")
            cmd = g("CommandLine", "")
            user = g("User", "")
            parent = g("ParentImage", "")
            return f"Process: {img}" + (f" | CMD: {cmd}" if cmd else "") + (f" | User: {user}" if user else "") + (f" | Parent: {parent}" if parent else "")
        if eid == 3:
            return f"Network: {g('Image','?')} → {g('DestinationIp','?')}:{g('DestinationPort','?')} ({g('Protocol','tcp')})"
        if eid == 8:
            return f"Remote thread: {g('SourceImage','?')} → {g('TargetImage','?')}"
        if eid == 10:
            return f"Process access: {g('SourceImage','?')} → {g('TargetImage','?')} (Access: {g('GrantedAccess','?')})"
        if eid == 11:
            return f"File created: {g('TargetFilename','?')} by {g('Image','?')}"
        if eid in (12, 13, 14):
            return f"Registry: {g('EventType','?')} {g('TargetObject','?')} by {g('Image','?')}"
        if eid == 22:
            return f"DNS: {g('Image','?')} queried {g('QueryName','?')}"
        return f"Sysmon Event {eid}: " + " | ".join(f"{k}: {v}" for k, v in list(data.items())[:4])

    # Windows Security / System events
    if eid == 4624:
        return f"Logon: {g('TargetDomainName','?')}\\{g('TargetUserName','?')} from {g('IpAddress','?')} (Type {g('LogonType','?')})"
    if eid == 4625:
        return f"Logon failure: {g('TargetDomainName','?')}\\{g('TargetUserName','?')} from {g('IpAddress','?')}"
    if eid == 4648:
        return f"Logon (explicit creds): {g('SubjectDomainName','?')}\\{g('SubjectUserName','?')} → {g('TargetUserName','?')} on {g('TargetServerName','?')}"
    if eid == 4688:
        return f"Process: {g('NewProcessName','?')} | CMD: {g('CommandLine','')} | User: {g('SubjectUserName','?')}"
    if eid == 4698:
        return f"Scheduled task created: {g('TaskName','?')} by {g('SubjectUserName','?')}"
    if eid in (4697, 7045):
        return f"Service: {g('ServiceName','?')} | Path: {g('ServiceFileName', g('ImagePath','?'))}"
    if eid == 4720:
        return f"Account created: {g('TargetUserName','?')} by {g('SubjectUserName','?')}"
    if eid in (4728, 4732, 4756):
        return f"Member added to group: {g('TargetUserName','?')} → {g('TargetDomainName','?')}\\{g('GroupName', g('TargetGroupName','?'))} by {g('SubjectUserName','?')}"
    if eid in (4768, 4769):
        return f"Kerberos ticket: {g('TargetUserName','?')} from {g('IpAddress','?')} for {g('ServiceName','?')}"
    if eid in (4771, 4776):
        return f"Auth failure: {g('TargetUserName','?')} from {g('IpAddress','?')}"
    if eid == 4104:
        block = g("ScriptBlockText", "")
        return f"PowerShell script: {block[:120]}{'…' if len(block) > 120 else ''}"
    if eid == 1102:
        return f"Audit log cleared by {g('SubjectUserName','?')}"

    # Generic fallback
    event_type = mitre_info.get("event_type") or f"Event {eid}"
    fields = " | ".join(f"{k}: {v}" for k, v in list(data.items())[:3])
    return f"{event_type}" + (f": {fields}" if fields else "")


def _flag_suspicious(
    eid: int,
    mitre_info: dict,
    is_sysmon: bool,
    base_reason: str,
) -> tuple[bool, list[str]]:
    reasons: list[str] = []

    if is_sysmon and eid in _SUSPICIOUS_SYS:
        reasons.append(base_reason)
    if not is_sysmon and eid in _SUSPICIOUS_WIN:
        reasons.append(base_reason)

    tactic = mitre_info.get("mitre_tactic_id")
    if tactic in _HIGH_RISK_TACTICS:
        reasons.append(f"MITRE {tactic}: {mitre_info.get('mitre_tactic_name','')}")

    return bool(reasons), reasons


# ─── SQLite (Chrome / Firefox) ────────────────────────────────────────────────

# Chrome WebKit epoch: microseconds since 1601-01-01.
_WEBKIT_EPOCH_OFFSET = 11_644_473_600_000_000  # microseconds


def _parse_sqlite(content: bytes, filename: str) -> list[dict]:
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            f.write(content)
            tmp_path = f.name

        conn = sqlite3.connect(tmp_path)
        conn.row_factory = sqlite3.Row
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}

        results: list[dict] = []

        if "visits" in tables and "urls" in tables:
            # Chrome history
            rows = conn.execute(
                "SELECT v.visit_time, u.url, u.title "
                "FROM visits v JOIN urls u ON v.url = u.id "
                "ORDER BY v.visit_time DESC LIMIT ?",
                (MAX_EVENTS,)
            ).fetchall()
            for r in rows:
                ts = _webkit_ts(r["visit_time"])
                url   = r["url"] or ""
                title = r["title"] or url
                results.append(_make_event(
                    event_time=ts,
                    hostname=None,
                    source="Chrome History",
                    event_type="Browser Visit",
                    description=f"Visited: {title} | URL: {url}",
                    raw_log=json.dumps({"url": url, "title": title}, ensure_ascii=False)[:MAX_RAW_CHARS],
                    suspicious=False,
                    suspicious_reasons=[],
                ))

        elif "moz_historyvisits" in tables and "moz_places" in tables:
            # Firefox history
            rows = conn.execute(
                "SELECT v.visit_date, p.url, p.title "
                "FROM moz_historyvisits v JOIN moz_places p ON v.place_id = p.id "
                "ORDER BY v.visit_date DESC LIMIT ?",
                (MAX_EVENTS,)
            ).fetchall()
            for r in rows:
                ts = _unix_us_ts(r["visit_date"])
                url   = r["url"] or ""
                title = r["title"] or url
                results.append(_make_event(
                    event_time=ts,
                    hostname=None,
                    source="Firefox History",
                    event_type="Browser Visit",
                    description=f"Visited: {title} | URL: {url}",
                    raw_log=json.dumps({"url": url, "title": title}, ensure_ascii=False)[:MAX_RAW_CHARS],
                    suspicious=False,
                    suspicious_reasons=[],
                ))
        else:
            conn.close()
            raise ValueError("SQLite database does not appear to be Chrome or Firefox history")

        conn.close()
        return results
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _webkit_ts(microseconds: Optional[int]) -> Optional[datetime]:
    if not microseconds:
        return None
    try:
        unix_us = microseconds - _WEBKIT_EPOCH_OFFSET
        return datetime.fromtimestamp(unix_us / 1_000_000, tz=timezone.utc)
    except Exception:
        return None


def _unix_us_ts(microseconds: Optional[int]) -> Optional[datetime]:
    if not microseconds:
        return None
    try:
        return datetime.fromtimestamp(microseconds / 1_000_000, tz=timezone.utc)
    except Exception:
        return None


# ─── Syslog / auth.log (RFC 3164 + ISO 8601) ─────────────────────────────────

def _parse_syslog(content: bytes) -> list[dict]:
    """Parse RFC 3164 / RFC 5424 / ISO-prefixed syslog text (Linux auth.log, syslog, macOS system.log)."""
    try:
        text = content.decode("utf-8-sig", errors="replace")
    except Exception as e:
        raise ValueError(f"Could not decode syslog: {e}")

    results: list[dict] = []
    now = datetime.now(tz=timezone.utc)

    for m in _SYSLOG_LINE_RE.finditer(text):
        if len(results) >= MAX_EVENTS:
            break
        ts_str     = m.group("iso_ts") or m.group("bsd_ts")
        event_time = _parse_syslog_ts(ts_str, now)
        host       = m.group("host") or None
        proc       = (m.group("proc") or "").strip()
        pid        = m.group("pid") or ""
        msg        = (m.group("msg") or "").strip()
        if not msg:
            continue

        # Match against MITRE rules using "{proc}: {msg}" so process context is included.
        search_str = f"{proc}: {msg}"
        mitre: dict = {}
        suspicious = False
        sus_reasons: list[str] = []
        for pat, ev_type, tac_id, tac_name, tec_id, tec_name, sus in _SYSLOG_RULES:
            if pat.search(search_str):
                mitre = {"event_type": ev_type, "mitre_tactic_id": tac_id,
                         "mitre_tactic_name": tac_name, "mitre_technique_id": tec_id,
                         "mitre_technique_name": tec_name}
                if sus:
                    suspicious = True
                    sus_reasons.append(f"{proc}: {ev_type}")
                break

        proc_label  = proc + (f"[{pid}]" if pid else "")
        description = (f"{proc_label}: {msg}" if proc_label else msg)[:512]
        raw_log     = json.dumps({"process": proc, "pid": pid or None, "host": host, "message": msg},
                                 ensure_ascii=False)[:MAX_RAW_CHARS]

        results.append(_make_event(
            event_time=event_time,
            hostname=host,
            source=f"syslog/{proc}" if proc else "syslog",
            event_type=mitre.get("event_type") or "Syslog Event",
            description=description,
            raw_log=raw_log,
            suspicious=suspicious,
            suspicious_reasons=sus_reasons,
            mitre_tactic_id=mitre.get("mitre_tactic_id"),
            mitre_tactic_name=mitre.get("mitre_tactic_name"),
            mitre_technique_id=mitre.get("mitre_technique_id"),
            mitre_technique_name=mitre.get("mitre_technique_name"),
        ))

    if not results:
        raise ValueError("No syslog lines found in file")
    return results


def _parse_syslog_ts(ts_str: Optional[str], ref: datetime) -> Optional[datetime]:
    if not ts_str:
        return None
    ts_str = ts_str.strip()
    # BSD / RFC 3164: "Jan  1 12:00:00" — year is inferred from ref (current time).
    bsd_m = re.match(r'([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})', ts_str)
    if bsd_m:
        mon = _BSD_MONTHS.get(bsd_m.group(1), 1)
        day = int(bsd_m.group(2))
        h, mi, s = int(bsd_m.group(3)), int(bsd_m.group(4)), int(bsd_m.group(5))
        year = ref.year
        # If the month/day appears to be in the future, assume previous year.
        if mon > ref.month or (mon == ref.month and day > ref.day):
            year -= 1
        try:
            return datetime(year, mon, day, h, mi, s, tzinfo=timezone.utc)
        except ValueError:
            return None
    # ISO 8601 / RFC 5424 — normalize then fromisoformat.
    try:
        ts = ts_str.replace('T', ' ', 1).replace('Z', '+00:00', 1)
        ts = re.sub(r'([+-])(\d{2})(\d{2})$', r'\1\2:\3', ts)  # ±HHMM → ±HH:MM
        dt = datetime.fromisoformat(ts)
        return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return _try_parse_ts(ts_str)


# ─── journald JSON (journalctl -o json / -o json-pretty) ─────────────────────

def _parse_journald(content: bytes) -> list[dict]:
    """Parse journalctl -o json (JSONL) or -o json-pretty (JSON array) export."""
    try:
        text = content.decode("utf-8-sig", errors="replace")
    except Exception as e:
        raise ValueError(f"Could not decode journald export: {e}")

    rows: list[dict] = []
    stripped = text.strip()
    # json-pretty: JSON array
    if stripped.startswith("["):
        try:
            data = json.loads(stripped)
            if isinstance(data, list):
                rows = [r for r in data if isinstance(r, dict)]
        except json.JSONDecodeError:
            pass
    # JSONL: one object per line
    if not rows:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    rows.append(obj)
            except json.JSONDecodeError:
                continue

    results: list[dict] = []
    for obj in rows:
        if len(results) >= MAX_EVENTS:
            break
        if "__REALTIME_TIMESTAMP" not in obj:
            continue
        try:
            us = int(obj["__REALTIME_TIMESTAMP"])
            event_time: Optional[datetime] = datetime.fromtimestamp(us / 1_000_000, tz=timezone.utc)
        except (ValueError, TypeError):
            event_time = None

        msg  = str(obj.get("MESSAGE", "")).strip()
        if not msg:
            continue
        proc = str(obj.get("SYSLOG_IDENTIFIER") or obj.get("_COMM") or "")
        pid  = str(obj.get("_PID", "") or "")
        host = str(obj.get("_HOSTNAME", "") or "") or None
        try:
            priority_int = int(obj.get("PRIORITY", 6))
        except (ValueError, TypeError):
            priority_int = 6

        search_str = f"{proc}: {msg}"
        mitre: dict = {}
        # Priority ≤ 3 (emergency / alert / critical / error) is always suspicious.
        suspicious  = priority_int <= 3
        sus_reasons: list[str] = [f"journald priority {priority_int} (critical)"] if suspicious else []

        for pat, ev_type, tac_id, tac_name, tec_id, tec_name, sus in _SYSLOG_RULES:
            if pat.search(search_str):
                mitre = {"event_type": ev_type, "mitre_tactic_id": tac_id,
                         "mitre_tactic_name": tac_name, "mitre_technique_id": tec_id,
                         "mitre_technique_name": tec_name}
                if sus and not suspicious:
                    suspicious = True
                    sus_reasons.append(f"{proc}: {ev_type}")
                break

        proc_label  = proc + (f"[{pid}]" if pid else "")
        description = (f"{proc_label}: {msg}" if proc_label else msg)[:512]
        raw_log     = json.dumps({"proc": proc, "pid": pid or None, "host": host,
                                  "priority": priority_int, "message": msg},
                                 ensure_ascii=False)[:MAX_RAW_CHARS]

        results.append(_make_event(
            event_time=event_time,
            hostname=host,
            source=f"journald/{proc}" if proc else "journald",
            event_type=mitre.get("event_type") or "Journal Event",
            description=description,
            raw_log=raw_log,
            suspicious=suspicious,
            suspicious_reasons=sus_reasons,
            mitre_tactic_id=mitre.get("mitre_tactic_id"),
            mitre_tactic_name=mitre.get("mitre_tactic_name"),
            mitre_technique_id=mitre.get("mitre_technique_id"),
            mitre_technique_name=mitre.get("mitre_technique_name"),
        ))

    return results


# ─── macOS Unified Log (log show --style json) ────────────────────────────────

def _parse_macos_unified_log(content: bytes) -> list[dict]:
    """Parse macOS Unified Log JSON export (log show --style json)."""
    try:
        data = json.loads(content.decode("utf-8-sig", errors="replace"))
    except Exception as e:
        raise ValueError(f"Could not parse macOS Unified Log JSON: {e}")

    if isinstance(data, dict):
        for key in ("entries", "events", "items", "data"):
            if key in data and isinstance(data[key], list):
                data = data[key]
                break
        else:
            data = [data]

    results: list[dict] = []
    for obj in data:
        if len(results) >= MAX_EVENTS:
            break
        if not isinstance(obj, dict):
            continue
        msg = str(obj.get("eventMessage", "") or "").strip()
        if not msg:
            continue

        event_time = _parse_macos_unified_ts(str(obj.get("timestamp", "") or ""))
        proc_path  = str(obj.get("processImagePath", "") or obj.get("senderImagePath", "") or "")
        proc       = proc_path.rsplit("/", 1)[-1] if proc_path else ""
        pid        = str(obj.get("processID", "") or "")
        subsystem  = str(obj.get("subsystem", "") or "")
        category   = str(obj.get("category", "") or "")

        # Search includes subsystem so com.apple.securityd patterns can match.
        search_str = f"{proc}: {msg} {subsystem}"
        mitre: dict = {}
        suspicious  = False
        sus_reasons: list[str] = []
        for pat, ev_type, tac_id, tac_name, tec_id, tec_name, sus in _SYSLOG_RULES:
            if pat.search(search_str):
                mitre = {"event_type": ev_type, "mitre_tactic_id": tac_id,
                         "mitre_tactic_name": tac_name, "mitre_technique_id": tec_id,
                         "mitre_technique_name": tec_name}
                if sus:
                    suspicious = True
                    sus_reasons.append(f"{proc}: {ev_type}")
                break

        proc_label  = proc + (f"[{pid}]" if pid else "")
        description = (f"[{subsystem}] {proc_label}: {msg}" if subsystem else
                       f"{proc_label}: {msg}" if proc_label else msg)[:512]
        raw_log     = json.dumps({"process": proc, "pid": pid or None,
                                  "subsystem": subsystem, "category": category,
                                  "message": msg}, ensure_ascii=False)[:MAX_RAW_CHARS]

        results.append(_make_event(
            event_time=event_time,
            hostname=None,
            source=f"macOS/{proc}" if proc else "macOS Unified Log",
            event_type=mitre.get("event_type") or "Unified Log",
            description=description,
            raw_log=raw_log,
            suspicious=suspicious,
            suspicious_reasons=sus_reasons,
            mitre_tactic_id=mitre.get("mitre_tactic_id"),
            mitre_tactic_name=mitre.get("mitre_tactic_name"),
            mitre_technique_id=mitre.get("mitre_technique_id"),
            mitre_technique_name=mitre.get("mitre_technique_name"),
        ))

    return results


def _parse_macos_unified_ts(ts_str: str) -> Optional[datetime]:
    """Parse macOS Unified Log timestamp: '2024-01-15 09:23:45.123456-0800'"""
    if not ts_str:
        return None
    try:
        ts = ts_str.strip().replace(' ', 'T', 1).replace('Z', '+00:00', 1)
        ts = re.sub(r'([+-])(\d{2})(\d{2})$', r'\1\2:\3', ts)
        dt = datetime.fromisoformat(ts)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


# ─── JSON format dispatcher ───────────────────────────────────────────────────

def _peek_first_json_obj(content: bytes) -> dict:
    """Return the first JSON object from content without full parsing, for format detection."""
    try:
        text = content.decode("utf-8-sig", errors="replace").lstrip()
        if text.startswith("["):
            start = text.index("{")
            depth = 0
            for i, ch in enumerate(text[start: start + 8192]):
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        return json.loads(text[start: start + i + 1])
        else:
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    return json.loads(line)
    except Exception:
        pass
    return {}


def _dispatch_json(content: bytes) -> tuple[str, list[dict]]:
    """Detect whether JSON content is journald, macOS Unified Log, or generic, then parse."""
    first = _peek_first_json_obj(content)
    if "__REALTIME_TIMESTAMP" in first:
        return "journald", _parse_journald(content)
    if "machTimestamp" in first or ("eventMessage" in first and "processID" in first):
        return "macos_unified_log", _parse_macos_unified_log(content)
    return "json", _parse_json(content)


# ─── CSV / TSV ────────────────────────────────────────────────────────────────

def _parse_csv(content: bytes, dialect: str = "auto") -> list[dict]:
    try:
        text = content.decode("utf-8-sig", errors="replace")
    except Exception as e:
        raise ValueError(f"Could not decode CSV: {e}")

    if dialect == "tsv":
        reader = csv.DictReader(io.StringIO(text), delimiter="\t")
    elif dialect == "auto":
        sample = text[:4096]
        tab_count   = sample.count("\t")
        comma_count = sample.count(",")
        delim = "\t" if tab_count > comma_count else ","
        reader = csv.DictReader(io.StringIO(text), delimiter=delim)
    else:
        reader = csv.DictReader(io.StringIO(text))

    results: list[dict] = []
    for row in reader:
        if len(results) >= MAX_EVENTS:
            break
        ev = _row_to_event(dict(row))
        if ev:
            results.append(ev)
    return results


# ─── JSON / JSONL ─────────────────────────────────────────────────────────────

def _parse_json(content: bytes) -> list[dict]:
    try:
        text = content.decode("utf-8-sig", errors="replace")
    except Exception as e:
        raise ValueError(f"Could not decode JSON: {e}")

    # JSONL — one object per line.
    stripped = text.strip()
    if "\n" in stripped and stripped[0] == "{":
        rows = []
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    else:
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")

        # Unwrap common top-level wrapper keys.
        if isinstance(parsed, dict):
            for key in ("events", "records", "data", "logs", "items", "results", "hits"):
                if key in parsed and isinstance(parsed[key], list):
                    parsed = parsed[key]
                    break
            else:
                parsed = [parsed]

        rows = parsed if isinstance(parsed, list) else [parsed]

    results: list[dict] = []
    for row in rows:
        if len(results) >= MAX_EVENTS:
            break
        if not isinstance(row, dict):
            continue
        ev = _row_to_event(row)
        if ev:
            results.append(ev)
    return results


# ─── Generic row → event (CSV / JSON) ────────────────────────────────────────

def _row_to_event(row: dict) -> Optional[dict]:
    if not row:
        return None

    # Heuristic field detection (lowercased keys).
    lower = {k.lower(): v for k, v in row.items() if v is not None}

    ts_str = _first(lower, _TS_COL)
    event_time = _try_parse_ts(ts_str)

    description = str(_first(lower, _DESC_COL) or "")
    if not description:
        # Fallback: join all values.
        description = " | ".join(f"{k}: {v}" for k, v in list(row.items())[:5] if v)

    if not description:
        return None

    hostname   = str(_first(lower, _HOST_COL) or "") or None
    event_type = str(_first(lower, _TYPE_COL) or "") or None
    source     = str(_first(lower, _SRC_COL)  or "") or None

    raw_log = json.dumps(row, ensure_ascii=False, default=str)[:MAX_RAW_CHARS]

    return _make_event(
        event_time=event_time,
        hostname=hostname,
        source=source or "CSV/JSON Import",
        event_type=event_type,
        description=description[:512],
        raw_log=raw_log,
        suspicious=False,
        suspicious_reasons=[],
    )


def _first(d: dict, keys: set) -> Optional[str]:
    for k in keys:
        if k in d and d[k]:
            return str(d[k])
    return None


# ─── Velociraptor offline-collector bundle (U1.3) ────────────────────────────
# The collector emits a ZIP with per-artifact JSONL under results/. We map each
# row to a normalized timeline event, reusing the generic timestamp/host
# heuristics + the per-artifact hints below. Collected files (uploads/) are NOT
# parsed here — exploding $MFT / hives / .evtx as child artifacts for dedicated
# parsers is U5's job.

VELO_MAX_EVENTS = 10_000

# Timestamp field paths probed in order (top-level + common nested shapes).
_VELO_TS_PATHS = [
    ("System", "TimeCreated", "SystemTime"),
    ("_ts",), ("EventTime",), ("Timestamp",), ("timestamp",),
    ("Mtime",), ("Btime",), ("Ctime",), ("Atime",),
    ("LastRunTime",), ("CreateTime",), ("Created",), ("Last_Run",),
    ("StartTime",), ("EndTime",), ("Time",),
]


def _velo_parse_any_time(v) -> Optional[datetime]:
    if isinstance(v, dict):
        for k in ("SystemTime", "Time", "value", "Value"):
            if k in v:
                return _velo_parse_any_time(v[k])
        return None
    s = str(v).strip()
    if not s:
        return None
    # RFC3339 with offset / 'Z' (Python 3.11+ fromisoformat handles both).
    try:
        s2 = s[:-1] + "+00:00" if s.endswith("Z") else s
        dt = datetime.fromisoformat(s2)
        return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return _try_parse_ts(s)


def _velo_time(row: dict) -> Optional[datetime]:
    for path in _VELO_TS_PATHS:
        v: object = row
        for k in path:
            if isinstance(v, dict) and k in v:
                v = v[k]
            else:
                v = None
                break
        if v not in (None, ""):
            dt = _velo_parse_any_time(v)
            if dt:
                return dt
    lower = {k.lower(): val for k, val in row.items() if isinstance(val, (str, int, float))}
    return _try_parse_ts(_first(lower, _TS_COL))


_VELO_DESC_FIELDS = ("Message", "Description", "Name", "OSPath", "Path",
                     "Executable", "CommandLine", "Exe", "Key", "ValueName",
                     "Url", "Binary", "FullPath")


def _velo_description(artifact: str, row: dict) -> str:
    if "Evtx" in artifact:
        sysd = row.get("System") if isinstance(row.get("System"), dict) else {}
        eid = sysd.get("EventID")
        if isinstance(eid, dict):
            eid = eid.get("Value")
        chan = sysd.get("Channel")
        msg = str(row.get("Message") or "").strip().splitlines()
        msg1 = msg[0] if msg else ""
        head = " · ".join(b for b in [f"EventID {eid}" if eid is not None else "", str(chan or "")] if b)
        return (f"{head} — {msg1}".strip(" —") or "Windows event")[:512]
    if "Pslist" in artifact:
        name = row.get("Name") or row.get("Exe") or ""
        pid  = row.get("Pid")
        cmd  = row.get("CommandLine") or ""
        return f"Process {name} (pid {pid}) {cmd}".strip()[:512]
    for k in _VELO_DESC_FIELDS:
        v = row.get(k)
        if isinstance(v, (str, int, float)) and str(v).strip():
            return f"{k}: {v}"[:512]
    bits = [f"{k}={v}" for k, v in row.items()
            if isinstance(v, (str, int, float)) and str(v).strip() and k.lower() not in _TS_COL]
    return " | ".join(bits[:4])[:512]


def _velo_row_to_event(artifact: str, row: dict, default_host: Optional[str]) -> Optional[dict]:
    if not row:
        return None
    description = _velo_description(artifact, row)
    if not description:
        return None
    lower = {k.lower(): v for k, v in row.items() if isinstance(v, (str, int, float)) and v != ""}
    host = _first(lower, _HOST_COL) or default_host
    short = artifact.split(".")[-1]
    return _make_event(
        event_time=_velo_time(row),
        hostname=host or None,
        source=f"velociraptor/{artifact}",
        event_type=short,
        description=description,
        raw_log=json.dumps(row, ensure_ascii=False, default=str)[:MAX_RAW_CHARS],
        suspicious=False,
        suspicious_reasons=[],
    )


def _velo_default_host(zf: zipfile.ZipFile) -> Optional[str]:
    for name in ("collection_context.json", "client_info.json"):
        if name in zf.namelist():
            try:
                ctx = json.loads(zf.read(name).decode("utf-8", "replace"))
                if isinstance(ctx, dict):
                    for k in ("Hostname", "hostname", "Fqdn", "fqdn"):
                        if ctx.get(k):
                            return str(ctx[k])
            except Exception:
                pass
    return None


def parse_velociraptor_collection(zip_source: Union[str, io.BytesIO]) -> list[dict]:
    """Parse a Velociraptor offline-collector ZIP into normalized events.

    `zip_source` is a path (preferred for large collections — members are read
    lazily) or a BytesIO. Raises ValueError if it's not a Velociraptor bundle
    or has no parseable result rows.
    """
    try:
        zf = zipfile.ZipFile(zip_source)
    except zipfile.BadZipFile as e:
        raise ValueError(f"Not a valid ZIP: {e}")
    with zf:
        names = zf.namelist()
        result_files = [n for n in names if n.startswith("results/") and n.endswith(".json")]
        if not result_files and not any(n in names for n in ("uploads.json", "collection_context.json")):
            raise ValueError("Not a Velociraptor collection (no results/ found)")

        default_host = _velo_default_host(zf)
        events: list[dict] = []
        for name in result_files:
            if len(events) >= VELO_MAX_EVENTS:
                break
            # Velociraptor URL-encodes the artifact/source path: e.g.
            # results/Windows.EventLogs.Evtx%2FAllEvents.json → Artifact "Windows.EventLogs.Evtx".
            artifact = unquote(name[len("results/"):-len(".json")]).split("/")[0]
            try:
                with zf.open(name) as fh:
                    for raw_line in fh:
                        if len(events) >= VELO_MAX_EVENTS:
                            break
                        line = raw_line.strip()
                        if not line:
                            continue
                        try:
                            row = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if not isinstance(row, dict):
                            continue
                        ev = _velo_row_to_event(artifact, row, default_host)
                        if ev:
                            events.append(ev)
            except Exception:
                continue

        if not events:
            raise ValueError("Velociraptor collection contained no parseable result rows")
        return events


# ─── Timestamp parsers ────────────────────────────────────────────────────────

_TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    # Microsoft Defender portal CSV export: "Jun 23, 2026 10:53:35 AM"
    "%b %d, %Y %I:%M:%S %p",
    "%b %d, %Y %I:%M %p",
]


def _parse_win_ts(ts: Optional[str]) -> Optional[datetime]:
    """Parse Windows SystemTime (7- or 9-decimal fraction, UTC)."""
    if not ts:
        return None
    try:
        ts = ts.rstrip("Z")
        if "." in ts:
            main, frac = ts.split(".", 1)
            frac = frac[:6].ljust(6, "0")
            ts = f"{main}.{frac}"
        return datetime.fromisoformat(ts).replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _try_parse_ts(s: Optional[str]) -> Optional[datetime]:
    """Try common datetime formats; return None if all fail."""
    if not s:
        return None
    s = str(s).strip()
    # Unix timestamp (numeric).
    try:
        epoch = float(s)
        if 1_000_000_000 < epoch < 9_999_999_999:
            return datetime.fromtimestamp(epoch, tz=timezone.utc)
        if epoch > 1_000_000_000_000:
            return datetime.fromtimestamp(epoch / 1000, tz=timezone.utc)
    except ValueError:
        pass
    # ISO 8601 via fromisoformat — handles offsets and (after normalizing) the
    # 7-digit fractional seconds Defender/Azure emit, which strptime's %f rejects.
    iso = s[:-1] + "+00:00" if s.endswith("Z") else s
    iso = re.sub(r"(\.\d{6})\d+", r"\1", iso)   # truncate >6 fractional digits
    try:
        dt = datetime.fromisoformat(iso)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


# ─── Normalized event builder ────────────────────────────────────────────────

def _make_event(
    *,
    event_time: Optional[datetime],
    hostname: Optional[str],
    source: Optional[str],
    event_type: Optional[str],
    description: str,
    raw_log: Optional[str],
    suspicious: bool,
    suspicious_reasons: list[str],
    mitre_tactic_id: Optional[str] = None,
    mitre_tactic_name: Optional[str] = None,
    mitre_technique_id: Optional[str] = None,
    mitre_technique_name: Optional[str] = None,
) -> dict:
    return {
        "event_time":           event_time.isoformat() if event_time else None,
        "hostname":             hostname or None,
        "source":               source or None,
        "event_type":           event_type or None,
        "description":          description,
        "raw_log":              raw_log or None,
        "mitre_tactic_id":      mitre_tactic_id or None,
        "mitre_tactic_name":    mitre_tactic_name or None,
        "mitre_technique_id":   mitre_technique_id or None,
        "mitre_technique_name": mitre_technique_name or None,
        "suspicious":           suspicious,
        "suspicious_reasons":   suspicious_reasons,
    }
