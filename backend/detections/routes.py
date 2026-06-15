"""Detection query generation from incident IOCs + MITRE techniques.

Mounted at prefix="/api/incidents".
Generates ready-to-use SIEM/XDR queries for Defender/Sentinel, Elastic,
Splunk, Cortex XDR, and CrowdStrike.
"""
import uuid
from io import BytesIO
from typing import Optional
import zipfile

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import current_user
from core.database import get_db
from incidents.access import get_accessible_incident
from models import IOC, Incident, TimelineEvent, User
from schemas import DetectionBundle, DetectionPlatform, DetectionQuery

router = APIRouter()

PLATFORMS = [
    {"key": "kql", "label": "Defender / Sentinel", "ext": "kql"},
    {"key": "eql", "label": "Elastic",              "ext": "eql"},
    {"key": "spl", "label": "Splunk",               "ext": "spl"},
    {"key": "xql", "label": "Cortex XDR",           "ext": "xql"},
    {"key": "cs",  "label": "CrowdStrike",           "ext": "cs"},
]

# ─── MITRE technique → query templates ───────────────────────────────────────

MITRE_TEMPLATES: dict[str, dict] = {
    "T1059.001": {
        "name": "PowerShell Execution",
        "kql": 'DeviceProcessEvents\n| where FileName =~ "powershell.exe"\n| where ProcessCommandLine has_any ("-EncodedCommand", "-enc ", "IEX", "DownloadString", "Invoke-Expression", "FromBase64String")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine',
        "eql": 'process where process.name == "powershell.exe" and\n  process.command_line : ("*-EncodedCommand*", "*-enc *", "*IEX*", "*DownloadString*")',
        "spl": 'index=* (process_name="powershell.exe" OR Image="*\\powershell.exe")\n| search CommandLine="*-EncodedCommand*" OR CommandLine="*IEX*" OR CommandLine="*DownloadString*"\n| table _time, host, user, CommandLine',
        "xql": 'dataset = xdr_data\n| filter event_type = ENUM.PROCESS and action_process_image_name = "powershell.exe"\n| filter action_process_command_line ~= "(?i)(-EncodedCommand|-enc |IEX|DownloadString)"\n| fields agent_hostname, actor_effective_username, action_process_command_line',
        "cs":  'event_simpleName=ProcessRollup2\n| search FileName=powershell.exe\n| search CommandLine="*-EncodedCommand*" OR CommandLine="*IEX*" OR CommandLine="*DownloadString*"\n| table ComputerName, UserName, CommandLine, ParentBaseFileName',
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "kql": 'DeviceProcessEvents\n| where FileName =~ "cmd.exe"\n| where ProcessCommandLine has_any ("/c", "/k", "echo", "certutil", "bitsadmin", "wscript", "cscript")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName',
        "eql": 'process where process.name == "cmd.exe" and\n  process.command_line : ("*/c *", "*/k *") and\n  process.command_line : ("*certutil*", "*bitsadmin*", "*echo*", "*wscript*")',
        "spl": 'index=* (process_name="cmd.exe" OR Image="*\\cmd.exe")\n| search CommandLine="*/c *" OR CommandLine="*/k *"\n| table _time, host, user, CommandLine, ParentImage',
        "xql": 'dataset = xdr_data\n| filter event_type = ENUM.PROCESS and action_process_image_name = "cmd.exe"\n| filter action_process_command_line ~= "(?i)/[ck] "\n| fields agent_hostname, actor_effective_username, action_process_command_line',
        "cs":  'event_simpleName=ProcessRollup2\n| search FileName=cmd.exe\n| search CommandLine="*/c *" OR CommandLine="*/k *"\n| table ComputerName, UserName, CommandLine, ParentBaseFileName',
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "kql": 'DeviceProcessEvents\n| where FileName in~ ("lsass.exe") and ProcessCommandLine has_any ("minidump", "procdump", "sekurlsa", "wce", "mimikatz")\n| union (DeviceProcessEvents | where InitiatingProcessFileName =~ "mimikatz.exe")\n| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine',
        "eql": 'process where process.name : ("mimikatz.exe", "procdump.exe", "wce.exe") or\n  (process.name == "lsass.exe" and process.parent.name != "wininit.exe")',
        "spl": 'index=* (Image="*\\mimikatz.exe" OR Image="*\\procdump.exe" OR TargetImage="*\\lsass.exe")\n| table _time, host, user, Image, CommandLine, TargetImage',
        "xql": 'dataset = xdr_data\n| filter action_process_image_name in ("mimikatz.exe", "procdump.exe", "wce.exe")\n   or (action_module_path ~= "(?i)lsass" and event_type = ENUM.LOAD_IMAGE)\n| fields agent_hostname, actor_effective_username, action_process_image_name',
        "cs":  'event_simpleName=ProcessRollup2\n| search FileName=mimikatz.exe OR FileName=procdump.exe\n| append [search event_simpleName=DnsRequest DomainName=*.onion]\n| table ComputerName, UserName, FileName, CommandLine',
    },
    "T1078": {
        "name": "Valid Accounts",
        "kql": 'IdentityLogonEvents\n| where ActionType == "LogonSuccess"\n| where AccountUpn !endswith "@yourdomain.com"\n| summarize count() by AccountUpn, DeviceName, bin(Timestamp, 1h)\n| where count_ > 5',
        "eql": 'authentication where event.outcome == "success" and\n  user.name != null and\n  source.ip != null and\n  not cidr_match(source.ip, "10.0.0.0/8", "192.168.0.0/16")',
        "spl": 'index=* sourcetype=WinEventLog:Security EventCode=4624\n| where Logon_Type=3 AND NOT src_ip IN ("10.0.0.0/8", "192.168.0.0/16")\n| stats count by src_ip, Account_Name, ComputerName | sort -count',
        "xql": 'dataset = xdr_data\n| filter event_type = ENUM.NETWORK and actor_primary_username != null\n| filter not incidr(action_remote_ip, "10.0.0.0/8")\n| fields agent_hostname, actor_primary_username, action_remote_ip',
        "cs":  'event_simpleName=UserLogon\n| stats count by UserName, ComputerName, RemoteAddressIP4 | sort -count\n| where count > 5',
    },
    "T1566": {
        "name": "Phishing",
        "kql": 'EmailEvents\n| where DeliveryAction == "Delivered"\n| where AttachmentCount > 0 or Urls has "http"\n| where SenderFromDomain !in ("trustedomain.com")\n| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, AttachmentCount',
        "eql": 'file where file.extension : ("exe", "dll", "js", "vbs", "hta", "lnk") and\n  process.name : ("outlook.exe", "thunderbird.exe", "winmail.exe")',
        "spl": 'index=* sourcetype=ms:o365:management action=receive\n| search Attachments!="" OR FileExtension=".exe" OR FileExtension=".js"\n| table _time, SenderAddress, RecipientAddress, Subject, Attachments',
        "xql": 'dataset = xdr_data\n| filter event_type = ENUM.FILE and action_file_extension in ("exe","dll","js","vbs","hta")\n| filter actor_process_image_name in ("outlook.exe", "thunderbird.exe")\n| fields agent_hostname, actor_primary_username, action_file_name',
        "cs":  'event_simpleName=EmailDelivered\n| search Attachment="*.exe" OR Attachment="*.js"\n| table ComputerName, UserName, SenderAddress, Subject',
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "kql": 'DeviceNetworkEvents\n| where RemotePort in (80, 443, 8080, 8443)\n| where ActionType == "ConnectionSuccess"\n| where not isempty(RemoteIPType)\n| summarize count() by DeviceName, RemoteIP, RemotePort, bin(Timestamp, 5m)\n| where count_ > 100',
        "eql": 'network where destination.port in (80, 443, 8080, 8443) and\n  event.outcome == "success" and\n  not source.ip : ("10.*", "192.168.*")',
        "spl": 'index=* sourcetype=access_log\n| rex field=_raw "(?<status>\\d{3})" | where status IN ("400","404","500","503")\n| stats count by src_ip, uri | sort -count | head 20',
        "xql": 'dataset = xdr_data\n| filter event_type = ENUM.NETWORK and action_remote_port in (80, 443, 8080, 8443)\n| summarize count() by agent_hostname, action_remote_ip\n| sort desc count',
        "cs":  'event_simpleName=NetworkConnectIP4\n| where RemotePort=80 OR RemotePort=443\n| stats count by ComputerName, RemoteAddressIP4 | sort -count | head 20',
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "kql": 'DeviceProcessEvents\n| where ProcessCommandLine has_any ("char(", "chr(", "base64", "gzip", "decompress", "frombase64string", "bxor")\n| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine',
        "eql": 'process where process.command_line : ("*base64*", "*gzip*", "*bXOR*", "*chr(*", "*char(*")',
        "spl": 'index=* CommandLine="*base64*" OR CommandLine="*gzip*" OR CommandLine="*bXOR*"\n| table _time, host, user, CommandLine, ParentImage',
        "xql": 'dataset = xdr_data\n| filter event_type = ENUM.PROCESS\n| filter action_process_command_line ~= "(?i)(base64|gzip|bxor|frombase64)"\n| fields agent_hostname, actor_effective_username, action_process_command_line',
        "cs":  'event_simpleName=ProcessRollup2\n| search CommandLine="*base64*" OR CommandLine="*gzip*" OR CommandLine="*bXOR*"\n| table ComputerName, UserName, CommandLine',
    },
    "T1055": {
        "name": "Process Injection",
        "kql": 'DeviceEvents\n| where ActionType in ("CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx")\n| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine',
        "eql": 'process where process.parent.name : ("explorer.exe", "svchost.exe") and\n  process.name : ("regsvr32.exe", "rundll32.exe", "mshta.exe", "wscript.exe")',
        "spl": 'index=* EventCode=8\n| table _time, host, SourceImage, TargetImage, StartAddress, StartModule',
        "xql": 'dataset = xdr_data\n| filter event_type = ENUM.INJECTION\n| fields agent_hostname, actor_process_image_name, action_remote_process_image_name',
        "cs":  'event_simpleName=CreateRemoteThread\n| table ComputerName, SourceFileName, TargetFileName, SourceProcessId, TargetProcessId',
    },
    "T1053": {
        "name": "Scheduled Task / Job",
        "kql": 'DeviceProcessEvents\n| where FileName =~ "schtasks.exe"\n| where ProcessCommandLine has_any ("/create", "/change", "/run")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine',
        "eql": 'process where process.name == "schtasks.exe" and\n  process.command_line : ("*/create*", "*/change*", "*/run*")',
        "spl": 'index=* Image="*\\schtasks.exe" CommandLine="*/create*" OR CommandLine="*/change*"\n| table _time, host, user, CommandLine',
        "xql": 'dataset = xdr_data\n| filter action_process_image_name = "schtasks.exe"\n| filter action_process_command_line ~= "(?i)/(create|change|run)"\n| fields agent_hostname, actor_effective_username, action_process_command_line',
        "cs":  'event_simpleName=ProcessRollup2\n| search FileName=schtasks.exe CommandLine="*/create*" OR CommandLine="*/change*"\n| table ComputerName, UserName, CommandLine',
    },
    "T1021": {
        "name": "Remote Services",
        "kql": 'DeviceLogonEvents\n| where LogonType in ("RemoteInteractive", "Network")\n| where ActionType == "LogonSuccess"\n| summarize count() by AccountName, RemoteIP, DeviceName, bin(Timestamp, 1h)',
        "eql": 'authentication where event.outcome == "success" and\n  winlog.event_data.LogonType in ("3", "10") and\n  source.ip != null and not source.ip : "127.0.0.1"',
        "spl": 'index=* sourcetype=WinEventLog:Security EventCode=4624 Logon_Type=10\n| stats count by Account_Name, src_ip, ComputerName | sort -count',
        "xql": 'dataset = xdr_data\n| filter event_type = ENUM.NETWORK and actor_primary_username != null\n| filter action_remote_port in (22, 3389, 5985, 5986, 445)\n| fields agent_hostname, actor_primary_username, action_remote_ip, action_remote_port',
        "cs":  'event_simpleName=UserLogon LogonType=10\n| stats count by UserName, RemoteAddressIP4, ComputerName | sort -count',
    },
}

LOLBIN_HUNT_QUERIES: dict[str, dict] = {
    "certutil": {
        "label": "certutil — LOLBin download/decode",
        "kql": 'DeviceProcessEvents\n| where FileName =~ "certutil.exe"\n| where ProcessCommandLine has_any ("-urlcache", "-decode", "-encode", "http", "ftp")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine',
        "eql": 'process where process.name == "certutil.exe" and\n  process.command_line : ("*-urlcache*", "*-decode*", "*http*")',
        "spl": 'index=* Image="*\\certutil.exe" (CommandLine="*-urlcache*" OR CommandLine="*-decode*")\n| table _time, host, user, CommandLine',
        "xql": 'dataset = xdr_data\n| filter action_process_image_name = "certutil.exe"\n| filter action_process_command_line ~= "(?i)(-urlcache|-decode|http)"\n| fields agent_hostname, actor_effective_username, action_process_command_line',
        "cs":  'event_simpleName=ProcessRollup2 FileName=certutil.exe\n| search CommandLine="*-urlcache*" OR CommandLine="*-decode*"\n| table ComputerName, UserName, CommandLine',
    },
    "mshta": {
        "label": "mshta — LOLBin script execution",
        "kql": 'DeviceProcessEvents\n| where FileName =~ "mshta.exe"\n| where ProcessCommandLine has_any ("javascript:", "vbscript:", "http", "\\\\", "script:")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine',
        "eql": 'process where process.name == "mshta.exe" and\n  process.command_line : ("*javascript:*", "*vbscript:*", "*http*")',
        "spl": 'index=* Image="*\\mshta.exe"\n| table _time, host, user, CommandLine, ParentImage',
        "xql": 'dataset = xdr_data\n| filter action_process_image_name = "mshta.exe"\n| fields agent_hostname, actor_effective_username, action_process_command_line',
        "cs":  'event_simpleName=ProcessRollup2 FileName=mshta.exe\n| table ComputerName, UserName, CommandLine, ParentBaseFileName',
    },
    "regsvr32": {
        "label": "regsvr32 — LOLBin COM scriptlet execution",
        "kql": 'DeviceProcessEvents\n| where FileName =~ "regsvr32.exe"\n| where ProcessCommandLine has_any ("/s", "/i", "/n", "scrobj", "http")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine',
        "eql": 'process where process.name == "regsvr32.exe" and\n  process.command_line : ("*/s*", "*/i*", "*scrobj*", "*http*")',
        "spl": 'index=* Image="*\\regsvr32.exe" (CommandLine="*scrobj*" OR CommandLine="*http*")\n| table _time, host, user, CommandLine',
        "xql": 'dataset = xdr_data\n| filter action_process_image_name = "regsvr32.exe"\n| fields agent_hostname, actor_effective_username, action_process_command_line',
        "cs":  'event_simpleName=ProcessRollup2 FileName=regsvr32.exe\n| search CommandLine="*scrobj*" OR CommandLine="*http*"\n| table ComputerName, UserName, CommandLine',
    },
}


def _q(label: str, kql: str, eql: str, spl: str, xql: str, cs: str,
       confidence: str = "MEDIUM", category: str = "Behavioral") -> dict:
    return {
        "label": label, "confidence": confidence, "category": category,
        "kql": kql, "eql": eql, "spl": spl, "xql": xql, "cs": cs,
    }


def _ioc_queries(iocs: list) -> list[dict]:
    """Generate indicator-based queries per platform from incident IOCs."""
    queries: list[dict] = []

    ips      = [i.value for i in iocs if i.type == "ip"]
    domains  = [i.value for i in iocs if i.type == "domain"]
    urls     = [i.value for i in iocs if i.type == "url"]
    hashes   = [i.value for i in iocs if i.type in ("hash_sha256", "hash_md5", "hash_sha1")]
    emails   = [i.value for i in iocs if i.type == "email"]
    reg_keys = [i.value for i in iocs if i.type == "registry_key"]

    def _join_kql(vals: list[str]) -> str:
        return ", ".join(f'"{v}"' for v in vals[:20])

    if ips:
        joined = _join_kql(ips)
        queries.append(_q(
            f"IP indicators ({len(ips)})",
            f'DeviceNetworkEvents\n| where RemoteIP in ({joined})\n| project Timestamp, DeviceName, AccountName, RemoteIP, RemotePort, RemoteUrl',
            f'network where destination.ip : ({", ".join(repr(ip) for ip in ips[:20])})',
            f'index=* (dest_ip IN ({", ".join(repr(ip) for ip in ips[:20])}) OR src_ip IN ({", ".join(repr(ip) for ip in ips[:20])}))\n| table _time, host, src_ip, dest_ip, dest_port',
            f'dataset = xdr_data\n| filter action_remote_ip in ({_join_kql(ips)})\n| fields agent_hostname, actor_effective_username, action_remote_ip, action_remote_port',
            f'event_simpleName=NetworkConnectIP4\n| search RemoteAddressIP4 IN ({_join_kql(ips)})\n| table ComputerName, UserName, RemoteAddressIP4, RemotePort',
            "HIGH", "Indicator",
        ))

    if domains:
        joined = _join_kql(domains)
        queries.append(_q(
            f"Domain indicators ({len(domains)})",
            f'DeviceNetworkEvents\n| where RemoteUrl has_any ({joined})\n| project Timestamp, DeviceName, AccountName, RemoteUrl, RemoteIP',
            f'dns where dns.question.name : ({", ".join(repr(d) for d in domains[:20])})',
            f'index=* (query IN ({", ".join(repr(d) for d in domains[:20])}) OR url IN ({", ".join(repr(d) for d in domains[:20])}))\n| table _time, host, src_ip, query, url',
            f'dataset = xdr_data\n| filter dns_query_name in ({_join_kql(domains)})\n| fields agent_hostname, actor_effective_username, dns_query_name',
            f'event_simpleName=DnsRequest\n| search DomainName IN ({_join_kql(domains)})\n| table ComputerName, UserName, DomainName, RemoteAddressIP4',
            "HIGH", "Indicator",
        ))

    if hashes:
        joined = _join_kql(hashes)
        queries.append(_q(
            f"File hash indicators ({len(hashes)})",
            f'DeviceFileEvents\n| where SHA256 in ({joined}) or MD5 in ({joined})\n| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256',
            f'file where file.hash.sha256 : ({", ".join(repr(h) for h in hashes[:20])})',
            f'index=* (sha256 IN ({", ".join(repr(h) for h in hashes[:20])}) OR md5 IN ({", ".join(repr(h) for h in hashes[:20])}))\n| table _time, host, file_name, sha256, md5',
            f'dataset = xdr_data\n| filter action_file_sha256 in ({_join_kql(hashes)}) or action_file_md5 in ({_join_kql(hashes)})\n| fields agent_hostname, actor_effective_username, action_file_name, action_file_sha256',
            f'event_simpleName=ProcessRollup2\n| search SHA256HashData IN ({_join_kql(hashes)}) OR MD5HashData IN ({_join_kql(hashes)})\n| table ComputerName, UserName, FileName, SHA256HashData',
            "HIGH", "Indicator",
        ))

    if emails:
        joined = _join_kql(emails)
        queries.append(_q(
            f"Email sender indicators ({len(emails)})",
            f'EmailEvents\n| where SenderFromAddress in ({joined}) or SenderMailFromAddress in ({joined})\n| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject',
            f'email where email.from.address : ({", ".join(repr(e) for e in emails[:20])})',
            f'index=* sourcetype=exchange SenderAddress IN ({", ".join(repr(e) for e in emails[:20])})\n| table _time, SenderAddress, RecipientAddress, Subject',
            f'dataset = email_data\n| filter email_sender in ({_join_kql(emails)})\n| fields email_sender, email_recipient, email_subject',
            f'event_simpleName=EmailDelivered\n| search SenderAddress IN ({_join_kql(emails)})\n| table ComputerName, SenderAddress, RecipientAddress, Subject',
            "HIGH", "Indicator",
        ))

    if reg_keys:
        joined = _join_kql(reg_keys)
        queries.append(_q(
            f"Registry key indicators ({len(reg_keys)})",
            f'DeviceRegistryEvents\n| where RegistryKey has_any ({joined})\n| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueName, RegistryValueData',
            f'registry where registry.path : ({", ".join(repr(r) for r in reg_keys[:20])})',
            f'index=* EventCode=4657 ObjectName IN ({", ".join(repr(r) for r in reg_keys[:20])})\n| table _time, host, user, ObjectName, NewValue',
            f'dataset = xdr_data\n| filter event_type = ENUM.REGISTRY\n| filter action_registry_key_name in ({_join_kql(reg_keys)})\n| fields agent_hostname, actor_effective_username, action_registry_key_name',
            f'event_simpleName=RegSystemConfigValueUpdate\n| search RegStringValue IN ({_join_kql(reg_keys)})\n| table ComputerName, UserName, RegObjectName, RegStringValue',
            "HIGH", "Indicator",
        ))

    return queries


def _mitre_queries(technique_ids: list[str]) -> list[dict]:
    queries: list[dict] = []
    for tid in technique_ids:
        tmpl = MITRE_TEMPLATES.get(tid)
        if not tmpl:
            continue
        queries.append(_q(
            f"{tid} — {tmpl['name']}",
            tmpl["kql"], tmpl["eql"], tmpl["spl"], tmpl["xql"], tmpl["cs"],
            "MEDIUM", "Behavioral",
        ))
    return queries


def _lolbin_queries() -> list[dict]:
    queries: list[dict] = []
    for name, tmpl in LOLBIN_HUNT_QUERIES.items():
        queries.append(_q(
            tmpl["label"],
            tmpl["kql"], tmpl["eql"], tmpl["spl"], tmpl["xql"], tmpl["cs"],
            "LOW", "Hunt",
        ))
    return queries


def _build_platform_bundles(all_queries: list[dict]) -> list[DetectionPlatform]:
    """Reshape flat list of cross-platform queries into per-platform DetectionPlatform objects."""
    result = []
    for plat in PLATFORMS:
        k = plat["key"]
        pq = []
        for q in all_queries:
            if q.get(k):
                pq.append(DetectionQuery(
                    label=q["label"],
                    query=q[k],
                    confidence=q["confidence"],
                    category=q["category"],
                ))
        result.append(DetectionPlatform(
            platform=k,
            label=plat["label"],
            queries=pq,
        ))
    return result


# ─── Endpoints ────────────────────────────────────────────────────────────────

async def _get_incident(db: AsyncSession, incident_id: uuid.UUID, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


@router.get("/{incident_id}/detections", response_model=DetectionBundle,
            summary="Generate SIEM detections for an incident")
async def get_detections(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> DetectionBundle:
    """Generate ready-to-use SIEM/XDR detection queries from the incident's IOCs and techniques.

    Builds indicator queries from the incident's IOCs, behavioral queries from MITRE
    technique IDs seen on its timeline events, and a fixed set of LOLBin hunt queries, then
    groups them per platform (Defender/Sentinel KQL, Elastic EQL, Splunk SPL, Cortex XQL,
    CrowdStrike). Requires access to the incident. Returns the per-platform query bundle
    with a total count.
    """
    await _get_incident(db, incident_id, user)

    iocs = (await db.execute(
        select(IOC).where(IOC.incident_id == incident_id)
    )).scalars().all()

    technique_ids = list({
        ev.mitre_technique_id
        for ev in (await db.execute(
            select(TimelineEvent).where(
                TimelineEvent.incident_id == incident_id,
                TimelineEvent.mitre_technique_id != None,
            )
        )).scalars().all()
        if ev.mitre_technique_id
    })

    all_queries = (
        _ioc_queries(iocs) +
        _mitre_queries(technique_ids) +
        _lolbin_queries()
    )

    platforms = _build_platform_bundles(all_queries)
    total = sum(len(p.queries) for p in platforms)

    return DetectionBundle(
        incident_id=incident_id,
        platforms=platforms,
        total=total,
    )


@router.get("/{incident_id}/detections/download",
            summary="Download detection queries as a ZIP")
async def download_detections(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """Download all generated detection queries for the incident as a ZIP bundle.

    Generates the same queries as the detections endpoint and packages them into
    per-platform files (one per query, named by category/label) plus a manifest.json.
    Requires access to the incident. Returns a streamed application/zip attachment.
    """
    bundle = await get_detections(incident_id, user, db)

    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        manifest = {"incident_id": str(incident_id), "platforms": []}
        for plat_obj in bundle.platforms:
            plat_info = {"platform": plat_obj.platform, "label": plat_obj.label, "files": []}
            ext = next((p["ext"] for p in PLATFORMS if p["key"] == plat_obj.platform), "txt")
            for i, q in enumerate(plat_obj.queries):
                filename = f"{plat_obj.platform}/{i+1:02d}_{q.category}_{q.label[:40].replace(' ', '_')}.{ext}"
                header = f"// [{q.confidence}] [{q.category}] {q.label}\n\n"
                zf.writestr(filename, header + q.query)
                plat_info["files"].append(filename)
            manifest["platforms"].append(plat_info)
        import json
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="detections-{incident_id}.zip"'},
    )
