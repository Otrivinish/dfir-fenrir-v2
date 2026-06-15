export const MITRE_TACTICS = [
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0010', name: 'Exfiltration' },
  { id: 'TA0011', name: 'Command and Control' },
  { id: 'TA0040', name: 'Impact' },
]

export const MITRE_TECHNIQUES = {
  TA0001: [
    { id: 'T1190', name: 'Exploit Public-Facing Application' },
    { id: 'T1566', name: 'Phishing' },
    { id: 'T1078', name: 'Valid Accounts' },
    { id: 'T1133', name: 'External Remote Services' },
    { id: 'T1195', name: 'Supply Chain Compromise' },
    { id: 'T1091', name: 'Replication Through Removable Media' },
    { id: 'T1199', name: 'Trusted Relationship' },
    { id: 'T1189', name: 'Drive-by Compromise' },
  ],
  TA0002: [
    { id: 'T1059', name: 'Command and Scripting Interpreter' },
    { id: 'T1203', name: 'Exploitation for Client Execution' },
    { id: 'T1106', name: 'Native API' },
    { id: 'T1053', name: 'Scheduled Task/Job' },
    { id: 'T1047', name: 'Windows Management Instrumentation' },
    { id: 'T1072', name: 'Software Deployment Tools' },
    { id: 'T1204', name: 'User Execution' },
    { id: 'T1569', name: 'System Services' },
  ],
  TA0003: [
    { id: 'T1078', name: 'Valid Accounts' },
    { id: 'T1136', name: 'Create Account' },
    { id: 'T1547', name: 'Boot or Logon Autostart Execution' },
    { id: 'T1543', name: 'Create or Modify System Process' },
    { id: 'T1197', name: 'BITS Jobs' },
    { id: 'T1037', name: 'Boot or Logon Initialization Scripts' },
    { id: 'T1574', name: 'Hijack Execution Flow' },
    { id: 'T1098', name: 'Account Manipulation' },
    { id: 'T1505', name: 'Server Software Component' },
    { id: 'T1053', name: 'Scheduled Task/Job' },
  ],
  TA0004: [
    { id: 'T1078', name: 'Valid Accounts' },
    { id: 'T1068', name: 'Exploitation for Privilege Escalation' },
    { id: 'T1055', name: 'Process Injection' },
    { id: 'T1134', name: 'Access Token Manipulation' },
    { id: 'T1548', name: 'Abuse Elevation Control Mechanism' },
    { id: 'T1543', name: 'Create or Modify System Process' },
    { id: 'T1574', name: 'Hijack Execution Flow' },
    { id: 'T1053', name: 'Scheduled Task/Job' },
  ],
  TA0005: [
    { id: 'T1027', name: 'Obfuscated Files or Information' },
    { id: 'T1036', name: 'Masquerading' },
    { id: 'T1070', name: 'Indicator Removal' },
    { id: 'T1055', name: 'Process Injection' },
    { id: 'T1562', name: 'Impair Defenses' },
    { id: 'T1078', name: 'Valid Accounts' },
    { id: 'T1218', name: 'System Binary Proxy Execution' },
    { id: 'T1553', name: 'Subvert Trust Controls' },
    { id: 'T1134', name: 'Access Token Manipulation' },
    { id: 'T1574', name: 'Hijack Execution Flow' },
  ],
  TA0006: [
    { id: 'T1003', name: 'OS Credential Dumping' },
    { id: 'T1110', name: 'Brute Force' },
    { id: 'T1555', name: 'Credentials from Password Stores' },
    { id: 'T1552', name: 'Unsecured Credentials' },
    { id: 'T1056', name: 'Input Capture' },
    { id: 'T1111', name: 'MFA Interception' },
    { id: 'T1558', name: 'Steal or Forge Kerberos Tickets' },
    { id: 'T1539', name: 'Steal Web Session Cookie' },
  ],
  TA0007: [
    { id: 'T1082', name: 'System Information Discovery' },
    { id: 'T1083', name: 'File and Directory Discovery' },
    { id: 'T1057', name: 'Process Discovery' },
    { id: 'T1049', name: 'System Network Connections Discovery' },
    { id: 'T1018', name: 'Remote System Discovery' },
    { id: 'T1033', name: 'System Owner/User Discovery' },
    { id: 'T1069', name: 'Permission Groups Discovery' },
    { id: 'T1087', name: 'Account Discovery' },
    { id: 'T1135', name: 'Network Share Discovery' },
    { id: 'T1046', name: 'Network Service Discovery' },
  ],
  TA0008: [
    { id: 'T1021', name: 'Remote Services' },
    { id: 'T1570', name: 'Lateral Tool Transfer' },
    { id: 'T1534', name: 'Internal Spearphishing' },
    { id: 'T1550', name: 'Use Alternate Authentication Material' },
    { id: 'T1563', name: 'Remote Service Session Hijacking' },
    { id: 'T1080', name: 'Taint Shared Content' },
  ],
  TA0009: [
    { id: 'T1005', name: 'Data from Local System' },
    { id: 'T1039', name: 'Data from Network Shared Drive' },
    { id: 'T1074', name: 'Data Staged' },
    { id: 'T1114', name: 'Email Collection' },
    { id: 'T1056', name: 'Input Capture' },
    { id: 'T1560', name: 'Archive Collected Data' },
    { id: 'T1113', name: 'Screen Capture' },
  ],
  TA0010: [
    { id: 'T1041', name: 'Exfiltration Over C2 Channel' },
    { id: 'T1048', name: 'Exfiltration Over Alternative Protocol' },
    { id: 'T1567', name: 'Exfiltration Over Web Service' },
    { id: 'T1020', name: 'Automated Exfiltration' },
  ],
  TA0011: [
    { id: 'T1071', name: 'Application Layer Protocol' },
    { id: 'T1095', name: 'Non-Application Layer Protocol' },
    { id: 'T1572', name: 'Protocol Tunneling' },
    { id: 'T1573', name: 'Encrypted Channel' },
    { id: 'T1008', name: 'Fallback Channels' },
    { id: 'T1105', name: 'Ingress Tool Transfer' },
    { id: 'T1132', name: 'Data Encoding' },
  ],
  TA0040: [
    { id: 'T1486', name: 'Data Encrypted for Impact' },
    { id: 'T1485', name: 'Data Destruction' },
    { id: 'T1499', name: 'Endpoint Denial of Service' },
    { id: 'T1498', name: 'Network Denial of Service' },
    { id: 'T1531', name: 'Account Access Removal' },
    { id: 'T1489', name: 'Service Stop' },
    { id: 'T1491', name: 'Defacement' },
    { id: 'T1490', name: 'Inhibit System Recovery' },
  ],
}

export function tacticColor(tacticId) {
  const map = {
    TA0001: 'var(--crit)',    // Initial Access
    TA0002: 'var(--high)',    // Execution
    TA0003: 'var(--med)',     // Persistence
    TA0004: 'var(--high)',    // Privilege Escalation
    TA0005: 'var(--accent)',  // Defense Evasion
    TA0006: 'var(--crit)',    // Credential Access
    TA0007: 'var(--low)',     // Discovery
    TA0008: 'var(--high)',    // Lateral Movement
    TA0009: 'var(--med)',     // Collection
    TA0010: 'var(--high)',    // Exfiltration
    TA0011: 'var(--accent)',  // Command and Control
    TA0040: 'var(--crit)',    // Impact
  }
  return map[tacticId] || 'var(--border-strong)'
}
