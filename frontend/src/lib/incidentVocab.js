// Standards-aligned vocabulary used by the incidents UI.
// Source of truth for labels, ordering, and pill colours.
//
//   severity — internal Low/Medium/High/Critical (NCISS mapping done at report time)
//   phase    — NIST SP 800-61 R3
//   tlp      — TLP 2.0
//
// Keep order stable across enum + UI — selectors render in this order.

export const SEVERITY = [
  { value: 'low',      label: 'Low',      pill: 'pill-low'  },
  { value: 'medium',   label: 'Medium',   pill: 'pill-med'  },
  { value: 'high',     label: 'High',     pill: 'pill-high' },
  { value: 'critical', label: 'Critical', pill: 'pill-crit' },
]

// glyph: a shape per phase so phase is never shown by colour alone — render it
//        aria-hidden next to the label. color: the theme's --phase-* token
//        (CSF 2.0 hue family, see tokens.css and CLAUDE.md "Phase palette").
export const PHASE = [
  { value: 'preparation',                      label: 'Preparation',                          short: 'Prep',   glyph: '◇', color: 'var(--phase-prep)'    },
  { value: 'detection_and_analysis',           label: 'Detection & Analysis',                 short: 'Detect', glyph: '◉', color: 'var(--phase-detect)'  },
  { value: 'containment_eradication_recovery', label: 'Containment, Eradication & Recovery', short: 'C/E/R',  glyph: '⊘', color: 'var(--phase-respond)' },
  { value: 'post_incident',                    label: 'Post-Incident',                        short: 'Post',   glyph: '↺', color: 'var(--phase-post)'    },
]

export const TLP = [
  { value: 'red',          label: 'TLP:RED',          pill: 'pill-crit' },
  { value: 'amber_strict', label: 'TLP:AMBER+STRICT', pill: 'pill-high' },
  { value: 'amber',        label: 'TLP:AMBER',        pill: 'pill-high' },
  { value: 'green',        label: 'TLP:GREEN',        pill: 'pill-ok'   },
  { value: 'clear',        label: 'TLP:CLEAR',        pill: 'pill-gray' },
]

export const STATUS = [
  { value: 'open',   label: 'Open',   pill: 'pill-low' },
  { value: 'closed', label: 'Closed', pill: 'pill-ok'  },
]

// Analyst's investigation-confidence assessment. Distinct from severity
// (impact) and phase (response posture).
export const TRIAGE_STATE = [
  { value: 'suspected',        label: 'Suspected',        pill: 'pill-low'  },
  { value: 'confirmed',        label: 'Confirmed',        pill: 'pill-crit' },
  { value: 'false_positive',   label: 'False Positive',   pill: 'pill-gray' },
  { value: 'benign_positive',  label: 'Benign Positive',  pill: 'pill-ok'   },
]

export const INCIDENT_TYPE = [
  { value: 'malware',                   label: 'Malware' },
  { value: 'ransomware',                label: 'Ransomware' },
  { value: 'phishing',                  label: 'Phishing / Social Engineering' },
  { value: 'data_breach',               label: 'Data Breach' },
  { value: 'unauthorized_access',       label: 'Unauthorized Access' },
  { value: 'insider_threat',            label: 'Insider Threat' },
  { value: 'ddos',                      label: 'Denial of Service' },
  { value: 'bec',                       label: 'Business Email Compromise' },
  { value: 'credential_compromise',     label: 'Credential Compromise' },
  { value: 'web_attack',                label: 'Web Application Attack' },
  { value: 'vulnerability_exploitation', label: 'Vulnerability Exploitation' },
  { value: 'supply_chain',              label: 'Supply Chain Attack' },
  { value: 'physical',                  label: 'Physical Security' },
  { value: 'other',                     label: 'Other' },
]

export const DETECTION_METHOD = [
  { value: 'siem_alert',            label: 'SIEM Alert' },
  { value: 'user_report',           label: 'User Report' },
  { value: 'threat_hunting',        label: 'Threat Hunting' },
  { value: 'external_notification', label: 'External Notification' },
  { value: 'automated_scan',        label: 'Automated Scan' },
  { value: 'pen_test',              label: 'Pen Test / Exercise' },
  { value: 'other',                 label: 'Other' },
]

export const SYSTEM_TYPE = [
  { value: 'workstation',    label: 'Workstation' },
  { value: 'server',         label: 'Server' },
  { value: 'network_device', label: 'Network Device' },
  { value: 'cloud_resource', label: 'Cloud Resource' },
  { value: 'application',    label: 'Application' },
  { value: 'database',       label: 'Database' },
  { value: 'mobile',         label: 'Mobile Device' },
  { value: 'other',          label: 'Other' },
]

// Entity types (backend EntityType). Affected systems are compromised entities (C2).
export const ENTITY_TYPE = [
  { value: 'host',          label: 'Host' },
  { value: 'user',          label: 'User' },
  { value: 'ip',            label: 'IP' },
  { value: 'domain',        label: 'Domain' },
  { value: 'email',         label: 'Email' },
  { value: 'service',       label: 'Service' },
  { value: 'network_range', label: 'Network range' },
  { value: 'group',         label: 'Group' },
  { value: 'other',         label: 'Other' },
]

// I4 intake: NIST SP 800-61 impact categories (backend FunctionalImpact / InformationImpact /
// Recoverability) and the IOC types a first indicator can have (backend IocType).
export const FUNCTIONAL_IMPACT = [
  { value: 'none',   label: 'None — no effect on services' },
  { value: 'low',    label: 'Low — minimal effect; all critical services still delivered' },
  { value: 'medium', label: 'Medium — a subset of critical services lost' },
  { value: 'high',   label: 'High — critical services can no longer be delivered' },
]

export const INFORMATION_IMPACT = [
  { value: 'none',        label: 'None — no information exfiltrated, changed or deleted' },
  { value: 'privacy',     label: 'Privacy breach — personal data accessed or exfiltrated' },
  { value: 'proprietary', label: 'Proprietary breach — confidential business data' },
  { value: 'integrity',   label: 'Integrity loss — information changed or deleted' },
]

export const RECOVERABILITY = [
  { value: 'regular',         label: 'Regular — predictable with existing resources' },
  { value: 'supplemented',    label: 'Supplemented — predictable with more resources' },
  { value: 'extended',        label: 'Extended — unpredictable; outside help needed' },
  { value: 'not_recoverable', label: 'Not recoverable — e.g. data published' },
]

export const IOC_TYPE = [
  { value: 'ip',            label: 'IP address' },
  { value: 'domain',        label: 'Domain' },
  { value: 'url',           label: 'URL' },
  { value: 'hash_md5',      label: 'Hash (MD5)' },
  { value: 'hash_sha1',     label: 'Hash (SHA1)' },
  { value: 'hash_sha256',   label: 'Hash (SHA256)' },
  { value: 'email',         label: 'Email' },
  { value: 'registry_key',  label: 'Registry key' },
  { value: 'file_path',     label: 'File path' },
  { value: 'crypto_wallet', label: 'Crypto wallet' },
  { value: 'other',         label: 'Other' },
]

function makeLookup(rows) {
  const out = {}
  for (const r of rows) out[r.value] = r
  return out
}
export const byValue = {
  severity:         makeLookup(SEVERITY),
  phase:            makeLookup(PHASE),
  tlp:              makeLookup(TLP),
  status:           makeLookup(STATUS),
  triage_state:     makeLookup(TRIAGE_STATE),
  incident_type:    makeLookup(INCIDENT_TYPE),
  detection_method: makeLookup(DETECTION_METHOD),
  system_type:      makeLookup(SYSTEM_TYPE),
  entity_type:      makeLookup(ENTITY_TYPE),
  functional_impact:  makeLookup(FUNCTIONAL_IMPACT),
  information_impact: makeLookup(INFORMATION_IMPACT),
  recoverability:     makeLookup(RECOVERABILITY),
}

export function labelOf(group, value) { return byValue[group]?.[value]?.label ?? value }
export function pillOf(group, value)  { return byValue[group]?.[value]?.pill  ?? 'pill-gray' }
