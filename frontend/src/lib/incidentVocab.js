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

export const PHASE = [
  { value: 'preparation',                      label: 'Preparation',                          short: 'Prep'   },
  { value: 'detection_and_analysis',           label: 'Detection & Analysis',                 short: 'Detect' },
  { value: 'containment_eradication_recovery', label: 'Containment, Eradication & Recovery', short: 'C/E/R'  },
  { value: 'post_incident',                    label: 'Post-Incident',                        short: 'Post'   },
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
}

export function labelOf(group, value) { return byValue[group]?.[value]?.label ?? value }
export function pillOf(group, value)  { return byValue[group]?.[value]?.pill  ?? 'pill-gray' }
