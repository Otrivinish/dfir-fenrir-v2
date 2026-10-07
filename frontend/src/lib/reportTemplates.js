import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import ReactMarkdown from 'react-markdown'
import { DETECTION_METHOD, SYSTEM_TYPE, labelOf } from './incidentVocab.js'
import { MITRE_TACTICS } from './mitre.js'
import { formatLocal } from './datetime.js'

// ─── Utilities ────────────────────────────────────────────────────────────────

function esc(s) {
  if (s == null) return ''
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

// "YYYY-MM-DD HH:MM:SS ±HH:MM" — ISO 8601, 24 h, in the operator's Fenrir
// timezone with the offset visible (same formatter as the rest of the app), so a
// report reads the same whatever the reader's browser locale is.
function fmtTs(iso) {
  if (!iso) return '—'
  return formatLocal(iso)
}

// G4 — an event whose time the exhibit's clock offset corrected: say so, with the time as recorded
// (escaped HTML text; '' when no offset was applied).
function offsetText(e) {
  if (!e.recorded_event_time || e.clock_offset_seconds == null) return ''
  const s = e.clock_offset_seconds
  const off = s === 0 ? '0 s' : `${s > 0 ? '+' : '\u2212'}${Math.abs(s)} s`
  return esc(`offset-corrected (${off}); recorded ${fmtTs(e.recorded_event_time)}`)
}

const SEV_HEX = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#22c55e' }
const TLP_HEX = { red: '#ef4444', amber: '#f59e0b', 'amber+strict': '#f97316', green: '#22c55e', clear: '#94a3b8' }
const PHASE_LABEL = {
  preparation: 'Preparation',
  detection_and_analysis: 'Detection & Analysis',
  containment_eradication_recovery: 'Containment, Eradication & Recovery',
  post_incident: 'Post-Incident Activity',   // L3 (R48): the phase value is post_incident (the raw key showed)
}

function sevHex(s)  { return SEV_HEX[s]  || '#64748b' }
function tlpHex(t)  { return TLP_HEX[t]  || '#64748b' }
function phaseLabel(p) { return PHASE_LABEL[p] || p || '—' }

function pct(done, total) { return total ? Math.round((done / total) * 100) : 0 }

// Plain-text → HTML: escape, preserve paragraphs (blank-line splits), keep
// single-line breaks as <br>. Returns '' for empty/whitespace-only input.
function narrativeToHtml(s) {
  if (!s) return ''
  const trimmed = String(s).trim()
  if (!trimmed) return ''
  return trimmed.split(/\n\s*\n/).map(p =>
    `<p class="narrative">${esc(p).replace(/\n/g, '<br>')}</p>`
  ).join('')
}

// Friendly labels — same vocabulary the incident UI shows.
const DETECTION_LABEL   = Object.fromEntries(DETECTION_METHOD.map(o => [o.value, o.label]))
const SYSTEM_TYPE_LABEL = Object.fromEntries(SYSTEM_TYPE.map(o => [o.value, o.label]))
const STAKEHOLDER_TYPE_LABEL = {
  internal: 'Internal', legal: 'Legal', regulatory: 'Regulatory',
  law_enforcement: 'Law Enforcement', media_pr: 'Media / PR', vendor: 'Vendor',
  ir_firm: 'IR Firm', customer: 'Customer', insurer: 'Insurer', board: 'Board', other: 'Other',
}

// MITRE tactic colours for the standalone report (the app's tacticColor()
// returns theme CSS variables that don't exist in the exported HTML).
const TACTIC_HEX = {
  'TA0043':'#64748b','TA0042':'#a16207',
  'TA0001':'#ef4444','TA0002':'#f97316','TA0003':'#f59e0b','TA0004':'#eab308',
  'TA0005':'#22c55e','TA0006':'#14b8a6','TA0007':'#06b6d4','TA0008':'#3b82f6',
  'TA0009':'#8b5cf6','TA0010':'#ec4899','TA0011':'#f43f5e','TA0040':'#94a3b8',
}

// Markdown → HTML for fields the UI renders as Markdown (incident
// description). Same renderer and defaults as the UI's <ReactMarkdown>: raw
// HTML is not passed through and unsafe URLs are stripped.
function markdownToHtml(s) {
  if (!s || !String(s).trim()) return ''
  return renderToStaticMarkup(createElement(ReactMarkdown, null, String(s)))
}

// ─── Report sections (single source) ─────────────────────────────────────────
// Order, title, executive-report rule and NIST CSF 2.0 subcategory IDs (`csf`,
// printed under the heading) for every numbered section. Used by
// generateProReport(), the "Show structure" preview and the Reports page's
// "Include sections" checkboxes — add or rename a section here, nowhere else.
// The section → CSF table is documented in docs/reports.md §2.
export const REPORT_SECTIONS = [
  { key: 'exec_summary',  title: 'Executive Summary',                   csf: ['RS.CO-03', 'RS.AN-03'] },
  { key: 'details',       title: 'Incident Details',                    csf: ['DE.AE-08', 'RS.MA-02', 'RS.MA-03'] },
  { key: 'assignments',   title: 'Assignments',                         csf: ['GV.RR-02'] },
  { key: 'stakeholders',  title: 'Stakeholders',                        csf: ['RS.CO-02', 'RS.CO-03'] },
  { key: 'detection',     title: 'Detection & Identification', fullOnly: true, csf: ['DE.AE-02', 'DE.AE-03', 'DE.AE-07'] },
  { key: 'cer',           title: 'Containment, Eradication & Recovery', fullOnly: true, csf: ['RS.MI-01', 'RS.MI-02', 'RC.RP-02'] },
  { key: 'recovery',      title: 'Recovery Validation', fullOnly: true,  csf: ['RC.RP-02', 'RC.RP-03', 'RC.RP-05'] },
  { key: 'decisions',     title: 'Decisions Log',                       csf: ['RS.AN-06', 'RS.MA-04'] },
  { key: 'impact',        title: 'Impact Assessment',                   csf: ['RS.AN-08', 'DE.AE-04'] },
  { key: 'legal',         title: 'Legal & Regulatory Deadlines',        csf: ['GV.OC-03', 'RS.CO-02'] },
  { key: 'comms_log',     title: 'Communications & Notification Log', fullOnly: true, csf: ['RS.CO-02', 'RS.CO-03'] },
  { key: 'root_cause',    title: 'Root Cause Analysis',                 csf: ['RS.AN-03'] },
  { key: 'attack_chain',  title: 'Attack Chain',                        csf: ['RS.AN-03', 'DE.AE-02'] },
  { key: 'attribution',   title: 'Threat Actor Attribution',            csf: ['ID.RA-03', 'DE.AE-07'] },
  { key: 'entities',      title: 'Entities & Attack Path',              csf: ['RS.AN-08', 'ID.AM-05'] },
  { key: 'evidence',      title: 'Evidence & Artifacts', fullOnly: true, csf: ['RS.AN-07'] },
  { key: 'attachments',   title: 'Figures',                             csf: ['RS.AN-06'] },
  { key: 'playbook',      title: 'Playbook', fullOnly: true,            csf: ['RS.MA-01'] },
  { key: 'closure',       title: 'Closure Checklist Completion',        csf: ['RC.RP-06'] },
  { key: 'lessons',       title: 'Lessons Learned & Recommendations',   csf: ['ID.IM-03', 'ID.IM-04'] },
  { key: 'remediation',   title: 'Remediation Plan',                    csf: ['ID.IM-03', 'ID.RA-06'] },
  { key: 'costs',         title: 'Cost Tracking',                       csf: ['RS.AN-08', 'RC.RP-06'] },
  { key: 'sign_off',      title: 'Approval & Sign-off',                 csf: ['RC.RP-06', 'GV.RR-02'] },
]
const SECTION_BY_KEY = Object.fromEntries(REPORT_SECTIONS.map(s => [s.key, s]))
// Appendices carry CSF IDs too (keyed by appendix title; same list for report and structure).
const APPENDIX_CSF = {
  'Affected Systems':  ['RS.AN-08', 'ID.AM-05'],
  'Incident Timeline': ['RS.AN-03', 'RS.AN-06'],
  'Case Notes':        ['RS.AN-06', 'RS.AN-07'],
}
// NCISS severity label (the server maps internal severity → NCISS: incident.nciss_severity).
// It is a fixed mapping, not an NCISS scoring, so every place it is shown says so.
function ncissLabel(v) { return v ? v.charAt(0).toUpperCase() + v.slice(1) : '—' }
const NCISS_TITLE = 'NCISS (mapped from internal severity)'
function csfLine(ids) {
  return ids && ids.length
    ? `<div class="csf-line">NIST CSF 2.0: ${ids.map(id => `<span class="csf-id">${esc(id)}</span>`).join(' ')}</div>`
    : ''
}
// Checkbox list for the Reports page: the cover stats strip + every section.
export const REPORT_SECTION_OPTIONS = [
  { key: 'kpis', title: 'Key metrics strip (cover)' },
  ...REPORT_SECTIONS,
]

// Sentinel string that lives in the footer until `injectReportSha256()` is
// awaited. Verifiers reverse the substitution to recompute and check.
export const REPORT_SHA256_PLACEHOLDER = '___FENRIR_REPORT_SHA256_PLACEHOLDER___'

// Self-describing footer hash. The placeholder lives in the rendered HTML;
// we hash the full document *while the placeholder is still in place*, then
// substitute the hash back. Verifier: extract the hash from the footer,
// replace it with the placeholder, recompute, compare. Async because Web
// Crypto's SHA-256 returns a Promise.
export async function injectReportSha256(html) {
  if (!html.includes(REPORT_SHA256_PLACEHOLDER)) return html
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(html))
  const hex = Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0')).join('')
  return html.replace(REPORT_SHA256_PLACEHOLDER, hex)
}

export async function verifyReportSha256(html) {
  const m = html.match(/<span class="report-sha256">([0-9a-f]{64})<\/span>/)
  if (!m) return { ok: false, reason: 'no SHA-256 marker found' }
  const claimed = m[1]
  const restored = html.replace(claimed, REPORT_SHA256_PLACEHOLDER)
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(restored))
  const hex = Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0')).join('')
  return { ok: hex === claimed, claimed, computed: hex }
}

// ─── Pro themes ───────────────────────────────────────────────────────────────
// Ported directly from v1's report_themes.py. All four themes share one
// structure (renderProReport below); only CSS variables differ. Severity and
// TLP colours override --red and --tlp at render time.

const PRO_THEMES = {
  // Original FENRIR dark/red look.
  tactical: {
    fonts: "@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');",
    vars: {
      'bg':           '#070710',
      'bg-card':      '#0e0e1a',
      'bg-section':   '#0b0b16',
      'border':       '#1e1e30',
      'border-light': '#16162a',
      'text':         '#e2e2f0',
      'text-muted':   '#8888aa',
      'text-dim':     '#555570',
      'text-strong':  '#ffffff',
      'th-bg':        '#0a0a18',
      'th-color':     '#8888aa',
      'tr-hover':     '#0f0f1e',
      'enrich-bg':    '#1e2a1e',
      'enrich-fg':    '#4ade80',
      'task-done':    '#4ade80',
      'green':        '#16a34a',
      'amber':        '#d97706',
      'blue':         '#2563eb',
      'font':         "'Inter', sans-serif",
      'mono':         "'JetBrains Mono', monospace",
    },
    cover_gradient: 'linear-gradient(135deg, #07070f 0%, #140008 50%, #070710 100%)',
    prose_color:    '#c8c8e0',
  },
  // Light, formal, neutral navy (matches the user's example HTML).
  executive: {
    fonts: "@import url('https://fonts.googleapis.com/css2?family=Source+Serif+Pro:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap');",
    vars: {
      'bg':           '#ffffff',
      'bg-card':      '#f8fafc',
      'bg-section':   '#f1f5f9',
      'border':       '#cbd5e1',
      'border-light': '#e2e8f0',
      'text':         '#0f172a',
      'text-muted':   '#475569',
      'text-dim':     '#64748b',
      'text-strong':  '#0f172a',
      'th-bg':        '#1e293b',
      'th-color':     '#ffffff',
      'tr-hover':     '#f1f5f9',
      'enrich-bg':    '#dcfce7',
      'enrich-fg':    '#15803d',
      'task-done':    '#15803d',
      'green':        '#15803d',
      'amber':        '#b45309',
      'blue':         '#1e40af',
      'font':         "'Source Serif Pro', Georgia, serif",
      'mono':         "'Inter', sans-serif",
    },
    cover_gradient: 'linear-gradient(135deg, #f8fafc 0%, #e0e7ff 50%, #f1f5f9 100%)',
    prose_color:    '#1e293b',
  },
  // High-contrast B/W, optimised for paper.
  print: {
    fonts: "@import url('https://fonts.googleapis.com/css2?family=Source+Serif+Pro:wght@400;600;700&family=Source+Code+Pro:wght@400;600&display=swap');",
    vars: {
      'bg':           '#ffffff',
      'bg-card':      '#ffffff',
      'bg-section':   '#fafafa',
      'border':       '#000000',
      'border-light': '#666666',
      'text':         '#000000',
      'text-muted':   '#333333',
      'text-dim':     '#555555',
      'text-strong':  '#000000',
      'th-bg':        '#000000',
      'th-color':     '#ffffff',
      'tr-hover':     '#f5f5f5',
      'enrich-bg':    '#eeeeee',
      'enrich-fg':    '#000000',
      'task-done':    '#000000',
      'green':        '#000000',
      'amber':        '#000000',
      'blue':         '#000000',
      'font':         "'Source Serif Pro', Georgia, serif",
      'mono':         "'Source Code Pro', monospace",
    },
    cover_gradient: '#ffffff',
    prose_color:    '#000000',
  },
  // Court-ready blue/grey.
  forensic: {
    fonts: "@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&family=Roboto+Mono:wght@400;500&display=swap');",
    vars: {
      'bg':           '#fafbfc',
      'bg-card':      '#ffffff',
      'bg-section':   '#f0f4f8',
      'border':       '#94a3b8',
      'border-light': '#cbd5e1',
      'text':         '#1e293b',
      'text-muted':   '#475569',
      'text-dim':     '#64748b',
      'text-strong':  '#0c4a6e',
      'th-bg':        '#e0f2fe',
      'th-color':     '#0c4a6e',
      'tr-hover':     '#f0f9ff',
      'enrich-bg':    '#dbeafe',
      'enrich-fg':    '#1e40af',
      'task-done':    '#0369a1',
      'green':        '#15803d',
      'amber':        '#b45309',
      'blue':         '#0c4a6e',
      'font':         "'Roboto', Arial, sans-serif",
      'mono':         "'Roboto Mono', monospace",
    },
    cover_gradient: 'linear-gradient(135deg, #f0f4f8 0%, #dbeafe 50%, #f0f9ff 100%)',
    prose_color:    '#1e293b',
  },
}

function _renderProCssVars(theme, sevColor, tlpColor) {
  const lines = Object.entries(theme.vars).map(([k, v]) => `  --${k}: ${v};`)
  lines.push(`  --red: ${sevColor};`)
  lines.push(`  --tlp: ${tlpColor};`)
  return `:root {\n${lines.join('\n')}\n}`
}

const TLP_MESSAGES = {
  RED:    'This information may not be shared outside your organization',
  AMBER:  'Limited disclosure — recipients only',
  GREEN:  'Community sharing permitted',
  WHITE:  'Unlimited public disclosure',
  CLEAR:  'Unlimited public disclosure',
}

// ─── Pro report: 11-chapter v1-style template ────────────────────────────────

function _proIocRows(iocs) {
  return iocs.map(i => {
    const statusHtml =
      i.malicious === true  ? '<span class="status-bad">⚠ Malicious</span>' :
      i.malicious === false ? '<span class="status-ok">✓ Clean</span>' :
                              '<span class="status-unk">? Unknown</span>'
    const enrichBits = []
    if (i.ti_matched)  enrichBits.push(`<span class="enrich-badge">TI: ${esc(i.ti_match_source || 'matched')}</span>`)
    if (i.lolbin_hit)  enrichBits.push(`<span class="enrich-badge" style="background:#fef3c7;color:#92400e">LOL: ${esc(i.lolbin_name || '')}</span>`)
    if (i.source)      enrichBits.push(`<span class="tiny" style="color:var(--text-dim)">src: ${esc(i.source)}</span>`)
    const enrich = enrichBits.length ? enrichBits.join(' ') : '—'
    const tags = (i.tags && i.tags.length)
      ? i.tags.slice(0, 3).map(t => `<span class="tag">${esc(t)}</span>`).join(' ')
      : '—'
    return `<tr>
      <td><span class="tag">${esc(i.type.replace(/_/g, ' '))}</span></td>
      <td class="mono small">${esc(i.value)}</td>
      <td>${statusHtml}</td>
      <td>${i.confidence ?? 50}%</td>
      <td>${enrich}</td>
      <td class="small">${tags}</td>
    </tr>`
  }).join('')
}

// Fixed column widths so Status / Notes line up vertically across the
// Containment, Eradication and Recovery tables regardless of text length.
const CER_COLS = '<colgroup><col style="width:19%"><col style="width:22%"><col style="width:10%"><col style="width:15%"><col style="width:22%"><col style="width:12%"></colgroup>'

function _proCERSubsection(actions, category, title) {
  const subset = (actions || []).filter(a => (a.category || '').toLowerCase() === category)
  if (!subset.length) {
    return `<h3>${title}</h3><div class="placeholder-box"><strong>[ NO ${title.toUpperCase()} ACTIONS RECORDED ]</strong></div>`
  }
  const rows = subset.map(a => `<tr>
    <td>${esc(a.title || '')}</td>
    <td class="small">${esc(a.description || '—')}</td>
    <td>${esc((a.status || '').replace(/_/g, ' '))}</td>
    <td class="mono small">${a.occurred_at ? esc(fmtTs(a.occurred_at)) : '—'}</td>
    <td class="small">${esc(a.notes || '—')}</td>
    <td class="mono small">${esc(a.performed_by || '—')}</td>
  </tr>`).join('')
  return `<h3>${title}</h3>
    <div class="table-wrap"><table class="table-fixed">${CER_COLS}
      <thead><tr><th>Action</th><th>Description</th><th>Status</th><th>Occurred At</th><th>Notes</th><th>By</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`
}

// I2: the stakeholder notification tracker (stakeholder_notifications from the API): roll-up, then one
// row per obligation from the stakeholder matrix, superseded ones flagged. Never contact details.
const SN_STATUS = { pending: 'Pending', notified: 'Notified', not_required: 'Not required' }
const SN_CHANNEL = { phone: 'Phone', email: 'Email', in_person: 'In person', oob: 'Out-of-band', other: 'Other' }
function _proNotificationsSection(sn) {
  const items = (sn && sn.items) || []
  const s = (sn && sn.summary) || {}
  if (!items.length) return ''
  const rows = items.map(x => {
    const late = x.status === 'notified' && x.notified_at && new Date(x.notified_at) > new Date(x.due_at)
    return `<tr>
    <td style="font-weight:600">${esc(x.role)}<div class="small">${esc(x.category)}${x.required ? '' : ' · advisory'}${x.superseded ? ` · superseded (${esc((x.superseded_reason || '').replace(/_/g, ' '))})` : ''}</div></td>
    <td style="text-transform:capitalize">${esc(x.severity)}</td>
    <td class="mono small">${esc(fmtTs(x.clock_start_at))}</td>
    <td class="mono small">${esc(fmtTs(x.due_at))}</td>
    <td>${esc(SN_STATUS[x.status] || x.status)}${x.overdue ? ' <strong>(overdue)</strong>' : ''}${late ? ' <strong>(late)</strong>' : ''}${x.not_required_reason ? `<div class="small">${esc(x.not_required_reason)}</div>` : ''}</td>
    <td class="mono small">${x.notified_at ? `${esc(fmtTs(x.notified_at))}<div class="small">${esc(SN_CHANNEL[x.channel] || x.channel || '')}${x.notified_by_username ? ` · ${esc(x.notified_by_username)}` : ''}${x.stakeholder_name ? ` · to ${esc(x.stakeholder_name)}` : ''}</div>` : '—'}</td>
  </tr>`
  }).join('')
  return `<h3 style="margin:0 0 8px">Stakeholder notifications (stakeholder matrix)</h3>
    <p>${s.notified || 0} of ${s.required_total || 0} required notification(s) recorded${s.overdue ? `, ${s.overdue} overdue` : ''}${s.not_required ? `, ${s.not_required} recorded as not required` : ''}. Each countdown starts when the incident first reached the rule's severity.</p>
    <div class="table-wrap"><table>
      <thead><tr><th>Stakeholder</th><th>Severity</th><th>Clock start</th><th>Due</th><th>Status</th><th>Notified</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`
}

// I1: one row per in-scope system (recovery.items from the API), with the roll-up above it.
const RECOVERY_STATE = { not_started: 'Not started', restoring: 'Restoring', restored: 'Restored', validated: 'Validated', not_required: 'Not required' }
function _proRecoverySection(rec) {
  const items = (rec && rec.items) || []
  const s = (rec && rec.summary) || {}
  if (!items.length) {
    return '<div class="placeholder-box"><strong>[ NO COMPROMISED SYSTEMS IN SCOPE ]</strong></div>'
  }
  const who = (at, by) => at ? `${esc(fmtTs(at))}${by ? `<div class="small">${esc(by)}</div>` : ''}` : '—'
  const rows = items.map(x => `<tr>
    <td class="mono">${esc(x.entity_value)}<div class="small">${esc((x.entity_type || '').replace(/_/g, ' '))}</div></td>
    <td>${esc(RECOVERY_STATE[x.state] || x.state)}${x.not_required_reason ? `<div class="small">${esc(x.not_required_reason)}</div>` : ''}</td>
    <td class="small">${esc(x.restore_point_ref || '—')}${x.restore_point_at ? `<div class="mono small">${esc(fmtTs(x.restore_point_at))}</div>` : ''}</td>
    <td class="mono small">${who(x.restored_at, x.restored_by_username)}</td>
    <td class="mono small">${who(x.validated_at, x.validated_by_username)}${x.same_person_validation ? '<div class="small"><strong>Same person restored and validated</strong></div>' : ''}</td>
    <td class="small">${esc(x.validation_method || '—')}${(x.validation_checklist || []).length ? `<div class="small">${x.validation_checklist.filter(c => c.done).length}/${x.validation_checklist.length} checks done</div>` : ''}</td>
    <td class="mono small">${x.monitoring_start || x.monitoring_end ? `${x.monitoring_start ? esc(fmtTs(x.monitoring_start)) : '—'} → ${x.monitoring_end ? esc(fmtTs(x.monitoring_end)) : 'open'}` : '—'}</td>
  </tr>`).join('')
  return `<p>${s.validated || 0} of ${(s.total || 0) - (s.not_required || 0)} system(s) validated clean${s.not_required ? `, ${s.not_required} not requiring restore` : ''}${s.complete ? ' — recovery of every system in scope is validated.' : ` — ${(s.not_started || 0) + (s.restoring || 0) + (s.restored || 0)} still open.`}${s.same_person_validations ? ` ${s.same_person_validations} validation(s) by the person who restored the system.` : ''}</p>
    <div class="table-wrap"><table>
      <thead><tr><th>System</th><th>State</th><th>Restore point</th><th>Restored</th><th>Validated</th><th>Method</th><th>Monitoring window</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`
}

function _proRemBucket(items, color) {
  const rows = items.map(ai =>
    `<tr><td>${esc(ai.action || '')}</td><td>${esc(ai.owner || '—')}</td><td class="mono small">${esc(ai.due_date || '—')}</td><td style="text-transform:capitalize">${esc(ai.priority || '')}</td><td>${esc((ai.status || '').replace(/_/g, ' '))}</td></tr>`
  ).join('')
  return `<div class="table-wrap" style="border-left:3px solid ${color}">
      <table>
        <thead><tr><th>Action</th><th>Owner</th><th>Due</th><th>Priority</th><th>Status</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`
}

// Per-bucket renderer: the Reports-tab narrative first, then the structured
// Lessons Learned action items for the same term. Placeholder only when both
// are empty.
function _proRemSection(narrative, items, label, color) {
  const narrativeHtml = narrativeToHtml(narrative)
  if (!narrativeHtml && !items.length) {
    return `<h3>${esc(label)}</h3><div class="placeholder-box"><strong>[ NO ${esc(label.toUpperCase())} ITEMS ]</strong></div>`
  }
  return `<h3>${esc(label)}</h3>`
    + (narrativeHtml ? `<div style="border-left:3px solid ${color};padding:6px 12px;margin-bottom:8px">${narrativeHtml}</div>` : '')
    + (items.length ? _proRemBucket(items, color) : '')
}

// Lessons Learned sub-heading: the Reports-tab narrative first, then the
// structured Lessons Learned entries. Placeholder only when both are empty.
function _proNarrativeAndList(narrative, structuredHtml) {
  const narrativeHtml = narrativeToHtml(narrative)
  if (!narrativeHtml && !structuredHtml) return '<div class="placeholder-box"><strong>[ PLACEHOLDER ]</strong></div>'
  return narrativeHtml + structuredHtml
}

function _fmtLate(hours) {
  return hours >= 48 ? `${Math.round(hours / 24)}d` : `${Math.round(hours)}h`
}

function _fmtSize(n) {
  if (n == null) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`
  return `${(n / (1024 * 1024)).toFixed(2)} MiB`
}

// Regulatory-deadline compliance badge. `compliance` is computed server-side
// (met | violated | pending | waived).
function _proComplianceHtml(d) {
  if (d.compliance === 'met')     return '<span class="status-ok">✓ Met</span>'
  if (d.compliance === 'waived')  return '<span class="status-unk">Waived</span>'
  if (d.compliance === 'pending') return '<span style="color:var(--amber);font-weight:600">Pending</span>'
  const how = d.status === 'completed'
    ? `completed ${_fmtLate(d.hours_late || 0)} late`
    : `overdue by ${_fmtLate(d.hours_late || 0)}`
  return `<span class="status-bad">✗ Violated</span><div class="tiny" style="color:var(--text-dim)">${esc(how)}</div>`
}

// Visual attack chain: one swimlane per observed MITRE tactic (ATT&CK
// kill-chain order), each tagged timeline event plotted by time. Returns ''
// when no event carries a tactic — the section is then omitted.
function _proAttackChain(evs) {
  const tagged = (evs || [])
    .filter(e => e.mitre_tactic_id)
    .sort((a, b) => new Date(a.event_time) - new Date(b.event_time))
  if (!tagged.length) return ''

  const order = MITRE_TACTICS.map(t => t.id)
  const rank  = (id) => { const i = order.indexOf(id); return i < 0 ? order.length : i }
  const laneIds = [...new Set(tagged.map(e => e.mitre_tactic_id))].sort((a, b) => rank(a) - rank(b))
  const nameOf = (id) => MITRE_TACTICS.find(t => t.id === id)?.name
    || tagged.find(e => e.mitre_tactic_id === id)?.mitre_tactic_name || id

  const times = tagged.map(e => new Date(e.event_time).getTime())
  const t0    = Math.min(...times)
  const span  = Math.max(1, Math.max(...times) - t0)
  const xPct  = (e) => 3 + ((new Date(e.event_time).getTime() - t0) / span) * 94

  const lanes = laneIds.map(id => {
    const color = TACTIC_HEX[id] || '#6b7280'
    const inLane = tagged.filter(e => e.mitre_tactic_id === id)
    const techs = {}
    for (const e of inLane) {
      if (e.mitre_technique_id) techs[e.mitre_technique_id] = (techs[e.mitre_technique_id] || 0) + 1
    }
    const chips = Object.entries(techs).map(([t, n]) =>
      `<span class="ac-chip" style="border-color:${color}66;color:${color}">${esc(t)}${n > 1 ? ` ×${n}` : ''}</span>`
    ).join('')
    const dots = inLane.map(e =>
      `<span class="ac-dot" style="left:${xPct(e).toFixed(2)}%;background:${color}" title="${esc(fmtTs(e.event_time))} — ${esc([e.mitre_technique_id, e.description].filter(Boolean).join(' '))}"></span>`
    ).join('')
    return `<div class="ac-lane">
      <div class="ac-label">
        <div class="ac-name" style="color:${color}">${esc(nameOf(id))}</div>
        <div class="ac-meta">${esc(id)} · ${inLane.length} event${inLane.length !== 1 ? 's' : ''}</div>
        <div>${chips}</div>
      </div>
      <div class="ac-track"><span class="ac-line"></span>${dots}</div>
    </div>`
  }).join('')

  return `<p class="small" style="color:var(--text-muted);margin-bottom:12px">${tagged.length} MITRE-tagged event${tagged.length !== 1 ? 's' : ''} across ${laneIds.length} tactic${laneIds.length !== 1 ? 's' : ''}, in ATT&amp;CK kill-chain order. Each dot is one timeline event, placed by time (left = earliest).</p>
  <div class="ac-wrap">${lanes}
    <div class="ac-axis"><span>${esc(fmtTs(tagged[0].event_time))}</span><span>${esc(fmtTs(tagged[tagged.length - 1].event_time))}</span></div>
  </div>`
}

// ── Appendix timeline renderer ────────────────────────────────────────────────
// Inline zig-zag spine matching the standalone Timeline HTML export format.
// Scoped under .atl-* CSS classes added to the pro report stylesheet.
function _proTimelineAppendix(evs) {
  if (!evs || !evs.length) return '<div class="placeholder-box"><strong>[ NO TIMELINE EVENTS ]</strong></div>'
  const rows = []
  let prevDate = null
  evs.forEach((ev, i) => {
    const local = formatLocal(ev.event_time)          // Fenrir timezone, not the browser's
    const dateLabel = local.slice(0, 10)
    const timeLabel = local.slice(11)                  // HH:MM:SS ±HH:MM
    if (dateLabel !== prevDate) {
      rows.push(`<div class="atl-date"><span>${esc(dateLabel)}</span></div>`)
      prevDate = dateLabel
    }
    const side  = i % 2 === 0 ? 'left' : 'right'
    const color = TACTIC_HEX[ev.mitre_tactic_id] || '#6b7280'
    const mitreLabel = [ev.mitre_technique_id, ev.mitre_technique_name].filter(Boolean).join(' ') || ev.mitre_tactic_name || ''
    rows.push(`
      <div class="atl-item ${side}">
        <div class="atl-dot" style="background:${color};box-shadow:0 0 6px ${color}55"></div>
        <div class="atl-card" style="border-left:3px solid ${color}">
          <div class="atl-header">
            <span class="atl-time">${esc(timeLabel)}</span>
            ${ev.event_type ? `<span class="atl-pill" style="background:${color}22;color:${color};border-color:${color}55">${esc(ev.event_type)}</span>` : ''}
            ${ev.hostname   ? `<span class="atl-host">${esc(ev.hostname)}</span>` : ''}
          </div>
          <div class="atl-desc">${esc(ev.description || '')}</div>
          ${offsetText(ev) ? `<div class="atl-meta">${offsetText(ev)}</div>` : ''}
          ${mitreLabel ? `<div class="atl-mitre" style="color:${color};border-color:${color}55;background:${color}1a">${esc(mitreLabel)}</div>` : ''}
          ${ev.source  ? `<div class="atl-meta">source: ${esc(ev.source)}</div>` : ''}
        </div>
      </div>`)
  })
  return `<div class="atl-wrap"><div class="atl-spine">${rows.join('\n')}</div></div>`
}

// H2 — case notes as written (plain text, never re-rendered as markdown): a corrected entry is struck
// through and names its correction; each row carries the entry's SHA-256 (also in the audit log).
function _proCaseNotesAppendix(notes) {
  if (!notes.length) return '<div class="placeholder-box"><strong>[ NO CASE NOTES ]</strong></div>'
  const pos = Object.fromEntries(notes.map((n, i) => [n.id, i + 1]))
  const linkText = l => [['evidence', 'exhibit'], ['entities', 'entity'], ['iocs', 'IOC'], ['timeline_events', 'event']]
    .filter(([k]) => l && l[k]).map(([k, w]) => `${l[k]} ${w}${l[k] !== 1 ? 's' : ''}`).join(', ') || '—'
  return `<p class="small" style="color:var(--text-muted);margin-bottom:16px">${notes.length} entr${notes.length !== 1 ? 'ies' : 'y'} · chronological · append-only: entries are never edited; a correction is a new entry.</p>
  <div class="table-wrap"><table class="table-fixed">
    <colgroup><col style="width:5%"><col style="width:17%"><col style="width:12%"><col style="width:40%"><col style="width:10%"><col style="width:16%"></colgroup>
    <thead><tr><th>#</th><th>Time</th><th>Author</th><th>Note</th><th>Links</th><th>SHA-256</th></tr></thead>
    <tbody>${notes.map((n, i) => `<tr>
      <td class="mono small">${i + 1}</td>
      <td class="mono small">${esc(fmtTs(n.created_at))}</td>
      <td class="small">${esc(n.author_username || '—')}</td>
      <td><div style="white-space:pre-wrap;${n.corrected_by_id ? 'text-decoration:line-through;opacity:.7' : ''}">${esc(n.body)}</div>
        ${n.corrects_id ? `<div class="tiny" style="color:var(--text-muted)">Correction of entry #${pos[n.corrects_id] || '?'}</div>` : ''}
        ${n.corrected_by_id ? `<div class="tiny" style="color:var(--text-muted)">Corrected by entry #${pos[n.corrected_by_id] || '?'}</div>` : ''}</td>
      <td class="small">${esc(linkText(n.links))}</td>
      <td class="mono tiny" style="word-break:break-all">${esc(n.content_sha256 || '')}</td>
    </tr>`).join('')}</tbody>
  </table></div>`
}

// Main pro renderer. Emits the full HTML with v1's structure + v2's data.
function generateProReport(data, opts = {}) {
  const {
    templateId = 'executive',
    mode = 'full',
    logo = null,
    footer = '',
    classification = '',
    audience = '',
    includeTimelineAppendix = false,
    sections: sectionToggles = {},
    figures: preparedFigures = null,
  } = opts
  // Every section is included unless its "Include sections" checkbox is off.
  const include = (key) => sectionToggles[key] !== false

  const inc = (data && data.incident) || {}
  const theme = PRO_THEMES[templateId] || PRO_THEMES.executive
  const sev = (inc.severity || 'medium').toLowerCase()
  const tlp = (inc.tlp || 'amber').toLowerCase()
  const sevColor = sevHex(sev)
  const tlpColor = tlpHex(tlp)
  const cssVars  = _renderProCssVars(theme, sevColor, tlpColor)
  const generated = fmtTs(data.generated_at || new Date().toISOString())
  const isExec = mode === 'executive'

  const iocs        = data.iocs    || []
  const ents        = data.entities || []
  const evs         = data.timeline_events || []
  const acts        = data.respond_actions  || []
  const tasks       = data.playbook_tasks   || []
  const decs        = data.decisions        || []
  const ll          = data.lessons_learned
  const ev          = data.evidence_summary || {}
  const bia         = data.business_impact
  const costs       = data.costs   || []
  const cl          = data.closure_checklist || []
  const assignments = data.assignments || []
  const deadlines   = data.regulatory_deadlines || []
  const stakeholders = data.stakeholders || []
  const attributions = data.attributions || []
  const affected    = data.affected_systems || []
  const oobLog      = data.oob_log || []
  const closure     = data.closure || {}
  const signOffs    = data.sign_offs || []
  const gateSignOffs = data.gate_sign_offs || []
  const caseNotes   = data.case_notes || []
  // Figures: images prepared by the Reports page (fetched, hashed, embedded); without
  // them (e.g. a caller that only has the data) every figure is listed, not embedded.
  const figures = preparedFigures
    || (data.report_files || []).map((f, i) => ({ ...f, n: i + 1, src: null, note: 'Image not embedded.' }))
  const nciss = ncissLabel(inc.nciss_severity)
  const malicIocs = iocs.filter(i => i.malicious === true).length
  const taskDone  = tasks.filter(t => t.status === 'done').length
  const taskPct   = pct(taskDone, tasks.length)

  // IOC type summary badges
  const iocTypes = {}
  for (const i of iocs) iocTypes[i.type] = (iocTypes[i.type] || 0) + 1
  const iocTypeBadges = Object.entries(iocTypes)
    .map(([t, n]) => `<span class="ioc-type-badge">${esc(t.replace(/_/g, ' '))}: <strong>${n}</strong></span>`)
    .join('')

  // Root cause — MITRE attack chain rows (events tagged with techniques)
  const mitreRows = evs.filter(e => e.mitre_technique_id).map(e => `<tr>
    <td class="mono small">${esc(fmtTs(e.event_time))}</td>
    <td class="mono small">${esc(e.mitre_technique_id)}: ${esc(e.mitre_technique_name || '')}</td>
    <td>${esc(e.description || '')}</td>
  </tr>`).join('')

  // Entities rows
  const entityRows = ents.map(e => `<tr>
    <td><span class="tag">${esc(e.type || '')}</span></td>
    <td class="mono">${esc(e.name || e.value || '')}</td>
    <td><span style="color:${sevHex(e.criticality)};text-transform:capitalize">${esc(e.criticality || '')}</span></td>
    <td>${e.compromised ? '<span class="status-bad">COMPROMISED</span>' : '<span class="status-ok">Not compromised</span>'}</td>
    <td class="small">${esc(e.description || '—')}</td>
  </tr>`).join('')

  // Closure checklist items
  const closureItems = cl.length
    ? `<div class="progress-outer"><div class="progress-inner" style="width:${pct(cl.filter(c => c.checked).length, cl.length)}%"></div></div>
       <div class="progress-label">${cl.filter(c => c.checked).length} / ${cl.length} closure items complete</div>
       <ul style="margin-top:12px;padding-left:0;list-style:none">${cl.map(c => `<li class="task-row ${c.checked ? 'task-done' : 'task-pending'}"><span class="task-icon">${c.checked ? '✓' : '○'}</span><span class="task-title">${esc(c.label)}</span>${c.assigned_to ? `<span class="task-time">${esc(c.assigned_to)}</span>` : ''}</li>`).join('')}</ul>`
    : ''

  // Assignments table
  const assignmentsHtml = assignments.length
    ? `<div class="table-wrap"><table>
        <thead><tr><th>Role</th><th>Analyst</th><th>Assigned by</th><th>Assigned at</th><th>Notes</th></tr></thead>
        <tbody>${assignments.map(a => `<tr>
          <td style="font-weight:600">${esc(a.role_label)}</td>
          <td class="mono">${esc(a.username)}</td>
          <td class="mono small">${esc(a.assigned_by_username || '—')}</td>
          <td class="mono small">${esc(fmtTs(a.assigned_at))}</td>
          <td class="small">${esc(a.notes || '—')}</td>
        </tr>`).join('')}</tbody>
      </table></div>`
    : '<div class="placeholder-box"><strong>[ NO ASSIGNMENTS RECORDED ]</strong></div>'

  // Stakeholders table — identity + role only (the API omits contact details)
  const stakeholdersHtml = stakeholders.length
    ? `<div class="table-wrap"><table>
        <thead><tr><th>Name</th><th>Title</th><th>Organization</th><th>Type</th></tr></thead>
        <tbody>${stakeholders.map(s => `<tr>
          <td style="font-weight:600">${esc(s.name)}</td>
          <td>${esc(s.title || '—')}</td>
          <td>${esc(s.organization || '—')}</td>
          <td><span class="tag">${esc(STAKEHOLDER_TYPE_LABEL[s.type] || s.type || '—')}</span></td>
        </tr>`).join('')}</tbody>
      </table></div>`
    : '<div class="placeholder-box"><strong>[ NO STAKEHOLDERS RECORDED ]</strong></div>'

  // Decisions log
  const decisionsHtml = decs.length
    ? `<div class="table-wrap"><table>
        <thead><tr><th>Decision</th><th>Outcome</th><th>Rationale</th><th>Decided By</th><th>Decided At</th></tr></thead>
        <tbody>${decs.map(d => `<tr>
          <td>${esc(d.summary || '')}</td>
          <td style="text-transform:capitalize">${esc(d.outcome || '')}</td>
          <td class="small">${esc(d.rationale || '—')}</td>
          <td class="mono small">${esc(d.decided_by_username || '—')}</td>
          <td class="mono small">${d.decided_at ? esc(fmtTs(d.decided_at)) : '—'}</td>
        </tr>`).join('')}</tbody>
      </table></div>`
    : '<div class="placeholder-box"><strong>[ NO DECISIONS RECORDED ]</strong></div>'

  // Legal & regulatory deadlines (from Legal → Initialize / custom deadlines)
  const deadlinesHtml = deadlines.length
    ? `<div class="table-wrap"><table>
        <thead><tr><th>Regulation</th><th>Obligation</th><th>Recipient</th><th>Deadline</th><th>Status</th><th>Completed</th><th>Compliance</th></tr></thead>
        <tbody>${deadlines.map(d => `<tr>
          <td style="font-weight:600;white-space:nowrap">${esc((d.regulation || '').replace(/_/g, ' '))}${d.article ? `<div class="tiny" style="color:var(--text-dim);font-weight:400">${esc(d.article)}</div>` : ''}${d.is_mandatory ? '' : '<div class="tiny" style="color:var(--text-dim);font-weight:400">optional</div>'}</td>
          <td class="small">${esc(d.obligation || '')}</td>
          <td class="small">${esc(d.recipient || '—')}</td>
          <td class="mono small">${esc(fmtTs(d.deadline_at))}</td>
          <td style="text-transform:capitalize">${esc((d.status || '').replace(/_/g, ' '))}</td>
          <td class="mono small">${d.completed_at ? esc(fmtTs(d.completed_at)) : '—'}</td>
          <td>${_proComplianceHtml(d)}</td>
        </tr>`).join('')}</tbody>
      </table></div>`
    : '<div class="placeholder-box"><strong>[ NO REGULATORY DEADLINES INITIALIZED ]</strong></div>'

  // Impact → Legal Obligations: empty unless legal deadlines have been
  // initialized for this incident (Post-Incident → Legal).
  const legalObligations = [...new Set(deadlines.map(d =>
    [(d.regulation || '').replace(/_/g, ' '), d.article].filter(Boolean).join(' ')
  ))].join(' · ')
  const legalCard = !deadlines.length
    ? '—'
    : (bia && bia.legal
        ? `${esc(bia.legal)}<div class="small" style="margin-top:6px;color:var(--text-muted);font-weight:400">${esc(legalObligations)}</div>`
        : esc(legalObligations))

  // Threat actor attribution
  const CONF_HEX = { confirmed: '#dc2626', probable: '#d97706', possible: '#2563eb' }
  const attributionHtml = attributions.length
    ? `<div class="table-wrap"><table>
        <thead><tr><th>Threat Actor</th><th>Confidence</th><th>Score</th><th>Motivation</th><th>Supporting Evidence</th><th>Analyst Notes</th><th>Attributed</th></tr></thead>
        <tbody>${attributions.map(a => `<tr>
          <td style="font-weight:600">${esc(a.actor_name || '—')}${(a.actor_mitre_id || a.actor_country) ? `<div class="tiny mono" style="color:var(--text-dim);font-weight:400">${esc([a.actor_mitre_id, a.actor_country].filter(Boolean).join(' · '))}</div>` : ''}</td>
          <td><span style="color:${CONF_HEX[a.confidence] || 'var(--text)'};font-weight:600;text-transform:capitalize">${esc(a.confidence || '')}</span></td>
          <td class="mono">${a.score != null ? esc(a.score) : '—'}</td>
          <td style="text-transform:capitalize">${esc(a.actor_motivation || '—')}</td>
          <td class="small">${a.supporting_ioc_count} IOC${a.supporting_ioc_count !== 1 ? 's' : ''} · ${a.supporting_timeline_count} event${a.supporting_timeline_count !== 1 ? 's' : ''}</td>
          <td class="small">${esc(a.analyst_notes || '—')}</td>
          <td class="mono small">${esc(a.created_by_username || '—')}<div>${a.created_at ? esc(fmtTs(a.created_at)) : ''}</div></td>
        </tr>`).join('')}</tbody>
      </table></div>`
    : '<div class="placeholder-box"><strong>[ NO THREAT ACTOR ATTRIBUTION RECORDED ]</strong></div>'

  // Affected systems (appendix)
  const affectedHtml = affected.length
    ? `<div class="table-wrap"><table>
        <thead><tr><th>System</th><th>Type</th><th>Notes</th><th>Added By</th><th>Added At</th></tr></thead>
        <tbody>${affected.map(s => `<tr>
          <td class="mono" style="font-weight:600">${esc(s.name)}</td>
          <td>${esc(SYSTEM_TYPE_LABEL[s.system_type] || s.system_type || labelOf('entity_type', s.entity_type) || '—')}</td>
          <td class="small">${esc(s.notes || '—')}</td>
          <td class="mono small">${esc(s.created_by_username || '—')}</td>
          <td class="mono small">${s.created_at ? esc(fmtTs(s.created_at)) : '—'}</td>
        </tr>`).join('')}</tbody>
      </table></div>`
    : '<div class="placeholder-box"><strong>[ NO AFFECTED SYSTEMS RECORDED ]</strong></div>'

  // Playbook tasks grouped by phase
  const playbookSections = (() => {
    if (!tasks.length) return ''
    const STATUS_ICON = { done: '✓', in_progress: '◑', open: '○', skipped: '—' }
    const byPhase = {}
    for (const t of tasks) { (byPhase[t.phase] = byPhase[t.phase] || []).push(t) }
    return Object.entries(byPhase).map(([phase, ts]) => {
      const done = ts.filter(t => t.status === 'done').length
      const rows = ts.map(t =>
        `<li class="task-row ${t.status === 'done' ? 'task-done' : 'task-pending'}">`
        + `<span class="task-icon">${STATUS_ICON[t.status] || '○'}</span>`
        + `<span class="task-title">${esc(t.title)}</span>`
        + (t.assignee_username ? `<span class="task-time">${esc(t.assignee_username)}</span>` : '')
        + `</li>`
      ).join('')
      return `<h3>${esc(phaseLabel(phase))} — ${done}/${ts.length} complete</h3>`
        + `<div class="progress-outer"><div class="progress-inner" style="width:${pct(done, ts.length)}%"></div></div>`
        + `<ul style="margin-top:8px;padding-left:0;list-style:none">${rows}</ul>`
    }).join('')
  })()

  // Remediation buckets from action items. Terms are measured from a fixed
  // anchor — the incident's close time, or the report time while it is still
  // open — so regenerating a closed incident's report never moves items.
  // Undated items get their own group rather than defaulting to long-term.
  const DAY = 86400000
  const anchorIso = inc.closed_at || data.generated_at || new Date().toISOString()
  const anchor = new Date(anchorIso).getTime()
  const aiItems = (ll && Array.isArray(ll.action_items)) ? ll.action_items : []
  const buckets = { short: [], medium: [], long: [], none: [] }
  for (const it of aiItems) {
    const due = it.due_date ? new Date(it.due_date).getTime() : null
    if (!due || isNaN(due)) { buckets.none.push(it); continue }
    const daysOut = (due - anchor) / DAY
    if      (daysOut <= 30) buckets.short.push(it)
    else if (daysOut <= 90) buckets.medium.push(it)
    else                    buckets.long.push(it)
  }

  // Cost summary — totalled per currency; amounts in different currencies are never added.
  const costByCur = {}
  for (const c of costs) {
    const amt = Number(c.amount) || 0
    if (!costByCur[c.currency]) costByCur[c.currency] = { total: 0, byCat: {} }
    const cur = costByCur[c.currency]
    cur.total += amt
    cur.byCat[c.category] = (cur.byCat[c.category] || 0) + amt
  }
  const costCurs = Object.keys(costByCur).sort()
  const costCurrency = (n) => n.toLocaleString(undefined, { maximumFractionDigits: 2 })
  const costMoney = (cur, n) => `${cur} ${costCurrency(n)}`

  // TLP message
  const tlpUpper = tlp.toUpperCase()
  const tlpMsg = TLP_MESSAGES[tlpUpper] || 'Handle according to TLP guidelines'

  // Classification / audience derived
  const classDisplay = classification || `TLP:${tlpUpper}`

  // Logo block: data-URL <img> if provided, else placeholder.
  const logoHtml = logo
    ? `<img class="logo-image" src="${esc(logo)}" alt="Company logo">`
    : '<div class="logo-placeholder">[ COMPANY LOGO ]</div>'

  const audienceNote = audience
    ? `<div style="margin-bottom:16px;padding:10px 16px;background:var(--bg-card);border:1px solid var(--border);border-radius:6px;font-size:12px;color:var(--text-muted);font-family:var(--mono)">Prepared for: ${esc(audience)}</div>`
    : ''

  const descriptionHtml = markdownToHtml(inc.description)
  const notClosed = '<span style="color:#d97706">Not closed</span>'
  const pending   = '<span style="color:#d97706">Pending</span>'

  // Communications & Notification Log — the out-of-band log (never the passphrase or contact details)
  const commsLogHtml = oobLog.length
    ? `<p class="small" style="color:var(--text-muted);margin-bottom:12px">Contacts logged out of band (Comms &amp; stakeholders → Out-of-band). Contact details and the verification passphrase are not printed.</p>
      <div class="table-wrap"><table>
        <thead><tr><th>Time</th><th>Direction</th><th>Channel</th><th>Stakeholder</th><th>Summary</th><th>Identity verified</th><th>Logged by</th></tr></thead>
        <tbody>${oobLog.map(o => `<tr>
          <td class="mono small">${esc(fmtTs(o.created_at))}</td>
          <td style="text-transform:capitalize">${esc(o.direction || '')}</td>
          <td style="text-transform:capitalize">${esc((o.channel || '').replace(/_/g, ' '))}</td>
          <td style="font-weight:600">${esc(o.stakeholder_name || '')}</td>
          <td class="small">${esc(o.summary || '')}</td>
          <td>${o.verified
            ? `<span class="status-ok">✓ Yes</span>${o.verification_method ? `<div class="tiny" style="color:var(--text-dim)">${esc(o.verification_method)}</div>` : ''}`
            : '<span class="status-unk">No</span>'}</td>
          <td class="mono small">${esc(o.created_by_username || '—')}</td>
        </tr>`).join('')}</tbody>
      </table></div>`
    : '<div class="placeholder-box"><strong>[ NO OUT-OF-BAND COMMUNICATIONS LOGGED ]</strong></div>'

  // Figures — numbered, caption + SHA-256 of the original file. '' when none are picked
  // (the section is then omitted). Only a raster data: URI is ever embedded.
  const RASTER_DATA_URI = /^data:image\/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/]+=*$/
  const figuresHtml = figures.length
    ? `<p class="small" style="color:var(--text-muted);margin-bottom:16px">Screenshots picked in Supporting documents. Each SHA-256 is of the original file as stored in FENRIR.</p>`
      + figures.map(f => {
        const title = f.caption || f.name
        const src = f.src && RASTER_DATA_URI.test(f.src) ? f.src : null
        return `<figure class="fig">
      ${src
        ? `<img src="${src}" alt="Figure ${f.n}: ${esc(title)}">`
        : `<div class="placeholder-box"><strong>[ FIGURE ${f.n} NOT EMBEDDED ]</strong>${esc(f.note || '')}</div>`}
      <figcaption><strong>Figure ${f.n}.</strong> ${esc(title)}
        <div class="fig-meta">${esc(f.name)} · ${esc(f.mime || 'unknown type')} · ${esc(_fmtSize(f.size))} · SHA-256 ${f.integrity === 'failed' ? '<strong class="fig-integrity-failed">integrity check failed</strong>' : f.sha256 ? `<span class="fig-sha">${esc(f.sha256)}</span>` : 'not available'}</div>
        ${src && f.note ? `<div class="fig-meta">${esc(f.note)}</div>` : ''}
      </figcaption>
    </figure>`
      }).join('')
    : ''

  // Approval & Sign-off — the recorded close sign-off, then a signature line per named role
  const signOffHtml = `
  <div class="two-col" style="margin-bottom:24px">
    <div class="info-card"><div class="label">Closed by</div><div class="value">${closure.closed ? esc(closure.closed_by || 'Not recorded') : notClosed}</div></div>
    <div class="info-card"><div class="label">Closed at</div><div class="value mono">${closure.closed_at ? esc(fmtTs(closure.closed_at)) : notClosed}</div></div>
  </div>
  <h3>Close sign-off statement</h3>
  ${closure.reason
    ? `<div class="prose" style="white-space:pre-wrap">${esc(closure.reason)}</div>`
    : `<div class="placeholder-box"><strong>[ ${closure.closed ? 'NO SIGN-OFF STATEMENT RECORDED' : 'NOT CLOSED — NO SIGN-OFF STATEMENT YET'} ]</strong></div>`}
  <h3>Signatures</h3>
  <div class="table-wrap"><table class="table-fixed">
    <colgroup><col style="width:26%"><col style="width:26%"><col style="width:30%"><col style="width:18%"></colgroup>
    <thead><tr><th>Role</th><th>Name</th><th>Signature</th><th>Date</th></tr></thead>
    <tbody>${signOffs.flatMap(r => (r.assignees && r.assignees.length ? r.assignees : [null]).map(a => `<tr class="sig-row">
      <td style="font-weight:600">${esc(r.role_label)}</td>
      <td>${a
        ? `${esc(a.name)}${a.name !== a.username ? `<div class="tiny mono" style="color:var(--text-dim)">${esc(a.username)}</div>` : ''}`
        : '<span class="status-unk">Not assigned</span>'}</td>
      <td><span class="sig-line"></span></td>
      <td><span class="sig-line"></span></td>
    </tr>`)).join('')}</tbody>
  </table></div>
  <h3>Recorded gate sign-offs</h3>
  ${gateSignOffs.length ? `<div class="table-wrap"><table class="table-fixed">
    <colgroup><col style="width:18%"><col style="width:20%"><col style="width:16%"><col style="width:46%"></colgroup>
    <thead><tr><th>Gate</th><th>Role · signer</th><th>Signed at</th><th>Statement · gate-state SHA-256</th></tr></thead>
    <tbody>${gateSignOffs.map(g => `<tr>
      <td class="small">${esc(g.gate_label)}</td>
      <td class="small"><strong>${esc(g.role_label)}</strong><div>${esc(g.username)} <span class="tiny mono">(${esc(g.signed_as)})</span></div>${g.current ? '' : '<div class="tiny">before a re-open; no longer counts</div>'}</td>
      <td class="mono small">${esc(fmtTs(g.signed_at))}</td>
      <td class="small"><div style="white-space:pre-wrap">${esc(g.statement)}</div><div class="tiny mono">${esc(g.state_sha256)}</div></td>
    </tr>`).join('')}</tbody>
  </table></div>`
    : '<div class="placeholder-box"><strong>[ NO GATE SIGN-OFF RECORDED ]</strong></div>'}`

  // ── Sections ─────────────────────────────────────────────────────────────
  // KEEP IN SYNC: keys/titles/fullOnly come from REPORT_SECTIONS; "Show structure"
  // (_skeletonSections / _skeletonAppendices below) describes this list — order, titles, fullOnly / conditional rules
  // and the fields each section prints. Change one, change the other.
  // Numbered in order of appearance. `fullOnly` sections are left out of the
  // executive report; a section whose body is '' (attack chain with no
  // MITRE-tagged events) is omitted.
  const sections = [
    { key: 'exec_summary', body: `
  ${audienceNote}
  ${narrativeToHtml(ll && ll.incident_narrative)
    || '<div class="placeholder-box"><strong>[ PLACEHOLDER — EXECUTIVE SUMMARY ]</strong>On [DATE], [ORGANIZATION] identified a security incident with [SEVERITY] severity. The response team achieved initial containment by [TIME]. This report details the full findings and recommended remediation actions.</div>'}` },

    { key: 'details', body: `
  <div class="two-col" style="margin-bottom:24px">
    <div class="info-card"><div class="label">Incident Type</div><div class="value">${esc(inc.incident_type ? inc.incident_type.replace(/_/g, ' ') : '[Not specified]')}</div></div>
    <div class="info-card"><div class="label">Severity</div><div class="value" style="color:${sevColor}">${esc(sev.toUpperCase())}</div><div class="small nciss" style="color:var(--text-muted);margin-top:4px">${NCISS_TITLE}: <strong>${esc(nciss)}</strong></div></div>
    <div class="info-card"><div class="label">TLP Classification</div><div class="value" style="color:${tlpColor}">TLP:${tlpUpper}</div></div>
    <div class="info-card"><div class="label">Current Phase</div><div class="value">${esc(phaseLabel(inc.phase))}</div></div>
    <div class="info-card"><div class="label">Triage State</div><div class="value">${esc(inc.triage_state || '—')}</div></div>
    <div class="info-card"><div class="label">Reporter</div><div class="value">${esc(inc.reporter || '—')}</div></div>
    <div class="info-card"><div class="label">Occurred At</div><div class="value mono">${inc.occurred_at ? esc(fmtTs(inc.occurred_at)) : '—'}</div></div>
    <div class="info-card"><div class="label">Detected At</div><div class="value mono">${inc.detected_at ? esc(fmtTs(inc.detected_at)) : '—'}</div></div>
    <div class="info-card"><div class="label">Contained At</div><div class="value mono">${inc.contained_at ? esc(fmtTs(inc.contained_at)) : pending}</div></div>
    <div class="info-card"><div class="label">Eradicated At</div><div class="value mono">${inc.eradicated_at ? esc(fmtTs(inc.eradicated_at)) : pending}</div></div>
    <div class="info-card"><div class="label">Recovered At</div><div class="value mono">${inc.recovered_at ? esc(fmtTs(inc.recovered_at)) : pending}</div></div>
    <div class="info-card"><div class="label">Closed At</div><div class="value mono">${inc.closed_at ? esc(fmtTs(inc.closed_at)) : notClosed}</div></div>
  </div>
  <h3>Incident Description</h3>
  ${descriptionHtml
    ? `<div class="prose md">${descriptionHtml}</div>`
    : '<div class="placeholder-box"><strong>[ PLACEHOLDER — DESCRIPTION ]</strong></div>'}
  ${(inc.tags && inc.tags.length)
    ? `<h3>Tags</h3><div>${inc.tags.map(t => `<span class="tag" style="margin-right:6px">${esc(t)}</span>`).join('')}</div>`
    : ''}` },

    { key: 'assignments', body: assignmentsHtml },

    { key: 'stakeholders', body: stakeholdersHtml },

    { key: 'detection', body: `
  <h3>Detection Method</h3>
  ${inc.detection_method
    ? `<div class="prose" style="white-space:pre-wrap">${esc(DETECTION_LABEL[inc.detection_method] || inc.detection_method)}</div>`
    : '<div class="placeholder-box"><strong>[ PLACEHOLDER — DETECTION METHOD ]</strong></div>'}
  <h3>Timeline of Key Events</h3>
  ${evs.length
    ? `<div class="table-wrap"><table>
        <thead><tr><th>Timestamp</th><th>Hostname</th><th>Event Type</th><th>Description</th><th>MITRE Technique</th></tr></thead>
        <tbody>${evs.map(e => `<tr>
          <td class="mono small">${esc(fmtTs(e.event_time))}${offsetText(e) ? `<div class="small">${offsetText(e)}</div>` : ''}</td>
          <td class="mono">${esc(e.hostname || '—')}</td>
          <td><span class="tag">${esc(e.event_type || '—')}</span></td>
          <td>${esc(e.description || '')}</td>
          <td class="mono small">${e.mitre_technique_id ? `${esc(e.mitre_technique_id)}: ${esc(e.mitre_technique_name || '')}` : '—'}</td>
        </tr>`).join('')}</tbody>
      </table></div>`
    : '<div class="placeholder-box"><strong>[ NO TIMELINE EVENTS ]</strong></div>'}
  <h3>IOCs Summary</h3>
  ${iocs.length
    ? `<div style="margin-bottom:14px">${iocTypeBadges}</div>
       <div class="table-wrap"><table>
         <thead><tr><th>Type</th><th>Value</th><th>Status</th><th>Confidence</th><th>Enrichment</th><th>Tags</th></tr></thead>
         <tbody>${_proIocRows(iocs)}</tbody>
       </table></div>`
    : '<div class="placeholder-box"><strong>[ NO IOCs RECORDED ]</strong></div>'}` },

    { key: 'cer', body: `
  ${_proCERSubsection(acts, 'containment', 'Containment Actions')}
  ${_proCERSubsection(acts, 'eradication', 'Eradication Actions')}
  ${_proCERSubsection(acts, 'recovery',    'Recovery Actions')}` },

    { key: 'recovery', body: _proRecoverySection(data.recovery) },

    { key: 'decisions', body: decisionsHtml },

    { key: 'impact', body: `
  <div class="two-col" style="margin-bottom:24px">
    <div class="info-card"><div class="label">Financial Impact</div><div class="value">${bia && bia.financial ? esc(bia.financial) : '[ To be assessed ]'}</div></div>
    <div class="info-card"><div class="label">Operational Downtime</div><div class="value">${bia && bia.operational ? esc(bia.operational) : '[ To be assessed ]'}</div></div>
    <div class="info-card"><div class="label">Data Exposure</div><div class="value">${bia && bia.data_exposure ? esc(bia.data_exposure) : '[ To be assessed ]'}</div></div>
    <div class="info-card"><div class="label">Reputational Impact</div><div class="value">${bia && bia.reputational ? esc(bia.reputational) : '[ To be assessed ]'}</div></div>
    <div class="info-card"><div class="label">Regulatory Risk</div><div class="value">${bia && bia.regulatory ? esc(bia.regulatory) : '[ To be assessed ]'}</div></div>
    <div class="info-card"><div class="label">Legal Obligations</div><div class="value">${legalCard}</div></div>
  </div>
  ${bia && bia.notes
    ? `<div class="prose" style="white-space:pre-wrap;margin-top:16px;padding:16px;background:var(--bg-card);border-radius:6px;border-left:3px solid #d97706">${esc(bia.notes)}</div>`
    : ''}` },

    { key: 'legal', body: deadlinesHtml },

    { key: 'comms_log', body: _proNotificationsSection(data.stakeholder_notifications) + commsLogHtml },

    { key: 'root_cause', body: `
  <h3>Initial Attack Vector / Root Cause Category</h3>
  ${ll && ll.root_cause_category
    ? `<div class="prose" style="white-space:pre-wrap"><strong>${esc(ll.root_cause_category.replace(/_/g, ' ').toUpperCase())}</strong>${ll.root_cause_description ? ' — ' + esc(ll.root_cause_description) : ''}</div>`
    : '<div class="placeholder-box"><strong>[ PLACEHOLDER — INITIAL ACCESS ]</strong></div>'}
  <h3>Contributing Factors</h3>
  ${ll && ll.contributing_factors && ll.contributing_factors.length
    ? `<ul style="padding-left:20px">${ll.contributing_factors.map(f => `<li>${esc(f)}</li>`).join('')}</ul>`
    : '<div class="placeholder-box"><strong>[ PLACEHOLDER ]</strong></div>'}
  <h3>Attack Chain (MITRE ATT&amp;CK)</h3>
  ${mitreRows
    ? `<div class="table-wrap"><table>
         <thead><tr><th>Timestamp</th><th>Technique</th><th>Description</th></tr></thead>
         <tbody>${mitreRows}</tbody>
       </table></div>`
    : '<div class="placeholder-box"><strong>[ NO MITRE TECHNIQUES MAPPED ]</strong></div>'}` },

    { key: 'attack_chain', body: _proAttackChain(evs) },

    { key: 'attribution', body: attributionHtml },

    { key: 'entities', body: ents.length
    ? `<div class="table-wrap"><table>
         <thead><tr><th>Type</th><th>Name / Value</th><th>Criticality</th><th>Status</th><th>Notes</th></tr></thead>
         <tbody>${entityRows}</tbody>
       </table></div>`
    : '<div class="placeholder-box"><strong>[ NO ENTITIES RECORDED ]</strong></div>' },

    { key: 'evidence', body: ev.total
    ? `<div class="two-col" style="margin-bottom:24px">
         <div class="info-card"><div class="label">Total Items</div><div class="value">${ev.total}</div></div>
         <div class="info-card"><div class="label">Active</div><div class="value">${ev.active || 0}</div></div>
         <div class="info-card"><div class="label">Digital Files</div><div class="value">${ev.digital || 0}</div></div>
         <div class="info-card"><div class="label">Physical Items</div><div class="value">${ev.physical || 0}</div></div>
       </div>`
    : '<div class="placeholder-box"><strong>[ NO EVIDENCE ITEMS COLLECTED ]</strong></div>' },

    { key: 'attachments', body: figuresHtml },

    { key: 'playbook',
      body: playbookSections || '<div class="placeholder-box"><strong>[ NO PLAYBOOK TASKS RECORDED ]</strong></div>' },

    { key: 'closure',
      body: closureItems || '<div class="placeholder-box"><strong>[ NO CLOSURE CHECKLIST ITEMS ]</strong></div>' },

    { key: 'lessons', body: `
  <h3>What Worked Well</h3>
  ${_proNarrativeAndList(ll && ll.report_what_worked_well,
      ll && ll.what_went_well && ll.what_went_well.length
        ? `<ul style="padding-left:20px">${ll.what_went_well.map(s => `<li>${esc(s)}</li>`).join('')}</ul>` : '')}
  <h3>What Could Be Improved</h3>
  ${_proNarrativeAndList(ll && ll.report_what_could_improve,
      ll && ll.friction_points && ll.friction_points.length
        ? `<ul style="padding-left:20px">${ll.friction_points.map(s => `<li>${esc(s)}</li>`).join('')}</ul>` : '')}
  <h3>Security Recommendations / Control Improvements</h3>
  ${_proNarrativeAndList(ll && ll.report_security_recommendations,
      ll && ll.control_improvements && ll.control_improvements.length
        ? `<div class="table-wrap"><table>
             <thead><tr><th>Recommendation</th><th>Category</th><th>Priority</th></tr></thead>
             <tbody>${ll.control_improvements.map(ci => `<tr><td>${esc(ci.recommendation || '')}</td><td style="text-transform:capitalize">${esc(ci.category || '')}</td><td style="text-transform:capitalize">${esc(ci.priority || '')}</td></tr>`).join('')}</tbody>
           </table></div>` : '')}
  ${!isExec && ll && ll.meeting_minutes ? `<h3>Review Meeting Minutes</h3>${narrativeToHtml(ll.meeting_minutes)}` : ''}` },

    { key: 'remediation', body: `
  <p class="small" style="color:var(--text-muted);margin-bottom:8px">Terms are measured from ${inc.closed_at ? 'the incident close time' : 'the report generation time (incident still open)'}: ${esc(fmtTs(anchorIso))}.</p>
  ${_proRemSection(ll && ll.report_remediation_short,  buckets.short,  'Short-Term (0–30 days)',   '#dc2626')}
  ${_proRemSection(ll && ll.report_remediation_medium, buckets.medium, 'Medium-Term (30–90 days)', '#ea580c')}
  ${_proRemSection(ll && ll.report_remediation_long,   buckets.long,   'Long-Term (90+ days)',     '#2563eb')}
  ${buckets.none.length ? _proRemSection(null, buckets.none, 'Unscheduled (no due date)', '#6b7280') : ''}` },

    { key: 'costs', body: `
  ${bia && bia.financial
    ? `<h3>Financial Impact Narrative</h3><div class="prose" style="white-space:pre-wrap">${esc(bia.financial)}</div>`
    : ''}
  ${costs.length
    ? `<h3>Cost Summary — Total: <span class="mono">${esc(costCurs.map(cur => costMoney(cur, costByCur[cur].total)).join(' · '))}</span></h3>
       <div class="two-col" style="margin-bottom:16px">
         ${costCurs.flatMap(cur => Object.entries(costByCur[cur].byCat).sort((a, b) => b[1] - a[1]).map(([cat, sum]) =>
           `<div class="info-card"><div class="label">${esc(cat.replace(/_/g, ' '))}</div><div class="value mono">${esc(costMoney(cur, sum))}</div></div>`
         )).join('')}
       </div>
       <h3>Itemised Costs</h3>
       <div class="table-wrap"><table>
         <thead><tr><th>Category</th><th>Description</th><th style="text-align:right">Amount</th><th>Phase</th></tr></thead>
         <tbody>${costs.map(c => `<tr>
           <td style="text-transform:capitalize">${esc((c.category || '').replace(/_/g, ' '))}</td>
           <td>${esc(c.description || '')}</td>
           <td class="mono" style="text-align:right">${esc(costMoney(c.currency, Number(c.amount) || 0))}</td>
           <td>${esc(c.ir_phase ? phaseLabel(c.ir_phase) : '')}</td>
         </tr>`).join('')}</tbody>
       </table></div>`
    : ((bia && bia.financial) ? '' : '<div class="placeholder-box"><strong>[ NO COSTS RECORDED ]</strong></div>')}` },

    { key: 'sign_off', body: signOffHtml },
  ].map(s => ({ ...SECTION_BY_KEY[s.key], ...s }))
   .sort((a, b) => REPORT_SECTIONS.indexOf(SECTION_BY_KEY[a.key]) - REPORT_SECTIONS.indexOf(SECTION_BY_KEY[b.key]))
   .filter(s => !(isExec && s.fullOnly) && include(s.key) && s.body)

  const sectionsHtml = sections.map((s, i) => `
<div class="section${i % 2 ? ' section-alt' : ''}" data-section="${esc(s.key)}">
  <div class="section-header"><span class="section-number">§ ${String(i + 1).padStart(2, '0')}</span><h2>${esc(s.title)}</h2></div>
  ${csfLine(s.csf)}
  ${s.body}
</div>`).join('\n')

  // Appendices: always-present first, optional last, so letters never change
  // and never leave a gap — A = Affected Systems, B = Timeline (optional).
  const appendices = [
    { title: 'Affected Systems', body: affectedHtml },
    includeTimelineAppendix && { title: 'Incident Timeline', body: `
  <p style="font-size:12px;color:var(--text-muted);margin-bottom:24px">${evs.length} event${evs.length !== 1 ? 's' : ''} · chronological · all phases</p>
  ${_proTimelineAppendix(evs)}` },
    // H2: the append-only case notes, full report only, after the existing appendices.
    !isExec && { title: 'Case Notes', body: _proCaseNotesAppendix(caseNotes) },
  ].filter(Boolean)

  const appendicesHtml = appendices.map((a, i) => {
    const letter = String.fromCharCode(65 + i)
    return `
<div class="section" style="page-break-before:always">
  <div class="section-header">
    <span class="section-number" style="letter-spacing:1px">${letter}</span>
    <h2>Appendix ${letter} — ${esc(a.title)}</h2>
  </div>
  ${csfLine(APPENDIX_CSF[a.title])}
  ${a.body}
</div>`
  }).join('\n')

  // ── Body ─────────────────────────────────────────────────────────────────
  const body = `
<div class="tlp-banner">TLP:${tlpUpper} — ${esc(tlpMsg)}</div>

<div class="cover">
  <div class="cover-inner">
    ${logoHtml}
    <div class="cover-eyebrow">Incident Response Report // DFIR-FENRIR v2</div>
    <div class="cover-title">${esc(inc.title || '')}</div>
    <div class="cover-subtitle">Post-Incident Analysis &amp; Forensic Report</div>
    <div class="cover-badges">
      <span class="badge badge-sev">${esc(sev.toUpperCase())} SEVERITY</span>
      <span class="badge badge-tlp">TLP:${tlpUpper}</span>
      <span class="badge badge-phase">${esc(phaseLabel(inc.phase))}</span>
      ${inc.status === 'closed'
        ? '<span class="badge" style="background:#1a1a2e;color:#dc2626;border:1px solid #dc2626">CLOSED</span>'
        : '<span class="badge" style="background:#1a1a0a;color:#ca8a04;border:1px solid #ca8a04">ACTIVE</span>'}
    </div>
    <div class="cover-meta">
      <div class="cover-meta-item"><strong>Incident ID</strong>${esc(inc.ref || `${(inc.id || '').slice(0, 8).toUpperCase()}...`)}</div>
      <div class="cover-meta-item"><strong>Opened</strong>${esc(fmtTs(inc.created_at))}</div>
      <div class="cover-meta-item"><strong>Closed</strong>${inc.closed_at ? esc(fmtTs(inc.closed_at)) : 'Not closed'}</div>
      <div class="cover-meta-item"><strong>Generated</strong>${esc(generated)}</div>
    </div>
  </div>
</div>

<div class="doc-control">
  <div class="doc-control-item"><div class="label">Classification</div><div class="value">${esc(classDisplay)}</div></div>
  <div class="doc-control-item"><div class="label">Severity</div><div class="value" style="color:${sevColor}">${esc(sev.toUpperCase())}</div></div>
  <div class="doc-control-item"><div class="label">${NCISS_TITLE}</div><div class="value nciss">${esc(nciss)}</div></div>
  <div class="doc-control-item"><div class="label">IR Phase</div><div class="value">${esc(phaseLabel(inc.phase))}</div></div>
  <div class="doc-control-item"><div class="label">Timeline Events</div><div class="value">${evs.length}</div></div>
  <div class="doc-control-item"><div class="label">IOCs</div><div class="value">${iocs.length} (${malicIocs} malicious)</div></div>
  <div class="doc-control-item"><div class="label">Report Type</div><div class="value">${isExec ? 'Exec' : 'Full'}</div></div>
</div>

${include('kpis') ? `<div class="stats-bar">
  <div class="stat"><div class="stat-value">${evs.length}</div><div class="stat-label">Timeline Events</div></div>
  <div class="stat"><div class="stat-value">${iocs.length}</div><div class="stat-label">IOCs</div></div>
  <div class="stat"><div class="stat-value" style="color:#dc2626">${malicIocs}</div><div class="stat-label">Malicious IOCs</div></div>
  <div class="stat"><div class="stat-value">${ents.length}</div><div class="stat-label">Entities</div></div>
  <div class="stat"><div class="stat-value">${ev.total || 0}</div><div class="stat-label">Evidence Items</div></div>
  <div class="stat"><div class="stat-value" style="color:${taskPct === 100 ? '#16a34a' : '#d97706'}">${taskPct}%</div><div class="stat-label">Playbook Done</div></div>
</div>` : ''}

${sectionsHtml}

${appendicesHtml}

<div class="footer">
  <div>
    <div style="margin-bottom:4px">DFIR-FENRIR v2 Incident Response Platform // Generated Report</div>
    <div style="color:var(--text-dim)">Incident ID: ${esc(inc.id || '')} // Generated: ${esc(generated)}</div>
    ${footer ? `<div style="margin-top:4px;color:var(--text-dim)">${esc(footer)}</div>` : ''}
  </div>
  <div class="footer-tlp">TLP:${tlpUpper}</div>
  <div style="text-align:right;font-size:10px;color:var(--text-dim)">
    <div>Integrity (SHA-256)</div>
    <div class="report-sha256" style="user-select:all;color:var(--text);word-break:break-all;max-width:280px">${REPORT_SHA256_PLACEHOLDER}</div>
  </div>
</div>`

  // ── CSS (v1's full pro stylesheet, theme-driven) ─────────────────────────
  const css = `
  ${theme.fonts}
  ${cssVars}
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: var(--font); background: var(--bg); color: var(--text); font-size: 14px; line-height: 1.6; }
  a { color: var(--blue); }
  .cover { background: ${theme.cover_gradient}; padding: 0; min-height: 360px; position: relative; overflow: hidden; border-bottom: 3px solid ${sevColor}; }
  .cover-inner { padding: 60px 64px 48px; position: relative; z-index: 2; }
  .cover::before { content: ''; position: absolute; top: -100px; right: -100px; width: 500px; height: 500px; border-radius: 50%; background: radial-gradient(circle, ${sevColor}18 0%, transparent 70%); z-index: 1; }
  .logo-placeholder { width: 160px; height: 56px; border: 2px dashed var(--border); border-radius: 6px; display: flex; align-items: center; justify-content: center; color: var(--text-dim); font-size: 11px; letter-spacing: 1px; margin-bottom: 36px; font-family: var(--mono); }
  .logo-image { max-width: 240px; max-height: 80px; width: auto; height: auto; margin-bottom: 36px; display: block; }
  .cover-eyebrow { font-size: 11px; color: var(--text-dim); letter-spacing: 3px; text-transform: uppercase; margin-bottom: 12px; font-family: var(--mono); }
  .cover-title { font-size: 38px; font-weight: 800; color: var(--text-strong); line-height: 1.15; max-width: 700px; letter-spacing: -0.5px; }
  .cover-subtitle { font-size: 16px; color: var(--text-muted); margin-top: 10px; font-weight: 400; }
  .cover-badges { display: flex; gap: 10px; margin-top: 24px; flex-wrap: wrap; }
  .badge { padding: 5px 14px; border-radius: 4px; font-size: 12px; font-weight: 700; letter-spacing: 1.5px; text-transform: uppercase; }
  .badge-sev { background: ${sevColor}; color: #fff; }
  .badge-tlp { background: transparent; border: 2px solid ${tlpColor}; color: ${tlpColor}; }
  .badge-phase { background: var(--bg-card); border: 1px solid var(--border); color: var(--text-muted); letter-spacing: 1px; }
  .cover-meta { margin-top: 32px; display: flex; gap: 32px; flex-wrap: wrap; }
  .cover-meta-item { font-size: 12px; color: var(--text-dim); font-family: var(--mono); }
  .cover-meta-item strong { color: var(--text-muted); display: block; margin-bottom: 2px; }
  .tlp-banner { background: ${tlpColor}22; border-bottom: 1px solid ${tlpColor}44; padding: 8px 64px; font-size: 11px; font-weight: 700; letter-spacing: 2px; color: ${tlpColor}; text-align: center; font-family: var(--mono); }
  .doc-control { background: var(--bg-card); border-bottom: 1px solid var(--border); padding: 20px 64px; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 12px; }
  .doc-control-item { font-size: 12px; }
  .doc-control-item .label { color: var(--text-dim); font-family: var(--mono); letter-spacing: 1px; font-size: 10px; text-transform: uppercase; }
  .doc-control-item .value { color: var(--text); font-weight: 600; margin-top: 2px; }
  .stats-bar { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); background: var(--bg-card); border-bottom: 1px solid var(--border); padding: 0; }
  .stat { padding: 20px 24px; border-right: 1px solid var(--border); text-align: center; }
  .stat:last-child { border-right: none; }
  .stat-value { font-size: 28px; font-weight: 800; color: var(--text-strong); line-height: 1; }
  .stat-label { font-size: 10px; color: var(--text-dim); letter-spacing: 1.5px; text-transform: uppercase; margin-top: 4px; font-family: var(--mono); }
  .section { padding: 48px 64px; border-bottom: 1px solid var(--border-light); }
  .section-alt { background: var(--bg-section); }
  .section-header { display: flex; align-items: center; gap: 14px; margin-bottom: 28px; }
  .section-number { font-size: 11px; font-family: var(--mono); color: var(--red); border: 1px solid var(--red); padding: 2px 8px; border-radius: 3px; letter-spacing: 2px; flex-shrink: 0; }
  .section h2 { font-size: 20px; font-weight: 700; color: var(--text-strong); }
  .section h3 { font-size: 14px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; margin: 28px 0 12px; }
  .prose { color: ${theme.prose_color}; line-height: 1.8; font-size: 14px; }
  .placeholder-box { border: 2px dashed var(--border); border-radius: 8px; padding: 24px; color: var(--text-dim); font-style: italic; font-size: 13px; line-height: 1.7; background: var(--bg-card); }
  .placeholder-box strong { color: var(--text-muted); font-style: normal; display: block; margin-bottom: 8px; font-family: var(--mono); font-size: 11px; letter-spacing: 1px; }
  .table-wrap { overflow-x: auto; border-radius: 8px; border: 1px solid var(--border); margin-bottom: 12px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { background: var(--th-bg); color: var(--th-color); padding: 10px 14px; text-align: left; font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase; font-family: var(--mono); border-bottom: 1px solid var(--border); white-space: nowrap; }
  td { padding: 10px 14px; border-bottom: 1px solid var(--border-light); vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: var(--tr-hover); }
  .mono { font-family: var(--mono); }
  .small { font-size: 12px; }
  .tiny { font-size: 11px; }
  .tag { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; background: var(--bg-card); border: 1px solid var(--border); color: var(--text-muted); letter-spacing: 0.5px; font-family: var(--mono); }
  .status-ok { color: var(--green); font-weight: 600; }
  .status-bad { color: #dc2626; font-weight: 600; }
  .status-unk { color: var(--text-dim); }
  .enrich-badge { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 700; background: var(--enrich-bg); color: var(--enrich-fg); margin-right: 3px; font-family: var(--mono); }
  .ioc-type-badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 12px; background: var(--bg-card); border: 1px solid var(--border); color: var(--text-muted); margin: 3px; font-family: var(--mono); }
  .progress-outer { background: var(--border); border-radius: 6px; height: 10px; margin: 12px 0; overflow: hidden; }
  .progress-inner { height: 10px; border-radius: 6px; background: linear-gradient(90deg, ${sevColor}, ${sevColor}99); width: 0%; }
  .progress-label { font-size: 12px; color: var(--text-muted); margin-top: 4px; font-family: var(--mono); }
  .task-row { display: flex; align-items: baseline; gap: 10px; padding: 5px 0; font-size: 13px; list-style: none; }
  .task-done { color: var(--task-done); }
  .task-pending { color: var(--text-dim); }
  .task-icon { font-family: var(--mono); font-size: 12px; flex-shrink: 0; width: 14px; }
  .task-title { flex: 1; }
  .task-time { color: var(--text-dim); font-family: var(--mono); font-size: 10px; margin-left: auto; white-space: nowrap; }
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  .info-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
  .info-card .label { font-size: 10px; color: var(--text-dim); letter-spacing: 1.5px; text-transform: uppercase; font-family: var(--mono); margin-bottom: 6px; }
  .info-card .value { font-size: 15px; font-weight: 600; color: var(--text); }
  .footer { padding: 24px 64px; display: flex; justify-content: space-between; align-items: flex-start; color: var(--text-dim); font-size: 11px; background: var(--bg-card); border-top: 1px solid var(--border); font-family: var(--mono); gap: 12px; flex-wrap: wrap; }
  .footer-tlp { color: ${tlpColor}; font-weight: 700; letter-spacing: 1px; }
  .csf-line { margin: -18px 0 24px; font-size: 11px; color: var(--text-dim); font-family: var(--mono); letter-spacing: 0.5px; }
  .csf-id { display: inline-block; padding: 1px 6px; border: 1px solid var(--border); border-radius: 3px; color: var(--text-muted); background: var(--bg-card); }
  .fig { margin: 0 0 32px; page-break-inside: avoid; }
  .fig img { display: block; max-width: 100%; height: auto; border: 1px solid var(--border); border-radius: 6px; }
  .fig figcaption { margin-top: 8px; font-size: 13px; color: var(--text); }
  .fig-meta { margin-top: 4px; font-family: var(--mono); font-size: 11px; color: var(--text-dim); overflow-wrap: anywhere; }
  .sig-row td { height: 56px; vertical-align: bottom; }
  .sig-line { display: block; border-bottom: 1px solid var(--text-muted); height: 24px; }
  .table-fixed { table-layout: fixed; }
  .table-fixed th { white-space: normal; }
  .table-fixed td { overflow-wrap: anywhere; }
  .md { line-height: 1.7; }
  .md p, .md ul, .md ol, .md pre, .md blockquote { margin: 0 0 10px; }
  .md ul, .md ol { padding-left: 22px; }
  .md li { margin-bottom: 4px; }
  .section .md h1, .section .md h2, .section .md h3, .section .md h4 { font-size: 15px; font-weight: 700; color: var(--text-strong); text-transform: none; letter-spacing: 0; margin: 16px 0 8px; }
  .section .md h1 { font-size: 18px; }
  .section .md h2 { font-size: 16px; }
  .md code { font-family: var(--mono); font-size: 12px; background: var(--bg-card); border: 1px solid var(--border); border-radius: 3px; padding: 0 4px; }
  .md pre { background: var(--bg-card); border: 1px solid var(--border); border-radius: 6px; padding: 10px 12px; overflow-x: auto; }
  .md pre code { border: none; padding: 0; }
  .md blockquote { border-left: 3px solid var(--border); padding-left: 12px; color: var(--text-muted); }
  .md a { color: var(--blue); }
  .ac-wrap { border: 1px solid var(--border); border-radius: 8px; overflow: hidden; background: var(--bg-card); }
  .ac-lane { display: flex; min-height: 58px; border-bottom: 1px solid var(--border-light); }
  .ac-label { width: 220px; flex-shrink: 0; padding: 8px 12px; border-right: 1px solid var(--border); }
  .ac-name { font-size: 12px; font-weight: 700; }
  .ac-meta { font-size: 10px; color: var(--text-dim); font-family: var(--mono); margin: 2px 0 4px; }
  .ac-chip { display: inline-block; font-family: var(--mono); font-size: 9px; padding: 0 5px; border: 1px solid; border-radius: 3px; margin: 0 3px 3px 0; }
  .ac-track { position: relative; flex: 1; }
  .ac-line { position: absolute; left: 0; right: 0; top: 50%; border-top: 1px dashed var(--border); }
  .ac-dot { position: absolute; top: 50%; width: 12px; height: 12px; border-radius: 50%; transform: translate(-50%, -50%); border: 2px solid var(--bg-card); -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .ac-axis { display: flex; justify-content: space-between; margin-left: 220px; padding: 6px 12px; font-family: var(--mono); font-size: 10px; color: var(--text-dim); }
  @media print { .section { padding: 32px 48px; } table { font-size: 11px; } }
  .atl-wrap{position:relative}
  .atl-spine{position:relative;padding:8px 0}
  .atl-spine::before{content:'';position:absolute;left:50%;top:0;bottom:0;width:2px;background:var(--border);transform:translateX(-50%)}
  .atl-date{text-align:center;position:relative;margin:18px 0 10px;z-index:2}
  .atl-date span{display:inline-block;background:var(--bg);border:1px solid var(--border);padding:3px 12px;border-radius:20px;font-family:var(--mono);font-size:10px;color:var(--text-dim);letter-spacing:.06em}
  .atl-item{display:flex;width:50%;position:relative;margin-bottom:12px}
  .atl-item.left{padding-right:26px;justify-content:flex-end}
  .atl-item.right{padding-left:26px;margin-left:50%}
  .atl-dot{position:absolute;width:10px;height:10px;border-radius:50%;top:13px;z-index:3;border:2px solid var(--bg)}
  .atl-item.left .atl-dot{right:-6px}
  .atl-item.right .atl-dot{left:-6px}
  .atl-card{background:var(--bg-card);border:1px solid var(--border);border-radius:5px;padding:9px 11px;width:100%}
  .atl-header{display:flex;flex-wrap:wrap;gap:4px 6px;align-items:center;margin-bottom:5px}
  .atl-time{font-family:var(--mono);font-size:10px;font-weight:600;color:var(--text-muted);flex-shrink:0}
  .atl-host{font-family:var(--mono);font-size:9px;color:var(--text-dim);margin-left:auto}
  .atl-pill{font-size:9px;font-weight:700;padding:1px 6px;border-radius:3px;letter-spacing:.03em;white-space:nowrap;border:1px solid}
  .atl-desc{font-size:12px;color:var(--text);line-height:1.45;word-break:break-word}
  .atl-mitre{display:inline-block;font-family:var(--mono);font-size:9px;font-weight:600;padding:1px 6px;border-radius:3px;border:1px solid;margin-top:3px}
  .atl-meta{font-size:10px;color:var(--text-dim);margin-top:3px}
  @media(max-width:768px){.atl-spine::before{left:14px}.atl-item,.atl-item.right{width:100%;margin-left:0;padding-left:28px;padding-right:0;justify-content:flex-start}.atl-item.left .atl-dot,.atl-item.right .atl-dot{left:9px;right:auto}}
  @media print{.atl-spine::before{background:#ccc}.atl-card{background:#fff;border-color:#ccc}.atl-date span{background:#fff}}`

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IR Report — ${esc(inc.title || 'Incident')}</title>
<style>${css}</style>
</head>
<body>${body}</body>
</html>`
}

// ─── Main export ──────────────────────────────────────────────────────────────

export const TEMPLATE_META = [
  { id: 'executive', name: 'Executive (light · serif)',  desc: 'Light, formal, navy/serif. Suitable for leadership and stakeholder delivery.' },
  { id: 'tactical',  name: 'Tactical (v1 · dark red)',   desc: 'The original FENRIR look — dark indigo with red accents. For operators who want the v1 visual identity.' },
  { id: 'forensic',  name: 'Forensic (court-ready)',     desc: 'Light blue/grey, monospace data fields. For regulatory, legal, or law enforcement handoff.' },
  { id: 'print',     name: 'Print (B/W, paper)',         desc: 'High-contrast black & white. Dense, paper-optimised.' },
]

// ─── Skeleton preview ─────────────────────────────────────────────────────────
// Renders a structural preview of the report: every dynamic field appears as a
// pill marking where the data comes from. Static prose stays as-is so the user
// can see the difference between "you wrote this" and "we'll fill it in".
// Honours the same section toggles / mode as generateReport — sections you
// excluded show up greyed out so the structure stays honest.

const SKELETON_CSS = `
  body { background: #0b0b16; color: #e2e2f0; font: 14px/1.55 -apple-system, BlinkMacSystemFont, 'Segoe UI', Inter, sans-serif; padding: 32px 48px; max-width: 920px; margin: 0 auto; }
  h1 { font-size: 22px; margin: 0 0 4px; letter-spacing: 0.02em; }
  h2 { font-size: 14px; margin: 24px 0 8px; color: #93c5fd; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 700; }
  h3 { font-size: 13px; margin: 12px 0 6px; color: #c8c8e0; font-weight: 600; }
  p, li { color: #b8b8d0; }
  ul { margin: 0; padding-left: 18px; }
  li { margin: 4px 0; }
  .sk-banner { background: #1e3a5f; border: 1px solid #60a5fa55; color: #93c5fd; padding: 10px 14px; border-radius: 6px; margin-bottom: 24px; font-size: 13px; }
  .sk-section { background: #0e0e1a; border: 1px solid #1e1e30; border-radius: 8px; padding: 16px 20px; margin-bottom: 14px; position: relative; }
  .sk-section.excluded { opacity: 0.55; border-color: #7f1d1d; background: #1a0a0a; }
  .sk-section.excluded h3 { text-decoration: line-through; color: #fca5a5; }
  .sk-section.excluded ul { text-decoration: line-through; }
  .sk-section .excluded-badge { position: absolute; top: 12px; right: 16px; font-size: 10px; font-weight: 800; letter-spacing: 0.12em; text-transform: uppercase; color: #fff; background: #b91c1c; padding: 3px 8px; border-radius: 3px; font-family: 'JetBrains Mono', monospace; }
  .ph { display: inline-block; padding: 1px 8px; background: #1e3a5f33; color: #93c5fd; border: 1px solid #60a5fa55; border-radius: 4px; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px; font-weight: 600; letter-spacing: 0.02em; }
  .ph-auto { color: #86efac; background: #14532d33; border-color: #4ade8055; }
  .ph-user { color: #fbbf24; background: #78350f33; border-color: #f59e0b55; }
  .static { color: #c8c8e0; }
  .where { color: #8888aa; font-size: 12px; }
  .sk-num { display: inline-block; min-width: 38px; margin-right: 8px; padding: 1px 6px; border: 1px solid #f8717155; border-radius: 3px; color: #f87171; font: 700 10px 'JetBrains Mono', Consolas, monospace; letter-spacing: 0.1em; text-align: center; }
  .sk-tag { margin-left: 8px; padding: 1px 6px; border-radius: 3px; background: #1e1e30; color: #8888aa; font-size: 10px; font-weight: 600; }
  .sk-cond { margin: 0 0 6px; color: #fbbf24; font-size: 12px; font-style: italic; }
  .sk-csf { margin: 0 0 6px; color: #8888aa; font: 600 11px 'JetBrains Mono', Consolas, monospace; letter-spacing: 0.04em; }
  .legend { display: flex; gap: 10px; margin-bottom: 24px; font-size: 11px; color: #8888aa; flex-wrap: wrap; }
  .legend > span { display: inline-flex; align-items: center; gap: 6px; }
  .meta { font-size: 11px; color: #555570; font-family: 'JetBrains Mono', Consolas, monospace; margin-top: 32px; padding-top: 16px; border-top: 1px solid #1e1e30; }
`

// `kind` is 'auto' (filled from incident data), 'user' (filled from form input),
// or undefined (generic data field).
function ph(label, kind) {
  const cls = kind === 'auto' ? 'ph ph-auto' : kind === 'user' ? 'ph ph-user' : 'ph'
  return `<span class="${cls}">${esc(label)}</span>`
}

// Where a value is entered in the UI — shown after its data field.
function where(s) { return `<span class="where">← ${esc(s)}</span>` }

// ─── KEEP IN SYNC ─────────────────────────────────────────────────────────────
// "Show structure" must describe exactly what generateProReport() renders.
// _skeletonSections() mirrors its `sections` array and _skeletonAppendices()
// its `appendices` array: same order, same titles, same `fullOnly` (left out
// of the executive report) and conditional rules, same fields per section.
// Whenever the main report changes, update these two functions — and vice
// versa: a change here that the report doesn't make is a bug.
function _skeletonSections() {
  const list = [
    { key: 'exec_summary', items: [
      `Audience note (when set): ${ph('Advanced options → Audience', 'user')}`,
      `Narrative: ${ph('lessons_learned.incident_narrative', 'auto')} ${where('Post-Incident → Lessons Learned → Incident Narrative (shown on Details → Resolution summary)')}`,
    ]},
    { key: 'details', items: [
      `Type · Severity · TLP · Triage state · Reporter: ${ph('incident.incident_type / severity / tlp / triage_state / reporter', 'auto')} ${where('Details → Classification')}`,
      `${NCISS_TITLE}, next to the severity: ${ph('incident.nciss_severity', 'auto')} <span class="static">— critical → Emergency, high → Severe, medium → Medium, low → Low</span>`,
      `Current phase: ${ph('incident.phase', 'auto')} ${where('phase stepper in the incident header')}`,
      `Occurred · Detected at: ${ph('incident.occurred_at / detected_at', 'auto')} ${where('Details → Classification')}`,
      `Contained · Eradicated · Recovered at: ${ph('incident.contained_at / eradicated_at / recovered_at', 'auto')} ${where('Declare … in the incident header, or Details → Classification')} <span class="static">— "Pending" until declared</span>`,
      `Closed at: ${ph('incident.closed_at', 'auto')} ${where('set when the incident is closed')} <span class="static">— "Not closed" while open</span>`,
      `Incident description (rendered as Markdown): ${ph('incident.description', 'auto')} ${where('Details → Description')}`,
      `Tags (when set): ${ph('incident.tags[]', 'auto')} ${where('Details → Snapshot → Tags')}`,
    ]},
    { key: 'assignments', items: [
      `Table: ${ph('assignments[*] (role, analyst, assigned by, assigned at, notes)', 'auto')} ${where('Team')}`,
    ]},
    { key: 'stakeholders', items: [
      `Table: ${ph('stakeholders[*] (name, title, organization, type)', 'auto')} ${where('Comms & stakeholders → Stakeholders')}`,
      `<span class="static">Contact methods and notes are never printed.</span>`,
    ]},
    { key: 'detection', items: [
      `Detection method (friendly label): ${ph('incident.detection_method', 'auto')} ${where('Details → Classification')}`,
      `Timeline of key events: ${ph('timeline_events[*] (time, hostname, event type, description, MITRE technique)', 'auto')} ${where('Timeline tab')}`,
      `IOCs summary: ${ph('iocs[*] (type, value, malicious, confidence, TI match / source, tags)', 'auto')} ${where('IOCs')}`,
    ]},
    { key: 'cer', items: [
      `Containment / Eradication / Recovery tables (aligned columns): ${ph('respond_actions[*] (title, description, status, occurred at, notes, assignee = "By")', 'auto')} ${where('Respond → actions')}`,
    ]},
    { key: 'recovery', items: [
      `Roll-up: ${ph('recovery.summary (validated of in scope, not required, open, same-person validations)', 'auto')} ${where('Recovery')}`,
      `Table: ${ph('recovery.items[*] (system, state, restore point, restored at/by, validated at/by, method + checklist, monitoring window)', 'auto')} ${where('Recovery')}`,
    ]},
    { key: 'decisions', items: [
      `Table: ${ph('decisions[*] (summary, outcome, rationale, decided by, decided at)', 'auto')} ${where('Respond → Decisions')}`,
    ]},
    { key: 'impact', items: [
      `Financial · Operational · Data exposure · Reputational · Regulatory · Notes: ${ph('business_impact.*', 'auto')} ${where('Post-Incident → Costs & Impact → Business Impact Assessment')}`,
      `Legal obligations: ${ph('regulatory_deadlines[*] regulation + article', 'auto')} + ${ph('business_impact.legal', 'auto')} <span class="static">— empty ("—") unless legal deadlines have been initialized</span> ${where('Legal & regulatory → Initialize deadlines')}`,
    ]},
    { key: 'legal', items: [
      `Table: ${ph('regulatory_deadlines[*] (regulation, article, obligation, recipient, deadline, status, completed)', 'auto')} ${where('Legal & regulatory')}`,
      `Compliance: ${ph('met / violated (late or overdue) / pending / waived', 'auto')} <span class="static">— computed by the server</span>`,
    ]},
    { key: 'comms_log', items: [
      `Notifications: ${ph('stakeholder_notifications (summary + items: role, severity, clock start, due, status, notified at/by/channel)', 'auto')} ${where('Comms & stakeholders → Notifications')}`,
      `Table: ${ph('oob_log[*] (time, direction, channel, stakeholder, summary, identity verified + method, logged by)', 'auto')} ${where('Comms & stakeholders → Out-of-band')}`,
      `<span class="static">Contact details and the verification passphrase are never printed.</span>`,
    ]},
    { key: 'root_cause', items: [
      `Root cause category + description · Contributing factors: ${ph('lessons_learned.root_cause_*, contributing_factors[]', 'auto')} ${where('Post-Incident → Lessons Learned → Root Cause Analysis')}`,
      `MITRE ATT&CK table: ${ph('timeline_events[*] with a MITRE technique', 'auto')} ${where('Timeline tab')}`,
    ]},
    { key: 'attack_chain', conditional: 'Only when at least one timeline event carries a MITRE tactic — otherwise omitted and the sections below move up one number.', items: [
      `Swimlane per tactic (ATT&amp;CK kill-chain order), one dot per event by time: ${ph('timeline_events[*] (mitre_tactic_id, technique, event_time)', 'auto')} ${where('Timeline tab → MITRE tactic / technique')}`,
    ]},
    { key: 'attribution', items: [
      `Table: ${ph('attributions[*] (actor, MITRE ID, country, confidence, score, motivation, supporting IOCs/events, notes, attributed by/at)', 'auto')} ${where('ATT&CK & attribution → Attribution')}`,
    ]},
    { key: 'entities', items: [
      `Table: ${ph('entities[*] (type, name / value, criticality, compromised, description)', 'auto')} ${where('Entities tab (compromised: entity drawer)')}`,
    ]},
    { key: 'evidence', items: [
      `Counts: ${ph('evidence_summary (total, active, digital, physical)', 'auto')} ${where('Evidence tab')}`,
    ]},
    { key: 'attachments', conditional: 'Only when at least one file is ticked "Include in report" in Supporting documents — otherwise omitted and the sections below move up one number.', items: [
      `Numbered figures (Figure 1, 2 …), oldest first: image + ${ph('report_files[*].caption (or file name)', 'auto')} ${where('Supporting documents → Include in report')}`,
      `Under each: file name · type · size · ${ph('SHA-256 of the original file', 'auto')} <span class="static">(computed in the browser from the downloaded original; checked against the server's)</span>`,
      `<span class="static">Images over 1.5 MB are downscaled to at most 1920 px (JPEG) for the report. Embedded images are capped at 7 MiB in total; you are warned before saving and figures over the cap are listed without the image.</span>`,
    ]},
    { key: 'playbook', items: [
      `Per-phase tasks + progress: ${ph('playbook_tasks[*] (title, phase, status)', 'auto')} ${where('Playbook tab')}`,
    ]},
    { key: 'closure', items: [
      `Progress + items: ${ph('closure_checklist[*] (label, checked, owner)', 'auto')} ${where('Post-Incident → Closure Checklist')}`,
    ]},
    { key: 'lessons', items: [
      `Each sub-heading prints the report text first, then the structured Lessons Learned entries:`,
      `What worked well: ${ph('report_what_worked_well', 'auto')} + ${ph('what_went_well[]', 'auto')}`,
      `What could be improved: ${ph('report_what_could_improve', 'auto')} + ${ph('friction_points[]', 'auto')}`,
      `Security recommendations: ${ph('report_security_recommendations', 'auto')} + ${ph('control_improvements[]', 'auto')}`,
      `Review meeting minutes (full report only, when recorded): ${ph('meeting_minutes', 'auto')}`,
      `${where('Post-Incident → Lessons Learned (Report Text, lists, Review Details)')}`,
    ]},
    { key: 'remediation', items: [
      `Short (0–30 d) · Medium (30–90 d) · Long (90+ d): ${ph('report_remediation_short / medium / long', 'auto')} text, then ${ph('action_items[] by due date', 'auto')}`,
      `<span class="static">Terms are measured from the incident's close time (report time while open), so regenerating never moves items. Undated items go under "Unscheduled".</span>`,
      `${where('text: Post-Incident → Lessons Learned → Remediation Plan · action items: Post-Incident → Lessons Learned → Action Items')}`,
    ]},
    { key: 'costs', items: [
      `Financial impact narrative: ${ph('business_impact.financial', 'auto')} ${where('Post-Incident → Costs & Impact → Business Impact Assessment')}`,
      `Totals per currency and by category + itemised costs: ${ph('costs[*] (category, description, amount, currency)', 'auto')} ${where('Post-Incident → Costs & Impact → Cost Tracking')}`,
    ]},
    { key: 'sign_off', items: [
      `Closed by · Closed at: ${ph('closure.closed_by / closed_at', 'auto')} ${where('Close (Post-Incident) in the incident header')} <span class="static">— "Not closed" while open</span>`,
      `Close sign-off statement: ${ph('closure.reason', 'auto')} <span class="static">— the reason given at Close</span>`,
      `Signature line per role: ${ph('sign_offs[*] (Incident Commander, Deputy, Legal Liaison, DPO → assignees)', 'auto')} ${where('Team')} <span class="static">— "Not assigned" when the role is empty; signature and date are left blank for ink</span>`,
      `Recorded gate sign-offs: ${ph('gate_sign_offs[*] (gate, role, signer, signed at, statement, gate-state SHA-256)', 'auto')} ${where('the Resolve / Close gate panel')} <span class="static">— append-only; ones made before a re-open are marked</span>`,
    ]},
  ]
  // Order and titles always follow REPORT_SECTIONS (the single source).
  const byKey = Object.fromEntries(list.map(s => [s.key, s]))
  return REPORT_SECTIONS.map(s => ({ items: [], ...byKey[s.key], ...s }))
}

// Mirrors the `appendices` array in generateProReport() — see KEEP IN SYNC above.
// Fixed letters: always-present appendices first, optional ones last.
function _skeletonAppendices(opts) {
  return [
    { letter: 'A', title: 'Affected Systems', included: true, items: [
      `Table: ${ph('affected_systems[*] (name, type, notes, added by, added at)', 'auto')} ${where('Details → Affected systems')}`,
    ]},
    { letter: 'B', title: 'Incident Timeline', included: !!opts.includeTimelineAppendix,
      hint: 'Optional — tick "Appendix B — Timeline" under Advanced options → Appendix.', items: [
      `Zig-zag timeline of every event: ${ph('timeline_events[*]', 'auto')} ${where('Timeline tab')}`,
    ]},
    { letter: opts.includeTimelineAppendix ? 'C' : 'B', title: 'Case Notes', included: (opts.mode || 'full') !== 'executive',
      hint: 'Full Technical Report only. Lettered after the Timeline appendix when that is included.', items: [
      `Table: ${ph('case_notes[*] (time, author, note as written — struck through when corrected, links, SHA-256)', 'auto')} ${where('Case notes')}`,
    ]},
  ]
}

export function generateSkeleton(opts = {}) {
  const {
    mode = 'full',
    classification = '',
    audience = '',
    footer = '',
    includeInternalEvents = false,
    sections: sectionToggles = {},
  } = opts
  const isExec = mode === 'executive'
  const include = (key) => sectionToggles[key] !== false
  const all = _skeletonSections()
  const shown = all.filter(s => !(isExec && s.fullOnly))
  const omitted = all.filter(s => isExec && s.fullOnly).map(s => s.title)
  const unticked = shown.filter(s => !include(s.key)).map(s => s.title)

  const summary = `
    <div class="sk-banner">
      Structure preview · <strong>${esc(isExec ? 'Executive Summary' : 'Full Technical Report')}</strong>
      ${classification ? ` · ${esc(classification)}` : ''}
      ${audience ? ` · for ${esc(audience)}` : ''}
      ${isExec ? `<div style="margin-top:6px">Left out of the executive report: ${omitted.map(esc).join(' · ')}.</div>` : ''}
      ${unticked.length ? `<div style="margin-top:6px">Unticked under "Include sections": ${unticked.map(esc).join(' · ')}.</div>` : ''}
      ${isExec && !includeInternalEvents ? '<div style="margin-top:6px">⚠ Timeline-based parts only use events flagged <code>external_safe</code> (tick "Include internal-only events" to override).</div>' : ''}
    </div>
    <div class="legend">
      <span>${ph('auto from incident data', 'auto')}</span>
      <span>${ph('your input on this page', 'user')}</span>
      <span>${where('where it is entered')}</span>
    </div>`

  const cover = `
    <div class="sk-section">
      <h3>Cover · document control · stats bar</h3>
      <ul>
        <li>Title · severity · TLP · phase · status badges: ${ph('incident.title / severity / tlp / phase / status', 'auto')}</li>
        <li>Document control: classification · severity · ${ph('incident.nciss_severity', 'auto')} (${NCISS_TITLE}) · phase · counts · report type</li>
        <li>Logo: ${ph('Branding → Company logo', 'user')}</li>
        <li>Incident ID: ${ph('incident.ref (e.g. INC-2026-00009)', 'auto')} · Opened: ${ph('incident.created_at', 'auto')} · Closed: ${ph('incident.closed_at', 'auto')} <span class="static">("Not closed" while open)</span> · Generated: ${ph('report time', 'auto')}</li>
        <li>Classification: ${ph('Advanced options → Classification marking', 'user')} or fallback ${ph('incident.tlp', 'auto')}</li>
        <li>Counts${include('kpis') ? '' : ' <span class="sk-tag">unticked — not printed</span>'}: ${ph('timeline events · IOCs (malicious) · entities · evidence items · playbook %', 'auto')}</li>
      </ul>
    </div>`

  // Unticked sections stay visible (greyed, unnumbered) so the structure stays honest;
  // numbering counts only the sections the report will actually print.
  let n = 0
  const secs = shown.map((s) => include(s.key) ? `
      <div class="sk-section">
        <h3><span class="sk-num">§ ${String(++n).padStart(2, '0')}</span>${esc(s.title)}${s.fullOnly ? '<span class="sk-tag">full report only</span>' : ''}</h3>
        <p class="sk-csf">NIST CSF 2.0: ${s.csf.map(esc).join(' · ')}</p>
        ${s.conditional ? `<p class="sk-cond">${esc(s.conditional)}</p>` : ''}
        <ul>${s.items.filter(Boolean).map(item => `<li>${item}</li>`).join('')}</ul>
      </div>` : `
      <div class="sk-section excluded">
        <span class="excluded-badge">Not included</span>
        <h3>${esc(s.title)}</h3>
        <p class="sk-cond">Unticked under Advanced options → Include sections.</p>
      </div>`).join('')

  const apps = _skeletonAppendices(opts).map(a => `
      <div class="sk-section${a.included ? '' : ' excluded'}">
        ${a.included ? '' : '<span class="excluded-badge">Not included</span>'}
        <h3><span class="sk-num">${a.letter}</span>Appendix ${a.letter} — ${esc(a.title)}</h3>
        <p class="sk-csf">NIST CSF 2.0: ${APPENDIX_CSF[a.title].map(esc).join(' · ')}</p>
        ${a.hint ? `<p class="sk-cond">${esc(a.hint)}</p>` : ''}
        <ul>${a.items.map(item => `<li>${item}</li>`).join('')}</ul>
      </div>`).join('')

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Report structure preview</title>
<style>${SKELETON_CSS}</style>
</head><body>
<h1>Report Structure</h1>
<p style="color:#8888aa;font-size:12px;margin-top:0">What the analyst sees on Preview / Download — every coloured pill is a field the system fills in for you.</p>
${summary}
${cover}
${secs}
${apps}
<div class="meta">Footer: ${footer ? `<span class="static">"${esc(footer)}"</span>` : ph('Branding → Footer text', 'user')} · incident UUID · generation time · TLP · SHA-256 integrity hash</div>
</body></html>`
}


// generateReport — delegates to the new pro template. `includeInternalEvents`
// still filters timeline events for executive mode. Legacy `templateId` values
// from the old THEMES map (mission_control / nordic / compact) fall back to
// the closest pro theme.
const LEGACY_TEMPLATE_MAP = {
  mission_control: 'tactical',
  nordic:          'executive',
  compact:         'print',
}

export function generateReport(data, opts = {}) {
  const {
    mode = 'full',
    includeInternalEvents = false,
    templateId = 'executive',
  } = opts

  const resolvedId = PRO_THEMES[templateId]
    ? templateId
    : (LEGACY_TEMPLATE_MAP[templateId] || 'executive')

  const filteredData = { ...data }
  if (mode === 'executive' && !includeInternalEvents) {
    filteredData.timeline_events = (data.timeline_events || [])
      .filter(ev => ev.external_safe !== false)
  }

  return generateProReport(filteredData, { ...opts, templateId: resolvedId })
}
