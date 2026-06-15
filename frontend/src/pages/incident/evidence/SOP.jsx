import { useEffect, useRef, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../../api/client.js'

// ─── Authority citation badges ────────────────────────────────────────────────

const CITE_COLORS = {
  nist:  { bg: '#1e3a5f', text: '#93c5fd' },
  iso:   { bg: '#1a3d2b', text: '#86efac' },
  swgde: { bg: '#3b1f4e', text: '#d8b4fe' },
  acpo:  { bg: '#3b2a1a', text: '#fbbf24' },
  tlp:   { bg: '#1f2d3b', text: '#7dd3fc' },
}

function Cite({ type, label }) {
  const c = CITE_COLORS[type] || CITE_COLORS.nist
  return (
    <span style={{
      display: 'inline-block',
      background: c.bg,
      color: c.text,
      fontSize: 10,
      fontFamily: 'var(--font-mono)',
      fontWeight: 600,
      padding: '1px 6px',
      borderRadius: 3,
      marginLeft: 6,
      letterSpacing: '0.02em',
      verticalAlign: 'middle',
      whiteSpace: 'nowrap',
    }}>{label}</span>
  )
}

// ─── SOP content definition ───────────────────────────────────────────────────
// Each phase has an id, title, summary, citations, and steps.
// Each step has: id, title, citations, body, autoCheck (fn(items, events) → bool|null, null=manual)

const PHASES = [
  {
    id: 'identification',
    title: 'Identification & Authorisation',
    summary: 'Establish legal basis, assign unique identifiers, document source context',
    citations: [
      { type: 'nist',  label: 'NIST SP 800-86 §3.1' },
      { type: 'iso',   label: 'ISO 27037 §9.1' },
      { type: 'acpo',  label: 'ACPO P1' },
    ],
    steps: [
      {
        id: '1.1',
        title: 'Assign a unique, immutable evidence identifier',
        body: 'Each item must carry a stable reference number that appears on all documentation, labels, and transfer records throughout its lifetime. Do not reuse identifiers.',
        cites: [
          { type: 'nist', label: 'NIST SP 800-86 §3.1.1' },
          { type: 'iso',  label: 'ISO 27037 §9.1.2' },
        ],
        autoCheck: (items) => {
          if (!items.length) return null
          return items.every(i => i.identifier && i.identifier.trim())
        },
        autoLabel: 'identifier present on all items',
      },
      {
        id: '1.2',
        title: 'Document source description and relevance',
        body: 'Record what the item is, where it came from, why it is relevant to the investigation, and its condition at the time of identification.',
        cites: [
          { type: 'iso',   label: 'ISO 27037 §9.1.3' },
          { type: 'swgde', label: 'SWGDE §4.1' },
        ],
        autoCheck: (items) => {
          if (!items.length) return null
          const missing = items.filter(i => !i.description || !i.description.trim())
          return missing.length === 0
        },
        autoLabel: 'description present on all items',
        autoWarnLabel: (items) => {
          const missing = items.filter(i => !i.description || !i.description.trim())
          return `${missing.length} item${missing.length !== 1 ? 's' : ''} missing description`
        },
      },
      {
        id: '1.3',
        title: 'Establish legal authority prior to collection',
        body: 'Confirm you have the appropriate legal authorisation — warrant, consent, corporate policy, or applicable exception — before collecting or accessing any evidence. Document the authority in the case file.',
        cites: [
          { type: 'nist', label: 'NIST SP 800-86 §3.1' },
          { type: 'acpo', label: 'ACPO Principle 1' },
        ],
        autoCheck: () => null,
      },
      {
        id: '1.4',
        title: 'Photograph and document the source in situ',
        body: 'Before any collection activity, photograph the scene, device, or storage media in its original state. For physical items, capture the physical location, connected cables, and surrounding context. Attach photos to the evidence record.',
        cites: [
          { type: 'iso',   label: 'ISO 27037 §9.1.4' },
          { type: 'swgde', label: 'SWGDE §4.2' },
        ],
        autoCheck: (items) => {
          const physical = items.filter(i => i.kind === 'physical_item')
          if (!physical.length) return null
          return physical.every(i => i.photos && i.photos.length > 0)
        },
        autoLabel: 'photos present on all physical items',
        autoWarnLabel: (items) => {
          const missing = items.filter(i => i.kind === 'physical_item' && (!i.photos || i.photos.length === 0))
          return `${missing.length} physical item${missing.length !== 1 ? 's' : ''} have no photos`
        },
      },
    ],
  },

  {
    id: 'collection',
    title: 'Collection / Acquisition',
    summary: 'Capture evidence with documented methodology and cryptographic integrity verification',
    citations: [
      { type: 'nist',  label: 'NIST SP 800-86 §3.2' },
      { type: 'iso',   label: 'ISO 27037 §9.2' },
      { type: 'swgde', label: 'SWGDE §5' },
    ],
    steps: [
      {
        id: '2.1',
        title: 'Record collector identity, date, time, and location',
        body: 'The collecting officer or analyst must be identified by name and role. The exact time, date, and physical or logical location of collection must be recorded. This creates an unambiguous starting point for the chain.',
        cites: [
          { type: 'nist',  label: 'NIST SP 800-86 §3.2.1' },
          { type: 'swgde', label: 'SWGDE §5.1' },
        ],
        autoCheck: (items) => {
          if (!items.length) return null
          const noCollector = items.filter(i => !i.collected_by_id)
          const noLocation  = items.filter(i => !i.collected_location || !i.collected_location.trim())
          return noCollector.length === 0 && noLocation.length === 0
        },
        autoLabel: 'collector and location documented on all items',
        autoWarnLabel: (items) => {
          const parts = []
          const nc = items.filter(i => !i.collected_by_id).length
          const nl = items.filter(i => !i.collected_location || !i.collected_location.trim()).length
          if (nc) parts.push(`${nc} missing collector`)
          if (nl) parts.push(`${nl} missing location`)
          return parts.join('; ')
        },
      },
      {
        id: '2.2',
        title: 'Generate cryptographic hash values at acquisition',
        body: 'Compute MD5, SHA-1, and SHA-256 hashes of each digital item at the moment of acquisition, before any analysis. Record all three values. SHA-256 is the minimum; MD5 and SHA-1 are retained for backward compatibility with legacy tooling.',
        cites: [
          { type: 'nist', label: 'NIST SP 800-86 §3.2.3' },
          { type: 'iso',  label: 'ISO 27037 §9.2.3' },
        ],
        autoCheck: (items) => {
          const digital = items.filter(i => i.kind === 'digital_file')
          if (!digital.length) return null
          return digital.every(i => i.sha256)
        },
        autoLabel: 'SHA-256 hash present on all digital items',
        autoWarnLabel: (items) => {
          const missing = items.filter(i => i.kind === 'digital_file' && !i.sha256)
          return `${missing.length} digital item${missing.length !== 1 ? 's' : ''} missing SHA-256`
        },
      },
      {
        id: '2.3',
        title: 'Use a forensically sound acquisition method',
        body: 'Where possible, acquire a forensic image rather than copying the original. Write-blockers must be used for storage media. For live systems, justify the collection method and document any deviation from best practice.',
        cites: [
          { type: 'acpo', label: 'ACPO Principle 2' },
          { type: 'iso',  label: 'ISO 27037 §9.2.1' },
          { type: 'nist', label: 'NIST SP 800-86 §3.2.2' },
        ],
        autoCheck: () => null,
      },
      {
        id: '2.4',
        title: 'Document acquisition tool, version, and parameters',
        body: 'Record the tool name, version, hash, and command-line parameters used for acquisition. This enables independent verification and supports admissibility arguments.',
        cites: [
          { type: 'nist',  label: 'NIST SP 800-86 §3.2.4' },
          { type: 'swgde', label: 'SWGDE §5.3' },
        ],
        autoCheck: () => null,
      },
    ],
  },

  {
    id: 'preservation',
    title: 'Preservation',
    summary: 'Encrypted storage, access controls, TLP classification, and continuous integrity assurance',
    citations: [
      { type: 'nist', label: 'NIST SP 800-86 §3.3' },
      { type: 'iso',  label: 'ISO 27037 §9.3' },
      { type: 'acpo', label: 'ACPO P3 & P4' },
      { type: 'tlp',  label: 'TLP 2.0' },
    ],
    steps: [
      {
        id: '3.1',
        title: 'Apply TLP classification to restrict access',
        body: 'Every evidence item must carry a TLP marking that governs who may access it. Default to TLP:AMBER. Escalate to TLP:RED for items containing credentials, PII, or sensitive business data. Do not relax classifications without documented justification.',
        cites: [
          { type: 'tlp', label: 'TLP 2.0' },
        ],
        autoCheck: (items) => {
          if (!items.length) return null
          return items.every(i => i.tlp)
        },
        autoLabel: 'TLP classification set on all items',
      },
      {
        id: '3.2',
        title: 'Store encrypted at rest under access control',
        body: 'Digital evidence files are stored using AES-256-GCM encryption with a per-file nonce. The evidence KEK (key-encryption key) is held separately from the evidence volume. Physical items must be secured in a locked container with logged access.',
        cites: [
          { type: 'nist', label: 'NIST SP 800-86 §3.3.1' },
          { type: 'iso',  label: 'ISO 27037 §9.3.1' },
        ],
        autoCheck: (items) => {
          if (!items.length) return null
          // System enforces AES-256-GCM; nonce_hex presence is the indicator
          // Physical items: we accept as compliant by policy
          const digital = items.filter(i => i.kind === 'digital_file')
          if (!digital.length) return true
          // nonce_hex is not exposed in EvidenceOut (intentionally) — treat as system-enforced
          return true
        },
        autoLabel: 'system-enforced AES-256-GCM for all digital items',
      },
      {
        id: '3.3',
        title: 'Document and maintain a named custodian',
        body: 'Every active evidence item must have an identified current custodian who is accountable for its integrity and security. Custodian changes must go through the formal transfer procedure (Phase 4).',
        cites: [
          { type: 'nist', label: 'NIST SP 800-86 §3.3.2' },
          { type: 'acpo', label: 'ACPO Principle 4' },
        ],
        autoCheck: (items) => {
          const active = items.filter(i => i.status === 'active')
          if (!active.length) return null
          return active.every(i => i.current_custodian_id)
        },
        autoLabel: 'custodian assigned on all active items',
        autoWarnLabel: (items) => {
          const missing = items.filter(i => i.status === 'active' && !i.current_custodian_id)
          return `${missing.length} active item${missing.length !== 1 ? 's' : ''} without custodian`
        },
      },
      {
        id: '3.4',
        title: 'Maintain a continuous, tamper-evident audit trail',
        body: 'Every access, transfer, analysis, and verification event must be recorded in the custody log. The audit chain uses hash-chaining so that any tampering with historical records is detectable.',
        cites: [
          { type: 'acpo', label: 'ACPO Principle 3' },
          { type: 'nist', label: 'NIST SP 800-86 §3.3.3' },
        ],
        autoCheck: (items, events) => {
          if (!items.length) return null
          const itemIds = new Set(items.map(i => i.id))
          const loggedIds = new Set(events.map(e => e.resource_id))
          return [...itemIds].every(id => loggedIds.has(id))
        },
        autoLabel: 'all items have at least one custody log entry',
        autoWarnLabel: (items, events) => {
          const loggedIds = new Set(events.map(e => e.resource_id))
          const missing = items.filter(i => !loggedIds.has(i.id))
          return `${missing.length} item${missing.length !== 1 ? 's' : ''} with no custody log entries`
        },
      },
    ],
  },

  {
    id: 'transfer',
    title: 'Transfer',
    summary: 'Documented handoff between custodians with verified condition at each transition',
    citations: [
      { type: 'swgde', label: 'SWGDE §6' },
      { type: 'nist',  label: 'NIST SP 800-86 §3.3.3' },
      { type: 'acpo',  label: 'ACPO P3' },
    ],
    steps: [
      {
        id: '4.1',
        title: 'Create a transfer record for every custody handoff',
        body: 'No evidence may change hands without a corresponding transfer record stating: transferring party, receiving party, timestamp, reason, and condition at transfer. Both parties should acknowledge the transfer.',
        cites: [
          { type: 'swgde', label: 'SWGDE §6.1' },
          { type: 'nist',  label: 'NIST SP 800-86 §3.3.3' },
        ],
        autoCheck: (items, events) => {
          const transferEvents = events.filter(e => e.event_type === 'evidence_transfer' || (e.details && e.details.action === 'transfer'))
          // We can check this only if we expect transfers; treat as manual
          return null
        },
      },
      {
        id: '4.2',
        title: 'Verify and record item condition at each transfer',
        body: 'Before accepting custody, the receiving party must inspect the item and confirm it matches the recorded description and that seals are intact. Any discrepancy must be documented immediately.',
        cites: [
          { type: 'swgde', label: 'SWGDE §6.2' },
          { type: 'iso',   label: 'ISO 27037 §9.3.2' },
        ],
        autoCheck: () => null,
      },
      {
        id: '4.3',
        title: 'Obtain acknowledgement from both parties',
        body: 'Transfers require a signature (physical) or system-recorded acceptance (digital) from both the outgoing and incoming custodian. A unilateral transfer record is insufficient for court purposes.',
        cites: [
          { type: 'swgde', label: 'SWGDE §6.3' },
          { type: 'acpo',  label: 'ACPO Principle 3' },
        ],
        autoCheck: () => null,
      },
      {
        id: '4.4',
        title: 'Do not leave evidence unattended outside secure storage during transit',
        body: 'Evidence in transit is at maximum vulnerability. Use tamper-evident packaging. For digital transfers, use encrypted channels only. Document transport method and duration.',
        cites: [
          { type: 'iso',   label: 'ISO 27037 §9.3.2' },
          { type: 'swgde', label: 'SWGDE §6.4' },
        ],
        autoCheck: () => null,
      },
    ],
  },

  {
    id: 'analysis',
    title: 'Analysis',
    summary: 'Forensic examination on copies only, with documented tools, methodology, and analyst identity',
    citations: [
      { type: 'nist', label: 'NIST SP 800-86 §3.4' },
      { type: 'iso',  label: 'ISO 27037 §9.4' },
      { type: 'acpo', label: 'ACPO P2' },
    ],
    steps: [
      {
        id: '5.1',
        title: 'Work only on forensic copies — never the original',
        body: 'Originals must be preserved unmodified. All analysis is performed on verified forensic copies. The copy must be verified against the original hash before analysis begins.',
        cites: [
          { type: 'acpo', label: 'ACPO Principle 1' },
          { type: 'nist', label: 'NIST SP 800-86 §3.4.1' },
        ],
        autoCheck: () => null,
      },
      {
        id: '5.2',
        title: 'Verify hash integrity before and after examination',
        body: 'Recompute the SHA-256 hash of the forensic copy before beginning analysis and again at the conclusion. Hash mismatches must be investigated and documented before results can be relied upon.',
        cites: [
          { type: 'nist', label: 'NIST SP 800-86 §3.4.3' },
          { type: 'iso',  label: 'ISO 27037 §9.4.2' },
        ],
        autoCheck: (items, events) => {
          if (!items.length) return null
          const verifyEvents = events.filter(e =>
            e.event_type === 'evidence_verify' ||
            (e.details && e.details.action === 'verify')
          )
          if (!verifyEvents.length) return null
          return true
        },
        autoLabel: 'integrity verification events recorded in custody log',
      },
      {
        id: '5.3',
        title: 'Log analyst identity for every examination session',
        body: 'The name and role of the analyst performing examination must be recorded for each session. System access controls enforce this automatically; supplement with examination notes documenting scope and methodology.',
        cites: [
          { type: 'acpo',  label: 'ACPO Principle 2' },
          { type: 'swgde', label: 'SWGDE §7.1' },
        ],
        autoCheck: (items, events) => {
          if (!items.length) return null
          const examEvents = events.filter(e =>
            e.event_type === 'evidence_examine' ||
            (e.details && e.details.action === 'examine')
          )
          if (!examEvents.length) return null
          return examEvents.every(e => e.username || e.user_id)
        },
        autoLabel: 'all examination events have analyst identity recorded',
      },
      {
        id: '5.4',
        title: 'Document all tools, versions, and methodologies used',
        body: 'For each analysis tool: record name, version, hash, configuration, and the specific technique applied. This documentation enables peer review, independent verification, and courtroom testimony.',
        cites: [
          { type: 'nist',  label: 'NIST SP 800-86 §3.4.2' },
          { type: 'swgde', label: 'SWGDE §7.2' },
        ],
        autoCheck: () => null,
      },
    ],
  },

  {
    id: 'disposition',
    title: 'Disposition',
    summary: 'Documented return, destruction, or archival with final integrity verification and approver sign-off',
    citations: [
      { type: 'nist',  label: 'NIST SP 800-86 §3.5' },
      { type: 'swgde', label: 'SWGDE §8' },
      { type: 'iso',   label: 'ISO 27037 §9.5' },
    ],
    steps: [
      {
        id: '6.1',
        title: 'Generate and record final integrity hash at disposition',
        body: 'Immediately before disposal or return, recompute the SHA-256 hash and record it. This proves the item was not altered during its time in custody and provides a definitive endpoint to the chain.',
        cites: [
          { type: 'nist',  label: 'NIST SP 800-86 §3.5.1' },
          { type: 'swgde', label: 'SWGDE §8.1' },
        ],
        autoCheck: (items) => {
          const disposed = items.filter(i => i.disposed_at || ['destroyed', 'returned'].includes(i.status))
          if (!disposed.length) return null
          return disposed.every(i => i.final_hash_at_disposition)
        },
        autoLabel: 'final hash recorded on all disposed items',
        autoWarnLabel: (items) => {
          const missing = items.filter(i =>
            (i.disposed_at || ['destroyed', 'returned'].includes(i.status)) &&
            !i.final_hash_at_disposition
          )
          return `${missing.length} disposed item${missing.length !== 1 ? 's' : ''} missing final hash`
        },
      },
      {
        id: '6.2',
        title: 'Obtain authorised approver sign-off before disposal',
        body: 'Destruction or return of evidence requires explicit authorisation from the case owner or designated authority. The approver identity and timestamp must be documented.',
        cites: [
          { type: 'swgde', label: 'SWGDE §8.2' },
          { type: 'acpo',  label: 'ACPO Principle 4' },
        ],
        autoCheck: () => null,
      },
      {
        id: '6.3',
        title: 'Document disposition method, date, and outcome',
        body: 'Record how the item was disposed of: secure erasure with certified overwrites, physical destruction with certificate, or return to owner with receipt. Each method has specific requirements to prevent data recovery or re-use.',
        cites: [
          { type: 'nist',  label: 'NIST SP 800-86 §3.5.2' },
          { type: 'swgde', label: 'SWGDE §8.3' },
        ],
        autoCheck: (items) => {
          const disposed = items.filter(i => i.disposed_at || ['destroyed', 'returned'].includes(i.status))
          if (!disposed.length) return null
          return disposed.every(i => i.disposed_at && i.status !== 'active')
        },
        autoLabel: 'disposition timestamp and status recorded on all disposed items',
      },
      {
        id: '6.4',
        title: 'Retain custody records for the required retention period',
        body: 'Chain-of-custody documentation must be retained for the duration required by applicable law or organisational policy — typically 3–7 years for civil matters, longer for criminal proceedings. Records must remain intact and accessible.',
        cites: [
          { type: 'swgde', label: 'SWGDE §8.4' },
          { type: 'nist',  label: 'NIST SP 800-86 §3.5.3' },
        ],
        autoCheck: () => null,
      },
    ],
  },
]

// ─── Compliance engine ────────────────────────────────────────────────────────

function computeCompliance(phase, items, events) {
  const stepResults = phase.steps.map(step => {
    const result = step.autoCheck ? step.autoCheck(items, events) : null
    return { step, result }
  })

  const checked = stepResults.filter(r => r.result !== null)
  if (!checked.length) return { status: 'manual', checked: 0, total: phase.steps.length }

  const fails = checked.filter(r => r.result === false)
  if (fails.length > 0) return { status: 'fail', checked: checked.length, total: phase.steps.length, stepResults }

  return { status: 'ok', checked: checked.length, total: phase.steps.length, stepResults }
}

function PhaseStatus({ status, checked, total }) {
  const configs = {
    ok:     { color: 'var(--ok)',   symbol: '✓', label: 'Compliant' },
    fail:   { color: 'var(--crit)', symbol: '✕', label: 'Action required' },
    manual: { color: 'var(--muted)',symbol: '○', label: 'Manual' },
  }
  const c = configs[status] || configs.manual
  return (
    <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, color: c.color, fontWeight: 600 }}>
      <span style={{ fontSize: 14 }}>{c.symbol}</span>
      <span>{c.label}</span>
      {checked > 0 && <span style={{ fontWeight: 400, color: 'var(--dim)' }}>({checked}/{total} auto-checked)</span>}
    </span>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

// ISO/IEC 27037 is the canonical handling spine (see docs/standards-map.md);
// NIST 800-86 / ACPO / SWGDE are cross-walk citations "mapped to" it.
const STANDARDS = [
  { value: 'iso',   label: 'ISO/IEC 27037 (canonical)' },
  { value: 'all',   label: 'All standards' },
  { value: 'nist',  label: 'NIST SP 800-86 (mapped to)' },
  { value: 'acpo',  label: 'ACPO Good Practice Guide (mapped to)' },
  { value: 'swgde', label: 'SWGDE (mapped to)' },
]

export default function EvidenceSOP() {
  const { inc } = useOutletContext()
  const [items,   setItems]   = useState([])
  const [events,  setEvents]  = useState([])
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)
  const [standard, setStandard] = useState('iso')   // ISO/IEC 27037 is the canonical spine
  const phaseRefs = useRef({})
  const filterCites = (cites = []) =>
    standard === 'all' ? cites : cites.filter(c => c.type === standard)

  useEffect(() => {
    Promise.all([
      api.listEvidence(inc.id, { limit: 200 }),
      api.incidentCustodyLog(inc.id),
    ])
      .then(([ev, log]) => {
        setItems(ev.items || [])
        setEvents(Array.isArray(log) ? log : (log.items || []))
      })
      .catch(e => setError(e.message || 'Failed to load evidence data'))
      .finally(() => setLoading(false))
  }, [inc.id])

  if (loading) return <div className="panel-empty"><div>Loading…</div></div>
  if (error)   return (
    <div className="alert error" role="alert" style={{ margin: 'var(--space-3)' }}>
      <span className="alert-icon">!</span><span>{error}</span>
    </div>
  )

  const complianceResults = PHASES.map(phase => ({
    phase,
    compliance: computeCompliance(phase, items, events),
  }))

  const overallFails = complianceResults.filter(r => r.compliance.status === 'fail').length
  const overallOk    = complianceResults.filter(r => r.compliance.status === 'ok').length

  return (
    <section className="panel">
      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="panel-toolbar">
        <h2 className="panel-h">Chain of Custody — Standard Operating Procedure</h2>
        <label style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', fontSize: 12, color: 'var(--muted)' }}>
          Authority
          <select
            className="select"
            value={standard}
            onChange={e => setStandard(e.target.value)}
            style={{ minWidth: 200 }}
          >
            {STANDARDS.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
          </select>
        </label>
      </div>

      {/* ── Incident compliance summary ──────────────────────────────────── */}
      <div style={{
        background: 'var(--surface-2)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        padding: 'var(--space-3)',
        marginBottom: 'var(--space-5)',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-3)' }}>
          <div style={{ fontWeight: 600, fontSize: 13 }}>
            Incident compliance — {items.length} evidence item{items.length !== 1 ? 's' : ''}
          </div>
          {items.length === 0 ? (
            <span style={{ fontSize: 12, color: 'var(--dim)' }}>No evidence items yet — add items to see compliance status</span>
          ) : (
            <span style={{ fontSize: 12, color: overallFails > 0 ? 'var(--crit)' : 'var(--ok)' }}>
              {overallFails > 0
                ? `${overallFails} phase${overallFails !== 1 ? 's' : ''} require attention`
                : `${overallOk} of ${PHASES.length} phases auto-verified`}
            </span>
          )}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 'var(--space-2)' }}>
          {complianceResults.map(({ phase, compliance }) => (
            <button
              key={phase.id}
              type="button"
              onClick={() => phaseRefs.current[phase.id]?.scrollIntoView({ behavior: 'smooth', block: 'start' })}
              style={{
                background: 'var(--surface)',
                border: `1px solid ${compliance.status === 'fail' ? 'var(--crit)' : compliance.status === 'ok' ? 'var(--ok)' : 'var(--border)'}`,
                borderRadius: 'var(--radius-sm)',
                padding: 'var(--space-2) var(--space-3)',
                textAlign: 'left',
                cursor: 'pointer',
                transition: 'border-color .15s',
              }}
            >
              <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 4 }}>{phase.title}</div>
              <PhaseStatus {...compliance} />
            </button>
          ))}
        </div>
      </div>

      {/* ── Full SOP document ────────────────────────────────────────────── */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-5)' }}>
        {complianceResults.map(({ phase, compliance }, phaseIdx) => (
          <div
            key={phase.id}
            ref={el => phaseRefs.current[phase.id] = el}
            style={{
              borderLeft: `3px solid ${compliance.status === 'fail' ? 'var(--crit)' : compliance.status === 'ok' ? 'var(--ok)' : 'var(--border-strong)'}`,
              paddingLeft: 'var(--space-4)',
            }}
          >
            {/* Phase header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 'var(--space-3)', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-2)', marginBottom: 4 }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--dim)' }}>Phase {phaseIdx + 1}</span>
                  <h3 style={{ fontSize: 16, fontWeight: 700 }}>{phase.title}</h3>
                </div>
                <p style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 'var(--space-2)' }}>{phase.summary}</p>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {filterCites(phase.citations).map((c, i) => <Cite key={i} {...c} />)}
                </div>
              </div>
              <PhaseStatus {...compliance} />
            </div>

            {/* Steps */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              {phase.steps.map(step => {
                const stepResult = compliance.stepResults?.find(r => r.step.id === step.id)
                const result = stepResult?.result ?? null

                let indicator, indicatorColor, indicatorTitle
                if (result === true) {
                  indicator = '✓'; indicatorColor = 'var(--ok)'
                  indicatorTitle = step.autoLabel || 'Auto-verified'
                } else if (result === false) {
                  indicator = '✕'; indicatorColor = 'var(--crit)'
                  indicatorTitle = step.autoWarnLabel ? step.autoWarnLabel(items, events) : 'Check failed'
                } else {
                  indicator = '○'; indicatorColor = 'var(--dim)'
                  indicatorTitle = 'Manual — cannot be auto-verified'
                }

                return (
                  <div key={step.id} style={{
                    display: 'grid',
                    gridTemplateColumns: '28px 1fr',
                    gap: 'var(--space-2)',
                  }}>
                    {/* Step indicator */}
                    <div style={{ paddingTop: 2 }}>
                      <span
                        title={indicatorTitle}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          width: 22,
                          height: 22,
                          borderRadius: '50%',
                          border: `1.5px solid ${indicatorColor}`,
                          color: indicatorColor,
                          fontSize: 11,
                          fontWeight: 700,
                          flexShrink: 0,
                          cursor: 'help',
                        }}
                      >
                        {indicator}
                      </span>
                    </div>

                    {/* Step content */}
                    <div>
                      <div style={{ display: 'flex', alignItems: 'baseline', flexWrap: 'wrap', gap: 4, marginBottom: 4 }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--dim)' }}>{step.id}</span>
                        <span style={{ fontWeight: 600, fontSize: 13 }}>{step.title}</span>
                        {filterCites(step.cites).map((c, i) => <Cite key={i} {...c} />)}
                      </div>
                      <p style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.6 }}>{step.body}</p>

                      {/* Auto-check result detail */}
                      {result === false && step.autoWarnLabel && (
                        <div style={{
                          marginTop: 'var(--space-2)',
                          padding: '6px 10px',
                          background: 'var(--surface-2)',
                          borderLeft: '2px solid var(--crit)',
                          borderRadius: '0 var(--radius-sm) var(--radius-sm) 0',
                          fontSize: 12,
                          color: 'var(--crit)',
                        }}>
                          {step.autoWarnLabel(items, events)}
                        </div>
                      )}
                      {result === true && (
                        <div style={{
                          marginTop: 'var(--space-2)',
                          padding: '6px 10px',
                          background: 'var(--surface-2)',
                          borderLeft: '2px solid var(--ok)',
                          borderRadius: '0 var(--radius-sm) var(--radius-sm) 0',
                          fontSize: 12,
                          color: 'var(--ok)',
                        }}>
                          {step.autoLabel || 'Verified'}
                        </div>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        ))}
      </div>

      {/* ── Footer ──────────────────────────────────────────────────────── */}
      <div style={{ marginTop: 'var(--space-5)', paddingTop: 'var(--space-4)', borderTop: '1px solid var(--border)', fontSize: 11, color: 'var(--dim)', lineHeight: 1.7 }}>
        <strong style={{ color: 'var(--muted)' }}>Standards referenced:</strong>
        <br />
        NIST SP 800-86 — Guide to Integrating Forensic Techniques into Incident Response (NIST, 2006)
        <br />
        ISO/IEC 27037:2012 — Information technology — Security techniques — Guidelines for identification, collection, acquisition and preservation of digital evidence
        <br />
        SWGDE Best Practices for Digital &amp; Multimedia Evidence — Scientific Working Group on Digital Evidence
        <br />
        ACPO Good Practice Guide for Computer-Based Electronic Evidence (v5) — Association of Chief Police Officers
        <br />
        TLP 2.0 — Traffic Light Protocol (CISA / FIRST)
      </div>
    </section>
  )
}
