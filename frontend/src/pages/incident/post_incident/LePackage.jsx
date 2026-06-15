import { useCallback, useEffect, useState } from 'react'
import { api } from '../../../api/client.js'
import { useAuth } from '../../../hooks/useAuth.jsx'
import { formatLocalShort } from '../../../lib/datetime.js'
import HandoffWizard from './HandoffWizard.jsx'
import UtcDateTimeInput from '../../../components/UtcDateTimeInput.jsx'

// ─── Helpers ──────────────────────────────────────────────────────────────────

const LEGAL_BASIS_OPTIONS = [
  { value: 'warrant',     label: 'Warrant' },
  { value: 'subpoena',    label: 'Subpoena' },
  { value: 'court_order', label: 'Court order' },
  { value: 'mla',         label: 'MLAT (mutual legal assistance)' },
  { value: 'voluntary',   label: 'Voluntary disclosure' },
  { value: 'other',       label: 'Other (document in case file)' },
]

const STATUS_TONE = {
  ready:    { fg: 'var(--ok)',   bg: 'rgba(34,197,94,0.10)',  label: 'Ready' },
  consumed: { fg: 'var(--muted)', bg: 'var(--surface-2)',     label: 'Downloaded' },
  expired:  { fg: 'var(--muted)', bg: 'var(--surface-2)',     label: 'Expired' },
  revoked:  { fg: 'var(--crit)', bg: 'rgba(239,68,68,0.10)',  label: 'Revoked' },
}

function fmtBytes(n) {
  if (n == null) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MiB`
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GiB`
}

function StatusPill({ status }) {
  const tone = STATUS_TONE[status] || { fg: 'var(--text)', bg: 'var(--surface-2)', label: status || '—' }
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px',
      borderRadius: 'var(--radius-sm)', fontSize: 11,
      color: tone.fg, background: tone.bg,
      border: `1px solid ${tone.fg}`,
    }}>{tone.label}</span>
  )
}

function Hash({ value, short = true }) {
  if (!value) return <span style={{ color: 'var(--muted)' }}>—</span>
  const display = short ? `${value.slice(0, 12)}…${value.slice(-4)}` : value
  return (
    <span
      style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text)' }}
      title={value}
    >{display}</span>
  )
}

// ─── Issued-modal ─────────────────────────────────────────────────────────────

function IssuedModal({ issued, onClose }) {
  const [copiedKey, setCopiedKey] = useState(false)
  const [copiedUrl, setCopiedUrl] = useState(false)

  async function copy(text, setter) {
    try {
      await navigator.clipboard.writeText(text)
      setter(true)
      setTimeout(() => setter(false), 1500)
    } catch {
      // navigator.clipboard may be blocked; ignore — user can select+copy.
    }
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      zIndex: 50,
    }}>
      <div style={{
        background: 'var(--surface)', border: '1px solid var(--border)',
        borderRadius: 'var(--radius-lg)', padding: 'var(--space-4)',
        width: 720, maxWidth: '95vw', maxHeight: '90vh', overflow: 'auto',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-3)' }}>
          <span style={{
            display: 'inline-block', width: 10, height: 10, borderRadius: '50%',
            background: 'var(--crit)',
          }} />
          <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700 }}>LE package ready — shown ONCE</h3>
        </div>

        <p style={{ margin: 0, fontSize: 13, color: 'var(--muted)' }}>
          The bundle is an <strong>AES-256 password-protected ZIP</strong> — the
          recipient opens it with any standard archive tool (macOS Finder,
          7-Zip / WinRAR, <code>unzip -P</code>). Hand the password to the
          requesting authority over a separate channel. The platform will
          <strong> not</strong> show this password again.
        </p>

        <div style={{ marginTop: 'var(--space-3)', display: 'grid', gap: 'var(--space-3)' }}>
          <div>
            <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
              Bundle password (AES-256 ZIP)
            </label>
            <div style={{ display: 'flex', gap: 4 }}>
              <input
                readOnly
                value={issued.bundle_password}
                style={{
                  flex: 1, fontFamily: 'var(--font-mono)', fontSize: 13,
                  background: 'var(--surface-2)', border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)', padding: '6px 8px', color: 'var(--text)',
                }}
                onFocus={(e) => e.target.select()}
              />
              <button className="btn" onClick={() => copy(issued.bundle_password, setCopiedKey)}>
                {copiedKey ? '✓ copied' : 'Copy'}
              </button>
            </div>
          </div>

          <div>
            <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
              Password-protected ZIP (single-use, 24h)
            </label>
            <div style={{ display: 'flex', gap: 4, marginTop: 4 }}>
              <a
                className="btn primary"
                href={issued.download_url}
                download
                style={{ flex: 1, textAlign: 'center', textDecoration: 'none' }}
              >
                ↓ Download bundle (.zip)
              </a>
              <button
                type="button"
                className="btn"
                title="Copy URL — share with recipient out of band"
                onClick={() => copy(issued.download_url, setCopiedUrl)}
              >
                {copiedUrl ? '✓ URL copied' : 'Copy URL'}
              </button>
            </div>
            <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4 }}>
              Token is consumed on first successful download — clicking either button burns it.
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-3)' }}>
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                Bundle SHA-256
              </label>
              <div style={{ marginTop: 2 }}><Hash value={issued.bundle_sha256} short={false} /></div>
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                Manifest SHA-256
              </label>
              <div style={{ marginTop: 2 }}><Hash value={issued.manifest_sha256} short={false} /></div>
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                HMAC-SHA-256 (sender of record)
              </label>
              <div style={{ marginTop: 2 }}><Hash value={issued.hmac_sha256} short={false} /></div>
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                Audit anchor row hash
              </label>
              <div style={{ marginTop: 2 }}><Hash value={issued.audit_anchor_row_hash} short={false} /></div>
            </div>
          </div>

          <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.5 }}>
            <strong>Files:</strong> {issued.file_count?.toLocaleString() || 0} ·{' '}
            <strong>Size:</strong> {fmtBytes(issued.total_bytes)} ·{' '}
            <strong>Evidence items:</strong> {issued.evidence_count?.toLocaleString() || 0} ·{' '}
            <strong>Audit rows:</strong> {issued.audit_row_count?.toLocaleString() || 0}
          </div>

          {issued.acknowledgment_url && (
            <div style={{
              padding: 'var(--space-3)', background: 'var(--accent-soft)',
              border: '1px solid var(--accent)', borderRadius: 'var(--radius)',
            }}>
              <div style={{ fontSize: 11, color: 'var(--accent)', textTransform: 'uppercase',
                            letterSpacing: 0.5, fontWeight: 700, marginBottom: 4 }}>
                Recipient acknowledgment URL (single-use)
              </div>
              <div style={{
                fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all',
                padding: '6px 8px', background: 'var(--surface-2)',
                border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)',
                userSelect: 'all',
              }}>
                {window.location.origin}{issued.acknowledgment_url}
              </div>
              <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4, lineHeight: 1.5 }}>
                Print on the handoff form (or render as QR). When the recipient submits the
                acknowledgment, the chain is closed in the platform's audit log.
                Token is consumed on first submission.
              </div>
            </div>
          )}
        </div>

        <div style={{ marginTop: 'var(--space-4)', display: 'flex', justifyContent: 'flex-end' }}>
          <button className="btn primary" onClick={onClose}>I've recorded the password — close</button>
        </div>
      </div>
    </div>
  )
}

// ─── Generate-modal ──────────────────────────────────────────────────────────

function GenerateModal({ inc, onClose, onIssued }) {
  const [form, setForm] = useState({
    case_reference: '',
    requesting_authority: '',
    legal_basis: 'warrant',
    retention_until: '',
    legal_hold_only: false,
    include_artifacts: false,
    recipient: '',
  })
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  function set(k, v) { setForm(f => ({ ...f, [k]: v })) }

  async function submit() {
    setError(null)
    setSubmitting(true)
    try {
      const payload = {
        case_reference:       form.case_reference.trim(),
        requesting_authority: form.requesting_authority.trim(),
        legal_basis:          form.legal_basis,
        legal_hold_only:      form.legal_hold_only,
        include_artifacts:    form.include_artifacts,
      }
      if (form.retention_until) payload.retention_until = new Date(form.retention_until).toISOString()
      if (form.recipient.trim()) payload.recipient = form.recipient.trim()

      const issued = await api.prepareLePackage(inc.id, payload)
      onIssued(issued)
    } catch (e) {
      setError(e.message || 'Generation failed')
    } finally {
      setSubmitting(false)
    }
  }

  const canSubmit = form.case_reference.trim() && form.requesting_authority.trim() && !submitting

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      zIndex: 50,
    }}>
      <div style={{
        background: 'var(--surface)', border: '1px solid var(--border)',
        borderRadius: 'var(--radius-lg)', padding: 'var(--space-4)',
        width: 600, maxWidth: '95vw', maxHeight: '90vh', overflow: 'auto',
      }}>
        <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700 }}>Generate LE package</h3>
        <p style={{ margin: '4px 0 var(--space-3)', fontSize: 12, color: 'var(--muted)' }}>
          Builds an AES-256 password-protected ZIP for hand-off to law enforcement. The bundle
          password is shown <strong>once</strong>; record it before closing the issued-modal.
        </p>

        {error && (
          <div style={{
            margin: '0 0 var(--space-3)', padding: '8px 10px',
            background: 'rgba(239,68,68,0.10)', border: '1px solid var(--crit)',
            borderRadius: 'var(--radius-sm)', color: 'var(--crit)', fontSize: 12,
          }}>{error}</div>
        )}

        <div style={{ display: 'grid', gap: 'var(--space-3)' }}>
          <div>
            <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
              Case reference *
            </label>
            <input
              autoFocus
              value={form.case_reference}
              onChange={(e) => set('case_reference', e.target.value)}
              maxLength={128}
              placeholder="e.g. STK-2026-00114"
              style={{
                width: '100%', fontFamily: 'var(--font-mono)', fontSize: 12,
                background: 'var(--surface-2)', border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)', padding: '6px 8px', color: 'var(--text)',
              }}
            />
          </div>
          <div>
            <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
              Requesting authority *
            </label>
            <input
              value={form.requesting_authority}
              onChange={(e) => set('requesting_authority', e.target.value)}
              maxLength={256}
              placeholder="e.g. Stockholm County Police"
              style={{
                width: '100%', fontSize: 13,
                background: 'var(--surface-2)', border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)', padding: '6px 8px', color: 'var(--text)',
              }}
            />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-3)' }}>
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                Legal basis *
              </label>
              <select
                value={form.legal_basis}
                onChange={(e) => set('legal_basis', e.target.value)}
                style={{
                  width: '100%', fontSize: 13,
                  background: 'var(--surface-2)', border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)', padding: '6px 8px', color: 'var(--text)',
                }}
              >
                {LEGAL_BASIS_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                Retention until (optional)
              </label>
              <input
                type="date"
                value={form.retention_until}
                onChange={(e) => set('retention_until', e.target.value)}
                style={{
                  width: '100%', fontSize: 13,
                  background: 'var(--surface-2)', border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)', padding: '6px 8px', color: 'var(--text)',
                }}
              />
            </div>
          </div>
          <div>
            <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
              Recipient label (optional)
            </label>
            <input
              value={form.recipient}
              onChange={(e) => set('recipient', e.target.value)}
              maxLength={256}
              placeholder="Defaults to the requesting authority"
              style={{
                width: '100%', fontSize: 13,
                background: 'var(--surface-2)', border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)', padding: '6px 8px', color: 'var(--text)',
              }}
            />
          </div>

          <fieldset style={{
            border: '1px solid var(--border)', borderRadius: 'var(--radius)',
            padding: 'var(--space-2) var(--space-3)',
          }}>
            <legend style={{ fontSize: 11, color: 'var(--muted)', padding: '0 4px' }}>Build options</legend>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6, fontSize: 13, cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={form.legal_hold_only}
                onChange={(e) => set('legal_hold_only', e.target.checked)}
              />
              <span>
                Only include evidence flagged <code style={{ fontFamily: 'var(--font-mono)' }}>legal_hold = true</code>
              </span>
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={form.include_artifacts}
                onChange={(e) => set('include_artifacts', e.target.checked)}
              />
              <span>
                Include quarantine artifacts (wrapped in <code style={{ fontFamily: 'var(--font-mono)' }}>infected</code>-password ZIP)
              </span>
            </label>
          </fieldset>
        </div>

        <div style={{ marginTop: 'var(--space-4)', display: 'flex', justifyContent: 'flex-end', gap: 'var(--space-2)' }}>
          <button className="btn" onClick={onClose} disabled={submitting}>Cancel</button>
          <button className="btn primary" onClick={submit} disabled={!canSubmit}>
            {submitting ? 'Generating…' : 'Generate'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Main section ─────────────────────────────────────────────────────────────

export default function LePackage({ inc }) {
  const { user } = useAuth()
  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [showModal, setShowModal] = useState(false)
  const [issued, setIssued] = useState(null)

  const load = useCallback(async () => {
    if (user?.role !== 'admin') { setLoading(false); return }
    setLoading(true)
    setError(null)
    try {
      const r = await api.listLePackages(inc.id)
      setItems(r.items || [])
    } catch (e) {
      setError(e.message || 'Failed to load LE package history')
    } finally {
      setLoading(false)
    }
  }, [inc.id, user?.role])

  useEffect(() => { load() }, [load])

  if (user?.role !== 'admin') {
    return (
      <div style={{
        marginTop: 'var(--space-4)',
        padding: 'var(--space-3)',
        background: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        fontSize: 12, color: 'var(--muted)',
      }}>
        LE package generation is admin-only. Ask an administrator to issue a hand-off bundle.
      </div>
    )
  }

  return (
    <section style={{ marginTop: 'var(--space-4)' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-2)' }}>
        <div>
          <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700 }}>Law-Enforcement Package</h3>
          <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>
            Court-ready evidence bundle. AES-256-GCM encrypted. README + MANIFEST + INTEGRITY.sha256 + audit-chain verifier output included.
          </div>
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
          <button className="btn ghost" onClick={() => setShowModal('quick')}>+ Quick generate</button>
          <button className="btn primary" onClick={() => setShowModal('wizard')}
                  title="EU-aware handoff wizard (EIO/MLA + recipient + receipt loop)">
            🛡 Handoff wizard
          </button>
        </div>
      </div>

      {error && (
        <div style={{
          padding: '8px 10px', marginBottom: 'var(--space-2)',
          background: 'rgba(239,68,68,0.10)', border: '1px solid var(--crit)',
          borderRadius: 'var(--radius-sm)', color: 'var(--crit)', fontSize: 12,
        }}>{error}</div>
      )}

      {loading ? (
        <div style={{ fontSize: 12, color: 'var(--muted)' }}>Loading history…</div>
      ) : items.length === 0 ? (
        <div style={{
          padding: 'var(--space-3)',
          background: 'var(--surface)', border: '1px dashed var(--border)',
          borderRadius: 'var(--radius)', textAlign: 'center',
          fontSize: 12, color: 'var(--muted)',
        }}>
          No LE packages generated for this incident yet.
        </div>
      ) : (
        <div style={{
          background: 'var(--surface)', border: '1px solid var(--border)',
          borderRadius: 'var(--radius)', overflow: 'hidden',
        }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ background: 'var(--surface-2)', textAlign: 'left' }}>
                <th style={th}>Case ref</th>
                <th style={th}>Authority</th>
                <th style={th}>Basis</th>
                <th style={th}>Generated</th>
                <th style={th}>Files</th>
                <th style={th}>Size</th>
                <th style={th}>Bundle SHA-256</th>
                <th style={th}>Status</th>
                <th style={{ ...th, textAlign: 'right' }}>Ack</th>
              </tr>
            </thead>
            <tbody>
              {items.map(lp => (
                <tr key={lp.id} style={{ borderTop: '1px solid var(--border)' }}>
                  <td style={td}><code style={{ fontFamily: 'var(--font-mono)' }}>{lp.case_reference}</code></td>
                  <td style={td}>{lp.requesting_authority}</td>
                  <td style={td}>{lp.legal_basis}</td>
                  <td style={td}>{formatLocalShort(lp.prepared_at)}</td>
                  <td style={td}>{lp.file_count?.toLocaleString() || '—'}</td>
                  <td style={td}>{fmtBytes(lp.total_bytes)}</td>
                  <td style={td}><Hash value={lp.bundle_sha256} /></td>
                  <td style={td}><StatusPill status={lp.status} /></td>
                  <td style={{ ...td, textAlign: 'right' }}>
                    {lp.acknowledged_at ? (
                      <span
                        style={{ fontSize: 11, color: 'var(--ok)' }}
                        title={`Ack'd by ${lp.acknowledged_by_name || '—'} at ${lp.acknowledged_at}`}
                      >
                        ✓ {formatLocalShort(lp.acknowledged_at)}
                      </span>
                    ) : (
                      <button
                        className="btn"
                        style={{ fontSize: 11, padding: '2px 8px' }}
                        onClick={() => setShowModal({ kind: 'manual-ack', lp })}
                        title="Record an out-of-network receipt on the recipient's behalf"
                      >
                        + Manual ack
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showModal === 'quick' && (
        <GenerateModal
          inc={inc}
          onClose={() => setShowModal(false)}
          onIssued={(r) => { setIssued(r); setShowModal(false); load() }}
        />
      )}
      {showModal === 'wizard' && (
        <HandoffWizard
          inc={inc}
          onClose={() => setShowModal(false)}
          onIssued={(r) => { setIssued(r); setShowModal(false); load() }}
        />
      )}
      {showModal?.kind === 'manual-ack' && (
        <ManualAckModal
          inc={inc}
          lp={showModal.lp}
          onClose={() => setShowModal(false)}
          onAcked={() => { setShowModal(false); load() }}
        />
      )}
      {issued && (
        <IssuedModal issued={issued} onClose={() => setIssued(null)} />
      )}
    </section>
  )
}

// ─── Manual-ack modal ────────────────────────────────────────────────────────
// Admin attests, on the recipient's behalf, that an external party received
// the bundle out-of-network (paper handoff, email, phone-confirmed, in-person,
// secure portal). Closes the audit chain with `details.method = "manual:..."`.

const ACK_METHODS = [
  { value: 'paper',          label: 'Signed paper receipt' },
  { value: 'email',          label: 'Signed/PDF email reply' },
  { value: 'phone',          label: 'Phone-confirmed' },
  { value: 'in_person',      label: 'In-person handoff' },
  { value: 'secure_portal',  label: 'Secure-portal upload' },
  { value: 'other',          label: 'Other (document in attestation)' },
]

function ManualAckModal({ inc, lp, onClose, onAcked }) {
  const [form, setForm] = useState({
    recipient_name:    '',
    recipient_title:   '',
    recipient_agency:  '',
    received_at:       new Date().toISOString(),  // canonical UTC ISO
    method:            'paper',
    attestation_text:  '',
    evidence_id:       '',
  })
  const [evidence, setEvidence] = useState([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  // Pull the incident's evidence list so the admin can link the scanned receipt
  // they (presumably) already uploaded under Evidence → Items.
  useEffect(() => {
    let cancelled = false
    api.listEvidence(inc.id, { limit: 200 })
      .then(r => { if (!cancelled) setEvidence(r.items || []) })
      .catch(() => {})
    return () => { cancelled = true }
  }, [inc.id])

  function set(k, v) { setForm(f => ({ ...f, [k]: v })) }

  async function submit() {
    if (!form.recipient_name.trim() || form.attestation_text.trim().length < 10) {
      setError('Recipient name and an attestation (≥ 10 chars) are required.')
      return
    }
    setBusy(true)
    setError(null)
    try {
      const payload = {
        recipient_name:   form.recipient_name.trim(),
        recipient_title:  form.recipient_title.trim() || null,
        recipient_agency: form.recipient_agency.trim() || null,
        received_at:      form.received_at,
        method:           form.method,
        attestation_text: form.attestation_text.trim(),
        evidence_id:      form.evidence_id || null,
      }
      await api.manualAckLePackage(inc.id, lp.id, payload)
      onAcked()
    } catch (e) {
      setError(e.message || 'Failed to record acknowledgment')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      zIndex: 50,
    }}>
      <div style={{
        background: 'var(--surface)', border: '1px solid var(--border)',
        borderRadius: 'var(--radius-lg)', padding: 'var(--space-4)',
        width: 640, maxWidth: '95vw', maxHeight: '90vh', overflow: 'auto',
      }}>
        <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700 }}>Manual acknowledgment</h3>
        <p style={{ margin: '4px 0 var(--space-3)', fontSize: 12, color: 'var(--muted)' }}>
          Use this when the recipient cannot reach the URL-based ack page (offline LE
          agency, paper handoff). You attest receipt on their behalf — the chain closes
          with <code>details.method = "manual:<i>{form.method}</i>"</code> in the audit log,
          and the <strong>URL ack token is burned</strong> so it cannot be used afterwards.
        </p>
        <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 'var(--space-3)' }}>
          Case: <code style={{ fontFamily: 'var(--font-mono)' }}>{lp.case_reference}</code> ·
          Authority: <strong>{lp.requesting_authority}</strong>
        </div>

        {error && (
          <div style={{
            padding: '8px 10px', marginBottom: 'var(--space-2)',
            background: 'rgba(239,68,68,0.10)', border: '1px solid var(--crit)',
            borderRadius: 'var(--radius-sm)', color: 'var(--crit)', fontSize: 12,
          }}>{error}</div>
        )}

        <div style={{ display: 'grid', gap: 'var(--space-3)' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-2)' }}>
            <Field label="Recipient name *">
              <input className="input" value={form.recipient_name}
                     onChange={e => set('recipient_name', e.target.value)}
                     maxLength={256} autoFocus />
            </Field>
            <Field label="Title">
              <input className="input" value={form.recipient_title}
                     onChange={e => set('recipient_title', e.target.value)}
                     maxLength={256} placeholder="e.g. Det. Smith, Cybercrime Unit" />
            </Field>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-2)' }}>
            <Field label="Agency / Organisation">
              <input className="input" value={form.recipient_agency}
                     onChange={e => set('recipient_agency', e.target.value)}
                     maxLength={256} placeholder="e.g. Metropolitan Police, OCSCU" />
            </Field>
            <Field label="Received at (UTC) *">
              <UtcDateTimeInput value={form.received_at} onChange={v => set('received_at', v)} hint={false} />
            </Field>
          </div>

          <Field label="Delivery method *">
            <select className="select" value={form.method}
                    onChange={e => set('method', e.target.value)}>
              {ACK_METHODS.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
            </select>
          </Field>

          <Field label="Attestation (your statement of receipt) *">
            <textarea className="input" rows={4} maxLength={4096}
                      value={form.attestation_text}
                      onChange={e => set('attestation_text', e.target.value)}
                      placeholder="e.g. Signed paper receipt obtained from Det. Smith at Met. Police HQ at 14:32 UTC. Scanned copy filed under case <ref> as Evidence."
                      style={{ resize: 'vertical', minHeight: 80 }} />
          </Field>

          <Field label="Link scanned receipt (Evidence — optional)">
            <select className="select" value={form.evidence_id}
                    onChange={e => set('evidence_id', e.target.value)}>
              <option value="">— none —</option>
              {evidence.map(e => (
                <option key={e.id} value={e.id}>
                  {e.name || e.identifier || e.id.slice(0, 8)} ({e.kind || 'item'})
                </option>
              ))}
            </select>
            <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4 }}>
              Upload the scanned signed paper under Evidence → Items first so it
              inherits the AES-256 at-rest encryption + chain-of-custody log,
              then link it here.
            </div>
          </Field>
        </div>

        <div style={{ marginTop: 'var(--space-4)', display: 'flex', gap: 'var(--space-2)', justifyContent: 'flex-end' }}>
          <button className="btn" onClick={onClose} disabled={busy}>Cancel</button>
          <button className="btn primary" onClick={submit} disabled={busy}>
            {busy ? 'Recording…' : 'Record acknowledgment'}
          </button>
        </div>
      </div>
    </div>
  )
}

function Field({ label, children }) {
  return (
    <label style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: 12, color: 'var(--muted)' }}>
      <span style={{ textTransform: 'uppercase', letterSpacing: 0.5, fontSize: 11 }}>{label}</span>
      {children}
    </label>
  )
}

const th = { padding: '6px 8px', fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5, fontWeight: 600 }
const td = { padding: '6px 8px', verticalAlign: 'top' }
