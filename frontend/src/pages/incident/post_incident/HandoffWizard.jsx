import { useEffect, useState } from 'react'
import { api } from '../../../api/client.js'

// Wizard C — Authority handoff.
//
// Wraps the existing /le-package POST with the full Wizard-C field set
// (EIO/MLA cross-border refs, recipient details, delivery channel, sender
// declaration, optional ack token + URL). The legacy GenerateModal still
// exists for routine cases — this wizard is for cases destined for court.
//
// Steps:
//   1. Case binding              — case ref + authority + retention
//   2. Legal basis               — incl. EIO (Dir. 2014/41/EU) + MLA (Budapest Art. 31)
//   3. Build options             — legal_hold_only + include_artifacts
//   4. Recipient                 — name, role, ID, org, address, delivery channel
//   5. Sender declaration        — operator certification text (signed Ed25519)
//   6. Acknowledgment            — enable single-use receipt URL
//   7. Issue                     — final review + Generate

const LEGAL_BASIS = [
  { value: 'warrant',     label: 'Warrant' },
  { value: 'subpoena',    label: 'Subpoena' },
  { value: 'court_order', label: 'Court order' },
  { value: 'eio',         label: 'European Investigation Order (Dir. 2014/41/EU)' },
  { value: 'mla',         label: 'MLAT — Mutual Legal Assistance (Budapest Conv. Art. 31)' },
  { value: 'voluntary',   label: 'Voluntary disclosure' },
  { value: 'other',       label: 'Other (document in case file)' },
]

const DELIVERY_CHANNEL = [
  { value: 'download_url',    label: 'One-time encrypted download URL (default)' },
  { value: 'sealed_usb',      label: 'Sealed USB / physical media (courier)' },
  { value: 'encrypted_email', label: 'Encrypted email (recipient public key)' },
  { value: 'courier',         label: 'Courier (sealed bag, tracked)' },
  { value: 'other',           label: 'Other (document in delivery notes)' },
]

const DEFAULT_DECLARATION =
  'I hereby certify that the evidence in this bundle was collected, ' +
  'preserved, examined, and prepared in accordance with the platform-recorded ' +
  'chain of custody. The cryptographic hashes embedded in the manifest match ' +
  'the underlying artefacts as of the moment of bundle generation, and the ' +
  'tamper-evident audit anchor proves continuity to that point. I am the ' +
  'authorised preparer of this handoff.'

function StepHeader({ n, total, title, subtitle }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'baseline', gap: 'var(--space-2)',
      marginBottom: 'var(--space-3)',
    }}>
      <span style={{
        fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)',
        padding: '2px 8px', borderRadius: 'var(--radius-sm)',
        background: 'var(--accent-soft)',
      }}>STEP {n}/{total}</span>
      <h3 style={{ margin: 0, fontSize: 15 }}>{title}</h3>
      {subtitle && <span style={{ color: 'var(--muted)', fontSize: 12 }}>{subtitle}</span>}
    </div>
  )
}

const FIELD = {
  display: 'block', fontSize: 11, color: 'var(--muted)',
  textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 4,
}
const INPUT = {
  width: '100%', fontSize: 13,
  background: 'var(--surface-2)', border: '1px solid var(--border)',
  borderRadius: 'var(--radius-sm)', padding: '6px 8px', color: 'var(--text)',
}

export default function HandoffWizard({ inc, onClose, onIssued }) {
  const [step, setStep] = useState(1)
  const total = 7

  const [form, setForm] = useState({
    // Step 1
    case_reference:       '',
    requesting_authority: '',
    retention_until:      '',
    // Step 2
    legal_basis:          'warrant',
    eio_reference:        '',
    issuing_state:        '',
    executing_state:      '',
    mla_reference:        '',
    // Step 3
    legal_hold_only:   false,
    include_artifacts: false,
    // Step 4
    recipient_name:         '',
    recipient_role:         '',
    recipient_id_ref:       '',
    recipient_organisation: '',
    recipient_address:      '',
    delivery_channel:       'download_url',
    delivery_notes:         '',
    // Step 5
    sender_declaration: DEFAULT_DECLARATION,
    // Step 6
    enable_acknowledgment: true,
  })

  const [busy, setBusy]   = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  function set(k, v) { setForm(f => ({ ...f, [k]: v })) }

  function validate(s) {
    setError(null)
    if (s === 1) {
      if (!form.case_reference.trim())       { setError('Case reference required.'); return false }
      if (!form.requesting_authority.trim()) { setError('Requesting authority required.'); return false }
    }
    if (s === 2) {
      if (form.legal_basis === 'eio' && !form.eio_reference.trim()) {
        setError('EIO selected — EIO reference number required.'); return false
      }
      if (form.legal_basis === 'eio' && (!form.issuing_state.trim() || !form.executing_state.trim())) {
        setError('EIO selected — issuing and executing state codes required.'); return false
      }
      if (form.legal_basis === 'mla' && !form.mla_reference.trim()) {
        setError('MLA selected — MLAT request reference required.'); return false
      }
    }
    if (s === 4) {
      if (!form.recipient_name.trim()) { setError('Recipient name required.'); return false }
      if (form.delivery_channel === 'other' && !form.delivery_notes.trim()) {
        setError('Delivery channel = "other" requires notes.'); return false
      }
    }
    if (s === 5) {
      if (!form.sender_declaration.trim()) { setError('Sender declaration required.'); return false }
    }
    return true
  }
  function next() { if (validate(step)) setStep(s => Math.min(total, s + 1)) }
  function prev() { setStep(s => Math.max(1, s - 1)) }

  async function commit() {
    if (!validate(step)) return
    setBusy(true); setError(null)
    try {
      const payload = {
        case_reference:       form.case_reference.trim(),
        requesting_authority: form.requesting_authority.trim(),
        legal_basis:          form.legal_basis,
        legal_hold_only:      form.legal_hold_only,
        include_artifacts:    form.include_artifacts,
      }
      if (form.retention_until) {
        payload.retention_until = new Date(form.retention_until).toISOString()
      }
      // Wizard C extras — only send non-empty.
      const extras = {
        eio_reference:          form.eio_reference.trim(),
        issuing_state:          form.issuing_state.trim(),
        executing_state:        form.executing_state.trim(),
        mla_reference:          form.mla_reference.trim(),
        recipient_name:         form.recipient_name.trim(),
        recipient_role:         form.recipient_role.trim(),
        recipient_id_ref:       form.recipient_id_ref.trim(),
        recipient_organisation: form.recipient_organisation.trim(),
        recipient_address:      form.recipient_address.trim(),
        delivery_channel:       form.delivery_channel,
        delivery_notes:         form.delivery_notes.trim(),
        sender_declaration:     form.sender_declaration.trim(),
      }
      for (const [k, v] of Object.entries(extras)) {
        if (v) payload[k] = v
      }
      payload.enable_acknowledgment = form.enable_acknowledgment

      const issued = await api.prepareLePackage(inc.id, payload)
      onIssued(issued)
    } catch (e) {
      setError(e.message || 'Generation failed.')
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
        width: 760, maxWidth: '95vw', maxHeight: '92vh', overflow: 'auto',
      }}>
        <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 'var(--space-3)' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 17, fontWeight: 700 }}>🛡 Authority handoff wizard</h3>
            <p style={{ margin: '2px 0 0', fontSize: 12, color: 'var(--muted)' }}>
              Court-grade LE-package generation. EU-aware (EIO Dir. 2014/41/EU · Budapest Conv. Art. 31).
            </p>
          </div>
          <button className="btn ghost" onClick={onClose} disabled={busy}>Close</button>
        </div>

        {/* Progress strip */}
        <div style={{ display: 'flex', gap: 4, marginBottom: 'var(--space-3)' }}>
          {Array.from({ length: total }, (_, i) => (
            <div key={i} style={{
              flex: 1, height: 4, borderRadius: 2,
              background: i < step ? 'var(--accent)' : 'var(--border)',
            }} />
          ))}
        </div>

        {error && (
          <div style={{
            margin: '0 0 var(--space-3)', padding: '8px 10px',
            background: 'rgba(239,68,68,0.10)', border: '1px solid var(--crit)',
            borderRadius: 'var(--radius-sm)', color: 'var(--crit)', fontSize: 12,
          }}>{error}</div>
        )}

        {/* Step 1 — Case binding */}
        {step === 1 && (
          <div style={{ display: 'grid', gap: 'var(--space-3)' }}>
            <StepHeader n={1} total={total} title="Case binding" subtitle="Who's asking and for which case" />
            <div>
              <label style={FIELD}>Case reference *</label>
              <input value={form.case_reference} onChange={e => set('case_reference', e.target.value)}
                     maxLength={128} placeholder="e.g. STK-2026-00114"
                     style={{ ...INPUT, fontFamily: 'var(--font-mono)' }} autoFocus />
            </div>
            <div>
              <label style={FIELD}>Requesting authority *</label>
              <input value={form.requesting_authority} onChange={e => set('requesting_authority', e.target.value)}
                     maxLength={256} placeholder="e.g. Stockholm County Police, Cybercrime Unit"
                     style={INPUT} />
            </div>
            <div>
              <label style={FIELD}>Retention until (optional)</label>
              <input type="date" value={form.retention_until}
                     onChange={e => set('retention_until', e.target.value)} style={INPUT} />
              <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 4 }}>
                Recipient retention deadline — informational; doesn't gate disposal.
              </div>
            </div>
          </div>
        )}

        {/* Step 2 — Legal basis (incl. EIO/MLA) */}
        {step === 2 && (
          <div style={{ display: 'grid', gap: 'var(--space-3)' }}>
            <StepHeader n={2} total={total} title="Legal basis"
                        subtitle="Picks the appropriate cross-border instrument if applicable" />
            <div>
              <label style={FIELD}>Legal basis *</label>
              <select value={form.legal_basis} onChange={e => set('legal_basis', e.target.value)} style={INPUT}>
                {LEGAL_BASIS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>
            {form.legal_basis === 'eio' && (
              <div style={{
                padding: 'var(--space-3)', background: 'var(--surface-2)',
                border: '1px solid var(--border)', borderRadius: 'var(--radius)',
                display: 'grid', gap: 'var(--space-3)',
              }}>
                <div>
                  <label style={FIELD}>EIO reference number *</label>
                  <input value={form.eio_reference} onChange={e => set('eio_reference', e.target.value)}
                         maxLength={128} placeholder="EIO/2026/0042"
                         style={{ ...INPUT, fontFamily: 'var(--font-mono)' }} />
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-3)' }}>
                  <div>
                    <label style={FIELD}>Issuing state * (ISO 3166-1)</label>
                    <input value={form.issuing_state} onChange={e => set('issuing_state', e.target.value.toUpperCase())}
                           maxLength={2} placeholder="DE"
                           style={{ ...INPUT, fontFamily: 'var(--font-mono)' }} />
                  </div>
                  <div>
                    <label style={FIELD}>Executing state * (ISO 3166-1)</label>
                    <input value={form.executing_state} onChange={e => set('executing_state', e.target.value.toUpperCase())}
                           maxLength={2} placeholder="SE"
                           style={{ ...INPUT, fontFamily: 'var(--font-mono)' }} />
                  </div>
                </div>
                <div style={{ fontSize: 11, color: 'var(--dim)' }}>
                  EIO = European Investigation Order (Directive 2014/41/EU). Single instrument
                  across participating MS since 2017 — replaces most MLA in EU criminal matters.
                </div>
              </div>
            )}
            {form.legal_basis === 'mla' && (
              <div style={{
                padding: 'var(--space-3)', background: 'var(--surface-2)',
                border: '1px solid var(--border)', borderRadius: 'var(--radius)',
                display: 'grid', gap: 'var(--space-3)',
              }}>
                <div>
                  <label style={FIELD}>MLAT reference *</label>
                  <input value={form.mla_reference} onChange={e => set('mla_reference', e.target.value)}
                         maxLength={128} placeholder="e.g. CoE-2026-0017"
                         style={{ ...INPUT, fontFamily: 'var(--font-mono)' }} />
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-3)' }}>
                  <div>
                    <label style={FIELD}>Issuing state (ISO 3166-1)</label>
                    <input value={form.issuing_state} onChange={e => set('issuing_state', e.target.value.toUpperCase())}
                           maxLength={2} style={{ ...INPUT, fontFamily: 'var(--font-mono)' }} />
                  </div>
                  <div>
                    <label style={FIELD}>Executing state (ISO 3166-1)</label>
                    <input value={form.executing_state} onChange={e => set('executing_state', e.target.value.toUpperCase())}
                           maxLength={2} style={{ ...INPUT, fontFamily: 'var(--font-mono)' }} />
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Step 3 — Build options */}
        {step === 3 && (
          <div style={{ display: 'grid', gap: 'var(--space-3)' }}>
            <StepHeader n={3} total={total} title="Build options" subtitle="What goes into the bundle" />
            <label style={{ display: 'flex', alignItems: 'flex-start', gap: 8, fontSize: 13, cursor: 'pointer' }}>
              <input type="checkbox" checked={form.legal_hold_only}
                     onChange={e => set('legal_hold_only', e.target.checked)} style={{ marginTop: 3 }} />
              <span>
                Only include evidence flagged <code style={{ fontFamily: 'var(--font-mono)' }}>legal_hold = true</code>
                <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 2 }}>
                  Recommended for narrow handoffs — minimises data exposure (GDPR Art. 5.1(c)).
                </div>
              </span>
            </label>
            <label style={{ display: 'flex', alignItems: 'flex-start', gap: 8, fontSize: 13, cursor: 'pointer' }}>
              <input type="checkbox" checked={form.include_artifacts}
                     onChange={e => set('include_artifacts', e.target.checked)} style={{ marginTop: 3 }} />
              <span>
                Include quarantine artifacts (in <code style={{ fontFamily: 'var(--font-mono)' }}>infected</code>-password ZIP)
                <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 2 }}>
                  Adds the malware-analyst-convention nested ZIP per item. Skip for non-malware cases.
                </div>
              </span>
            </label>
          </div>
        )}

        {/* Step 4 — Recipient */}
        {step === 4 && (
          <div style={{ display: 'grid', gap: 'var(--space-3)' }}>
            <StepHeader n={4} total={total} title="Recipient" subtitle="Specific officer / clerk receiving the bundle" />
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-3)' }}>
              <div>
                <label style={FIELD}>Recipient name *</label>
                <input value={form.recipient_name} onChange={e => set('recipient_name', e.target.value)}
                       maxLength={256} placeholder="Insp. P. Hansen" style={INPUT} autoFocus />
              </div>
              <div>
                <label style={FIELD}>Role</label>
                <input value={form.recipient_role} onChange={e => set('recipient_role', e.target.value)}
                       maxLength={128} placeholder="Lead investigator" style={INPUT} />
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-3)' }}>
              <div>
                <label style={FIELD}>ID / badge / court ref</label>
                <input value={form.recipient_id_ref} onChange={e => set('recipient_id_ref', e.target.value)}
                       maxLength={128} placeholder="B-44219" style={{ ...INPUT, fontFamily: 'var(--font-mono)' }} />
              </div>
              <div>
                <label style={FIELD}>Organisation</label>
                <input value={form.recipient_organisation} onChange={e => set('recipient_organisation', e.target.value)}
                       maxLength={256} placeholder="(defaults to requesting authority)" style={INPUT} />
              </div>
            </div>
            <div>
              <label style={FIELD}>Recipient address</label>
              <textarea value={form.recipient_address} onChange={e => set('recipient_address', e.target.value)}
                        rows={2} maxLength={4096}
                        placeholder="Mailing / service address for physical / written follow-up"
                        style={{ ...INPUT, resize: 'vertical' }} />
            </div>
            <div>
              <label style={FIELD}>Delivery channel *</label>
              <select value={form.delivery_channel} onChange={e => set('delivery_channel', e.target.value)} style={INPUT}>
                {DELIVERY_CHANNEL.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>
            <div>
              <label style={FIELD}>Delivery notes</label>
              <textarea value={form.delivery_notes} onChange={e => set('delivery_notes', e.target.value)}
                        rows={2} maxLength={4096}
                        placeholder="Tracking #, courier ref, recipient PGP key fingerprint, etc."
                        style={{ ...INPUT, resize: 'vertical' }} />
            </div>
          </div>
        )}

        {/* Step 5 — Sender declaration */}
        {step === 5 && (
          <div style={{ display: 'grid', gap: 'var(--space-3)' }}>
            <StepHeader n={5} total={total} title="Sender declaration"
                        subtitle="Signed Ed25519. eIDAS-QES hook reserved." />
            <div>
              <label style={FIELD}>Declaration text *</label>
              <textarea value={form.sender_declaration}
                        onChange={e => set('sender_declaration', e.target.value)}
                        rows={8} maxLength={4096}
                        style={{ ...INPUT, resize: 'vertical', fontFamily: 'var(--font-mono)', fontSize: 11 }} />
            </div>
            <div style={{
              padding: 'var(--space-2) var(--space-3)', background: 'var(--surface-2)',
              border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)',
              fontSize: 11, color: 'var(--muted)',
            }}>
              The declaration is included in the bundle manifest. The bundle itself is signed with
              the platform's Ed25519 key. An eIDAS Qualified Electronic Signature (QES) integration
              can replace the Ed25519 path without schema change.
            </div>
          </div>
        )}

        {/* Step 6 — Acknowledgment */}
        {step === 6 && (
          <div style={{ display: 'grid', gap: 'var(--space-3)' }}>
            <StepHeader n={6} total={total} title="Receipt acknowledgment"
                        subtitle="Closes the chain on the recipient's side" />
            <label style={{ display: 'flex', alignItems: 'flex-start', gap: 8, fontSize: 13, cursor: 'pointer' }}>
              <input type="checkbox" checked={form.enable_acknowledgment}
                     onChange={e => set('enable_acknowledgment', e.target.checked)} style={{ marginTop: 3 }} />
              <span>
                Generate a single-use receipt URL
                <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 2 }}>
                  Recipient hits the URL (printed on the handoff form / shown as QR) to confirm receipt.
                  The acknowledgment is written into the hash-chained audit log and locks the row's status to
                  "received". Token is single-use and burned after consumption.
                </div>
              </span>
            </label>
          </div>
        )}

        {/* Step 7 — Issue */}
        {step === 7 && (
          <div style={{ display: 'grid', gap: 'var(--space-3)' }}>
            <StepHeader n={7} total={total} title="Issue" subtitle="Final review before generation" />
            <div style={{
              padding: 'var(--space-3)', background: 'var(--surface-2)',
              border: '1px solid var(--border)', borderRadius: 'var(--radius)',
              fontSize: 12,
            }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '4px 12px' }}>
                <span style={{ color: 'var(--muted)' }}>Case</span>
                <span style={{ fontFamily: 'var(--font-mono)' }}>{form.case_reference}</span>
                <span style={{ color: 'var(--muted)' }}>Authority</span>
                <span>{form.requesting_authority}</span>
                <span style={{ color: 'var(--muted)' }}>Basis</span>
                <span>{LEGAL_BASIS.find(l => l.value === form.legal_basis)?.label}</span>
                {form.legal_basis === 'eio' && (
                  <>
                    <span style={{ color: 'var(--muted)' }}>EIO ref</span>
                    <span style={{ fontFamily: 'var(--font-mono)' }}>{form.eio_reference} ({form.issuing_state} → {form.executing_state})</span>
                  </>
                )}
                {form.legal_basis === 'mla' && (
                  <>
                    <span style={{ color: 'var(--muted)' }}>MLA ref</span>
                    <span style={{ fontFamily: 'var(--font-mono)' }}>{form.mla_reference}</span>
                  </>
                )}
                <span style={{ color: 'var(--muted)' }}>Recipient</span>
                <span>{form.recipient_name}{form.recipient_role ? `, ${form.recipient_role}` : ''}</span>
                <span style={{ color: 'var(--muted)' }}>Delivery</span>
                <span>{DELIVERY_CHANNEL.find(d => d.value === form.delivery_channel)?.label}</span>
                <span style={{ color: 'var(--muted)' }}>Bundle scope</span>
                <span>
                  {form.legal_hold_only ? 'legal-hold only' : 'all evidence'}
                  {form.include_artifacts ? ' + artifacts' : ''}
                </span>
                <span style={{ color: 'var(--muted)' }}>Acknowledgment</span>
                <span>{form.enable_acknowledgment ? '✓ enabled' : '— disabled'}</span>
              </div>
            </div>
          </div>
        )}

        {/* Foot */}
        <div style={{ marginTop: 'var(--space-4)', display: 'flex', justifyContent: 'space-between' }}>
          <button className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
            {step > 1 && (
              <button className="btn ghost" onClick={prev} disabled={busy}>Back</button>
            )}
            {step < total && (
              <button className="btn primary" onClick={next} disabled={busy}>Next</button>
            )}
            {step === total && (
              <button className="btn primary" onClick={commit} disabled={busy}>
                {busy ? 'Generating…' : 'Generate handoff bundle'}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
