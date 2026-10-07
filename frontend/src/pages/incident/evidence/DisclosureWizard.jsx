import { useEffect, useState } from 'react'
import { api } from '../../../api/client.js'
import { DraftBadge } from '../../../components/ExhibitPicker.jsx'

// Disclosure package wizard (K1, R36): the one way exhibits leave FENRIR — Evidence › Export and the LE package
// merged. POST /api/incidents/{id}/disclosures does the work (rights, required fields, custody rows, signature);
// this only collects the request. Steps: purpose → exhibits → case & legal basis → recipient → declaration &
// receipt → review.

export const PURPOSES = [
  { value: 'law_enforcement', label: 'Law enforcement',
    desc: 'Court-ready handoff to police or a prosecutor (warrant, EIO, MLA …).',
    sections: 'Exhibits, custody and audit, incident, timeline, IOCs, forensic results, communications, case notes, recovery, notifications, sign-offs.' },
  { value: 'regulator', label: 'Regulator',
    desc: 'A data-protection authority or CSIRT (e.g. GDPR Art. 33, NIS2 Art. 23).',
    sections: 'Exhibits, custody and audit, incident, timeline, IOCs, recovery, notifications, sign-offs. No forensic results, communications or case notes.' },
  { value: 'internal', label: 'Internal',
    desc: 'Legal counsel, insurer or an outside lab working for you.',
    sections: 'Exhibits, custody and audit, incident, timeline, IOCs, forensic results, case notes, recovery. No communications, notifications or sign-offs.' },
]

const LE_BASIS = [
  { value: 'warrant',     label: 'Warrant' },
  { value: 'subpoena',    label: 'Subpoena' },
  { value: 'court_order', label: 'Court order' },
  { value: 'eio',         label: 'European Investigation Order (Dir. 2014/41/EU)' },
  { value: 'mla',         label: 'MLAT — Mutual Legal Assistance (Budapest Conv. Art. 31)' },
  { value: 'voluntary',   label: 'Voluntary disclosure' },
  { value: 'other',       label: 'Other (document in the case file)' },
]
const REGULATOR_BASIS = [
  { value: 'statutory',   label: 'Statutory obligation (e.g. GDPR Art. 33, NIS2 Art. 23)' },
  { value: 'court_order', label: 'Court order' },
  { value: 'voluntary',   label: 'Voluntary disclosure' },
  { value: 'other',       label: 'Other (document in the case file)' },
]
export const BASIS_LABEL = Object.fromEntries([...LE_BASIS, ...REGULATOR_BASIS, { value: 'internal', label: 'Internal' }]
  .map(o => [o.value, o.label]))

const DELIVERY_CHANNEL = [
  { value: 'download_url',    label: 'One-time encrypted download URL (default)' },
  { value: 'sealed_usb',      label: 'Sealed USB / physical media (courier)' },
  { value: 'encrypted_email', label: 'Encrypted email (recipient public key)' },
  { value: 'courier',         label: 'Courier (sealed bag, tracked)' },
  { value: 'other',           label: 'Other (document in delivery notes)' },
]

const DEFAULT_DECLARATION =
  'I hereby certify that the evidence in this package was collected, preserved, examined and prepared in ' +
  'accordance with the platform-recorded chain of custody. The hashes in the signed manifest match the ' +
  'underlying files as of the moment the package was built, and the tamper-evident audit anchor proves ' +
  'continuity to that point. I am the authorised preparer of this disclosure.'

// Mirrors the server refusal (409 evidence_not_exportable): these exhibits are not offered at all.
const NOT_DISCLOSABLE = new Set(['destroyed', 'verify_failed'])
const STEPS = ['Purpose', 'Exhibits', 'Case & legal basis', 'Recipient', 'Declaration & receipt', 'Review']

function StepHeader({ n, title, subtitle }) {
  return (
    <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-2)', marginBottom: 'var(--space-3)', flexWrap: 'wrap' }}>
      <span style={{
        fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)',
        padding: '2px 8px', borderRadius: 'var(--radius-sm)', background: 'var(--accent-soft)',
      }}>STEP {n}/{STEPS.length}</span>
      <h3 style={{ margin: 0, fontSize: 15 }}>{title}</h3>
      {subtitle && <span style={{ color: 'var(--muted)', fontSize: 12 }}>{subtitle}</span>}
    </div>
  )
}

function Check({ checked, onChange, label, hint, testid }) {
  return (
    <label style={{ display: 'flex', alignItems: 'flex-start', gap: 8, fontSize: 13, cursor: 'pointer' }}>
      <input type="checkbox" checked={checked} onChange={e => onChange(e.target.checked)} style={{ marginTop: 3 }}
             data-testid={testid} />
      <span>{label}{hint && <div className="field-hint">{hint}</div>}</span>
    </label>
  )
}

export default function DisclosureWizard({ inc, onClose, onIssued }) {
  const [step, setStep] = useState(1)
  const [exhibits, setExhibits] = useState(null)        // null = loading
  const [picked, setPicked] = useState(new Set())
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [f, setF] = useState({
    purpose: 'law_enforcement',
    include_unsealed_drafts: false, include_artifacts: false,
    case_reference: '', requesting_authority: '', legal_basis: 'warrant', retention_until: '',
    eio_reference: '', issuing_state: '', executing_state: '', mla_reference: '',
    recipient_name: '', recipient_role: '', recipient_id_ref: '', recipient_organisation: '',
    recipient_address: '', delivery_channel: 'download_url', delivery_notes: '',
    sender_declaration: DEFAULT_DECLARATION, enable_acknowledgment: true,
  })
  const set = (k, v) => setF(x => ({ ...x, [k]: v }))
  const internal = f.purpose === 'internal'
  const basisOptions = f.purpose === 'regulator' ? REGULATOR_BASIS : LE_BASIS

  useEffect(() => {
    const ctl = new AbortController()
    api.listAllPages(api.listEvidence, inc.id, {}, 200, { signal: ctl.signal })
      .then(all => {
        if (ctl.signal.aborted) return
        setExhibits(all)
        setPicked(new Set(all.filter(e => !NOT_DISCLOSABLE.has(e.status)).map(e => e.id)))
      })
      .catch(e => { if (!ctl.signal.aborted) { setExhibits([]); setError(e.message || 'Could not load the exhibits') } })
    return () => ctl.abort()
  }, [inc.id])

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  function choosePurpose(p) {
    setF(x => ({ ...x, purpose: p,
      legal_basis: p === 'regulator' ? 'statutory' : p === 'law_enforcement' ? 'warrant' : 'internal',
      enable_acknowledgment: p !== 'internal' }))
  }

  const offered = (exhibits || []).filter(e => !NOT_DISCLOSABLE.has(e.status))
  const hidden = (exhibits || []).length - offered.length
  const allPicked = offered.length > 0 && offered.every(e => picked.has(e.id))
  const toggle = (id) => setPicked(p => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n })
  const draftsPicked = offered.filter(e => picked.has(e.id) && !e.coc_sealed).length

  function validate(s) {
    setError(null)
    const need = (cond, msg) => { if (!cond) { setError(msg); return false } return true }
    if (s === 2) return need(exhibits !== null, 'The exhibits are still loading.')
    if (s === 3 && !internal) {
      if (!need(f.case_reference.trim(), 'Case reference required.')) return false
      if (!need(f.requesting_authority.trim(), f.purpose === 'regulator' ? 'Regulator required.' : 'Requesting authority required.')) return false
      if (f.legal_basis === 'eio' && !need(f.eio_reference.trim() && f.issuing_state.trim() && f.executing_state.trim(),
        'EIO: the EIO reference and the issuing and executing states are required.')) return false
      if (f.legal_basis === 'mla' && !need(f.mla_reference.trim(), 'MLA: the MLAT reference is required.')) return false
    }
    if (s === 4) {
      if (!need(f.recipient_name.trim(), 'Recipient name required.')) return false
      if (!need(f.delivery_channel !== 'other' || f.delivery_notes.trim(), 'Delivery channel "other" needs delivery notes.')) return false
    }
    if (s === 5 && !internal) return need(f.sender_declaration.trim(), 'Sender declaration required.')
    return true
  }
  const next = () => { if (validate(step)) setStep(s => Math.min(STEPS.length, s + 1)) }
  const prev = () => { setError(null); setStep(s => Math.max(1, s - 1)) }

  async function build() {
    setBusy(true); setError(null)
    try {
      const payload = {
        purpose: f.purpose,
        item_ids: offered.filter(e => picked.has(e.id)).map(e => e.id),
        include_unsealed_drafts: f.include_unsealed_drafts,
        include_artifacts: f.include_artifacts,
        enable_acknowledgment: f.enable_acknowledgment,
        delivery_channel: f.delivery_channel,
      }
      if (!internal) payload.legal_basis = f.legal_basis
      if (f.retention_until) payload.retention_until = new Date(f.retention_until).toISOString()
      for (const k of ['case_reference', 'requesting_authority', 'eio_reference', 'issuing_state', 'executing_state',
                       'mla_reference', 'recipient_name', 'recipient_role', 'recipient_id_ref', 'recipient_organisation',
                       'recipient_address', 'delivery_notes', 'sender_declaration']) {
        const v = f[k].trim()
        if (v) payload[k] = v
      }
      onIssued(await api.createDisclosure(inc.id, payload))
    } catch (e) {
      setError(e.message || 'The package could not be built.')
    } finally {
      setBusy(false)
    }
  }

  const purpose = PURPOSES.find(p => p.value === f.purpose)
  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="dw-title" style={{ width: 'min(760px, 96vw)' }}
           data-testid="disclosure-wizard">
        <div className="modal-head">
          <h2 id="dw-title">New disclosure package</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <div className="modal-body">
          <div style={{ display: 'flex', gap: 4, marginBottom: 'var(--space-3)' }} aria-hidden="true">
            {STEPS.map((_, i) => (
              <div key={i} style={{ flex: 1, height: 4, borderRadius: 2, background: i < step ? 'var(--accent)' : 'var(--border)' }} />
            ))}
          </div>

          {step === 1 && (
            <div className="form">
              <StepHeader n={1} title="Purpose" subtitle="Who receives it decides what goes in" />
              <fieldset className="field" style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}>
                <legend className="field-label">Purpose *</legend>
                {PURPOSES.map(p => (
                  <label key={p.value} style={{ display: 'flex', gap: 8, alignItems: 'baseline', fontSize: 13, marginTop: 6 }}>
                    <input type="radio" name="dw-purpose" value={p.value} checked={f.purpose === p.value}
                           onChange={() => choosePurpose(p.value)} data-testid={`dw-purpose-${p.value}`} />
                    <span>
                      <b>{p.label}</b> — {p.desc}
                      <span className="field-hint" style={{ display: 'block' }}>Contains: {p.sections}</span>
                    </span>
                  </label>
                ))}
              </fieldset>
              <div className="field-hint">
                Every package is signed (Ed25519 over its manifest), custody-logged on each exhibit, audited, and
                announced to the admins.
              </div>
            </div>
          )}

          {step === 2 && (
            <div className="form">
              <StepHeader n={2} title="Exhibits" subtitle="What leaves the platform" />
              {exhibits === null ? <div className="field-hint">Loading exhibits…</div> : (
                <>
                  <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap' }}>
                    <button type="button" className="btn ghost" disabled={offered.length === 0}
                            onClick={() => setPicked(allPicked ? new Set() : new Set(offered.map(e => e.id)))}>
                      {allPicked ? 'Unselect all' : 'Select all'}
                    </button>
                    <span style={{ color: 'var(--muted)', fontSize: 12 }} data-testid="dw-picked">
                      {offered.filter(e => picked.has(e.id)).length} of {offered.length} selected
                    </span>
                  </div>
                  {hidden > 0 && (
                    <div className="field-hint" data-testid="dw-hidden">
                      {hidden} destroyed or verify-failed exhibit{hidden === 1 ? ' is' : 's are'} not listed: {hidden === 1 ? 'it' : 'they'} can’t be disclosed.
                    </div>
                  )}
                  {offered.length === 0 ? (
                    <div className="field-hint">No exhibit can be disclosed. The package will carry the records only.</div>
                  ) : (
                    <div className="table-scroll">
                      <table className="settings-table compact" data-testid="dw-exhibits">
                        <thead><tr><th style={{ width: 32 }}></th><th>Exhibit</th><th>Kind</th><th>Status</th></tr></thead>
                        <tbody>
                          {offered.map(e => (
                            <tr key={e.id} style={{ cursor: 'pointer' }} onClick={() => toggle(e.id)}>
                              <td><input type="checkbox" checked={picked.has(e.id)} onChange={() => toggle(e.id)}
                                         onClick={ev => ev.stopPropagation()} aria-label={`Include ${e.identifier}`} /></td>
                              <td>
                                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{e.identifier}</div>
                                <div style={{ color: 'var(--muted)', fontSize: 12 }}>{e.name}</div>
                                {!e.coc_sealed && <div style={{ marginTop: 2 }}><DraftBadge title="Unsealed draft: left out unless you include unsealed drafts (below)" /></div>}
                              </td>
                              <td><span className="pill">{e.kind === 'digital_file' ? 'File' : 'Physical'}</span></td>
                              <td><span className="pill">{e.status.replace(/_/g, ' ')}</span></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                  <Check checked={f.include_unsealed_drafts} onChange={v => set('include_unsealed_drafts', v)}
                         testid="dw-include-drafts" label="Include unsealed drafts"
                         hint={`Off (default): a draft is listed in Evidence_Inventory.csv as "excluded: unsealed draft", with no custody log or file${draftsPicked ? ` (${draftsPicked} selected)` : ''}. On: drafts go in like sealed exhibits; audited.`} />
                  <Check checked={f.include_artifacts} onChange={v => set('include_artifacts', v)}
                         label="Include quarantine artifacts"
                         hint="Adds the suspected malware as a nested ZIP with the password “infected”. Skip unless the recipient needs the samples." />
                </>
              )}
            </div>
          )}

          {step === 3 && (
            <div className="form">
              <StepHeader n={3} title="Case & legal basis" subtitle={purpose.label} />
              <div className="field">
                <label className="field-label" htmlFor="dw-case">Case reference{internal ? ' (optional)' : ' *'}</label>
                <input id="dw-case" className="input" value={f.case_reference} maxLength={128}
                       onChange={e => set('case_reference', e.target.value)} style={{ fontFamily: 'var(--font-mono)' }}
                       placeholder={internal ? `Default: ${inc.ref || 'the incident reference'}` : 'e.g. STK-2026-00114'} />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="dw-auth">
                  {f.purpose === 'regulator' ? 'Regulator *' : internal ? 'Requested by (optional)' : 'Requesting authority *'}
                </label>
                <input id="dw-auth" className="input" value={f.requesting_authority} maxLength={256}
                       onChange={e => set('requesting_authority', e.target.value)}
                       placeholder={f.purpose === 'regulator' ? 'e.g. Integritetsskyddsmyndigheten (IMY)' : internal ? 'e.g. Legal department' : 'e.g. Stockholm County Police, Cybercrime Unit'} />
              </div>
              {!internal && (
                <div className="field">
                  <label className="field-label" htmlFor="dw-basis">Legal basis *</label>
                  <select id="dw-basis" className="select" value={f.legal_basis} onChange={e => set('legal_basis', e.target.value)}>
                    {basisOptions.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
              )}
              {f.legal_basis === 'eio' && (
                <>
                  <div className="field">
                    <label className="field-label" htmlFor="dw-eio">EIO reference *</label>
                    <input id="dw-eio" className="input" value={f.eio_reference} maxLength={128}
                           onChange={e => set('eio_reference', e.target.value)} style={{ fontFamily: 'var(--font-mono)' }} />
                  </div>
                  <div className="form-row">
                    <div className="field">
                      <label className="field-label" htmlFor="dw-is">Issuing state * (ISO 3166-1)</label>
                      <input id="dw-is" className="input" value={f.issuing_state} maxLength={2}
                             onChange={e => set('issuing_state', e.target.value.toUpperCase())} />
                    </div>
                    <div className="field">
                      <label className="field-label" htmlFor="dw-es">Executing state * (ISO 3166-1)</label>
                      <input id="dw-es" className="input" value={f.executing_state} maxLength={2}
                             onChange={e => set('executing_state', e.target.value.toUpperCase())} />
                    </div>
                  </div>
                </>
              )}
              {f.legal_basis === 'mla' && (
                <div className="field">
                  <label className="field-label" htmlFor="dw-mla">MLAT reference *</label>
                  <input id="dw-mla" className="input" value={f.mla_reference} maxLength={128}
                         onChange={e => set('mla_reference', e.target.value)} style={{ fontFamily: 'var(--font-mono)' }} />
                </div>
              )}
              <div className="field">
                <label className="field-label" htmlFor="dw-ret">Retention until (optional)</label>
                <input id="dw-ret" type="date" className="input" value={f.retention_until}
                       onChange={e => set('retention_until', e.target.value)} />
                <div className="field-hint">The recipient’s retention deadline. Informational; it doesn’t gate disposal.</div>
              </div>
            </div>
          )}

          {step === 4 && (
            <div className="form">
              <StepHeader n={4} title="Recipient" subtitle="The person who receives the package" />
              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="dw-rn">Recipient name *</label>
                  <input id="dw-rn" className="input" value={f.recipient_name} maxLength={256}
                         onChange={e => set('recipient_name', e.target.value)} />
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="dw-rr">Role</label>
                  <input id="dw-rr" className="input" value={f.recipient_role} maxLength={128}
                         onChange={e => set('recipient_role', e.target.value)} />
                </div>
              </div>
              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="dw-ro">Organisation</label>
                  <input id="dw-ro" className="input" value={f.recipient_organisation} maxLength={256}
                         onChange={e => set('recipient_organisation', e.target.value)} />
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="dw-rid">ID / badge / reference</label>
                  <input id="dw-rid" className="input" value={f.recipient_id_ref} maxLength={128}
                         onChange={e => set('recipient_id_ref', e.target.value)} style={{ fontFamily: 'var(--font-mono)' }} />
                </div>
              </div>
              <div className="field">
                <label className="field-label" htmlFor="dw-ra">Address</label>
                <textarea id="dw-ra" className="input" rows={2} maxLength={4096} value={f.recipient_address}
                          onChange={e => set('recipient_address', e.target.value)} />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="dw-dc">Delivery channel *</label>
                <select id="dw-dc" className="select" value={f.delivery_channel} onChange={e => set('delivery_channel', e.target.value)}>
                  {DELIVERY_CHANNEL.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              </div>
              <div className="field">
                <label className="field-label" htmlFor="dw-dn">Delivery notes{f.delivery_channel === 'other' ? ' *' : ''}</label>
                <textarea id="dw-dn" className="input" rows={2} maxLength={4096} value={f.delivery_notes}
                          onChange={e => set('delivery_notes', e.target.value)}
                          placeholder="Tracking number, courier reference, the recipient’s key fingerprint …" />
              </div>
            </div>
          )}

          {step === 5 && (
            <div className="form">
              <StepHeader n={5} title="Declaration & receipt" />
              <div className="field">
                <label className="field-label" htmlFor="dw-decl">Sender declaration{internal ? ' (optional)' : ' *'}</label>
                <textarea id="dw-decl" className="input compact" rows={6} maxLength={4096} value={f.sender_declaration}
                          onChange={e => set('sender_declaration', e.target.value)}
                          style={{ fontFamily: 'var(--font-mono)' }} />
                <div className="field-hint">Recorded with the package. The manifest is signed with the platform’s Ed25519 key.</div>
              </div>
              <Check checked={f.enable_acknowledgment} onChange={v => set('enable_acknowledgment', v)}
                     label="Create a single-use receipt URL"
                     hint="The recipient opens it to confirm receipt; the receipt is written to the audit log. You can also record a receipt by hand later." />
            </div>
          )}

          {step === 6 && (
            <div className="form">
              <StepHeader n={6} title="Review" subtitle="Building can take minutes for large exhibits" />
              <dl className="disclosure-review" data-testid="dw-review">
                <dt>Purpose</dt><dd>{purpose.label}</dd>
                <dt>Exhibits</dt><dd>{offered.filter(e => picked.has(e.id)).length}{f.include_unsealed_drafts ? ' (unsealed drafts included)' : ''}{f.include_artifacts ? ' + quarantine artifacts' : ''}</dd>
                <dt>Case</dt><dd style={{ fontFamily: 'var(--font-mono)' }}>{f.case_reference.trim() || inc.ref || '—'}</dd>
                {!internal && <><dt>Authority</dt><dd>{f.requesting_authority}</dd><dt>Legal basis</dt><dd>{BASIS_LABEL[f.legal_basis]}</dd></>}
                <dt>Recipient</dt><dd>{f.recipient_name}{f.recipient_organisation ? `, ${f.recipient_organisation}` : ''}</dd>
                <dt>Delivery</dt><dd>{DELIVERY_CHANNEL.find(d => d.value === f.delivery_channel)?.label}</dd>
                <dt>Receipt URL</dt><dd>{f.enable_acknowledgment ? 'Yes' : 'No'}</dd>
              </dl>
            </div>
          )}

          {error && (
            <div className="alert error" role="alert" style={{ marginTop: 'var(--space-3)' }}>
              <span className="alert-icon">!</span><span>{error}</span>
            </div>
          )}
        </div>
        <div className="modal-foot" style={{ justifyContent: 'space-between' }}>
          <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
            {step > 1 && <button type="button" className="btn ghost" onClick={prev} disabled={busy}>Back</button>}
            {step < STEPS.length
              ? <button type="button" className="btn primary" onClick={next} disabled={busy}>Next</button>
              : <button type="button" className="btn primary" onClick={build} disabled={busy} data-testid="dw-build">
                  {busy ? 'Building…' : 'Build disclosure package'}
                </button>}
          </div>
        </div>
      </div>
    </div>
  )
}
