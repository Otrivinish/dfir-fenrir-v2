import { useCallback, useEffect, useRef, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../../api/client.js'
import { formatLocal, formatLocalShort } from '../../../lib/datetime.js'
import LocalDateTimePicker from '../../../components/LocalDateTimePicker.jsx'
import DisclosureWizard, { BASIS_LABEL, PURPOSES } from './DisclosureWizard.jsx'

// Evidence › Disclosure package (K1, R36): Evidence › Export and Post-Incident › Reports › LE package merged
// into one signed, custody-logged package per purpose (internal / law enforcement / regulator). The incident
// lead or an admin builds them (manage_disclosures from GET …/access; the API enforces it).

const PURPOSE_LABEL = Object.fromEntries(PURPOSES.map(p => [p.value, p.label]))
const STATUS = {
  ready:    ['pill-ok', 'Ready'],
  consumed: ['pill-gray', 'Downloaded'],
  expired:  ['pill-gray', 'Expired'],
  revoked:  ['pill-crit', 'Revoked'],
  pending:  ['pill-med', 'Pending'],
}

function fmtBytes(n) {
  if (n == null) return '—'
  const units = ['B', 'KiB', 'MiB', 'GiB']
  let v = n, i = 0
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

function StatusPill({ status }) {
  const [cls, label] = STATUS[status] || ['pill-gray', status || '—']
  return <span className={`pill ${cls}`}>{label}</span>
}

function Hash({ value }) {
  if (!value) return <span style={{ color: 'var(--dim)' }}>—</span>
  return <span title={value} style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{value.slice(0, 12)}…</span>
}

export default function Disclosure() {
  const { inc, access } = useOutletContext()
  const canManage = !!access?.capabilities?.includes('manage_disclosures')
  const [items, setItems] = useState([])
  const [legacy, setLegacy] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [modal, setModal] = useState(null)          // null | 'wizard' | { ack: disclosure }
  const [issued, setIssued] = useState(null)
  const loadAbort = useRef(null)

  const load = useCallback(async () => {
    if (!canManage) { setLoading(false); return }
    loadAbort.current?.abort()
    const { signal } = (loadAbort.current = new AbortController())
    setError(null)
    try {
      const [all, exports] = await Promise.all([
        api.listAllPages(api.listDisclosures, inc.id, {}, 200, { signal }),
        api.listAllPages(api.listExports, inc.id, {}, 200, { signal }).catch(() => []),
      ])
      if (signal.aborted) return
      setItems(all)
      // Evidence exports built before K1 (no disclosure record of their own): kept visible, read-only.
      const own = new Set(all.map(d => d.custody_export_id))
      setLegacy(exports.filter(e => !own.has(e.id)))
    } catch (e) {
      if (!signal.aborted) setError(e.message || 'Could not load the disclosure packages')
    } finally {
      if (!signal.aborted) setLoading(false)
    }
  }, [inc.id, canManage])

  useEffect(() => { load(); return () => loadAbort.current?.abort() }, [load])

  if (!canManage) {
    return (
      <section className="panel">
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">⇪</div>
          <div>Disclosure packages are for this incident’s lead.</div>
          <div style={{ color: 'var(--dim)', fontSize: 12 }}>
            An admin, or the analyst assigned as Incident Commander or Deputy, builds them. Ask them to disclose the exhibits.
          </div>
        </div>
      </section>
    )
  }

  return (
    <section className="panel" data-testid="disclosure-page">
      <div className="panel-toolbar">
        <h2 className="panel-h">Disclosure packages</h2>
        <button type="button" className="btn primary" onClick={() => setModal('wizard')} data-testid="disclosure-new">
          + New disclosure package
        </button>
      </div>
      <div className="field-hint" style={{ margin: '0 0 var(--space-3)' }}>
        One signed, custody-logged package per handoff: exhibits, their custody and audit trail, and the records
        the purpose needs. AES-256 password-protected ZIP; the password and the one-time download link are shown once.
      </div>

      {error && <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div>}

      {loading ? (
        <div className="panel-empty"><div>Loading…</div></div>
      ) : items.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">⇪</div>
          <div>No disclosure packages yet.</div>
          <div style={{ color: 'var(--dim)', fontSize: 12 }}>Click “+ New disclosure package” to build one.</div>
        </div>
      ) : (
        <div className="table-scroll">
          <table className="settings-table compact" data-testid="disclosure-list">
            <thead>
              <tr>
                <th>Purpose</th><th>Case</th><th>Recipient</th><th>Exhibits</th><th>Built</th>
                <th>Size</th><th>Bundle SHA-256</th><th>Status</th><th className="actions">Receipt</th>
              </tr>
            </thead>
            <tbody>
              {items.map(d => (
                <tr key={d.id}>
                  <td><span className="pill">{PURPOSE_LABEL[d.purpose] || d.purpose}</span></td>
                  <td>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{d.case_reference}</div>
                    <div style={{ color: 'var(--muted)', fontSize: 11 }}>{BASIS_LABEL[d.legal_basis] || d.legal_basis}</div>
                  </td>
                  <td>
                    <div>{d.recipient_name || '—'}</div>
                    <div style={{ color: 'var(--muted)', fontSize: 11 }}>{d.recipient_organisation || d.requesting_authority}</div>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{d.evidence_count ?? d.item_ids?.length ?? 0}</td>
                  <td title={formatLocal(d.prepared_at)}>{formatLocalShort(d.prepared_at)}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{fmtBytes(d.total_bytes)}</td>
                  <td><Hash value={d.bundle_sha256} /></td>
                  <td><StatusPill status={d.status} /></td>
                  <td className="actions">
                    {d.acknowledged_at ? (
                      <span style={{ fontSize: 12, color: 'var(--ok)' }}
                            title={`Received by ${d.acknowledged_by_name || '—'} at ${formatLocal(d.acknowledged_at)}`}>
                        ✓ {formatLocalShort(d.acknowledged_at)}
                      </span>
                    ) : (
                      <button type="button" className="btn ghost" onClick={() => setModal({ ack: d })}
                              title="Record a receipt the recipient gave outside the platform">
                        Record receipt
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {legacy.length > 0 && (
        <details style={{ marginTop: 'var(--space-4)' }} data-testid="disclosure-legacy">
          <summary style={{ cursor: 'pointer', color: 'var(--muted)', fontSize: 13 }}>
            Earlier evidence exports ({legacy.length}) — built before disclosure packages
          </summary>
          <div className="table-scroll" style={{ marginTop: 'var(--space-2)' }}>
            <table className="settings-table compact">
              <thead><tr><th>Recipient</th><th>Purpose</th><th>Exhibits</th><th>Size</th><th>Bundle SHA-256</th><th>Built</th><th>Status</th></tr></thead>
              <tbody>
                {legacy.map(e => (
                  <tr key={e.id}>
                    <td>{e.recipient}</td>
                    <td style={{ color: 'var(--muted)', fontSize: 12 }}>{e.purpose}</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{e.item_ids?.length || 0}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{fmtBytes(e.file_size)}</td>
                    <td><Hash value={e.bundle_sha256} /></td>
                    <td title={formatLocal(e.created_at)}>{formatLocalShort(e.created_at)}</td>
                    <td><StatusPill status={e.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}

      {modal === 'wizard' && (
        <DisclosureWizard inc={inc} onClose={() => setModal(null)}
                          onIssued={(r) => { setModal(null); setIssued(r); load() }} />
      )}
      {modal?.ack && (
        <ManualAckModal inc={inc} lp={modal.ack} onClose={() => setModal(null)}
                        onAcked={() => { setModal(null); load() }} />
      )}
      {issued && <IssuedModal issued={issued} onClose={() => setIssued(null)} />}
    </section>
  )
}

// ─── The one-time result ──────────────────────────────────────────────────────

function CopyButton({ text, label }) {
  const [done, setDone] = useState(false)
  return (
    <button type="button" className="btn ghost" onClick={async () => {
      try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1500) } catch { /* select + copy by hand */ }
    }}>{done ? '✓ Copied' : label}</button>
  )
}

function IssuedModal({ issued, onClose }) {
  const drafts = issued.unsealed_drafts_excluded || []
  const failed = issued.integrity_failures || []
  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="di-title" style={{ width: 'min(720px, 96vw)' }}
           data-testid="disclosure-issued">
        <div className="modal-head">
          <h2 id="di-title">Disclosure package ready — shown once</h2>
        </div>
        <div className="modal-body">
          <div className="form">
            <p style={{ margin: 0, fontSize: 13, color: 'var(--muted)' }}>
              {PURPOSE_LABEL[issued.purpose] || issued.purpose} package for <b>{issued.recipient_name || issued.requesting_authority}</b>.
              The bundle is an AES-256 password-protected ZIP that opens in any standard archive tool. Give the
              password to the recipient over a separate channel: it is <b>not</b> shown again.
            </p>
            <div className="field">
              <span className="field-label">Bundle password</span>
              <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
                <div className="disclosure-secret" style={{ flex: 1 }} data-testid="di-password">{issued.bundle_password}</div>
                <CopyButton text={issued.bundle_password} label="Copy" />
              </div>
            </div>
            <div className="field">
              <span className="field-label">Download (single use, 24 h)</span>
              <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
                <a className="btn primary" href={issued.download_url} download>↓ Download bundle (.zip)</a>
                <CopyButton text={`${window.location.origin}${issued.download_url}`} label="Copy link" />
              </div>
              <div className="field-hint">The first successful download uses up the link.</div>
            </div>
            <dl className="disclosure-review">
              <dt>Signature</dt><dd>Ed25519 over MANIFEST.json (MANIFEST.json.sig + SIGNING_PUBLIC_KEY.pem), plus HMAC-SHA-256</dd>
              <dt>Bundle SHA-256</dt><dd style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{issued.bundle_sha256}</dd>
              <dt>Manifest SHA-256</dt><dd style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{issued.manifest_sha256}</dd>
              <dt>Audit anchor</dt><dd style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{issued.audit_anchor_row_hash || '—'}</dd>
              <dt>Contents</dt><dd>{issued.evidence_count ?? 0} exhibits · {issued.file_count ?? 0} files · {fmtBytes(issued.total_bytes)} · {issued.audit_row_count ?? 0} audit rows</dd>
            </dl>
            {drafts.length > 0 && (
              <div className="alert info" role="status" data-testid="di-drafts">
                <span className="alert-icon">i</span>
                <span>Left out as unsealed drafts ({drafts.length}): {drafts.join(', ')}. Seal them on Exhibits and build again to include them.</span>
              </div>
            )}
            {failed.length > 0 && (
              <div className="alert error" role="alert" data-testid="di-integrity">
                <span className="alert-icon">!</span>
                <span>
                  Failed their integrity check while the package was built ({failed.length}): {failed.map(x => x.identifier).join(', ')}.
                  The package lists each without its file, and each is now frozen (verify failed). Don’t hand the package over without explaining this.
                </span>
              </div>
            )}
            {issued.acknowledgment_url && (
              <div className="field">
                <span className="field-label">Recipient receipt URL (single use)</span>
                <div className="disclosure-secret">{window.location.origin}{issued.acknowledgment_url}</div>
                <div className="field-hint">Print it on the handoff form or send it with the package. The recipient’s receipt is written to the audit log.</div>
              </div>
            )}
          </div>
        </div>
        <div className="modal-foot">
          <button type="button" className="btn primary" onClick={onClose}>I’ve recorded the password — close</button>
        </div>
      </div>
    </div>
  )
}

// ─── Receipt recorded by hand ─────────────────────────────────────────────────
// The lead attests, for the recipient, that they received the package outside the platform (paper, email,
// phone, in person, portal). The audit row says details.method = "manual:…"; the receipt URL is burned.

const ACK_METHODS = [
  { value: 'paper',         label: 'Signed paper receipt' },
  { value: 'email',         label: 'Signed / PDF email reply' },
  { value: 'phone',         label: 'Phone-confirmed' },
  { value: 'in_person',     label: 'In-person handoff' },
  { value: 'secure_portal', label: 'Secure-portal upload' },
  { value: 'other',         label: 'Other (say how in the attestation)' },
]

function ManualAckModal({ inc, lp, onClose, onAcked }) {
  const [form, setForm] = useState({
    recipient_name: lp.recipient_name || '', recipient_title: '', recipient_agency: lp.recipient_organisation || '',
    received_at: new Date().toISOString(), method: 'paper', attestation_text: '', evidence_id: '',
  })
  const [exhibits, setExhibits] = useState([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  useEffect(() => {
    const ctl = new AbortController()
    api.listAllPages(api.listEvidence, inc.id, {}, 200, { signal: ctl.signal })
      .then(all => { if (!ctl.signal.aborted) setExhibits(all) })
      .catch(() => {})
    return () => ctl.abort()
  }, [inc.id])

  async function submit() {
    if (!form.recipient_name.trim() || form.attestation_text.trim().length < 10) {
      setError('The recipient’s name and an attestation of at least 10 characters are required.')
      return
    }
    setBusy(true); setError(null)
    try {
      await api.manualAckLePackage(inc.id, lp.id, {
        recipient_name: form.recipient_name.trim(),
        recipient_title: form.recipient_title.trim() || null,
        recipient_agency: form.recipient_agency.trim() || null,
        received_at: form.received_at,
        method: form.method,
        attestation_text: form.attestation_text.trim(),
        evidence_id: form.evidence_id || null,
      })
      onAcked()
    } catch (e) {
      setError(e.message || 'The receipt could not be recorded')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="dack-title" style={{ width: 'min(640px, 96vw)' }}>
        <div className="modal-head">
          <h2 id="dack-title">Record receipt</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <div className="modal-body">
          <div className="form">
            <div className="field-hint">
              Package <span style={{ fontFamily: 'var(--font-mono)' }}>{lp.case_reference}</span> ({PURPOSE_LABEL[lp.purpose] || lp.purpose}).
              You attest the receipt for the recipient; the receipt URL stops working.
            </div>
            <div className="form-row">
              <div className="field">
                <label className="field-label" htmlFor="dack-name">Recipient name *</label>
                <input id="dack-name" className="input" value={form.recipient_name} maxLength={256}
                       onChange={e => set('recipient_name', e.target.value)} />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="dack-title-in">Title</label>
                <input id="dack-title-in" className="input" value={form.recipient_title} maxLength={256}
                       onChange={e => set('recipient_title', e.target.value)} />
              </div>
            </div>
            <div className="form-row">
              <div className="field">
                <label className="field-label" htmlFor="dack-agency">Agency / organisation</label>
                <input id="dack-agency" className="input" value={form.recipient_agency} maxLength={256}
                       onChange={e => set('recipient_agency', e.target.value)} />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="dack-at">Received at *</label>
                <LocalDateTimePicker id="dack-at" value={form.received_at} onChange={v => set('received_at', v)} required />
              </div>
            </div>
            <div className="field">
              <label className="field-label" htmlFor="dack-method">How it was confirmed *</label>
              <select id="dack-method" className="select" value={form.method} onChange={e => set('method', e.target.value)}>
                {ACK_METHODS.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
              </select>
            </div>
            <div className="field">
              <label className="field-label" htmlFor="dack-att">Attestation *</label>
              <textarea id="dack-att" className="input" rows={4} maxLength={4096} value={form.attestation_text}
                        onChange={e => set('attestation_text', e.target.value)}
                        placeholder="e.g. Signed paper receipt from Det. Smith at police HQ; scanned and registered as an exhibit." />
            </div>
            <div className="field">
              <label className="field-label" htmlFor="dack-ev">Scanned receipt (exhibit, optional)</label>
              <select id="dack-ev" className="select" value={form.evidence_id} onChange={e => set('evidence_id', e.target.value)}>
                <option value="">— none —</option>
                {exhibits.map(e => <option key={e.id} value={e.id}>{e.identifier} — {e.name}</option>)}
              </select>
              <div className="field-hint">Register the scan first (Evidence › Register) so it is encrypted and custody-logged.</div>
            </div>
            {error && <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div>}
          </div>
        </div>
        <div className="modal-foot">
          <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="button" className="btn primary" onClick={submit} disabled={busy}>
            {busy ? 'Recording…' : 'Record receipt'}
          </button>
        </div>
      </div>
    </div>
  )
}
