import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { api } from '../../api/client.js'

// Public recipient-ack page for LE-package handoff (Wizard C step 6).
// No platform account required — the URL itself is the auth bearer.
// Single-use; token is burned on POST.

export default function AcknowledgeHandoff() {
  const { token } = useParams()
  const [pkg, setPkg]       = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]   = useState(null)

  const [name, setName]     = useState('')
  const [notes, setNotes]   = useState('')
  const [busy, setBusy]     = useState(false)
  const [done, setDone]     = useState(null)

  useEffect(() => {
    api.getLePackageByAck(token)
      .then(setPkg)
      .catch(e => setError(e.message || 'Token invalid or already consumed.'))
      .finally(() => setLoading(false))
  }, [token])

  async function submit(e) {
    e.preventDefault()
    if (!name.trim()) { setError('Please enter your name.'); return }
    setBusy(true); setError(null)
    try {
      const r = await api.acknowledgeLePackage(token, {
        name:  name.trim(),
        notes: notes.trim() || null,
      })
      setDone(r)
    } catch (e) {
      setError(e.message || 'Acknowledgment failed.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh', background: 'var(--bg)', color: 'var(--text)',
      display: 'flex', alignItems: 'flex-start', justifyContent: 'center',
      padding: 'var(--space-4)',
    }}>
      <div style={{
        width: 'min(640px, 100%)',
        background: 'var(--surface)', border: '1px solid var(--border)',
        borderRadius: 'var(--radius-lg)', padding: 'var(--space-4)',
        marginTop: 'var(--space-5)',
      }}>
        <h1 style={{ margin: 0, fontSize: 20 }}>DFIR-FENRIR — Evidence handoff acknowledgment</h1>
        <p style={{ margin: '4px 0 var(--space-3)', fontSize: 13, color: 'var(--muted)' }}>
          By submitting this form you confirm receipt of the law-enforcement evidence bundle described below.
        </p>

        {loading && <div style={{ color: 'var(--muted)' }}>Loading…</div>}

        {error && !done && (
          <div className="alert error" role="alert">
            <span className="alert-icon">!</span><span>{error}</span>
          </div>
        )}

        {pkg && !done && (
          <>
            <div style={{
              padding: 'var(--space-3)', background: 'var(--surface-2)',
              border: '1px solid var(--border)', borderRadius: 'var(--radius)',
              marginBottom: 'var(--space-3)', fontSize: 13,
              display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '4px 12px',
            }}>
              <span style={{ color: 'var(--muted)' }}>Case reference</span>
              <span style={{ fontFamily: 'var(--font-mono)' }}>{pkg.case_reference}</span>
              <span style={{ color: 'var(--muted)' }}>Requesting authority</span>
              <span>{pkg.requesting_authority}</span>
              <span style={{ color: 'var(--muted)' }}>Legal basis</span>
              <span>{pkg.legal_basis}</span>
              {pkg.eio_reference && (
                <>
                  <span style={{ color: 'var(--muted)' }}>EIO reference</span>
                  <span style={{ fontFamily: 'var(--font-mono)' }}>
                    {pkg.eio_reference} {pkg.issuing_state && pkg.executing_state ? `(${pkg.issuing_state} → ${pkg.executing_state})` : ''}
                  </span>
                </>
              )}
              {pkg.mla_reference && (
                <>
                  <span style={{ color: 'var(--muted)' }}>MLA reference</span>
                  <span style={{ fontFamily: 'var(--font-mono)' }}>{pkg.mla_reference}</span>
                </>
              )}
              <span style={{ color: 'var(--muted)' }}>Bundle SHA-256</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all' }}>{pkg.bundle_sha256}</span>
              <span style={{ color: 'var(--muted)' }}>Manifest SHA-256</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all' }}>{pkg.manifest_sha256}</span>
              <span style={{ color: 'var(--muted)' }}>Files / size</span>
              <span>{pkg.file_count} files · {pkg.total_bytes} bytes</span>
            </div>

            {pkg.sender_declaration && (
              <div style={{
                padding: 'var(--space-2) var(--space-3)', marginBottom: 'var(--space-3)',
                background: 'var(--surface-2)', border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)', fontSize: 11,
                color: 'var(--muted)', fontStyle: 'italic',
              }}>
                <strong style={{ color: 'var(--text)' }}>Sender declaration:</strong> {pkg.sender_declaration}
              </div>
            )}

            <form onSubmit={submit}>
              <div className="field" style={{ marginBottom: 'var(--space-2)' }}>
                <label className="field-label">Your name *</label>
                <input className="input" value={name} onChange={e => setName(e.target.value)}
                       autoFocus required maxLength={256}
                       placeholder="As recorded on your warrant card / court ID" />
              </div>
              <div className="field" style={{ marginBottom: 'var(--space-3)' }}>
                <label className="field-label">Notes (optional)</label>
                <textarea className="input" value={notes} onChange={e => setNotes(e.target.value)}
                          rows={3} maxLength={4096}
                          placeholder="e.g. received via courier ref 4471, sealed bag intact, hash matched on cross-check" />
              </div>
              <button type="submit" className="btn primary" disabled={busy}>
                {busy ? 'Submitting…' : 'I confirm receipt'}
              </button>
            </form>
          </>
        )}

        {done && (
          <div className="alert info" role="status">
            <span className="alert-icon">✓</span>
            <span>
              Receipt recorded for case <strong>{done.case_reference}</strong> at{' '}
              <span style={{ fontFamily: 'var(--font-mono)' }}>{done.acknowledged_at}</span>.
              Signed by <strong>{done.acknowledged_by_name}</strong>. You may close this page.
            </span>
          </div>
        )}
      </div>
    </div>
  )
}
