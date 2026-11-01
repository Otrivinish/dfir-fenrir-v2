import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import { api } from '../api/client.js'

// RD: an admin defers failing readiness checks for good (POST /api/readiness/deferrals). Every listed
// check starts ticked; the reason is optional. The server decides what may be deferred and audits it.
export default function ReadinessDeferDialog({ checks, onClose, onDone }) {
  const [picked, setPicked] = useState(() => checks.map(c => c.id))
  const [reason, setReason] = useState('')
  const [busy, setBusy]     = useState(false)
  const [error, setError]   = useState(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  const toggle = (id) => setPicked(p => p.includes(id) ? p.filter(x => x !== id) : [...p, id])

  const submit = async (e) => {
    e.preventDefault()
    if (!picked.length) { setError('Tick at least one check.'); return }
    setBusy(true); setError(null)
    try {
      onDone(await api.deferReadinessChecks({ check_ids: picked, reason: reason.trim() || null }))
    } catch (e2) {
      setError(e2.message || 'Could not defer the checks')
      setBusy(false)
    }
  }

  return createPortal(
    <div className="modal-backdrop" style={{ zIndex: 60 }}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="rd-defer-title" style={{ maxWidth: 520 }}>
        <div className="modal-head">
          <h2 id="rd-defer-title">Defer readiness check{checks.length === 1 ? '' : 's'}</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <form onSubmit={submit}>
          <div className="modal-body">
            <div className="form">
              <p className="rd-defer-intro">
                A deferred check stops showing on the Dashboard and in New incident, for everyone, until an admin
                undoes it. It keeps running and stays on the Readiness page, marked Deferred.
              </p>
              <fieldset className="field rd-defer-checks">
                <legend className="field-label">Checks</legend>
                {checks.map(c => (
                  <label key={c.id} className="rd-defer-check">
                    <input type="checkbox" checked={picked.includes(c.id)} onChange={() => toggle(c.id)} />
                    <span>{c.title}</span>
                  </label>
                ))}
              </fieldset>
              <div className="field">
                <label className="field-label" htmlFor="rd-defer-reason">Reason (optional)</label>
                <textarea id="rd-defer-reason" className="input" rows={3} maxLength={500}
                          value={reason} onChange={(e) => setReason(e.target.value)} />
              </div>
              <span className="field-hint">Each deferral is audit-logged with who deferred it and when.</span>
              {error && (
                <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div>
              )}
            </div>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button type="submit" className="btn primary" disabled={busy || !picked.length}>
              {busy ? 'Deferring…' : 'Defer'}
            </button>
          </div>
        </form>
      </div>
    </div>,
    document.body,
  )
}
