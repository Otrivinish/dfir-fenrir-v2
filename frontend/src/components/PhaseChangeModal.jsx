import { useEffect, useState } from 'react'
import { PHASE } from '../lib/incidentVocab.js'

// Confirmation modal for phase changes from the status-band stepper.
// `currentPhase` and `targetPhase` are 800-61 R3 values from incidentVocab.
// `onConfirm` returns a promise; modal shows loading + surfaces errors inline.
export default function PhaseChangeModal({ currentPhase, targetPhase, onConfirm, onClose }) {
  const [busy, setBusy]   = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  if (!targetPhase) return null

  const fromIdx = PHASE.findIndex(p => p.value === currentPhase)
  const toIdx   = PHASE.findIndex(p => p.value === targetPhase)
  const goingBack = toIdx < fromIdx

  const from = PHASE[fromIdx]
  const to   = PHASE[toIdx]
  const verb = goingBack ? 'Revert' : 'Advance'

  const submit = async () => {
    setError(null); setBusy(true)
    try {
      await onConfirm(targetPhase)
    } catch (e) {
      setError(e.message || 'Could not change phase.')
      setBusy(false)
    }
    // success path: parent unmounts the modal
  }

  return (
    <div
      className="modal-backdrop"
     
    >
      <div className="modal" role="dialog" aria-labelledby="phase-modal-title">
        <div className="modal-head">
          <h2 id="phase-modal-title">{verb} to {to?.label}?</h2>
          <button
            type="button"
            className="modal-close"
            onClick={onClose}
            disabled={busy}
            aria-label="Close"
          >×</button>
        </div>
        <div className="modal-body">
          <p style={{ margin: '0 0 var(--space-3) 0', color: 'var(--text)', fontSize: 14, lineHeight: 1.6 }}>
            Phase will move from <b>{from?.label || currentPhase}</b> to <b>{to?.label}</b>.
            {' '}This change is recorded in the audit log.
          </p>
          {goingBack && (
            <div className="alert warn" role="status" style={{ marginBottom: 'var(--space-2)' }}>
              <span className="alert-icon">!</span>
              <span>You're reverting to an earlier phase. Confirm this matches your runbook.</span>
            </div>
          )}
          {error && (
            <div className="alert error" role="alert">
              <span className="alert-icon">!</span>
              <span>{error}</span>
            </div>
          )}
        </div>
        <div className="modal-foot">
          <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="button" className="btn primary" onClick={submit} disabled={busy}>
            {busy ? 'Saving…' : `${verb} phase`}
          </button>
        </div>
      </div>
    </div>
  )
}
