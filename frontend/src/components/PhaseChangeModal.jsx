import { useEffect, useState } from 'react'
import { PHASE, labelOf } from '../lib/incidentVocab.js'
import { GateItems, useGate } from './GateItems.jsx'

// Confirmation modal for phase changes from the status-band stepper.
// `currentPhase` and `targetPhase` are 800-61 R3 values from incidentVocab.
// Moving into Post-Incident shows Gate 1 from the API; when it is unmet the move needs
// Override + a justification. Moving back needs a reason. The API enforces both.
// `onConfirm(targetPhase, { phase_reason?, override_gate? })` returns a promise; the
// modal shows loading + surfaces errors inline. `canOverride` is the override_gate
// capability from GET …/access (the incident lead); without it no Override is offered.
// A false / benign positive leaving Detection & Analysis can later close without Gate 2, so
// the API needs triage_reason for that move (M2: 422 triage_reason_required): `triageState`
// is the incident's triage_state, and the modal then asks for it.
const REASON_MIN = 10
const CLOSABLE_ANY_PHASE = ['false_positive', 'benign_positive']

export default function PhaseChangeModal({ incidentId, currentPhase, targetPhase, triageState, canOverride = false, onConfirm, onClose }) {
  const [busy, setBusy]         = useState(false)
  const [error, setError]       = useState(null)
  const [reason, setReason]     = useState('')
  const [triageReason, setTriageReason] = useState('')
  const [override, setOverride] = useState(false)
  const gated = targetPhase === 'post_incident'
  const { gate, setGate, loading, error: gateError } = useGate(incidentId, 'post_incident', gated)

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

  const unmet      = gated && !!gate && !gate.met
  const overriding = unmet && canOverride && override
  const needReason = goingBack || overriding
  const n          = reason.trim().length
  const needTriageReason = currentPhase === 'detection_and_analysis' && targetPhase !== currentPhase
                           && CLOSABLE_ANY_PHASE.includes(triageState)
  const tn         = triageReason.trim().length
  const triageLabel = labelOf('triage_state', triageState)
  const canSubmit  = !busy && !(gated && loading) && !(unmet && !overriding) && (!needReason || n >= REASON_MIN)
                     && (!needTriageReason || tn >= REASON_MIN)

  const submit = async () => {
    setError(null); setBusy(true)
    const extra = {}
    if (needReason) extra.phase_reason = reason.trim()
    if (overriding) extra.override_gate = true
    if (needTriageReason) extra.triage_reason = triageReason.trim()
    try {
      await onConfirm(targetPhase, extra)
    } catch (e) {
      if (e.code === 'gate_unmet' && Array.isArray(e.data?.unmet)) {
        // The gate changed since it was loaded: show the server's list.
        setGate(g => ({ gate: 'post_incident', label: g?.label || 'Gate 1', carried_forward: g?.carried_forward || [],
                        met: false, exempt: false, unmet: e.data.unmet }))
        setError('The gate is not met: see the list above.')
      } else if (e.code === 'triage_reason_required') {
        setError(`Say why this incident is a ${triageLabel || 'false or benign positive'}: at least ${REASON_MIN} characters. `
                 + 'It leaves Detection & Analysis and can then be closed without Gate 2.')
      } else {
        setError(e.message || 'Could not change phase.')
      }
      setBusy(false)
    }
    // success path: parent unmounts the modal
  }

  return (
    <div className="modal-backdrop">
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
          <div className="form">
            <p style={{ margin: 0, color: 'var(--text)', fontSize: 14, lineHeight: 1.6 }}>
              Phase will move from <b>{from?.label || currentPhase}</b> to <b>{to?.label}</b>.
              {' '}This change is recorded in the audit log.
            </p>
            {goingBack && (
              <div className="alert warn" role="status">
                <span className="alert-icon">!</span>
                <span>You're moving back to an earlier phase. Give the reason; it goes into the audit log.</span>
              </div>
            )}
            {gated && loading && (
              <span className="field-hint" role="status">Checking Gate 1…</span>
            )}
            {gated && gateError && (
              <div className="alert error" role="alert">
                <span className="alert-icon">!</span>
                <span>{gateError} The server still checks the gate when you confirm.</span>
              </div>
            )}
            {gated && <GateItems incidentId={incidentId} gate={gate} onNavigate={onClose} />}
            {unmet && !canOverride && (
              <span className="field-hint" data-override-unavailable>
                Only this incident's lead (Incident Commander or Deputy) or an admin can override the gate.
              </span>
            )}
            {unmet && canOverride && (
              <div className="field">
                <label style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', cursor: 'pointer', fontSize: 13 }}>
                  <input id="phase-override" type="checkbox" checked={override} disabled={busy}
                         aria-describedby="phase-override-hint"
                         onChange={e => setOverride(e.target.checked)} />
                  Override: move to {to?.label} anyway
                </label>
                <span id="phase-override-hint" className="field-hint">
                  The override, the missing items and your justification go into the audit log and onto the Timeline.
                </span>
              </div>
            )}
            {needReason && (
              <div className="field">
                <label className="field-label" htmlFor="phase-reason">
                  {goingBack ? 'Reason for moving back' : 'Override justification'}
                </label>
                <textarea id="phase-reason" className="input" rows={3} maxLength={2000} required
                          placeholder={goingBack ? 'What changed: new evidence, recurrence, a missed step…'
                                                 : 'Why the incident can move on although items are missing…'}
                          value={reason} onChange={e => setReason(e.target.value)} disabled={busy} />
                <span className="field-hint">
                  Goes into the audit log.{n < REASON_MIN ? ` At least ${REASON_MIN} characters (${n} so far).` : ''}
                </span>
              </div>
            )}
            {needTriageReason && (
              <div className="field">
                <label className="field-label" htmlFor="phase-triage-reason">
                  Reason for the {triageLabel} triage
                </label>
                <textarea id="phase-triage-reason" className="input" rows={3} maxLength={2000} required
                          aria-describedby="phase-triage-reason-hint"
                          placeholder="What was checked, by whom, and why it is not malicious…"
                          value={triageReason} onChange={e => setTriageReason(e.target.value)} disabled={busy} />
                <span id="phase-triage-reason-hint" className="field-hint">
                  A {triageLabel} that leaves Detection & Analysis can be closed without Gate 2, so the reason goes
                  into the audit log and onto the Timeline.{tn < REASON_MIN ? ` At least ${REASON_MIN} characters (${tn} so far).` : ''}
                </span>
              </div>
            )}
            {error && (
              <div className="alert error" role="alert">
                <span className="alert-icon">!</span>
                <span>{error}</span>
              </div>
            )}
          </div>
        </div>
        <div className="modal-foot">
          <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="button" className="btn primary" onClick={submit} disabled={!canSubmit}>
            {busy ? 'Saving…' : overriding ? 'Override and advance' : `${verb} phase`}
          </button>
        </div>
      </div>
    </div>
  )
}
