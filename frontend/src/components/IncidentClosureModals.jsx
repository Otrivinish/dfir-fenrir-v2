import { useEffect, useState } from 'react'
import { PHASE, labelOf } from '../lib/incidentVocab.js'
import { GateItems, useGate } from './GateItems.jsx'

// Close and Re-open modals for the incident header. Both need a reason of at least
// REASON_MIN characters (the API checks it too: 422 reason_required). `onConfirm`
// does the POST; errors (e.g. a 409) show inline and keep the modal open.
// Close shows Gate 2 from the API; when it is unmet, closing needs Override (the
// sign-off statement is the justification), offered only with the override_gate
// capability from GET …/access (`canOverride`: the incident lead).
// Re-open: the API decides whether Gate 1 applies (re-opening into Post-Incident an
// incident closed in another phase); a 409 gate_unmet lists the items here, and the
// lead may then Override with the reason as the justification.
const REASON_MIN = 10
const REOPEN_PHASES = PHASE.filter(p => p.value !== 'preparation')

function useEscape(busy, onClose) {
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])
}

function ReasonField({ id, label, hint, placeholder, value, onChange }) {
  const n = value.trim().length
  return (
    <div className="field">
      <label className="field-label" htmlFor={id}>{label}</label>
      <textarea id={id} className="input" rows={4} maxLength={2000} required autoFocus
                placeholder={placeholder} value={value} onChange={e => onChange(e.target.value)} />
      <span className="field-hint">
        {hint}{n < REASON_MIN ? ` At least ${REASON_MIN} characters (${n} so far).` : ''}
      </span>
    </div>
  )
}

function ErrorAlert({ error }) {
  if (!error) return null
  return (
    <div className="alert error" role="alert">
      <span className="alert-icon">!</span>
      <span>{error}</span>
    </div>
  )
}

export function CloseIncidentModal({ inc, canOverride = false, onConfirm, onClose }) {
  const [reason, setReason]     = useState('')
  const [override, setOverride] = useState(false)
  const [busy, setBusy]         = useState(false)
  const [error, setError]       = useState(null)
  const { gate, setGate, loading, error: gateError } = useGate(inc.id, 'close')
  useEscape(busy, onClose)

  const unmet      = !!gate && !gate.met
  const overriding = unmet && canOverride && override

  const submit = async (e) => {
    e.preventDefault()
    setError(null); setBusy(true)
    try {
      await onConfirm(reason.trim(), overriding)
    } catch (err) {
      if (err.code === 'gate_unmet' && Array.isArray(err.data?.unmet)) {
        // The gate changed since it was loaded: show the server's list.
        setGate(g => ({ gate: 'close', label: g?.label || 'Gate 2', carried_forward: g?.carried_forward || [],
                        met: false, exempt: false, unmet: err.data.unmet }))
        setError('The gate is not met: see the list above.')
      } else {
        setError(err.message || 'Could not close the incident.')
      }
      setBusy(false)
    }
    // success path: parent unmounts the modal
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="close-inc-title">
        <div className="modal-head">
          <h2 id="close-inc-title">Close incident</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <form onSubmit={submit}>
          <div className="modal-body">
            <div className="form">
              <p style={{ margin: 0, color: 'var(--text)', fontSize: 14, lineHeight: 1.6 }}>
                Closing signs the incident off. You are recorded as the closer, and the incident becomes
                read-only except for Lessons Learned action items. Re-opening needs a reason.
              </p>
              {inc.phase !== 'post_incident' && (
                <div className="alert info" role="status">
                  <span className="alert-icon">i</span>
                  <span>
                    Closing as a <b>{labelOf('triage_state', inc.triage_state)}</b> from{' '}
                    <b>{labelOf('phase', inc.phase)}</b>; the phase stays as it is.
                  </span>
                </div>
              )}
              {loading && <span className="field-hint" role="status">Checking Gate 2…</span>}
              {gateError && (
                <ErrorAlert error={`${gateError} The server still checks the gate when you close.`} />
              )}
              <GateItems incidentId={inc.id} gate={gate} onNavigate={onClose} />
              {unmet && !canOverride && (
                <span className="field-hint" data-override-unavailable>
                  Only this incident's lead (Incident Commander or Deputy) or an admin can override the gate.
                </span>
              )}
              {unmet && canOverride && (
                <div className="field">
                  <label style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', cursor: 'pointer', fontSize: 13 }}>
                    <input id="close-override" type="checkbox" checked={override} disabled={busy}
                           aria-describedby="close-override-hint"
                           onChange={e => setOverride(e.target.checked)} />
                    Override: close anyway
                  </label>
                  <span id="close-override-hint" className="field-hint">
                    Your sign-off statement is the justification. The override and the missing items go into the audit log and onto the Timeline.
                  </span>
                </div>
              )}
              <ReasonField id="close-reason" label="Sign-off statement" value={reason} onChange={setReason}
                           placeholder="Why the incident can be closed, and on whose authority…"
                           hint="Goes into the audit log and the Timeline." />
              <ErrorAlert error={error} />
            </div>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button type="submit" className="btn primary"
                    disabled={busy || loading || (unmet && !overriding) || reason.trim().length < REASON_MIN}>
              {busy ? 'Closing…' : overriding ? 'Override and close' : 'Close incident'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export function ReopenIncidentModal({ incidentId, canOverride = false, onConfirm, onClose }) {
  const [reason, setReason]     = useState('')
  const [phase, setPhase]       = useState('')
  const [busy, setBusy]         = useState(false)
  const [error, setError]       = useState(null)
  const [gate, setGate]         = useState(null)    // from a 409 gate_unmet reply
  const [override, setOverride] = useState(false)
  useEscape(busy, onClose)

  const unmet      = !!gate && phase === 'post_incident'
  const overriding = unmet && canOverride && override

  const choosePhase = (value) => {
    setPhase(value)
    if (value !== 'post_incident') { setGate(null); setOverride(false); setError(null) }
  }

  const submit = async (e) => {
    e.preventDefault()
    setError(null); setBusy(true)
    try {
      await onConfirm(reason.trim(), phase, overriding)
    } catch (err) {
      if (err.code === 'gate_unmet' && Array.isArray(err.data?.unmet)) {
        setGate({ gate: 'post_incident', label: 'Gate 1', carried_forward: [], met: false, exempt: false,
                  unmet: err.data.unmet })
        setError('Gate 1 is not met: see the list above.')
      } else {
        setError(err.message || 'Could not re-open the incident.')
      }
      setBusy(false)
    }
    // success path: parent unmounts the modal
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="reopen-inc-title">
        <div className="modal-head">
          <h2 id="reopen-inc-title">Re-open incident</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <form onSubmit={submit}>
          <div className="modal-body">
            <div className="form">
              <div className="field">
                <label className="field-label" htmlFor="reopen-phase">Re-open in phase</label>
                <select id="reopen-phase" className="select" required value={phase}
                        onChange={e => choosePhase(e.target.value)}>
                  <option value="" disabled>Choose a phase…</option>
                  {REOPEN_PHASES.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
                </select>
              </div>
              {unmet && <GateItems incidentId={incidentId} gate={gate} onNavigate={onClose} />}
              {unmet && !canOverride && (
                <span className="field-hint" data-override-unavailable style={{ color: 'var(--muted)' }}>
                  Only this incident's lead (Incident Commander or Deputy) or an admin can override the gate.
                  You can re-open it in an earlier phase instead.
                </span>
              )}
              {unmet && canOverride && (
                <div className="field">
                  <label style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', cursor: 'pointer', fontSize: 13 }}>
                    <input id="reopen-override" type="checkbox" checked={override} disabled={busy}
                           aria-describedby="reopen-override-hint"
                           onChange={e => setOverride(e.target.checked)} />
                    Override: re-open in Post-Incident anyway
                  </label>
                  <span id="reopen-override-hint" className="field-hint" style={{ color: 'var(--muted)' }}>
                    Your reason is the justification. The override and the missing items go into the audit log and onto the Timeline.
                  </span>
                </div>
              )}
              <ReasonField id="reopen-reason" label="Reason" value={reason} onChange={setReason}
                           placeholder="What changed: new evidence, recurrence, a missed step…"
                           hint="Goes into the audit log and the Timeline. The closer and close time are cleared." />
              <ErrorAlert error={error} />
            </div>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button type="submit" className="btn primary"
                    disabled={busy || !phase || (unmet && !overriding) || reason.trim().length < REASON_MIN}>
              {busy ? 'Re-opening…' : overriding ? 'Override and re-open' : 'Re-open incident'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
