import { useEffect, useState } from 'react'
import LocalDateTimePicker from './LocalDateTimePicker.jsx'

// Response milestones, in order. The incident header offers the first one not yet set.
export const MILESTONES = [
  { field: 'contained_at',  label: 'contained',  title: 'Contained',  event: 'Containment declared' },
  { field: 'eradicated_at', label: 'eradicated', title: 'Eradicated', event: 'Eradication declared' },
  { field: 'recovered_at',  label: 'recovered',  title: 'Recovered',  event: 'Recovery declared' },
]

// "Declare contained / eradicated / recovered": one time, pre-filled with now and
// editable. `onConfirm(field, isoUtc)` does the PATCH; the API validates the time and
// adds the timeline event. Errors (e.g. a 422) show inline and keep the modal open.
export default function DeclareMilestoneModal({ milestone, onConfirm, onClose }) {
  const [value, setValue] = useState(() => new Date().toISOString())
  const [busy, setBusy]   = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  const submit = async (e) => {
    e.preventDefault()
    setError(null); setBusy(true)
    try {
      await onConfirm(milestone.field, value)
    } catch (err) {
      setError(err.message || 'Could not save.')
      setBusy(false)
    }
    // success path: parent unmounts the modal
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="declare-modal-title">
        <div className="modal-head">
          <h2 id="declare-modal-title">Declare {milestone.label}</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <form onSubmit={submit}>
          <div className="modal-body">
            <div className="form">
              <div className="field">
                <label className="field-label" htmlFor="declare-at">{milestone.title}</label>
                <LocalDateTimePicker id="declare-at" value={value} onChange={setValue} required />
                <span className="field-hint">
                  Pre-filled with now; change it if it happened earlier. Adds a “{milestone.event}” event to the Timeline.
                </span>
              </div>
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
            <button type="submit" className="btn primary" disabled={busy}>
              {busy ? 'Saving…' : `Declare ${milestone.label}`}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
