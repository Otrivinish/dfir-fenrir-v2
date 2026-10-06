import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import { api } from '../api/client.js'
import LocalDateTimePicker from './LocalDateTimePicker.jsx'

const OUTCOMES = [
  { value: 'pending',  label: 'Pending'  },
  { value: 'approved', label: 'Approved' },
  { value: 'rejected', label: 'Rejected' },
  { value: 'deferred', label: 'Deferred' },
]

// J4 (R33): promote a War Room message (kind "warroom") or a comment (kind "comment") of this
// incident to a timeline event or a Respond decision. Text and time start as the message's and
// stay editable; the server keeps the reference to the message and audits the promotion.
export default function PromoteDialog({ incidentId, source, onClose, onDone }) {
  const [target,  setTarget]  = useState('timeline_event')
  const [text,    setText]    = useState((source.body ?? '').slice(0, 4096))
  const [when,    setWhen]    = useState(source.created_at ?? '')
  const [outcome, setOutcome] = useState('pending')
  const [busy,    setBusy]    = useState(false)
  const [error,   setError]   = useState(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  const submit = async (e) => {
    e.preventDefault()
    if (!text.trim()) { setError('The text can’t be empty.'); return }
    setBusy(true); setError(null)
    try {
      const res = await api.promoteMessage(incidentId, {
        source_kind: source.kind, source_id: source.id, target,
        text: text.trim(), event_time: when || null,
        ...(target === 'decision' ? { outcome } : {}),
      })
      onDone(res)
    } catch (e2) {
      setError(e2.message || 'Could not promote the message')
      setBusy(false)
    }
  }

  return createPortal(
    <div className="modal-backdrop" style={{ zIndex: 60 }}>
      <div className="modal" role="dialog" aria-labelledby="promote-title" data-promote-dialog style={{ maxWidth: 520 }}>
        <div className="modal-head">
          <h2 id="promote-title">Promote {source.kind === 'warroom' ? 'War Room message' : 'comment'}</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy}>×</button>
        </div>
        <form onSubmit={submit}>
          <div className="modal-body">
            <div className="form">
              <fieldset className="field" style={{ border: 'none', padding: 0, margin: 0 }}>
                <legend className="field-label">Promote to</legend>
                <div style={{ display: 'flex', gap: 'var(--space-4)' }}>
                  <label style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                    <input type="radio" name="promote-target" value="timeline_event"
                           checked={target === 'timeline_event'} onChange={() => setTarget('timeline_event')} />
                    Timeline event
                  </label>
                  <label style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                    <input type="radio" name="promote-target" value="decision"
                           checked={target === 'decision'} onChange={() => setTarget('decision')} />
                    Decision
                  </label>
                </div>
              </fieldset>
              <div className="field">
                <label className="field-label" htmlFor="promote-text">
                  {target === 'decision' ? 'Decision summary' : 'Event description'}
                </label>
                <textarea id="promote-text" className="input" rows={4} maxLength={4096} required
                          value={text} onChange={(e) => setText(e.target.value)} />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="promote-time">
                  {target === 'decision' ? 'Decided at' : 'Event time'}
                </label>
                <LocalDateTimePicker id="promote-time" value={when} onChange={setWhen} required />
              </div>
              {target === 'decision' && (
                <div className="field">
                  <label className="field-label" htmlFor="promote-outcome">Outcome</label>
                  <select id="promote-outcome" className="select" value={outcome} onChange={(e) => setOutcome(e.target.value)}>
                    {OUTCOMES.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
              )}
              <span className="field-hint">The new record keeps a link to this message; the promotion is audited.</span>
              {error && (
                <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div>
              )}
            </div>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button type="submit" className="btn primary" disabled={busy}>{busy ? 'Promoting…' : 'Promote'}</button>
          </div>
        </form>
      </div>
    </div>,
    document.body,
  )
}
