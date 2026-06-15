import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.js'
import { formatLocalShort, relative } from '../lib/datetime.js'

function AckModal({ handoff, onSave, onClose }) {
  const [note,   setNote]   = useState('')
  const [saving, setSaving] = useState(false)
  const [err,    setErr]    = useState('')

  async function submit(e) {
    e.preventDefault()
    setSaving(true); setErr('')
    try {
      await onSave(handoff, note || null)
      onClose()
    } catch (e) {
      setErr(e.message || 'Acknowledge failed')
      setSaving(false)
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 480 }}>
        <div className="modal-head">
          <span className="modal-title">Acknowledge handoff</span>
          <button className="modal-close" onClick={onClose} type="button">✕</button>
        </div>
        <form className="modal-body" onSubmit={submit}>
          <div style={{ marginBottom: 'var(--space-3)', color: 'var(--muted)', fontSize: 13 }}>
            Handoff from <strong style={{ color: 'var(--text)' }}>{handoff.outgoing_username}</strong>
            {' '}on incident <strong style={{ color: 'var(--accent)' }}>{handoff.incident_id}</strong>
          </div>
          {handoff.note && (
            <div style={{
              background: 'var(--surface-2)', borderRadius: 'var(--radius)',
              padding: 'var(--space-3)', marginBottom: 'var(--space-3)',
              fontSize: 13, whiteSpace: 'pre-wrap', borderLeft: '3px solid var(--border)',
            }}>
              {handoff.note}
            </div>
          )}
          {err && <div className="form-error">{err}</div>}
          <label className="form-label">Acknowledgment note (optional)</label>
          <textarea className="input" rows={3} value={note} onChange={e => setNote(e.target.value)}
            placeholder="Any notes for the outgoing analyst…" />
          <div className="modal-actions" style={{ marginTop: 'var(--space-4)' }}>
            <button type="button" className="btn" onClick={onClose} disabled={saving}>Cancel</button>
            <button type="submit" className="btn primary" disabled={saving}>
              {saving ? 'Saving…' : 'Acknowledge'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default function Handoffs() {
  const [items,   setItems]   = useState([])
  const [loading, setLoading] = useState(true)
  const [err,     setErr]     = useState('')
  const [acking,  setAcking]  = useState(null)  // handoff being acknowledged

  const load = useCallback(async () => {
    setErr('')
    try {
      const res = await api.listPendingHandoffs()
      setItems(res.items)
    } catch (e) {
      setErr(e.message || 'Could not load handoffs')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function handleAck(handoff, note) {
    await api.acknowledgeHandoff(handoff.incident_id, handoff.id, { acknowledged_note: note })
    await load()
  }

  return (
    <div className="page-wrap">
      <div className="page-head">
        <div>
          <div className="page-sub">Commander</div>
          <h1 className="page-title">Pending Handoffs</h1>
        </div>
      </div>

      {err && <div className="form-error" style={{ marginBottom: 'var(--space-3)' }}>{err}</div>}

      {loading ? (
        <div className="panel-empty">Loading…</div>
      ) : items.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark">✓</div>
          <div>No pending handoffs — you're all caught up.</div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
          {items.map(h => (
            <div key={h.id} className="panel" style={{
              padding: 'var(--space-4)',
              borderLeft: '3px solid var(--high)',
            }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-3)' }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 4 }}>
                    <span style={{ fontWeight: 600 }}>From {h.outgoing_username}</span>
                    <span style={{ color: 'var(--muted)', fontSize: 12 }}>{relative(h.created_at)}</span>
                  </div>
                  <div style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 'var(--space-2)' }}>
                    Incident:{' '}
                    <Link to={`/incidents/${h.incident_id}/handoffs`}
                      style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>
                      {h.incident_id}
                    </Link>
                  </div>
                  {h.note && (
                    <div style={{
                      background: 'var(--surface-2)', borderRadius: 'var(--radius)',
                      padding: 'var(--space-3)', fontSize: 13,
                      whiteSpace: 'pre-wrap', borderLeft: '3px solid var(--border)',
                    }}>
                      {h.note}
                    </div>
                  )}
                </div>
                <button className="btn primary" onClick={() => setAcking(h)}>
                  Acknowledge
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {acking && (
        <AckModal
          handoff={acking}
          onSave={handleAck}
          onClose={() => setAcking(null)}
        />
      )}
    </div>
  )
}
