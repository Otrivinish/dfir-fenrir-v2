import { useCallback, useEffect, useState } from 'react'
import { api } from '../api/client.js'
import { useAuth } from '../hooks/useAuth.jsx'

function fmtDate(dateStr) {
  // dateStr is YYYY-MM-DD from the backend; display as-is (no TZ shift for calendar dates)
  return dateStr || ''
}

function initials(name, username) {
  const src = name || username || '?'
  return src.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2)
}

function EntryModal({ entry, users, onSave, onClose }) {
  const isEdit = !!entry
  const [userId,    setUserId]    = useState(entry?.user_id    ?? '')
  const [startDate, setStartDate] = useState(entry?.start_date ?? '')
  const [endDate,   setEndDate]   = useState(entry?.end_date   ?? '')
  const [notes,     setNotes]     = useState(entry?.notes      ?? '')
  const [saving,    setSaving]    = useState(false)
  const [err,       setErr]       = useState('')

  async function submit(e) {
    e.preventDefault()
    if (!userId)    { setErr('Select a user'); return }
    if (!startDate) { setErr('Set a start date'); return }
    if (!endDate)   { setErr('Set an end date'); return }
    if (endDate < startDate) { setErr('End date must be on or after start date'); return }
    setSaving(true); setErr('')
    try {
      await onSave({ user_id: userId, start_date: startDate, end_date: endDate, notes: notes || null })
      onClose()
    } catch (e) {
      setErr(e.message || 'Save failed')
      setSaving(false)
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <div className="modal-head">
          <span className="modal-title">{isEdit ? 'Edit on-call entry' : 'Add on-call entry'}</span>
          <button className="modal-close" onClick={onClose} type="button">✕</button>
        </div>
        <form className="modal-body" onSubmit={submit}>
          {err && <div className="form-error">{err}</div>}
          <label className="form-label">Analyst</label>
          <select className="input" value={userId} onChange={e => setUserId(e.target.value)} required>
            <option value="">— select —</option>
            {users.map(u => (
              <option key={u.id} value={u.id}>{u.username}{u.full_name ? ` (${u.full_name})` : ''}</option>
            ))}
          </select>
          <label className="form-label" style={{ marginTop: 'var(--space-3)' }}>Start date</label>
          <input className="input" type="date" value={startDate}
            onChange={e => setStartDate(e.target.value)} required />
          <label className="form-label" style={{ marginTop: 'var(--space-3)' }}>End date</label>
          <input className="input" type="date" value={endDate}
            onChange={e => setEndDate(e.target.value)} required />
          <label className="form-label" style={{ marginTop: 'var(--space-3)' }}>Notes (optional)</label>
          <input className="input" type="text" value={notes}
            onChange={e => setNotes(e.target.value)} maxLength={256} />
          <div className="modal-actions" style={{ marginTop: 'var(--space-4)' }}>
            <button type="button" className="btn" onClick={onClose} disabled={saving}>Cancel</button>
            <button type="submit" className="btn primary" disabled={saving}>
              {saving ? 'Saving…' : 'Save'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default function OnCall() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'

  const [data,       setData]       = useState({ items: [], current: null })
  const [users,      setUsers]      = useState([])
  const [loading,    setLoading]    = useState(true)
  const [err,        setErr]        = useState('')
  const [modal,      setModal]      = useState(null)  // null | 'add' | entry-object
  const [deletingId, setDeletingId] = useState(null)
  const [showPast,   setShowPast]   = useState(false)

  const load = useCallback(async () => {
    setErr('')
    try {
      const res = await api.listOnCall(showPast)
      setData(res)
    } catch (e) {
      setErr(e.message || 'Could not load schedule')
    } finally {
      setLoading(false)
    }
  }, [showPast])

  useEffect(() => { load() }, [load])

  useEffect(() => {
    if (!isAdmin) return
    api.listAssignableUsers().then(setUsers).catch(() => {})
  }, [isAdmin])

  async function handleSave(payload) {
    if (modal === 'add') {
      await api.createOnCall(payload)
    } else {
      await api.updateOnCall(modal.id, payload)
    }
    await load()
  }

  async function handleDelete(id) {
    if (!confirm('Remove this on-call entry?')) return
    setDeletingId(id)
    try {
      await api.deleteOnCall(id)
      await load()
    } catch (e) {
      setErr(e.message || 'Delete failed')
    } finally {
      setDeletingId(null)
    }
  }

  const cur = data.current

  return (
    <div className="page-wrap">
      <div className="page-head">
        <div>
          <div className="page-sub">Commander</div>
          <h1 className="page-title">On-Call Schedule</h1>
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--muted)', fontSize: 13, cursor: 'pointer' }}>
            <input type="checkbox" checked={showPast} onChange={e => setShowPast(e.target.checked)} />
            Show past
          </label>
          {isAdmin && (
            <button className="btn primary" onClick={() => setModal('add')}>+ Add entry</button>
          )}
        </div>
      </div>

      {err && <div className="form-error" style={{ marginBottom: 'var(--space-3)' }}>{err}</div>}

      {cur && (
        <div className="panel" style={{
          marginBottom: 'var(--space-4)',
          borderLeft: '3px solid var(--ok)',
          background: 'var(--surface)',
          padding: 'var(--space-3) var(--space-4)',
          display: 'flex', alignItems: 'center', gap: 'var(--space-3)',
        }}>
          <div style={{
            width: 36, height: 36, borderRadius: '50%',
            background: 'var(--ok)', color: '#000',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontWeight: 700, fontSize: 13, flexShrink: 0,
          }}>
            {initials(cur.display_name, cur.username)}
          </div>
          <div>
            <div style={{ fontWeight: 600 }}>
              {cur.display_name || cur.username}
              <span style={{ marginLeft: 8, color: 'var(--muted)', fontSize: 12 }}>@{cur.username}</span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>
              On-call now · {fmtDate(cur.start_date)} – {fmtDate(cur.end_date)}
              {cur.notes && <span style={{ marginLeft: 8 }}>{cur.notes}</span>}
            </div>
          </div>
          <span className="pill" style={{ marginLeft: 'auto', background: 'var(--ok)', color: '#000', fontSize: 11 }}>
            ACTIVE
          </span>
        </div>
      )}

      {loading ? (
        <div className="panel-empty">Loading…</div>
      ) : data.items.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark">○</div>
          <div>No on-call entries{showPast ? '' : ' — try enabling "Show past"'}.</div>
          {isAdmin && <div><button className="btn primary" onClick={() => setModal('add')}>Add the first entry</button></div>}
        </div>
      ) : (
        <div className="panel">
          <table className="data-table">
            <thead>
              <tr>
                <th>Analyst</th>
                <th>Start</th>
                <th>End</th>
                <th>Notes</th>
                <th>Status</th>
                {isAdmin && <th style={{ width: 80 }} />}
              </tr>
            </thead>
            <tbody>
              {data.items.map(e => {
                const today = new Date().toISOString().slice(0, 10)
                const isActive = e.start_date <= today && today <= e.end_date
                const isPast   = e.end_date < today
                return (
                  <tr key={e.id} style={{ opacity: isPast ? 0.55 : 1 }}>
                    <td>
                      <span style={{ fontWeight: 600 }}>{e.display_name || e.username}</span>
                      <span style={{ marginLeft: 6, color: 'var(--muted)', fontSize: 12 }}>@{e.username}</span>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{fmtDate(e.start_date)}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{fmtDate(e.end_date)}</td>
                    <td style={{ color: 'var(--muted)', fontSize: 13 }}>{e.notes || '—'}</td>
                    <td>
                      {isActive
                        ? <span className="pill" style={{ background: 'var(--ok)', color: '#000', fontSize: 11 }}>Active</span>
                        : isPast
                        ? <span className="pill" style={{ background: 'var(--surface-2)', color: 'var(--muted)', fontSize: 11 }}>Past</span>
                        : <span className="pill" style={{ background: 'var(--accent-soft)', color: 'var(--accent)', fontSize: 11 }}>Upcoming</span>
                      }
                    </td>
                    {isAdmin && (
                      <td>
                        <div style={{ display: 'flex', gap: 'var(--space-1)' }}>
                          <button className="btn" style={{ fontSize: 12, padding: '2px 8px' }}
                            onClick={() => setModal(e)}>Edit</button>
                          <button className="btn" style={{ fontSize: 12, padding: '2px 8px', color: 'var(--crit)' }}
                            disabled={deletingId === e.id}
                            onClick={() => handleDelete(e.id)}>
                            {deletingId === e.id ? '…' : 'Del'}
                          </button>
                        </div>
                      </td>
                    )}
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {modal && (
        <EntryModal
          entry={modal === 'add' ? null : modal}
          users={users}
          onSave={handleSave}
          onClose={() => setModal(null)}
        />
      )}
    </div>
  )
}
