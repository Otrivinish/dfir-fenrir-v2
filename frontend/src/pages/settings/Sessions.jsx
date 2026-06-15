import { useCallback, useEffect, useState } from 'react'
import { api } from '../../api/client.js'
import { formatLocal, formatLocalShort, relative } from '../../lib/datetime.js'

export default function Sessions() {
  const [sessions, setSessions] = useState([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [busy, setBusy]         = useState(false)
  const [editingId, setEditingId]   = useState(null)
  const [editLabel, setEditLabel]   = useState('')

  const load = useCallback(async () => {
    setError(null)
    try {
      const list = await api.listSessions()
      setSessions(list)
    } catch (e) {
      setError(e.message || 'Could not load sessions')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const onRevoke = async (s) => {
    if (s.is_current) return
    if (!window.confirm(`Revoke session "${s.label || s.id.slice(0, 8)}"?`)) return
    setBusy(true)
    try {
      await api.revokeSession(s.id)
      await load()
    } catch (e) {
      setError(e.message || 'Could not revoke session')
    } finally {
      setBusy(false)
    }
  }

  const onRevokeOthers = async () => {
    const others = sessions.filter(s => !s.is_current).length
    if (others === 0) return
    if (!window.confirm(`Revoke all ${others} other sessions?`)) return
    setBusy(true)
    try {
      await api.revokeOtherSessions()
      await load()
    } catch (e) {
      setError(e.message || 'Could not revoke other sessions')
    } finally {
      setBusy(false)
    }
  }

  const startEdit = (s) => {
    setEditingId(s.id)
    setEditLabel(s.label || '')
  }
  const cancelEdit = () => { setEditingId(null); setEditLabel('') }
  const commitEdit = async (s) => {
    const next = editLabel.trim()
    if (!next || next === (s.label || '')) { cancelEdit(); return }
    setBusy(true)
    try {
      await api.labelSession(s.id, next)
      await load()
    } catch (e) {
      setError(e.message || 'Could not update label')
    } finally {
      setBusy(false)
      cancelEdit()
    }
  }

  const otherCount = sessions.filter(s => !s.is_current).length

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">Active sessions</h2>
        <button
          type="button"
          className="btn ghost"
          onClick={onRevokeOthers}
          disabled={busy || otherCount === 0}
          title={otherCount === 0 ? 'No other sessions' : `Revoke ${otherCount} other sessions`}
        >
          Revoke all others
        </button>
      </div>

      {error && (
        <div className="alert error" role="alert">
          <span className="alert-icon">!</span>
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="panel-empty"><div>Loading…</div></div>
      ) : sessions.length === 0 ? (
        <div className="panel-empty"><div>No sessions found.</div></div>
      ) : (
        <table className="settings-table">
          <thead>
            <tr>
              <th>Label</th>
              <th>Location</th>
              <th>User agent</th>
              <th>Last seen</th>
              <th>Expires</th>
              <th className="actions">Actions</th>
            </tr>
          </thead>
          <tbody>
            {sessions.map(s => (
              <tr key={s.id}>
                <td>
                  {editingId === s.id ? (
                    <input
                      className="input"
                      autoFocus
                      value={editLabel}
                      onChange={(e) => setEditLabel(e.target.value)}
                      onBlur={() => commitEdit(s)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') { e.preventDefault(); commitEdit(s) }
                        if (e.key === 'Escape') { e.preventDefault(); cancelEdit() }
                      }}
                      maxLength={64}
                    />
                  ) : (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                      <button
                        type="button"
                        className="btn ghost"
                        style={{ padding: '4px 8px', fontFamily: 'var(--font-body)', fontWeight: 500 }}
                        onClick={() => startEdit(s)}
                        title="Click to rename"
                      >
                        {s.label || <span style={{ color: 'var(--dim)' }}>untitled</span>}
                      </button>
                      {s.is_current && <span className="pill ok">Current</span>}
                    </span>
                  )}
                </td>
                <td>{locationOf(s) || <span style={{ color: 'var(--dim)' }}>—</span>}</td>
                <td title={s.user_agent || ''} style={{ maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {s.user_agent || <span style={{ color: 'var(--dim)' }}>—</span>}
                </td>
                <td title={formatLocal(s.last_seen_at)}>{relative(s.last_seen_at)}</td>
                <td title={formatLocal(s.expires_at)}
                    style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                  {formatLocalShort(s.expires_at)}
                </td>
                <td className="actions">
                  <button
                    type="button"
                    className="btn ghost"
                    onClick={() => onRevoke(s)}
                    disabled={busy || s.is_current}
                    title={s.is_current ? 'Use sign-out to end the current session' : 'Revoke this session'}
                  >
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}

function locationOf(s) {
  const parts = [s.city, s.country].filter(Boolean)
  const place = parts.join(', ')
  if (place && s.ip_address) return `${place} (${s.ip_address})`
  return place || s.ip_address || ''
}
