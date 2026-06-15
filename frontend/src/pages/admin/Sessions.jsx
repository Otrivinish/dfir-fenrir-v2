import { useCallback, useEffect, useState } from 'react'
import { api } from '../../api/client.js'
import { formatLocal, formatLocalShort, relative } from '../../lib/datetime.js'
import { useAuth } from '../../hooks/useAuth.jsx'

export default function AdminSessions() {
  const { user: me } = useAuth()
  const [sessions, setSessions] = useState([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [busy, setBusy]         = useState(false)
  const [filter, setFilter]     = useState('')

  const load = useCallback(async () => {
    setError(null)
    try {
      const list = await api.listAdminSessions()
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
    if (!window.confirm(`Revoke session for ${s.username}?\n\nIP: ${s.ip_address || '—'}\nLabel: ${s.label || 'untitled'}`)) return
    setBusy(true)
    try {
      await api.adminRevokeSession(s.id)
      await load()
    } catch (e) {
      setError(e.message || 'Could not revoke session')
    } finally {
      setBusy(false)
    }
  }

  const q = filter.trim().toLowerCase()
  const visible = q
    ? sessions.filter(s =>
        s.username.toLowerCase().includes(q) ||
        (s.ip_address || '').toLowerCase().includes(q) ||
        (s.label || '').toLowerCase().includes(q) ||
        (s.user_agent || '').toLowerCase().includes(q)
      )
    : sessions

  // Group stats
  const uniqueUsers  = new Set(sessions.map(s => s.user_id)).size
  const currentCount = sessions.filter(s => s.is_current).length

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <div>
          <h2 className="panel-h">Sessions</h2>
          <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>
            {sessions.length} active session{sessions.length !== 1 ? 's' : ''} across {uniqueUsers} user{uniqueUsers !== 1 ? 's' : ''}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
          <input
            className="input"
            style={{ fontSize: 12, padding: '4px 10px', width: 200 }}
            placeholder="Filter by user, IP, label…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <button
            type="button"
            className="btn ghost"
            style={{ fontSize: 12 }}
            onClick={load}
            disabled={loading || busy}
          >↻ Refresh</button>
        </div>
      </div>

      {error && (
        <div className="alert error" role="alert">
          <span className="alert-icon">!</span>
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="panel-empty"><div>Loading…</div></div>
      ) : visible.length === 0 ? (
        <div className="panel-empty"><div>{q ? 'No sessions match filter.' : 'No active sessions.'}</div></div>
      ) : (
        <table className="settings-table">
          <thead>
            <tr>
              <th>User</th>
              <th>Label</th>
              <th>IP address</th>
              <th style={{ maxWidth: 220 }}>User agent</th>
              <th>Created</th>
              <th>Last seen</th>
              <th>Expires</th>
              <th className="actions">Actions</th>
            </tr>
          </thead>
          <tbody>
            {visible.map(s => (
              <tr key={s.id}>
                <td>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                    <span style={{
                      fontFamily: 'var(--font-mono)', fontSize: 12,
                      color: s.is_current ? 'var(--accent)' : 'var(--text)',
                      fontWeight: s.is_current ? 700 : 400,
                    }}>
                      {s.username}
                    </span>
                    {s.is_current && <span className="pill ok">You</span>}
                  </span>
                </td>
                <td style={{ color: s.label ? 'var(--text)' : 'var(--dim)', fontSize: 12 }}>
                  {s.label || '—'}
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                  {locationOf(s) || <span style={{ color: 'var(--dim)' }}>—</span>}
                </td>
                <td
                  title={s.user_agent || ''}
                  style={{ fontSize: 11, maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--muted)' }}
                >
                  {s.user_agent || <span style={{ color: 'var(--dim)' }}>—</span>}
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}
                    title={formatLocal(s.created_at)}>
                  {formatLocal(s.created_at).slice(0, 16)}
                </td>
                <td title={formatLocal(s.last_seen_at)}>
                  {relative(s.last_seen_at)}
                </td>
                <td title={formatLocal(s.expires_at)}
                    style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                  {formatLocalShort(s.expires_at)}
                </td>
                <td className="actions">
                  <button
                    type="button"
                    className="btn ghost"
                    style={{ fontSize: 12, color: s.is_current ? undefined : 'var(--crit)' }}
                    onClick={() => onRevoke(s)}
                    disabled={busy || s.is_current}
                    title={s.is_current ? 'Use sign-out to end your own session' : `Revoke ${s.username}'s session`}
                  >
                    {s.is_current ? 'Current' : 'Revoke'}
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
