import { useCallback, useEffect, useMemo, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../api/client.js'
import { formatLocal } from '../../lib/datetime.js'

// Derive colour from action suffix — avoids exhaustive mapping for an open vocabulary.
function actionColor(action) {
  if (!action) return 'var(--border)'
  if (action.endsWith('_failed') || action.endsWith('_denied') || action.endsWith('_delete') || action.endsWith('_destroy') || action.endsWith('_revoke')) return 'var(--crit)'
  if (action.endsWith('_close') || action.endsWith('_dispose') || action.endsWith('_return')) return 'var(--high)'
  if (action.endsWith('_create') || action.endsWith('_collect') || action.endsWith('_upload')) return 'var(--ok)'
  if (action.endsWith('_transfer') || action.endsWith('_phase_change') || action.endsWith('_instantiate')) return 'var(--accent)'
  if (action.endsWith('_verify') || action.endsWith('_examine') || action.endsWith('_export')) return 'var(--med)'
  return 'var(--muted)'
}

function actionLabel(action) {
  if (!action) return '—'
  return action.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

const OUTCOME_COLOR = {
  success: 'var(--ok)',
  failure: 'var(--crit)',
  denied:  'var(--high)',
}

export default function AuditLog() {
  const { inc } = useOutletContext()
  const [entries, setEntries]   = useState([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [actionFilter, setActionFilter] = useState('')
  const [userFilter, setUserFilter]     = useState('')

  const load = useCallback(async () => {
    setError(null)
    try {
      const data = await api.incidentAuditLog(inc.id, { limit: 500 })
      setEntries(data.items || [])
    } catch (e) {
      setError(e.message || 'Could not load audit log')
    } finally {
      setLoading(false)
    }
  }, [inc.id])

  useEffect(() => { load() }, [load])

  const filtered = useMemo(() => {
    return entries.filter(e => {
      if (actionFilter && e.action !== actionFilter) return false
      if (userFilter   && e.username !== userFilter)  return false
      return true
    })
  }, [entries, actionFilter, userFilter])

  const actionOptions = useMemo(() => {
    const seen = new Set()
    return entries.map(e => e.action).filter(a => { if (seen.has(a)) return false; seen.add(a); return true }).sort()
  }, [entries])

  const userOptions = useMemo(() => {
    const seen = new Set()
    return entries.map(e => e.username).filter(u => u && (seen.has(u) ? false : seen.add(u))).sort()
  }, [entries])

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">Audit Log</h2>
        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
          <select
            className="select"
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            aria-label="Filter by action"
          >
            <option value="">All actions</option>
            {actionOptions.map(a => (
              <option key={a} value={a}>{actionLabel(a)}</option>
            ))}
          </select>
          <select
            className="select"
            value={userFilter}
            onChange={(e) => setUserFilter(e.target.value)}
            aria-label="Filter by user"
          >
            <option value="">All users</option>
            {userOptions.map(u => (
              <option key={u} value={u}>{u}</option>
            ))}
          </select>
          <span style={{ color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
            {filtered.length} of {entries.length}
          </span>
        </div>
      </div>

      {error && (
        <div className="alert error" role="alert">
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="panel-empty"><div>Loading…</div></div>
      ) : entries.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">⌗</div>
          <div>No audit events yet.</div>
          <div style={{ color: 'var(--dim)', fontSize: 12 }}>
            Actions taken on this incident and its resources are recorded here.
          </div>
        </div>
      ) : (
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
          {filtered.map(ev => (
            <li
              key={ev.id}
              style={{
                display: 'grid',
                gridTemplateColumns: '170px 1fr',
                gap: 'var(--space-3)',
                padding: 'var(--space-2) var(--space-3)',
                background: 'var(--surface-2)',
                border: '1px solid var(--border)',
                borderLeft: `3px solid ${actionColor(ev.action)}`,
                borderRadius: 'var(--radius)',
              }}
            >
              <div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}>
                  {formatLocal(ev.timestamp)}
                </div>
                {ev.request_method && (
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--dim)', marginTop: 2 }}>
                    {ev.request_method} {ev.ip_address}
                  </div>
                )}
              </div>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
                  <b style={{ color: actionColor(ev.action) }}>
                    {actionLabel(ev.action)}
                  </b>
                  {ev.username && (
                    <span style={{ color: 'var(--muted)' }}>
                      by <span style={{ fontFamily: 'var(--font-mono)' }}>{ev.username}</span>
                      {ev.role_at_time && (
                        <span style={{ color: 'var(--dim)', marginLeft: 4 }}>({ev.role_at_time})</span>
                      )}
                    </span>
                  )}
                  {ev.outcome && (
                    <span style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: 10,
                      color: OUTCOME_COLOR[ev.outcome] || 'var(--muted)',
                      textTransform: 'uppercase',
                    }}>
                      {ev.outcome}
                    </span>
                  )}
                </div>

                {(ev.resource_type || ev.resource_label) && (
                  <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>
                    {ev.resource_type && (
                      <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--dim)' }}>{ev.resource_type}</span>
                    )}
                    {ev.resource_label && (
                      <span style={{ marginLeft: 6 }}>{ev.resource_label}</span>
                    )}
                    {ev.resource_id && !ev.resource_label && (
                      <span style={{ marginLeft: 6, fontFamily: 'var(--font-mono)', color: 'var(--dim)' }}>
                        {ev.resource_id.slice(0, 8)}…
                      </span>
                    )}
                  </div>
                )}

                {ev.request_path && (
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--dim)', marginTop: 2 }}>
                    {ev.request_path}
                  </div>
                )}

                {ev.details && Object.keys(ev.details).length > 0 && (
                  <details style={{ marginTop: 4 }}>
                    <summary style={{ cursor: 'pointer', color: 'var(--muted)', fontSize: 12 }}>details</summary>
                    <pre style={{
                      margin: '4px 0 0', fontSize: 10, color: 'var(--muted)',
                      background: 'var(--bg)', padding: 'var(--space-2)',
                      borderRadius: 'var(--radius-sm)', overflow: 'auto',
                      whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                    }}>{JSON.stringify(ev.details, null, 2)}</pre>
                  </details>
                )}

                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--dim)', marginTop: 4 }}>
                  hash: {ev.row_hash.slice(0, 16)}…
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
