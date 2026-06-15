import { useCallback, useEffect, useMemo, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../../api/client.js'
import { formatLocal } from '../../../lib/datetime.js'

const ACTION_COLOR = {
  evidence_collect:                  'var(--ok)',
  evidence_update:                   'var(--muted)',
  evidence_transfer:                 'var(--accent)',
  evidence_examine:                  'var(--med)',
  evidence_verify:                   'var(--ok)',
  evidence_verify_failed:            'var(--crit)',
  evidence_destroy:                  'var(--crit)',
  evidence_return:                   'var(--high)',
  evidence_archive:                  'var(--muted)',
  evidence_export:                   'var(--accent)',
  evidence_export_create:            'var(--accent)',
  evidence_export_download:          'var(--accent)',
  evidence_export_download_denied:   'var(--crit)',
}

const ACTION_LABEL = {
  evidence_collect:                'Collected',
  evidence_update:                 'Updated',
  evidence_transfer:               'Transferred',
  evidence_examine:                'Examined',
  evidence_verify:                 'Verified',
  evidence_verify_failed:          'Verify FAILED',
  evidence_destroy:                'Destroyed',
  evidence_return:                 'Returned',
  evidence_archive:                'Archived',
  evidence_export:                 'Exported',
  evidence_export_create:          'Export bundle created',
  evidence_export_download:        'Export downloaded',
  evidence_export_download_denied: 'Export download denied',
}

export default function CustodyLog() {
  const { inc } = useOutletContext()
  const [events, setEvents]   = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)
  const [actionFilter, setActionFilter] = useState('')

  const load = useCallback(async () => {
    setError(null)
    try {
      const rows = await api.incidentCustodyLog(inc.id)
      setEvents(rows)
    } catch (e) {
      setError(e.message || 'Could not load custody log')
    } finally {
      setLoading(false)
    }
  }, [inc.id])

  useEffect(() => { load() }, [load])

  const filtered = useMemo(() => {
    if (!actionFilter) return events
    return events.filter(e => e.event_type === actionFilter)
  }, [events, actionFilter])

  const actionOptions = useMemo(() => {
    const seen = new Set()
    return events
      .map(e => e.event_type)
      .filter(t => { if (seen.has(t)) return false; seen.add(t); return true })
      .sort()
  }, [events])

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">Custody log — full incident</h2>
        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
          <select
            className="select"
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            aria-label="Filter by action"
          >
            <option value="">All actions</option>
            {actionOptions.map(t => (
              <option key={t} value={t}>{ACTION_LABEL[t] || t}</option>
            ))}
          </select>
          <span style={{ color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
            {filtered.length} of {events.length}
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
      ) : events.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">⌗</div>
          <div>No custody events yet.</div>
          <div style={{ color: 'var(--dim)', fontSize: 12 }}>
            Events land here as evidence is collected, transferred, examined, verified, or disposed.
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
                borderLeft: `3px solid ${ACTION_COLOR[ev.event_type] || 'var(--border)'}`,
                borderRadius: 'var(--radius)',
              }}
            >
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}>
                {formatLocal(ev.created_at)}
              </div>
              <div>
                <div>
                  <b style={{ color: ACTION_COLOR[ev.event_type] || 'var(--text)' }}>
                    {ACTION_LABEL[ev.event_type] || ev.event_type}
                  </b>
                  {' by '}
                  <span style={{ fontFamily: 'var(--font-mono)' }}>{ev.username || '—'}</span>
                  {ev.resource_id && (
                    <>
                      {' · '}
                      <span style={{ color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                        {ev.resource_type === 'custody_export' ? 'export' : 'item'}{' '}
                        {ev.resource_id.slice(0, 8)}…
                      </span>
                    </>
                  )}
                  {ev.outcome && ev.outcome !== 'success' && (
                    <>
                      {' · '}
                      <span className="pill" style={{ color: 'var(--crit)' }}>{ev.outcome}</span>
                    </>
                  )}
                </div>
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
                  hash: {ev.hash ? ev.hash.slice(0, 16) + '…' : '—'}
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
