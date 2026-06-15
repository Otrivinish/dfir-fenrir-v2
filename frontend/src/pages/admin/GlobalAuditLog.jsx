import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../../api/client.js'
import { formatLocal } from '../../lib/datetime.js'
import UtcDateTimeInput from '../../components/UtcDateTimeInput.jsx'

// ─── Shared helpers (mirror per-incident AuditLog.jsx) ───────────────────────

function actionColor(action) {
  if (!action) return 'var(--border)'
  if (action.endsWith('_failed') || action.endsWith('_denied') || action.endsWith('_delete') || action.endsWith('_destroy') || action.endsWith('_revoke')) return 'var(--crit)'
  if (action.endsWith('_close')  || action.endsWith('_dispose') || action.endsWith('_return'))  return 'var(--high)'
  if (action.endsWith('_create') || action.endsWith('_collect') || action.endsWith('_upload'))  return 'var(--ok)'
  if (action.endsWith('_transfer') || action.endsWith('_phase_change') || action.endsWith('_instantiate')) return 'var(--accent)'
  if (action.endsWith('_verify')  || action.endsWith('_examine') || action.endsWith('_export')) return 'var(--med)'
  return 'var(--muted)'
}

function actionLabel(action) {
  if (!action) return '—'
  return action.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

const OUTCOME_COLOR = { success: 'var(--ok)', failure: 'var(--crit)', denied: 'var(--high)' }

const RESOURCE_TYPES = [
  'incident', 'ioc', 'entity', 'evidence', 'timeline_event', 'playbook_task',
  'respond_action', 'decision', 'comment', 'oob_log', 'stakeholder', 'assignment',
  'user', 'session', 'team', 'operational_role', 'yara_rule', 'threat_feed',
  'artifact', 'custody_export', 'regulatory_deadline',
]

// ─── Row component ────────────────────────────────────────────────────────────

function AuditRow({ ev }) {
  const [expanded, setExpanded] = useState(false)
  const hasDetail = Object.keys(ev.details ?? {}).length > 0

  return (
    <li style={{
      background:   'var(--surface-2)',
      border:       '1px solid var(--border)',
      borderLeft:   `3px solid ${actionColor(ev.action)}`,
      borderRadius: 'var(--radius)',
    }}>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '160px 140px 1fr auto',
          gap: 'var(--space-3)',
          padding: 'var(--space-2) var(--space-3)',
          alignItems: 'start',
          cursor: hasDetail ? 'pointer' : 'default',
        }}
        onClick={() => hasDetail && setExpanded(x => !x)}
      >
        {/* Timestamp + IP */}
        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}>
            {formatLocal(ev.timestamp)}
          </div>
          {ev.ip_address && (
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--dim)', marginTop: 2 }}>
              {ev.request_method} {ev.ip_address}
            </div>
          )}
        </div>

        {/* User */}
        <div>
          {ev.username
            ? <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{ev.username}</span>
            : <span style={{ color: 'var(--dim)', fontSize: 11 }}>—</span>
          }
          {ev.role_at_time && (
            <div style={{ color: 'var(--dim)', fontSize: 10 }}>{ev.role_at_time}</div>
          )}
        </div>

        {/* Action + resource */}
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
            <b style={{ color: actionColor(ev.action), fontSize: 13 }}>{actionLabel(ev.action)}</b>
            {ev.outcome && (
              <span style={{
                fontFamily: 'var(--font-mono)', fontSize: 10,
                color: OUTCOME_COLOR[ev.outcome] ?? 'var(--muted)',
                border: `1px solid ${OUTCOME_COLOR[ev.outcome] ?? 'var(--border)'}`,
                borderRadius: 'var(--radius-sm)', padding: '0 5px',
              }}>{ev.outcome}</span>
            )}
          </div>
          {ev.resource_label && (
            <div style={{ fontSize: 12, color: 'var(--text)', marginTop: 2 }}>{ev.resource_label}</div>
          )}
          {ev.resource_type && (
            <div style={{ fontSize: 10, color: 'var(--dim)', fontFamily: 'var(--font-mono)', marginTop: 1 }}>
              {ev.resource_type}{ev.resource_id ? ` · ${ev.resource_id.slice(0, 8)}…` : ''}
            </div>
          )}
        </div>

        {/* Expand toggle */}
        {hasDetail && (
          <span style={{ color: 'var(--muted)', fontSize: 11, userSelect: 'none' }}>
            {expanded ? '▲' : '▼'}
          </span>
        )}
      </div>

      {expanded && (
        <div style={{
          padding: 'var(--space-2) var(--space-3) var(--space-3)',
          borderTop: '1px solid var(--border)',
          display: 'flex', flexDirection: 'column', gap: 'var(--space-2)',
        }}>
          <pre style={{
            margin: 0, fontFamily: 'var(--font-mono)', fontSize: 11,
            color: 'var(--muted)', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
          }}>
            {JSON.stringify(ev.details, null, 2)}
          </pre>
          <div style={{ display: 'flex', gap: 'var(--space-4)', fontSize: 10, color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>
            <span>row_hash: {ev.row_hash?.slice(0, 16)}…</span>
            <span>prev_hash: {ev.prev_hash?.slice(0, 16)}…</span>
          </div>
        </div>
      )}
    </li>
  )
}

// ─── Filter bar ───────────────────────────────────────────────────────────────

function FilterBar({ onApply }) {
  const [action,       setAction]       = useState('')
  const [username,     setUsername]     = useState('')
  const [resourceType, setResourceType] = useState('')
  const [dateFrom,     setDateFrom]     = useState('')
  const [dateTo,       setDateTo]       = useState('')

  const handleSubmit = e => {
    e.preventDefault()
    onApply({ action, username, resource_type: resourceType, date_from: dateFrom, date_to: dateTo })
  }

  const handleReset = () => {
    setAction(''); setUsername(''); setResourceType(''); setDateFrom(''); setDateTo('')
    onApply({})
  }

  return (
    <form onSubmit={handleSubmit} style={{
      display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap', alignItems: 'flex-end',
      marginBottom: 'var(--space-3)',
    }}>
      <input
        className="input" placeholder="Action contains…"
        value={action} onChange={e => setAction(e.target.value)}
        style={{ width: 180 }}
      />
      <input
        className="input" placeholder="Username"
        value={username} onChange={e => setUsername(e.target.value)}
        style={{ width: 140 }}
      />
      <select className="input" value={resourceType} onChange={e => setResourceType(e.target.value)} style={{ width: 160 }}>
        <option value="">All resource types</option>
        {RESOURCE_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
      </select>
      <UtcDateTimeInput
        value={dateFrom} onChange={setDateFrom}
        title="From (UTC)" placeholder="From — YYYY-MM-DD HH:mm:ss"
        hint={false} style={{ width: 210 }}
      />
      <UtcDateTimeInput
        value={dateTo} onChange={setDateTo}
        title="To (UTC)" placeholder="To — YYYY-MM-DD HH:mm:ss"
        hint={false} style={{ width: 210 }}
      />
      <button type="submit"  className="btn btn-primary" style={{ fontSize: '0.8rem' }}>Apply</button>
      <button type="button"  className="btn btn-ghost"   style={{ fontSize: '0.8rem' }} onClick={handleReset}>Reset</button>
    </form>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function GlobalAuditLog() {
  const [entries,    setEntries]    = useState([])
  const [loading,    setLoading]    = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error,      setError]      = useState(null)
  const [nextCursor, setNextCursor] = useState(null)
  const activeFilters = useRef({})

  const load = useCallback(async (filters = {}, cursor = null, append = false) => {
    if (append) setLoadingMore(true); else setLoading(true)
    setError(null)
    try {
      const params = { ...filters, limit: 100 }
      if (cursor) params.cursor = cursor
      const data = await api.globalAuditLog(params)
      setEntries(prev => append ? [...prev, ...(data.items ?? [])] : (data.items ?? []))
      setNextCursor(data.next_cursor ?? null)
    } catch (e) {
      setError(e.message || 'Failed to load audit log')
    } finally {
      setLoading(false)
      setLoadingMore(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const handleApply = useCallback(filters => {
    activeFilters.current = filters
    load(filters)
  }, [load])

  const handleLoadMore = useCallback(() => {
    load(activeFilters.current, nextCursor, true)
  }, [load, nextCursor])

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">Global Audit Log</h2>
        <span style={{ color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
          {entries.length} events{nextCursor ? '+' : ''}
        </span>
      </div>

      <FilterBar onApply={handleApply} />

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
          <div>No audit events match the current filters.</div>
        </div>
      ) : (
        <>
          <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
            {entries.map(ev => <AuditRow key={ev.id} ev={ev} />)}
          </ul>

          {nextCursor && (
            <div style={{ marginTop: 'var(--space-3)', textAlign: 'center' }}>
              <button
                className="btn btn-ghost"
                onClick={handleLoadMore}
                disabled={loadingMore}
              >
                {loadingMore ? 'Loading…' : 'Load more'}
              </button>
            </div>
          )}
        </>
      )}
    </section>
  )
}
