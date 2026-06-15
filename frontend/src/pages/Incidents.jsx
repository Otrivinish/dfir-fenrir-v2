import { useEffect, useState, useCallback } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { api } from '../api/client.js'
import { formatLocal, formatLocalShort } from '../lib/datetime.js'
import { SEVERITY, STATUS, labelOf, pillOf } from '../lib/incidentVocab.js'
import IncidentCreateModal from '../components/IncidentCreateModal.jsx'
import TagChip from '../components/TagChip.jsx'

export default function Incidents() {
  const navigate = useNavigate()
  // Read initial filters from URL so deep-links like /incidents?tag=apt28 (e.g.
  // from the Dashboard Top Tags widget) drop us into the right view.
  const [searchParams, setSearchParams] = useSearchParams()
  const [filters, setFilters]   = useState({
    status:   searchParams.get('status')   || '',
    severity: searchParams.get('severity') || '',
    tag:      (searchParams.get('tag') || '').toLowerCase(),
  })
  const [items, setItems]       = useState([])
  const [cursor, setCursor]     = useState(null)
  const [nextCursor, setNext]   = useState(null)
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState('')
  const [showCreate, setCreate] = useState(false)

  const load = useCallback(async (resetCursor = null) => {
    setLoading(true); setError('')
    try {
      const params = {}
      if (filters.status)   params.status   = filters.status
      if (filters.severity) params.severity = filters.severity
      if (filters.tag)      params.tag      = filters.tag
      if (resetCursor)      params.cursor   = resetCursor
      const r = await api.listIncidents(params)
      if (resetCursor) {
        setItems(prev => [...prev, ...r.items])
      } else {
        setItems(r.items)
      }
      setNext(r.next_cursor)
      setCursor(resetCursor)
    } catch (e) {
      setError(e.message || 'Could not load incidents.')
    } finally {
      setLoading(false)
    }
  }, [filters.status, filters.severity, filters.tag])

  useEffect(() => { load(null) /* eslint-disable-next-line */ }, [filters.status, filters.severity, filters.tag])

  // Reflect filters back into the URL so the page is bookmarkable and the
  // browser back button restores the same view.
  useEffect(() => {
    const next = new URLSearchParams()
    if (filters.status)   next.set('status', filters.status)
    if (filters.severity) next.set('severity', filters.severity)
    if (filters.tag)      next.set('tag', filters.tag)
    setSearchParams(next, { replace: true })
  }, [filters.status, filters.severity, filters.tag, setSearchParams])

  const toggleFilter = (key, value) => {
    setFilters(f => ({ ...f, [key]: f[key] === value ? '' : value }))
  }

  const onCreated = (inc) => {
    setCreate(false)
    setItems(prev => [inc, ...prev])
    navigate(`/incidents/${inc.id}`)
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Incidents</h1>
          <div className="page-sub">NIST SP 800-61 R3</div>
        </div>
        <div>
          <button className="btn primary" type="button" onClick={() => setCreate(true)}>+ New incident</button>
        </div>
      </div>

      <div className="filter-bar" role="toolbar" aria-label="Filters">
        <span className="chip" style={{ cursor: 'default', borderColor: 'transparent', background: 'transparent' }}>STATUS</span>
        {STATUS.map(s => (
          <button key={s.value}
                  className={`chip ${filters.status === s.value ? 'on' : ''}`}
                  onClick={() => toggleFilter('status', s.value)}
                  type="button">{s.label}</button>
        ))}
        <span className="chip-sep" aria-hidden="true" />
        <span className="chip" style={{ cursor: 'default', borderColor: 'transparent', background: 'transparent' }}>SEVERITY</span>
        {SEVERITY.map(s => (
          <button key={s.value}
                  className={`chip ${filters.severity === s.value ? 'on' : ''}`}
                  onClick={() => toggleFilter('severity', s.value)}
                  type="button">{s.label}</button>
        ))}
        <span className="chip-sep" aria-hidden="true" />
        <span className="chip" style={{ cursor: 'default', borderColor: 'transparent', background: 'transparent' }}>TAG</span>
        <input
          type="search"
          value={filters.tag}
          onChange={e => setFilters(f => ({ ...f, tag: e.target.value.trim().toLowerCase() }))}
          placeholder="e.g. apt28"
          aria-label="Filter by tag"
          style={{
            fontSize: 12, padding: '2px 8px',
            background: 'var(--surface)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm)', color: 'var(--text)',
            minWidth: 140, fontFamily: 'var(--font-mono)',
          }}
        />
        {filters.tag && (
          <button
            type="button"
            className="chip"
            onClick={() => setFilters(f => ({ ...f, tag: '' }))}
          >× clear</button>
        )}
      </div>

      {error && (
        <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      <div className="tbl-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th style={{ width: 90 }}>Ref</th>
              <th style={{ width: 110 }}>Severity</th>
              <th>Title</th>
              <th>Phase</th>
              <th>TLP</th>
              <th>Status</th>
              <th>Tags</th>
              <th>Reporter</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {!loading && items.length === 0 && (
              <tr><td colSpan={9} className="tbl-empty">No incidents yet. Click <strong>New incident</strong> to create one.</td></tr>
            )}
            {items.map(inc => (
              <tr key={inc.id} onClick={() => navigate(`/incidents/${inc.id}`)}>
                <td className="num" style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--accent)' }}>{inc.ref ?? '—'}</td>
                <td><span className={`pill ${pillOf('severity', inc.severity)}`}>{labelOf('severity', inc.severity)}</span></td>
                <td className="title">{inc.title}</td>
                <td>{labelOf('phase', inc.phase)}</td>
                <td><span className={`pill ${pillOf('tlp', inc.tlp)}`}>{labelOf('tlp', inc.tlp)}</span></td>
                <td><span className={`pill ${pillOf('status', inc.status)}`}>{labelOf('status', inc.status)}</span></td>
                <td onClick={(e) => e.stopPropagation()}>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3, maxWidth: 220 }}>
                    {(inc.tags || []).slice(0, 4).map(t => (
                      <TagChip key={t} tag={t} dense
                        onClick={() => setFilters(f => ({ ...f, tag: t }))}
                        title={`Filter by ${t}`} />
                    ))}
                    {(inc.tags || []).length > 4 && (
                      <span style={{ fontSize: 10, color: 'var(--dim)' }}>+{inc.tags.length - 4}</span>
                    )}
                  </div>
                </td>
                <td className="num">{inc.reporter || '—'}</td>
                <td className="ts" title={formatLocal(inc.created_at)}>{formatLocalShort(inc.created_at)}</td>
              </tr>
            ))}
            {loading && items.length === 0 && (
              <tr><td colSpan={9} className="tbl-empty">Loading…</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {nextCursor && (
        <div style={{ marginTop: 'var(--space-3)', textAlign: 'center' }}>
          <button className="btn" type="button" disabled={loading} onClick={() => load(nextCursor)}>
            {loading ? 'Loading…' : 'Load more'}
          </button>
        </div>
      )}

      <IncidentCreateModal
        open={showCreate}
        onClose={() => setCreate(false)}
        onCreated={onCreated}
      />
    </>
  )
}
