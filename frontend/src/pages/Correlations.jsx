import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.js'
import { SEVERITY, PHASE } from '../lib/incidentVocab.js'

const SEV_LOOKUP  = Object.fromEntries(SEVERITY.map(s => [s.value, s]))
const PHASE_LOOKUP = Object.fromEntries(PHASE.map(p => [p.value, p]))

const IOC_TYPE_LABELS = {
  ip: 'IP', domain: 'Domain', url: 'URL',
  hash_md5: 'MD5', hash_sha1: 'SHA1', hash_sha256: 'SHA256',
  email: 'Email', registry_key: 'Registry', file_path: 'File path', other: 'Other',
}

const ENTITY_TYPE_LABELS = {
  host: 'Host', user: 'User', service: 'Service', ip: 'IP',
  domain: 'Domain', url: 'URL', email: 'Email', file: 'File',
  process: 'Process', network: 'Network', other: 'Other',
}

function SevPill({ value }) {
  const s = SEV_LOOKUP[value]
  if (!s) return null
  return <span className={`pill ${s.pill}`} style={{ fontSize: 10 }}>{s.label}</span>
}

function PhaseChip({ value }) {
  const p = PHASE_LOOKUP[value]
  if (!p) return null
  return <span className="pill" style={{ fontSize: 10, background: 'var(--surface-2)', color: 'var(--muted)' }}>{p.short}</span>
}

function IncidentPill({ inc }) {
  return (
    <Link
      to={`/incidents/${inc.id}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 4,
        padding: '2px 7px',
        borderRadius: 'var(--radius-sm)',
        background: 'var(--surface-2)',
        border: '1px solid var(--border)',
        color: 'var(--accent)',
        fontSize: 11,
        fontFamily: 'var(--font-mono)',
        textDecoration: 'none',
        whiteSpace: 'nowrap',
      }}
      title={inc.title}
    >
      {inc.ref && <span style={{ opacity: 0.75, marginRight: 3 }}>{inc.ref}</span>}
      {inc.title.length > 28 ? inc.title.slice(0, 26) + '…' : inc.title}
    </Link>
  )
}

// ─── Shared IOC row ───────────────────────────────────────────────────────────

function IocRow({ item }) {
  const [expanded, setExpanded] = useState(false)
  const typeLabel = IOC_TYPE_LABELS[item.type] || item.type

  return (
    <>
      <tr>
        <td style={{ width: 90 }}>
          <span className="pill" style={{ fontSize: 10 }}>{typeLabel}</span>
        </td>
        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, wordBreak: 'break-all', maxWidth: 340 }}>
          {item.value}
        </td>
        <td style={{ width: 80, textAlign: 'center' }}>
          <span
            style={{
              fontFamily: 'var(--font-mono)',
              fontWeight: 700,
              fontSize: 14,
              color: item.incident_count >= 4 ? 'var(--crit)' : item.incident_count >= 2 ? 'var(--high)' : 'var(--accent)',
            }}
          >
            {item.incident_count}
          </span>
        </td>
        <td>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, alignItems: 'center' }}>
            {item.incidents.slice(0, 4).map(inc => (
              <IncidentPill key={inc.id} inc={inc} />
            ))}
            {item.incidents.length > 4 && (
              <button
                type="button"
                className="btn ghost"
                onClick={() => setExpanded(e => !e)}
              >
                {expanded ? 'less' : `+${item.incidents.length - 4} more`}
              </button>
            )}
          </div>
          {expanded && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
              {item.incidents.slice(4).map(inc => (
                <IncidentPill key={inc.id} inc={inc} />
              ))}
            </div>
          )}
        </td>
      </tr>
    </>
  )
}

// ─── Shared Entity row ────────────────────────────────────────────────────────

function EntityRow({ item }) {
  const [expanded, setExpanded] = useState(false)
  const typeLabel = ENTITY_TYPE_LABELS[item.type] || item.type

  return (
    <tr>
      <td style={{ width: 90 }}>
        <span className="pill" style={{ fontSize: 10 }}>{typeLabel}</span>
      </td>
      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, wordBreak: 'break-all', maxWidth: 340 }}>
        {item.value}
      </td>
      <td style={{ width: 80, textAlign: 'center' }}>
        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontWeight: 700,
            fontSize: 14,
            color: item.incident_count >= 4 ? 'var(--crit)' : item.incident_count >= 2 ? 'var(--high)' : 'var(--accent)',
          }}
        >
          {item.incident_count}
        </span>
      </td>
      <td>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, alignItems: 'center' }}>
          {item.incidents.slice(0, 4).map(inc => (
            <IncidentPill key={inc.id} inc={inc} />
          ))}
          {item.incidents.length > 4 && (
            <button
              type="button"
              className="btn ghost"
              onClick={() => setExpanded(e => !e)}
            >
              {expanded ? 'less' : `+${item.incidents.length - 4} more`}
            </button>
          )}
        </div>
        {expanded && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
            {item.incidents.slice(4).map(inc => (
              <IncidentPill key={inc.id} inc={inc} />
            ))}
          </div>
        )}
      </td>
    </tr>
  )
}

// ─── Tab: Shared IOCs ─────────────────────────────────────────────────────────

function SharedIocsTab() {
  const [items, setItems]         = useState([])
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState(null)
  const [nextCursor, setNext]     = useState(null)
  const [loadingMore, setMore]    = useState(false)
  const [tagFilter, setTagFilter] = useState('')
  const [ready, setReady]         = useState(false)   // the first query has answered
  // The tag box queries on every keystroke: only the newest query may set state, so a slower
  // answer for an earlier value (e.g. its invalid_tag error) can't land after a newer one.
  const loadSeq = useRef(0)

  const load = useCallback(async (cursor = null) => {
    const seq = cursor ? loadSeq.current : ++loadSeq.current
    const params = {}
    if (cursor)    params.cursor = cursor
    if (tagFilter) params.tag    = tagFilter
    try {
      const res = await api.listCorrelatedIocs(params)
      if (seq !== loadSeq.current) return
      setError(null)   // a successful query clears the previous one's error (e.g. invalid_tag)
      setItems(prev => cursor ? [...prev, ...res.items] : res.items)
      setNext(res.next_cursor)
    } catch (e) {
      if (seq !== loadSeq.current) return
      setError(e.code === 'invalid_tag'
        ? `"${tagFilter}" is not a usable tag: tags use lowercase letters, digits and - . / :`
        : (e.message || 'Could not load correlated IOCs'))
    } finally {
      if (seq === loadSeq.current) { setLoading(false); setMore(false); setReady(true) }
    }
  }, [tagFilter])

  useEffect(() => { setLoading(true); load() }, [load])

  const loadMore = () => {
    if (!nextCursor || loadingMore) return
    setMore(true)
    load(nextCursor)
  }

  // After the first answer the tag box stays on screen (also while loading, empty or in error),
  // so typing never loses focus and an invalid tag can be corrected in place.
  if (!ready) return <div className="panel-empty"><div>Loading…</div></div>

  return (
    <>
      <div style={{
        display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
        flexWrap: 'wrap', marginBottom: 'var(--space-3)',
      }}>
        <span style={{ color: 'var(--muted)', fontSize: 13, flex: '1 1 auto' }}>
          {loading ? 'Loading…' : !error && items.length > 0 && <>
            {items.length} IOC value{items.length !== 1 ? 's' : ''} observed across multiple incidents.
            Sorted by number of incidents, highest first.
          </>}
        </span>
        <input
          type="search"
          value={tagFilter}
          onChange={(e) => setTagFilter(e.target.value.trim().toLowerCase())}
          placeholder="Filter by IOC tag (e.g. c2)"
          aria-label="Filter by IOC tag"
          style={{
            fontSize: 12, padding: '4px 8px',
            background: 'var(--surface)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm)', color: 'var(--text)',
            minWidth: 180, fontFamily: 'var(--font-mono)',
          }}
        />
        {tagFilter && (
          <button type="button" className="chip" onClick={() => setTagFilter('')}>× clear</button>
        )}
      </div>
      {error ? (
        <div className="alert error" role="alert" data-corr-error>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      ) : items.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">◌</div>
          <div>{tagFilter ? `No shared IOCs tagged "${tagFilter}".` : 'No shared IOCs detected.'}</div>
          <div style={{ color: 'var(--dim)', fontSize: 12 }}>IOC values seen in 2+ incidents will appear here.</div>
        </div>
      ) : <>
      <table className="settings-table">
        <thead>
          <tr>
            <th style={{ width: 90 }}>Type</th>
            <th>Value</th>
            <th style={{ width: 80, textAlign: 'center' }}>Incidents</th>
            <th>Seen in</th>
          </tr>
        </thead>
        <tbody>
          {items.map(item => <IocRow key={`${item.type}::${item.value}`} item={item} />)}
        </tbody>
      </table>
      {nextCursor && (
        <div style={{ marginTop: 'var(--space-3)', textAlign: 'center' }}>
          <button
            type="button"
            className="btn ghost"
            onClick={loadMore}
            disabled={loadingMore}
          >
            {loadingMore ? 'Loading…' : 'Load more'}
          </button>
        </div>
      )}
      </>}
    </>
  )
}

// ─── Tab: Shared Entities ─────────────────────────────────────────────────────

function SharedEntitiesTab() {
  const [items, setItems]         = useState([])
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState(null)
  const [nextCursor, setNext]     = useState(null)
  const [loadingMore, setMore]    = useState(false)

  const load = useCallback(async (cursor = null) => {
    const params = cursor ? { cursor } : {}
    try {
      const res = await api.listCorrelatedEntities(params)
      setItems(prev => cursor ? [...prev, ...res.items] : res.items)
      setNext(res.next_cursor)
    } catch (e) {
      setError(e.message || 'Could not load correlated entities')
    } finally {
      setLoading(false)
      setMore(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const loadMore = () => {
    if (!nextCursor || loadingMore) return
    setMore(true)
    load(nextCursor)
  }

  if (loading) return <div className="panel-empty"><div>Loading…</div></div>
  if (error)   return (
    <div className="alert error" role="alert">
      <span className="alert-icon">!</span><span>{error}</span>
    </div>
  )
  if (items.length === 0) return (
    <div className="panel-empty">
      <div className="panel-empty-mark" aria-hidden="true">◌</div>
      <div>No shared entities detected.</div>
      <div style={{ color: 'var(--dim)', fontSize: 12 }}>Entities seen in 2+ incidents will appear here.</div>
    </div>
  )

  return (
    <>
      <p style={{ color: 'var(--muted)', fontSize: 13, marginBottom: 'var(--space-3)' }}>
        {items.length} entity value{items.length !== 1 ? 's' : ''} observed across multiple incidents.
        Sorted by number of incidents, highest first.
      </p>
      <table className="settings-table">
        <thead>
          <tr>
            <th style={{ width: 90 }}>Type</th>
            <th>Value</th>
            <th style={{ width: 80, textAlign: 'center' }}>Incidents</th>
            <th>Seen in</th>
          </tr>
        </thead>
        <tbody>
          {items.map(item => <EntityRow key={`${item.type}::${item.value}`} item={item} />)}
        </tbody>
      </table>
      {nextCursor && (
        <div style={{ marginTop: 'var(--space-3)', textAlign: 'center' }}>
          <button
            type="button"
            className="btn ghost"
            onClick={loadMore}
            disabled={loadingMore}
          >
            {loadingMore ? 'Loading…' : 'Load more'}
          </button>
        </div>
      )}
    </>
  )
}

// ─── Page root ────────────────────────────────────────────────────────────────

const TABS = [
  { id: 'iocs',     label: 'Shared IOCs' },
  { id: 'entities', label: 'Shared Entities' },
]

export default function Correlations() {
  const [tab, setTab] = useState('iocs')

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <div>
          <h2 className="panel-h">Correlations</h2>
          <p style={{ color: 'var(--muted)', fontSize: 13, margin: 0 }}>
            IOCs and entities observed across multiple incidents.
          </p>
        </div>
      </div>

      <div className="tabs-h">
        {TABS.map(t => (
          <button
            key={t.id}
            type="button"
            className={`tab-h${tab === t.id ? ' active' : ''}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'iocs'     && <SharedIocsTab />}
      {tab === 'entities' && <SharedEntitiesTab />}
    </section>
  )
}
