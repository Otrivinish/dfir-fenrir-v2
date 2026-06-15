import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.js'
import { formatLocal } from '../lib/datetime.js'

const SEV_COLOR = { critical: 'var(--crit)', high: 'var(--high)', medium: 'var(--med)', low: 'var(--low)' }

const IOC_TYPE_LABELS = {
  ip: 'IP', domain: 'Domain', url: 'URL',
  hash_md5: 'MD5', hash_sha1: 'SHA1', hash_sha256: 'SHA256',
  email: 'Email', registry_key: 'Registry key', file_path: 'File path', other: 'Other',
}
const IOC_TYPES = Object.entries(IOC_TYPE_LABELS).map(([v, l]) => ({ value: v, label: l }))

// ─── KPI card ────────────────────────────────────────────────────────────────

function KpiCard({ label, value, accent }) {
  return (
    <div style={{
      background: 'var(--surface)', border: '1px solid var(--border)',
      borderRadius: 'var(--radius)', padding: 'var(--space-3) var(--space-4)',
      minWidth: 120, textAlign: 'center', flex: 1,
    }}>
      <div style={{ fontSize: 26, fontFamily: 'var(--font-mono)', fontWeight: 700, color: accent || 'var(--accent)' }}>
        {typeof value === 'number' ? value.toLocaleString() : (value ?? '—')}
      </div>
      <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4 }}>{label}</div>
    </div>
  )
}

// ─── Matched incidents tab ────────────────────────────────────────────────────

function MatchedIncidents() {
  const [items, setItems]     = useState([])
  const [cursor, setCursor]   = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState(null)
  const [init, setInit]       = useState(false)

  const load = useCallback(async (nextCursor = null) => {
    setLoading(true)
    setError(null)
    try {
      const params = { limit: 50 }
      if (nextCursor) params.cursor = nextCursor
      const res = await api.getTiIncidentMatches(params)
      setItems(prev => nextCursor ? [...prev, ...res.items] : res.items)
      setCursor(res.next_cursor || null)
    } catch (e) {
      setError(e.message || 'Failed to load matches')
    } finally {
      setLoading(false)
      setInit(true)
    }
  }, [])

  useEffect(() => { load() }, [load])

  if (!init && loading) return <div style={{ color: 'var(--muted)', fontSize: 13, padding: 'var(--space-4) 0' }}>Loading…</div>

  if (init && !loading && items.length === 0) {
    return (
      <div className="panel-empty" style={{ marginTop: 'var(--space-4)' }}>
        <div className="panel-empty-mark" aria-hidden="true">◌</div>
        <div>No TI matches found.</div>
        <div style={{ color: 'var(--dim)', fontSize: 12 }}>
          Pull feeds in Settings → Threat Intelligence, then scan incidents via IOCs → Scan TI.
        </div>
      </div>
    )
  }

  return (
    <div style={{ marginTop: 'var(--space-4)' }}>
      {error && (
        <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}
      <table className="settings-table" style={{ fontSize: 13 }}>
        <thead>
          <tr>
            <th>Incident</th>
            <th style={{ width: 80 }}>Severity</th>
            <th style={{ width: 70 }}>Status</th>
            <th style={{ width: 100, textAlign: 'right' }}>TI Matches</th>
            <th style={{ width: 140 }}>Created</th>
          </tr>
        </thead>
        <tbody>
          {items.map(row => (
            <tr key={row.incident_id}>
              <td>
                <Link
                  to={`/incidents/${row.incident_id}/forensic/iocs`}
                  style={{ color: 'var(--accent)', textDecoration: 'none', fontWeight: 500 }}
                >
                  {row.title}
                </Link>
              </td>
              <td>
                <span
                  className="pill"
                  style={{ fontSize: 10, background: SEV_COLOR[row.severity] + '22', color: SEV_COLOR[row.severity] || 'var(--muted)', borderColor: SEV_COLOR[row.severity] + '44' }}
                >
                  {row.severity}
                </span>
              </td>
              <td>
                <span className="pill" style={{ fontSize: 10 }}>{row.status}</span>
              </td>
              <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--crit)', fontSize: 13 }}>
                {row.match_count}
              </td>
              <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--dim)' }}>
                {row.created_at ? formatLocal(row.created_at).slice(0, 16) : '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {cursor && (
        <div style={{ marginTop: 'var(--space-3)', textAlign: 'center' }}>
          <button
            type="button"
            className="btn ghost"
            style={{ fontSize: 12 }}
            onClick={() => load(cursor)}
            disabled={loading}
          >
            {loading ? 'Loading…' : 'Load more'}
          </button>
        </div>
      )}
    </div>
  )
}

// ─── IOC database tab ─────────────────────────────────────────────────────────

function IocDatabase() {
  const [items, setItems]     = useState([])
  const [total, setTotal]     = useState(0)
  const [loading, setLoading] = useState(false)
  const [q, setQ]             = useState('')
  const [typeF, setTypeF]     = useState('')
  const [cursor, setCursor]   = useState(null)

  const load = useCallback(async (opts = {}) => {
    setLoading(true)
    try {
      const params = { limit: 50 }
      if (opts.cursor)                        params.cursor = opts.cursor
      if ((opts.q   ?? q)    !== '')          params.q    = opts.q   ?? q
      if ((opts.type ?? typeF) !== '')        params.type = opts.type ?? typeF
      const res = await api.listTiIocs(params)
      setItems(opts.cursor ? prev => [...prev, ...res.items] : res.items)
      setTotal(res.total)
      setCursor(res.next_cursor || null)
    } finally {
      setLoading(false)
    }
  }, [q, typeF])

  useEffect(() => { load() }, [load])

  const search = (e) => { e.preventDefault(); load({ cursor: null }) }

  return (
    <div style={{ marginTop: 'var(--space-4)' }}>
      <div style={{ display: 'flex', gap: 'var(--space-2)', marginBottom: 'var(--space-3)', alignItems: 'center', flexWrap: 'wrap' }}>
        <form onSubmit={search} style={{ display: 'flex', gap: 'var(--space-2)', flex: 1 }}>
          <input
            className="input"
            placeholder="Search value…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            style={{ maxWidth: 320, fontFamily: 'var(--font-mono)', fontSize: 12 }}
          />
          <select
            className="select"
            value={typeF}
            onChange={(e) => { setTypeF(e.target.value); load({ type: e.target.value, cursor: null }) }}
          >
            <option value="">All types</option>
            {IOC_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
          </select>
          <button type="submit" className="btn ghost" style={{ fontSize: 12 }}>Search</button>
        </form>
        <span style={{ color: 'var(--muted)', fontSize: 12, flexShrink: 0 }}>
          {total.toLocaleString()} total
        </span>
      </div>

      {items.length === 0 && !loading ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">◌</div>
          <div style={{ color: 'var(--muted)', fontSize: 13 }}>No IOCs in database. Pull a feed to populate.</div>
        </div>
      ) : (
        <table className="settings-table" style={{ fontSize: 12 }}>
          <thead>
            <tr>
              <th style={{ width: 100 }}>Type</th>
              <th>Value</th>
              <th style={{ width: 160 }}>Feed</th>
              <th style={{ width: 140 }}>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {loading && items.length === 0 ? (
              <tr><td colSpan={4} style={{ color: 'var(--muted)', textAlign: 'center', padding: 'var(--space-4)' }}>Loading…</td></tr>
            ) : items.map(i => (
              <tr key={i.id}>
                <td><span className="pill" style={{ fontSize: 10 }}>{IOC_TYPE_LABELS[i.type] || i.type}</span></td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all' }}>{i.value}</td>
                <td style={{ color: 'var(--muted)', fontSize: 11 }}>{i.feed_name}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--dim)' }}>
                  {formatLocal(i.last_seen_at).slice(0, 16)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {cursor && (
        <div style={{ marginTop: 'var(--space-3)', textAlign: 'center' }}>
          <button
            type="button"
            className="btn ghost"
            style={{ fontSize: 12 }}
            onClick={() => load({ cursor })}
            disabled={loading}
          >
            {loading ? 'Loading…' : 'Load more'}
          </button>
        </div>
      )}
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function ThreatIntelHub() {
  const [summary, setSummary] = useState(null)
  const [tab, setTab]         = useState('matches')  // 'matches' | 'iocs'

  useEffect(() => {
    api.getTiSummary().then(setSummary).catch(() => {})
  }, [])

  return (
    <div className="page-content">
      <div className="page-head">
        <div>
          <h1 className="page-title">Threat Intel Hub</h1>
          <p style={{ color: 'var(--muted)', fontSize: 13, margin: 0 }}>
            Cross-incident threat intelligence — matched IOCs and global feed database.
          </p>
        </div>
        <Link to="/settings/threat-intel" className="btn ghost" style={{ fontSize: 12, alignSelf: 'flex-start' }}>
          Manage Feeds ↗
        </Link>
      </div>

      {/* KPI strip */}
      <div style={{ display: 'flex', gap: 'var(--space-3)', marginBottom: 'var(--space-5)', flexWrap: 'wrap' }}>
        <KpiCard label="TI IOCs in database" value={summary?.total_iocs} />
        <KpiCard label="Active feeds"        value={summary?.active_feeds} />
        <KpiCard label="Total feeds"         value={summary?.total_feeds} />
        <KpiCard
          label="Incidents with TI hits"
          value={summary?.incidents_with_matches}
          accent={summary?.incidents_with_matches > 0 ? 'var(--crit)' : 'var(--ok)'}
        />
      </div>

      {/* Tab toggle */}
      <div style={{ display: 'flex', gap: 'var(--space-1)', marginBottom: 'var(--space-4)', borderBottom: '1px solid var(--border)', paddingBottom: 'var(--space-2)' }}>
        {[
          { key: 'matches', label: 'Matched Incidents' },
          { key: 'iocs',    label: 'IOC Database' },
        ].map(t => (
          <button
            key={t.key}
            type="button"
            className={`btn ${tab === t.key ? 'primary' : 'ghost'}`}
            style={{ fontSize: 13 }}
            onClick={() => setTab(t.key)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'matches' && <MatchedIncidents />}
      {tab === 'iocs'    && <IocDatabase />}
    </div>
  )
}
