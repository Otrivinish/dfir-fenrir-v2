import { useCallback, useEffect, useState } from 'react'
import { api } from '../../api/client.js'
import { formatLocal } from '../../lib/datetime.js'

const IOC_TYPE_LABELS = {
  ip: 'IP', domain: 'Domain', url: 'URL',
  hash_md5: 'MD5', hash_sha1: 'SHA1', hash_sha256: 'SHA256',
  email: 'Email', registry_key: 'Registry key', file_path: 'File path', other: 'Other',
}

const IOC_TYPES = Object.entries(IOC_TYPE_LABELS).map(([v, l]) => ({ value: v, label: l }))

const FEED_TYPES = ['csv', 'json', 'txt']

function interval(hours) {
  if (hours < 24) return `${hours}h`
  if (hours === 24) return '24h (daily)'
  return `${hours}h`
}

function nextPull(feed) {
  if (!feed.last_pulled_at) return 'Never pulled'
  const next = new Date(new Date(feed.last_pulled_at).getTime() + feed.pull_interval_hours * 3_600_000)
  const diff = next - Date.now()
  if (diff <= 0) return 'Overdue'
  const h = Math.floor(diff / 3_600_000)
  const m = Math.floor((diff % 3_600_000) / 60_000)
  return `in ${h > 0 ? `${h}h ` : ''}${m}m`
}

// ─── Add feed modal ───────────────────────────────────────────────────────────

function AddFeedModal({ onClose, onCreated }) {
  const [name, setName]         = useState('')
  const [url, setUrl]           = useState('')
  const [feedType, setFeedType] = useState('txt')
  const [iocType, setIocType]   = useState('ip')
  const [interval_, setInterval_] = useState(24)
  const [busy, setBusy]         = useState(false)
  const [error, setError]       = useState(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      await api.createTiFeed({
        name: name.trim(),
        url: url.trim(),
        feed_type: feedType,
        ioc_type: iocType,
        pull_interval_hours: interval_,
        parser_config: {},
      })
      onCreated()
    } catch (err) {
      setError(err.message || 'Could not create feed.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div
      className="modal-backdrop"
     
    >
      <div className="modal" role="dialog" aria-labelledby="add-feed-title" style={{ maxWidth: 520 }}>
        <div className="modal-head">
          <h2 id="add-feed-title">Add custom feed</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body">
            <div className="form">
              <div className="field">
                <label className="field-label" htmlFor="af-name">Name</label>
                <input id="af-name" className="input" value={name} onChange={(e) => setName(e.target.value)} required maxLength={128} />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="af-url">Feed URL</label>
                <input id="af-url" className="input" value={url} onChange={(e) => setUrl(e.target.value)} required maxLength={512} placeholder="https://…" style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} />
                <div className="field-hint">Must use https://. Private/RFC-1918 addresses are blocked.</div>
              </div>
              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="af-ftype">Format</label>
                  <select id="af-ftype" className="select" value={feedType} onChange={(e) => setFeedType(e.target.value)}>
                    {FEED_TYPES.map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
                  </select>
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="af-itype">IOC type</label>
                  <select id="af-itype" className="select" value={iocType} onChange={(e) => setIocType(e.target.value)}>
                    {IOC_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                  </select>
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="af-int">Pull interval (h)</label>
                  <input id="af-int" className="input" type="number" min={1} max={168} value={interval_} onChange={(e) => setInterval_(Number(e.target.value))} style={{ width: 80 }} />
                </div>
              </div>
              {error && <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div>}
            </div>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button type="submit" className="btn primary" disabled={busy || !name.trim() || !url.trim()}>
              {busy ? 'Adding…' : 'Add Feed'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── Global IOC browser ───────────────────────────────────────────────────────

function GlobalIocBrowser() {
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
      if (opts.cursor) params.cursor = opts.cursor
      if (opts.q ?? q) params.q = opts.q ?? q
      if (opts.type ?? typeF) params.type = opts.type ?? typeF
      const res = await api.listTiIocs(params)
      setItems(res.items)
      setTotal(res.total)
      setCursor(res.next_cursor || null)
    } finally {
      setLoading(false)
    }
  }, [q, typeF])

  useEffect(() => { load() }, [load])

  const search = (e) => {
    e.preventDefault()
    load({ cursor: null })
  }

  if (!items.length && !loading && total === 0) {
    return (
      <div className="panel-empty" style={{ padding: 'var(--space-4) 0' }}>
        <div className="panel-empty-mark" aria-hidden="true">◌</div>
        <div style={{ color: 'var(--muted)', fontSize: 13 }}>No threat intel IOCs yet. Pull a feed to populate the database.</div>
      </div>
    )
  }

  return (
    <div style={{ marginTop: 'var(--space-4)' }}>
      <div style={{ display: 'flex', gap: 'var(--space-2)', marginBottom: 'var(--space-3)', alignItems: 'center' }}>
        <form onSubmit={search} style={{ display: 'flex', gap: 'var(--space-2)', flex: 1 }}>
          <input
            className="input"
            placeholder="Search value…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            style={{ maxWidth: 300, fontFamily: 'var(--font-mono)', fontSize: 12 }}
          />
          <select className="select" value={typeF} onChange={(e) => { setTypeF(e.target.value); load({ type: e.target.value, cursor: null }) }}>
            <option value="">All types</option>
            {IOC_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
          </select>
          <button type="submit" className="btn ghost" style={{ fontSize: 12 }}>Search</button>
        </form>
        <span style={{ color: 'var(--muted)', fontSize: 12 }}>
          {total.toLocaleString()} total
        </span>
      </div>

      {loading ? (
        <div style={{ color: 'var(--muted)', fontSize: 13, padding: 'var(--space-3) 0' }}>Loading…</div>
      ) : (
        <table className="settings-table" style={{ fontSize: 12 }}>
          <thead>
            <tr>
              <th style={{ width: 100 }}>Type</th>
              <th>Value</th>
              <th style={{ width: 140 }}>Feed</th>
              <th style={{ width: 140 }}>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {items.map(i => (
              <tr key={i.id}>
                <td><span className="pill">{IOC_TYPE_LABELS[i.type] || i.type}</span></td>
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
          <button type="button" className="btn ghost" style={{ fontSize: 12 }} onClick={() => load({ cursor })}>
            Load more
          </button>
        </div>
      )}
    </div>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function ThreatIntel() {
  const [feeds, setFeeds]       = useState([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [addOpen, setAddOpen]   = useState(false)
  const [pulling, setPulling]   = useState({})   // feedId → bool
  const [initBusy, setInitBusy] = useState(false)
  const [pullAllBusy, setPullAllBusy] = useState(false)
  const [tab, setTab]           = useState('feeds')  // 'feeds' | 'iocs'

  const load = useCallback(async () => {
    setError(null)
    try {
      const data = await api.listTiFeeds()
      setFeeds(data)
    } catch (e) {
      setError(e.message || 'Could not load feeds')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const onInit = async () => {
    setInitBusy(true)
    try {
      const res = await api.initTiFeeds()
      if (res.created > 0) await load()
      else setError(null)   // idempotent — already initialised
    } catch (e) {
      setError(e.message || 'Could not initialise feeds')
    } finally {
      setInitBusy(false)
    }
  }

  const onPull = async (feed) => {
    setPulling(p => ({ ...p, [feed.id]: true }))
    try {
      await api.pullTiFeed(feed.id)
      // Poll once after 3s for updated stats
      setTimeout(async () => {
        await load()
        setPulling(p => ({ ...p, [feed.id]: false }))
      }, 3000)
    } catch (e) {
      setError(e.message || 'Pull failed')
      setPulling(p => ({ ...p, [feed.id]: false }))
    }
  }

  const onPullAll = async () => {
    setPullAllBusy(true)
    try {
      await api.pullAllTiFeeds()
      setTimeout(async () => { await load(); setPullAllBusy(false) }, 5000)
    } catch (e) {
      setError(e.message || 'Pull all failed')
      setPullAllBusy(false)
    }
  }

  const onToggle = async (feed) => {
    try {
      await api.updateTiFeed(feed.id, { enabled: !feed.enabled })
      await load()
    } catch (e) {
      setError(e.message || 'Could not update feed')
    }
  }

  const onDelete = async (feed) => {
    if (!window.confirm(`Delete feed "${feed.name}"?\n\nThis will remove all ${feed.total_iocs_ingested.toLocaleString()} ingested IOCs from this feed.`)) return
    try {
      await api.deleteTiFeed(feed.id)
      await load()
    } catch (e) {
      setError(e.message || 'Could not delete feed')
    }
  }

  const totalIocs = feeds.reduce((s, f) => s + (f.last_ioc_count || 0), 0)
  const enabledCount = feeds.filter(f => f.enabled).length
  const neverPulled  = feeds.filter(f => !f.last_pulled_at).length

  return (
    <>
      <div className="settings-section">
        <h2 className="settings-section-title">Threat Intelligence Feeds</h2>
        <p style={{ color: 'var(--muted)', fontSize: 13, marginBottom: 'var(--space-4)', marginTop: 0 }}>
          Global IOC feeds matched automatically against incident indicators.
          Feeds are managed globally; IOC matching is per-incident.
        </p>

        {/* Stats strip */}
        {feeds.length > 0 && (
          <div style={{ display: 'flex', gap: 'var(--space-4)', marginBottom: 'var(--space-4)' }}>
            {[
              { label: 'Feeds', value: feeds.length },
              { label: 'Enabled', value: enabledCount },
              { label: 'Never pulled', value: neverPulled, warn: neverPulled > 0 },
              { label: 'IOCs loaded', value: totalIocs.toLocaleString() },
            ].map(s => (
              <div key={s.label} style={{
                background: 'var(--surface-2)', border: '1px solid var(--border)',
                borderRadius: 'var(--radius)', padding: 'var(--space-2) var(--space-3)',
                minWidth: 90, textAlign: 'center',
              }}>
                <div style={{ fontSize: 18, fontFamily: 'var(--font-mono)', fontWeight: 700, color: s.warn ? 'var(--high)' : 'var(--accent)' }}>
                  {s.value}
                </div>
                <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>{s.label}</div>
              </div>
            ))}
          </div>
        )}

        {error && (
          <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
            <span className="alert-icon">!</span><span>{error}</span>
          </div>
        )}

        {/* Toolbar */}
        <div style={{ display: 'flex', gap: 'var(--space-2)', marginBottom: 'var(--space-3)' }}>
          {feeds.length === 0 && !loading && (
            <button type="button" className="btn primary" onClick={onInit} disabled={initBusy}>
              {initBusy ? 'Initialising…' : 'Load Default Feeds'}
            </button>
          )}
          {feeds.length > 0 && (
            <button type="button" className="btn ghost" onClick={onInit} disabled={initBusy} style={{ fontSize: 12 }}>
              {initBusy ? '…' : '+ Add Defaults'}
            </button>
          )}
          <button type="button" className="btn ghost" onClick={() => setAddOpen(true)} style={{ fontSize: 12 }}>
            + Custom Feed
          </button>
          {feeds.length > 0 && (
            <button type="button" className="btn ghost" onClick={onPullAll} disabled={pullAllBusy} style={{ fontSize: 12 }}>
              {pullAllBusy ? 'Queued…' : 'Pull All'}
            </button>
          )}
          {/* Tab toggle */}
          {feeds.length > 0 && (
            <div style={{ marginLeft: 'auto', display: 'flex', gap: 'var(--space-1)' }}>
              {['feeds', 'iocs'].map(t => (
                <button
                  key={t}
                  type="button"
                  className={`btn ${tab === t ? 'primary' : 'ghost'}`}
                  style={{ fontSize: 12 }}
                  onClick={() => setTab(t)}
                >
                  {t === 'feeds' ? 'Feeds' : 'IOC Database'}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Feed cards */}
        {tab === 'feeds' && (
          loading ? (
            <div style={{ color: 'var(--muted)', fontSize: 13 }}>Loading…</div>
          ) : feeds.length === 0 ? (
            <div className="panel-empty">
              <div className="panel-empty-mark" aria-hidden="true">◌</div>
              <div>No feeds configured.</div>
              <div style={{ color: 'var(--dim)', fontSize: 12 }}>Click "Load Default Feeds" to add the built-in Abuse.ch + Emerging Threats feeds.</div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
              {feeds.map(feed => {
                const isPulling = pulling[feed.id]
                return (
                  <div
                    key={feed.id}
                    style={{
                      background: 'var(--surface)',
                      border: `1px solid ${feed.enabled ? 'var(--border)' : 'var(--border)'}`,
                      borderLeft: `3px solid ${feed.enabled ? 'var(--accent)' : 'var(--dim)'}`,
                      borderRadius: 'var(--radius)',
                      padding: 'var(--space-3) var(--space-4)',
                      opacity: feed.enabled ? 1 : 0.6,
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-3)' }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
                          <span style={{ fontWeight: 600, fontSize: 14 }}>{feed.name}</span>
                          <span className="pill" style={{ fontSize: 10 }}>{feed.feed_type.toUpperCase()}</span>
                          <span className="pill" style={{ fontSize: 10 }}>{IOC_TYPE_LABELS[feed.ioc_type] || feed.ioc_type}</span>
                          {!feed.enabled && <span className="pill pill-gray" style={{ fontSize: 10 }}>disabled</span>}
                        </div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--dim)', marginTop: 4, wordBreak: 'break-all' }}>
                          {feed.url}
                        </div>
                        <div style={{ display: 'flex', gap: 'var(--space-4)', marginTop: 'var(--space-2)', fontSize: 12, color: 'var(--muted)', flexWrap: 'wrap' }}>
                          <span>Interval: {interval(feed.pull_interval_hours)}</span>
                          <span>
                            Last pull:{' '}
                            {feed.last_pulled_at
                              ? <span title={formatLocal(feed.last_pulled_at)}>{formatLocal(feed.last_pulled_at).slice(0, 16)}</span>
                              : <span style={{ color: 'var(--high)' }}>never</span>}
                          </span>
                          {feed.last_pulled_at && (
                            <span>Next: {nextPull(feed)}</span>
                          )}
                          <span style={{ color: feed.last_ioc_count > 0 ? 'var(--ok)' : 'var(--dim)' }}>
                            {feed.last_ioc_count.toLocaleString()} IOCs last pull
                          </span>
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: 'var(--space-1)', flexShrink: 0 }}>
                        <button
                          type="button"
                          className="btn ghost"
                          style={{ fontSize: 12 }}
                          onClick={() => onPull(feed)}
                          disabled={isPulling}
                        >
                          {isPulling ? 'Queued…' : 'Pull'}
                        </button>
                        <button
                          type="button"
                          className="btn ghost"
                          style={{ fontSize: 12 }}
                          onClick={() => onToggle(feed)}
                        >
                          {feed.enabled ? 'Disable' : 'Enable'}
                        </button>
                        <button
                          type="button"
                          className="btn ghost"
                          style={{ fontSize: 12, color: 'var(--crit)' }}
                          onClick={() => onDelete(feed)}
                        >
                          Delete
                        </button>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          )
        )}

        {/* Global IOC database tab */}
        {tab === 'iocs' && <GlobalIocBrowser />}
      </div>

      {addOpen && (
        <AddFeedModal
          onClose={() => setAddOpen(false)}
          onCreated={() => { setAddOpen(false); load() }}
        />
      )}
    </>
  )
}
