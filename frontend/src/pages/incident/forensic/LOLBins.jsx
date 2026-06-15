import { useRef, useState, useEffect } from 'react'
import { api } from '../../../api/client.js'
import { formatLocal } from '../../../lib/datetime.js'

// Technique risk-level → CSS token
function techniqueToken(type) {
  const t = (type || '').toLowerCase()
  if (['execute', 'shell', 'suid', 'sudo', 'bind-shell', 'reverse-shell',
       'non-interactive-bind-shell', 'non-interactive-reverse-shell', 'download'].includes(t))
    return '--crit'
  if (['upload', 'capabilities', 'file-write'].includes(t))
    return '--high'
  if (['file-read', 'library'].includes(t))
    return '--med'
  return '--muted'
}

function techniqueColor(type) { return `var(${techniqueToken(type)})` }

// Platform → token
const PLATFORM_TOKEN = { windows: '--high', linux: '--accent' }
const PLATFORM_LABEL = { windows: 'Windows · LOLBAS', linux: 'Linux · GTFOBins' }
function platformColor(p) { return `var(${PLATFORM_TOKEN[p] || '--muted'})` }

// ── Sub-components ────────────────────────────────────────────────────────────

function TechniqueCard({ t }) {
  const [open, setOpen] = useState(false)
  const color = techniqueColor(t.type)
  return (
    <div style={{
      background: 'var(--surface-2)', borderRadius: 'var(--radius-sm)',
      padding: 'var(--space-2) var(--space-3)', marginBottom: 'var(--space-1)',
      border: `1px solid color-mix(in srgb, ${color} 20%, transparent)`,
    }}>
      <div
        style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', cursor: 'pointer', flexWrap: 'wrap' }}
        onClick={() => setOpen(o => !o)}
      >
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 700, letterSpacing: '0.08em',
          textTransform: 'uppercase', padding: '1px 6px', borderRadius: 'var(--radius-sm)',
          color, background: `color-mix(in srgb, ${color} 14%, transparent)`,
          border: `1px solid color-mix(in srgb, ${color} 30%, transparent)`, flexShrink: 0,
        }}>{t.type}</span>
        {t.privileges && (
          <span style={{
            fontSize: 10, color: 'var(--dim)', background: 'var(--surface)',
            padding: '1px 5px', borderRadius: 'var(--radius-sm)',
          }}>{t.privileges}</span>
        )}
        {(t.mitre || []).map(m => (
          <span key={m} style={{
            fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--accent)',
            background: 'color-mix(in srgb, var(--accent) 12%, transparent)',
            padding: '1px 5px', borderRadius: 'var(--radius-sm)', flexShrink: 0,
          }}>{m}</span>
        ))}
        {t.description && (
          <span style={{
            fontSize: 11, color: 'var(--muted)', flex: 1, overflow: 'hidden',
            textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>{t.description}</span>
        )}
        <span style={{ fontSize: 10, color: 'var(--dim)', marginLeft: 'auto', flexShrink: 0 }}>
          {open ? '▴' : '▾'}
        </span>
      </div>
      {open && t.command && (
        <pre style={{
          marginTop: 'var(--space-2)', background: 'var(--bg)',
          border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)',
          padding: 'var(--space-2) var(--space-3)', fontSize: 11,
          fontFamily: 'var(--font-mono)', color: 'var(--ok)',
          overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
        }}>{t.command}</pre>
      )}
      {open && t.detect && (
        <div style={{ marginTop: 'var(--space-1)', fontSize: 11, color: 'var(--dim)', fontStyle: 'italic' }}>
          ⚑ {t.detect}
        </div>
      )}
    </div>
  )
}

function EntryCard({ entry }) {
  const [open, setOpen] = useState(false)
  const pc = platformColor(entry.platform)
  const types = [...new Set((entry.techniques || []).map(t => t.type))]

  return (
    <div style={{
      background: 'var(--surface)', border: '1px solid var(--border)',
      borderLeft: `3px solid ${pc}`, borderRadius: 'var(--radius)',
      marginBottom: 'var(--space-2)',
    }}>
      <div
        style={{ padding: 'var(--space-3) var(--space-4)', cursor: 'pointer', display: 'flex', alignItems: 'flex-start', gap: 'var(--space-3)' }}
        onClick={() => setOpen(o => !o)}
      >
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap', marginBottom: 'var(--space-1)' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 14, fontWeight: 800, color: 'var(--text)' }}>
              {entry.full_name || entry.name}
            </span>
            <span style={{
              fontSize: 10, fontWeight: 700, padding: '1px 6px', borderRadius: 'var(--radius-sm)',
              color: pc, background: `color-mix(in srgb, ${pc} 14%, transparent)`,
              border: `1px solid color-mix(in srgb, ${pc} 30%, transparent)`,
            }}>{PLATFORM_LABEL[entry.platform] || entry.platform}</span>
          </div>
          {entry.description && (
            <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.5, marginBottom: 'var(--space-1)' }}>
              {entry.description}
            </div>
          )}
          <div style={{ display: 'flex', gap: 'var(--space-1)', flexWrap: 'wrap' }}>
            {types.slice(0, 8).map(t => {
              const c = techniqueColor(t)
              return (
                <span key={t} style={{
                  fontSize: 10, padding: '1px 5px', borderRadius: 'var(--radius-sm)',
                  color: c, background: `color-mix(in srgb, ${c} 10%, transparent)`,
                  border: `1px solid color-mix(in srgb, ${c} 25%, transparent)`,
                }}>{t}</span>
              )
            })}
            {types.length > 8 && (
              <span style={{ fontSize: 10, color: 'var(--dim)' }}>+{types.length - 8} more</span>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexShrink: 0 }}>
          <span style={{ fontSize: 12, color: 'var(--dim)' }}>{entry.techniques?.length || 0} techniques</span>
          <span style={{ fontSize: 13, color: 'var(--dim)' }}>{open ? '▴' : '▾'}</span>
        </div>
      </div>

      {open && (
        <div style={{ padding: '0 var(--space-4) var(--space-3)' }}>
          {(entry.paths || []).filter(Boolean).length > 0 && (
            <div style={{ marginBottom: 'var(--space-3)' }}>
              <div style={{ fontSize: 10, color: 'var(--dim)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 'var(--space-1)' }}>
                Paths
              </div>
              {entry.paths.filter(Boolean).map((p, i) => (
                <code key={i} style={{
                  display: 'block', fontSize: 11, fontFamily: 'var(--font-mono)',
                  color: 'var(--muted)', background: 'var(--surface-2)',
                  padding: '2px var(--space-2)', borderRadius: 'var(--radius-sm)', marginBottom: 2,
                }}>{p}</code>
              ))}
            </div>
          )}
          <div style={{ fontSize: 10, color: 'var(--dim)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 'var(--space-2)' }}>
            Techniques ({entry.techniques?.length || 0})
          </div>
          {(entry.techniques || []).map((t, i) => <TechniqueCard key={i} t={t} />)}
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function LOLBins() {
  const [entries,  setEntries]  = useState([])
  const [status,   setStatus]   = useState(null)
  const [loading,  setLoading]  = useState(true)
  const [syncing,  setSyncing]  = useState(false)
  const [q,        setQ]        = useState('')
  const [platform, setPlatform] = useState('')
  const [error,    setError]    = useState(null)
  const debounce = useRef(null)

  const loadStatus = () =>
    api.lolbinsStatus().then(setStatus).catch(() => {})

  const loadEntries = (query, plat) => {
    setLoading(true)
    api.lolbinsSearch(query, plat)
      .then(data => { setEntries(data || []); setError(null) })
      .catch(e  => setError(e.message || 'Search failed'))
      .finally(() => setLoading(false))
  }

  useEffect(() => { loadStatus(); loadEntries('', '') }, [])

  const handleSearch = (val) => {
    setQ(val)
    clearTimeout(debounce.current)
    debounce.current = setTimeout(() => loadEntries(val, platform), 300)
  }

  const handlePlatform = (val) => {
    setPlatform(val)
    loadEntries(q, val)
  }

  const handleSync = async () => {
    setSyncing(true)
    try {
      await api.lolbinsSync()
      setTimeout(() => { loadStatus(); loadEntries(q, platform); setSyncing(false) }, 5000)
    } catch (e) {
      setError(e.message || 'Sync failed')
      setSyncing(false)
    }
  }

  const syncTs = status?.last_sync
    ? formatLocal(new Date(status.last_sync * 1000).toISOString())
    : 'never'

  return (
    <div>
      {/* Status bar */}
      {status && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 'var(--space-4)',
          padding: 'var(--space-2) var(--space-3)',
          background: 'var(--surface)', border: '1px solid var(--border)',
          borderRadius: 'var(--radius)', marginBottom: 'var(--space-3)', fontSize: 12,
          flexWrap: 'wrap',
        }}>
          <span style={{ color: 'var(--muted)' }}>
            Total: <strong style={{ color: 'var(--text)' }}>{status.total}</strong>
          </span>
          <span style={{ color: `var(${PLATFORM_TOKEN.windows})` }}>
            Windows (LOLBAS): <strong>{status.windows}</strong>
          </span>
          <span style={{ color: `var(${PLATFORM_TOKEN.linux})` }}>
            Linux (GTFOBins): <strong>{status.linux}</strong>
          </span>
          <span style={{ color: 'var(--dim)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
            Last sync: {syncTs}
          </span>
          <button
            type="button" className="btn ghost"
            style={{ fontSize: 11, marginLeft: 'auto', whiteSpace: 'nowrap' }}
            onClick={handleSync} disabled={syncing}
          >
            {syncing ? '⟳ Syncing…' : '⟳ Force sync'}
          </button>
        </div>
      )}

      {/* Not-yet-synced banner */}
      {status && !status.synced && !loading && (
        <div style={{
          padding: 'var(--space-4)', textAlign: 'center',
          background: 'var(--surface)', border: `1px solid color-mix(in srgb, var(--med) 40%, transparent)`,
          borderRadius: 'var(--radius)', marginBottom: 'var(--space-3)',
        }}>
          <div style={{ fontSize: 28, marginBottom: 'var(--space-2)', color: 'var(--med)' }}>⟳</div>
          <div style={{ fontWeight: 600, marginBottom: 'var(--space-1)', color: 'var(--text)' }}>
            Database not yet synced
          </div>
          <div style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 'var(--space-3)' }}>
            FENRIR syncs LOLBAS and GTFOBins on first request. Check back in a moment, or force a sync now.
          </div>
          <button type="button" className="btn primary" onClick={handleSync} disabled={syncing}>
            {syncing ? '⟳ Syncing…' : '⟳ Sync now'}
          </button>
        </div>
      )}

      {/* Search + platform filter */}
      <div style={{ display: 'flex', gap: 'var(--space-2)', marginBottom: 'var(--space-3)', flexWrap: 'wrap' }}>
        <input
          className="input"
          style={{ flex: 1, minWidth: 200, fontFamily: 'var(--font-mono)', fontSize: 13 }}
          value={q}
          onChange={e => handleSearch(e.target.value)}
          placeholder="Search binary name, technique, description…"
        />
        <div style={{ display: 'flex', gap: 'var(--space-1)' }}>
          {[['', 'All'], ['windows', '⊞ Windows'], ['linux', '⊟ Linux']].map(([val, label]) => (
            <button
              key={val} type="button"
              className={`btn ${platform === val ? 'primary' : 'ghost'}`}
              style={{ fontSize: 12 }}
              onClick={() => handlePlatform(val)}
            >{label}</button>
          ))}
        </div>
      </div>

      {error && (
        <div className="alert error" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      <div style={{ fontSize: 12, color: 'var(--dim)', marginBottom: 'var(--space-2)', fontFamily: 'var(--font-mono)' }}>
        {loading ? 'Loading…' : `${entries.length} entries${q ? ` matching "${q}"` : ''}`}
      </div>

      {!loading && entries.map(entry => (
        <EntryCard key={`${entry.source}-${entry.name}`} entry={entry} />
      ))}

      {!loading && entries.length === 0 && status?.synced && (
        <div style={{ textAlign: 'center', padding: 'var(--space-6)', color: 'var(--dim)' }}>
          <div style={{ fontSize: 28, marginBottom: 'var(--space-2)' }}>◎</div>
          <div>No results for &ldquo;{q}&rdquo;</div>
        </div>
      )}
    </div>
  )
}
