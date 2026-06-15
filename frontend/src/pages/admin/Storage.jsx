import { useState, useEffect, useCallback } from 'react'
import { api } from '../../api/client.js'

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtBytes(n) {
  if (n === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.min(Math.floor(Math.log2(n) / 10), units.length - 1)
  const v = n / Math.pow(1024, i)
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`
}

function fmtCount(n) {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000)     return `${(n / 1_000).toFixed(1)}K`
  return String(n)
}

function usageColor(pct) {
  if (pct >= 90) return 'var(--crit)'
  if (pct >= 75) return 'var(--high)'
  if (pct >= 50) return 'var(--med)'
  return 'var(--ok)'
}

// ─── Volume card ──────────────────────────────────────────────────────────────

function VolumeCard({ vol }) {
  if (!vol.exists) {
    return (
      <div style={{
        border: '1px solid var(--border)', borderRadius: 'var(--radius)',
        background: 'var(--surface)', padding: 'var(--space-4)', opacity: 0.5,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 8 }}>
          <span style={{ fontWeight: 600, fontSize: 14 }}>{vol.label}</span>
          <span style={{
            fontSize: 10, padding: '1px 6px', borderRadius: 'var(--radius-sm)',
            background: 'var(--surface-2)', color: 'var(--muted)', border: '1px solid var(--border)',
          }}>not mounted</span>
        </div>
        <div style={{ fontSize: 11, color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>{vol.path}</div>
      </div>
    )
  }

  const usedPct = vol.fs_total_bytes > 0
    ? Math.round((vol.fs_used_bytes / vol.fs_total_bytes) * 100)
    : 0
  const color = usageColor(usedPct)

  return (
    <div style={{
      border: '1px solid var(--border)',
      borderTop: `3px solid ${color}`,
      borderRadius: 'var(--radius)',
      background: 'var(--surface)',
      padding: 'var(--space-4)',
    }}>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-2)', marginBottom: 12 }}>
        <span style={{ fontWeight: 600, fontSize: 14 }}>{vol.label}</span>
        <span style={{ fontSize: 11, color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>{vol.path}</span>
      </div>

      <div style={{ marginBottom: 14 }}>
        <div style={{ fontSize: 20, fontWeight: 700, fontFamily: 'var(--font-mono)', lineHeight: 1 }}>
          {fmtBytes(vol.content_bytes)}
        </div>
        <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>
          {fmtCount(vol.file_count)} file{vol.file_count !== 1 ? 's' : ''}
          {vol.scan_capped && (
            <span style={{ color: 'var(--dim)' }}> (scan capped at 50 K)</span>
          )}
        </div>
      </div>

      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
          <span style={{ fontSize: 11, color: 'var(--muted)' }}>
            Filesystem — {usedPct}% used
          </span>
          <span style={{ fontSize: 11, color: 'var(--dim)' }}>
            {fmtBytes(vol.fs_free_bytes)} free of {fmtBytes(vol.fs_total_bytes)}
          </span>
        </div>
        <div style={{ height: 6, borderRadius: 3, background: 'var(--surface-2)' }}>
          <div style={{
            height: '100%', borderRadius: 3,
            width: `${Math.min(usedPct, 100)}%`,
            background: color,
            transition: 'width 0.4s ease',
          }} />
        </div>
        <div style={{
          display: 'flex', justifyContent: 'space-between', marginTop: 4,
          fontSize: 10, color: 'var(--dim)', fontFamily: 'var(--font-mono)',
        }}>
          <span>{fmtBytes(vol.fs_used_bytes)} used</span>
          <span>{fmtBytes(vol.fs_total_bytes)} total</span>
        </div>
      </div>
    </div>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function Storage() {
  const [data, setData]       = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)
  const [lastAt, setLastAt]   = useState(null)
  const [reclaiming, setReclaiming] = useState(false)
  const [reclaimMsg, setReclaimMsg] = useState(null)

  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const d = await api.getStorageStatus()
      setData(d)
      setLastAt(new Date())
    } catch (e) {
      setError(e.message || 'Failed to load storage data')
    } finally {
      setLoading(false)
    }
  }, [])

  const reclaim = useCallback(async () => {
    setReclaiming(true); setReclaimMsg(null)
    try {
      const r = await api.cleanupCollections()
      setReclaimMsg(
        `Reclaimed ${fmtBytes(r.reclaimable_bytes ?? r.reclaimed_bytes ?? 0)} `
        + `(${r.reclaimed_files ?? 0} package${(r.reclaimed_files ?? 0) !== 1 ? 's' : ''}; `
        + `${r.expired ?? 0} expired, ${r.superseded ?? 0} superseded).`
      )
      await load()
    } catch (e) {
      setReclaimMsg(e.message || 'Cleanup failed')
    } finally {
      setReclaiming(false)
    }
  }, [load])

  useEffect(() => { load() }, [load])

  const totalContent = data?.volumes.reduce((s, v) => s + v.content_bytes, 0) ?? 0
  const totalFiles   = data?.volumes.reduce((s, v) => s + v.file_count,   0) ?? 0

  return (
    <section className="panel">
      <div className="panel-toolbar" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h2 className="panel-h" style={{ margin: 0 }}>Storage</h2>
          {lastAt && (
            <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 2 }}>
              Last refreshed {lastAt.toLocaleTimeString()}
            </div>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
          {data && (
            <span style={{ fontSize: 12, color: 'var(--muted)' }}>
              {fmtBytes(totalContent)} across {fmtCount(totalFiles)} files
            </span>
          )}
          <button
            className="btn btn-ghost btn-sm"
            onClick={load}
            disabled={loading}
          >{loading ? 'Scanning…' : 'Refresh'}</button>
        </div>
      </div>

      {error && (
        <div style={{
          margin: 'var(--space-3) var(--space-4)',
          padding: 'var(--space-2) var(--space-3)',
          background: 'color-mix(in srgb, var(--crit) 10%, transparent)',
          borderRadius: 'var(--radius-sm)', fontSize: 12, color: 'var(--crit)',
        }}>{error}</div>
      )}

      {loading && !data && (
        <div className="panel-empty">
          <div style={{ fontSize: 13, color: 'var(--muted)' }}>Scanning volumes…</div>
        </div>
      )}

      {data && (
        <div style={{
          padding: 'var(--space-4)',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
          gap: 'var(--space-3)',
        }}>
          {data.volumes.map(vol => (
            <VolumeCard key={vol.label} vol={vol} />
          ))}
        </div>
      )}

      {data?.collections && (
        <div style={{ padding: '0 var(--space-4) var(--space-4)' }}>
          <div style={{
            border: '1px solid var(--border)',
            borderTop: `3px solid ${data.collections.reclaimable_bytes > 0 ? 'var(--high)' : 'var(--ok)'}`,
            borderRadius: 'var(--radius)', background: 'var(--surface)', padding: 'var(--space-4)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 'var(--space-3)', flexWrap: 'wrap', marginBottom: 12 }}>
              <div>
                <span style={{ fontWeight: 600, fontSize: 14 }}>Collection packages</span>
                <span style={{ fontSize: 11, color: 'var(--dim)', marginLeft: 8, fontFamily: 'var(--font-mono)' }}>
                  quarantine/_collections
                </span>
                <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>
                  Velociraptor collectors (~60 MB each). The retention sweep reclaims expired,
                  superseded, and consumed packages.
                </div>
              </div>
              <button className="btn btn-ghost btn-sm" onClick={reclaim}
                      disabled={reclaiming || data.collections.reclaimable_bytes <= 0}>
                {reclaiming ? 'Reclaiming…' : 'Reclaim now'}
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: 'var(--space-3)' }}>
              {[
                ['On disk',     fmtBytes(data.collections.on_disk_bytes), `${fmtCount(data.collections.file_count)} files`, 'var(--text)'],
                ['Active',      fmtBytes(data.collections.active_bytes),  `${data.collections.active_count} package${data.collections.active_count !== 1 ? 's' : ''}`, 'var(--ok)'],
                ['Reclaimable', fmtBytes(data.collections.reclaimable_bytes), 'next sweep frees', data.collections.reclaimable_bytes > 0 ? 'var(--high)' : 'var(--dim)'],
                ['Stale',       String(data.collections.stale_count), 'outdated build', data.collections.stale_count > 0 ? 'var(--high)' : 'var(--dim)'],
              ].map(([label, val, sub, color]) => (
                <div key={label}>
                  <div style={{ fontSize: 10, color: 'var(--dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{label}</div>
                  <div style={{ fontSize: 18, fontWeight: 700, fontFamily: 'var(--font-mono)', color, lineHeight: 1.2 }}>{val}</div>
                  <div style={{ fontSize: 10, color: 'var(--dim)' }}>{sub}</div>
                </div>
              ))}
            </div>

            {reclaimMsg && (
              <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 12, fontFamily: 'var(--font-mono)' }}>
                {reclaimMsg}
              </div>
            )}
          </div>
        </div>
      )}
    </section>
  )
}
