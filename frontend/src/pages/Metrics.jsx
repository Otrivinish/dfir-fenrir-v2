import { useEffect, useState, useCallback } from 'react'
import { api } from '../api/client.js'

// ─── Formatters ───────────────────────────────────────────────────────────────

function fmtMins(min) {
  if (min === null || min === undefined) return '—'
  if (min < 0) return '—'
  if (min < 60) return `${Math.round(min)}m`
  if (min < 1440) {
    const h = Math.floor(min / 60)
    const m = Math.round(min % 60)
    return m ? `${h}h ${m}m` : `${h}h`
  }
  const d = Math.floor(min / 1440)
  const rem = Math.round((min % 1440) / 60)
  return rem ? `${d}d ${rem}h` : `${d}d`
}

function shortWeek(w) {
  // "2026-W18" → "W18"
  return w ? w.split('-')[1] : ''
}

// ─── Tokens ───────────────────────────────────────────────────────────────────

const SEV_TOKEN = {
  critical: 'var(--crit)',
  high:     'var(--high)',
  medium:   'var(--med)',
  low:      'var(--low)',
}
const SEV_ORDER = ['critical', 'high', 'medium', 'low']

const PHASE_LABELS = {
  preparation:                        'Preparation',
  detection_and_analysis:             'Detection & Analysis',
  containment_eradication_recovery:   'Containment, Eradication & Recovery',
  post_incident_activity:             'Post-Incident Activity',
}

// ─── Shared sub-components ────────────────────────────────────────────────────

function StatCard({ title, value, sub, accent, children }) {
  return (
    <div style={{
      background: 'var(--surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      padding: 'var(--space-4)',
    }}>
      <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--muted)', marginBottom: 6 }}>
        {title}
      </div>
      <div style={{ fontSize: 28, fontWeight: 700, lineHeight: 1, color: accent || 'var(--text)', fontFamily: 'var(--font-mono)' }}>
        {value ?? '—'}
      </div>
      {sub && <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4 }}>{sub}</div>}
      {children}
    </div>
  )
}

function PanelSection({ title, children, style }) {
  return (
    <div style={{
      background: 'var(--surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      overflow: 'hidden',
      ...style,
    }}>
      <div style={{
        background: 'var(--surface-2)',
        padding: 'var(--space-2) var(--space-3)',
        fontSize: 11,
        fontWeight: 700,
        textTransform: 'uppercase',
        letterSpacing: '0.08em',
        color: 'var(--muted)',
        borderBottom: '1px solid var(--border)',
      }}>
        {title}
      </div>
      <div style={{ padding: 'var(--space-3)' }}>
        {children}
      </div>
    </div>
  )
}

function HBar({ items, maxOverride }) {
  const max = maxOverride ?? Math.max(1, ...items.map(i => i.value))
  if (!items.length) return <div style={{ fontSize: 12, color: 'var(--dim)' }}>No data</div>
  return (
    <div className="an-bars">
      {items.map((item, i) => (
        <div key={i} className="an-bar-row">
          <span className="an-bar-label" style={{ width: 120, flexShrink: 0 }}>{item.label}</span>
          <div className="an-bar-track">
            <div
              className="an-bar-fill"
              style={{ width: `${Math.round((item.value / max) * 100)}%`, background: item.color || 'var(--accent)' }}
            />
          </div>
          <span className="an-bar-count">{item.value}</span>
        </div>
      ))}
    </div>
  )
}

// ─── Volume mini-chart ────────────────────────────────────────────────────────

function VolumeMiniChart({ data }) {
  if (!data?.length) return <div style={{ fontSize: 12, color: 'var(--dim)' }}>No data in window</div>
  const maxVal = Math.max(1, ...data.flatMap(d => [d.opened, d.closed]))
  const chartH = 72
  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'flex-end', gap: 2, height: chartH }}>
        {data.map(w => (
          <div
            key={w.week}
            style={{ flex: 1, display: 'flex', gap: 1, alignItems: 'flex-end', minWidth: 0 }}
            title={`${shortWeek(w.week)}: opened ${w.opened}, closed ${w.closed}`}
          >
            <div style={{
              flex: 1,
              height: Math.max(2, Math.round((w.opened / maxVal) * (chartH - 4))),
              background: 'var(--crit)',
              opacity: 0.75,
              borderRadius: '2px 2px 0 0',
            }} />
            <div style={{
              flex: 1,
              height: Math.max(2, Math.round((w.closed / maxVal) * (chartH - 4))),
              background: 'var(--ok)',
              opacity: 0.75,
              borderRadius: '2px 2px 0 0',
            }} />
          </div>
        ))}
      </div>
      {/* Week labels — show first, middle, last */}
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--dim)', marginTop: 4 }}>
        <span>{shortWeek(data[0]?.week)}</span>
        {data.length > 2 && <span>{shortWeek(data[Math.floor(data.length / 2)]?.week)}</span>}
        {data.length > 1 && <span>{shortWeek(data[data.length - 1]?.week)}</span>}
      </div>
      <div style={{ display: 'flex', gap: 12, fontSize: 11, color: 'var(--muted)', marginTop: 6 }}>
        <span><span style={{ color: 'var(--crit)', fontWeight: 700 }}>■</span> Opened</span>
        <span><span style={{ color: 'var(--ok)',   fontWeight: 700 }}>■</span> Closed</span>
      </div>
    </div>
  )
}

// ─── Severity trend mini-chart (stacked horizontal bars per week) ─────────────

function SeverityTrendChart({ data }) {
  if (!data?.length) return <div style={{ fontSize: 12, color: 'var(--dim)' }}>No data in window</div>
  const maxVal = Math.max(1, ...data.map(w => SEV_ORDER.reduce((s, k) => s + (w[k] || 0), 0)))
  return (
    <div>
      {data.map(w => {
        const total = SEV_ORDER.reduce((s, k) => s + (w[k] || 0), 0)
        if (!total) return null
        return (
          <div key={w.week} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5 }}>
            <span style={{ fontSize: 10, color: 'var(--dim)', width: 30, flexShrink: 0, fontFamily: 'var(--font-mono)' }}>
              {shortWeek(w.week)}
            </span>
            <div style={{ flex: 1, height: 8, display: 'flex', gap: 1, borderRadius: 4, overflow: 'hidden', background: 'var(--surface-2)' }}>
              {SEV_ORDER.map(s => {
                const n = w[s] || 0
                if (!n) return null
                return (
                  <div
                    key={s}
                    title={`${s}: ${n}`}
                    style={{ flex: n, background: SEV_TOKEN[s], minWidth: 2 }}
                  />
                )
              })}
            </div>
            <span style={{ fontSize: 10, color: 'var(--muted)', fontFamily: 'var(--font-mono)', width: 20, textAlign: 'right' }}>
              {total}
            </span>
          </div>
        )
      })}
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginTop: 6 }}>
        {SEV_ORDER.map(s => (
          <span key={s} style={{ fontSize: 10, color: SEV_TOKEN[s], fontWeight: 700 }}>■ {s}</span>
        ))}
      </div>
    </div>
  )
}

// ─── TTx table ────────────────────────────────────────────────────────────────

function TtxTable({ data }) {
  if (!data?.length) return <div style={{ fontSize: 12, color: 'var(--dim)' }}>No closed incidents in window</div>
  const TH = { fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--muted)', padding: '0 8px 6px', whiteSpace: 'nowrap' }
  const TD = { padding: '5px 8px', borderBottom: '1px solid var(--border)', fontSize: 12, fontFamily: 'var(--font-mono)' }
  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            <th style={{ ...TH, textAlign: 'left' }}>Week</th>
            <th style={{ ...TH, textAlign: 'right', color: 'var(--accent)' }}>MTTD</th>
            <th style={{ ...TH, textAlign: 'right', color: 'var(--high)'   }}>MTTR</th>
            <th style={{ ...TH, textAlign: 'right', color: 'var(--med)'    }}>MTTC</th>
          </tr>
        </thead>
        <tbody>
          {data.map(row => (
            <tr key={row.week}>
              <td style={{ ...TD, color: 'var(--dim)' }}>{shortWeek(row.week)}</td>
              <td style={{ ...TD, textAlign: 'right', color: row.mttd ? 'var(--accent)' : 'var(--dim)' }}>{fmtMins(row.mttd)}</td>
              <td style={{ ...TD, textAlign: 'right', color: row.mttr ? 'var(--high)'   : 'var(--dim)' }}>{fmtMins(row.mttr)}</td>
              <td style={{ ...TD, textAlign: 'right', color: row.mttc ? 'var(--med)'    : 'var(--dim)' }}>{fmtMins(row.mttc)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div style={{ display: 'flex', gap: 12, fontSize: 10, color: 'var(--muted)', marginTop: 6 }}>
        <span style={{ color: 'var(--accent)' }}>MTTD</span> Mean time to detect
        <span style={{ color: 'var(--high)' }}>MTTR</span> Mean time to respond (close)
        <span style={{ color: 'var(--med)' }}>MTTC</span> Mean time to contain
      </div>
    </div>
  )
}

// ─── Severity bar (summary card) ─────────────────────────────────────────────

function SevBar({ bySev }) {
  const total = SEV_ORDER.reduce((s, k) => s + (bySev[k] || 0), 0)
  if (!total) return <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 4 }}>No incidents</div>
  return (
    <div style={{ marginTop: 8 }}>
      <div style={{ display: 'flex', height: 6, borderRadius: 3, overflow: 'hidden', gap: 1, marginBottom: 4 }}>
        {SEV_ORDER.map(s => {
          const n = bySev[s] || 0
          if (!n) return null
          return <div key={s} style={{ flex: n, background: SEV_TOKEN[s], minWidth: 3 }} title={`${s}: ${n}`} />
        })}
      </div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {SEV_ORDER.map(s => {
          const n = bySev[s] || 0
          return (
            <span key={s} style={{ fontSize: 10, color: n ? SEV_TOKEN[s] : 'var(--dim)', fontWeight: n ? 700 : 400 }}>
              {n} {s}
            </span>
          )
        })}
      </div>
    </div>
  )
}

// ─── Playbook stats ───────────────────────────────────────────────────────────

function PlaybookStats({ stats }) {
  const pct = stats?.avg_completion_pct
  const count = stats?.incidents_with_playbook || 0
  const color = pct === null ? 'var(--dim)' : pct >= 90 ? 'var(--ok)' : pct >= 50 ? 'var(--accent)' : 'var(--high)'
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
      <div style={{ display: 'flex', gap: 'var(--space-3)' }}>
        <div style={{ flex: 1, textAlign: 'center' }}>
          <div style={{ fontSize: 28, fontWeight: 700, fontFamily: 'var(--font-mono)', color }}>{pct !== null ? `${pct}%` : '—'}</div>
          <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>Avg completion</div>
        </div>
        <div style={{ flex: 1, textAlign: 'center' }}>
          <div style={{ fontSize: 28, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text)' }}>{count}</div>
          <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>With playbook</div>
        </div>
      </div>
      {pct !== null && (
        <div>
          <div style={{ height: 8, background: 'var(--surface-2)', borderRadius: 4, overflow: 'hidden' }}>
            <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 4, transition: 'width 0.4s' }} />
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Phase distribution ───────────────────────────────────────────────────────

function PhaseDistribution({ openByPhase }) {
  const entries = Object.entries(openByPhase || {}).sort((a, b) => b[1] - a[1])
  if (!entries.length) return <div style={{ fontSize: 12, color: 'var(--dim)' }}>No open incidents</div>
  const max = Math.max(1, ...entries.map(([, n]) => n))
  return (
    <div className="an-bars">
      {entries.map(([phase, n]) => (
        <div key={phase} className="an-bar-row">
          <span className="an-bar-label" style={{ width: 180, flexShrink: 0, fontSize: 11 }}>
            {PHASE_LABELS[phase] || phase}
          </span>
          <div className="an-bar-track">
            <div className="an-bar-fill" style={{ width: `${Math.round((n / max) * 100)}%`, background: 'var(--accent)' }} />
          </div>
          <span className="an-bar-count">{n}</span>
        </div>
      ))}
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function Metrics() {
  const [data,    setData]    = useState(null)
  const [window,  setWindow]  = useState(90)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState('')

  const load = useCallback(async (w) => {
    setLoading(true); setError('')
    try {
      setData(await api.getMetrics(w))
    } catch (e) {
      setError(e.message || 'Failed to load metrics')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load(window) }, [load, window])

  const s = data?.status_summary || {}

  return (
    <div style={{ maxWidth: 1400 }}>

      {/* Header */}
      <div className="page-head" style={{ marginBottom: 'var(--space-4)' }}>
        <div>
          <h1 className="page-title">Portfolio Metrics</h1>
          <div className="page-sub">Cross-incident analytics{data ? ` — ${data.window_days}-day window` : ''}</div>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {[30, 90, 180].map(d => (
            <button
              key={d}
              className="btn"
              style={window === d ? { borderColor: 'var(--accent)', color: 'var(--accent)' } : {}}
              onClick={() => setWindow(d)}
              disabled={loading}
            >
              {d}d
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div style={{ background: 'color-mix(in srgb, var(--crit) 10%, transparent)', border: '1px solid var(--crit)', borderRadius: 'var(--radius)', padding: 'var(--space-3)', fontSize: 13, color: 'var(--crit)', marginBottom: 'var(--space-4)' }}>
          {error}
        </div>
      )}

      {loading && !data && (
        <div style={{ textAlign: 'center', padding: 'var(--space-6)', color: 'var(--muted)' }}>
          Computing metrics…
        </div>
      )}

      {data && (
        <>
          {/* ── Row 1: Summary stat cards ──────────────────────────────────── */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 'var(--space-3)', marginBottom: 'var(--space-4)' }}>

            <StatCard title="Total Incidents" value={s.total} />

            <StatCard
              title="Open"
              value={s.open}
              accent={s.open > 0 ? 'var(--crit)' : 'var(--ok)'}
            >
              <SevBar bySev={s.by_severity || {}} />
            </StatCard>

            <StatCard title="Closed" value={s.closed} accent="var(--ok)" />

            <StatCard
              title="IOC Types"
              value={data.ioc_type_distribution?.reduce((s, r) => s + r.count, 0) || 0}
              sub={`${data.ioc_type_distribution?.length || 0} distinct types`}
              accent="var(--accent)"
            />

            <StatCard
              title="Playbook Completion"
              value={data.playbook_stats?.avg_completion_pct !== null
                ? `${data.playbook_stats?.avg_completion_pct}%`
                : '—'}
              sub={`${data.playbook_stats?.incidents_with_playbook || 0} incidents with playbook`}
              accent={
                data.playbook_stats?.avg_completion_pct >= 90 ? 'var(--ok)' :
                data.playbook_stats?.avg_completion_pct >= 50 ? 'var(--accent)' :
                data.playbook_stats?.avg_completion_pct !== null ? 'var(--high)' : 'var(--dim)'
              }
            />

          </div>

          {/* ── Row 2: Volume + Severity trend ─────────────────────────────── */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-4)', marginBottom: 'var(--space-4)' }}>

            <PanelSection title="Incident Volume (per week)">
              <VolumeMiniChart data={data.volume_by_week} />
            </PanelSection>

            <PanelSection title="Severity Trend (opened per week)">
              <SeverityTrendChart data={data.severity_trend} />
            </PanelSection>

          </div>

          {/* ── Row 3: TTx trend + Phase distribution ──────────────────────── */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-4)', marginBottom: 'var(--space-4)' }}>

            <PanelSection title="TTx Trend (closed per week)">
              <TtxTable data={data.ttx_by_week} />
            </PanelSection>

            <PanelSection title="Open Incidents by Phase">
              <PhaseDistribution openByPhase={s.open_by_phase} />
            </PanelSection>

          </div>

          {/* ── Row 4: Incident types + IOC types + MITRE tactics ─────────── */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 'var(--space-4)', marginBottom: 'var(--space-4)' }}>

            <PanelSection title="Incident Types (all time)">
              <HBar
                items={(data.incident_types || []).map(r => ({
                  label: r.type,
                  value: r.count,
                  color: 'var(--accent)',
                }))}
              />
              {!data.incident_types?.length && <div style={{ fontSize: 12, color: 'var(--dim)' }}>No typed incidents</div>}
            </PanelSection>

            <PanelSection title="IOC Types (all incidents)">
              <HBar
                items={(data.ioc_type_distribution || []).map(r => ({
                  label: r.type,
                  value: r.count,
                  color: 'var(--high)',
                }))}
              />
            </PanelSection>

            <PanelSection title="Top MITRE Tactics (all time)">
              <HBar
                items={(data.top_mitre_tactics || []).map(r => ({
                  label: r.tactic_name,
                  value: r.count,
                  color: 'var(--med)',
                }))}
              />
              {!data.top_mitre_tactics?.length && <div style={{ fontSize: 12, color: 'var(--dim)' }}>No MITRE-tagged events</div>}
            </PanelSection>

          </div>

          {/* ── Row 5: Analyst load + Playbook stats ───────────────────────── */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-4)' }}>

            <PanelSection title="Analyst Load (open incidents)">
              {data.analyst_load?.length ? (
                <HBar
                  items={data.analyst_load.map(r => ({
                    label: r.username,
                    value: r.open_count,
                    color: 'var(--crit)',
                  }))}
                />
              ) : (
                <div style={{ fontSize: 12, color: 'var(--dim)' }}>No assignments on open incidents</div>
              )}
            </PanelSection>

            <PanelSection title="Playbook Completion (all incidents)">
              <PlaybookStats stats={data.playbook_stats} />
            </PanelSection>

          </div>
        </>
      )}

    </div>
  )
}
