import { useEffect, useMemo, useState, useCallback } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, notifyUnauthorized } from '../api/client.js'
import { labelOf, byValue } from '../lib/incidentVocab.js'
import { relative, formatLocal } from '../lib/datetime.js'
import SevBadge, { SEV_PALETTE } from '../components/SevBadge.jsx'
import IncidentCreateModal from '../components/IncidentCreateModal.jsx'
import TagChip from '../components/TagChip.jsx'

const STALE_DAYS = 7
const LS_MINE = 'fenrir.dashboard.mine'

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtMinutes(min) {
  if (min === null || min === undefined) return '—'
  if (min < 60)   return `${Math.round(min)}m`
  if (min < 1440) return `${(min / 60).toFixed(1)}h`
  return `${(min / 1440).toFixed(1)}d`
}

function timeSince(iso) {
  const ms = Date.now() - new Date(iso).getTime()
  const h  = Math.floor(ms / 3600000)
  if (h < 24) return `${h}h`
  return `${Math.floor(h / 24)}d`
}

function incNum(inc) {
  return inc.ref ?? ('#' + inc.id.replace(/-/g, '').slice(-6).toUpperCase())
}

// ─── Event type config ────────────────────────────────────────────────────────

const EVENT_CONFIG = {
  incident_created:  { label: 'Incident opened',   dot: 'var(--crit)'   },
  incident_closed:   { label: 'Incident closed',   dot: 'var(--ok)'     },
  ioc_added:         { label: 'IOC added',          dot: 'var(--high)'   },
  timeline_event:    { label: 'Timeline event',     dot: 'var(--accent)' },
  respond_action:    { label: 'Respond action',     dot: 'var(--med)'    },
  evidence_collected:{ label: 'Evidence collected', dot: 'var(--low)'    },
}

// ─── Severity breakdown bar ───────────────────────────────────────────────────

const SEV_ORDER = ['critical', 'high', 'medium', 'low']
const SEV_TOKEN = {
  critical: SEV_PALETTE.critical.text,
  high:     SEV_PALETTE.high.text,
  medium:   SEV_PALETTE.medium.text,
  low:      SEV_PALETTE.low.text,
}

function SevBar({ bySev, total }) {
  if (!total) return <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 4 }}>No open incidents</div>
  return (
    <div style={{ marginTop: 8 }}>
      <div style={{ display: 'flex', height: 6, borderRadius: 3, overflow: 'hidden', gap: 1, marginBottom: 6 }}>
        {SEV_ORDER.map(s => {
          const n = bySev[s] || 0
          if (!n) return null
          return <div key={s} style={{ flex: n, background: SEV_TOKEN[s], minWidth: 3 }} title={`${s}: ${n}`} />
        })}
      </div>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
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

// ─── KPI Card ─────────────────────────────────────────────────────────────────

function KPICard({ title, value, sub, accent, children }) {
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
      <div style={{ fontSize: 30, fontWeight: 700, lineHeight: 1, color: accent || 'var(--text)' }}>
        {value ?? '—'}
      </div>
      {sub && <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4 }}>{sub}</div>}
      {children}
    </div>
  )
}

// ─── Open incidents table ─────────────────────────────────────────────────────

const TH = { fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--muted)', padding: '0 10px 8px', whiteSpace: 'nowrap', borderBottom: '1px solid var(--border)' }
const TD = { padding: '9px 10px', borderBottom: '1px solid var(--border)', verticalAlign: 'middle' }

// Statuses considered "open / still owed" for the Legal column pill colour.
const LEGAL_OPEN_STATUSES = new Set(['pending', 'in_progress'])

function LegalCell({ deadlines }) {
  if (!deadlines || deadlines.length === 0) {
    return <span style={{ color: 'var(--dim)' }}>—</span>
  }
  // Dedup by regulation: pick worst status (open > waived > completed) so each
  // regulation appears once with its most-urgent status colour.
  const byReg = new Map()
  for (const d of deadlines) {
    const cur = byReg.get(d.regulation)
    const rank = (s) => (LEGAL_OPEN_STATUSES.has(s) ? 2 : s === 'completed' ? 0 : 1)
    if (!cur || rank(d.status) > rank(cur.status)) byReg.set(d.regulation, d)
  }
  const pills = Array.from(byReg.values()).sort((a, b) => a.regulation.localeCompare(b.regulation))
  return (
    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
      {pills.map(d => {
        const open = LEGAL_OPEN_STATUSES.has(d.status)
        const completed = d.status === 'completed'
        const color = open ? 'var(--high)' : completed ? 'var(--ok)' : 'var(--muted)'
        return (
          <span
            key={d.regulation}
            title={`${d.regulation} — ${d.status.replace('_',' ')}`}
            style={{
              fontSize: 10, fontFamily: 'var(--font-mono)', fontWeight: 700,
              padding: '1px 6px', borderRadius: 'var(--radius-sm)',
              color,
              background: `color-mix(in srgb, ${color} 14%, transparent)`,
              border: `1px solid color-mix(in srgb, ${color} 30%, transparent)`,
            }}
          >{d.regulation}</span>
        )
      })}
    </div>
  )
}

function IncidentRow({ inc, legal }) {
  const [hov, setHov] = useState(false)
  const navigate = useNavigate()
  return (
    <tr
      onClick={() => navigate(`/incidents/${inc.id}/details`)}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{ background: hov ? 'var(--surface-2)' : 'transparent', transition: 'background 0.1s', cursor: 'pointer' }}
    >
      <td style={{ ...TD, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)', whiteSpace: 'nowrap' }}>
        {incNum(inc)}
      </td>
      <td style={{ ...TD, maxWidth: 260 }}>
        <Link
          to={`/incidents/${inc.id}/details`}
          style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', textDecoration: 'none', display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
          title={inc.title}
        >
          {inc.title}
        </Link>
      </td>
      <td style={{ ...TD, whiteSpace: 'nowrap' }}>
        <SevBadge value={inc.severity} />
      </td>
      <td style={{ ...TD, fontSize: 12, color: 'var(--muted)', whiteSpace: 'nowrap' }}>
        {labelOf('phase', inc.phase)}
      </td>
      <td style={{ ...TD, whiteSpace: 'nowrap' }} onClick={(e) => e.stopPropagation()}>
        <LegalCell deadlines={legal} />
      </td>
      <td style={{ ...TD, fontSize: 12, color: 'var(--muted)' }}>
        {inc.reporter || <span style={{ color: 'var(--dim)' }}>—</span>}
      </td>
      <td style={{ ...TD, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)', whiteSpace: 'nowrap', textAlign: 'right' }}>
        {timeSince(inc.created_at)}
      </td>
    </tr>
  )
}

// ─── Main Dashboard ───────────────────────────────────────────────────────────

export default function Dashboard() {
  const [summary,   setSummary]   = useState(null)
  const [activity,  setActivity]  = useState(null)
  const [incidents, setIncidents] = useState(null)
  const [loading,   setLoading]   = useState(true)
  const [error,     setError]     = useState('')

  const [legalByIncident, setLegalByIncident] = useState({})
  const [overdueTotal,    setOverdueTotal]    = useState(0)
  const [oncall,          setOncall]          = useState(null)
  const [mine, setMine] = useState(() => {
    try { return localStorage.getItem(LS_MINE) === '1' } catch { return false }
  })
  const [showCreate, setShowCreate] = useState(false)
  const [trend,    setTrend]    = useState(null)   // { days, series:[{date, opened, closed}] }
  const [workload, setWorkload] = useState([])     // [{user_id, username, active_count}]
  const [tactics,  setTactics]  = useState([])     // [{tactic_id, tactic_name, count}]
  const [topTags,  setTopTags]  = useState([])     // [{tag, count}]
  const [lastUpdated, setLastUpdated] = useState(null)

  const setMinePersist = useCallback((v) => {
    setMine(v)
    try { localStorage.setItem(LS_MINE, v ? '1' : '0') } catch { /* ok */ }
  }, [])

  const load = useCallback(async () => {
    setLoading(true); setError('')
    try {
      const [sum, act, incs, legal, oc, tr, wl, tt, tg] = await Promise.all([
        api.getDashboardSummary(mine),
        api.getDashboardActivity(mine, 50),
        api.listIncidents({ status: 'open', limit: 50, ...(mine ? { mine: true } : {}) }),
        api.getDashboardLegalSummary(mine).catch(() => ({ by_incident: {}, overdue_total: 0 })),
        api.getCurrentOnCall().catch(() => null),
        api.getDashboardTrend(30, mine).catch(() => null),
        api.getDashboardWorkload().catch(() => ({ items: [] })),
        api.getDashboardTopTactics(8).catch(() => ({ items: [] })),
        api.getDashboardTopTags('incident', 8).catch(() => ({ items: [] })),
      ])
      setSummary(sum)
      setActivity(act.items)
      setIncidents(incs.items)
      setLegalByIncident(legal?.by_incident || {})
      setOverdueTotal(legal?.overdue_total || 0)
      setOncall(oc || null)
      setTrend(tr)
      setWorkload(wl?.items || [])
      setTactics(tt?.items || [])
      setTopTags(tg?.items || [])
      setLastUpdated(new Date())
    } catch (e) {
      setError(e.message || 'Failed to load dashboard')
    } finally {
      setLoading(false)
    }
  }, [mine])

  useEffect(() => { load() }, [load])

  // Live refresh — subscribes to the notifications WS and reloads when an
  // event that could move a dashboard number fires. The WS is best-effort:
  // failures fall back to the existing manual refresh-on-mount behaviour.
  useEffect(() => {
    const wsBase = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host
    let ws
    let reload
    try {
      ws = new WebSocket(`${wsBase}/api/notifications/ws`)
    } catch {
      return
    }

    // Debounce: a phase change can fire 2-3 events back-to-back; collapse them
    // so we don't hammer the backend with full reloads.
    let timer = null
    reload = () => {
      if (timer) return
      timer = setTimeout(() => { timer = null; load() }, 800)
    }

    ws.onmessage = (ev) => {
      try {
        const m = JSON.parse(ev.data)
        if (m.type !== 'notification') return
        // Refresh on lifecycle events. Comment/mention notifications don't
        // change any visible counter so we skip them to stay quiet.
        if (['incident_created', 'phase_changed', 'handoff_pending'].includes(m.notification_type || m.type) ||
            (typeof m.title === 'string' && /opened|reopened|resolved|phase/i.test(m.title))) {
          reload()
        }
      } catch { /* ignore */ }
    }
    ws.onerror = () => {}
    ws.onclose = (e) => { if (timer) clearTimeout(timer); if (e.code === 4001) notifyUnauthorized() }
    return () => { try { ws.close() } catch { /* ok */ } }
  }, [load])

  const onCreatedIncident = useCallback((newInc) => {
    setShowCreate(false)
    // Optimistic: prepend to the open-incidents list so the operator sees it
    // immediately without waiting for a roundtrip.
    if (newInc && newInc.status === 'open') {
      setIncidents(prev => [newInc, ...(prev || [])])
    }
    load()
  }, [load])

  // Stale incidents — no updated_at change in STALE_DAYS days. Derived from
  // the open-incidents list so we don't need a dedicated endpoint.
  const staleCount = useMemo(() => {
    if (!incidents) return 0
    const cutoff = Date.now() - STALE_DAYS * 86400 * 1000
    return incidents.filter(i => {
      const t = i.updated_at || i.created_at
      return t && new Date(t).getTime() < cutoff
    }).length
  }, [incidents])

  // Phase distribution from the open-incidents list — phase enum from incidentVocab.
  const byPhase = useMemo(() => {
    const counts = {}
    for (const i of (incidents || [])) counts[i.phase] = (counts[i.phase] || 0) + 1
    return counts
  }, [incidents])

  // Top incident-type breakdown — top 5 + "other" bucket.
  const byType = useMemo(() => {
    const counts = {}
    for (const i of (incidents || [])) {
      const t = i.incident_type || 'unspecified'
      counts[t] = (counts[t] || 0) + 1
    }
    return counts
  }, [incidents])

  if (loading && !summary) return (
    <div className="panel"><div className="panel-empty">Loading dashboard…</div></div>
  )
  if (error) return (
    <div className="panel">
      <div className="panel-empty">
        <div className="panel-empty-mark" aria-hidden="true">!</div>
        <div>{error}</div>
      </div>
    </div>
  )

  const sample = (n, label) =>
    n > 0 ? `${n} incident${n !== 1 ? 's' : ''}` : `No data — ${label}`

  return (
    <div style={{ maxWidth: 1280 }}>

      {/* Header — title + scope chips + create-incident CTA */}
      <div className="page-head" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 'var(--space-3)' }}>
        <div>
          <h1 className="page-title">Dashboard</h1>
          <div className="page-sub">30-day rolling metrics</div>
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
          <div style={{ display: 'flex', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', overflow: 'hidden' }}>
            {[['all', 'All', false], ['mine', 'Mine', true]].map(([id, label, val]) => (
              <button
                key={id}
                type="button"
                onClick={() => setMinePersist(val)}
                style={{
                  fontSize: 12, padding: '4px 12px',
                  background: mine === val ? 'var(--accent-soft)' : 'transparent',
                  color: mine === val ? 'var(--accent)' : 'var(--muted)',
                  border: 'none', cursor: 'pointer',
                }}
              >{label}</button>
            ))}
          </div>
          {lastUpdated && (
            <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--ok)' }} title="Live — WebSocket connected" />
              {formatLocal(lastUpdated.toISOString()).slice(11)}
            </span>
          )}
          <button
            type="button"
            className="btn primary"
            onClick={() => setShowCreate(true)}
          >+ New incident</button>
        </div>
      </div>

      {/* Context strip — single line with on-call, stale, overdue legal */}
      <ContextStrip
        oncall={oncall}
        staleCount={staleCount}
        overdueTotal={overdueTotal}
      />

      {/* KPI grid — 7 cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(170px,1fr))', gap: 'var(--space-3)', marginBottom: 'var(--space-4)', marginTop: 'var(--space-3)' }}>

        <KPICard
          title="Open"
          value={summary?.open_total ?? 0}
          accent={summary?.open_total > 0 ? SEV_PALETTE.critical.text : 'var(--ok)'}
        />
        <KPICard
          title="Critical + High"
          value={summary?.critical_high ?? 0}
          sub="open, need action"
          accent={(summary?.critical_high ?? 0) > 0 ? SEV_PALETTE.critical.text : 'var(--muted)'}
        />
        <KPICard
          title="Opened 30d"
          value={summary?.opened_30d ?? 0}
          sub="new incidents this window"
          accent="var(--accent)"
        />
        <KPICard
          title="Closed 30d"
          value={summary?.closed_30d ?? 0}
          sub={summary?.closure_rate_30d != null ? `${summary.closure_rate_30d}% closure rate` : 'no opens yet'}
          accent="var(--ok)"
        />
        <KPICard
          title="MTTD"
          value={fmtMinutes(summary?.mttd_minutes)}
          sub={sample(summary?.mttd_sample, 'need occurred_at set')}
          accent="var(--accent)"
        />
        <KPICard
          title="MTTR"
          value={fmtMinutes(summary?.mttr_minutes)}
          sub={sample(summary?.mttr_sample, 'no closed incidents')}
          accent="var(--accent)"
        />
        <KPICard
          title="MTTC"
          value={fmtMinutes(summary?.mttc_minutes)}
          sub={sample(summary?.mttc_sample, 'need CER phase reached')}
          accent="var(--accent)"
        />
      </div>

      {/* Distribution row — phase / severity / type, derived from open incidents */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(280px,1fr))', gap: 'var(--space-3)', marginBottom: 'var(--space-4)' }}>
        <DistributionCard
          title="Active Phase"
          subtitle="NIST 800-61 R3"
          items={byPhase}
          orderedKeys={['preparation', 'detection_and_analysis', 'containment_eradication_recovery', 'post_incident']}
          labelOf={(k) => labelOf('phase', k)}
          colorOf={() => 'var(--accent)'}
        />
        <DistributionCard
          title="Active Severity"
          items={summary?.open_by_sev || {}}
          orderedKeys={SEV_ORDER}
          labelOf={(k) => k.charAt(0).toUpperCase() + k.slice(1)}
          colorOf={(k) => SEV_TOKEN[k]}
        />
        <DistributionCard
          title="Incident Type"
          subtitle="open incidents"
          items={byType}
          orderedKeys={Object.keys(byType).sort((a, b) => byType[b] - byType[a]).slice(0, 6)}
          labelOf={(k) => byValue.incident_type?.[k]?.label ?? k}
          colorOf={() => 'var(--med)'}
        />
      </div>

      {/* Trend chart — full-width opened-vs-closed mini bar chart */}
      <TrendChart trend={trend} style={{ marginBottom: 'var(--space-4)' }} />

      {/* Two-column: incidents table + activity feed */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: 'var(--space-4)', alignItems: 'start' }}>

        {/* Open incidents table */}
        <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--space-3) var(--space-4)' }}>
            <h2 className="panel-h" style={{ margin: 0 }}>Open Incidents</h2>
            <Link to="/incidents" style={{ fontSize: 12, color: 'var(--accent)' }}>View all →</Link>
          </div>
          {!incidents?.length ? (
            <div className="panel-empty" style={{ padding: 'var(--space-4)' }}>No open incidents</div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ background: 'var(--surface-2)' }}>
                    <th style={{ ...TH, paddingLeft: 16 }}>#</th>
                    <th style={TH}>Title</th>
                    <th style={TH}>Severity</th>
                    <th style={TH}>Phase</th>
                    <th style={TH}>Legal</th>
                    <th style={TH}>Assignee</th>
                    <th style={{ ...TH, textAlign: 'right', paddingRight: 16 }}>Age</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.map(inc => <IncidentRow key={inc.id} inc={inc} legal={legalByIncident[inc.id]} />)}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Activity feed */}
        <div className="panel">
          <h2 className="panel-h">Recent Activity</h2>
          <div style={{ fontSize: 11, color: 'var(--dim)', marginBottom: 'var(--space-2)' }}>Last 14 days</div>
          {!activity?.length ? (
            <div style={{ fontSize: 12, color: 'var(--muted)', padding: 'var(--space-3) 0' }}>
              No activity yet
            </div>
          ) : (
            <div style={{ maxHeight: 560, overflowY: 'auto', marginRight: -4, paddingRight: 4 }}>
              {activity.map((item, i) => {
                const cfg = EVENT_CONFIG[item.event_type] || { label: item.event_type, dot: 'var(--muted)' }
                return (
                  <div
                    key={i}
                    style={{
                      display: 'grid',
                      gridTemplateColumns: '8px 1fr',
                      gap: 8,
                      padding: '8px 0',
                      borderBottom: i < activity.length - 1 ? '1px solid var(--border)' : 'none',
                    }}
                  >
                    <div style={{
                      width: 7, height: 7, borderRadius: '50%',
                      background: cfg.dot, marginTop: 5, flexShrink: 0,
                    }} />
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 4 }}>
                        <Link
                          to={`/incidents/${item.incident_id}/details`}
                          style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)', textDecoration: 'none', lineHeight: 1.3 }}
                        >
                          {item.incident_title}
                        </Link>
                        <span style={{ fontSize: 10, color: 'var(--dim)', flexShrink: 0, paddingTop: 2 }}>
                          {relative(item.ts)}
                        </span>
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2, lineHeight: 1.4 }}>
                        <span style={{ color: cfg.dot, fontWeight: 600 }}>{cfg.label}</span>
                        {item.label && item.label !== item.incident_title && (
                          <span style={{ marginLeft: 4 }}>— {item.label}</span>
                        )}
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

      </div>

      {/* Bottom row — Analyst Workload + Top Tactics + Top Tags */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 'var(--space-4)', marginTop: 'var(--space-4)' }}>
        <WorkloadCard items={workload} />
        <TopTacticsCard items={tactics} />
        <TopTagsCard items={topTags} />
      </div>

      <IncidentCreateModal
        open={showCreate}
        onClose={() => setShowCreate(false)}
        onCreated={onCreatedIncident}
      />
    </div>
  )
}

// ─── Context strip — on-call, stale, overdue legal ───────────────────────────

function ContextStrip({ oncall, staleCount, overdueTotal }) {
  const items = []

  // On-call display — initials avatar + name. Stable hue from username so the
  // same person always gets the same colour.
  if (oncall) {
    const name = oncall.full_name || oncall.username || '—'
    const initial = (name || '?')[0].toUpperCase()
    const hue = (oncall.username || '').split('').reduce((a, c) => a + c.charCodeAt(0), 0) % 360
    items.push(
      <div key="oncall" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <div style={{
          width: 22, height: 22, borderRadius: '50%',
          background: `hsl(${hue}, 55%, 45%)`,
          color: '#fff', fontWeight: 700, fontSize: 11,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>{initial}</div>
        <div style={{ fontSize: 12 }}>
          <span style={{ color: 'var(--dim)' }}>On-call: </span>
          <span style={{ color: 'var(--text)', fontWeight: 600 }}>{name}</span>
        </div>
      </div>
    )
  } else {
    items.push(
      <div key="oncall" style={{ fontSize: 12, color: 'var(--dim)' }}>
        On-call: <span style={{ color: 'var(--muted)' }}>nobody scheduled</span>
        {' · '}
        <Link to="/on-call" style={{ color: 'var(--accent)' }}>set rota →</Link>
      </div>
    )
  }

  const stat = (label, value, danger) => (
    <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, fontSize: 12 }}>
      <span style={{ color: 'var(--dim)' }}>{label}:</span>
      <span style={{
        color: danger ? 'var(--crit)' : 'var(--text)',
        fontWeight: 700,
        fontFamily: 'var(--font-mono)',
      }}>{value}</span>
    </div>
  )

  items.push(<div key="stale-sep" style={{ color: 'var(--border)' }}>·</div>)
  items.push(<div key="stale">{stat(`Stale (>${STALE_DAYS}d)`, staleCount, staleCount > 0)}</div>)
  items.push(<div key="leg-sep"   style={{ color: 'var(--border)' }}>·</div>)
  items.push(<div key="legal">{stat('Legal overdue', overdueTotal, overdueTotal > 0)}</div>)

  return (
    <div style={{
      display: 'flex',
      flexWrap: 'wrap',
      alignItems: 'center',
      gap: 'var(--space-3)',
      padding: '8px 14px',
      background: 'var(--surface-2)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      marginBottom: 'var(--space-3)',
    }}>
      {items}
    </div>
  )
}

// ─── Distribution card — stacked bar + per-bucket count list ─────────────────

function DistributionCard({ title, subtitle, items, orderedKeys, labelOf, colorOf }) {
  const total = orderedKeys.reduce((s, k) => s + (items[k] || 0), 0)
  return (
    <div className="panel" style={{ padding: 'var(--space-3) var(--space-4)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 6 }}>
        <h2 className="panel-h" style={{ margin: 0 }}>{title}</h2>
        <span style={{ fontSize: 11, color: 'var(--dim)' }}>
          {subtitle ? subtitle + ' · ' : ''}{total} total
        </span>
      </div>

      {total === 0 ? (
        <div style={{ fontSize: 12, color: 'var(--dim)', padding: '8px 0' }}>No data</div>
      ) : (
        <>
          <div style={{ display: 'flex', height: 8, borderRadius: 4, overflow: 'hidden', gap: 1, marginBottom: 10 }}>
            {orderedKeys.map(k => {
              const n = items[k] || 0
              if (!n) return null
              return <div key={k} style={{ flex: n, background: colorOf(k), minWidth: 3 }} title={`${labelOf(k)}: ${n}`} />
            })}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            {orderedKeys.map(k => {
              const n = items[k] || 0
              const pct = total > 0 ? Math.round((n / total) * 100) : 0
              const color = n ? colorOf(k) : 'var(--dim)'
              return (
                <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: color, flexShrink: 0 }} />
                  <span style={{ flex: 1, color: n ? 'var(--text)' : 'var(--dim)' }}>{labelOf(k)}</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--muted)', fontSize: 11 }}>
                    {n} · {pct}%
                  </span>
                </div>
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}

// ─── Trend chart — opened (crit) vs closed (ok) bar pairs per day ────────────
// CSS-only; we deliberately don't pull in chart libraries for one widget.

function TrendChart({ trend, style }) {
  const series = trend?.series || []
  const max = Math.max(1, ...series.map(d => Math.max(d.opened, d.closed)))

  if (!series.length) {
    return (
      <div className="panel" style={{ padding: 'var(--space-3) var(--space-4)', ...style }}>
        <h2 className="panel-h" style={{ margin: 0, marginBottom: 6 }}>Trend</h2>
        <div style={{ fontSize: 12, color: 'var(--dim)' }}>No data</div>
      </div>
    )
  }

  const totalOpened = series.reduce((s, d) => s + d.opened, 0)
  const totalClosed = series.reduce((s, d) => s + d.closed, 0)

  return (
    <div className="panel" style={{ padding: 'var(--space-3) var(--space-4)', ...style }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 8 }}>
        <h2 className="panel-h" style={{ margin: 0 }}>Trend — last {trend?.days || 30} days</h2>
        <div style={{ display: 'flex', gap: 'var(--space-3)', fontSize: 11, color: 'var(--muted)', fontFamily: 'var(--font-mono)' }}>
          <span><span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: 2, background: SEV_PALETTE.critical.text, marginRight: 4, verticalAlign: 'middle' }} /> Opened: {totalOpened}</span>
          <span><span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: 2, background: 'var(--ok)', marginRight: 4, verticalAlign: 'middle' }} /> Closed: {totalClosed}</span>
        </div>
      </div>

      {/* Bars — pair per day. Two thin stacked columns side-by-side per day. */}
      <div style={{
        display: 'flex', alignItems: 'flex-end', gap: 2,
        height: 80,
        padding: '4px 0',
        borderBottom: '1px solid var(--border)',
      }}>
        {series.map(d => {
          const oh = Math.max(d.opened ? 2 : 0, Math.round((d.opened / max) * 70))
          const ch = Math.max(d.closed ? 2 : 0, Math.round((d.closed / max) * 70))
          return (
            <div
              key={d.date}
              style={{ flex: 1, minWidth: 4, display: 'flex', alignItems: 'flex-end', justifyContent: 'center', gap: 1, height: '100%' }}
              title={`${d.date} — opened: ${d.opened}, closed: ${d.closed}`}
            >
              <div style={{ width: '45%', height: oh, background: SEV_PALETTE.critical.text, borderRadius: '1px 1px 0 0', opacity: d.opened ? 1 : 0.15 }} />
              <div style={{ width: '45%', height: ch, background: 'var(--ok)', borderRadius: '1px 1px 0 0', opacity: d.closed ? 1 : 0.15 }} />
            </div>
          )
        })}
      </div>

      {/* X-axis labels — show first / mid / last to avoid crowding */}
      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4, fontSize: 10, color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>
        <span>{series[0]?.date}</span>
        <span>{series[Math.floor(series.length / 2)]?.date}</span>
        <span>{series[series.length - 1]?.date}</span>
      </div>
    </div>
  )
}

// ─── Workload card — per-analyst active-incident bar ─────────────────────────

function WorkloadCard({ items }) {
  const max = Math.max(1, ...items.map(i => i.active_count))
  return (
    <div className="panel" style={{ padding: 'var(--space-3) var(--space-4)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 8 }}>
        <h2 className="panel-h" style={{ margin: 0 }}>Analyst Workload</h2>
        <span style={{ fontSize: 11, color: 'var(--dim)' }}>open incidents</span>
      </div>
      {items.length === 0 ? (
        <div style={{ fontSize: 12, color: 'var(--dim)' }}>Nobody assigned yet</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {items.map(it => {
            const w = `${Math.round((it.active_count / max) * 100)}%`
            // Same stable-hue avatar as the on-call card so the same analyst is
            // visually consistent across the page.
            const hue = (it.username || '').split('').reduce((a, c) => a + c.charCodeAt(0), 0) % 360
            return (
              <div key={it.user_id} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{
                  width: 20, height: 20, borderRadius: '50%',
                  background: `hsl(${hue}, 55%, 45%)`,
                  color: '#fff', fontWeight: 700, fontSize: 10,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0,
                }}>{(it.username || '?')[0].toUpperCase()}</div>
                <div style={{ flex: 1, fontSize: 12, color: 'var(--text)', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {it.username}
                </div>
                <div style={{ flex: 2, height: 8, background: 'var(--surface-2)', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ width: w, height: '100%', background: 'var(--accent)' }} />
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)', width: 24, textAlign: 'right' }}>
                  {it.active_count}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ─── Top MITRE tactics card ──────────────────────────────────────────────────

function TopTacticsCard({ items }) {
  const max = Math.max(1, ...items.map(i => i.count))
  return (
    <div className="panel" style={{ padding: 'var(--space-3) var(--space-4)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 8 }}>
        <h2 className="panel-h" style={{ margin: 0 }}>Top MITRE Tactics</h2>
        <span style={{ fontSize: 11, color: 'var(--dim)' }}>open incidents</span>
      </div>
      {items.length === 0 ? (
        <div style={{ fontSize: 12, color: 'var(--dim)' }}>No MITRE-tagged events yet</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {items.map(t => {
            const w = `${Math.round((t.count / max) * 100)}%`
            return (
              <div key={t.tactic_id} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)', width: 50, flexShrink: 0 }}>
                  {t.tactic_id}
                </span>
                <span style={{ flex: 1, color: 'var(--text)', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {t.tactic_name}
                </span>
                <div style={{ flex: 2, height: 8, background: 'var(--surface-2)', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ width: w, height: '100%', background: 'var(--high)' }} />
                </div>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)', width: 24, textAlign: 'right' }}>
                  {t.count}
                </span>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ─── Top tags card — usage rollup across open incidents ──────────────────────

function TopTagsCard({ items }) {
  const navigate = useNavigate()
  const max = Math.max(1, ...items.map(i => i.count))
  return (
    <div className="panel" style={{ padding: 'var(--space-3) var(--space-4)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 8 }}>
        <h2 className="panel-h" style={{ margin: 0 }}>Top Tags</h2>
        <span style={{ fontSize: 11, color: 'var(--dim)' }}>open incidents</span>
      </div>
      {items.length === 0 ? (
        <div style={{ fontSize: 12, color: 'var(--dim)' }}>No tagged open incidents yet</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {items.map(t => {
            const w = `${Math.round((t.count / max) * 100)}%`
            return (
              <div key={t.tag} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
                <TagChip
                  tag={t.tag}
                  dense
                  onClick={() => navigate(`/incidents?tag=${encodeURIComponent(t.tag)}`)}
                  title={`Filter incidents by ${t.tag}`}
                />
                <div style={{ flex: 1, height: 8, background: 'var(--surface-2)', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ width: w, height: '100%', background: 'var(--accent)' }} />
                </div>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)', width: 24, textAlign: 'right' }}>
                  {t.count}
                </span>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
