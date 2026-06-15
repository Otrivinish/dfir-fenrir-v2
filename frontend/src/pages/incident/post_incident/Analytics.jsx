import { useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../../api/client.js'

function fmtMins(mins) {
  if (mins === null || mins === undefined) return '—'
  if (mins < 0) return '—'
  if (mins < 60) return `${mins}m`
  if (mins < 1440) {
    const h = Math.floor(mins / 60)
    const m = mins % 60
    return m ? `${h}h ${m}m` : `${h}h`
  }
  const d = Math.floor(mins / 1440)
  const rem = Math.floor((mins % 1440) / 60)
  return rem ? `${d}d ${rem}h` : `${d}d`
}

function StatCard({ label, value, sub, color }) {
  return (
    <div className="an-stat">
      <span className="an-stat-val" style={color ? { color } : undefined}>{value}</span>
      <span className="an-stat-lbl">{label}</span>
      {sub && <span className="an-stat-sub">{sub}</span>}
    </div>
  )
}

function BarChart({ items }) {
  const max = Math.max(1, ...items.map(i => i.value))
  return (
    <div className="an-bars">
      {items.map(item => (
        <div key={item.label} className="an-bar-row">
          <span className="an-bar-label">{item.label}</span>
          <div className="an-bar-track">
            <div
              className="an-bar-fill"
              style={{
                width: `${Math.round((item.value / max) * 100)}%`,
                background: item.color || 'var(--accent)',
              }}
            />
          </div>
          <span className="an-bar-count">{item.value}</span>
        </div>
      ))}
    </div>
  )
}

function Section({ title, children }) {
  return (
    <div className="an-section">
      <div className="an-section-title">{title}</div>
      {children}
    </div>
  )
}

const TASK_COLORS   = { done: 'var(--ok)', in_progress: 'var(--accent)', open: 'var(--muted)', skipped: 'var(--dim)' }
const RESP_COLORS   = { done: 'var(--ok)', in_progress: 'var(--accent)', open: 'var(--muted)', deferred: 'var(--dim)' }
const RESP_CATS     = ['containment', 'eradication', 'recovery']
const RESP_STATUSES = ['done', 'in_progress', 'open', 'deferred']

export default function Analytics() {
  const { inc } = useOutletContext()
  const [data,    setData]    = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)

  useEffect(() => {
    api.getIncidentAnalytics(inc.id)
      .then(setData)
      .catch(e => setError(e.message || 'Failed to load analytics'))
      .finally(() => setLoading(false))
  }, [inc.id])

  if (loading) return <div className="pi-loading">Computing analytics…</div>
  if (error)   return <div className="pi-error">{error}</div>
  if (!data)   return null

  const { timing, iocs, entities, timeline, playbook, respond, evidence } = data

  const iocBars = Object.entries(iocs.by_type)
    .sort(([, a], [, b]) => b - a)
    .map(([type, n]) => ({ label: type, value: n }))

  const entityBars = Object.entries(entities.by_type)
    .sort(([, a], [, b]) => b - a)
    .map(([type, n]) => ({ label: type, value: n }))

  const phaseBars = Object.entries(timeline.by_phase)
    .sort(([, a], [, b]) => b - a)
    .map(([phase, n]) => ({ label: phase.replace(/_/g, ' '), value: n }))

  const taskBars = ['done', 'in_progress', 'open', 'skipped']
    .map(s => ({ label: s.replace('_', ' '), value: playbook.by_status[s] || 0, color: TASK_COLORS[s] }))
    .filter(i => i.value > 0)

  const isEmpty = iocs.total === 0 && entities.total === 0 && timeline.total === 0
    && playbook.total === 0 && respond.total === 0 && evidence.total === 0

  return (
    <div className="an-root">

      {/* ── Top stat cards ──────────────────────────────────────────────── */}
      <div className="an-stats-row">
        <StatCard
          label="Time to Detect"
          value={fmtMins(timing.ttd_mins)}
          sub="occurred → created"
        />
        <StatCard
          label="Time to Contain"
          value={fmtMins(timing.ttc_mins)}
          sub="created → contained"
        />
        <StatCard
          label="Time to Resolve"
          value={fmtMins(timing.ttr_mins)}
          sub="created → closed"
        />
        <StatCard label="IOCs" value={iocs.total} />
        <StatCard
          label="Entities"
          value={entities.total}
          sub={entities.compromised ? `${entities.compromised} compromised` : undefined}
          color={entities.compromised ? 'var(--crit)' : undefined}
        />
        <StatCard
          label="Playbook"
          value={`${playbook.completion_pct}%`}
          sub={playbook.total
            ? `${playbook.by_status?.done || 0} / ${playbook.total - (playbook.by_status?.skipped || 0)} done`
            : 'no tasks'}
          color={playbook.completion_pct === 100 ? 'var(--ok)' : undefined}
        />
      </div>

      {/* ── IOCs by type ────────────────────────────────────────────────── */}
      {iocBars.length > 0 && (
        <Section title={`IOCs by type · ${iocs.total} total`}>
          <BarChart items={iocBars} />
        </Section>
      )}

      {/* ── Entities by type ────────────────────────────────────────────── */}
      {entityBars.length > 0 && (
        <Section title={`Entities by type · ${entities.total} total`}>
          <BarChart items={entityBars} />
        </Section>
      )}

      {/* ── Timeline by IR phase ─────────────────────────────────────────── */}
      {phaseBars.length > 0 && (
        <Section title={`Timeline · ${timeline.total} events · ${timeline.mitre_mapped} MITRE-mapped`}>
          <BarChart items={phaseBars} />
        </Section>
      )}

      {/* ── Playbook tasks ───────────────────────────────────────────────── */}
      {playbook.total > 0 && (
        <Section title={`Playbook · ${playbook.total} tasks · ${playbook.completion_pct}% complete`}>
          <BarChart items={taskBars} />
        </Section>
      )}

      {/* ── Respond actions ──────────────────────────────────────────────── */}
      {respond.total > 0 && (
        <Section title={`Respond actions · ${respond.total} total`}>
          <div className="an-respond-grid">
            {RESP_CATS.map(cat => {
              const catData = respond.by_category[cat] || {}
              const catTotal = Object.values(catData).reduce((a, b) => a + b, 0)
              if (!catTotal) return null
              return (
                <div key={cat} className="an-respond-cat">
                  <div className="an-respond-cat-head">
                    {cat}
                    <span className="an-respond-count">{catTotal}</span>
                  </div>
                  {RESP_STATUSES.map(s => {
                    const n = catData[s] || 0
                    if (!n) return null
                    return (
                      <div key={s} className="an-respond-row">
                        <span className="an-respond-dot" style={{ background: RESP_COLORS[s] }} />
                        <span className="an-respond-status">{s.replace('_', ' ')}</span>
                        <span className="an-respond-n">{n}</span>
                      </div>
                    )
                  })}
                </div>
              )
            })}
          </div>
        </Section>
      )}

      {/* ── Evidence ─────────────────────────────────────────────────────── */}
      {evidence.total > 0 && (
        <Section title={`Evidence · ${evidence.total} items`}>
          <div className="an-evidence-row">
            {Object.entries(evidence.by_kind).map(([kind, n]) => (
              <div key={kind} className="an-evidence-kind">
                <span className="an-evidence-n">{n}</span>
                <span className="an-evidence-lbl">{kind.replace('_', ' ')}</span>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* ── Empty state ──────────────────────────────────────────────────── */}
      {isEmpty && (
        <div className="pi-empty" style={{ padding: 'var(--space-6)' }}>
          <div className="panel-empty-mark" aria-hidden="true">◌</div>
          <div>No data yet.</div>
          <div style={{ color: 'var(--dim)', fontSize: 12 }}>
            Add IOCs, entities, timeline events, and playbook tasks to populate analytics.
          </div>
        </div>
      )}
    </div>
  )
}
