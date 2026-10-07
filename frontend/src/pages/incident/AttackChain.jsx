import { useEffect, useState } from 'react'
import { api } from '../../api/client.js'
import { formatLocalShort } from '../../lib/datetime.js'
import { MITRE_TACTICS, tacticColor } from '../../lib/mitre.js'

// Attack chain: MITRE-tagged timeline events over time, one swimlane per observed tactic in
// ATT&CK order. K4 (R40): folded into the incident ATT&CK view (Mitre.jsx, under Coverage);
// it used to be a duplicate Post-Incident tab, whose address now redirects there (App.jsx).
export default function AttackChain({ inc }) {
  const [events,  setEvents]  = useState([])
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)

  useEffect(() => {
    // Fetch all timeline events in one shot (limit=500 covers any realistic incident)
    const fetchAll = async () => {
      const results = []
      let cursor = null
      do {
        const page = await api.listTimelineEvents(inc.id, { limit: 500, ...(cursor ? { cursor } : {}) })
        results.push(...page.items)
        cursor = page.next_cursor
      } while (cursor)
      return results
    }
    fetchAll()
      .then(setEvents)
      .catch(e => setError(e.message || 'Failed to load timeline'))
      .finally(() => setLoading(false))
  }, [inc.id])

  if (loading) return <div className="pi-loading">Building attack chain…</div>
  if (error)   return <div className="pi-error">{error}</div>

  // Filter to MITRE-tagged events; sort chronologically
  const tagged = events
    .filter(e => e.mitre_tactic_id)
    .sort((a, b) => new Date(a.event_time) - new Date(b.event_time))

  if (tagged.length === 0) return (
    <div className="pi-empty" style={{ padding: 'var(--space-6)' }}>
      <div className="panel-empty-mark" aria-hidden="true">◌</div>
      <div>No MITRE-tagged timeline events yet.</div>
      <div style={{ color: 'var(--dim)', fontSize: 12 }}>
        Tag events with a tactic and technique in the Timeline tab to build the attack chain.
      </div>
    </div>
  )

  // Build swimlanes — one per observed tactic, canonical ATT&CK order
  const observedIds = new Set(tagged.map(e => e.mitre_tactic_id))
  const lanes = MITRE_TACTICS.filter(t => observedIds.has(t.id))
  for (const id of observedIds) {
    if (!lanes.some(l => l.id === id)) {
      const sample = tagged.find(e => e.mitre_tactic_id === id)
      lanes.push({ id, name: sample?.mitre_tactic_name || id })
    }
  }
  const laneIdx = Object.fromEntries(lanes.map((l, i) => [l.id, i]))

  // Time range + horizontal mapping (with 4% lateral padding)
  const timeNums = tagged.map(e => new Date(e.event_time).getTime())
  const t0   = Math.min(...timeNums)
  const t1   = Math.max(...timeNums)
  const span = Math.max(1, t1 - t0)
  const xPct = (ts) => 4 + ((new Date(ts).getTime() - t0) / span) * 92

  const LANE_H  = 56
  const LABEL_W = 200
  const totalH  = lanes.length * LANE_H
  const laneY   = (i) => i * LANE_H + LANE_H / 2

  // Axis ticks
  const tickCount = span > 1 ? 5 : 1
  const ticks = []
  for (let i = 0; i < tickCount; i++) {
    const frac = tickCount > 1 ? i / (tickCount - 1) : 0
    ticks.push({ pct: 4 + frac * 92, iso: new Date(t0 + span * frac).toISOString() })
  }

  return (
    <div>
      {/* Swimlane chain */}
      <div style={{
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        background: 'var(--surface)',
        overflow: 'hidden',
        marginBottom: 'var(--space-5)',
      }}>
        <div style={{ display: 'flex' }}>
          {/* Lane labels */}
          <div style={{
            width: LABEL_W,
            flexShrink: 0,
            borderRight: '1px solid var(--border)',
            background: 'var(--surface-2)',
          }}>
            {lanes.map((l, i) => {
              const color = tacticColor(l.id)
              const count = tagged.filter(e => e.mitre_tactic_id === l.id).length
              return (
                <div key={l.id} style={{
                  height: LANE_H,
                  padding: '0 var(--space-3)',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'center',
                  borderBottom: i < lanes.length - 1 ? '1px solid var(--border)' : 'none',
                  borderLeft: `3px solid ${color}`,
                }}>
                  <div style={{
                    fontSize: 10, fontFamily: 'var(--font-mono)',
                    fontWeight: 700, color, letterSpacing: '0.05em',
                  }}>{l.id}</div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)', lineHeight: 1.2 }}>
                    {l.name}
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--muted)', fontFamily: 'var(--font-mono)' }}>
                    {count} event{count !== 1 ? 's' : ''}
                  </div>
                </div>
              )
            })}
          </div>

          {/* Plot area */}
          <div style={{ flex: 1, position: 'relative', minWidth: 0 }}>
            {/* Lane bands */}
            {lanes.map((l, i) => (
              <div key={l.id} style={{
                height: LANE_H,
                borderBottom: i < lanes.length - 1 ? '1px solid var(--border)' : 'none',
                background: i % 2 === 1 ? 'var(--surface-2)' : 'transparent',
              }} />
            ))}

            {/* Connectors */}
            <svg
              width="100%"
              height={totalH}
              style={{ position: 'absolute', inset: 0, pointerEvents: 'none' }}
            >
              {tagged.slice(0, -1).map((e, i) => {
                const next = tagged[i + 1]
                return (
                  <line key={i}
                    x1={`${xPct(e.event_time)}%`}
                    y1={laneY(laneIdx[e.mitre_tactic_id])}
                    x2={`${xPct(next.event_time)}%`}
                    y2={laneY(laneIdx[next.mitre_tactic_id])}
                    strokeWidth="1.5"
                    strokeDasharray="4 4"
                    style={{ stroke: 'var(--border-strong)' }}
                  />
                )
              })}
            </svg>

            {/* Event dots */}
            <div style={{ position: 'absolute', inset: 0 }}>
              {tagged.map(ev => {
                const color = tacticColor(ev.mitre_tactic_id)
                const techLabel = ev.mitre_technique_id || ev.mitre_tactic_id
                const tip = `${formatLocalShort(ev.event_time)}\n${techLabel}\n${ev.description || ''}`
                return (
                  <div key={ev.id}
                    title={tip}
                    style={{
                      position: 'absolute',
                      left: `${xPct(ev.event_time)}%`,
                      top:  `${laneY(laneIdx[ev.mitre_tactic_id])}px`,
                      width: 12, height: 12,
                      transform: 'translate(-50%, -50%)',
                      background: color,
                      border: '2px solid var(--surface)',
                      borderRadius: '50%',
                      boxShadow: '0 0 0 1px var(--border-strong)',
                      cursor: 'help',
                    }}
                  />
                )
              })}
            </div>
          </div>
        </div>

        {/* Time axis */}
        <div style={{
          display: 'flex',
          borderTop: '1px solid var(--border)',
          background: 'var(--surface-2)',
        }}>
          <div style={{ width: LABEL_W, flexShrink: 0, borderRight: '1px solid var(--border)' }} />
          <div style={{ flex: 1, position: 'relative', height: 24 }}>
            {ticks.map((tk, i) => (
              <div key={i} style={{
                position: 'absolute',
                left: `${tk.pct}%`,
                top: 0, height: 24,
                transform: 'translateX(-50%)',
                fontSize: 10,
                fontFamily: 'var(--font-mono)',
                color: 'var(--muted)',
                display: 'flex',
                alignItems: 'center',
                whiteSpace: 'nowrap',
              }}>
                {formatLocalShort(tk.iso)}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Chronological event list */}
      <div style={{ borderTop: '1px solid var(--border)', paddingTop: 'var(--space-4)' }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--muted)', marginBottom: 'var(--space-3)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          Chronological sequence · {tagged.length} event{tagged.length !== 1 ? 's' : ''}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-1)' }}>
          {tagged.map(ev => {
            const color = tacticColor(ev.mitre_tactic_id)
            return (
              <div key={ev.id} style={{
                display: 'flex',
                alignItems: 'baseline',
                gap: 'var(--space-3)',
                padding: 'var(--space-2) var(--space-3)',
                background: 'var(--surface)',
                border: '1px solid var(--border)',
                borderLeft: `2px solid ${color}`,
                borderRadius: 'var(--radius-sm)',
                fontSize: 12,
              }}>
                <span style={{
                  fontFamily: 'var(--font-mono)', fontSize: 11,
                  color: 'var(--muted)', whiteSpace: 'nowrap', flexShrink: 0,
                }}>
                  {formatLocalShort(ev.event_time)}
                </span>
                <span style={{
                  fontFamily: 'var(--font-mono)', fontSize: 10,
                  color, whiteSpace: 'nowrap', flexShrink: 0,
                }}>
                  {ev.mitre_technique_id || ev.mitre_tactic_id}
                </span>
                <span style={{ color: 'var(--text)', flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {ev.event_type && <span style={{ color: 'var(--accent)', marginRight: 6 }}>{ev.event_type}</span>}
                  {ev.description}
                </span>
                {ev.hostname && (
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--dim)', flexShrink: 0 }}>
                    {ev.hostname}
                  </span>
                )}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
