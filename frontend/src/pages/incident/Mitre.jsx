import { useCallback, useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../api/client.js'
import { MITRE_TACTICS, tacticColor } from '../../lib/mitre.js'

// Build a lookup from the canonical tactic list so we can render all 12 rows
// even when some have no observed events (gap rows).
const TACTIC_ORDER = MITRE_TACTICS.map(t => t.id)
const TACTIC_NAME  = Object.fromEntries(MITRE_TACTICS.map(t => [t.id, t.name]))

export default function Mitre() {
  const { inc } = useOutletContext()

  const [data,    setData]    = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)

  const load = useCallback(async () => {
    setError(null)
    try {
      const r = await api.getMitreCoverage(inc.id)
      setData(r)
    } catch (e) {
      setError(e.message || 'Could not load MITRE coverage')
    } finally {
      setLoading(false)
    }
  }, [inc.id])

  useEffect(() => { load() }, [load])

  if (loading) return <div className="panel"><div className="panel-empty">Loading…</div></div>

  if (error) return (
    <div className="panel">
      <div className="alert error" role="alert">
        <span className="alert-icon">!</span><span>{error}</span>
      </div>
    </div>
  )

  // Index observed tactics by ID for fast lookup
  const observed = Object.fromEntries((data?.tactics || []).map(t => [t.tactic_id, t]))
  const { tactics_observed, techniques_observed } = data?.summary || {}

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">MITRE ATT&amp;CK Coverage</h2>
      </div>

      {/* Summary bar */}
      <div style={{
        display: 'flex',
        gap: 'var(--space-4)',
        marginBottom: 'var(--space-4)',
        padding: 'var(--space-3)',
        background: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
      }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: 24, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text)' }}>
            {tactics_observed ?? 0}
          </div>
          <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>of 12 tactics</div>
        </div>
        <div style={{ width: 1, background: 'var(--border)' }} />
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: 24, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text)' }}>
            {techniques_observed ?? 0}
          </div>
          <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>techniques observed</div>
        </div>
        <div style={{ flex: 1 }} />
        <div style={{ fontSize: 11, color: 'var(--dim)', alignSelf: 'center' }}>
          Derived from tagged timeline events
        </div>
      </div>

      {tactics_observed === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">◌</div>
          <div>No MITRE-tagged timeline events yet.</div>
          <div style={{ color: 'var(--dim)', fontSize: 12 }}>
            Tag events with a tactic and technique in the Timeline tab to build coverage.
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
          {TACTIC_ORDER.map(tacticId => {
            const obs  = observed[tacticId]
            const color = tacticColor(tacticId)

            if (!obs) {
              // Gap row — tactic not observed in this incident
              return (
                <div
                  key={tacticId}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 'var(--space-3)',
                    padding: 'var(--space-2) var(--space-3)',
                    background: 'var(--bg)',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius)',
                    opacity: 0.45,
                  }}
                >
                  <span style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 11,
                    color: 'var(--muted)',
                    minWidth: 56,
                  }}>{tacticId}</span>
                  <span style={{ fontSize: 12, color: 'var(--muted)' }}>{TACTIC_NAME[tacticId]}</span>
                  <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--dim)' }}>not observed</span>
                </div>
              )
            }

            // Active row — tactic observed
            return (
              <div
                key={tacticId}
                style={{
                  background: 'var(--surface)',
                  border: `1px solid var(--border)`,
                  borderLeft: `3px solid ${color}`,
                  borderRadius: 'var(--radius)',
                  padding: 'var(--space-3)',
                }}
              >
                {/* Tactic header */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 8 }}>
                  <span style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 11,
                    fontWeight: 700,
                    color,
                    minWidth: 56,
                  }}>{tacticId}</span>
                  <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)' }}>
                    {obs.tactic_name || TACTIC_NAME[tacticId]}
                  </span>
                  <span style={{
                    marginLeft: 'auto',
                    fontSize: 11,
                    color: 'var(--muted)',
                    fontFamily: 'var(--font-mono)',
                  }}>
                    {obs.event_count} event{obs.event_count !== 1 ? 's' : ''}
                  </span>
                </div>

                {/* Technique pills */}
                {obs.techniques.length > 0 ? (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {obs.techniques.map(tech => (
                      <span
                        key={tech.technique_id}
                        className="pill"
                        style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}
                        title={`${tech.event_count} event${tech.event_count !== 1 ? 's' : ''}`}
                      >
                        {tech.technique_id} · {tech.technique_name}
                        {tech.event_count > 1 && (
                          <span style={{ marginLeft: 4, opacity: 0.65 }}>×{tech.event_count}</span>
                        )}
                      </span>
                    ))}
                  </div>
                ) : (
                  <div style={{ fontSize: 11, color: 'var(--dim)' }}>
                    Tactic tagged — no technique specified
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </section>
  )
}
