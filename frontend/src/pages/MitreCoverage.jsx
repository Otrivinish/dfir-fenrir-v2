import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.js'
import { MITRE_TACTICS, MITRE_TECHNIQUES, tacticColor } from '../lib/mitre.js'

// ─── Heat styling by incident count ──────────────────────────────────────────

function heatStyle(count) {
  if (count === 0) return {
    background: 'transparent',
    border: '1px solid var(--border)',
    color: 'var(--dim)',
    opacity: 0.55,
    cursor: 'default',
  }
  if (count === 1) return {
    background: 'var(--accent-soft)',
    border: '1px solid var(--accent)',
    color: 'var(--accent)',
    cursor: 'pointer',
  }
  if (count <= 3) return {
    background: 'color-mix(in srgb, var(--med) 18%, var(--surface))',
    border: '1px solid var(--med)',
    color: 'var(--med)',
    cursor: 'pointer',
  }
  return {
    background: 'color-mix(in srgb, var(--high) 18%, var(--surface))',
    border: '1px solid var(--high)',
    color: 'var(--high)',
    cursor: 'pointer',
  }
}

// ─── Severity pill (reused from incident list) ────────────────────────────────

const SEV_COLOR = {
  critical: 'var(--crit)',
  high:     'var(--high)',
  medium:   'var(--med)',
  low:      'var(--low)',
}

function SevPill({ severity }) {
  return (
    <span style={{
      fontSize: 10,
      fontFamily: 'var(--font-mono)',
      padding: '1px 5px',
      borderRadius: 'var(--radius-sm)',
      border: `1px solid ${SEV_COLOR[severity] || 'var(--border)'}`,
      color: SEV_COLOR[severity] || 'var(--muted)',
    }}>
      {severity || '—'}
    </span>
  )
}

// ─── Technique detail modal ───────────────────────────────────────────────────

function TechModal({ tech, onClose }) {
  if (!tech) return null
  return (
    <div
      className="modal-backdrop"
      onMouseDown={e => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="modal" style={{ maxWidth: 520, width: '100%' }} role="dialog" aria-modal="true">
        <div className="modal-header">
          <h2 className="modal-title" style={{ fontFamily: 'var(--font-mono)', fontSize: 14 }}>
            {tech.technique_id} · {tech.technique_name || tech.tactic_id}
          </h2>
          <button className="modal-close" onClick={onClose} aria-label="Close">✕</button>
        </div>
        <div className="modal-body">
          <div style={{ marginBottom: 'var(--space-3)', display: 'flex', gap: 'var(--space-3)', alignItems: 'center' }}>
            <span style={{ fontSize: 12, color: 'var(--muted)' }}>Tactic:</span>
            <span style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 11,
              color: tacticColor(tech.tactic_id),
              fontWeight: 700,
            }}>{tech.tactic_id}</span>
            <span style={{
              marginLeft: 'auto',
              fontFamily: 'var(--font-mono)',
              fontSize: 22,
              fontWeight: 700,
              color: 'var(--text)',
            }}>{tech.incidents.length}</span>
            <span style={{ fontSize: 11, color: 'var(--muted)' }}>
              incident{tech.incidents.length !== 1 ? 's' : ''}
            </span>
          </div>

          {tech.incidents.length === 0 ? (
            <p style={{ fontSize: 12, color: 'var(--muted)', textAlign: 'center', padding: 'var(--space-4) 0' }}>
              No incidents recorded for this technique.
            </p>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  <th style={{ textAlign: 'left', padding: '4px 8px', color: 'var(--muted)', fontWeight: 500 }}>Ref</th>
                  <th style={{ textAlign: 'left', padding: '4px 8px', color: 'var(--muted)', fontWeight: 500 }}>Incident</th>
                  <th style={{ textAlign: 'left', padding: '4px 8px', color: 'var(--muted)', fontWeight: 500 }}>Sev</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {tech.incidents.map(inc => (
                  <tr
                    key={inc.id}
                    style={{ borderBottom: '1px solid var(--border)' }}
                  >
                    <td style={{ padding: '6px 8px', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)' }}>
                      {inc.ref || '—'}
                    </td>
                    <td style={{ padding: '6px 8px', color: 'var(--text)' }}>{inc.title}</td>
                    <td style={{ padding: '6px 8px' }}><SevPill severity={inc.severity} /></td>
                    <td style={{ padding: '6px 8px', textAlign: 'right' }}>
                      <Link
                        to={`/incidents/${inc.id}/timeline`}
                        style={{ fontSize: 11, color: 'var(--accent)' }}
                        onClick={onClose}
                      >
                        Timeline →
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function MitreCoverage() {
  const [data,      setData]      = useState(null)
  const [loading,   setLoading]   = useState(true)
  const [error,     setError]     = useState(null)
  const [selected,  setSelected]  = useState(null)  // TechniqueHit for detail modal
  const [showAll,   setShowAll]   = useState(true)   // false = observed-only

  const load = useCallback(async () => {
    setError(null)
    try {
      setData(await api.getGlobalMitreCoverage())
    } catch (e) {
      setError(e.message || 'Could not load MITRE coverage')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  // Index techniques by (tactic_id, technique_id) for O(1) lookup.
  const techIndex = {}
  if (data) {
    for (const t of data.techniques) {
      const key = `${t.tactic_id}::${t.technique_id}`
      techIndex[key] = t
    }
  }

  function getTech(tacticId, techniqueId) {
    return techIndex[`${tacticId}::${techniqueId}`] || null
  }

  function handleCellClick(tacticId, technique) {
    const hit = getTech(tacticId, technique.id)
    if (!hit || hit.incident_count === 0) return
    setSelected(hit)
  }

  const { tactics_observed, techniques_observed, incidents_with_mitre } = data?.summary || {}

  if (loading) return (
    <main className="page-main">
      <div className="panel"><div className="panel-empty">Loading MITRE matrix…</div></div>
    </main>
  )

  if (error) return (
    <main className="page-main">
      <div className="panel">
        <div className="alert error" role="alert">
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      </div>
    </main>
  )

  return (
    <main className="page-main" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
        <h1 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text)', margin: 0 }}>
          MITRE ATT&amp;CK Coverage
        </h1>
        <span style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>Enterprise Matrix</span>
      </div>

      {/* Summary bar */}
      <div style={{
        display: 'flex',
        gap: 'var(--space-5)',
        padding: 'var(--space-3) var(--space-4)',
        background: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        flexWrap: 'wrap',
      }}>
        {[
          { val: tactics_observed ?? 0,    label: 'of 12 tactics observed' },
          { val: techniques_observed ?? 0, label: 'techniques observed' },
          { val: incidents_with_mitre ?? 0, label: 'incidents with ATT&CK tags' },
        ].map(({ val, label }) => (
          <div key={label} style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-2)' }}>
            <span style={{ fontSize: 26, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text)' }}>
              {val}
            </span>
            <span style={{ fontSize: 11, color: 'var(--muted)' }}>{label}</span>
          </div>
        ))}
        <div style={{ flex: 1 }} />

        {/* Legend */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
          {[
            { style: heatStyle(0), label: 'No hits' },
            { style: heatStyle(1), label: '1 incident' },
            { style: heatStyle(2), label: '2–3' },
            { style: heatStyle(4), label: '4+' },
          ].map(({ style, label }) => (
            <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <div style={{
                width: 12,
                height: 12,
                borderRadius: 2,
                background: style.background,
                border: style.border,
              }} />
              <span style={{ fontSize: 10, color: 'var(--muted)' }}>{label}</span>
            </div>
          ))}
        </div>

        {/* Show all / observed-only toggle */}
        <button
          className="btn btn-ghost"
          style={{ fontSize: 11, padding: '2px 8px' }}
          onClick={() => setShowAll(v => !v)}
        >
          {showAll ? 'Observed only' : 'Show all techniques'}
        </button>
      </div>

      {/* Matrix */}
      <div style={{ overflowX: 'auto', paddingBottom: 'var(--space-3)' }}>
        <div style={{
          display: 'flex',
          gap: 'var(--space-2)',
          minWidth: 'max-content',
        }}>
          {MITRE_TACTICS.map(tactic => {
            const color = tacticColor(tactic.id)
            const techniques = MITRE_TECHNIQUES[tactic.id] || []

            // Optionally filter to only observed techniques within this tactic.
            const visibleTechs = showAll
              ? techniques
              : techniques.filter(t => {
                  const hit = getTech(tactic.id, t.id)
                  return hit && hit.incident_count > 0
                })

            if (!showAll && visibleTechs.length === 0) return null

            return (
              <div
                key={tactic.id}
                style={{
                  width: 148,
                  flex: '0 0 148px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 2,
                }}
              >
                {/* Tactic header */}
                <div style={{
                  padding: '4px 6px',
                  borderRadius: 'var(--radius-sm)',
                  background: 'var(--surface)',
                  borderTop: `3px solid ${color}`,
                  borderLeft: '1px solid var(--border)',
                  borderRight: '1px solid var(--border)',
                  borderBottom: '1px solid var(--border)',
                  marginBottom: 4,
                }}>
                  <div style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 9,
                    color,
                    fontWeight: 700,
                    letterSpacing: '0.03em',
                  }}>{tactic.id}</div>
                  <div style={{
                    fontSize: 11,
                    fontWeight: 600,
                    color: 'var(--text)',
                    lineHeight: 1.3,
                    marginTop: 2,
                  }}>{tactic.name}</div>
                  <div style={{ fontSize: 9, color: 'var(--dim)', marginTop: 2 }}>
                    {(() => {
                      const obs = techniques.filter(t => {
                        const h = getTech(tactic.id, t.id)
                        return h && h.incident_count > 0
                      }).length
                      return `${obs}/${techniques.length}`
                    })()}
                  </div>
                </div>

                {/* Technique cells */}
                {visibleTechs.map(tech => {
                  const hit = getTech(tactic.id, tech.id)
                  const count = hit?.incident_count || 0
                  const style = heatStyle(count)

                  return (
                    <div
                      key={tech.id}
                      style={{
                        padding: '3px 5px',
                        borderRadius: 2,
                        ...style,
                        transition: 'opacity 0.1s',
                      }}
                      onClick={() => handleCellClick(tactic.id, tech)}
                      title={count > 0
                        ? `${tech.id} · ${tech.name}\n${count} incident${count !== 1 ? 's' : ''}`
                        : `${tech.id} · ${tech.name}\nNot observed`
                      }
                    >
                      <div style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 9,
                        fontWeight: 700,
                        opacity: count === 0 ? 0.6 : 1,
                      }}>{tech.id}</div>
                      <div style={{
                        fontSize: 10,
                        lineHeight: 1.3,
                        marginTop: 1,
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                      }}>{tech.name}</div>
                      {count > 0 && (
                        <div style={{ fontSize: 9, marginTop: 2, opacity: 0.8 }}>
                          {count} incident{count !== 1 ? 's' : ''}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            )
          })}
        </div>
      </div>

      {/* Detail modal */}
      {selected && (
        <TechModal
          tech={selected}
          onClose={() => setSelected(null)}
        />
      )}
    </main>
  )
}
