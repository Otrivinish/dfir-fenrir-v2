import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.js'
import { formatLocal } from '../lib/datetime.js'

// Phase-gate status for the phase-change and Close modals. The API decides
// (GET /api/incidents/{id}/gates — the same code enforces it); this only renders it.

// Loads one gate ("post_incident" or "close") when `enabled`. `setGate` lets a modal
// replace the list with the `unmet` items of a 409 gate_unmet reply.
export function useGate(incidentId, name, enabled = true) {
  const [gate, setGate]       = useState(null)
  const [loading, setLoading] = useState(enabled)
  const [error, setError]     = useState(null)

  useEffect(() => {
    if (!enabled) { setLoading(false); return }
    let alive = true
    setLoading(true); setError(null)
    api.getIncidentGates(incidentId)
      .then(r => { if (alive) setGate((r.items || []).find(g => g.gate === name) || null) })
      .catch(e => { if (alive) setError(e.message || 'Could not check the gate.') })
      .finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [incidentId, name, enabled])

  return { gate, setGate, loading, error }
}

// What blocks the gate (each with a link to where it is fixed) and the open
// obligations it carries forward. `onNavigate` runs when a link is followed.
export function GateItems({ incidentId, gate, onNavigate }) {
  if (!gate) return null
  if (gate.exempt) {
    return (
      <div className="alert info" role="status" data-gate-state="exempt">
        <span className="alert-icon">i</span>
        <span>{gate.label} does not apply to a false or benign positive.</span>
      </div>
    )
  }
  return (
    <>
      {gate.met ? (
        <div className="alert info" role="status" data-gate-state="met">
          <span className="alert-icon">✓</span>
          <span>{gate.label}: met.</span>
        </div>
      ) : (
        <div className="alert warn" role="status" data-gate-state="unmet">
          <span className="alert-icon">!</span>
          <div>
            <b>{gate.label}: {gate.unmet.length} {gate.unmet.length === 1 ? 'item' : 'items'} missing</b>
            <ul style={{ margin: 'var(--space-1) 0 0', paddingLeft: 'var(--space-4)', color: 'var(--text)', lineHeight: 1.5 }}>
              {gate.unmet.map(it => (
                <li key={it.key} data-gate-key={it.key}>
                  {it.label}
                  {it.detail && <span style={{ color: 'var(--muted)' }}> — {it.detail}</span>}
                  {it.fix_hint && (
                    <div style={{ fontSize: 12 }}>
                      {it.route
                        ? <Link to={`/incidents/${incidentId}/${it.route}`} onClick={onNavigate}>→ {it.fix_hint}</Link>
                        : <span style={{ color: 'var(--muted)' }}>{it.fix_hint}</span>}
                    </div>
                  )}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
      {gate.carried_forward?.length > 0 && (
        <div style={{ fontSize: 12, color: 'var(--muted)' }} data-gate-carried>
          Carried forward (open, not blocking):
          <ul style={{ margin: '2px 0 0', paddingLeft: 'var(--space-4)' }}>
            {gate.carried_forward.map(it => (
              <li key={`${it.label}|${it.due_at}`}>
                {it.label}{it.due_at && <> — due {formatLocal(it.due_at)}</>}
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  )
}
