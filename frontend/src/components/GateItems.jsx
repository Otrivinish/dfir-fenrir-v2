import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.js'
import { formatLocal } from '../lib/datetime.js'

// Phase-gate status for the phase-change and Close modals. The API decides
// (GET /api/incidents/{id}/gates — the same code enforces it); this only renders it.
// Gates v2 (I5): every check has a level. Block-level items stop the move (the incident
// lead may override with a reason); warnings are shown and recorded, never blocking.
// Sign-offs (IC, and the DPO for a personal-data breach) are recorded here.

const REASON_MIN = 10
const ROLE_LABEL = { ic: 'Incident Commander', dpo: 'Data Protection Officer' }
const ROLE_WHO = {
  ic: "Only this incident's lead (Incident Commander or Deputy) or an admin can sign as Incident Commander.",
  dpo: 'Only the analyst assigned Data Protection Officer on this incident, or an admin, can sign as DPO.',
}

// Loads one gate ("post_incident" or "close") when `enabled`. `setGate` lets a modal
// replace the list with the `unmet` items of a 409 gate_unmet reply; `reload` re-reads it.
export function useGate(incidentId, name, enabled = true) {
  const [gate, setGate]       = useState(null)
  const [loading, setLoading] = useState(enabled)
  const [error, setError]     = useState(null)
  const [tick, setTick]       = useState(0)

  useEffect(() => {
    if (!enabled) { setLoading(false); return }
    let alive = true
    setLoading(true); setError(null)
    api.getIncidentGates(incidentId)
      .then(r => { if (alive) setGate((r.items || []).find(g => g.gate === name) || null) })
      .catch(e => { if (alive) setError(e.message || 'Could not check the gate.') })
      .finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [incidentId, name, enabled, tick])

  const reload = useCallback(() => setTick(t => t + 1), [])
  return { gate, setGate, loading, error, reload }
}

function CheckList({ incidentId, items, onNavigate }) {
  return (
    <ul style={{ margin: 'var(--space-1) 0 0', paddingLeft: 'var(--space-4)', color: 'var(--text)', lineHeight: 1.5 }}>
      {items.map(it => (
        <li key={it.key} data-gate-key={it.key} data-gate-level={it.level}>
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
  )
}

function SignOffRow({ incidentId, gateName, role, signed, allowed, onSigned }) {
  const [open, setOpen]   = useState(false)
  const [text, setText]   = useState('')
  const [busy, setBusy]   = useState(false)
  const [error, setError] = useState(null)
  const n = text.trim().length
  const id = `gate-signoff-${gateName}-${role}`

  const submit = async () => {
    setBusy(true); setError(null)
    try {
      await api.signOffGate(incidentId, gateName, { role, statement: text.trim() })
      setOpen(false); setText('')
      onSigned?.()
    } catch (e) {
      setError(e.message || 'Could not record the sign-off.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <li data-signoff-role={role} data-signoff-state={signed ? 'signed' : 'missing'} style={{ marginTop: 'var(--space-1)' }}>
      <b>{ROLE_LABEL[role]}</b>{': '}
      {signed ? (
        <>
          <span aria-hidden="true">✓</span> signed by <b>{signed.username}</b> · {formatLocal(signed.signed_at)}
          <div style={{ color: 'var(--muted)', fontStyle: 'italic', whiteSpace: 'pre-wrap' }}>“{signed.statement}”</div>
          {!signed.matches_current_state && (
            <div style={{ fontSize: 12, color: 'var(--muted)' }} data-signoff-changed>
              The blocking checks changed since this sign-off. It still counts; sign again to record the current state.
            </div>
          )}
        </>
      ) : <span style={{ color: 'var(--muted)' }}>not signed</span>}
      {allowed && !open && (
        <div>
          <button type="button" className="btn ghost" onClick={() => setOpen(true)}
                  data-signoff-open={role}>
            {signed ? 'Sign again' : `Sign off as ${ROLE_LABEL[role]}`}
          </button>
        </div>
      )}
      {!allowed && !signed && <div className="field-hint">{ROLE_WHO[role]}</div>}
      {open && (
        <div className="field" style={{ marginTop: 'var(--space-1)' }}>
          <label className="field-label" htmlFor={id}>Sign-off statement ({ROLE_LABEL[role]})</label>
          <textarea id={id} className="input" rows={2} maxLength={2000} value={text} disabled={busy}
                    placeholder="What you approve, on what basis…" onChange={e => setText(e.target.value)} />
          <span className="field-hint">
            Recorded with your name, the time and a hash of the gate as it is now; it can't be edited.
            {n < REASON_MIN ? ` At least ${REASON_MIN} characters (${n} so far).` : ''}
          </span>
          <div style={{ display: 'flex', gap: 'var(--space-2)', marginTop: 'var(--space-1)' }}>
            <button type="button" className="btn primary" disabled={busy || n < REASON_MIN}
                    onClick={submit} data-signoff-submit={role}>
              {busy ? 'Signing…' : 'Sign off'}
            </button>
            <button type="button" className="btn ghost" disabled={busy}
                    onClick={() => { setOpen(false); setError(null) }}>Cancel</button>
          </div>
          {error && <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div>}
        </div>
      )}
    </li>
  )
}

// What blocks the gate and what only warns (each with a link to where it is fixed), the
// sign-offs it needs, and the open obligations it carries forward. `onNavigate` runs when a
// link is followed; `canSign` = { ic, dpo } from GET …/access; `onSigned` re-reads the gate.
export function GateItems({ incidentId, gate, onNavigate, canSign = {}, onSigned }) {
  if (!gate) return null
  if (gate.exempt) {
    return (
      <div className="alert info" role="status" data-gate-state="exempt">
        <span className="alert-icon">i</span>
        <span>{gate.label} does not apply to a false or benign positive.</span>
      </div>
    )
  }
  const blocks   = gate.unmet || []
  const warns    = gate.warnings || []
  const checks   = gate.checks || []
  const met      = checks.filter(c => c.status === 'met').length
  const required = gate.sign_offs_required || []
  const latest   = role => (gate.sign_offs || []).find(s => s.role === role)
  return (
    <>
      {blocks.length === 0 ? (
        <div className="alert info" role="status" data-gate-state="met">
          <span className="alert-icon">✓</span>
          <span>
            {gate.label}: met{checks.length ? ` (${met} of ${checks.length} checks)` : ''}.
            {warns.length > 0 && ` ${warns.length} ${warns.length === 1 ? 'warning' : 'warnings'} below; they don't block.`}
          </span>
        </div>
      ) : (
        <div className="alert warn" role="status" data-gate-state="unmet" data-gate-group="block">
          <span className="alert-icon">!</span>
          <div>
            <b>{gate.label}: {blocks.length} blocking {blocks.length === 1 ? 'item' : 'items'}</b>
            <CheckList incidentId={incidentId} items={blocks} onNavigate={onNavigate} />
          </div>
        </div>
      )}
      {warns.length > 0 && (
        <div className="alert info" role="status" data-gate-group="warn">
          <span className="alert-icon">i</span>
          <div>
            <b>{warns.length} {warns.length === 1 ? 'warning' : 'warnings'}: recorded with the change, never blocking</b>
            <CheckList incidentId={incidentId} items={warns} onNavigate={onNavigate} />
          </div>
        </div>
      )}
      {required.length > 0 && (
        <div style={{ fontSize: 13 }} data-gate-signoffs>
          <b>Sign-offs this gate needs</b>
          <ul style={{ margin: '2px 0 0', paddingLeft: 'var(--space-4)', listStyle: 'none' }}>
            {required.map(role => (
              <SignOffRow key={role} incidentId={incidentId} gateName={gate.gate} role={role}
                          signed={latest(role)} allowed={!!canSign[role]} onSigned={onSigned} />
            ))}
          </ul>
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
