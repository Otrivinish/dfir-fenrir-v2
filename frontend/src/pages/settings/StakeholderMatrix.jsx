import { useCallback, useEffect, useState } from 'react'
import { api } from '../../api/client.js'

const SEVERITIES = ['critical', 'high', 'medium', 'low']
const CATEGORIES = [
  'operational', 'regulatory', 'legal', 'executive',
  'media', 'technical', 'other',
]
const SEV_COLOR = {
  critical: 'var(--crit)',
  high:     'var(--high)',
  medium:   'var(--med)',
  low:      'var(--low)',
}

function formatMinutes(mins) {
  if (mins < 60)    return `${mins}m`
  if (mins < 1440)  return `${Math.round(mins / 60 * 10) / 10}h`
  return `${Math.round(mins / 1440 * 10) / 10}d`
}

export default function StakeholderMatrix() {
  const [rules,   setRules]   = useState([])
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)
  const [adding,  setAdding]  = useState(false)
  const [editing, setEditing] = useState(null)   // rule.id of the one being edited
  const [busy,    setBusy]    = useState(false)

  const load = useCallback(async () => {
    try {
      const data = await api.listStakeholderMatrix()
      setRules(data.items || [])
    } catch (e) {
      setError(e.message || 'Failed to load matrix')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function save(payload, ruleId) {
    setBusy(true)
    setError(null)
    try {
      if (ruleId) await api.updateStakeholderRule(ruleId, payload)
      else        await api.createStakeholderRule(payload)
      setAdding(false)
      setEditing(null)
      await load()
    } catch (e) {
      setError(e.data?.detail || e.message || 'Failed to save rule')
    } finally {
      setBusy(false)
    }
  }

  async function remove(rule) {
    if (!window.confirm(`Delete rule "${rule.role}" for ${rule.severity} incidents?`)) return
    setBusy(true)
    setError(null)
    try {
      await api.deleteStakeholderRule(rule.id)
      await load()
    } catch (e) {
      setError(e.message || 'Failed to delete rule')
    } finally {
      setBusy(false)
    }
  }

  if (loading) return <div className="panel-empty"><div>Loading matrix…</div></div>

  // Group rules by severity for the per-severity panel layout.
  const grouped = SEVERITIES.map(sev => ({
    severity: sev,
    rules: rules.filter(r => r.severity === sev),
  }))

  return (
    <section className="panel" style={{ padding: 'var(--space-4)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginBottom: 'var(--space-3)' }}>
        <div style={{ flex: 1 }}>
          <h2 className="panel-h" style={{ margin: 0 }}>Stakeholder Matrix</h2>
          <p style={{ margin: '4px 0 0', fontSize: 12, color: 'var(--muted)' }}>
            Define who must be notified per incident severity, and within what timeframe.
            A banner appears on the Communications tab when severity matches a required rule.
          </p>
        </div>
        {!adding && (
          <button
            type="button"
            className="btn primary"
            style={{ fontSize: 12 }}
            onClick={() => setAdding(true)}
          >+ Add rule</button>
        )}
      </div>

      {error && <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>{error}</div>}

      {adding && (
        <RuleForm
          onSave={(payload) => save(payload, null)}
          onCancel={() => setAdding(false)}
          busy={busy}
        />
      )}

      {grouped.map(({ severity, rules: sevRules }) => (
        <div key={severity} style={{ marginTop: 'var(--space-4)' }}>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
            marginBottom: 'var(--space-2)',
          }}>
            <span className="pill" style={{
              fontSize: 11, fontWeight: 700, textTransform: 'uppercase',
              letterSpacing: '0.08em',
              color: SEV_COLOR[severity],
              background: `color-mix(in srgb, ${SEV_COLOR[severity]} 14%, transparent)`,
              borderColor: `color-mix(in srgb, ${SEV_COLOR[severity]} 40%, transparent)`,
            }}>{severity}</span>
            <span style={{ fontSize: 11, color: 'var(--dim)' }}>
              {sevRules.length} rule{sevRules.length !== 1 ? 's' : ''}
            </span>
          </div>

          {sevRules.length === 0 ? (
            <div style={{ fontSize: 12, color: 'var(--dim)', padding: 'var(--space-2)' }}>
              No rules.
            </div>
          ) : (
            <table className="settings-table">
              <thead>
                <tr>
                  <th>Stakeholder role</th>
                  <th style={{ width: 140 }}>Notify within</th>
                  <th style={{ width: 130 }}>Category</th>
                  <th style={{ width: 90 }}>Required</th>
                  <th className="actions">Actions</th>
                </tr>
              </thead>
              <tbody>
                {sevRules.map(rule => editing === rule.id ? (
                  <tr key={rule.id}>
                    <td colSpan={5} style={{ padding: 0 }}>
                      <RuleForm
                        initial={rule}
                        onSave={(payload) => save(payload, rule.id)}
                        onCancel={() => setEditing(null)}
                        busy={busy}
                      />
                    </td>
                  </tr>
                ) : (
                  <tr key={rule.id}>
                    <td style={{ fontWeight: 600 }}>{rule.role}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                      {formatMinutes(rule.notify_within_minutes)}
                      <span style={{ color: 'var(--dim)', marginLeft: 6 }}>
                        ({rule.notify_within_minutes} min)
                      </span>
                    </td>
                    <td style={{ textTransform: 'capitalize', fontSize: 12 }}>{rule.category}</td>
                    <td>
                      {rule.required ? (
                        <span className="pill pill-crit" style={{ fontSize: 10 }}>★ Required</span>
                      ) : (
                        <span style={{ color: 'var(--dim)', fontSize: 12 }}>Advisory</span>
                      )}
                    </td>
                    <td className="actions">
                      <button type="button" className="btn ghost"
                              style={{ fontSize: 11 }}
                              onClick={() => setEditing(rule.id)}>Edit</button>
                      <button type="button" className="btn ghost"
                              style={{ fontSize: 11, color: 'var(--crit)' }}
                              onClick={() => remove(rule)}
                              disabled={busy}>Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      ))}
    </section>
  )
}


function RuleForm({ initial, onSave, onCancel, busy }) {
  const [severity, setSeverity] = useState(initial?.severity || 'critical')
  const [role,     setRole]     = useState(initial?.role || '')
  const [minutes,  setMinutes]  = useState(initial?.notify_within_minutes ?? 60)
  const [category, setCategory] = useState(initial?.category || 'operational')
  const [required, setRequired] = useState(initial?.required ?? false)

  function submit(e) {
    e?.preventDefault?.()
    const cleanRole = role.trim()
    if (!cleanRole) return
    onSave({
      severity,
      role: cleanRole,
      notify_within_minutes: Number(minutes),
      category,
      required,
    })
  }

  return (
    <form onSubmit={submit} style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(5, minmax(0, 1fr)) auto auto',
      gap: 'var(--space-2)',
      alignItems: 'end',
      padding: 'var(--space-3)',
      background: 'var(--surface-2)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius-sm)',
      marginBottom: 'var(--space-3)',
    }}>
      <div>
        <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.06em', display: 'block', marginBottom: 4 }}>Severity</label>
        <select className="select" value={severity} onChange={e => setSeverity(e.target.value)} style={{ width: '100%' }}>
          {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>
      <div style={{ gridColumn: 'span 2' }}>
        <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.06em', display: 'block', marginBottom: 4 }}>Stakeholder role</label>
        <input className="input" autoFocus value={role} onChange={e => setRole(e.target.value)}
               placeholder="e.g. CISO, Legal Counsel, Board" maxLength={128} required />
      </div>
      <div>
        <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.06em', display: 'block', marginBottom: 4 }}>Notify within (min)</label>
        <input className="input" type="number" min={1} max={10080} value={minutes}
               onChange={e => setMinutes(e.target.value)} required style={{ fontFamily: 'var(--font-mono)' }} />
      </div>
      <div>
        <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.06em', display: 'block', marginBottom: 4 }}>Category</label>
        <select className="select" value={category} onChange={e => setCategory(e.target.value)} style={{ width: '100%' }}>
          {CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
      </div>
      <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, cursor: 'pointer', marginBottom: 8 }}>
        <input type="checkbox" checked={required} onChange={e => setRequired(e.target.checked)} />
        Required
      </label>
      <div style={{ display: 'flex', gap: 'var(--space-1)', marginBottom: 4 }}>
        <button type="submit"  className="btn primary" style={{ fontSize: 12 }} disabled={busy || !role.trim()}>
          {busy ? 'Saving…' : (initial ? 'Save' : 'Add')}
        </button>
        <button type="button"  className="btn ghost"   style={{ fontSize: 12 }} onClick={onCancel} disabled={busy}>
          Cancel
        </button>
      </div>
    </form>
  )
}
