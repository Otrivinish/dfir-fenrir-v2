import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../../../api/client.js'
import { useAuth } from '../../../hooks/useAuth.jsx'
import { PISection } from './Reports.jsx'

// Post-Incident → Costs & Impact (J3, R29): the business impact assessment and cost tracking,
// moved out of Reports unchanged. Both stay editable after the incident is closed (the API allows it).

// ── Cost category / phase display labels ──────────────────────────────────────

const COST_CATEGORIES = [
  { value: 'personnel',         label: 'Personnel' },
  { value: 'tools_licenses',    label: 'Tools & Licenses' },
  { value: 'external_ir',       label: 'External IR' },
  { value: 'legal_counsel',     label: 'Legal Counsel' },
  { value: 'regulatory_fines',  label: 'Regulatory Fines' },
  { value: 'downtime_revenue',  label: 'Downtime / Revenue Loss' },
  { value: 'remediation_infra', label: 'Remediation / Infra' },
  { value: 'pr_communications', label: 'PR / Communications' },
  { value: 'other',             label: 'Other' },
]

const IR_PHASES = [
  { value: 'detection',     label: 'Detection' },
  { value: 'containment',   label: 'Containment' },
  { value: 'eradication',   label: 'Eradication' },
  { value: 'recovery',      label: 'Recovery' },
  { value: 'post_incident', label: 'Post-Incident' },
]

const CAT_LABEL  = Object.fromEntries(COST_CATEGORIES.map(c => [c.value, c.label]))
const PHASE_LABEL = Object.fromEntries(IR_PHASES.map(p => [p.value, p.label]))

// ── Business Impact Assessment ────────────────────────────────────────────────

const BIA_FIELDS = [
  { key: 'financial',     label: 'Financial Impact' },
  { key: 'operational',   label: 'Operational Impact' },
  { key: 'data_exposure', label: 'Data Exposure' },
  { key: 'reputational',  label: 'Reputational Impact' },
  { key: 'regulatory',    label: 'Regulatory Impact' },
  { key: 'legal',         label: 'Legal Exposure' },
]

function BusinessImpact({ inc, viewer }) {
  const [form,    setForm]    = useState({ financial: '', operational: '', data_exposure: '', reputational: '', regulatory: '', legal: '', notes: '' })
  const [loading, setLoading] = useState(true)
  const [saving,  setSaving]  = useState(false)
  const [saved,   setSaved]   = useState(false)
  const [error,   setError]   = useState(null)
  const savedTimer = useRef(null)

  useEffect(() => {
    api.getBusinessImpact(inc.id)
      .then(d => setForm({
        financial:     d.financial     || '',
        operational:   d.operational   || '',
        data_exposure: d.data_exposure || '',
        reputational:  d.reputational  || '',
        regulatory:    d.regulatory    || '',
        legal:         d.legal         || '',
        notes:         d.notes         || '',
      }))
      .catch(e => setError(e.message || 'Failed to load BIA'))
      .finally(() => setLoading(false))
  }, [inc.id])

  function set(k, v) { setForm(f => ({ ...f, [k]: v })) }

  async function save() {
    setSaving(true); setError(null)
    try {
      const payload = {}
      for (const [k, v] of Object.entries(form)) {
        payload[k] = v.trim() || null
      }
      await api.updateBusinessImpact(inc.id, payload)
      setSaved(true)
      clearTimeout(savedTimer.current)
      savedTimer.current = setTimeout(() => setSaved(false), 2500)
    } catch (e) {
      setError(e.message || 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  if (loading) return <div style={{ padding: 'var(--space-3)', color: 'var(--muted)', fontSize: 13 }}>Loading…</div>

  return (
    <div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-3)', marginBottom: 'var(--space-3)' }}>
        {BIA_FIELDS.map(f => (
          <div key={f.key} className="field">
            <label className="field-label">{f.label}</label>
            <textarea
              className="input compact"
              rows={3}
              value={form[f.key]}
              onChange={e => set(f.key, e.target.value)}
              maxLength={2048}
              disabled={viewer}
              placeholder="Describe the impact…"
              style={{ resize: 'vertical' }}
            />
          </div>
        ))}
      </div>
      <div className="field" style={{ marginBottom: 'var(--space-3)' }}>
        <label className="field-label">Notes</label>
        <textarea
          className="input compact"
          rows={3}
          value={form.notes}
          onChange={e => set('notes', e.target.value)}
          maxLength={4096}
          disabled={viewer}
          placeholder="Additional context, caveats, assumptions…"
          style={{ resize: 'vertical' }}
        />
      </div>
      {error && <div className="alert error" style={{ marginBottom: 'var(--space-2)' }}><span className="alert-icon">!</span><span>{error}</span></div>}
      <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
        {saved && <span style={{ fontSize: 12, color: 'var(--ok)' }}>Saved</span>}
        {!viewer && (
          <button type="button" className="btn primary" onClick={save} disabled={saving}>
            {saving ? 'Saving…' : 'Save business impact'}
          </button>
        )}
      </div>
    </div>
  )
}

// ── Cost Tracking ─────────────────────────────────────────────────────────────

const EMPTY_COST = { category: 'personnel', description: '', amount: '', currency: 'USD', ir_phase: '', is_estimated: false, incurred_at: '' }

function CostModal({ incId, existing, onSaved, onClose }) {
  const [form,   setForm]   = useState(existing ? {
    category:    existing.category,
    description: existing.description,
    amount:      String(existing.amount),
    currency:    existing.currency,
    ir_phase:    existing.ir_phase || '',
    is_estimated: existing.is_estimated,
    incurred_at: existing.incurred_at || '',
  } : { ...EMPTY_COST })
  const [saving, setSaving] = useState(false)
  const [error,  setError]  = useState(null)

  function set(k, v) { setForm(f => ({ ...f, [k]: v })) }

  async function submit(e) {
    e.preventDefault()
    if (!form.description.trim()) { setError('Description is required.'); return }
    const amount = parseFloat(form.amount)
    if (isNaN(amount) || amount < 0) { setError('Amount must be a valid non-negative number.'); return }
    setSaving(true); setError(null)
    try {
      const payload = {
        category:    form.category,
        description: form.description.trim(),
        amount,
        currency:    form.currency.trim().toUpperCase() || 'USD',
        ir_phase:    form.ir_phase || null,
        is_estimated: form.is_estimated,
        incurred_at: form.incurred_at || null,
      }
      const saved = existing
        ? await api.updateCost(incId, existing.id, payload)
        : await api.createCost(incId, payload)
      onSaved(saved, !!existing)
    } catch (e) {
      setError(e.message || 'Failed to save')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="modal-overlay">
      <div className="modal" style={{ maxWidth: 520 }}>
        <div className="modal-head">
          <span className="modal-title">{existing ? 'Edit Cost Entry' : 'Add Cost Entry'}</span>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close">✕</button>
        </div>
        <form onSubmit={submit} style={{ padding: 'var(--space-4)', display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-3)' }}>
            <div className="field">
              <label className="field-label">Category</label>
              <select className="select" value={form.category} onChange={e => set('category', e.target.value)}>
                {COST_CATEGORIES.map(c => <option key={c.value} value={c.value}>{c.label}</option>)}
              </select>
            </div>
            <div className="field">
              <label className="field-label">IR Phase</label>
              <select className="select" value={form.ir_phase} onChange={e => set('ir_phase', e.target.value)}>
                <option value="">— None —</option>
                {IR_PHASES.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
              </select>
            </div>
          </div>

          <div className="field">
            <label className="field-label">Description</label>
            <input className="input" value={form.description} onChange={e => set('description', e.target.value)} maxLength={512} required placeholder="What cost is this?" />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 80px 140px', gap: 'var(--space-3)' }}>
            <div className="field">
              <label className="field-label">Amount</label>
              <input type="number" className="input" min={0} step="0.01" value={form.amount} onChange={e => set('amount', e.target.value)} required placeholder="0.00" />
            </div>
            <div className="field">
              <label className="field-label">Currency</label>
              <input className="input" value={form.currency} onChange={e => set('currency', e.target.value)} maxLength={3} placeholder="USD" style={{ textTransform: 'uppercase' }} />
            </div>
            <div className="field">
              <label className="field-label">Incurred Date</label>
              <input type="date" className="input" value={form.incurred_at} onChange={e => set('incurred_at', e.target.value)} />
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <input type="checkbox" id="is-estimated" checked={form.is_estimated} onChange={e => set('is_estimated', e.target.checked)} />
            <label htmlFor="is-estimated" style={{ fontSize: 13, cursor: 'pointer' }}>This is an estimate (not yet realised)</label>
          </div>

          {error && <div className="alert error"><span className="alert-icon">!</span><span>{error}</span></div>}

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 'var(--space-2)' }}>
            <button type="button" className="btn ghost" onClick={onClose} disabled={saving}>Cancel</button>
            <button type="submit" className="btn primary" disabled={saving}>{saving ? 'Saving…' : (existing ? 'Update' : 'Add entry')}</button>
          </div>
        </form>
      </div>
    </div>
  )
}

function CostTracking({ inc, viewer }) {
  const [costs,   setCosts]   = useState([])
  const [summary, setSummary] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)
  const [modal,   setModal]   = useState(null)   // null | 'add' | cost-object

  const load = useCallback(async () => {
    try {
      const [c, s] = await Promise.all([api.listCosts(inc.id), api.costSummary(inc.id)])
      setCosts(c)
      setSummary(s)
    } catch (e) {
      setError(e.message || 'Failed to load costs')
    } finally {
      setLoading(false)
    }
  }, [inc.id])

  useEffect(() => { load() }, [load])

  async function remove(costId) {
    if (!confirm('Delete this cost entry?')) return
    try {
      await api.deleteCost(inc.id, costId)
      setCosts(prev => prev.filter(c => c.id !== costId))
      // refresh summary
      const s = await api.costSummary(inc.id)
      setSummary(s)
    } catch (e) {
      setError(e.message || 'Delete failed')
    }
  }

  function onSaved(saved, isEdit) {
    setCosts(prev => isEdit ? prev.map(c => c.id === saved.id ? saved : c) : [...prev, saved])
    setModal(null)
    api.costSummary(inc.id).then(setSummary).catch(() => {})
  }

  if (loading) return <div style={{ padding: 'var(--space-3)', color: 'var(--muted)', fontSize: 13 }}>Loading…</div>

  return (
    <div>
      {/* Summary strip — one per currency (amounts in different currencies are never added) */}
      {summary && (Object.keys(summary.by_currency).length ? Object.entries(summary.by_currency) : [[summary.currency, summary]]).map(([cur, t]) => (
        <div key={cur} style={{ display: 'flex', gap: 'var(--space-4)', padding: 'var(--space-3)', background: 'var(--surface-2)', borderRadius: 'var(--radius)', marginBottom: 'var(--space-3)', flexWrap: 'wrap' }}>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 18, fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{cur} {t.total_realised.toLocaleString(undefined, { minimumFractionDigits: 2 })}</div>
            <div style={{ fontSize: 11, color: 'var(--muted)' }}>Realised</div>
          </div>
          <div style={{ width: 1, background: 'var(--border)' }} />
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 18, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--muted)' }}>{cur} {t.total_estimated.toLocaleString(undefined, { minimumFractionDigits: 2 })}</div>
            <div style={{ fontSize: 11, color: 'var(--muted)' }}>Estimated</div>
          </div>
          <div style={{ width: 1, background: 'var(--border)' }} />
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 18, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>{cur} {t.total.toLocaleString(undefined, { minimumFractionDigits: 2 })}</div>
            <div style={{ fontSize: 11, color: 'var(--muted)' }}>Total</div>
          </div>
        </div>
      ))}

      {/* Table */}
      {costs.length > 0 ? (
        <div style={{ overflowX: 'auto', marginBottom: 'var(--space-3)' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)', color: 'var(--muted)', fontSize: 11 }}>
                <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em' }}>Category</th>
                <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em' }}>Description</th>
                <th style={{ textAlign: 'right', padding: '6px 8px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em' }}>Amount</th>
                <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em' }}>Phase</th>
                <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em' }}>Date</th>
                <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em' }}>Type</th>
                <th style={{ padding: '6px 8px' }} />
              </tr>
            </thead>
            <tbody>
              {costs.map(c => (
                <tr key={c.id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '6px 8px', color: 'var(--text)' }}>{CAT_LABEL[c.category] || c.category}</td>
                  <td style={{ padding: '6px 8px', color: 'var(--text)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.description}</td>
                  <td style={{ padding: '6px 8px', textAlign: 'right', fontFamily: 'var(--font-mono)', color: 'var(--text)' }}>
                    {c.currency} {Number(c.amount).toLocaleString(undefined, { minimumFractionDigits: 2 })}
                  </td>
                  <td style={{ padding: '6px 8px', color: 'var(--muted)' }}>{c.ir_phase ? PHASE_LABEL[c.ir_phase] || c.ir_phase : '—'}</td>
                  <td style={{ padding: '6px 8px', color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>{c.incurred_at || '—'}</td>
                  <td style={{ padding: '6px 8px' }}>
                    {c.is_estimated
                      ? <span style={{ fontSize: 10, color: 'var(--med)', fontWeight: 700 }}>EST</span>
                      : <span style={{ fontSize: 10, color: 'var(--ok)', fontWeight: 700 }}>ACTUAL</span>
                    }
                  </td>
                  <td style={{ padding: '6px 8px', whiteSpace: 'nowrap' }}>
                    {!viewer && (<>
                      <button type="button" className="btn ghost" onClick={() => setModal(c)}>Edit</button>
                      {' '}
                      <button type="button" className="btn ghost" style={{ color: 'var(--crit)' }} onClick={() => remove(c.id)}>✕</button>
                    </>)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div style={{ color: 'var(--dim)', fontSize: 13, marginBottom: 'var(--space-3)' }}>No cost entries yet.</div>
      )}

      {error && <div className="alert error" style={{ marginBottom: 'var(--space-2)' }}><span className="alert-icon">!</span><span>{error}</span></div>}

      {!viewer && <button type="button" className="btn ghost" onClick={() => setModal('add')}>+ Add cost entry</button>}

      {modal && (
        <CostModal
          incId={inc.id}
          existing={modal === 'add' ? null : modal}
          onSaved={onSaved}
          onClose={() => setModal(null)}
        />
      )}
    </div>
  )
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function CostsImpact({ inc }) {
  // L2 (R43): a viewer reads the assessment and costs; writing them is analyst-only on the API.
  const { user } = useAuth()
  const viewer = user?.role === 'viewer'
  return (
    <div style={{ maxWidth: 960 }}>
      <PISection title="Business Impact Assessment">
        <BusinessImpact inc={inc} viewer={viewer} />
      </PISection>
      <PISection title="Cost Tracking">
        <CostTracking inc={inc} viewer={viewer} />
      </PISection>
    </div>
  )
}
