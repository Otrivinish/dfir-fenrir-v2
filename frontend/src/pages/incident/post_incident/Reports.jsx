import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../../../api/client.js'
import { TEMPLATE_META, generateReport, generateSkeleton, injectReportSha256 } from '../../../lib/reportTemplates.js'
import LePackage from './LePackage.jsx'

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

function BusinessImpact({ inc }) {
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
              className="input"
              rows={3}
              value={form[f.key]}
              onChange={e => set(f.key, e.target.value)}
              maxLength={2048}
              placeholder="Describe the impact…"
              style={{ resize: 'vertical', fontSize: 13 }}
            />
          </div>
        ))}
      </div>
      <div className="field" style={{ marginBottom: 'var(--space-3)' }}>
        <label className="field-label">Notes</label>
        <textarea
          className="input"
          rows={3}
          value={form.notes}
          onChange={e => set('notes', e.target.value)}
          maxLength={4096}
          placeholder="Additional context, caveats, assumptions…"
          style={{ resize: 'vertical', fontSize: 13 }}
        />
      </div>
      {error && <div className="alert error" style={{ marginBottom: 'var(--space-2)' }}><span className="alert-icon">!</span><span>{error}</span></div>}
      <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
        {saved && <span style={{ fontSize: 12, color: 'var(--ok)' }}>Saved</span>}
        <button type="button" className="btn primary" onClick={save} disabled={saving} style={{ fontSize: 13 }}>
          {saving ? 'Saving…' : 'Save business impact'}
        </button>
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

function CostTracking({ inc }) {
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
      {/* Summary strip */}
      {summary && (
        <div style={{ display: 'flex', gap: 'var(--space-4)', padding: 'var(--space-3)', background: 'var(--surface-2)', borderRadius: 'var(--radius)', marginBottom: 'var(--space-3)', flexWrap: 'wrap' }}>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 18, fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{summary.currency} {summary.total_realised.toLocaleString(undefined, { minimumFractionDigits: 2 })}</div>
            <div style={{ fontSize: 11, color: 'var(--muted)' }}>Realised</div>
          </div>
          <div style={{ width: 1, background: 'var(--border)' }} />
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 18, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--muted)' }}>{summary.currency} {summary.total_estimated.toLocaleString(undefined, { minimumFractionDigits: 2 })}</div>
            <div style={{ fontSize: 11, color: 'var(--muted)' }}>Estimated</div>
          </div>
          <div style={{ width: 1, background: 'var(--border)' }} />
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 18, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>{summary.currency} {summary.total.toLocaleString(undefined, { minimumFractionDigits: 2 })}</div>
            <div style={{ fontSize: 11, color: 'var(--muted)' }}>Total</div>
          </div>
        </div>
      )}

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
                    <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '2px 6px' }} onClick={() => setModal(c)}>Edit</button>
                    {' '}
                    <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '2px 6px', color: 'var(--crit)' }} onClick={() => remove(c.id)}>✕</button>
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

      <button type="button" className="btn ghost" style={{ fontSize: 13 }} onClick={() => setModal('add')}>+ Add cost entry</button>

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

// ── Lessons & Remediation (Reports-tab narratives) ──────────────────────────
// Six plain-text fields that feed §09 Lessons Learned and §10 Remediation Plan.
// Persisted on the same `lessons_learned` row used by the Lessons Learned tab,
// so the rich structured editor and these quick-fill narratives stay in sync.

const LR_FIELDS = [
  { key: 'report_what_worked_well',         label: 'What worked well',
    placeholder: 'Detection was fast; the on-call rota was clear; comms were calm…' },
  { key: 'report_what_could_improve',       label: 'What could be improved',
    placeholder: 'Containment took longer than target; runbook for X was missing…' },
  { key: 'report_security_recommendations', label: 'Security recommendations / control improvements',
    placeholder: 'Enforce MFA on remaining VPN endpoints; tighten egress filtering on tier-1 hosts…' },
]

const LR_REMEDIATION = [
  { key: 'report_remediation_short',  label: 'Short-term (0–30 days)',          color: '#dc2626',
    placeholder: 'Rotate exposed credentials; deploy EDR on tier-1 assets…' },
  { key: 'report_remediation_medium', label: 'Medium-term (30–90 days)',         color: '#ea580c',
    placeholder: 'Roll out conditional access policy; segment file-server VLAN…' },
  { key: 'report_remediation_long',   label: 'Long-term (90+ days)',             color: '#2563eb',
    placeholder: 'Replace legacy auth proxy; full IAM review; tabletop exercise cadence…' },
]

const EMPTY_LR = Object.fromEntries(
  [...LR_FIELDS, ...LR_REMEDIATION].map(f => [f.key, ''])
)

function LessonsAndRemediation({ inc }) {
  const [form,    setForm]    = useState(EMPTY_LR)
  const [loading, setLoading] = useState(true)
  const [saving,  setSaving]  = useState(false)
  const [saved,   setSaved]   = useState(false)
  const [error,   setError]   = useState(null)
  const savedTimer = useRef(null)

  useEffect(() => {
    api.getLessonsLearned(inc.id)
      .then(d => setForm({
        report_what_worked_well:         d.report_what_worked_well         || '',
        report_what_could_improve:       d.report_what_could_improve       || '',
        report_security_recommendations: d.report_security_recommendations || '',
        report_remediation_short:        d.report_remediation_short        || '',
        report_remediation_medium:       d.report_remediation_medium       || '',
        report_remediation_long:         d.report_remediation_long         || '',
      }))
      .catch(e => setError(e.message || 'Failed to load lessons'))
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
      await api.saveLessonsLearned(inc.id, payload)
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
      <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 'var(--space-3)', lineHeight: 1.5 }}>
        Free-text fields that fill §09 Lessons Learned and §10 Remediation Plan in the
        generated report. Empty fields fall back to the structured entries on the
        Lessons Learned tab.
      </div>

      <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 'var(--space-2)' }}>
        Lessons Learned &amp; Recommendations
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)', marginBottom: 'var(--space-4)' }}>
        {LR_FIELDS.map(f => (
          <div key={f.key} className="field">
            <label className="field-label">{f.label}</label>
            <textarea
              className="input"
              rows={3}
              value={form[f.key]}
              onChange={e => set(f.key, e.target.value)}
              maxLength={16384}
              placeholder={f.placeholder}
              style={{ resize: 'vertical', fontSize: 13 }}
            />
          </div>
        ))}
      </div>

      <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 'var(--space-2)' }}>
        Remediation Plan
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)', marginBottom: 'var(--space-3)' }}>
        {LR_REMEDIATION.map(f => (
          <div key={f.key} className="field">
            <label className="field-label" style={{ borderLeft: `3px solid ${f.color}`, paddingLeft: 8 }}>
              {f.label}
            </label>
            <textarea
              className="input"
              rows={3}
              value={form[f.key]}
              onChange={e => set(f.key, e.target.value)}
              maxLength={16384}
              placeholder={f.placeholder}
              style={{ resize: 'vertical', fontSize: 13 }}
            />
          </div>
        ))}
      </div>

      {error && <div className="alert error" style={{ marginBottom: 'var(--space-2)' }}><span className="alert-icon">!</span><span>{error}</span></div>}
      <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
        {saved && <span style={{ fontSize: 12, color: 'var(--ok)' }}>Saved</span>}
        <button type="button" className="btn primary" onClick={save} disabled={saving} style={{ fontSize: 13 }}>
          {saving ? 'Saving…' : 'Save lessons & remediation'}
        </button>
      </div>
    </div>
  )
}

// ── Section wrapper ───────────────────────────────────────────────────────────

function PISection({ title, children }) {
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius)', marginBottom: 'var(--space-5)', overflow: 'hidden' }}>
      <div style={{ background: 'var(--surface-2)', padding: 'var(--space-2) var(--space-3)', fontWeight: 700, fontSize: 13, borderBottom: '1px solid var(--border)', letterSpacing: '0.04em' }}>
        {title}
      </div>
      <div style={{ padding: 'var(--space-4)' }}>
        {children}
      </div>
    </div>
  )
}

const LS_LOGO   = 'fenrir:report:logo'
const LS_FOOTER = 'fenrir:report:footer'

function loadLogo()   { try { return localStorage.getItem(LS_LOGO)   || null } catch { return null } }
function loadFooter() { try { return localStorage.getItem(LS_FOOTER) || ''   } catch { return ''   } }

const SWATCH = {
  mission_control: '#070b14',
  executive:       '#1e3a5f',
  nordic:          '#4f46e5',
  forensic:        '#374151',
  compact:         '#0d47a1',
  tactical:        '#dc2626',
}

// ── Report generation ─────────────────────────────────────────────────────────

// Default section-include flags. Defaults match the pre-toggle behaviour so
// existing reports look unchanged unless the operator explicitly opts out.
const DEFAULT_SECTIONS = {
  overview: true, kpis: true, iocs: true, entities: true,
  entity_graph: false,
  timeline: true, actions: true, playbook: true, evidence: true,
  mitre: true, lessons: true, remediation: true, closure: true,
}

const TLP_OPTIONS = ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED']

export default function Reports({ inc }) {
  const [templateId, setTemplateId] = useState('executive')
  const [mode,       setMode]       = useState('full')
  const [logo,       setLogo]       = useState(loadLogo)
  const [footer,     setFooter]     = useState(loadFooter)
  const [loading,    setLoading]    = useState(false)
  const [error,      setError]      = useState(null)
  const [advancedOpen, setAdvancedOpen] = useState(false)
  const [classification,        setClassification]        = useState('')   // '' = inherit incident TLP
  const [audience,              setAudience]              = useState('')
  const [includeInternalEvents,  setIncludeInternalEvents]  = useState(false)
  const [includeTimelineAppendix, setIncludeTimelineAppendix] = useState(false)
  const [sections,               setSections]               = useState(DEFAULT_SECTIONS)
  const toggleSection = (key) => setSections(s => ({ ...s, [key]: !s[key] }))
  const fileRef = useRef(null)

  const [history,        setHistory]        = useState([])
  const [historyLoading, setHistoryLoading] = useState(true)
  const [downloadTarget, setDownloadTarget] = useState(null)   // history row to download
  const [accessReason,   setAccessReason]   = useState('')
  const [downloading,    setDownloading]    = useState(false)

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true)
    try {
      const items = await api.listReportHistory(inc.id)
      setHistory(items || [])
    } catch {
      setHistory([])
    } finally {
      setHistoryLoading(false)
    }
  }, [inc.id])

  useEffect(() => { loadHistory() }, [loadHistory])

  async function confirmDownload() {
    const row = downloadTarget
    if (!row || !accessReason.trim()) return
    setDownloading(true)
    setError(null)
    try {
      const resp = await fetch(api.downloadSavedReportUrl(inc.id, row.id), {
        method:      'POST',
        credentials: 'same-origin',
        headers:     { 'Content-Type': 'application/json' },
        body:        JSON.stringify({ access_reason: accessReason.trim() }),
      })
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}))
        throw new Error(err.detail || `HTTP ${resp.status}`)
      }
      const headerSha = resp.headers.get('X-Report-SHA256') || ''
      const blob = await resp.blob()

      // Optional client-side integrity check — flag a tampered transport.
      try {
        const buf = await blob.arrayBuffer()
        const digest = await crypto.subtle.digest('SHA-256', buf)
        const got = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('')
        if (headerSha && got !== headerSha) {
          setError(`SHA-256 mismatch — expected ${headerSha.slice(0,12)}…, got ${got.slice(0,12)}…`)
          return
        }
      } catch { /* SubtleCrypto unavailable — skip verify, server already audited */ }

      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `fenrir-report-${row.report_type}-${row.id.slice(0,8)}.html`
      document.body.appendChild(a); a.click(); document.body.removeChild(a)
      URL.revokeObjectURL(url)
      setDownloadTarget(null)
      setAccessReason('')
      loadHistory()
    } catch (e) {
      setError(e.message || 'Download failed.')
    } finally {
      setDownloading(false)
    }
  }

  function handleLogoFile(e) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = ev => {
      const url = ev.target.result
      setLogo(url)
      try { localStorage.setItem(LS_LOGO, url) } catch { /* quota */ }
    }
    reader.readAsDataURL(file)
  }

  function clearLogo() {
    setLogo(null)
    try { localStorage.removeItem(LS_LOGO) } catch { /* ok */ }
    if (fileRef.current) fileRef.current.value = ''
  }

  function handleFooter(val) {
    setFooter(val)
    try { localStorage.setItem(LS_FOOTER, val) } catch { /* quota */ }
  }

  function showStructure() {
    setError(null)
    const html = generateSkeleton({
      mode, footer,
      classification, audience,
      includeInternalEvents,
      sections,
    })
    const w = window.open('', '_blank')
    if (!w) { setError('Pop-up blocked — please allow pop-ups for this site.'); return }
    w.document.write(html)
    w.document.close()
  }

  async function generate(action) {
    setLoading(true)
    setError(null)
    try {
      const data = await api.getReportData(inc.id)
      const rawHtml = generateReport(data, {
        templateId, mode, logo, footer,
        classification, audience,
        includeInternalEvents,
        includeTimelineAppendix,
        sections,
      })
      // Self-describing SHA-256: the placeholder in the footer is replaced
      // with the SHA-256 of the document while the placeholder was still in
      // place. Verifiers reverse the substitution to confirm integrity.
      const html = await injectReportSha256(rawHtml)
      if (action === 'preview') {
        const w = window.open('', '_blank')
        if (!w) { setError('Pop-up blocked — please allow pop-ups for this site.'); return }
        w.document.write(html)
        w.document.close()
      } else {
        const blob = new Blob([html], { type: 'text/html;charset=utf-8' })
        const url  = URL.createObjectURL(blob)
        const a    = document.createElement('a')
        const slug = inc.title.slice(0, 30).replace(/[^a-zA-Z0-9]/g, '-').replace(/-+/g, '-')
        a.href     = url
        a.download = `fenrir-report-${mode}-${slug}.html`
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
      }

      // Persist to history for audit-grade re-download with SHA-256 integrity.
      // Best-effort — surfacing a save error here would block the analyst's
      // primary workflow (preview/download), so fall back quietly.
      try {
        await api.saveReport(inc.id, {
          report_type:    mode === 'executive' ? 'exec' : 'full',
          template_id:    templateId,
          classification: classification || `TLP:${(inc.tlp || 'AMBER').toUpperCase()}`,
          audience:       audience || null,
          footer_text:    footer || null,
          html,
        })
        loadHistory()
      } catch (e) {
        // eslint-disable-next-line no-console
        console.warn('Report history save failed:', e?.message)
      }
    } catch (e) {
      setError(e.message || 'Failed to generate report')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ maxWidth: 960 }}>

      {/* Business Impact Assessment */}
      <PISection title="Business Impact Assessment">
        <BusinessImpact inc={inc} />
      </PISection>

      {/* Lessons Learned & Remediation Plan (Reports-tab quick-fill) */}
      <PISection title="Lessons Learned & Remediation Plan">
        <LessonsAndRemediation inc={inc} />
      </PISection>

      {/* Cost Tracking */}
      <PISection title="Cost Tracking">
        <CostTracking inc={inc} />
      </PISection>

      {/* Template picker */}
      <div style={{ marginBottom: 'var(--space-4)' }}>
        <div style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--muted)', marginBottom: 'var(--space-2)' }}>
          Report Layout
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(170px,1fr))', gap: 'var(--space-2)' }}>
          {TEMPLATE_META.map(t => (
            <button
              key={t.id}
              type="button"
              onClick={() => setTemplateId(t.id)}
              style={{
                textAlign: 'left',
                padding: 'var(--space-3)',
                borderRadius: 'var(--radius)',
                border: templateId === t.id
                  ? '2px solid var(--accent)'
                  : '2px solid var(--border)',
                background: templateId === t.id ? 'var(--surface-2)' : 'var(--surface)',
                cursor: 'pointer',
                transition: 'border-color .15s',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-1)' }}>
                <div style={{ width: 12, height: 12, borderRadius: 3, background: SWATCH[t.id], flexShrink: 0 }} />
                <span style={{ fontWeight: 600, fontSize: 13 }}>{t.name}</span>
              </div>
              <span style={{ fontSize: 11, color: 'var(--muted)', lineHeight: 1.4, display: 'block' }}>{t.desc}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Mode + branding in a row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-4)', marginBottom: 'var(--space-4)' }}>

        {/* Mode */}
        <div>
          <div style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--muted)', marginBottom: 'var(--space-2)' }}>
            Report Type
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
            {[
              { value: 'executive', label: 'Executive Summary', desc: 'Key facts, KPIs, MITRE tactics, lessons & recommendations. No raw IOC values or full timeline.' },
              { value: 'full',      label: 'Full Technical Report', desc: 'All sections: complete IOC table, timeline, entities, respond actions, playbook, evidence.' },
            ].map(opt => (
              <label
                key={opt.value}
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: 'var(--space-2)',
                  padding: 'var(--space-2) var(--space-3)',
                  borderRadius: 'var(--radius)',
                  border: mode === opt.value ? '1px solid var(--accent)' : '1px solid var(--border)',
                  background: mode === opt.value ? 'var(--surface-2)' : 'var(--surface)',
                  cursor: 'pointer',
                }}
              >
                <input
                  type="radio"
                  name="report-mode"
                  value={opt.value}
                  checked={mode === opt.value}
                  onChange={() => setMode(opt.value)}
                  style={{ marginTop: 3, flexShrink: 0 }}
                />
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>{opt.label}</div>
                  <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2, lineHeight: 1.4 }}>{opt.desc}</div>
                </div>
              </label>
            ))}
          </div>
        </div>

        {/* Branding */}
        <div>
          <div style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--muted)', marginBottom: 'var(--space-2)' }}>
            Branding
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
            <div>
              <label className="field-label" style={{ marginBottom: 'var(--space-1)', display: 'block' }}>Company logo</label>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
                {logo && (
                  <img
                    src={logo}
                    alt="Logo preview"
                    style={{ maxHeight: 36, maxWidth: 120, objectFit: 'contain', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: 4, background: '#fff' }}
                  />
                )}
                <input
                  ref={fileRef}
                  type="file"
                  accept="image/*"
                  style={{ display: 'none' }}
                  onChange={handleLogoFile}
                />
                <button type="button" className="btn ghost" style={{ fontSize: 12 }} onClick={() => fileRef.current?.click()}>
                  {logo ? 'Change logo' : 'Upload logo'}
                </button>
                {logo && (
                  <button type="button" className="btn ghost" style={{ fontSize: 12, color: 'var(--crit)' }} onClick={clearLogo}>
                    Remove
                  </button>
                )}
              </div>
              <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 4 }}>Saved locally in browser. PNG or SVG recommended.</div>
            </div>

            <div>
              <label className="field-label" htmlFor="report-footer" style={{ marginBottom: 'var(--space-1)', display: 'block' }}>Footer text</label>
              <input
                id="report-footer"
                className="input"
                value={footer}
                onChange={e => handleFooter(e.target.value)}
                placeholder="e.g. Acme Security Operations Centre — Confidential"
                maxLength={256}
                style={{ fontSize: 12 }}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Advanced options — classification, audience, visibility filter, section toggles */}
      <div style={{ marginBottom: 'var(--space-4)' }}>
        <button
          type="button"
          onClick={() => setAdvancedOpen(o => !o)}
          style={{
            background: 'transparent', border: 'none', padding: 0,
            fontSize: 12, fontWeight: 700, textTransform: 'uppercase',
            letterSpacing: '0.08em', color: 'var(--muted)', cursor: 'pointer',
            display: 'flex', alignItems: 'center', gap: 6, marginBottom: 'var(--space-2)',
          }}
        >
          {advancedOpen ? '▼' : '▶'} Advanced options
        </button>

        {advancedOpen && (
          <div style={{
            background: 'var(--surface-2)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius)',
            padding: 'var(--space-3)',
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: 'var(--space-4)',
          }}>
            {/* Left: classification + audience + visibility */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              <div>
                <label className="field-label" htmlFor="rpt-class" style={{ marginBottom: 'var(--space-1)', display: 'block' }}>
                  Classification marking
                </label>
                <select
                  id="rpt-class"
                  className="select"
                  value={classification}
                  onChange={e => setClassification(e.target.value)}
                  style={{ width: '100%', fontSize: 12 }}
                >
                  <option value="">— inherit from incident TLP —</option>
                  {TLP_OPTIONS.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>

              <div>
                <label className="field-label" htmlFor="rpt-aud" style={{ marginBottom: 'var(--space-1)', display: 'block' }}>
                  Audience
                </label>
                <input
                  id="rpt-aud"
                  className="input"
                  value={audience}
                  onChange={e => setAudience(e.target.value)}
                  placeholder="e.g. CISO + Board"
                  maxLength={128}
                  style={{ fontSize: 12 }}
                />
              </div>

              {mode === 'executive' && (
                <label style={{ display: 'flex', alignItems: 'flex-start', gap: 8, fontSize: 12, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={includeInternalEvents}
                    onChange={e => setIncludeInternalEvents(e.target.checked)}
                    style={{ marginTop: 2, flexShrink: 0 }}
                  />
                  <span>
                    <div>Include internal-only events</div>
                    <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 2 }}>
                      Default: executive reports only show events flagged <code>external_safe</code>.
                      Override for full disclosure to your audience.
                    </div>
                  </span>
                </label>
              )}
            </div>

            {/* Right: section toggles */}
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 'var(--space-2)' }}>
                Include sections
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '4px 12px' }}>
                {[
                  ['overview',  'Overview'],
                  ['kpis',      'Key metrics'],
                  ['iocs',      'IOCs'],
                  ['entities',     'Entities'],
                  ['entity_graph', 'Entity graph (optional)'],
                  ['timeline',     'Timeline'],
                  ['actions',   'Respond actions'],
                  ['playbook',  'Playbook'],
                  ['evidence',  'Evidence'],
                  ['mitre',     'MITRE mapping'],
                  ['lessons',     'Lessons learned'],
                  ['remediation', 'Remediation plan'],
                  ['closure',     'Closure checklist'],
                ].map(([key, label]) => (
                  <label key={key} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={!!sections[key]}
                      onChange={() => toggleSection(key)}
                    />
                    <span>{label}</span>
                  </label>
                ))}
              </div>
              <button
                type="button"
                onClick={() => setSections(DEFAULT_SECTIONS)}
                style={{
                  marginTop: 'var(--space-2)',
                  background: 'transparent', border: 'none', padding: 0,
                  fontSize: 11, color: 'var(--accent)', cursor: 'pointer',
                }}
              >
                Reset to defaults
              </button>

              <div style={{
                marginTop: 'var(--space-3)',
                paddingTop: 'var(--space-2)',
                borderTop: '1px solid var(--border)',
              }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>
                  Appendix
                </div>
                <label style={{ display: 'flex', alignItems: 'flex-start', gap: 6, fontSize: 12, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={includeTimelineAppendix}
                    onChange={e => setIncludeTimelineAppendix(e.target.checked)}
                    style={{ marginTop: 2, flexShrink: 0 }}
                  />
                  <span>
                    <div>Appendix A — Timeline</div>
                    <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 2 }}>
                      Visual zig-zag spine appended after §14, for C-tier readers.
                    </div>
                  </span>
                </label>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="alert error" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {/* Generate actions */}
      <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap' }}>
        <button
          type="button"
          className="btn primary"
          onClick={() => generate('preview')}
          disabled={loading}
          style={{ fontSize: 14, padding: '8px 20px' }}
        >
          {loading ? 'Building report…' : 'Preview in new tab'}
        </button>
        <button
          type="button"
          className="btn ghost"
          onClick={() => generate('download')}
          disabled={loading}
        >
          Download HTML
        </button>
        <button
          type="button"
          className="btn ghost"
          onClick={showStructure}
          disabled={loading}
          title="Show the report structure with autogen-field placeholders"
        >
          Show structure
        </button>
        <span style={{ fontSize: 11, color: 'var(--dim)', marginLeft: 'var(--space-1)' }}>
          Self-contained HTML — open in browser and print / save as PDF
        </span>
      </div>

      {/* Tip */}
      <div style={{ marginTop: 'var(--space-4)', padding: 'var(--space-3)', background: 'var(--surface-2)', borderRadius: 'var(--radius)', fontSize: 12, color: 'var(--muted)', lineHeight: 1.6 }}>
        <strong style={{ color: 'var(--text)' }}>To save as PDF:</strong> Open the preview, then press{' '}
        <kbd style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 3, padding: '1px 5px', fontFamily: 'var(--font-mono)', fontSize: 11 }}>Ctrl+P</kbd>{' '}
        (Windows/Linux) or{' '}
        <kbd style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 3, padding: '1px 5px', fontFamily: 'var(--font-mono)', fontSize: 11 }}>⌘+P</kbd>{' '}
        (macOS), choose "Save as PDF" as the destination, and set margins to "None" or "Minimum" for best results.
      </div>

      {/* Report history — audit-grade re-download with SHA-256 + access reason */}
      <PISection title="Report History">
        <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 'var(--space-2)' }}>
          Every generated report is persisted with a SHA-256 integrity hash.
          Re-downloads require an audit-logged access reason.
        </div>
        {historyLoading ? (
          <div style={{ color: 'var(--muted)', fontSize: 12 }}>Loading…</div>
        ) : history.length === 0 ? (
          <div style={{ color: 'var(--dim)', fontSize: 12, fontStyle: 'italic' }}>
            No reports generated for this incident yet.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="settings-table" style={{ fontSize: 12 }}>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Layout</th>
                  <th>Classification</th>
                  <th>Generated</th>
                  <th>SHA-256</th>
                  <th>Size</th>
                  <th>Accesses</th>
                  <th style={{ textAlign: 'right' }}></th>
                </tr>
              </thead>
              <tbody>
                {history.map(r => (
                  <tr key={r.id}>
                    <td>
                      <span className="pill" style={{ fontSize: 10 }}>
                        {r.report_type === 'exec' ? 'Executive' : 'Full'}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}>
                      {r.template_id}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                      {r.classification}
                      {r.audience && <div style={{ color: 'var(--dim)', fontSize: 10 }}>{r.audience}</div>}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)', whiteSpace: 'nowrap' }}>
                      {new Date(r.generated_at).toISOString().replace('T', ' ').slice(0, 19) + 'Z'}
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn ghost"
                        title={`Click to copy:\n${r.sha256}`}
                        onClick={() => navigator.clipboard?.writeText(r.sha256)}
                        style={{ padding: '1px 6px', fontFamily: 'var(--font-mono)', fontSize: 10 }}
                      >{r.sha256.slice(0, 12)}…</button>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}>
                      {fmtBytes(r.file_size)}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)', textAlign: 'right' }}>
                      {r.access_count}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        type="button"
                        className="btn ghost"
                        style={{ fontSize: 11 }}
                        onClick={() => { setDownloadTarget(r); setAccessReason('') }}
                      >↓ Download</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </PISection>

      {/* Re-download modal — captures mandatory access reason */}
      {downloadTarget && (
        <div className="modal-backdrop" onClick={() => !downloading && setDownloadTarget(null)}>
          <div className="modal" style={{ maxWidth: 480 }} onClick={e => e.stopPropagation()}>
            <div className="modal-head">
              <h2>Download report</h2>
              <button
                type="button"
                className="modal-close"
                onClick={() => setDownloadTarget(null)}
                disabled={downloading}
                aria-label="Close"
              >×</button>
            </div>
            <div className="modal-body">
              <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 'var(--space-3)' }}>
                Provide a reason for accessing this report. The reason is
                audit-logged alongside your username and IP.
              </div>
              <div style={{
                fontSize: 11, color: 'var(--dim)', fontFamily: 'var(--font-mono)',
                background: 'var(--surface-2)', padding: 'var(--space-2)',
                borderRadius: 'var(--radius-sm)', marginBottom: 'var(--space-3)',
                wordBreak: 'break-all',
              }}>
                {downloadTarget.report_type === 'exec' ? 'Executive Summary' : 'Full Report'}
                {' · '}
                {downloadTarget.classification}
                {' · '}
                SHA-256: {downloadTarget.sha256.slice(0, 24)}…
              </div>
              <div className="field">
                <label className="field-label" htmlFor="rpt-reason">Access reason *</label>
                <textarea
                  id="rpt-reason"
                  className="input"
                  rows={3}
                  value={accessReason}
                  onChange={e => setAccessReason(e.target.value)}
                  placeholder="e.g. Preparing executive briefing for CISO meeting"
                  autoFocus
                />
              </div>
            </div>
            <div className="modal-foot">
              <button
                type="button"
                className="btn ghost"
                onClick={() => setDownloadTarget(null)}
                disabled={downloading}
              >Cancel</button>
              <button
                type="button"
                className="btn primary"
                onClick={confirmDownload}
                disabled={downloading || !accessReason.trim()}
              >{downloading ? 'Downloading…' : '↓ Download'}</button>
            </div>
          </div>
        </div>
      )}

      <LePackage inc={inc} />
    </div>
  )
}

function fmtBytes(n) {
  if (n == null) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`
  return `${(n / (1024 * 1024)).toFixed(2)} MiB`
}
