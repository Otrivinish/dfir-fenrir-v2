import { useCallback, useEffect, useRef, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../api/client.js'
import UtcDateTimeInput from '../../components/UtcDateTimeInput.jsx'

// ── Constants ──────────────────────────────────────────────────────────────────

const REGULATIONS = ['GDPR', 'NIS2', 'DORA', 'PCI_DSS', 'HIPAA', 'CCPA']

const REG_LABELS = {
  GDPR:    'GDPR',
  NIS2:    'NIS2',
  DORA:    'DORA',
  PCI_DSS: 'PCI-DSS',
  HIPAA:   'HIPAA',
  CCPA:    'CCPA',
}

// Colour accents per regulation (CSS token–compatible).
const REG_COLORS = {
  GDPR:    '#3b82f6',
  NIS2:    '#8b5cf6',
  DORA:    '#f59e0b',
  PCI_DSS: '#ef4444',
  HIPAA:   '#10b981',
  CCPA:    '#06b6d4',
}

const VALID_STATUSES = ['pending', 'in_progress', 'completed', 'waived']
const STATUS_LABELS  = { pending: 'Pending', in_progress: 'In Progress', completed: 'Completed', waived: 'Waived' }
const STATUS_COLORS  = {
  pending:     'var(--muted)',
  in_progress: 'var(--med)',
  completed:   'var(--ok)',
  waived:      'var(--dim)',
}

// ── Countdown helpers ──────────────────────────────────────────────────────────

function countdown(deadline_at) {
  const diff = new Date(deadline_at).getTime() - Date.now()
  if (diff <= 0) return null
  const totalSecs = Math.floor(diff / 1000)
  const d = Math.floor(totalSecs / 86400)
  const h = Math.floor((totalSecs % 86400) / 3600)
  const m = Math.floor((totalSecs % 3600) / 60)
  const s = totalSecs % 60
  return { d, h, m, s }
}

function pad(n) { return String(n).padStart(2, '0') }

function CountdownDisplay({ deadline_at, status, regColor }) {
  const [tick, setTick] = useState(0)
  const timerRef = useRef(null)

  useEffect(() => {
    timerRef.current = setInterval(() => setTick(t => t + 1), 1000)
    return () => clearInterval(timerRef.current)
  }, [])

  if (status === 'completed') return <span style={{ color: 'var(--ok)', fontFamily: 'var(--font-mono)', fontSize: 16 }}>Completed</span>
  if (status === 'waived')    return <span style={{ color: 'var(--dim)', fontFamily: 'var(--font-mono)', fontSize: 16 }}>Waived</span>

  const ct = countdown(deadline_at)
  if (!ct) {
    return <span style={{ color: 'var(--crit)', fontFamily: 'var(--font-mono)', fontSize: 16, fontWeight: 700 }}>OVERDUE</span>
  }

  const timerColor = (ct.d === 0 && ct.h < 6) ? 'var(--high)'
                   : (regColor || 'var(--text)')

  return (
    <span style={{ fontFamily: 'var(--font-mono)', color: timerColor }}>
      {ct.d > 0 && <span style={{ fontSize: 13, fontWeight: 400, color: 'var(--muted)' }}>{ct.d}d </span>}
      <span style={{ fontSize: 18, fontWeight: 700 }}>{pad(ct.h)}:{pad(ct.m)}:{pad(ct.s)}</span>
    </span>
  )
}

// ── Initialize panel ──────────────────────────────────────────────────────────

function InitPanel({ incId, onDone }) {
  const [selected, setSelected]     = useState(['GDPR'])
  const [breachAt, setBreachAt]     = useState(() => new Date().toISOString())  // canonical UTC ISO
  const [loading, setLoading]       = useState(false)
  const [error,   setError]         = useState(null)

  function toggleReg(reg) {
    setSelected(prev =>
      prev.includes(reg) ? prev.filter(r => r !== reg) : [...prev, reg]
    )
  }

  async function init() {
    if (!selected.length) { setError('Select at least one regulation.'); return }
    if (!breachAt) { setError('Breach detected-at is required.'); return }
    setLoading(true); setError(null)
    try {
      await api.initializeDeadlines(incId, { regulations: selected, breach_detected_at: breachAt })
      onDone()
    } catch (e) {
      setError(e.message || 'Failed to initialize')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      background: 'var(--surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius-lg)',
      padding: 'var(--space-4)',
      maxWidth: 640,
    }}>
      <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 'var(--space-1)' }}>
        Initialize Regulatory Deadlines
      </div>
      <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 'var(--space-3)' }}>
        Select the applicable regulations and set the breach detection time. Notification deadlines will be calculated automatically.
      </div>

      <div style={{ marginBottom: 'var(--space-3)' }}>
        <div style={{ fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--muted)', marginBottom: 'var(--space-2)' }}>
          Applicable Regulations
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
          {REGULATIONS.map(reg => {
            const on = selected.includes(reg)
            return (
              <button
                key={reg}
                type="button"
                onClick={() => toggleReg(reg)}
                style={{
                  padding: '5px 14px',
                  borderRadius: 'var(--radius)',
                  border: `2px solid ${on ? REG_COLORS[reg] : 'var(--border)'}`,
                  background: on ? `${REG_COLORS[reg]}22` : 'var(--surface-2)',
                  color: on ? REG_COLORS[reg] : 'var(--muted)',
                  fontWeight: on ? 700 : 400,
                  fontSize: 13,
                  cursor: 'pointer',
                  transition: 'all .12s',
                }}
              >
                {REG_LABELS[reg]}
              </button>
            )
          })}
        </div>
      </div>

      <div style={{ marginBottom: 'var(--space-3)' }}>
        <label style={{ fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--muted)', display: 'block', marginBottom: 'var(--space-1)' }}>
          Breach Detected At
        </label>
        <div style={{ maxWidth: 260 }}>
          <UtcDateTimeInput value={breachAt} onChange={setBreachAt} />
        </div>
        <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 4 }}>
          All deadlines are calculated from this timestamp.
        </div>
      </div>

      {error && (
        <div className="alert error" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      <button
        type="button"
        className="btn primary"
        onClick={init}
        disabled={loading || !selected.length}
      >
        {loading ? 'Initializing…' : 'Initialize deadlines'}
      </button>
    </div>
  )
}

// ── Deadline card ──────────────────────────────────────────────────────────────

function DeadlineCard({ d, incId, onUpdated, onDeleted }) {
  const [expanded,  setExpanded]  = useState(false)
  const [notesDraft, setNotesDraft] = useState(d.completion_notes || '')
  const [saving,    setSaving]    = useState(false)
  const [error,     setError]     = useState(null)

  const overdue = d.is_overdue
  const done    = d.status === 'completed' || d.status === 'waived'
  const regColor = REG_COLORS[d.regulation] || 'var(--accent)'

  async function setStatus(newStatus) {
    setSaving(true); setError(null)
    try {
      const payload = { status: newStatus }
      if (newStatus === 'completed' && notesDraft.trim()) {
        payload.completion_notes = notesDraft.trim()
      }
      const updated = await api.updateDeadline(incId, d.id, payload)
      onUpdated(updated)
      setExpanded(false)
    } catch (e) {
      setError(e.message || 'Update failed')
    } finally {
      setSaving(false)
    }
  }

  async function saveNotes() {
    setSaving(true); setError(null)
    try {
      const updated = await api.updateDeadline(incId, d.id, { completion_notes: notesDraft.trim() || null })
      onUpdated(updated)
      setExpanded(false)
    } catch (e) {
      setError(e.message || 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  async function remove() {
    if (!confirm('Delete this deadline?')) return
    try {
      await api.deleteDeadline(incId, d.id)
      onDeleted(d.id)
    } catch (e) {
      setError(e.message || 'Delete failed')
    }
  }

  return (
    <div style={{
      background: 'var(--surface)',
      border: `1px solid ${overdue && !done ? 'var(--crit)' : 'var(--border)'}`,
      borderLeft: `4px solid ${overdue && !done ? 'var(--crit)' : regColor}`,
      borderRadius: 'var(--radius)',
      padding: 'var(--space-3)',
      opacity: done ? 0.7 : 1,
    }}>
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
        {/* Reg badge */}
        <span style={{
          fontSize: 11,
          fontWeight: 700,
          padding: '2px 8px',
          borderRadius: 3,
          background: `${regColor}22`,
          color: regColor,
          flexShrink: 0,
          fontFamily: 'var(--font-mono)',
        }}>
          {REG_LABELS[d.regulation] || d.regulation}
        </span>

        {/* Article */}
        {d.article && (
          <span style={{ fontSize: 11, color: 'var(--dim)', flexShrink: 0, alignSelf: 'center' }}>
            {d.article}
          </span>
        )}

        {/* Mandatory badge */}
        {d.is_mandatory && (
          <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--high)', marginLeft: 'auto', flexShrink: 0 }}>
            MANDATORY
          </span>
        )}
      </div>

      {/* Obligation */}
      <div style={{ fontWeight: 600, fontSize: 13, marginTop: 'var(--space-1)', color: 'var(--text)' }}>
        {d.obligation}
      </div>

      {/* Recipient */}
      {d.recipient && (
        <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>
          To: {d.recipient}
        </div>
      )}

      {/* Countdown + status row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginTop: 'var(--space-2)', flexWrap: 'wrap' }}>
        <div>
          <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--dim)', marginBottom: 2 }}>
            Time remaining
          </div>
          <CountdownDisplay deadline_at={d.deadline_at} status={d.status} regColor={regColor} />
        </div>
        <div>
          <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--dim)', marginBottom: 2 }}>
            Deadline
          </div>
          <span style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text)' }}>
            {new Date(d.deadline_at).toLocaleString()}
          </span>
        </div>
        <div style={{ marginLeft: 'auto' }}>
          <span style={{ fontSize: 12, fontWeight: 600, color: STATUS_COLORS[d.status] }}>
            {STATUS_LABELS[d.status] || d.status}
          </span>
        </div>
      </div>

      {/* Notes */}
      {d.notes && (
        <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 'var(--space-2)', padding: 'var(--space-2)', background: 'var(--bg)', borderRadius: 'var(--radius-sm)', lineHeight: 1.5 }}>
          {d.notes}
        </div>
      )}

      {/* Actions row */}
      <div style={{ display: 'flex', gap: 'var(--space-1)', marginTop: 'var(--space-2)', flexWrap: 'wrap' }}>
        {!done && d.status !== 'in_progress' && (
          <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '3px 8px' }}
            onClick={() => setStatus('in_progress')} disabled={saving}>
            Mark In Progress
          </button>
        )}
        {!done && (
          <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '3px 8px', color: 'var(--ok)' }}
            onClick={() => setExpanded(x => !x)} disabled={saving}>
            {expanded ? 'Cancel' : 'Mark Completed'}
          </button>
        )}
        {!done && (
          <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '3px 8px', color: 'var(--dim)' }}
            onClick={() => setStatus('waived')} disabled={saving}>
            Waive
          </button>
        )}
        {done && (
          <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '3px 8px' }}
            onClick={() => setStatus('pending')} disabled={saving}>
            Reopen
          </button>
        )}
        <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '3px 8px', color: 'var(--crit)', marginLeft: 'auto' }}
          onClick={remove} disabled={saving}>
          Delete
        </button>
      </div>

      {/* Completion notes panel */}
      {expanded && (
        <div style={{ marginTop: 'var(--space-2)', paddingTop: 'var(--space-2)', borderTop: '1px solid var(--border)' }}>
          <label style={{ fontSize: 12, color: 'var(--muted)', display: 'block', marginBottom: 'var(--space-1)' }}>
            Completion notes (optional)
          </label>
          <textarea
            autoFocus
            className="input"
            rows={3}
            value={notesDraft}
            onChange={e => setNotesDraft(e.target.value)}
            maxLength={4096}
            style={{ width: '100%', fontSize: 12, resize: 'vertical', marginBottom: 'var(--space-2)' }}
            placeholder="Reference numbers, timestamps, contact names…"
          />
          <div style={{ display: 'flex', gap: 'var(--space-1)' }}>
            <button type="button" className="btn primary" style={{ fontSize: 12 }}
              onClick={() => setStatus('completed')} disabled={saving}>
              {saving ? 'Saving…' : 'Confirm Completed'}
            </button>
            <button type="button" className="btn ghost" style={{ fontSize: 12 }}
              onClick={saveNotes} disabled={saving}>
              Save notes only
            </button>
          </div>
        </div>
      )}

      {error && (
        <div style={{ fontSize: 12, color: 'var(--crit)', marginTop: 'var(--space-1)' }}>{error}</div>
      )}
    </div>
  )
}

// ── Add custom deadline modal ──────────────────────────────────────────────────

function AddDeadlineModal({ incId, onCreated, onClose }) {
  const [form, setForm] = useState({
    regulation: 'GDPR',
    article: '',
    obligation: '',
    recipient: '',
    deadline_hours: 72,
    breach_detected_at: new Date().toISOString(),   // canonical UTC ISO
    is_mandatory: true,
    notes: '',
  })
  const [saving, setSaving] = useState(false)
  const [error,  setError]  = useState(null)

  function set(k, v) { setForm(f => ({ ...f, [k]: v })) }

  async function submit(e) {
    e.preventDefault()
    if (!form.obligation.trim()) { setError('Obligation is required.'); return }
    setSaving(true); setError(null)
    try {
      const payload = {
        ...form,
        breach_detected_at: form.breach_detected_at,
        deadline_hours: parseInt(form.deadline_hours, 10),
        article: form.article.trim() || null,
        recipient: form.recipient.trim() || null,
        notes: form.notes.trim() || null,
      }
      const created = await api.createDeadline(incId, payload)
      onCreated(created)
    } catch (e) {
      setError(e.message || 'Failed to create')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="modal-overlay">
      <div className="modal" style={{ maxWidth: 540 }}>
        <div className="modal-head">
          <span className="modal-title">Add Custom Deadline</span>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close">✕</button>
        </div>
        <form onSubmit={submit} style={{ padding: 'var(--space-4)', display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-3)' }}>
            <div className="field">
              <label className="field-label">Regulation</label>
              <select className="select" value={form.regulation} onChange={e => set('regulation', e.target.value)}>
                {REGULATIONS.map(r => <option key={r} value={r}>{REG_LABELS[r]}</option>)}
                <option value="OTHER">Other</option>
              </select>
            </div>
            <div className="field">
              <label className="field-label">Article / Reference</label>
              <input className="input" value={form.article} onChange={e => set('article', e.target.value)} maxLength={128} placeholder="e.g. Article 33" />
            </div>
          </div>

          <div className="field">
            <label className="field-label">Obligation</label>
            <input className="input" value={form.obligation} onChange={e => set('obligation', e.target.value)} maxLength={512} required placeholder="Describe the notification obligation…" />
          </div>

          <div className="field">
            <label className="field-label">Recipient</label>
            <input className="input" value={form.recipient} onChange={e => set('recipient', e.target.value)} maxLength={256} placeholder="Who receives the notification?" />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-3)' }}>
            <div className="field">
              <label className="field-label">Deadline (hours from breach)</label>
              <input type="number" className="input" min={1} value={form.deadline_hours} onChange={e => set('deadline_hours', e.target.value)} />
            </div>
            <div className="field">
              <label className="field-label">Breach Detected At (UTC)</label>
              <UtcDateTimeInput value={form.breach_detected_at} onChange={v => set('breach_detected_at', v)} />
            </div>
          </div>

          <div className="field">
            <label className="field-label">Notes</label>
            <textarea className="input" rows={2} value={form.notes} onChange={e => set('notes', e.target.value)} maxLength={4096} placeholder="Guidance, conditions, exceptions…" style={{ resize: 'vertical' }} />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <input type="checkbox" id="is-mandatory" checked={form.is_mandatory} onChange={e => set('is_mandatory', e.target.checked)} />
            <label htmlFor="is-mandatory" style={{ fontSize: 13, cursor: 'pointer' }}>Mandatory obligation</label>
          </div>

          {error && (
            <div className="alert error"><span className="alert-icon">!</span><span>{error}</span></div>
          )}

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 'var(--space-2)' }}>
            <button type="button" className="btn ghost" onClick={onClose} disabled={saving}>Cancel</button>
            <button type="submit" className="btn primary" disabled={saving}>{saving ? 'Saving…' : 'Add deadline'}</button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Main Legal page ────────────────────────────────────────────────────────────

export default function Legal() {
  const { inc } = useOutletContext()

  const [deadlines,    setDeadlines]    = useState([])
  const [loading,      setLoading]      = useState(true)
  const [error,        setError]        = useState(null)
  const [showAdd,      setShowAdd]      = useState(false)
  const [showMoreInit, setShowMoreInit] = useState(false)

  const load = useCallback(async () => {
    setError(null)
    try {
      const rows = await api.listDeadlines(inc.id)
      setDeadlines(rows)
    } catch (e) {
      setError(e.message || 'Failed to load deadlines')
    } finally {
      setLoading(false)
    }
  }, [inc.id])

  useEffect(() => { load() }, [load])

  function onUpdated(updated) {
    setDeadlines(prev => prev.map(d => d.id === updated.id ? updated : d))
  }

  function onDeleted(id) {
    setDeadlines(prev => prev.filter(d => d.id !== id))
  }

  function onCreated(d) {
    setDeadlines(prev => [...prev, d].sort((a, b) => new Date(a.deadline_at) - new Date(b.deadline_at)))
    setShowAdd(false)
  }

  if (loading) return <div className="panel"><div className="panel-empty">Loading…</div></div>

  if (error) return (
    <div className="panel">
      <div className="alert error" role="alert">
        <span className="alert-icon">!</span><span>{error}</span>
      </div>
    </div>
  )

  // Group by regulation for visual separation
  const grouped = {}
  for (const d of deadlines) {
    if (!grouped[d.regulation]) grouped[d.regulation] = []
    grouped[d.regulation].push(d)
  }

  const overdueCount = deadlines.filter(d => d.is_overdue).length

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">Regulatory Deadlines</h2>
        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
          {overdueCount > 0 && (
            <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--crit)', padding: '3px 10px', border: '1px solid var(--crit)', borderRadius: 'var(--radius)' }}>
              {overdueCount} OVERDUE
            </span>
          )}
          <button type="button" className="btn ghost" style={{ fontSize: 12 }} onClick={() => setShowAdd(true)}>
            + Add custom
          </button>
        </div>
      </div>

      {deadlines.length === 0 ? (
        <InitPanel incId={inc.id} onDone={load} />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          {Object.entries(grouped).map(([reg, items]) => (
            <div key={reg}>
              <div style={{
                fontSize: 11,
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
                color: REG_COLORS[reg] || 'var(--muted)',
                marginBottom: 'var(--space-2)',
                borderBottom: `1px solid ${REG_COLORS[reg] || 'var(--border)'}44`,
                paddingBottom: 'var(--space-1)',
              }}>
                {REG_LABELS[reg] || reg}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                {items.sort((a, b) => new Date(a.deadline_at) - new Date(b.deadline_at)).map(d => (
                  <DeadlineCard
                    key={d.id}
                    d={d}
                    incId={inc.id}
                    onUpdated={onUpdated}
                    onDeleted={onDeleted}
                  />
                ))}
              </div>
            </div>
          ))}

          <div style={{ marginTop: 'var(--space-2)' }}>
            {showMoreInit ? (
              <InitPanel incId={inc.id} onDone={() => { setShowMoreInit(false); load() }} />
            ) : (
              <button type="button" className="btn ghost" style={{ fontSize: 12 }} onClick={() => setShowMoreInit(true)}>
                + Initialize additional regulation
              </button>
            )}
          </div>
        </div>
      )}

      {showAdd && (
        <AddDeadlineModal
          incId={inc.id}
          onCreated={onCreated}
          onClose={() => setShowAdd(false)}
        />
      )}
    </section>
  )
}
