import { useCallback, useEffect, useRef, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../api/client.js'
import LocalDateTimePicker from '../../components/LocalDateTimePicker.jsx'
import { formatLocal } from '../../lib/datetime.js'

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
// The default anchor is the incident's Detected time; each selected regulation can
// have its own anchor (awareness differs between GDPR Art. 33, NIS2 Art. 23 and DORA).
// The API defaults to detected_at too, returns 422 anchor_required when there is no
// anchor at all, and skips template rows the incident already has.

function InitPanel({ inc, onDone }) {
  const [selected, setSelected]     = useState(['GDPR'])
  const [breachAt, setBreachAt]     = useState(() => inc.detected_at || '')  // canonical UTC ISO
  const [own, setOwn]               = useState({})   // regulation → own anchor ('' = default)
  const [loading, setLoading]       = useState(false)
  const [error,   setError]         = useState(null)
  const [info,    setInfo]          = useState(null)

  function toggleReg(reg) {
    setSelected(prev =>
      prev.includes(reg) ? prev.filter(r => r !== reg) : [...prev, reg]
    )
  }

  async function init() {
    if (!selected.length) { setError('Select at least one regulation.'); return }
    setLoading(true); setError(null); setInfo(null)
    try {
      const anchors = Object.fromEntries(selected.filter(r => own[r]).map(r => [r, own[r]]))
      const payload = { regulations: selected, anchors }
      if (breachAt) payload.breach_detected_at = breachAt
      const created = await api.initializeDeadlines(inc.id, payload)
      if (Array.isArray(created) && created.length === 0) {
        setInfo('Nothing new: the selected regulations are already initialised.')
      } else {
        onDone()
      }
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
        Select the applicable regulations and check the anchor (when the organisation became aware of the breach). Notification deadlines are calculated from it.
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
        <label htmlFor="legal-anchor" style={{ fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--muted)', display: 'block', marginBottom: 'var(--space-1)' }}>
          Anchor (breach awareness)
        </label>
        <div style={{ maxWidth: 260 }}>
          <LocalDateTimePicker id="legal-anchor" value={breachAt} onChange={setBreachAt} required />
        </div>
        <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 4 }}>
          {inc.detected_at
            ? `Defaults to the incident's Detected time (${formatLocal(inc.detected_at)}). Used for every regulation without its own anchor.`
            : 'This incident has no Detected time: enter the anchor here, or set Detected on Details.'}
        </div>
      </div>

      {selected.length > 0 && (
        <div style={{ marginBottom: 'var(--space-3)' }}>
          <div style={{ fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--muted)', marginBottom: 'var(--space-1)' }}>
            Own anchor per regulation (optional)
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
            {REGULATIONS.filter(r => selected.includes(r)).map(reg => (
              <div key={reg} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                <label htmlFor={`legal-anchor-${reg}`} style={{ width: 72, fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text)' }}>
                  {REG_LABELS[reg]}
                </label>
                <div style={{ maxWidth: 260, flex: 1 }}>
                  <LocalDateTimePicker id={`legal-anchor-${reg}`} value={own[reg] || ''} clearable hint={false}
                    placeholder="Same as the anchor above"
                    onChange={v => setOwn(o => ({ ...o, [reg]: v }))} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {error && (
        <div className="alert error" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}
      {info && (
        <div className="alert info" role="status" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">i</span><span>{info}</span>
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

// ── Waive / delete / re-anchor dialog ──────────────────────────────────────────
// Each needs a written justification of at least REASON_MIN characters (the API
// checks it too: 422 notes_required / reason_required). Errors stay in the dialog.

const REASON_MIN = 10
const ACTIONS = {
  waive: {
    title: 'Waive deadline', label: 'Justification', button: 'Waive',
    hint: 'Why this obligation does not apply, and on whose authority. Saved as the completion notes and in the audit log.',
    placeholder: 'e.g. DPO assessment: data encrypted at rest, no risk to individuals (Art. 34(3)(a))…',
  },
  delete: {
    title: 'Delete deadline', label: 'Reason', button: 'Delete deadline',
    hint: 'The audit log keeps the reason and a full copy of the deadline.',
    placeholder: 'e.g. Duplicate of the GDPR Art. 33 row created by an earlier initialise…',
  },
  reanchor: {
    title: 'Re-anchor deadline', label: 'Reason', button: 'Re-anchor',
    hint: 'The deadline is recalculated from the new anchor. The old and new times and the reason go into the audit log.',
    placeholder: 'e.g. Awareness confirmed by the DPO at 09:12, not at detection…',
  },
}

function DeadlineActionModal({ mode, d, onConfirm, onClose }) {
  const cfg = ACTIONS[mode]
  const [text, setText]     = useState('')
  const [anchor, setAnchor] = useState(d.breach_detected_at || '')
  const [busy, setBusy]     = useState(false)
  const [error, setError]   = useState(null)
  const n = text.trim().length

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  const submit = async (e) => {
    e.preventDefault()
    setError(null); setBusy(true)
    try {
      await onConfirm(text.trim(), anchor)
    } catch (err) {
      setError(err.message || 'Request failed.')
      setBusy(false)
    }
    // success path: parent unmounts the dialog
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="legal-action-title">
        <div className="modal-head">
          <h2 id="legal-action-title">{cfg.title}</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <form onSubmit={submit}>
          <div className="modal-body">
            <div className="form">
              <p style={{ margin: 0, color: 'var(--text)', fontSize: 14, lineHeight: 1.6 }}>
                <b>{REG_LABELS[d.regulation] || d.regulation}</b>{(d.article_label || d.article) ? ` ${d.article_label || d.article}` : ''}: {d.obligation}
              </p>
              {mode === 'reanchor' && (
                <div className="field">
                  <label className="field-label" htmlFor="legal-reanchor-at">New anchor</label>
                  <LocalDateTimePicker id="legal-reanchor-at" value={anchor} onChange={setAnchor} required />
                  <span className="field-hint">Currently {formatLocal(d.breach_detected_at)}; due {formatLocal(d.deadline_at)}.</span>
                </div>
              )}
              <div className="field">
                <label className="field-label" htmlFor="legal-action-reason">{cfg.label}</label>
                <textarea id="legal-action-reason" className="input" rows={4} maxLength={2000} required autoFocus
                          placeholder={cfg.placeholder} value={text} onChange={e => setText(e.target.value)} />
                <span className="field-hint">
                  {cfg.hint}{n < REASON_MIN ? ` At least ${REASON_MIN} characters (${n} so far).` : ''}
                </span>
              </div>
              {error && (
                <div className="alert error" role="alert">
                  <span className="alert-icon">!</span><span>{error}</span>
                </div>
              )}
            </div>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button type="submit" className="btn primary"
                    disabled={busy || n < REASON_MIN || (mode === 'reanchor' && !anchor)}>
              {busy ? 'Saving…' : cfg.button}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Deadline card ──────────────────────────────────────────────────────────────

function DeadlineCard({ d, incId, isClosed, onUpdated, onDeleted }) {
  const [expanded,  setExpanded]  = useState(false)
  const [notesDraft, setNotesDraft] = useState(d.completion_notes || '')
  // Follow the server's notes when they change (e.g. a waiver justification saved via the dialog).
  useEffect(() => { setNotesDraft(d.completion_notes || '') }, [d.completion_notes])
  const [saving,    setSaving]    = useState(false)
  const [error,     setError]     = useState(null)
  const [action,    setAction]    = useState(null)   // 'waive' | 'delete' | 'reanchor' | null

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

  // Waive / delete / re-anchor: confirmed in DeadlineActionModal with a justification.
  // Errors throw back into the dialog, which stays open.
  async function confirmAction(text, anchor) {
    if (action === 'delete') {
      await api.deleteDeadline(incId, d.id, text)
      setAction(null)
      onDeleted(d.id)
      return
    }
    const payload = action === 'waive'
      ? { status: 'waived', completion_notes: text }
      : { breach_detected_at: anchor, reason: text }
    const updated = await api.updateDeadline(incId, d.id, payload)
    setAction(null)
    onUpdated(updated)
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

        {/* Article (display label; NIS2 rows show their Art. 23(4) point) */}
        {(d.article_label || d.article) && (
          <span className="legal-article" style={{ fontSize: 11, color: 'var(--dim)', flexShrink: 0, alignSelf: 'center' }}>
            {d.article_label || d.article}
          </span>
        )}

        {/* Mandatory / internal-target badge */}
        {d.is_mandatory && (
          <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--high)', marginLeft: 'auto', flexShrink: 0 }}>
            MANDATORY
          </span>
        )}
        {d.internal_target && (
          <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--muted)', marginLeft: d.is_mandatory ? 0 : 'auto', flexShrink: 0 }}
                title="The law sets no fixed window (&quot;without undue delay&quot;): this time is an internal target, not a statutory deadline.">
            INTERNAL TARGET
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
            {d.internal_target ? 'Internal target' : 'Deadline'}
          </div>
          <span className="legal-deadline-at" style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text)' }}>
            {formatLocal(d.deadline_at)}
          </span>
        </div>
        <div>
          <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--dim)', marginBottom: 2 }}>
            Anchor{d.deadline_months ? ` + ${d.deadline_months} calendar month${d.deadline_months > 1 ? 's' : ''}` : ` + ${d.deadline_hours}h`}
          </div>
          <span className="legal-anchor-at" style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--muted)' }}>
            {formatLocal(d.breach_detected_at)}
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
            onClick={() => setAction('waive')} disabled={saving}>
            Waive
          </button>
        )}
        {done && (
          <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '3px 8px' }}
            onClick={() => setStatus('pending')} disabled={saving}>
            Reopen
          </button>
        )}
        {!isClosed && (
          <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '3px 8px' }}
            onClick={() => setAction('reanchor')} disabled={saving}>
            Re-anchor
          </button>
        )}
        {!isClosed && (
          <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '3px 8px', color: 'var(--crit)', marginLeft: 'auto' }}
            onClick={() => setAction('delete')} disabled={saving}>
            Delete
          </button>
        )}
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

      {action && (
        <DeadlineActionModal mode={action} d={d} onConfirm={confirmAction} onClose={() => setAction(null)} />
      )}
    </div>
  )
}

// ── Add custom deadline modal ──────────────────────────────────────────────────

function AddDeadlineModal({ inc, onCreated, onClose }) {
  const [form, setForm] = useState({
    regulation: 'GDPR',
    article: '',
    obligation: '',
    recipient: '',
    deadline_hours: 72,
    breach_detected_at: inc.detected_at || '',   // canonical UTC ISO; defaults to Detected
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
        deadline_hours: parseInt(form.deadline_hours, 10),
        article: form.article.trim() || null,
        recipient: form.recipient.trim() || null,
        notes: form.notes.trim() || null,
      }
      if (!payload.breach_detected_at) delete payload.breach_detected_at   // API: incident detected_at
      const created = await api.createDeadline(inc.id, payload)
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
              <label className="field-label">Deadline (hours from anchor)</label>
              <input type="number" className="input" min={1} value={form.deadline_hours} onChange={e => set('deadline_hours', e.target.value)} />
            </div>
            <div className="field">
              <label className="field-label" htmlFor="legal-add-anchor">Anchor (breach awareness)</label>
              <LocalDateTimePicker id="legal-add-anchor" value={form.breach_detected_at} onChange={v => set('breach_detected_at', v)} required />
              <span className="field-hint">{inc.detected_at ? "Defaults to the incident's Detected time." : 'The incident has no Detected time: enter the anchor.'}</span>
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
  const { inc, isClosed, bumpLegal } = useOutletContext()

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

  // After any change: refetch (a change can move other rows too — completing the NIS2 72h
  // notification re-anchors the NIS2 final report) and refresh the header clock chips.
  function changed() {
    load()
    bumpLegal?.()
  }

  function onUpdated(updated) {
    setDeadlines(prev => prev.map(d => d.id === updated.id ? updated : d))
    changed()
  }

  function onDeleted(id) {
    setDeadlines(prev => prev.filter(d => d.id !== id))
    changed()
  }

  function onCreated(d) {
    setDeadlines(prev => [...prev, d].sort((a, b) => new Date(a.deadline_at) - new Date(b.deadline_at)))
    setShowAdd(false)
    changed()
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
          {!isClosed && (
            <button type="button" className="btn ghost" style={{ fontSize: 12 }} onClick={() => setShowAdd(true)}>
              + Add custom
            </button>
          )}
        </div>
      </div>

      {isClosed && (
        <div className="alert info" role="status" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">i</span>
          <span>The incident is closed. Deadlines can still be completed, waived or annotated; adding, deleting and re-anchoring need the incident re-opened.</span>
        </div>
      )}

      {deadlines.length === 0 ? (
        isClosed ? <div className="panel-empty">No regulatory deadlines.</div> : <InitPanel inc={inc} onDone={changed} />
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
                    isClosed={isClosed}
                    onUpdated={onUpdated}
                    onDeleted={onDeleted}
                  />
                ))}
              </div>
            </div>
          ))}

          {!isClosed && (
            <div style={{ marginTop: 'var(--space-2)' }}>
              {showMoreInit ? (
                <InitPanel inc={inc} onDone={() => { setShowMoreInit(false); changed() }} />
              ) : (
                <button type="button" className="btn ghost" style={{ fontSize: 12 }} onClick={() => setShowMoreInit(true)}>
                  + Initialize additional regulation
                </button>
              )}
            </div>
          )}
        </div>
      )}

      {showAdd && (
        <AddDeadlineModal
          inc={inc}
          onCreated={onCreated}
          onClose={() => setShowAdd(false)}
        />
      )}
    </section>
  )
}
