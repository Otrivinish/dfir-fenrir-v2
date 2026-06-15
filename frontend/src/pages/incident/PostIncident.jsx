import { useCallback, useEffect, useRef, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../api/client.js'
import { formatLocal, formatLocalShort } from '../../lib/datetime.js'
import { MITRE_TACTICS, tacticColor } from '../../lib/mitre.js'
import Analytics from './post_incident/Analytics.jsx'
import Reports from './post_incident/Reports.jsx'

// ─── Tab navigation ───────────────────────────────────────────────────────────

const TABS = ['Analytics', 'Closure Checklist', 'Lessons Learned', 'Attack Chain', 'Reports']

// ─── Closure Checklist ────────────────────────────────────────────────────────

function ClosureChecklist({ inc }) {
  const isClosed = inc?.status === 'closed'
  const [items,   setItems]   = useState([])
  const [users,   setUsers]   = useState([])
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)
  const [busy,    setBusy]    = useState({})
  const [adding,    setAdding]    = useState(false)
  const [newLabel,  setNewLabel]  = useState('')
  const [creating,  setCreating]  = useState(false)

  const load = useCallback(async () => {
    try {
      const [data, assignable] = await Promise.all([
        api.listClosureChecklist(inc.id),
        api.listAssignableUsers(),
      ])
      setItems(data.items)
      setUsers(assignable)
    } catch (e) {
      setError(e.message || 'Failed to load checklist')
    } finally {
      setLoading(false)
    }
  }, [inc.id])

  useEffect(() => { load() }, [load])

  async function toggle(item) {
    if (busy[item.id] || isClosed) return
    setBusy(b => ({ ...b, [item.id]: true }))
    try {
      const updated = await api.toggleClosureItem(inc.id, item.id, !item.checked)
      setItems(prev => prev.map(i => i.id === updated.id ? updated : i))
    } catch {
      // leave state as-is on error
    } finally {
      setBusy(b => { const n = { ...b }; delete n[item.id]; return n })
    }
  }

  async function patchMeta(item, payload) {
    setBusy(b => ({ ...b, [item.id]: true }))
    try {
      const updated = await api.patchChecklistMeta(inc.id, item.id, payload)
      setItems(prev => prev.map(i => i.id === updated.id ? updated : i))
    } catch {
      // leave state as-is on error
    } finally {
      setBusy(b => { const n = { ...b }; delete n[item.id]; return n })
    }
  }

  async function createItem() {
    const label = newLabel.trim()
    if (!label || creating) return
    setCreating(true)
    try {
      const created = await api.createClosureItem(inc.id, label)
      setItems(prev => [...prev, created])
      setNewLabel('')
      setAdding(false)
    } catch (e) {
      setError(e.message || 'Failed to add item')
    } finally {
      setCreating(false)
    }
  }

  async function deleteItem(item) {
    if (busy[item.id] || isClosed) return
    if (!window.confirm(`Delete "${item.label}"?\n\nThis removes the item from this incident's checklist.`)) return
    setBusy(b => ({ ...b, [item.id]: true }))
    try {
      await api.deleteClosureItem(inc.id, item.id)
      setItems(prev => prev.filter(i => i.id !== item.id))
    } catch (e) {
      setError(e.message || 'Failed to delete item')
    } finally {
      setBusy(b => { const n = { ...b }; delete n[item.id]; return n })
    }
  }

  if (loading) return <div className="pi-loading">Loading checklist…</div>
  if (error)   return <div className="pi-error">{error}</div>

  const checked = items.filter(i => i.checked).length
  const pct     = items.length ? Math.round((checked / items.length) * 100) : 0

  return (
    <div className="pi-checklist">
      <div className="pi-progress-wrap" style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
        <div className="pi-progress-bar" style={{ flex: 1 }}>
          <div className="pi-progress-fill" style={{ width: `${pct}%` }} />
        </div>
        <span className="pi-progress-label">{checked} / {items.length} complete</span>
        {!isClosed && !adding && (
          <button
            type="button"
            className="btn primary"
            style={{ fontSize: 12, padding: '4px 12px', flexShrink: 0 }}
            onClick={() => setAdding(true)}
          >
            + Add item
          </button>
        )}
      </div>

      {adding && !isClosed && (
        <div style={{ marginTop: 'var(--space-3)', display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
          <input
            autoFocus
            className="input"
            placeholder="New checklist item label…"
            value={newLabel}
            onChange={e => setNewLabel(e.target.value)}
            maxLength={256}
            disabled={creating}
            onKeyDown={e => {
              if (e.key === 'Enter')  { e.preventDefault(); createItem() }
              if (e.key === 'Escape') { setNewLabel(''); setAdding(false) }
            }}
            style={{ flex: 1, fontSize: 13 }}
          />
          <button
            type="button"
            className="btn primary"
            style={{ fontSize: 12, padding: '4px 12px' }}
            onClick={createItem}
            disabled={!newLabel.trim() || creating}
          >
            {creating ? 'Adding…' : 'Add'}
          </button>
          <button
            type="button"
            className="btn ghost"
            style={{ fontSize: 12, padding: '4px 12px' }}
            onClick={() => { setNewLabel(''); setAdding(false) }}
            disabled={creating}
          >
            Cancel
          </button>
        </div>
      )}

      <ul className="pi-checklist-list">
        {items.map(item => (
          <ChecklistRow
            key={item.id}
            item={item}
            users={users}
            busyToggle={!!busy[item.id]}
            isClosed={isClosed}
            onToggle={() => toggle(item)}
            onMeta={(payload) => patchMeta(item, payload)}
            onDelete={() => deleteItem(item)}
          />
        ))}
      </ul>
    </div>
  )
}

function ChecklistRow({ item, users, busyToggle, isClosed, onToggle, onMeta, onDelete }) {
  const [expanded,    setExpanded]    = useState(false)
  const [notesDraft,  setNotesDraft]  = useState(item.notes || '')
  const [editingNote, setEditingNote] = useState(false)

  // Keep notesDraft in sync if item updates externally (e.g. after save)
  useEffect(() => { setNotesDraft(item.notes || '') }, [item.notes])

  function saveNotes() {
    const trimmed = notesDraft.trim()
    if (trimmed === (item.notes || '')) { setEditingNote(false); return }
    onMeta({ notes: trimmed || null })
    setEditingNote(false)
  }

  function assignUser(userId) {
    const id = userId || null
    onMeta({ assigned_to_id: id })
  }

  return (
    <li className={`pi-checklist-item${item.checked ? ' pi-checked' : ''}`}>
      {/* Main row */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', width: '100%' }}>
        <button
          type="button"
          className="pi-checkbox"
          aria-label={item.checked ? 'Mark incomplete' : 'Mark complete'}
          onClick={onToggle}
          disabled={busyToggle || isClosed}
          style={{ flexShrink: 0, marginTop: 2 }}
        >
          {item.checked ? '✓' : ''}
        </button>

        <div style={{ flex: 1, minWidth: 0 }}>
          <span className="pi-checklist-label">{item.label}</span>

          {/* Meta line */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)', marginTop: 4, fontSize: 12, color: 'var(--muted)' }}>
            {item.checked && item.checked_by && (
              <span>
                Checked by <strong style={{ color: 'var(--text)' }}>{item.checked_by}</strong>
                {item.checked_at && <> · {formatLocal(item.checked_at).slice(0, 16)}</>}
              </span>
            )}
            {item.assigned_to ? (
              <span>
                Assigned: <strong style={{ color: 'var(--accent)' }}>{item.assigned_to}</strong>
              </span>
            ) : !isClosed && (
              <span style={{ color: 'var(--dim)' }}>Unassigned</span>
            )}
            {item.notes && !editingNote && (
              <span
                style={{ color: 'var(--text)', cursor: isClosed ? 'default' : 'pointer', fontStyle: 'italic' }}
                onClick={() => !isClosed && setEditingNote(true)}
                title={isClosed ? undefined : 'Click to edit note'}
              >
                {item.notes}
              </span>
            )}
          </div>

          {/* Notes inline edit */}
          {editingNote && (
            <div style={{ marginTop: 'var(--space-2)', display: 'flex', gap: 'var(--space-2)', alignItems: 'flex-start' }}>
              <textarea
                autoFocus
                className="input"
                rows={2}
                value={notesDraft}
                onChange={e => setNotesDraft(e.target.value)}
                maxLength={4096}
                style={{ flex: 1, fontSize: 12, resize: 'vertical' }}
                onKeyDown={e => {
                  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); saveNotes() }
                  if (e.key === 'Escape') { setNotesDraft(item.notes || ''); setEditingNote(false) }
                }}
              />
              <button type="button" className="btn primary" style={{ fontSize: 12, padding: '4px 10px' }} onClick={saveNotes}>Save</button>
              <button type="button" className="btn ghost"   style={{ fontSize: 12, padding: '4px 10px' }} onClick={() => { setNotesDraft(item.notes || ''); setEditingNote(false) }}>Cancel</button>
            </div>
          )}
        </div>

        {/* Actions */}
        {!isClosed && (
          <div style={{ display: 'flex', gap: 'var(--space-1)', flexShrink: 0 }}>
            {!editingNote && (
              <button
                type="button"
                className="btn ghost"
                style={{ fontSize: 11, padding: '2px 6px' }}
                title={item.notes ? 'Edit note' : 'Add note'}
                onClick={() => setEditingNote(true)}
              >
                {item.notes ? 'Note' : '+ Note'}
              </button>
            )}
            <button
              type="button"
              className="btn ghost"
              style={{ fontSize: 11, padding: '2px 6px' }}
              onClick={() => setExpanded(x => !x)}
              title="Assign owner"
            >
              {expanded ? 'Close' : 'Assign'}
            </button>
            <button
              type="button"
              className="btn ghost"
              style={{ fontSize: 11, padding: '2px 6px', color: 'var(--crit)' }}
              onClick={onDelete}
              disabled={busyToggle}
              title="Delete this item from the checklist"
              aria-label={`Delete ${item.label}`}
            >
              ✕
            </button>
          </div>
        )}
      </div>

      {/* Assign panel */}
      {expanded && !isClosed && (
        <div style={{ marginTop: 'var(--space-2)', paddingLeft: 32 }}>
          <select
            className="select"
            style={{ fontSize: 12 }}
            value={item.assigned_to_id || ''}
            onChange={e => { assignUser(e.target.value || null); setExpanded(false) }}
          >
            <option value="">— Unassigned —</option>
            {users.map(u => (
              <option key={u.id} value={u.id}>
                {u.full_name ? `${u.full_name} (${u.username})` : u.username}
              </option>
            ))}
          </select>
        </div>
      )}
    </li>
  )
}

// ─── Lessons Learned constants ────────────────────────────────────────────────

const ROOT_CAUSE_OPTIONS = [
  { value: '',                   label: '— Select category —' },
  { value: 'unpatched_system',   label: 'Unpatched system / software' },
  { value: 'misconfiguration',   label: 'Misconfiguration' },
  { value: 'access_control',     label: 'Access control failure' },
  { value: 'human_error',        label: 'Human error' },
  { value: 'social_engineering', label: 'Social engineering / phishing' },
  { value: 'vendor_third_party', label: 'Vendor / third-party' },
  { value: 'monitoring_gap',     label: 'Monitoring / detection gap' },
  { value: 'process_failure',    label: 'Process failure' },
  { value: 'unknown',            label: 'Unknown' },
  { value: 'other',              label: 'Other' },
]

const EFFECTIVENESS_DIMS = [
  { id: 'detection',   label: 'Detection',              desc: 'Speed and accuracy of threat detection' },
  { id: 'containment', label: 'Containment',            desc: 'Effectiveness of initial containment' },
  { id: 'comms',       label: 'Communications',         desc: 'Timeliness and clarity of internal/external comms' },
  { id: 'roles',       label: 'Roles & Responsibilities', desc: 'Clarity of assignment and adherence' },
  { id: 'plan',        label: 'IR Plan',                desc: 'Adequacy of the IR plan' },
  { id: 'docs',        label: 'Documentation',          desc: 'Evidence collection and record-keeping quality' },
]

const RATING_OPTIONS = ['good', 'acceptable', 'poor']
const RATING_COLORS  = { good: 'var(--ok)', acceptable: 'var(--med)', poor: 'var(--crit)' }

const TIMELINE_PHASES = [
  { key: 'timeline_detection_mins',   label: 'Detection' },
  { key: 'timeline_escalation_mins',  label: 'Escalation' },
  { key: 'timeline_containment_mins', label: 'Containment' },
  { key: 'timeline_comms_mins',       label: 'Comms' },
  { key: 'timeline_remediation_mins', label: 'Remediation' },
]

const AI_PRIORITIES  = ['high', 'medium', 'low']
const AI_STATUSES    = ['open', 'in_progress', 'done']
const CTRL_CATEGORIES = ['preventive', 'detective', 'corrective', 'process', 'training', 'other']
const CTRL_PRIORITIES = ['high', 'medium', 'low']

const EMPTY_LL = {
  status: 'draft',
  conducted_at: '',
  facilitated_by: '',
  participants: [],
  incident_narrative: '',
  root_cause_category: '',
  root_cause_description: '',
  contributing_factors: [],
  effectiveness: {},
  what_went_well: [],
  friction_points: [],
  near_misses: [],
  timeline_detection_mins: '',
  timeline_escalation_mins: '',
  timeline_containment_mins: '',
  timeline_comms_mins: '',
  timeline_remediation_mins: '',
  action_items: [],
  control_improvements: [],
}

function llFromApi(data) {
  return {
    status:                   data.status || 'draft',
    conducted_at:             data.conducted_at ? data.conducted_at.slice(0, 10) : '',
    facilitated_by:           data.facilitated_by || '',
    participants:             data.participants || [],
    incident_narrative:       data.incident_narrative || '',
    root_cause_category:      data.root_cause_category || '',
    root_cause_description:   data.root_cause_description || '',
    contributing_factors:     data.contributing_factors || [],
    effectiveness:            data.effectiveness || {},
    what_went_well:           data.what_went_well || [],
    friction_points:          data.friction_points || [],
    near_misses:              data.near_misses || [],
    timeline_detection_mins:  data.timeline_detection_mins ?? '',
    timeline_escalation_mins: data.timeline_escalation_mins ?? '',
    timeline_containment_mins:data.timeline_containment_mins ?? '',
    timeline_comms_mins:      data.timeline_comms_mins ?? '',
    timeline_remediation_mins:data.timeline_remediation_mins ?? '',
    action_items:             data.action_items || [],
    control_improvements:     data.control_improvements || [],
  }
}

function llToPayload(form) {
  const p = { ...form }
  // coerce timeline ints
  for (const ph of TIMELINE_PHASES) {
    const v = p[ph.key]
    p[ph.key] = v !== '' && v !== null && v !== undefined ? parseInt(v, 10) || null : null
  }
  // coerce empty date
  if (!p.conducted_at) p.conducted_at = null
  return p
}

// ─── Shared sub-components ────────────────────────────────────────────────────

function LLSection({ title, children }) {
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius)', marginBottom: 'var(--space-4)', overflow: 'hidden' }}>
      <div style={{ background: 'var(--surface-2)', padding: 'var(--space-2) var(--space-3)', fontWeight: 600, fontSize: 13, borderBottom: '1px solid var(--border)' }}>
        {title}
      </div>
      <div style={{ padding: 'var(--space-3)' }}>
        {children}
      </div>
    </div>
  )
}

function StringList({ value, onChange, placeholder, disabled }) {
  const [draft, setDraft] = useState('')

  function add() {
    const t = draft.trim()
    if (!t) return
    onChange([...value, t])
    setDraft('')
  }

  return (
    <div>
      {value.map((item, i) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 4 }}>
          <span style={{ flex: 1, fontSize: 13 }}>{item}</span>
          {!disabled && (
            <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '2px 6px' }}
              onClick={() => onChange(value.filter((_, j) => j !== i))}>✕</button>
          )}
        </div>
      ))}
      {!disabled && (
        <div style={{ display: 'flex', gap: 'var(--space-2)', marginTop: 4 }}>
          <input className="input" value={draft} onChange={e => setDraft(e.target.value)}
            placeholder={placeholder} maxLength={512} style={{ flex: 1, fontSize: 13 }}
            onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); add() } }} />
          <button type="button" className="btn ghost" onClick={add} disabled={!draft.trim()}>Add</button>
        </div>
      )}
    </div>
  )
}

// ─── LessonsLearned component ─────────────────────────────────────────────────

function LessonsLearned({ inc }) {
  const isClosed = inc?.status === 'closed'
  const [form,    setForm]    = useState(EMPTY_LL)
  const [loading, setLoading] = useState(true)
  const [saving,  setSaving]  = useState(false)
  const [saved,   setSaved]   = useState(false)
  const [error,   setError]   = useState(null)
  const savedTimer = useRef(null)

  useEffect(() => {
    api.getLessonsLearned(inc.id)
      .then(data => setForm(llFromApi(data)))
      .catch(e => setError(e.message || 'Failed to load'))
      .finally(() => setLoading(false))
  }, [inc.id])

  function set(key, val) { setForm(prev => ({ ...prev, [key]: val })) }

  async function save() {
    setSaving(true); setError(null)
    try {
      const updated = await api.saveLessonsLearned(inc.id, llToPayload(form))
      setForm(llFromApi(updated))
      setSaved(true)
      clearTimeout(savedTimer.current)
      savedTimer.current = setTimeout(() => setSaved(false), 2500)
    } catch (e) {
      setError(e.message || 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  function openExport() {
    window.open(api.exportLessonsLearned(inc.id), '_blank')
  }

  if (loading) return <div className="pi-loading">Loading…</div>

  const disabled = isClosed

  // ── effectiveness helpers
  function setEff(dimId, key, val) {
    setForm(prev => ({
      ...prev,
      effectiveness: {
        ...prev.effectiveness,
        [dimId]: { ...(prev.effectiveness[dimId] || {}), [key]: val },
      },
    }))
  }

  // ── timeline max for bar chart
  const tlMax = Math.max(1, ...TIMELINE_PHASES.map(ph => parseInt(form[ph.key], 10) || 0))

  // ── action items
  function addAI() {
    set('action_items', [...form.action_items, { id: crypto.randomUUID(), action: '', owner: '', due_date: '', priority: 'medium', status: 'open' }])
  }
  function updateAI(id, key, val) {
    set('action_items', form.action_items.map(ai => ai.id === id ? { ...ai, [key]: val } : ai))
  }
  function removeAI(id) {
    set('action_items', form.action_items.filter(ai => ai.id !== id))
  }

  // ── control improvements
  function addCI() {
    set('control_improvements', [...form.control_improvements, { id: crypto.randomUUID(), recommendation: '', category: 'preventive', priority: 'medium' }])
  }
  function updateCI(id, key, val) {
    set('control_improvements', form.control_improvements.map(ci => ci.id === id ? { ...ci, [key]: val } : ci))
  }
  function removeCI(id) {
    set('control_improvements', form.control_improvements.filter(ci => ci.id !== id))
  }

  return (
    <div className="pi-lessons">

      {/* ── Status / header controls ──────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-4)', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
          <span style={{ fontSize: 13, color: 'var(--muted)' }}>Status</span>
          {['draft', 'final'].map(s => (
            <button
              key={s}
              type="button"
              className={`btn ${form.status === s ? 'primary' : 'ghost'}`}
              style={{ fontSize: 12, padding: '3px 10px', textTransform: 'capitalize' }}
              onClick={() => !disabled && set('status', s)}
              disabled={disabled}
            >
              {s}
            </button>
          ))}
        </div>
        <button type="button" className="btn ghost" style={{ fontSize: 12 }} onClick={openExport}>
          Export HTML
        </button>
      </div>

      {/* ── Review details ────────────────────────────────────────────────── */}
      <LLSection title="Review Details">
        <div className="form-row">
          <div className="field">
            <label className="field-label">Date conducted</label>
            <input type="date" className="input" value={form.conducted_at}
              onChange={e => set('conducted_at', e.target.value)} disabled={disabled} />
          </div>
          <div className="field">
            <label className="field-label">Facilitated by</label>
            <input className="input" value={form.facilitated_by} maxLength={256}
              onChange={e => set('facilitated_by', e.target.value)} disabled={disabled}
              placeholder="Name or role…" />
          </div>
        </div>
        <div className="field" style={{ marginTop: 'var(--space-2)' }}>
          <label className="field-label">Participants</label>
          <StringList value={form.participants} onChange={v => set('participants', v)}
            placeholder="Add participant name…" disabled={disabled} />
        </div>
      </LLSection>

      {/* ── Incident narrative ────────────────────────────────────────────── */}
      <LLSection title="Incident Narrative">
        <textarea className="pi-lessons-textarea" rows={6} disabled={disabled}
          placeholder="Factual account of what happened: initial access vector, progression, scope of impact…"
          value={form.incident_narrative}
          onChange={e => set('incident_narrative', e.target.value)} />
      </LLSection>

      {/* ── Root cause ───────────────────────────────────────────────────── */}
      <LLSection title="Root Cause Analysis">
        <div className="form-row">
          <div className="field">
            <label className="field-label">Category</label>
            <select className="select" value={form.root_cause_category}
              onChange={e => set('root_cause_category', e.target.value)} disabled={disabled}>
              {ROOT_CAUSE_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>
        </div>
        <div className="field" style={{ marginTop: 'var(--space-2)' }}>
          <label className="field-label">Description</label>
          <textarea className="pi-lessons-textarea" rows={3} disabled={disabled}
            placeholder="Explain the root cause in detail…"
            value={form.root_cause_description}
            onChange={e => set('root_cause_description', e.target.value)} />
        </div>
        <div className="field" style={{ marginTop: 'var(--space-2)' }}>
          <label className="field-label">Contributing factors</label>
          <StringList value={form.contributing_factors} onChange={v => set('contributing_factors', v)}
            placeholder="Add contributing factor…" disabled={disabled} />
        </div>
      </LLSection>

      {/* ── Response effectiveness ────────────────────────────────────────── */}
      <LLSection title="Response Effectiveness">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
          {EFFECTIVENESS_DIMS.map(dim => {
            const d = form.effectiveness[dim.id] || {}
            return (
              <div key={dim.id} style={{ borderBottom: '1px solid var(--border)', paddingBottom: 'var(--space-3)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 'var(--space-2)', marginBottom: 'var(--space-2)' }}>
                  <div>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>{dim.label}</div>
                    <div style={{ fontSize: 12, color: 'var(--muted)' }}>{dim.desc}</div>
                  </div>
                  <div style={{ display: 'flex', gap: 'var(--space-1)' }}>
                    {RATING_OPTIONS.map(r => (
                      <button
                        key={r}
                        type="button"
                        className="btn ghost"
                        style={{
                          fontSize: 12, padding: '3px 10px',
                          textTransform: 'capitalize',
                          borderColor: d.rating === r ? RATING_COLORS[r] : undefined,
                          color:       d.rating === r ? RATING_COLORS[r] : undefined,
                          fontWeight:  d.rating === r ? 600 : 400,
                        }}
                        onClick={() => !disabled && setEff(dim.id, 'rating', d.rating === r ? '' : r)}
                        disabled={disabled}
                      >
                        {r}
                      </button>
                    ))}
                  </div>
                </div>
                <input className="input" value={d.notes || ''} maxLength={512} disabled={disabled}
                  placeholder="Notes (optional)…"
                  onChange={e => setEff(dim.id, 'notes', e.target.value)}
                  style={{ fontSize: 12 }} />
              </div>
            )
          })}
        </div>
      </LLSection>

      {/* ── Observations ─────────────────────────────────────────────────── */}
      <LLSection title="Observations">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-4)' }}>
          <div>
            <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 'var(--space-2)', color: 'var(--ok)' }}>What went well</div>
            <StringList value={form.what_went_well} onChange={v => set('what_went_well', v)}
              placeholder="Add observation…" disabled={disabled} />
          </div>
          <div>
            <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 'var(--space-2)', color: 'var(--high)' }}>Friction points</div>
            <StringList value={form.friction_points} onChange={v => set('friction_points', v)}
              placeholder="Add friction point…" disabled={disabled} />
          </div>
        </div>
      </LLSection>

      {/* ── Near misses ──────────────────────────────────────────────────── */}
      <LLSection title="Near Misses">
        <StringList value={form.near_misses} onChange={v => set('near_misses', v)}
          placeholder="Describe a near-miss event…" disabled={disabled} />
      </LLSection>

      {/* ── Response timeline ─────────────────────────────────────────────── */}
      <LLSection title="Response Timeline (minutes from incident start)">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
          {TIMELINE_PHASES.map(ph => {
            const mins = parseInt(form[ph.key], 10) || 0
            const pct  = tlMax > 0 ? Math.round((mins / tlMax) * 100) : 0
            return (
              <div key={ph.key} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                <span style={{ minWidth: 100, fontSize: 13 }}>{ph.label}</span>
                <div style={{ flex: 1, height: 12, background: 'var(--surface-2)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${pct}%`, minWidth: pct > 0 ? 4 : 0, height: '100%', background: 'var(--accent)', borderRadius: 3 }} />
                </div>
                <input type="number" className="input" min={0} disabled={disabled}
                  value={form[ph.key]} placeholder="—"
                  onChange={e => set(ph.key, e.target.value)}
                  style={{ width: 80, fontSize: 12, textAlign: 'right' }} />
                <span style={{ fontSize: 12, color: 'var(--muted)', minWidth: 24 }}>min</span>
              </div>
            )
          })}
        </div>
      </LLSection>

      {/* ── Action items ──────────────────────────────────────────────────── */}
      <LLSection title="Action Items">
        {form.action_items.length === 0 && (
          <div style={{ color: 'var(--dim)', fontSize: 13, marginBottom: 'var(--space-2)' }}>No action items yet.</div>
        )}
        {form.action_items.map(ai => (
          <div key={ai.id} style={{ display: 'grid', gridTemplateColumns: '1fr 120px 110px 90px 90px 32px', gap: 'var(--space-1)', marginBottom: 'var(--space-2)', alignItems: 'center' }}>
            <input className="input" value={ai.action} maxLength={512} disabled={disabled}
              placeholder="Action…" style={{ fontSize: 12 }}
              onChange={e => updateAI(ai.id, 'action', e.target.value)} />
            <input className="input" value={ai.owner} maxLength={128} disabled={disabled}
              placeholder="Owner" style={{ fontSize: 12 }}
              onChange={e => updateAI(ai.id, 'owner', e.target.value)} />
            <input type="date" className="input" value={ai.due_date || ''} disabled={disabled}
              style={{ fontSize: 12 }}
              onChange={e => updateAI(ai.id, 'due_date', e.target.value)} />
            <select className="select" value={ai.priority} disabled={disabled} style={{ fontSize: 12 }}
              onChange={e => updateAI(ai.id, 'priority', e.target.value)}>
              {AI_PRIORITIES.map(p => <option key={p} value={p} style={{ textTransform: 'capitalize' }}>{p.charAt(0).toUpperCase() + p.slice(1)}</option>)}
            </select>
            <select className="select" value={ai.status} disabled={disabled} style={{ fontSize: 12 }}
              onChange={e => updateAI(ai.id, 'status', e.target.value)}>
              {AI_STATUSES.map(s => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
            </select>
            {!disabled && (
              <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '0 6px' }}
                onClick={() => removeAI(ai.id)}>✕</button>
            )}
          </div>
        ))}
        {!disabled && (
          <div style={{ marginTop: 'var(--space-1)', display: 'flex', gap: 'var(--space-2)', fontSize: 11, color: 'var(--dim)', flexWrap: 'wrap', alignItems: 'center' }}>
            <button type="button" className="btn ghost" style={{ fontSize: 12 }} onClick={addAI}>+ Add action item</button>
            {form.action_items.length > 0 && (
              <span>Action · Owner · Due date · Priority · Status</span>
            )}
          </div>
        )}
      </LLSection>

      {/* ── Control improvements ──────────────────────────────────────────── */}
      <LLSection title="Control Improvements">
        {form.control_improvements.length === 0 && (
          <div style={{ color: 'var(--dim)', fontSize: 13, marginBottom: 'var(--space-2)' }}>No improvements recorded.</div>
        )}
        {form.control_improvements.map(ci => (
          <div key={ci.id} style={{ display: 'grid', gridTemplateColumns: '1fr 110px 90px 32px', gap: 'var(--space-1)', marginBottom: 'var(--space-2)', alignItems: 'center' }}>
            <input className="input" value={ci.recommendation} maxLength={512} disabled={disabled}
              placeholder="Recommendation…" style={{ fontSize: 12 }}
              onChange={e => updateCI(ci.id, 'recommendation', e.target.value)} />
            <select className="select" value={ci.category} disabled={disabled} style={{ fontSize: 12 }}
              onChange={e => updateCI(ci.id, 'category', e.target.value)}>
              {CTRL_CATEGORIES.map(c => <option key={c} value={c} style={{ textTransform: 'capitalize' }}>{c.charAt(0).toUpperCase() + c.slice(1)}</option>)}
            </select>
            <select className="select" value={ci.priority} disabled={disabled} style={{ fontSize: 12 }}
              onChange={e => updateCI(ci.id, 'priority', e.target.value)}>
              {CTRL_PRIORITIES.map(p => <option key={p} value={p} style={{ textTransform: 'capitalize' }}>{p.charAt(0).toUpperCase() + p.slice(1)}</option>)}
            </select>
            {!disabled && (
              <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '0 6px' }}
                onClick={() => removeCI(ci.id)}>✕</button>
            )}
          </div>
        ))}
        {!disabled && (
          <button type="button" className="btn ghost" style={{ fontSize: 12, marginTop: 'var(--space-1)' }} onClick={addCI}>+ Add improvement</button>
        )}
      </LLSection>

      {/* ── Footer ───────────────────────────────────────────────────────── */}
      {error && <div className="pi-error" style={{ marginBottom: 'var(--space-3)' }}>{error}</div>}

      {!disabled && (
        <div className="pi-lessons-footer">
          {saved && <span className="pi-saved-flash">Saved</span>}
          <button className="btn primary pi-save-btn" onClick={save} disabled={saving}>
            {saving ? 'Saving…' : 'Save lessons learned'}
          </button>
        </div>
      )}
    </div>
  )
}

// ─── Attack Chain ────────────────────────────────────────────────────────────

function AttackChain({ inc }) {
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

// ─── Page root ────────────────────────────────────────────────────────────────

export default function PostIncident() {
  const { inc } = useOutletContext()
  const [tab, setTab] = useState(0)

  return (
    <div className="pi-root">
      <div className="pi-tab-bar">
        {TABS.map((t, i) => (
          <button
            key={t}
            className={`pi-tab${tab === i ? ' pi-tab-active' : ''}`}
            onClick={() => setTab(i)}
          >
            {t}
          </button>
        ))}
      </div>

      <div className="pi-content">
        {tab === 0 && <Analytics       inc={inc} />}
        {tab === 1 && <ClosureChecklist inc={inc} />}
        {tab === 2 && <LessonsLearned  inc={inc} />}
        {tab === 3 && <AttackChain     inc={inc} />}
        {tab === 4 && <Reports         inc={inc} />}
      </div>
    </div>
  )
}
