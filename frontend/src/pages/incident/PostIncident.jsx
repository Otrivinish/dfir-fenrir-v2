import { useCallback, useEffect, useRef, useState } from 'react'
import { NavLink, Outlet, useOutletContext } from 'react-router-dom'
import { api } from '../../api/client.js'
import { useAuth } from '../../hooks/useAuth.jsx'
import { formatLocal } from '../../lib/datetime.js'
import Analytics from './post_incident/Analytics.jsx'
import Reports, { LR_FIELDS, LR_REMEDIATION } from './post_incident/Reports.jsx'
import CostsImpact from './post_incident/CostsImpact.jsx'

// ─── Tab navigation ───────────────────────────────────────────────────────────
// J3 (R29): each sub-tab is a route under /incidents/:id/post-incident/ (App.jsx), so reload
// and deep links keep it; the bare path redirects to analytics. Closure is last.

const TABS = [
  { to: 'analytics',    label: 'Analytics' },
  { to: 'lessons',      label: 'Lessons Learned' },
  { to: 'costs',        label: 'Costs & Impact' },
  { to: 'reports',      label: 'Reports' },
  { to: 'closure',      label: 'Closure Checklist' },
]

// ─── Closure Checklist ────────────────────────────────────────────────────────

function ClosureChecklist({ inc, viewer }) {
  const isClosed = inc?.status === 'closed'
  // L2 (R43): a viewer gets the closed-incident (read-only) view; the API refuses their writes.
  const ro = isClosed || viewer
  const [items,   setItems]   = useState([])
  const [users,   setUsers]   = useState([])
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)
  const [busy,    setBusy]    = useState({})
  const [rowError, setRowError] = useState({})   // item id → why its last note / assignee save failed
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
  }, [inc.id, isClosed])   // reload on close / re-open: the API ticks / unticks "incident formally closed"

  useEffect(() => { load() }, [load])

  async function toggle(item) {
    if (busy[item.id] || ro) return
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

  // I5: mark / unmark "not applicable"; the reason is optional (Gate 2 warns when it is missing).
  async function setNa(item, notApplicable, reason) {
    if (busy[item.id] || ro) return
    setBusy(b => ({ ...b, [item.id]: true }))
    setRowError(r => { const n = { ...r }; delete n[item.id]; return n })
    try {
      const updated = await api.setClosureItemNa(inc.id, item.id,
        notApplicable ? { not_applicable: true, na_reason: reason || null } : { not_applicable: false })
      setItems(prev => prev.map(i => i.id === updated.id ? updated : i))
    } catch (e) {
      setRowError(r => ({ ...r, [item.id]: e.message || 'Could not save' }))
    } finally {
      setBusy(b => { const n = { ...b }; delete n[item.id]; return n })
    }
  }

  async function patchMeta(item, payload) {
    setBusy(b => ({ ...b, [item.id]: true }))
    setRowError(r => { const n = { ...r }; delete n[item.id]; return n })
    try {
      const updated = await api.patchChecklistMeta(inc.id, item.id, payload)
      setItems(prev => prev.map(i => i.id === updated.id ? updated : i))
    } catch (e) {
      // Say why (e.g. 422 assignee_no_access: that person can't see this incident); the row keeps its value.
      setRowError(r => ({ ...r, [item.id]: e.message || 'Could not save' }))
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
    if (busy[item.id] || ro) return
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

  const checked = items.filter(i => i.checked || i.not_applicable).length   // N/A counts as done (Gate 2)
  const pct     = items.length ? Math.round((checked / items.length) * 100) : 0

  return (
    <div className="pi-checklist">
      <div className="pi-progress-wrap" style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
        <div className="pi-progress-bar" style={{ flex: 1 }}>
          <div className="pi-progress-fill" style={{ width: `${pct}%` }} />
        </div>
        <span className="pi-progress-label">{checked} / {items.length} complete</span>
        {!ro && !adding && (
          <button
            type="button"
            className="btn primary"
            style={{ flexShrink: 0 }}
            onClick={() => setAdding(true)}
          >
            + Add item
          </button>
        )}
      </div>

      {adding && !ro && (
        <div style={{ marginTop: 'var(--space-3)', display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
          <input
            autoFocus
            className="input compact"
            placeholder="New checklist item label…"
            value={newLabel}
            onChange={e => setNewLabel(e.target.value)}
            maxLength={256}
            disabled={creating}
            onKeyDown={e => {
              if (e.key === 'Enter')  { e.preventDefault(); createItem() }
              if (e.key === 'Escape') { setNewLabel(''); setAdding(false) }
            }}
            style={{ flex: 1 }}
          />
          <button
            type="button"
            className="btn primary"
            onClick={createItem}
            disabled={!newLabel.trim() || creating}
          >
            {creating ? 'Adding…' : 'Add'}
          </button>
          <button
            type="button"
            className="btn ghost"
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
            error={rowError[item.id]}
            isClosed={ro}
            onToggle={() => toggle(item)}
            onNa={(na, reason) => setNa(item, na, reason)}
            onMeta={(payload) => patchMeta(item, payload)}
            onDelete={() => deleteItem(item)}
          />
        ))}
      </ul>
    </div>
  )
}

function ChecklistRow({ item, users, busyToggle, error, isClosed, onToggle, onNa, onMeta, onDelete }) {
  const [expanded,    setExpanded]    = useState(false)
  const [naOpen,      setNaOpen]      = useState(false)
  const [naDraft,     setNaDraft]     = useState('')
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
          <span className="pi-checklist-label" style={item.not_applicable ? { color: 'var(--muted)' } : undefined}>{item.label}</span>
          {item.not_applicable && (
            <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }} data-checklist-na>
              <span className="pill pill-gray" style={{ marginRight: 'var(--space-1)' }}>N/A</span>
              {item.na_reason ? item.na_reason : <span style={{ fontStyle: 'italic' }}>No reason given (Gate 2 warns)</span>}
            </div>
          )}
          {naOpen && (
            <div style={{ marginTop: 'var(--space-2)', display: 'flex', gap: 'var(--space-2)', alignItems: 'flex-start' }}>
              <input autoFocus className="input compact" style={{ flex: 1 }} maxLength={2000}
                     aria-label={`Why "${item.label}" is not applicable`}
                     placeholder="Why it is not applicable (recommended)"
                     value={naDraft} onChange={e => setNaDraft(e.target.value)}
                     onKeyDown={e => {
                       if (e.key === 'Enter')  { e.preventDefault(); onNa(true, naDraft.trim()); setNaOpen(false) }
                       if (e.key === 'Escape') { setNaOpen(false) }
                     }} />
              <button type="button" className="btn primary"
                      onClick={() => { onNa(true, naDraft.trim()); setNaOpen(false) }}>Mark N/A</button>
              <button type="button" className="btn ghost"
                      onClick={() => setNaOpen(false)}>Cancel</button>
            </div>
          )}

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
                className="input compact"
                rows={2}
                value={notesDraft}
                onChange={e => setNotesDraft(e.target.value)}
                maxLength={4096}
                style={{ flex: 1, resize: 'vertical' }}
                onKeyDown={e => {
                  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); saveNotes() }
                  if (e.key === 'Escape') { setNotesDraft(item.notes || ''); setEditingNote(false) }
                }}
              />
              <button type="button" className="btn primary" onClick={saveNotes}>Save</button>
              <button type="button" className="btn ghost" onClick={() => { setNotesDraft(item.notes || ''); setEditingNote(false) }}>Cancel</button>
            </div>
          )}
        </div>

        {/* Actions */}
        {!isClosed && (
          <div style={{ display: 'flex', gap: 'var(--space-1)', flexShrink: 0 }}>
            {item.not_applicable ? (
              <button type="button" className="btn ghost"
                      onClick={() => onNa(false)} disabled={busyToggle} title="This item applies after all">
                Clear N/A
              </button>
            ) : !item.checked && !naOpen && item.item_key !== 'incident_closed' && (
              <button type="button" className="btn ghost"
                      onClick={() => { setNaDraft(item.na_reason || ''); setNaOpen(true) }} disabled={busyToggle}
                      title="Mark not applicable, with a reason">
                N/A
              </button>
            )}
            {!editingNote && (
              <button
                type="button"
                className="btn ghost"
                title={item.notes ? 'Edit note' : 'Add note'}
                onClick={() => setEditingNote(true)}
              >
                {item.notes ? 'Note' : '+ Note'}
              </button>
            )}
            <button
              type="button"
              className="btn ghost"
              onClick={() => setExpanded(x => !x)}
              title="Assign owner"
            >
              {expanded ? 'Close' : 'Assign'}
            </button>
            <button
              type="button"
              className="btn ghost"
              style={{ color: 'var(--crit)' }}
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
            className="select compact"
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
      {error && (
        <div className="team-picker-error" role="alert" style={{ marginTop: 'var(--space-2)', marginLeft: 32 }}>
          <span className="team-picker-error-mark" aria-hidden="true">!</span><span>{error}</span>
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
  meeting_minutes: '',
  ...Object.fromEntries([...LR_FIELDS, ...LR_REMEDIATION].map(f => [f.key, ''])),
}

// Free-text fields sent as null when blank (J3: the report narratives and the minutes).
const LL_TEXT_KEYS = ['meeting_minutes', ...LR_FIELDS.map(f => f.key), ...LR_REMEDIATION.map(f => f.key)]

// Gate 2 (close) needs these three; Details shows them read-only as the Resolution summary.
const CLOSE_REQUIRED = [
  ['incident_narrative',              'what happened'],
  ['root_cause_description',          'root cause'],
  ['report_security_recommendations', 'recommendations'],
]

// "Insert key timeline events": key = the server's key_event (K3: flagged by an analyst, ATT&CK-tagged, or
// recorded by FENRIR: milestones, triage, decisions, respond actions, closure …), listed before the rest;
// at most this many lines.
const TL_INSERT_MAX = 50

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
    ...Object.fromEntries(LL_TEXT_KEYS.map(k => [k, data[k] || ''])),
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
  for (const k of LL_TEXT_KEYS) p[k] = (p[k] || '').trim() || null
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
            <button type="button" className="btn ghost"
              onClick={() => onChange(value.filter((_, j) => j !== i))}>✕</button>
          )}
        </div>
      ))}
      {!disabled && (
        <div style={{ display: 'flex', gap: 'var(--space-2)', marginTop: 4 }}>
          <input className="input compact" value={draft} onChange={e => setDraft(e.target.value)}
            placeholder={placeholder} maxLength={512} style={{ flex: 1 }}
            onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); add() } }} />
          <button type="button" className="btn ghost" onClick={add} disabled={!draft.trim()}>Add</button>
        </div>
      )}
    </div>
  )
}

// ─── LessonsLearned component ─────────────────────────────────────────────────

function LessonsLearned({ inc, viewer }) {
  const isClosed = inc?.status === 'closed'
  const [form,    setForm]    = useState(EMPTY_LL)
  const [loading, setLoading] = useState(true)
  const [saving,  setSaving]  = useState(false)
  const [saved,   setSaved]   = useState(false)
  const [error,   setError]   = useState(null)
  const [inserting,  setInserting]  = useState(false)
  const [insertNote, setInsertNote] = useState(null)
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
      // Closed: the API accepts action_items only (409 incident_closed otherwise).
      const payload = isClosed ? { action_items: form.action_items } : llToPayload(form)
      const updated = await api.saveLessonsLearned(inc.id, payload)
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

  // Draft insert only: appends the incident's timeline events (key events first, times in UTC)
  // to the narrative; nothing is saved until Save.
  async function insertTimelineEvents() {
    setInserting(true); setInsertNote(null)
    try {
      const events = []
      let cursor = null
      do {
        const page = await api.listTimelineEvents(inc.id, { limit: 500, ...(cursor ? { cursor } : {}) })
        events.push(...page.items)
        cursor = page.next_cursor
      } while (cursor)
      const isKey = e => e.key_event
      const key   = events.filter(isKey)
      const rest  = events.filter(e => !isKey(e))
      if (!events.length) { setInsertNote('No timeline events to insert.'); return }
      const line = e => {
        const text = String(e.description || '').replace(/\s+/g, ' ').trim()
        const tech = e.mitre_technique_id || e.mitre_tactic_id
        return `- ${e.event_time} — ${text.length > 200 ? text.slice(0, 199) + '…' : text}` +
               (tech ? ` [${tech}]` : '') + (e.hostname ? ` (${e.hostname})` : '')
      }
      const keyPick  = key.slice(0, TL_INSERT_MAX)
      const restPick = rest.slice(0, TL_INSERT_MAX - keyPick.length)
      const blocks = []
      if (keyPick.length)  blocks.push('Key timeline events (UTC):\n' + keyPick.map(line).join('\n'))
      if (restPick.length) blocks.push('Other timeline events (UTC):\n' + restPick.map(line).join('\n'))
      const left = events.length - keyPick.length - restPick.length
      if (left > 0) blocks.push(`… ${left} more event${left === 1 ? '' : 's'} on the Timeline.`)
      const text = blocks.join('\n\n')
      setForm(prev => ({ ...prev, incident_narrative: prev.incident_narrative.trim() ? `${prev.incident_narrative.trimEnd()}\n\n${text}` : text }))
      setInsertNote(`Inserted ${keyPick.length + restPick.length} event${keyPick.length + restPick.length === 1 ? '' : 's'}: edit the text, then save.`)
    } catch (e) {
      setInsertNote(e.message || 'Could not load the timeline.')
    } finally {
      setInserting(false)
    }
  }

  if (loading) return <div className="pi-loading">Loading…</div>

  // Everything except action items, which stay editable after Close. L2 (R43): a viewer edits nothing.
  const disabled = isClosed || viewer
  const missing  = CLOSE_REQUIRED.filter(([k]) => !String(form[k] || '').trim()).map(([, label]) => label)

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
              style={{ textTransform: 'capitalize' }}
              onClick={() => !disabled && set('status', s)}
              disabled={disabled}
            >
              {s}
            </button>
          ))}
        </div>
        <button type="button" className="btn ghost" onClick={openExport}>
          Export HTML
        </button>
      </div>
      {!isClosed && (
        <div data-ll-close-required style={{ fontSize: 12, marginBottom: 'var(--space-3)', color: missing.length ? 'var(--high)' : 'var(--ok)' }}>
          {missing.length
            ? `Required to close — missing: ${missing.join(', ')}.`
            : '✓ What happened, root cause and recommendations are filled in.'}
        </div>
      )}

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
        <div className="field" style={{ marginTop: 'var(--space-2)' }}>
          <label className="field-label" htmlFor="ll-minutes">Meeting minutes (optional)</label>
          <textarea id="ll-minutes" className="pi-lessons-textarea" rows={4} disabled={disabled} maxLength={32768}
            placeholder="Minutes of the review meeting: agenda, discussion, decisions…"
            value={form.meeting_minutes}
            onChange={e => set('meeting_minutes', e.target.value)} />
        </div>
      </LLSection>

      {/* ── Incident narrative ────────────────────────────────────────────── */}
      <LLSection title="Incident Narrative (what happened — required to close)">
        <textarea id="ll-narrative" className="pi-lessons-textarea" rows={6} disabled={disabled}
          placeholder="Factual account of what happened: initial access vector, progression, scope of impact…"
          value={form.incident_narrative}
          onChange={e => set('incident_narrative', e.target.value)} />
        {!disabled && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginTop: 'var(--space-2)', flexWrap: 'wrap' }}>
            <button type="button" className="btn ghost" onClick={insertTimelineEvents} disabled={inserting} data-ll-insert-timeline>
              {inserting ? 'Loading timeline…' : 'Insert key timeline events'}
            </button>
            {insertNote && <span style={{ fontSize: 12, color: 'var(--muted)' }} data-ll-insert-note>{insertNote}</span>}
          </div>
        )}
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
          <label className="field-label">Description (required to close)</label>
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
                        style={{ textTransform: 'capitalize',
                          borderColor: d.rating === r ? RATING_COLORS[r] : undefined,
                          color:       d.rating === r ? RATING_COLORS[r] : undefined,
                          fontWeight:  d.rating === r ? 600 : 400 }}
                        onClick={() => !disabled && setEff(dim.id, 'rating', d.rating === r ? '' : r)}
                        disabled={disabled}
                      >
                        {r}
                      </button>
                    ))}
                  </div>
                </div>
                <input className="input compact" value={d.notes || ''} maxLength={512} disabled={disabled}
                  placeholder="Notes (optional)…"
                  onChange={e => setEff(dim.id, 'notes', e.target.value)}
 />
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
                <input type="number" className="input compact" min={0} disabled={disabled}
                  value={form[ph.key]} placeholder="—"
                  onChange={e => set(ph.key, e.target.value)}
                  style={{ width: 80, textAlign: 'right' }} />
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
          <div key={ai.id} className="pi-ai-row">
            <input className="input compact" value={ai.action} maxLength={512} disabled={viewer}
              placeholder="Action…"
              onChange={e => updateAI(ai.id, 'action', e.target.value)} />
            <input className="input compact" value={ai.owner} maxLength={128} disabled={viewer}
              placeholder="Owner"
              onChange={e => updateAI(ai.id, 'owner', e.target.value)} />
            <input type="date" className="input compact" value={ai.due_date || ''} disabled={viewer}
              onChange={e => updateAI(ai.id, 'due_date', e.target.value)} />
            <select className="select compact" value={ai.priority} disabled={viewer}
              onChange={e => updateAI(ai.id, 'priority', e.target.value)}>
              {AI_PRIORITIES.map(p => <option key={p} value={p} style={{ textTransform: 'capitalize' }}>{p.charAt(0).toUpperCase() + p.slice(1)}</option>)}
            </select>
            <select className="select compact" value={ai.status} disabled={viewer}
              onChange={e => updateAI(ai.id, 'status', e.target.value)}>
              {AI_STATUSES.map(s => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
            </select>
            {!viewer && (
              <button type="button" className="btn ghost" aria-label="Remove action item"
                onClick={() => removeAI(ai.id)}>✕</button>
            )}
          </div>
        ))}
        <div style={{ marginTop: 'var(--space-1)', display: 'flex', gap: 'var(--space-2)', fontSize: 11, color: 'var(--dim)', flexWrap: 'wrap', alignItems: 'center' }}>
          {!viewer && <button type="button" className="btn ghost" onClick={addAI}>+ Add action item</button>}
          {form.action_items.length > 0 && (
            <span>Action · Owner · Due date · Priority · Status</span>
          )}
        </div>
      </LLSection>

      {/* ── Control improvements ──────────────────────────────────────────── */}
      <LLSection title="Control Improvements">
        {form.control_improvements.length === 0 && (
          <div style={{ color: 'var(--dim)', fontSize: 13, marginBottom: 'var(--space-2)' }}>No improvements recorded.</div>
        )}
        {form.control_improvements.map(ci => (
          <div key={ci.id} className="pi-ci-row">
            <input className="input compact" value={ci.recommendation} maxLength={512} disabled={disabled}
              placeholder="Recommendation…"
              onChange={e => updateCI(ci.id, 'recommendation', e.target.value)} />
            <select className="select compact" value={ci.category} disabled={disabled}
              onChange={e => updateCI(ci.id, 'category', e.target.value)}>
              {CTRL_CATEGORIES.map(c => <option key={c} value={c} style={{ textTransform: 'capitalize' }}>{c.charAt(0).toUpperCase() + c.slice(1)}</option>)}
            </select>
            <select className="select compact" value={ci.priority} disabled={disabled}
              onChange={e => updateCI(ci.id, 'priority', e.target.value)}>
              {CTRL_PRIORITIES.map(p => <option key={p} value={p} style={{ textTransform: 'capitalize' }}>{p.charAt(0).toUpperCase() + p.slice(1)}</option>)}
            </select>
            {!disabled && (
              <button type="button" className="btn ghost"
                onClick={() => removeCI(ci.id)}>✕</button>
            )}
          </div>
        ))}
        {!disabled && (
          <button type="button" className="btn ghost" style={{ marginTop: 'var(--space-1)' }} onClick={addCI}>+ Add improvement</button>
        )}
      </LLSection>

      {/* ── Report text (was Reports → Lessons & Remediation, J3) ─────────── */}
      <LLSection title="Report Text — Lessons & Recommendations">
        <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 'var(--space-3)' }}>
          Fills §09 of the generated report, before the lists above. Security recommendations are required to close.
        </div>
        {LR_FIELDS.map(f => (
          <div key={f.key} className="field" style={{ marginBottom: 'var(--space-2)' }}>
            <label className="field-label" htmlFor={`ll-${f.key}`}>{f.label}</label>
            <textarea id={`ll-${f.key}`} className="pi-lessons-textarea" rows={3} disabled={disabled} maxLength={16384}
              placeholder={f.placeholder} value={form[f.key]} onChange={e => set(f.key, e.target.value)} />
          </div>
        ))}
      </LLSection>

      <LLSection title="Remediation Plan">
        <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 'var(--space-3)' }}>
          Fills §10 of the generated report, before the action items with a due date in each term.
        </div>
        {LR_REMEDIATION.map(f => (
          <div key={f.key} className="field" style={{ marginBottom: 'var(--space-2)' }}>
            <label className="field-label" htmlFor={`ll-${f.key}`} style={{ borderLeft: `3px solid ${f.color}`, paddingLeft: 8 }}>{f.label}</label>
            <textarea id={`ll-${f.key}`} className="pi-lessons-textarea" rows={3} disabled={disabled} maxLength={16384}
              placeholder={f.placeholder} value={form[f.key]} onChange={e => set(f.key, e.target.value)} />
          </div>
        ))}
      </LLSection>

      {/* ── Footer ───────────────────────────────────────────────────────── */}
      {error && <div className="pi-error" style={{ marginBottom: 'var(--space-3)' }}>{error}</div>}

      {!viewer && (
        <div className="pi-lessons-footer">
          {saved && <span className="pi-saved-flash">Saved</span>}
          <button className="btn primary pi-save-btn" onClick={save} disabled={saving}>
            {saving ? 'Saving…' : isClosed ? 'Save action items' : 'Save lessons learned'}
          </button>
        </div>
      )}
    </div>
  )
}

// ─── Page root ────────────────────────────────────────────────────────────────

export default function PostIncident() {
  const ctx = useOutletContext()
  return (
    <div className="pi-root">
      <nav className="pi-tab-bar" aria-label="Post-Incident sections">
        {TABS.map(t => (
          <NavLink key={t.to} to={t.to}
                   className={({ isActive }) => `pi-tab${isActive ? ' pi-tab-active' : ''}`}>
            {t.label}
          </NavLink>
        ))}
      </nav>
      <div className="pi-content">
        <Outlet context={ctx} />
      </div>
    </div>
  )
}

// One route element per sub-tab (App.jsx); each reads the incident from the outlet context.
export function AnalyticsTab()   { const { inc } = useOutletContext(); return <Analytics        inc={inc} /> }
export function LessonsTab()     { const { inc } = useOutletContext(); const { user } = useAuth(); return <LessonsLearned inc={inc} viewer={user?.role === 'viewer'} /> }
export function CostsTab()       { const { inc } = useOutletContext(); return <CostsImpact      inc={inc} /> }
export function ReportsTab()     { const { inc } = useOutletContext(); return <Reports          inc={inc} /> }
export function ClosureTab()     { const { inc } = useOutletContext(); const { user } = useAuth(); return <ClosureChecklist inc={inc} viewer={user?.role === 'viewer'} /> }
