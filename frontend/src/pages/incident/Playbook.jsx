import { useCallback, useEffect, useMemo, useState } from 'react'
import { useOutletContext, Link } from 'react-router-dom'
import { useAuth } from '../../hooks/useAuth.jsx'
import { api } from '../../api/client.js'
import { PHASE, labelOf } from '../../lib/incidentVocab.js'
import { formatLocal } from '../../lib/datetime.js'
import LocalDateTimePicker from '../../components/LocalDateTimePicker.jsx'

const STATUS_LABEL = {
  open:         'Open',
  in_progress:  'In progress',
  done:         'Done',
  skipped:      'Skipped',
}
export default function Playbook() {
  const { inc, bumpRail, access } = useOutletContext()
  const isClosed = inc?.status === 'closed'
  // L2 (R43): a viewer reads the plan but can't change it (the API refuses them): no write buttons, read-only rows.
  const { user } = useAuth()
  const viewer = user?.role === 'viewer'
  // Replace is the incident lead's (IC / Deputy) or an admin's: the API says so in /access (I3).
  const canReplace = !!access?.capabilities?.includes('replace_playbook')

  const [tasks, setTasks]         = useState([])
  const [archived, setArchived]   = useState([])     // Done/Skipped history of replaced plans (read-only)
  const [templates, setTemplates] = useState([])
  const [suggested, setSuggested] = useState([])     // templates suggested for the incident type
  const [users, setUsers]         = useState([])
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState(null)
  const [notice, setNotice]       = useState(null)
  const [busy, setBusy]           = useState(false)
  const [modal, setModal]         = useState(null)   // null | 'add' | {apply: templateId} | {skip: task}

  const load = useCallback(async () => {
    setError(null)
    try {
      const [t, tpl, sug] = await Promise.all([
        api.listPlaybookTasks(inc.id, { includeArchived: true }),
        api.listPlaybookTemplates().catch(() => []),
        inc.incident_type
          ? api.listPlaybookTemplates({ incident_type: inc.incident_type }).catch(() => [])
          : Promise.resolve([]),
      ])
      setTasks(t.filter(x => !x.archived_at))
      setArchived(t.filter(x => x.archived_at))
      setTemplates(tpl)
      setSuggested(sug)
    } catch (e) {
      setError(e.message || 'Could not load playbook')
    } finally {
      setLoading(false)
    }
  }, [inc.id, inc.incident_type])

  useEffect(() => { load() }, [load])

  // Lazy-load users for the assignee picker. /users/assignable is open to
  // every authenticated user and returns active users only.
  useEffect(() => {
    let cancelled = false
    api.listAssignableUsers()
      .then(u => { if (!cancelled) setUsers(u || []) })
      .catch(() => {})
    return () => { cancelled = true }
  }, [])

  const usernameOf = (uid) => {
    if (!uid) return null
    const u = users.find(x => x.id === uid)
    return u ? u.username : uid.slice(0, 8) + '…'
  }

  // Suggested templates not yet in the current plan.
  const openSuggestions = suggested.filter(s => !tasks.some(t => t.source_template_id === s.id))

  // Group tasks by phase, preserving PHASE ordering.
  const groups = useMemo(() => {
    const byPhase = new Map(PHASE.map(p => [p.value, []]))
    for (const t of tasks) {
      if (!byPhase.has(t.phase)) byPhase.set(t.phase, [])
      byPhase.get(t.phase).push(t)
    }
    return Array.from(byPhase.entries())
      .filter(([, list]) => list.length > 0)
      .map(([phase, list]) => ({
        phase,
        label: labelOf('phase', phase),
        tasks: [...list].sort((a, b) => a.order_index - b.order_index),
        done:  list.filter(t => t.status === 'done').length,
        total: list.length,
      }))
  }, [tasks])

  const totalDone  = tasks.filter(t => t.status === 'done').length
  const totalTasks = tasks.length
  const progress   = totalTasks > 0 ? Math.round((totalDone / totalTasks) * 100) : 0

  const patchTask = async (task, payload, what) => {
    setBusy(true); setError(null)
    try {
      const updated = await api.updatePlaybookTask(inc.id, task.id, payload)
      setTasks(prev => prev.map(t => t.id === updated.id ? updated : t))
      bumpRail?.()
      return true
    } catch (e) {
      setError(e.message || `Could not ${what}`)
      return false
    } finally {
      setBusy(false)
    }
  }

  // Skipping needs a reason (the API answers 422 skip_reason_required without one).
  const onStatusChange = (task, next) => {
    if (next === 'skipped') { setModal({ skip: task }); return }
    patchTask(task, { status: next }, 'update status')
  }

  const onDueChange = (task, next) => patchTask(task, { due_at: next || null }, 'change the due date')

  const onAssigneeChange = (task, next) => patchTask(task, { assignee_id: next || null }, 'change assignee')

  const onDelete = async (task) => {
    if (!window.confirm(`Delete task "${task.title}"?`)) return
    setBusy(true); setError(null)
    try {
      await api.deletePlaybookTask(inc.id, task.id)
      setTasks(prev => prev.filter(t => t.id !== task.id))
      bumpRail?.()
    } catch (e) {
      setError(e.message || 'Could not delete task')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <div>
          <h2 className="panel-h" style={{ marginBottom: 4 }}>Playbook</h2>
          <div style={{ color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
            {totalDone}/{totalTasks} done ({progress}%)
            {totalTasks > 0 && (
              <span style={{ display: 'inline-block', width: 120, height: 6, background: 'var(--surface-2)', marginLeft: 'var(--space-2)', borderRadius: 3, verticalAlign: 'middle' }}>
                <span style={{ display: 'block', width: `${progress}%`, height: '100%', background: 'var(--accent)', borderRadius: 3 }} />
              </span>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)', alignItems: 'center' }}>
          <Link
            to="/playbooks"
            className="btn"
            style={{ textDecoration: 'none' }}
            title="Browse the playbook template library"
          >Browse library</Link>
          {!viewer && (
            <button
              type="button"
              className="btn"
              onClick={() => setModal({ apply: '' })}
              disabled={isClosed || templates.length === 0}
              title={isClosed ? 'Closed incidents are read-only' : 'Apply a template'}
            >Apply template</button>
          )}
          {!viewer && (
            <button
              type="button"
              className="btn primary"
              onClick={() => setModal('add')}
              disabled={isClosed}
            >+ Add task</button>
          )}
        </div>
      </div>

      {error && (
        <div className="alert error" role="alert">
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}
      {notice && (
        <div className="alert info" role="status">
          <span className="alert-icon">i</span><span>{notice}</span>
        </div>
      )}

      {!loading && !isClosed && !viewer && openSuggestions.length > 0 && (
        <div className="pb-suggest" role="note" aria-labelledby="pb-suggest-head">
          <span id="pb-suggest-head" className="pb-suggest-head">
            Suggested for {labelOf('incident_type', inc.incident_type)}:
          </span>
          {openSuggestions.map(s => (
            <button key={s.id} type="button" className="btn ghost" onClick={() => setModal({ apply: s.id })}
                    title="Opens Apply template with this template selected (nothing is applied yet)">
              {s.name} ({s.task_count} tasks)
            </button>
          ))}
        </div>
      )}

      {loading ? (
        <div className="panel-empty"><div>Loading…</div></div>
      ) : tasks.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">▤</div>
          <div>No tasks yet.</div>
          {!isClosed && !viewer && (
            <div style={{ color: 'var(--dim)', fontSize: 12 }}>
              Apply a seeded template (NIST 800-61 R3, CISA Federal IR, CISA Vulnerability Response)
              or add custom tasks.
            </div>
          )}
        </div>
      ) : (
        groups.map(g => (
          <PhaseGroup
            key={g.phase}
            group={g}
            users={users}
            usernameOf={usernameOf}
            onStatusChange={onStatusChange}
            onAssigneeChange={onAssigneeChange}
            onDueChange={onDueChange}
            onDelete={onDelete}
            isClosed={isClosed || viewer}
            canDelete={!viewer}
            busy={busy}
          />
        ))
      )}

      {!loading && archived.length > 0 && <ArchivedTasks tasks={archived} usernameOf={usernameOf} />}

      {modal === 'add' && (
        <AddTaskModal
          incidentId={inc.id}
          onClose={() => setModal(null)}
          onSaved={(t) => { setTasks(prev => [...prev, t]); setModal(null); bumpRail?.() }}
        />
      )}
      {modal?.apply !== undefined && (
        <ApplyTemplateModal
          incidentId={inc.id}
          templates={templates}
          suggested={suggested}
          typeLabel={inc.incident_type ? labelOf('incident_type', inc.incident_type) : null}
          initialTemplateId={modal.apply}
          existingCount={totalTasks}
          canReplace={canReplace}
          onClose={() => setModal(null)}
          onApplied={({ mode, plan, tpl }) => {
            setModal(null); bumpRail?.(); load()
            if (mode === 'append') {
              // Append never removes a task, so the growth of the plan is what was added.
              const added = plan.length - totalTasks, skipped = (tpl?.task_count ?? added) - added
              setNotice(`Added ${added} task${added === 1 ? '' : 's'} from ${tpl?.name || 'the template'}` +
                (skipped > 0 ? `; ${skipped} already in the plan ${skipped === 1 ? 'was' : 'were'} skipped.` : '.'))
            } else {
              setNotice('Plan replaced. Done and Skipped tasks of the old plan are under History.')
            }
          }}
        />
      )}
      {modal?.skip && (
        <SkipTaskModal
          task={modal.skip}
          onClose={() => setModal(null)}
          onSave={async (reason) => {
            if (await patchTask(modal.skip, { status: 'skipped', skip_reason: reason }, 'skip the task')) setModal(null)
          }}
          busy={busy}
        />
      )}
    </section>
  )
}

// ── Phase group ───────────────────────────────────────────────────────────

function PhaseGroup({ group, users, usernameOf, onStatusChange, onAssigneeChange, onDueChange, onDelete, isClosed, canDelete, busy }) {
  return (
    <div style={{ marginBottom: 'var(--space-4)' }}>
      <h3 style={{
        margin: '0 0 var(--space-2) 0',
        fontFamily: 'var(--font-heading)',
        fontSize: 12,
        letterSpacing: 'var(--heading-letter-spacing)',
        textTransform: 'var(--heading-transform)',
        color: 'var(--accent)',
      }}>
        {group.label}{' '}
        <span style={{ color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 400 }}>
          {group.done}/{group.total}
        </span>
      </h3>
      <ul className="pb-task-list">
        {group.tasks.map(t => (
          <li key={t.id} className="pb-task-row">
            <div>
              <select
                className="select compact"
                value={t.status}
                onChange={(e) => onStatusChange(t, e.target.value)}
                disabled={isClosed || busy}
                aria-label="Status"
              >
                {Object.entries(STATUS_LABEL).map(([v, l]) => (
                  <option key={v} value={v}>{l}</option>
                ))}
              </select>
            </div>
            <div className="pb-task-main">
              <div style={{
                fontWeight: 500,
                textDecoration: t.status === 'done' || t.status === 'skipped' ? 'line-through' : 'none',
                color: t.status === 'done' || t.status === 'skipped' ? 'var(--muted)' : 'var(--text)',
              }}>
                {t.title}
              </div>
              {t.description && (
                <div style={{ color: 'var(--muted)', fontSize: 12, marginTop: 2 }}>
                  {t.description}
                </div>
              )}
              {t.status === 'done' && t.completed_at && (
                <div style={{ color: 'var(--ok)', fontFamily: 'var(--font-mono)', fontSize: 10, marginTop: 2 }}>
                  done {formatLocal(t.completed_at)}
                </div>
              )}
              {t.status === 'skipped' && t.skip_reason && (
                <div className="pb-task-note">Skipped: {t.skip_reason}</div>
              )}
              {t.source_template_id && <div className="pb-task-note">from template</div>}
              {t.handoff_id && <div className="pb-task-note" data-task-handoff>from a handoff next step</div>}
              {t.linked_actions?.length > 0 && (
                <div className="link-chips" data-task-links style={{ marginTop: 4 }}>
                  {t.linked_actions.map(a => (
                    <span key={a.id} className="link-chip" data-chip="action" title={`${a.category}: ${a.title} (${a.status})`}>
                      → {a.title.slice(0, 40)} · {a.status.replace('_', ' ')}
                    </span>
                  ))}
                </div>
              )}
            </div>
            <div>
              <select
                className="select compact"
                value={t.assignee_id || ''}
                onChange={(e) => onAssigneeChange(t, e.target.value)}
                disabled={isClosed || busy}
                aria-label="Assignee"
              >
                <option value="">Unassigned</option>
                {users.map(u => (
                  <option key={u.id} value={u.id}>{u.username}</option>
                ))}
                {/* If a task is assigned to someone not in our user list (e.g. a
                    deactivated user) keep the value showing rather than dropping it silently. */}
                {t.assignee_id && !users.some(u => u.id === t.assignee_id) && (
                  <option value={t.assignee_id}>{usernameOf(t.assignee_id)}</option>
                )}
              </select>
            </div>
            <div className="pb-due">
              <LocalDateTimePicker
                id={`pb-due-${t.id}`}
                value={t.due_at || ''}
                onChange={(v) => onDueChange(t, v)}
                disabled={isClosed || busy}
                clearable
                hint={false}
                placeholder="Due (optional)"
              />
              {t.overdue && <div className="pb-overdue"><span aria-hidden="true">! </span>Overdue</div>}
            </div>
            <div style={{ textAlign: 'right' }}>
              {canDelete && (
                <button
                  type="button"
                  className="btn ghost"
                  onClick={() => onDelete(t)}
                  disabled={isClosed || busy}
                >Delete</button>
              )}
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
}

// ── History: Done/Skipped tasks of replaced plans (read-only) ─────────────

function ArchivedTasks({ tasks, usernameOf }) {
  return (
    <details className="pb-history">
      <summary>History: {tasks.length} task{tasks.length === 1 ? '' : 's'} from replaced plans (read-only)</summary>
      <ul>
        {tasks.map(t => (
          <li key={t.id}>
            <span className="pb-history-status">{STATUS_LABEL[t.status]}</span>
            <span className="pb-history-title">{t.title}</span>
            <span className="pb-task-note">
              {labelOf('phase', t.phase)}
              {t.status === 'done' && t.completed_at ? ` · done ${formatLocal(t.completed_at)}` : ''}
              {t.status === 'skipped' && t.skip_reason ? ` · skipped: ${t.skip_reason}` : ''}
              {t.assignee_id ? ` · ${usernameOf(t.assignee_id)}` : ''}
              {` · replaced ${formatLocal(t.archived_at)}${t.archive_reason ? `: ${t.archive_reason}` : ''}`}
            </span>
          </li>
        ))}
      </ul>
    </details>
  )
}

// ── Skip task modal (a reason is required) ───────────────────────────────

function SkipTaskModal({ task, onClose, onSave, busy }) {
  const [reason, setReason] = useState('')

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="pb-skip-title">
        <div className="modal-head">
          <h2 id="pb-skip-title">Skip task</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy}>×</button>
        </div>
        <form onSubmit={(e) => { e.preventDefault(); if (reason.trim()) onSave(reason.trim()) }}>
          <div className="modal-body">
            <div className="form">
              <div style={{ fontWeight: 500 }}>{task.title}</div>
              <div className="field">
                <label className="field-label" htmlFor="pb-skip-reason">Why is it skipped?</label>
                <textarea id="pb-skip-reason" className="input" value={reason} rows={3} maxLength={2048}
                          onChange={(e) => setReason(e.target.value)} autoFocus required
                          placeholder="e.g. Not applicable: no on-premises Exchange in scope" />
                <div className="field-hint">Recorded on the task and in the audit log.</div>
              </div>
            </div>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button type="submit" className="btn primary" disabled={busy || !reason.trim()}>
              {busy ? 'Saving…' : 'Skip task'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Add custom task modal ─────────────────────────────────────────────────

function AddTaskModal({ incidentId, onClose, onSaved }) {
  const [title, setTitle]             = useState('')
  const [description, setDescription] = useState('')
  const [phase, setPhase]             = useState('detection_and_analysis')
  const [busy, setBusy]               = useState(false)
  const [error, setError]             = useState(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    if (!title.trim()) { setError('Title is required.'); return }
    setBusy(true)
    try {
      const t = await api.createPlaybookTask(incidentId, {
        title:       title.trim(),
        description: description.trim() || null,
        phase,
        order_index: 9999,
      })
      onSaved(t)
    } catch (e2) {
      setError(e2.message || 'Could not add task')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop"
        >
      <div className="modal" role="dialog" aria-labelledby="pb-add-title">
        <div className="modal-head">
          <h2 id="pb-add-title">Add task</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy}>×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body">
            <div className="form">
              <div className="field">
                <label className="field-label" htmlFor="pb-title">Title</label>
                <input id="pb-title" className="input" value={title}
                       onChange={(e) => setTitle(e.target.value)}
                       autoFocus required maxLength={512} />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="pb-desc">Description (optional)</label>
                <textarea id="pb-desc" className="input" value={description}
                          onChange={(e) => setDescription(e.target.value)}
                          rows={3} maxLength={4096} />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="pb-phase">Phase (800-61 R3)</label>
                <select id="pb-phase" className="select" value={phase}
                        onChange={(e) => setPhase(e.target.value)}>
                  {PHASE.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
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
            <button type="submit" className="btn primary" disabled={busy}>
              {busy ? 'Adding…' : 'Add task'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Apply template modal ──────────────────────────────────────────────────
// Append (default, any analyst) adds the template's tasks; the API skips tasks of the same template
// already in the plan. Replace is for the incident lead or an admin and needs a reason.

function ApplyTemplateModal({ incidentId, templates, suggested, typeLabel, initialTemplateId, existingCount,
                              canReplace, onClose, onApplied }) {
  const suggestedIds = new Set(suggested.map(t => t.id))
  const others = templates.filter(t => !suggestedIds.has(t.id))
  const [templateId, setTemplateId] = useState(initialTemplateId || suggested[0]?.id || templates[0]?.id || '')
  const [mode, setMode]             = useState('append')
  const [reason, setReason]         = useState('')
  const [busy, setBusy]             = useState(false)
  const [error, setError]           = useState(null)

  const hasExisting = existingCount > 0
  const replacing = mode === 'replace' && hasExisting

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    if (!templateId) { setError('Pick a template.'); return }
    if (replacing && !reason.trim()) { setError('Say why the plan is replaced.'); return }
    setBusy(true)
    try {
      const plan = await api.instantiatePlaybook(incidentId, {
        template_id: templateId,
        mode: replacing ? 'replace' : 'append',
        ...(replacing ? { reason: reason.trim() } : {}),
      })
      onApplied({ mode: replacing ? 'replace' : 'append', plan, tpl: templates.find(t => t.id === templateId) })
    } catch (e2) {
      setError(e2.message || 'Could not apply template')
    } finally {
      setBusy(false)
    }
  }

  const option = (t) => (
    <option key={t.id} value={t.id}>
      {t.name} ({t.task_count} tasks){t.is_system ? '' : ' — custom'}
    </option>
  )
  const selected = templates.find(t => t.id === templateId)

  return (
    <div className="modal-backdrop"
        >
      <div className="modal" role="dialog" aria-labelledby="pb-apply-title">
        <div className="modal-head">
          <h2 id="pb-apply-title">Apply playbook template</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy}>×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body">
            <div className="form">
              <div className="field">
                <label className="field-label" htmlFor="pb-tpl">Template</label>
                <select id="pb-tpl" className="select" value={templateId}
                        onChange={(e) => setTemplateId(e.target.value)} autoFocus>
                  {suggested.length > 0 ? (
                    <>
                      <optgroup label={`Suggested for ${typeLabel}`}>{suggested.map(option)}</optgroup>
                      <optgroup label="All other templates">{others.map(option)}</optgroup>
                    </>
                  ) : templates.map(option)}
                </select>
              </div>

              {selected?.description && (
                <div style={{ color: 'var(--muted)', fontSize: 13, lineHeight: 1.5 }}>
                  {selected.description}
                </div>
              )}

              {hasExisting && (
                <fieldset className="pb-mode">
                  <legend className="field-label">The plan already has {existingCount} task{existingCount !== 1 ? 's' : ''}</legend>
                  <label>
                    <input type="radio" name="pb-mode" value="append" checked={mode === 'append'}
                           onChange={() => setMode('append')} />
                    <span><b>Add to the plan</b>: the template's tasks are added; tasks from this template
                      that are already in the plan are skipped.</span>
                  </label>
                  <label className={canReplace ? '' : 'pb-mode-off'}>
                    <input type="radio" name="pb-mode" value="replace" checked={mode === 'replace'}
                           onChange={() => setMode('replace')} disabled={!canReplace} />
                    <span><b>Replace the plan</b>: Done and Skipped tasks move to History (read-only); Open and
                      In-progress tasks are removed.
                      {!canReplace && ' Only the incident lead (IC or Deputy IC) or an admin can replace the plan.'}</span>
                  </label>
                </fieldset>
              )}

              {replacing && (
                <div className="field">
                  <label className="field-label" htmlFor="pb-replace-reason">Why replace the plan?</label>
                  <textarea id="pb-replace-reason" className="input" value={reason} rows={3} maxLength={2048}
                            onChange={(e) => setReason(e.target.value)} required
                            placeholder="e.g. Reclassified from phishing to ransomware" />
                  <div className="field-hint">Recorded on the archived tasks and in the audit log.</div>
                </div>
              )}

              {error && (
                <div className="alert error" role="alert">
                  <span className="alert-icon">!</span><span>{error}</span>
                </div>
              )}
            </div>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button
              type="submit"
              className="btn primary"
              disabled={busy || (replacing && !reason.trim())}
            >
              {busy ? 'Applying…' : replacing ? 'Replace plan' : hasExisting ? 'Add to plan' : 'Apply playbook'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
